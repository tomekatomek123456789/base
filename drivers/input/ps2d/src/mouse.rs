use crate::controller::Ps2;
use std::time::Duration;

pub const RESET_TIMEOUT: Duration = Duration::from_millis(1000);
pub const COMMAND_TIMEOUT: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
#[allow(dead_code)]
enum MouseCommand {
    SetScaling1To1 = 0xE6,
    SetScaling2To1 = 0xE7,
    StatusRequest = 0xE9,
    GetDeviceId = 0xF2,
    EnableReporting = 0xF4,
    SetDefaultsDisable = 0xF5,
    SetDefaults = 0xF6,
    Reset = 0xFF,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
enum MouseCommandData {
    SetSampleRate = 0xF3,
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
#[allow(dead_code)]
enum MouseId {
    /// Mouse sends three bytes
    Base = 0x00,
    /// Mouse sends fourth byte with scroll
    Intellimouse1 = 0x03,
    /// Mouse sends fourth byte with scroll, button 4, and button 5
    //TODO: support this mouse type
    Intellimouse2 = 0x04,
}

#[derive(Debug)]
pub enum MouseState {
    /// No mouse found
    None,
    /// Ready to initialize mouse
    Init,
    /// Reset command is sent
    Reset,
    /// BAT completion code returned
    Bat,
    /// Enable intellimouse features
    EnableIntellimouse { index: usize, sent_command: bool },
    /// Device ID update
    DeviceId,
    /// Enable reporting command sent
    EnableReporting { id: u8 },
    /// Mouse is streaming
    Streaming { id: u8 },
}

#[derive(Debug)]
#[must_use]
pub enum MouseResult {
    None,
    Packet(u8, bool),
    Timeout(Duration),
}

impl MouseState {
    pub fn reset(&mut self, ps2: &mut Ps2) -> MouseResult {
        match ps2.mouse_command_async(MouseCommand::Reset as u8) {
            Ok(()) => {
                *self = MouseState::Reset;
                MouseResult::Timeout(RESET_TIMEOUT)
            }
            Err(err) => {
                log::error!("failed to send mouse reset command: {:?}", err);
                //TODO: retry reset?
                *self = MouseState::None;
                MouseResult::None
            }
        }
    }

    fn enable_reporting(&mut self, id: u8, ps2: &mut Ps2) -> MouseResult {
        match ps2.mouse_command_async(MouseCommand::EnableReporting as u8) {
            Ok(()) => {
                *self = MouseState::EnableReporting { id };
                MouseResult::Timeout(COMMAND_TIMEOUT)
            }
            Err(err) => {
                log::error!("failed to enable mouse reporting: {:?}", err);
                //TODO: reset mouse?
                *self = MouseState::None;
                MouseResult::None
            }
        }
    }

    fn request_id(&mut self, ps2: &mut Ps2) -> MouseResult {
        match ps2.mouse_command_async(MouseCommand::GetDeviceId as u8) {
            Ok(()) => {
                *self = MouseState::DeviceId;
                MouseResult::Timeout(COMMAND_TIMEOUT)
            }
            Err(err) => {
                log::error!("failed to request mouse id: {:?}", err);
                //TODO: reset mouse instead?
                self.enable_reporting(MouseId::Base as u8, ps2)
            }
        }
    }

    fn enable_intellimouse(
        &mut self,
        index: usize,
        sent_command: bool,
        ps2: &mut Ps2,
    ) -> MouseResult {
        let magic = [200, 100, 80];
        if let Some(data) = magic.get(index) {
            match ps2.mouse_command_async(if sent_command {
                *data
            } else {
                MouseCommandData::SetSampleRate as u8
            }) {
                Ok(()) => {
                    *self = if sent_command {
                        MouseState::EnableIntellimouse {
                            index: index + 1,
                            sent_command: false,
                        }
                    } else {
                        MouseState::EnableIntellimouse {
                            index,
                            sent_command: true,
                        }
                    };
                    MouseResult::Timeout(COMMAND_TIMEOUT)
                }
                Err(err) => {
                    log::error!("failed to send intellimouse command: {:?}", err);
                    self.request_id(ps2)
                }
            }
        } else {
            self.request_id(ps2)
        }
    }

    pub fn handle(&mut self, data: u8, ps2: &mut Ps2) -> MouseResult {
        match *self {
            MouseState::None | MouseState::Init => {
                //TODO: enable port in this case, mouse hotplug may send 0xAA 0x00
                log::error!(
                    "received mouse byte {:02X} when mouse not initialized",
                    data
                );
                MouseResult::None
            }
            MouseState::Reset => {
                if data == 0xFA {
                    log::debug!("mouse reset ok");
                    MouseResult::Timeout(RESET_TIMEOUT)
                } else if data == 0xAA {
                    log::debug!("BAT completed");
                    *self = MouseState::Bat;
                    MouseResult::Timeout(COMMAND_TIMEOUT)
                } else {
                    log::warn!("unknown mouse response {:02X} after reset", data);
                    self.reset(ps2)
                }
            }
            MouseState::Bat => {
                if data == MouseId::Base as u8 {
                    // Enable intellimouse features
                    log::debug!("BAT mouse id {:02X} (base)", data);
                    self.enable_intellimouse(0, false, ps2)
                } else if data == MouseId::Intellimouse1 as u8 {
                    // Extra packet already enabled
                    log::debug!("BAT mouse id {:02X} (intellimouse)", data);
                    self.enable_reporting(data, ps2)
                } else {
                    log::warn!("unknown mouse id {:02X} after BAT", data);
                    MouseResult::Timeout(RESET_TIMEOUT)
                }
            }
            MouseState::EnableIntellimouse {
                index,
                sent_command,
            } => {
                if data == 0xFA {
                    self.enable_intellimouse(index, sent_command, ps2)
                } else {
                    log::warn!(
                        "unknown mouse response {:02X} while enabling intellimouse",
                        data
                    );
                    self.request_id(ps2)
                }
            }
            MouseState::DeviceId => {
                if data == 0xFA {
                    // Command OK response
                    //TODO: handle this separately?
                    MouseResult::Timeout(COMMAND_TIMEOUT)
                } else if data == MouseId::Base as u8 || data == MouseId::Intellimouse1 as u8 {
                    log::debug!("mouse id {:02X}", data);
                    self.enable_reporting(data, ps2)
                } else {
                    log::warn!("unknown mouse id {:02X} after requesting id", data);
                    self.reset(ps2)
                }
            }
            MouseState::EnableReporting { id } => {
                log::debug!("mouse id {:02X} enable reporting {:02X}", id, data);
                //TODO: handle response ok/error
                *self = MouseState::Streaming { id };
                MouseResult::None
            }
            MouseState::Streaming { id } => {
                MouseResult::Packet(data, id == MouseId::Intellimouse1 as u8)
            }
        }
    }

    pub fn handle_timeout(&mut self, ps2: &mut Ps2) -> MouseResult {
        let mut res = MouseResult::None;
        match *self {
            MouseState::None | MouseState::Streaming { .. } => MouseResult::None,
            MouseState::Init => {
                // The state uses a timeout on init to request a reset
                self.reset(ps2)
            }
            MouseState::Bat => {
                log::warn!("timeout while waiting for BAT completion");
                //TODO: limit number of resets
                self.reset(ps2)
            }
            MouseState::EnableIntellimouse { .. } => {
                //TODO: retry?
                log::warn!("timeout while enabling intellimouse");
                self.request_id(ps2)
            }
            MouseState::DeviceId => {
                log::warn!("timeout while requesting mouse id");
                self.enable_reporting(0, ps2)
            }
            _ => {
                log::warn!("TODO: timeout on {:?}", self);
                MouseResult::None
            }
        }
    }
}
