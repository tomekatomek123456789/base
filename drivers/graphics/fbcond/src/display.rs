use console_draw::{TextScreen, V2DisplayMap};
use drm::buffer::Buffer;
use drm::control::Device;
use graphics_ipc::v2::{Damage, V2GraphicsHandle};
use inputd::ConsumerHandle;
use std::io;

pub struct Display {
    pub input_handle: ConsumerHandle,
    pub map: Option<V2DisplayMap>,
}

impl Display {
    pub fn open_new_vt() -> io::Result<Self> {
        let mut display = Self {
            input_handle: ConsumerHandle::new_vt()?,
            map: None,
        };

        display.reopen_for_handoff();

        Ok(display)
    }

    /// Re-open the display after a handoff.
    pub fn reopen_for_handoff(&mut self) {
        let display_file = self.input_handle.open_display_v2().unwrap();
        let new_display_handle = V2GraphicsHandle::from_file(display_file).unwrap();

        log::debug!("fbcond: Opened new display");

        let (width, height) = new_display_handle
            .get_connector(new_display_handle.first_display().unwrap(), true)
            .unwrap()
            .modes()[0]
            .size();

        match V2DisplayMap::new(new_display_handle, width.into(), height.into()) {
            Ok(map) => {
                log::debug!(
                    "fbcond: Mapped new display with size {}x{}",
                    map.fb.size().0,
                    map.fb.size().1,
                );
                self.map = Some(map)
            }
            Err(err) => {
                eprintln!("fbcond: failed to open display: {}", err);
                return;
            }
        }
    }

    pub fn handle_resize(map: &mut V2DisplayMap, text_screen: &mut TextScreen) {
        let (width, height) = match map.display_handle.first_display().and_then(|handle| {
            Ok(map.display_handle.get_connector(handle, true)?.modes()[0].size())
        }) {
            Ok((width, height)) => (width.into(), height.into()),
            Err(err) => {
                log::error!("fbcond: failed to get display size: {}", err);
                map.fb.size()
            }
        };

        if (width, height) != map.fb.size() {
            match text_screen.resize(map, width, height) {
                Ok(()) => eprintln!("fbcond: mapped display"),
                Err(err) => {
                    eprintln!("fbcond: failed to create or map framebuffer: {}", err);
                    return;
                }
            }
        }
    }

    pub fn sync_rect(&mut self, damage: Damage) {
        if let Some(map) = &self.map {
            map.display_handle
                .update_plane(0, u32::from(map.fb.handle()), damage)
                .unwrap();
        }
    }
}
