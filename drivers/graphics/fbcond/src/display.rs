use console_draw::{TextScreen, V2DisplayMap};
use drm::buffer::{Buffer, DrmFourcc};
use drm::control::dumbbuffer::DumbMapping;
use drm::control::Device;
use graphics_ipc::v2::{Damage, V2GraphicsHandle};
use inputd::ConsumerHandle;
use std::{io, mem};

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
        let mut fb = new_display_handle
            .create_dumb_buffer((width.into(), height.into()), DrmFourcc::Argb8888, 32)
            .unwrap();

        let map = match new_display_handle.map_dumb_buffer(&mut fb) {
            Ok(map) => unsafe { mem::transmute::<DumbMapping<'_>, DumbMapping<'static>>(map) },
            Err(err) => {
                log::error!("failed to map display: {}", err);
                return;
            }
        };

        log::debug!(
            "fbcond: Mapped new display with size {}x{}",
            fb.size().0,
            fb.size().1,
        );

        self.map = Some(V2DisplayMap {
            display_handle: new_display_handle,
            fb,
            mapping: map,
        });
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
            match map
                .display_handle
                .create_dumb_buffer((width, height), DrmFourcc::Argb8888, 32)
            {
                Ok(fb) => {
                    match text_screen.resize(map, fb) {
                        Ok(()) => eprintln!("fbcond: mapped display"),
                        Err(err) => {
                            eprintln!("fbcond: failed to open display: {}", err);
                            return;
                        }
                    };
                }
                Err(err) => {
                    log::error!("fbcond: failed to create framebuffer: {}", err);
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
