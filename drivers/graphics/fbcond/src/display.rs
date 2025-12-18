use console_draw::TextScreen;
use drm::buffer::Buffer;
use drm::control::dumbbuffer::{DumbBuffer, DumbMapping};
use graphics_ipc::v2::{Damage, V2GraphicsHandle};
use inputd::ConsumerHandle;
use std::{io, mem, ptr};

pub struct Display {
    pub input_handle: ConsumerHandle,
    pub map: Option<DisplayMap>,
}

pub struct DisplayMap {
    display_handle: V2GraphicsHandle,
    fb: DumbBuffer,
    mapping: DumbMapping<'static>,
}

impl DisplayMap {
    pub unsafe fn console_map(&mut self) -> console_draw::DisplayMap {
        console_draw::DisplayMap {
            offscreen: ptr::slice_from_raw_parts_mut(
                self.mapping.as_mut_ptr() as *mut u32,
                self.mapping.len() / 4,
            ),
            width: self.fb.size().0 as usize,
            height: self.fb.size().1 as usize,
        }
    }
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
            .display_size(new_display_handle.first_display().unwrap())
            .unwrap();
        let mut fb = new_display_handle
            .create_dumb_framebuffer(width, height)
            .unwrap();

        let map = match new_display_handle.map_dumb_framebuffer(&mut fb) {
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

        self.map = Some(DisplayMap {
            display_handle: new_display_handle,
            fb,
            mapping: map,
        });
    }

    pub fn handle_resize(map: &mut DisplayMap, text_screen: &mut TextScreen) {
        let (width, height) = match map
            .display_handle
            .first_display()
            .and_then(|handle| map.display_handle.display_size(handle))
        {
            Ok((width, height)) => (width, height),
            Err(err) => {
                log::error!("fbcond: failed to get display size: {}", err);
                map.fb.size()
            }
        };

        if (width, height) != map.fb.size() {
            match map.display_handle.create_dumb_framebuffer(width, height) {
                Ok(mut fb) => {
                    let mut new_map = match map.display_handle.map_dumb_framebuffer(&mut fb) {
                        Ok(new_map) => unsafe {
                            mem::transmute::<DumbMapping<'_>, DumbMapping<'static>>(new_map)
                        },
                        Err(err) => {
                            eprintln!("fbcond: failed to open display: {}", err);
                            return;
                        }
                    };

                    new_map.fill(0);

                    text_screen.resize(
                        unsafe { &mut map.console_map() },
                        &mut console_draw::DisplayMap {
                            offscreen: ptr::slice_from_raw_parts_mut(
                                new_map.as_mut_ptr() as *mut u32,
                                new_map.len() / 4,
                            ),
                            width: fb.size().0 as usize,
                            height: fb.size().1 as usize,
                        },
                    );

                    let old_fb = mem::replace(&mut map.fb, fb);
                    map.mapping = new_map;

                    let _ = map.display_handle.destroy_dumb_framebuffer(old_fb);

                    eprintln!("fbcond: mapped display");
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
