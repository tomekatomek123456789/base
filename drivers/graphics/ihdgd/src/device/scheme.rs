//TODO: this is copied from vesad and should be adapted

use std::alloc::{self, Layout};
use std::convert::TryInto;
use std::ptr::{self, NonNull};

use driver_graphics::objects::{DrmConnector, DrmConnectorStatus, DrmObjects};
use driver_graphics::{
    modeinfo_for_size, CursorFramebuffer, CursorPlane, Framebuffer, GraphicsAdapter,
};
use graphics_ipc::v1::Damage;
use graphics_ipc::v2::ipc::{DRM_CAP_DUMB_BUFFER, DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT};
use syscall::{error::EINVAL, PAGE_SIZE};

use super::Device;

#[derive(Debug)]
pub struct Connector {
    framebuffer_id: usize,
}

//TODO: use hardware cursor
pub enum Cursor {}

impl CursorFramebuffer for Cursor {}

impl GraphicsAdapter for Device {
    type Connector = Connector;

    type Framebuffer = DumbFb;
    type Cursor = Cursor;

    fn name(&self) -> &'static [u8] {
        b"ihdgd"
    }

    fn desc(&self) -> &'static [u8] {
        b"Intel HD Graphics"
    }

    fn init(&mut self, objects: &mut DrmObjects<Self>) {
        // FIXME enumerate actual connectors
        for (framebuffer_id, _) in self.framebuffers.iter().enumerate() {
            objects.add_connector(Connector { framebuffer_id });
        }
    }

    fn get_cap(&self, cap: u32) -> syscall::Result<u64> {
        match cap {
            DRM_CAP_DUMB_BUFFER => Ok(1),
            _ => Err(syscall::Error::new(EINVAL)),
        }
    }

    fn set_client_cap(&self, cap: u32, _value: u64) -> syscall::Result<()> {
        match cap {
            // FIXME hide cursor plane unless this client cap is set
            DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT => Ok(()),
            _ => Err(syscall::Error::new(EINVAL)),
        }
    }

    fn probe_connector(&mut self, connector: &mut DrmConnector<Self>) {
        let framebuffer = &self.framebuffers[connector.driver_data.framebuffer_id];
        connector.connection = DrmConnectorStatus::Connected;
        connector.modes = vec![modeinfo_for_size(
            framebuffer.width as u32,
            framebuffer.height as u32,
        )];
    }

    fn display_count(&self) -> usize {
        self.framebuffers.len()
    }

    fn display_size(&self, display_id: usize) -> (u32, u32) {
        (
            self.framebuffers[display_id].width as u32,
            self.framebuffers[display_id].height as u32,
        )
    }

    fn create_dumb_framebuffer(&mut self, width: u32, height: u32) -> Self::Framebuffer {
        DumbFb::new(width as usize, height as usize)
    }

    fn map_dumb_framebuffer(&mut self, framebuffer: &Self::Framebuffer) -> *mut u8 {
        framebuffer.ptr.as_ptr().cast::<u8>()
    }

    fn update_plane(&mut self, display_id: usize, framebuffer: &Self::Framebuffer, damage: Damage) {
        framebuffer.sync(&mut self.framebuffers[display_id], damage)
    }

    fn supports_hw_cursor(&self) -> bool {
        false
    }

    fn create_cursor_framebuffer(&mut self) -> Self::Cursor {
        unimplemented!("ihdgd does not support this function");
    }

    fn map_cursor_framebuffer(&mut self, _cursor: &Self::Cursor) -> *mut u8 {
        unimplemented!("ihdgd does not support this function");
    }

    fn handle_cursor(&mut self, _cursor: &CursorPlane<Self::Cursor>, _dirty_fb: bool) {
        unimplemented!("ihdgd does not support this function");
    }
}

pub struct DeviceFb {
    pub onscreen: *mut [u32],
    pub width: usize,
    pub height: usize,
    pub stride: usize,
}

impl DeviceFb {
    pub unsafe fn new(
        virt: *mut u32,
        width: usize,
        height: usize,
        stride: usize,
        clear: bool,
    ) -> Self {
        let onscreen = ptr::slice_from_raw_parts_mut(virt, stride * height);
        if clear {
            (&mut *onscreen).fill(0);
        }
        Self {
            onscreen,
            width,
            height,
            stride,
        }
    }
}

pub struct DumbFb {
    width: usize,
    height: usize,
    ptr: NonNull<[u32]>,
}

impl DumbFb {
    fn new(width: usize, height: usize) -> DumbFb {
        let len = width * height;
        let layout = Self::layout(len);
        let ptr = unsafe { alloc::alloc_zeroed(layout) };
        let ptr = ptr::slice_from_raw_parts_mut(ptr.cast(), len);
        let ptr = NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout));

        DumbFb { width, height, ptr }
    }

    #[inline]
    fn layout(len: usize) -> Layout {
        // optimizes to an integer mul
        Layout::array::<u32>(len)
            .unwrap()
            .align_to(PAGE_SIZE)
            .unwrap()
    }
}

impl Drop for DumbFb {
    fn drop(&mut self) {
        let layout = Self::layout(self.ptr.len());
        unsafe { alloc::dealloc(self.ptr.as_ptr().cast(), layout) };
    }
}

impl Framebuffer for DumbFb {
    fn width(&self) -> u32 {
        self.width as u32
    }

    fn height(&self) -> u32 {
        self.height as u32
    }
}

impl DumbFb {
    fn sync(&self, framebuffer: &mut DeviceFb, sync_rect: Damage) {
        let sync_rect = sync_rect.clip(
            self.width.try_into().unwrap(),
            self.height.try_into().unwrap(),
        );

        let start_x: usize = sync_rect.x.try_into().unwrap();
        let start_y: usize = sync_rect.y.try_into().unwrap();
        let w: usize = sync_rect.width.try_into().unwrap();
        let h: usize = sync_rect.height.try_into().unwrap();

        let offscreen_ptr = self.ptr.as_ptr() as *mut u32;
        let onscreen_ptr = framebuffer.onscreen as *mut u32; // FIXME use as_mut_ptr once stable

        for row in start_y..start_y + h {
            unsafe {
                ptr::copy(
                    offscreen_ptr.add(row * self.width + start_x),
                    onscreen_ptr.add(row * framebuffer.stride + start_x),
                    w,
                );
            }
        }
    }
}
