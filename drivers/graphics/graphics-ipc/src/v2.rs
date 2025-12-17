use std::fs::File;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::io::AsRawFd;
use std::{io, mem, ptr};

use drm::control::connector::{self, State};
use drm::control::Device as _;
use drm::{ClientCapability, Device as _, DriverCapability};
use libredox::flag;

pub use crate::common::{Damage, DisplayMap};

extern "C" {
    fn redox_sys_call_v0(
        fd: usize,
        payload: *mut u8,
        payload_len: usize,
        flags: usize,
        metadata: *const u64,
        metadata_len: usize,
    ) -> usize;
}

unsafe fn sys_call<T>(
    fd: &impl AsRawFd,
    payload: &mut T,
    flags: usize,
    metadata: &[u64],
) -> libredox::error::Result<usize> {
    libredox::error::Error::demux(redox_sys_call_v0(
        fd.as_raw_fd() as usize,
        payload as *mut T as *mut u8,
        mem::size_of::<T>(),
        flags,
        metadata.as_ptr(),
        metadata.len(),
    ))
}

/// A graphics handle using the v2 graphics API.
///
/// The v2 graphics API allows creating framebuffers on the fly, using them for page flipping and
/// handles all displays using a single fd.
///
/// This API is not yet stable. Do not depend on it outside of the drivers repo until it has been
/// stabilized.
pub struct V2GraphicsHandle {
    file: File,
}

impl AsFd for V2GraphicsHandle {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

impl drm::Device for V2GraphicsHandle {}
impl drm::control::Device for V2GraphicsHandle {}

impl V2GraphicsHandle {
    pub fn from_file(file: File) -> io::Result<Self> {
        let handle = V2GraphicsHandle { file };
        handle.set_client_capability(ClientCapability::CursorPlaneHotspot, true)?;
        assert!(handle.get_driver_capability(DriverCapability::DumbBuffer)? == 1);
        Ok(handle)
    }

    pub fn first_display(&self) -> io::Result<connector::Handle> {
        for &connector in self.resource_handles().unwrap().connectors() {
            if self.get_connector(connector, true)?.state() == State::Connected {
                return Ok(connector);
            }
        }
        Err(io::Error::other("no connected display"))
    }

    pub fn display_size(&self, handle: connector::Handle) -> io::Result<(u32, u32)> {
        let (width, height) = self.get_connector(handle, true)?.modes()[0].size();
        Ok((u32::from(width), u32::from(height)))
    }

    pub fn create_dumb_framebuffer(&self, width: u32, height: u32) -> io::Result<usize> {
        let mut cmd = ipc::CreateDumbFramebuffer {
            width,
            height,

            fb_id: 0,
        };
        unsafe {
            sys_call(
                &self.file,
                &mut cmd,
                0,
                &[ipc::CREATE_DUMB_FRAMEBUFFER, 0, 0],
            )?;
        }
        Ok(cmd.fb_id)
    }

    pub fn map_dumb_framebuffer(
        &self,
        id: usize,
        width: u32,
        height: u32,
    ) -> io::Result<DisplayMap> {
        let mut cmd = ipc::DumbFramebufferMapOffset {
            fb_id: id,
            offset: 0,
        };
        unsafe {
            sys_call(
                &self.file,
                &mut cmd,
                0,
                &[ipc::DUMB_FRAMEBUFFER_MAP_OFFSET, 0, 0],
            )?;
        }

        let display_ptr = unsafe {
            libredox::call::mmap(libredox::call::MmapArgs {
                fd: self.file.as_raw_fd() as usize,
                offset: cmd.offset as u64,
                length: (width * height * 4) as usize,
                prot: flag::PROT_READ | flag::PROT_WRITE,
                flags: flag::MAP_SHARED,
                addr: core::ptr::null_mut(),
            })?
        };
        let offscreen = ptr::slice_from_raw_parts_mut(
            display_ptr as *mut u32,
            width as usize * height as usize,
        );

        Ok(unsafe { DisplayMap::new(offscreen, width as usize, height as usize) })
    }

    pub fn destroy_dumb_framebuffer(&self, id: usize) -> io::Result<usize> {
        let mut cmd = ipc::DestroyDumbFramebuffer { fb_id: id };
        unsafe {
            sys_call(
                &self.file,
                &mut cmd,
                0,
                &[ipc::DESTROY_DUMB_FRAMEBUFFER, 0, 0],
            )?;
        }
        Ok(cmd.fb_id)
    }

    pub fn update_plane(&self, display_id: usize, fb_id: usize, damage: Damage) -> io::Result<()> {
        let mut cmd = ipc::UpdatePlane {
            display_id,
            fb_id,
            damage,
        };
        unsafe {
            sys_call(&self.file, &mut cmd, 0, &[ipc::UPDATE_PLANE, 0, 0])?;
        }
        Ok(())
    }
}

pub mod ipc {
    use crate::common::Damage;

    pub use redox_ioctl::drm::*;

    // FIXME replace these with proper drm interfaces
    pub const CREATE_DUMB_FRAMEBUFFER: u64 = 3;
    #[repr(C, packed)]
    pub struct CreateDumbFramebuffer {
        pub width: u32,
        pub height: u32,

        pub fb_id: usize,
    }

    pub const DUMB_FRAMEBUFFER_MAP_OFFSET: u64 = 4;
    #[repr(C, packed)]
    pub struct DumbFramebufferMapOffset {
        pub fb_id: usize,

        pub offset: usize,
    }

    pub const DESTROY_DUMB_FRAMEBUFFER: u64 = 5;
    #[repr(C, packed)]
    pub struct DestroyDumbFramebuffer {
        pub fb_id: usize,
    }

    pub const UPDATE_PLANE: u64 = 6;
    #[repr(C, packed)]
    pub struct UpdatePlane {
        pub display_id: usize,
        pub fb_id: usize,
        pub damage: Damage,
    }
}
