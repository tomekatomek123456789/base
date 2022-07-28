use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use syscall::flag::{O_CLOEXEC, O_RDONLY};

use redox_exec::*;

pub fn main() -> ! {
    let (initfs_offset, initfs_length);

    let envs = {
        let mut env = [0_u8; 4096];

        let fd = FdGuard::new(syscall::open("sys:env", O_RDONLY).expect("bootstrap: failed to open env"));
        let bytes_read = syscall::read(*fd, &mut env).expect("bootstrap: failed to read env");

        if bytes_read >= env.len() {
            // TODO: Handle this, we can allocate as much as we want in theory.
            panic!("env is too large");
        }
        let env = &mut env[..bytes_read];

        let raw_iter = || env.split(|c| *c == b'\n').filter(|var| !var.is_empty());

        let mut initfs_offset_opt = None;
        let mut initfs_length_opt = None;

        for var in raw_iter() {
            let equal_sign = var.iter().position(|c| *c == b'=').expect("malformed environment variable");
            let name = &var[..equal_sign];
            let value = &var[equal_sign + 1..];

            match name {
                b"INITFS_OFFSET" => initfs_offset_opt = core::str::from_utf8(value).ok().and_then(|s| usize::from_str_radix(s, 16).ok()),
                b"INITFS_LENGTH" => initfs_length_opt = core::str::from_utf8(value).ok().and_then(|s| usize::from_str_radix(s, 16).ok()),

                _ => continue,
            }
        }
        initfs_offset = initfs_offset_opt.expect("missing INITFS_OFFSET");
        initfs_length = initfs_length_opt.expect("missing INITFS_LENGTH");

        let iter = || raw_iter().filter(|var| !var.starts_with(b"INITFS_"));
        let env_count = iter().count();

        iter().map(|var| var.to_owned()).collect::<Vec<_>>()
    };
    unsafe {
        use syscall::flag::MapFlags;
        // XXX: It may be a little unsafe to mprotect this after relibc has started, but since only
        // the bootloader can influence the data we use, it should be fine security-wise.
        let _ = syscall::mprotect(initfs_offset, initfs_length, MapFlags::PROT_READ | MapFlags::MAP_PRIVATE).expect("mprotect failed for initfs");

        spawn_initfs(initfs_offset, initfs_length);
    }
    let path = "initfs:bin/init";
    let total_args_envs_size = path.len() + 1 + envs.len() + envs.iter().map(|v| v.len()).sum::<usize>();

    let image_file = FdGuard::new(syscall::open(path, O_RDONLY).expect("failed to open init"));
    let open_via_dup = FdGuard::new(syscall::open("thisproc:current/open_via_dup", 0).expect("failed to open open_via_dup"));
    let memory = FdGuard::new(syscall::open("memory:", 0).expect("failed to open memory"));

    fexec_impl(image_file, open_via_dup, &memory, path.as_bytes(), [path], envs.iter(), total_args_envs_size, None).expect("failed to execute init");

    unreachable!()
}

unsafe fn spawn_initfs(initfs_start: usize, initfs_length: usize) {
    let mut buf = [0; 2];
    syscall::pipe2(&mut buf, syscall::O_CLOEXEC).expect("failed to open sync pipe");
    let [read, write] = buf;

    match redox_exec::fork_impl() {
        Err(err) => {
            panic!("Failed to fork in order to start initfs daemon: {}", err);
        }
        // Continue serving the scheme as the child.
        Ok(0) => {
            let _ = syscall::close(read);
        }
        // Return in order to execute init, as the parent.
        Ok(_) => {
            let _ = syscall::close(write);
            let _ = syscall::read(read, &mut [0]);

            let _ = syscall::chdir("initfs:");

            return;
        }
    }
    crate::initfs::run(core::slice::from_raw_parts(initfs_start as *const u8, initfs_length), write);
}
