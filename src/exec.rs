use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use syscall::flag::{O_CLOEXEC, O_RDONLY};
use syscall::{Error, EINTR};

use redox_rt::proc::*;

pub fn main() -> ! {
    let auth = FdGuard::new(
        syscall::open("/scheme/kernel.proc/authority", O_CLOEXEC)
            .expect("failed to get proc authority"),
    );
    let this_thr_fd =
        FdGuard::new(syscall::dup(*auth, b"cur-context").expect("failed to open open_via_dup"));
    let this_thr_fd = unsafe { redox_rt::initialize_freestanding(this_thr_fd) };

    let envs = {
        let mut env = [0_u8; 4096];

        let fd = FdGuard::new(
            syscall::open("/scheme/sys/env", O_RDONLY).expect("bootstrap: failed to open env"),
        );
        let bytes_read = syscall::read(*fd, &mut env).expect("bootstrap: failed to read env");

        if bytes_read >= env.len() {
            // TODO: Handle this, we can allocate as much as we want in theory.
            panic!("env is too large");
        }
        let env = &mut env[..bytes_read];

        let raw_iter = || env.split(|c| *c == b'\n').filter(|var| !var.is_empty());

        let iter = || raw_iter().filter(|var| !var.starts_with(b"INITFS_"));

        iter().map(|var| var.to_owned()).collect::<Vec<_>>()
    };

    extern "C" {
        // The linker script will define this as the location of the initfs header.
        static __initfs_header: u8;
    }

    let initfs_length = unsafe {
        (*(core::ptr::addr_of!(__initfs_header) as *const redox_initfs::types::Header)).initfs_size
    };

    spawn(
        "initfs daemon",
        &auth,
        &this_thr_fd,
        move |write_fd| unsafe {
            // Creating a reference to NULL is UB. Mask the UB for now using black_box.
            // FIXME use a raw pointer and inline asm for reading instead for the initfs header.
            let initfs_start = core::ptr::addr_of!(__initfs_header);
            let initfs_length = initfs_length.get() as usize;

            crate::initfs::run(
                core::slice::from_raw_parts(initfs_start, initfs_length),
                write_fd,
            );
        },
    );

    spawn("process manager", &auth, &this_thr_fd, |write_fd| {
        crate::procmgr::run(write_fd, &auth)
    });
    let init_proc_fd = unsafe { redox_rt::proc::make_init() };

    const CWD: &[u8] = b"/scheme/initfs";
    const DEFAULT_SCHEME: &[u8] = b"initfs";
    let extrainfo = ExtraInfo {
        cwd: Some(CWD),
        default_scheme: Some(DEFAULT_SCHEME),
        sigprocmask: 0,
        sigignmask: 0,
        umask: redox_rt::sys::get_umask(),
        thr_fd: **this_thr_fd,
        proc_fd: **init_proc_fd,
    };

    let path = "/scheme/initfs/bin/init";
    let total_args_envs_auxvpointee_size = path.len()
        + 1
        + envs.len()
        + envs.iter().map(|v| v.len()).sum::<usize>()
        + CWD.len()
        + 1
        + DEFAULT_SCHEME.len()
        + 1;

    let image_file = FdGuard::new(syscall::open(path, O_RDONLY).expect("failed to open init"));
    let memory = FdGuard::new(syscall::open("/scheme/memory", 0).expect("failed to open memory"));

    fexec_impl(
        image_file,
        this_thr_fd,
        init_proc_fd,
        &memory,
        path.as_bytes(),
        [path],
        envs.iter(),
        total_args_envs_auxvpointee_size,
        &extrainfo,
        None,
    )
    .expect("failed to execute init");

    unreachable!()
}

pub(crate) fn spawn(name: &str, auth: &FdGuard, this_thr_fd: &FdGuard, inner: impl FnOnce(usize)) {
    let read = syscall::open("/scheme/pipe", O_CLOEXEC).expect("failed to open sync read pipe");

    // The write pipe will not inherit O_CLOEXEC, but is closed by the daemon later.
    let write = syscall::dup(read, b"write").expect("failed to open sync write pipe");

    match fork_impl(&ForkArgs::Init { this_thr_fd, auth }) {
        Err(err) => {
            panic!("Failed to fork in order to start {name}: {err}");
        }
        // Continue serving the scheme as the child.
        Ok(0) => {
            let _ = syscall::close(read);
        }
        // Return in order to execute init, as the parent.
        Ok(_) => {
            let _ = syscall::close(write);
            loop {
                match syscall::read(read, &mut [0]) {
                    Err(Error { errno: EINTR }) => continue,
                    _ => break,
                }
            }

            return;
        }
    }
    inner(write);
}
