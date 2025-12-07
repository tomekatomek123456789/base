use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use syscall::flag::{O_CLOEXEC, O_RDONLY};
use syscall::{Error, EINTR};

use redox_rt::proc::*;

struct Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::max_level()
    }
    fn log(&self, record: &log::Record) {
        let file = record.file().unwrap_or("");
        let line = record.line().unwrap_or(0);
        let level = record.level();
        let msg = record.args();
        let _ = syscall::write(
            1,
            alloc::format!("[{file}:{line} {level}] {msg}\n").as_bytes(),
        );
    }
    fn flush(&self) {}
}

pub fn main() -> ! {
    let auth = FdGuard::open("/scheme/kernel.proc/authority", O_CLOEXEC)
        .expect("failed to get proc authority");
    let this_thr_fd = auth
        .dup(b"cur-context")
        .expect("failed to open open_via_dup")
        .to_upper()
        .unwrap();
    let this_thr_fd = unsafe { redox_rt::initialize_freestanding(this_thr_fd) };

    log::set_max_level(log::LevelFilter::Warn);
    let _ = log::set_logger(&Logger);

    let mut env_bytes = [0_u8; 4096];
    let envs = {
        let fd = FdGuard::open("/scheme/sys/env", O_RDONLY).expect("bootstrap: failed to open env");
        let bytes_read = fd
            .read(&mut env_bytes)
            .expect("bootstrap: failed to read env");

        if bytes_read >= env_bytes.len() {
            // TODO: Handle this, we can allocate as much as we want in theory.
            panic!("env is too large");
        }
        let env_bytes = &mut env_bytes[..bytes_read];

        env_bytes
            .split(|&c| c == b'\n')
            .filter(|var| !var.is_empty())
            .filter(|var| !var.starts_with(b"INITFS_"))
            .collect::<Vec<_>>()
    };

    unsafe extern "C" {
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
    let (init_proc_fd, init_thr_fd) = unsafe { redox_rt::proc::make_init() };
    // from this point, this_thr_fd is no longer valid

    const CWD: &[u8] = b"/scheme/initfs";
    let extrainfo = ExtraInfo {
        cwd: Some(CWD),
        sigprocmask: 0,
        sigignmask: 0,
        umask: redox_rt::sys::get_umask(),
        thr_fd: init_thr_fd.as_raw_fd(),
        proc_fd: init_proc_fd.as_raw_fd(),
    };

    let path = "/scheme/initfs/bin/init";

    let image_file = FdGuard::open(path, O_RDONLY)
        .expect("failed to open init")
        .to_upper()
        .unwrap();
    let memory = FdGuard::open("/scheme/memory", 0)
        .expect("failed to open memory")
        .to_upper()
        .unwrap();

    fexec_impl(
        image_file,
        init_thr_fd,
        init_proc_fd,
        &memory,
        path.as_bytes(),
        &[path.as_bytes()],
        &envs,
        &extrainfo,
        None,
    )
    .expect("failed to execute init");

    unreachable!()
}

pub(crate) fn spawn(
    name: &str,
    auth: &FdGuard,
    this_thr_fd: &FdGuardUpper,
    inner: impl FnOnce(usize),
) {
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
