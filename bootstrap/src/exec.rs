use alloc::borrow::ToOwned;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::CStr;
use core::str::FromStr;

use syscall::data::{GlobalSchemes, KernelSchemeInfo};
use syscall::flag::{O_CLOEXEC, O_RDONLY};
use syscall::CallFlags;
use syscall::{Error, EINTR};

use redox_rt::proc::*;

use crate::KernelSchemeMap;

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

const KERNEL_METADATA_BASE: usize = crate::arch::USERMODE_END - syscall::KERNEL_METADATA_SIZE;

pub fn main() -> ! {
    let mut cursor = KERNEL_METADATA_BASE;
    let kernel_scheme_infos = unsafe {
        let base_ptr = cursor as *const u8;
        let infos_len = *(base_ptr as *const usize);
        let infos_ptr = base_ptr.add(core::mem::size_of::<usize>()) as *const KernelSchemeInfo;
        let slice = core::slice::from_raw_parts(infos_ptr, infos_len);
        cursor += core::mem::size_of::<usize>() // kernel scheme number size
            + infos_len // kernel scheme number
            * core::mem::size_of::<KernelSchemeInfo>();
        slice
    };
    let scheme_creation_cap = unsafe {
        let base_ptr = cursor as *const u8;
        let cap = *(base_ptr as *const usize);
        cap
    };

    let kernel_schemes = KernelSchemeMap::new(kernel_scheme_infos);

    let auth = FdGuard::new(
        *kernel_schemes
            .get(GlobalSchemes::Proc)
            .expect("failed to get proc fd"),
    );
    let pipe_fd = *kernel_schemes
        .get(GlobalSchemes::Pipe)
        .expect("failed to get pipe fd");
    let infos_arc = Arc::new(kernel_schemes);

    let this_thr_fd = auth
        .dup(b"cur-context")
        .expect("failed to open open_via_dup")
        .to_upper()
        .unwrap();
    let this_thr_fd = unsafe { redox_rt::initialize_freestanding(this_thr_fd) };

    let mut env_bytes = [0_u8; 4096];
    let mut envs = {
        let fd = FdGuard::new(
            syscall::openat(
                *infos_arc
                    .get(GlobalSchemes::Sys)
                    .expect("failed to get sys fd"),
                "env",
                O_RDONLY | O_CLOEXEC,
                0,
            )
            .expect("bootstrap: failed to open env"),
        );
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
    //envs.push(b"LD_DEBUG=all");
    envs.push(b"LD_LIBRARY_PATH=/scheme/initfs/lib");

    log::set_max_level(log::LevelFilter::Warn);

    if let Some(log_env) = envs
        .iter()
        .find_map(|var| var.strip_prefix(b"BOOTSTRAP_LOG_LEVEL="))
    {
        if let Ok(Ok(log_level)) = str::from_utf8(&log_env).map(|s| log::LevelFilter::from_str(s)) {
            log::set_max_level(log_level);
        }
    }

    let _ = log::set_logger(&Logger);

    unsafe extern "C" {
        // The linker script will define this as the location of the initfs header.
        static __initfs_header: u8;
    }

    let initfs_length = unsafe {
        (*(core::ptr::addr_of!(__initfs_header) as *const redox_initfs::types::Header)).initfs_size
    };

    let infos_arc_clone = infos_arc.clone();
    let initfs_fd = spawn(
        "initfs daemon",
        &auth,
        &this_thr_fd,
        pipe_fd,
        move |write_fd| unsafe {
            // Creating a reference to NULL is UB. Mask the UB for now using black_box.
            // FIXME use a raw pointer and inline asm for reading instead for the initfs header.
            let initfs_start = core::ptr::addr_of!(__initfs_header);
            let initfs_length = initfs_length.get() as usize;

            crate::initfs::run(
                core::slice::from_raw_parts(initfs_start, initfs_length),
                write_fd,
                &infos_arc_clone,
                scheme_creation_cap,
            );
        },
    );

    let infos_arc_clone = infos_arc.clone();
    let proc_fd = spawn(
        "process manager",
        &auth,
        &this_thr_fd,
        pipe_fd,
        |write_fd| crate::procmgr::run(write_fd, &auth, &infos_arc_clone, scheme_creation_cap),
    );

    let infos_arc_clone = infos_arc.clone();
    let initns_fd = spawn(
        "init namespace manager",
        &auth,
        &this_thr_fd,
        pipe_fd,
        |write_fd| {
            crate::initnsmgr::run(
                write_fd,
                &infos_arc_clone,
                initfs_fd,
                proc_fd,
                scheme_creation_cap,
            )
        },
    );

    let (init_proc_fd, init_thr_fd) = unsafe { make_init(proc_fd) };
    // from this point, this_thr_fd is no longer valid

    const CWD: &[u8] = b"/scheme/initfs";
    let extrainfo = ExtraInfo {
        cwd: Some(CWD),
        sigprocmask: 0,
        sigignmask: 0,
        umask: redox_rt::sys::get_umask(),
        thr_fd: init_thr_fd.as_raw_fd(),
        proc_fd: init_proc_fd.as_raw_fd(),
        ns_fd: Some(initns_fd),
    };

    let path = "/bin/init";

    let image_file = FdGuard::new(
        syscall::openat(initfs_fd, path, O_RDONLY | O_CLOEXEC, 0).expect("failed to open init"),
    )
    .to_upper()
    .unwrap();

    drop(infos_arc);

    let exe_path = alloc::format!("/scheme/initfs{}", path);

    let FexecResult::Interp {
        path: interp_path,
        interp_override,
    } = fexec_impl(
        image_file,
        init_thr_fd,
        init_proc_fd,
        exe_path.as_bytes(),
        &[exe_path.as_bytes()],
        &envs,
        &extrainfo,
        None,
    )
    .expect("failed to execute init");

    // According to elf(5), PT_INTERP requires that the interpreter path be
    // null-terminated. Violating this should therefore give the "format error" ENOEXEC.
    let interp_cstr = CStr::from_bytes_with_nul(&interp_path).expect("interpreter not valid C str");
    let interp_file = FdGuard::new(
        syscall::openat(
            initns_fd, // initns, not initfs!
            interp_cstr.to_str().expect("interpreter not UTF-8"),
            O_RDONLY | O_CLOEXEC,
            0,
        )
        .expect("failed to open dynamic linker"),
    )
    .to_upper()
    .unwrap();

    fexec_impl(
        interp_file,
        init_thr_fd,
        init_proc_fd,
        exe_path.as_bytes(),
        &[exe_path.as_bytes()],
        &envs,
        &extrainfo,
        Some(interp_override),
    )
    .expect("failed to execute init");

    unreachable!()
}

pub(crate) fn spawn(
    name: &str,
    auth: &FdGuard,
    this_thr_fd: &FdGuardUpper,
    pipe_fd: usize,
    inner: impl FnOnce(usize) -> !,
) -> usize {
    let read = syscall::openat(pipe_fd, "", O_CLOEXEC, 0).expect("failed to open sync read pipe");

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

            let mut new_fd = usize::MAX;
            let fd_bytes = unsafe {
                core::slice::from_raw_parts_mut(
                    core::slice::from_mut(&mut new_fd).as_mut_ptr() as *mut u8,
                    core::mem::size_of::<usize>(),
                )
            };
            loop {
                match syscall::call_ro(read, fd_bytes, CallFlags::FD | CallFlags::FD_UPPER, &[]) {
                    Err(Error { errno: EINTR }) => continue,
                    _ => break,
                }
            }

            return new_fd;
        }
    }
    inner(write)
}
