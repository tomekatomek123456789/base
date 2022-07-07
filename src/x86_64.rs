use syscall::flag::MapFlags;

mod offsets {
    extern "C" {
        // text (R-X)
        static __text_start: u8;
        static __text_end: u8;
        // rodata (R--)
        static __rodata_start: u8;
        static __rodata_end: u8;
        // data+bss (RW-)
        static __data_start: u8;
        static __bss_end: u8;

        static __end: u8;
    }
    pub fn text() -> (usize, usize) {
        unsafe { (&__text_start as *const u8 as usize, &__text_end as *const u8 as usize) }
    }
    pub fn rodata() -> (usize, usize) {
        unsafe { (&__rodata_start as *const u8 as usize, &__rodata_end as *const u8 as usize) }
    }
    pub fn data_and_bss() -> (usize, usize) {
        unsafe { (&__data_start as *const u8 as usize, &__bss_end as *const u8 as usize) }
    }
    #[allow(dead_code)]
    pub fn end() -> usize {
        unsafe { &__end as *const u8 as usize }
    }
}

// relibc linkage stuff
#[no_mangle]
extern "C" fn _init() {}
#[no_mangle]
extern "C" fn _fini() {}

extern "C" fn nop() {}

#[no_mangle]
static __preinit_array_start: extern "C" fn() = nop;
#[no_mangle]
static __preinit_array_end: extern "C" fn() = nop;
#[no_mangle]
static __init_array_start: extern "C" fn() = nop;
#[no_mangle]
static __init_array_end: extern "C" fn() = nop;

#[no_mangle]
static __fini_array_start: extern "C" fn() = nop;
#[no_mangle]
static __fini_array_end: extern "C" fn() = nop;

#[no_mangle]
pub unsafe extern "sysv64" fn start() -> ! {
    // Remap self, from the previous RWX

    let (text_start, text_end) = offsets::text();
    let (rodata_start, rodata_end) = offsets::rodata();
    let (data_start, data_end) = offsets::data_and_bss();

    let _ = syscall::open("debug:", syscall::O_RDONLY); // stdin
    let _ = syscall::open("debug:", syscall::O_WRONLY); // stdout
    let _ = syscall::open("debug:", syscall::O_WRONLY); // stderr

    let _ = syscall::mprotect(text_start, text_end - text_start, MapFlags::PROT_READ | MapFlags::PROT_EXEC | MapFlags::MAP_PRIVATE).expect("mprotect failed for .text");
    let _ = syscall::mprotect(rodata_start, rodata_end - rodata_start, MapFlags::PROT_READ | MapFlags::MAP_PRIVATE).expect("mprotect failed for .rodata");
    let _ = syscall::mprotect(data_start, data_end - data_start, MapFlags::PROT_READ | MapFlags::PROT_WRITE | MapFlags::MAP_PRIVATE).expect("mprotect failed for .data/.bss");

    extern "C" {
        fn relibc_start(stack: usize);
    }
    use goblin::elf::header::header64::Header;
    use memoffset::offset_of;

    let stack = [
        // argc
        0,
        // argv null terminator
        0_usize,
        // envp null terminator
        0_usize,

        // Make the TLS part of ld.so happy, even though we do not use TLS.
        syscall::AT_PHDR,
        // The kernel loads the entire ELF, so the program header offset can be trivially received.
        // TODO: Use goblin for the ELF header (except rust accepts no null pointers...).
        (offset_of!(Header, e_phoff) as *mut u64).read() as usize,
        syscall::AT_PHENT,
        (offset_of!(Header, e_phentsize) as *mut u16).read() as usize,
        syscall::AT_PHNUM,
        (offset_of!(Header, e_phnum) as *mut u16).read() as usize,
        // auxv null terminator
        syscall::AT_NULL,
        0,
    ];
    relibc_start(stack.as_ptr() as usize);
    panic!();
}
