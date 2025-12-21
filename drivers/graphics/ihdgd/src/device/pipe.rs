use common::io::{Io, MmioPtr};
use syscall::error::Result;

use super::MmioRegion;

pub const PLANE_CTL_ENABLE: u32 = 1 << 31;

pub const PLANE_WM_ENABLE: u32 = 1 << 31;
pub const PLANE_WM_LINES_SHIFT: u32 = 14;

pub struct Plane {
    pub name: &'static str,
    pub index: usize,
    pub buf_cfg: MmioPtr<u32>,
    pub color_ctl: Option<MmioPtr<u32>>,
    pub color_ctl_gamma_disable: u32,
    pub ctl: MmioPtr<u32>,
    pub ctl_source_rgb_8888: u32,
    pub ctl_source_mask: u32,
    pub offset: MmioPtr<u32>,
    pub pos: MmioPtr<u32>,
    pub size: MmioPtr<u32>,
    pub stride: MmioPtr<u32>,
    pub surf: MmioPtr<u32>,
    pub wm: [MmioPtr<u32>; 8],
    pub wm_trans: MmioPtr<u32>,
}

impl Plane {
    pub fn dump(&self) {
        eprint!("Plane {}", self.name);
        eprint!(" buf_cfg {:08X}", self.buf_cfg.read());
        if let Some(reg) = &self.color_ctl {
            eprint!(" color_ctl {:08X}", reg.read());
        }
        eprint!(" ctl {:08X}", self.ctl.read());
        eprint!(" offset {:08X}", self.offset.read());
        eprint!(" pos {:08X}", self.offset.read());
        eprint!(" size {:08X}", self.size.read());
        eprint!(" stride {:08X}", self.stride.read());
        eprint!(" surf {:08X}", self.surf.read());
        for i in 0..self.wm.len() {
            eprint!(" wm_{} {:08X}", i, self.wm[i].read());
        }
        eprint!(" wm_trans {:08X}", self.wm_trans.read());
        eprintln!();
    }
}

pub struct Pipe {
    pub name: &'static str,
    pub index: usize,
    pub planes: Vec<Plane>,
    pub bottom_color: MmioPtr<u32>,
    pub misc: MmioPtr<u32>,
    pub srcsz: MmioPtr<u32>,
}

impl Pipe {
    pub fn dump(&self) {
        eprint!("Pipe {}", self.name);
        eprint!(" bottom_color {:08X}", self.bottom_color.read());
        eprint!(" misc {:08X}", self.misc.read());
        eprint!(" srcsz {:08X}", self.srcsz.read());
        eprintln!();
    }

    pub fn kabylake(gttmm: &MmioRegion) -> Result<Vec<Self>> {
        let mut pipes = Vec::with_capacity(3);
        for (i, name) in ["A", "B", "C"].iter().enumerate() {
            let mut planes = Vec::new();
            //TODO: cursor plane
            for (j, name) in ["1", "2", "3"].iter().enumerate() {
                planes.push(Plane {
                    name,
                    index: j,
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_BUF_CFG
                    buf_cfg: unsafe { gttmm.mmio(0x7027C + i * 0x1000 + j * 0x100)? },
                    // N/A
                    color_ctl: None,
                    color_ctl_gamma_disable: 0,
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_CTL
                    ctl: unsafe { gttmm.mmio(0x70180 + i * 0x1000 + j * 0x100)? },
                    ctl_source_rgb_8888: 0b0100 << 24,
                    ctl_source_mask: 0b1111 << 24,
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_OFFSET
                    offset: unsafe { gttmm.mmio(0x701A4 + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_POS
                    pos: unsafe { gttmm.mmio(0x7018C + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_SIZE
                    size: unsafe { gttmm.mmio(0x70190 + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_STRIDE
                    stride: unsafe { gttmm.mmio(0x70188 + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_SURF
                    surf: unsafe { gttmm.mmio(0x7019C + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-KBL-Vol 2c-1.17 PLANE_WM
                    wm: [
                        unsafe { gttmm.mmio(0x70240 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70244 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70248 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x7024C + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70250 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70254 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70258 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x7025C + i * 0x1000 + j * 0x100)? },
                    ],
                    wm_trans: unsafe { gttmm.mmio(0x70268 + i * 0x1000 + j * 0x100)? },
                });
            }
            pipes.push(Pipe {
                name,
                index: i,
                planes,
                // IHD-OS-KBL-Vol 2c-1.17 PIPE_BOTTOM_COLOR
                bottom_color: unsafe { gttmm.mmio(0x70034 + i * 0x1000)? },
                // IHD-OS-KBL-Vol 2c-1.17 PIPE_MISC
                misc: unsafe { gttmm.mmio(0x70030 + i * 0x1000)? },
                // IHD-OS-KBL-Vol 2c-1.17 PIPE_SRCSZ
                srcsz: unsafe { gttmm.mmio(0x6001C + i * 0x1000)? },
            })
        }
        Ok(pipes)
    }

    pub fn tigerlake(gttmm: &MmioRegion) -> Result<Vec<Self>> {
        let mut pipes = Vec::with_capacity(4);
        for (i, name) in ["A", "B", "C", "D"].iter().enumerate() {
            let mut planes = Vec::new();
            //TODO: cursor plane
            for (j, name) in ["1", "2", "3", "4", "5", "6", "7"].iter().enumerate() {
                planes.push(Plane {
                    name,
                    index: j,
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_BUF_CFG
                    buf_cfg: unsafe { gttmm.mmio(0x7027C + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_COLOR_CTL
                    color_ctl: Some(unsafe { gttmm.mmio(0x701CC + i * 0x1000 + j * 0x100)? }),
                    color_ctl_gamma_disable: 1 << 13,
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_CTL
                    ctl: unsafe { gttmm.mmio(0x70180 + i * 0x1000 + j * 0x100)? },
                    ctl_source_rgb_8888: 0b01000 << 23,
                    ctl_source_mask: 0b11111 << 23,
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_OFFSET
                    offset: unsafe { gttmm.mmio(0x701A4 + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_POS
                    pos: unsafe { gttmm.mmio(0x7018C + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_SIZE
                    size: unsafe { gttmm.mmio(0x70190 + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_STRIDE
                    stride: unsafe { gttmm.mmio(0x70188 + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_SURF
                    surf: unsafe { gttmm.mmio(0x7019C + i * 0x1000 + j * 0x100)? },
                    // IHD-OS-TGL-Vol 2c-12.21 PLANE_WM
                    wm: [
                        unsafe { gttmm.mmio(0x70240 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70244 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70248 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x7024C + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70250 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70254 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x70258 + i * 0x1000 + j * 0x100)? },
                        unsafe { gttmm.mmio(0x7025C + i * 0x1000 + j * 0x100)? },
                    ],
                    wm_trans: unsafe { gttmm.mmio(0x70268 + i * 0x1000 + j * 0x100)? },
                });
            }
            pipes.push(Pipe {
                name,
                index: i,
                planes,
                // IHD-OS-TGL-Vol 2c-12.21 PIPE_BOTTOM_COLOR
                bottom_color: unsafe { gttmm.mmio(0x70034 + i * 0x1000)? },
                // IHD-OS-TGL-Vol 2c-12.21 PIPE_MISC
                misc: unsafe { gttmm.mmio(0x70030 + i * 0x1000)? },
                // IHD-OS-TGL-Vol 2c-12.21 PIPE_SRCSZ
                srcsz: unsafe { gttmm.mmio(0x6001C + i * 0x1000)? },
            })
        }
        Ok(pipes)
    }
}
