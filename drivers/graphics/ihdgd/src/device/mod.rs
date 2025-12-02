use common::{io::{Io, MmioPtr}, timeout::Timeout};
use embedded_hal::prelude::*;
use pcid_interface::PciFunction;
use range_alloc::RangeAllocator;
use std::{collections::VecDeque, mem, ptr, sync::Arc, time::Duration};
use syscall::error::{Error, Result, EIO, ENODEV, ERANGE};

mod aux;
use self::aux::*;
mod ddi;
use self::ddi::*;
mod dpll;
use self::dpll::*;
mod gmbus;
pub use self::gmbus::*;
mod gpio;
pub use self::gpio::*;
mod hal;
pub use self::hal::*;
mod pipe;
use self::pipe::*;
mod power;
use self::power::*;
mod scheme;
use self::scheme::*;
mod transcoder;
use self::transcoder::*;

//TODO: move to common?
pub struct CallbackGuard<'a, T, F: FnOnce(&mut T)> {
    value: &'a mut T,
    fini: Option<F>,
}

impl<'a, T, F: FnOnce(&mut T)> CallbackGuard<'a, T, F> {
    // Note that fini will also run if init fails
    pub fn new(value: &'a mut T, init: impl FnOnce(&mut T) -> Result<()>, fini: F) -> Result<Self> {
        let mut this = Self {
            value,
            fini: Some(fini),
        };
        init(&mut this.value)?;
        Ok(this)
    }
}

impl<'a, T, F: FnOnce(&mut T)> Drop for CallbackGuard<'a, T, F> {
    fn drop(&mut self) {
        let fini = self.fini.take().unwrap();
        fini(&mut self.value);
    }
}

pub struct ChangeDetect {
    name: &'static str,
    reg: MmioPtr<u32>,
    value: u32,
}

impl ChangeDetect {
    fn new(name: &'static str, reg: MmioPtr<u32>) -> Self {
        let value = reg.read();
        Self {
            name,
            reg,
            value,
        }
    }

    fn log(&self) {
        log::info!("{} {:08X}", self.name, self.value);
    }

    fn check(&mut self) {
        let value = self.reg.read();
        if value != self.value {
            self.value = value;
            self.log();
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DeviceKind {
    KabyLake,
    TigerLake,
    Alchemist,
}

pub enum Event {
    DdiHotplug(&'static str),
}

pub struct InterruptRegs {
    // Interrupt status register, has live status of interrupts
    pub isr: MmioPtr<u32>,
    // Interrupt mask register, masks isr for iir, 0 is unmasked
    pub imr: MmioPtr<u32>,
    // Interrupt identity register, write 1 to clear
    pub iir: MmioPtr<u32>,
    // Interrupt enable register, 1 allows interrupt to propogate
    pub ier: MmioPtr<u32>,
}

pub struct Interrupter {
    change_detects: Vec<ChangeDetect>,
    display_int_ctl: MmioPtr<u32>,
    display_int_ctl_enable: u32,
    display_int_ctl_sde: u32,
    gfx_mstr_intr: Option<MmioPtr<u32>>,
    gfx_mstr_intr_display: u32,
    gfx_mstr_intr_enable: u32,
    sde_interrupt: InterruptRegs,
}

#[derive(Debug)]
pub struct MmioRegion {
    phys: usize,
    virt: usize,
    size: usize,
}

impl MmioRegion {
    fn new(phys: usize, size: usize, memory_type: common::MemoryType) -> Result<Self> {
        let virt = unsafe {
            common::physmap(
                phys,
                size,
                common::Prot::RW,
                memory_type,
            )? as usize
        };
        Ok(Self {
            phys,
            virt,
            size,
        })
    }

    unsafe fn mmio(&self, offset: usize) -> Result<MmioPtr<u32>> {
        // Any errors here will return ERANGE
        let err = Error::new(ERANGE);
        if offset.checked_add(mem::size_of::<u32>()).ok_or(err)? > self.size {
            return Err(err);
        }
        let addr = self.virt.checked_add(offset).ok_or(err)?;
        Ok(unsafe { MmioPtr::new(addr as *mut u32) })
    }
}

impl Drop for MmioRegion {
    fn drop(&mut self) {
        unsafe {
            let _ = libredox::call::munmap(self.virt as *mut (), self.size);
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum VideoInput {
    Hdmi,
    Dp,
}

pub struct Device {
    kind: DeviceKind,
    alloc_buffers: RangeAllocator<u32>,
    alloc_surfaces: RangeAllocator<u32>,
    ddis: Vec<Ddi>,
    dpclka_cfgcr0: Option<MmioPtr<u32>>,
    dplls: Vec<Dpll>,
    events: VecDeque<Event>,
    framebuffers: Vec<DeviceFb>,
    int: Interrupter,
    gttmm: Arc<MmioRegion>,
    gm: MmioRegion,
    gmbus: Gmbus,
    pipes: Vec<Pipe>,
    power_wells: PowerWells,
    ref_freq: u64,
    transcoders: Vec<Transcoder>,
}

impl Device {
    pub fn new(func: &PciFunction) -> Result<Self> {
        let kind = match (func.full_device_id.vendor_id, func.full_device_id.device_id) {
            // Kaby Lake
            (0x8086, 0x5912) |
            (0x8086, 0x5916) |
            (0x8086, 0x591B) |
            (0x8086, 0x591E) |
            (0x8086, 0x5926) |
            // Comet Lake, seems to be compatible with Kaby Lake
            (0x8086, 0x9B21) |
            (0x8086, 0x9B41) |
            (0x8086, 0x9BA4) |
            (0x8086, 0x9BAA) |
            (0x8086, 0x9BAC) |
            (0x8086, 0x9BC4) |
            (0x8086, 0x9BC5) |
            (0x8086, 0x9BC6) |
            (0x8086, 0x9BC8) |
            (0x8086, 0x9BCA) |
            (0x8086, 0x9BCC) |
            (0x8086, 0x9BE6) |
            (0x8086, 0x9BF6) => {
                DeviceKind::KabyLake
            }
            // Tiger Lake
            (0x8086, 0x9A40) |
            (0x8086, 0x9A49) |
            (0x8086, 0x9A60) |
            (0x8086, 0x9A68) |
            (0x8086, 0x9A70) |
            (0x8086, 0x9A78) => {
                DeviceKind::TigerLake
            }
            // Alchemist
            (0x8086, 0x5690) | // A770M
            (0x8086, 0x5691) | // A730M
            (0x8086, 0x5692) | // A550M
            (0x8086, 0x5693) | // A370M
            (0x8086, 0x5694) | // A350M
            (0x8086, 0x5696) | // A570M
            (0x8086, 0x5697) | // A530M
            (0x8086, 0x56A0) | // A770
            (0x8086, 0x56A1) | // A750
            (0x8086, 0x56A5) | // A380
            (0x8086, 0x56A6) | // A310
            (0x8086, 0x56B0) | // Pro A30M
            (0x8086, 0x56B1) | // Pro A40/A50
            (0x8086, 0x56B2) | // Pro A60M
            (0x8086, 0x56B3) | // Pro A60
            (0x8086, 0x56C0) | // GPU Flex 170
            (0x8086, 0x56C1)   // GPU Flex 140
            => {
                DeviceKind::Alchemist
            }
            (vendor_id, device_id) => {
                log::error!("unsupported ID {:04X}:{:04X}", vendor_id, device_id);
                return Err(Error::new(ENODEV));
            }
        };

        let gttmm = {
            let (phys, size) = func.bars[0].expect_mem();
            Arc::new(MmioRegion::new(phys, size, common::MemoryType::Uncacheable)?)
        };
        log::info!("GTTMM {:X?}", gttmm);
        let gm = {
            let (phys, size) = func.bars[2].expect_mem();
            MmioRegion::new(phys, size, common::MemoryType::WriteCombining)?
        };
        log::info!("GM {:X?}", gm);
        /* IOBAR not used, not present on all generations
        let iobar = func.bars[4].expect_port();
        log::debug!("IOBAR {:X?}", iobar);
        */

        // GMBUS seems to be stable for all generations
        let gmbus = unsafe { Gmbus::new(&gttmm)? };

        let dpclka_cfgcr0;
        let int;
        let ref_freq;
        match kind {
            DeviceKind::KabyLake => {
                dpclka_cfgcr0 = None;

                int = Interrupter {
                    change_detects: Vec::new(),
                    // IHD-OS-KBL-Vol 2c-1.17 MASTER_INT_CTL
                    display_int_ctl: unsafe { gttmm.mmio(0x44200)? },
                    display_int_ctl_enable: 1 << 31,
                    display_int_ctl_sde: 1 << 23,
                    gfx_mstr_intr: None,
                    gfx_mstr_intr_display: 0,
                    gfx_mstr_intr_enable: 0,
                    sde_interrupt: InterruptRegs {
                        isr: unsafe { gttmm.mmio(0xC4000)? },
                        imr: unsafe { gttmm.mmio(0xC4004)? },
                        iir: unsafe { gttmm.mmio(0xC4008)? },
                        ier: unsafe { gttmm.mmio(0xC400C)? },
                    }
                };

                // IHD-OS-KBL-Vol 12-1.17
                ref_freq = 24_000_000;
            }
            DeviceKind::TigerLake | DeviceKind::Alchemist => {
                // TigerLake: IHD-OS-TGL-Vol 2c-12.21
                // Alchemist: IHD-OS-ACM-Vol 2c-3.23

                dpclka_cfgcr0 = Some(unsafe { gttmm.mmio(0x164280)? });

                let dssm = unsafe { gttmm.mmio(0x51004)? };
                log::debug!("dssm {:08X}", dssm.read());

                const DSSM_REF_FREQ_24_MHZ: u32 = 0b000 << 29;
                const DSSM_REF_FREQ_19_2_MHZ: u32 = 0b001 << 29;
                const DSSM_REF_FREQ_38_4_MHZ: u32 = 0b010 << 29;
                const DSSM_REF_FREQ_MASK: u32 = 0b111 << 29;
                ref_freq = match dssm.read() & DSSM_REF_FREQ_MASK {
                    DSSM_REF_FREQ_24_MHZ => {
                        24_000_000
                    },
                    DSSM_REF_FREQ_19_2_MHZ => {
                        19_200_000
                    },
                    DSSM_REF_FREQ_38_4_MHZ => {
                        38_400_000
                    },
                    unknown => {
                        log::error!("unknown DSSM reference frequency {}", unknown);
                        return Err(Error::new(EIO));
                    }
                };

                int = Interrupter {
                    change_detects: vec![
                        ChangeDetect::new("de_hpd_interrupt", unsafe { gttmm.mmio(0x44470)? }),
                        ChangeDetect::new("de_port_interrupt", unsafe { gttmm.mmio(0x44440)? }),
                        ChangeDetect::new("shotplug_ctl_ddi", unsafe { gttmm.mmio(0xC4030)? }),
                        ChangeDetect::new("shotplug_ctl_tc", unsafe { gttmm.mmio(0xC4034)? }),
                        ChangeDetect::new("tbt_hotplug_ctl", unsafe { gttmm.mmio(0x44030)? }),
                        ChangeDetect::new("tc_hotplug_ctl", unsafe { gttmm.mmio(0x44038)? }),
                    ],
                    display_int_ctl: unsafe { gttmm.mmio(0x44200)? },
                    display_int_ctl_enable: 1 << 31,
                    display_int_ctl_sde: 1 << 23,
                    gfx_mstr_intr: Some(unsafe { gttmm.mmio(0x190010)? }),
                    gfx_mstr_intr_display: 1 << 16,
                    gfx_mstr_intr_enable: 1 << 31,
                    sde_interrupt: InterruptRegs {
                        isr: unsafe { gttmm.mmio(0xC4000)? },
                        imr: unsafe { gttmm.mmio(0xC4004)? },
                        iir: unsafe { gttmm.mmio(0xC4008)? },
                        ier: unsafe { gttmm.mmio(0xC400C)? },
                    }
                };
            }
        }

        let ddis;
        let dplls;
        let pipes;
        let power_wells;
        let transcoders;
        match kind {
            DeviceKind::KabyLake => {
                ddis = Ddi::kabylake(&gttmm)?;
                //TODO: kaby lake dplls
                dplls = Vec::new();
                pipes = Pipe::kabylake(&gttmm)?;
                power_wells = PowerWells::kabylake(&gttmm)?;
                transcoders = Transcoder::kabylake(&gttmm)?;
            },
            DeviceKind::TigerLake => {
                ddis = Ddi::tigerlake(&gttmm)?;
                dplls = Dpll::tigerlake(&gttmm)?;
                pipes = Pipe::tigerlake(&gttmm)?;
                power_wells = PowerWells::tigerlake(&gttmm)?;
                transcoders = Transcoder::tigerlake(&gttmm)?;
            },
            DeviceKind::Alchemist => {
                // Many registers are identical to tigerlake
                dplls = Dpll::tigerlake(&gttmm)?;
                pipes = Pipe::tigerlake(&gttmm)?;
                transcoders = Transcoder::tigerlake(&gttmm)?;
                // Power wells are distinct
                ddis = Ddi::alchemist(&gttmm)?;
                power_wells = PowerWells::alchemist(&gttmm)?;
            }
        }


        let mut this = Self {
            kind,
            alloc_buffers: RangeAllocator::new(0..1024), //TODO: get number of available buffers
            alloc_surfaces: RangeAllocator::new(0..gm.size as u32),
            ddis,
            dpclka_cfgcr0,
            dplls,
            events: VecDeque::new(),
            framebuffers: Vec::new(),
            int,
            gttmm,
            gm,
            gmbus,
            pipes,
            power_wells,
            ref_freq,
            transcoders,
        };
        this.init()?;
        Ok(this)
    }

    pub fn init(&mut self) -> Result<()> {
        // Discover current framebuffers
        self.alloc_buffers.reset();
        self.alloc_surfaces.reset();
        self.framebuffers.clear();
        for pipe in self.pipes.iter() {
            for plane in pipe.planes.iter() {
                if plane.ctl.readf(PLANE_CTL_ENABLE) {
                    let buf_cfg = plane.buf_cfg.read();
                    let buffer_start = buf_cfg & 0x7FF;
                    let buffer_end = (buf_cfg >> 16) & 0x7FF;
                    self.alloc_buffers.allocate_exact_range(buffer_start .. (buffer_end + 1)).map_err(|err| {
                        log::warn!("failed to allocate pre-existing buffer blocks {} to {}: {:?}", buffer_start, buffer_end, err);
                        Error::new(EIO)
                    })?;

                    let size = plane.size.read();
                    let width = (size & 0xFFFF) + 1;
                    let height = ((size >> 16) & 0xFFFF) + 1;
                    let stride_16 = plane.stride.read() & 0x7FF;
                    //TODO: this will be wrong for tiled planes
                    let stride = stride_16 * 16;
                    let surf = plane.surf.read() & 0xFFFFF000;
                    //TODO: read bits per pixel
                    let surf_size = (stride * height * 4).next_multiple_of(4096);
                    self.alloc_surfaces.allocate_exact_range(surf .. (surf + surf_size)).map_err(|err| {
                        log::warn!("failed to allocate pre-existing surface at 0x{:x} of size {}: {:?}", surf, surf_size, err);
                        Error::new(EIO)
                    })?;

                    self.framebuffers.push(unsafe {
                        DeviceFb::new(
                            (self.gm.virt + surf as usize) as *mut u32,
                            width as usize,
                            height as usize,
                            stride as usize,
                            false
                        )
                    });
                }
            }
        }

        // Probe all DDIs
        let ddi_names: Vec<&str> = self.ddis.iter().map(|ddi| ddi.name).collect();
        for ddi_name in ddi_names {
            self.probe_ddi(ddi_name)?;
        }

        self.dump();

        log::info!("device initialized with {} framebuffers", self.framebuffers.len());

        // Enable SDE interrupts
        {
            let mut mask = 0;
            for ddi in self.ddis.iter() {
                if let Some(sde_interrupt_hotplug) = ddi.sde_interrupt_hotplug {
                    mask |= sde_interrupt_hotplug;
                }
            }
            let sde_int = &mut self.int.sde_interrupt;
            // Enable DDI hotplug interrupts
            sde_int.ier.write(mask);
            // Clear identity register
            sde_int.iir.write(sde_int.iir.read());
            // Unmask all interrupts
            sde_int.imr.write(0);
        }
        // Enable display interrupts
        self.int.display_int_ctl.write(self.int.display_int_ctl_enable);
        if let Some(gfx_mstr_intr) = &mut self.int.gfx_mstr_intr {
            // Enable graphics interrupts
            gfx_mstr_intr.write(self.int.gfx_mstr_intr_enable);
        }
        for change_detect in self.int.change_detects.iter_mut() {
            change_detect.log();
        }

        Ok(())
    }

    pub fn dump(&self) {
        for ddi in self.ddis.iter() {
            if ddi.buf_ctl.readf(DDI_BUF_CTL_ENABLE) {
                ddi.dump();
            }
        }

        if let Some(dpclka_cfgcr0) = &self.dpclka_cfgcr0 {
            eprintln!("dpclka_cfgcr0 {:08X}", dpclka_cfgcr0.read());
        }
        for dpll in self.dplls.iter() {
            if dpll.enable.readf(DPLL_ENABLE_ENABLE) {
                dpll.dump();
            }
        }

        for (transcoder, pipe) in self.transcoders.iter().zip(self.pipes.iter()) {
            if transcoder.conf.readf(TRANS_CONF_ENABLE) {
                transcoder.dump();
                pipe.dump();
                for plane in pipe.planes.iter() {
                    if plane.index == 0 || plane.ctl.readf(PLANE_CTL_ENABLE) {
                        eprint!("  ");
                        plane.dump();
                    }
                }
            }
        }
    }

    pub fn probe_ddi(&mut self, name: &str) -> Result<bool> {
        let Some(ddi) = self.ddis.iter_mut().find(|ddi| ddi.name == name) else {
            log::warn!("DDI {} not found", name);
            return Err(Error::new(EIO));
        };

        // Enable DDI power well
        self.power_wells.enable_well_by_ddi(ddi.name)?;

        //TODO: init port if needed
        if let Some(port_comp_dw0) = ddi.port_comp(PortCompReg::Dw0) {
            log::debug!("PORT_COMP_DW0_{}: {:08X}", ddi.name, port_comp_dw0.read());
        }

        let mut aux_read_edid = |ddi: &mut Ddi| -> Result<[u8; 128]> {
            //TODO: BLOCK TCCOLD?

            //TODO: the request can be shared by multiple DDIs
            let pwr_well_ctl_aux_request = ddi.pwr_well_ctl_aux_request;
            let pwr_well_ctl_aux_state = ddi.pwr_well_ctl_aux_state;
            let mut pwr_well_ctl_aux = unsafe { MmioPtr::new(self.power_wells.ctl_aux.as_mut_ptr()) };
            let _pwr_guard = CallbackGuard::new(
                &mut pwr_well_ctl_aux,
                |pwr_well_ctl_aux| {
                    // Enable aux power
                    pwr_well_ctl_aux.writef(pwr_well_ctl_aux_request, true);
                    let timeout = Timeout::from_micros(1500);
                    while !pwr_well_ctl_aux.readf(pwr_well_ctl_aux_state) {
                        timeout.run().map_err(|()| {
                            log::debug!("timeout while requesting DDI {} aux power", ddi.name);
                            Error::new(EIO)
                        })?;
                    }
                    Ok(())
                },
                |pwr_well_ctl_aux| {
                    // Disable aux power
                    pwr_well_ctl_aux.writef(pwr_well_ctl_aux_request, false);
                }
            )?;

            let mut edid_data = [0; 128];
            Aux::new(ddi).write_read(
                0x50,
                &[0x00],
                &mut edid_data
            ).map_err(|_err| {
                Error::new(EIO)
            })?;

            Ok(edid_data)
        };

        let mut gmbus_read_edid = |ddi: &mut Ddi| -> Result<[u8; 128]> {
            let Some(pin_pair) = ddi.gmbus_pin_pair else {
                return Err(Error::new(EIO));
            };

            let mut edid_data = [0; 128];
            self.gmbus.pin_pair(pin_pair).write_read(
                0x50,
                &[0x00],
                &mut edid_data
            ).map_err(|_err| {
                Error::new(EIO)
            })?;

            Ok(edid_data)
        };

        let mut gpio_read_edid = |ddi: &mut Ddi| -> Result<[u8; 128]> {
            let Some(port) = &ddi.gpio_port else {
                return Err(Error::new(EIO));
            };

            let mut edid_data = [0; 128];
            let i2c_freq = 100_000.0;
            bitbang_hal::i2c::I2cBB::new(
                unsafe { port.clock(&self.gttmm)? },
                unsafe { port.data(&self.gttmm)? },
                HalTimer::new(Duration::from_secs_f64(1.0 / i2c_freq))
            ).write_read(
                0x50,
                &[0x00],
                &mut edid_data
            ).map_err(|_err| {
                Error::new(EIO)
            })?;

            Ok(edid_data)
        };

        let (source, edid_data) = match aux_read_edid(ddi) {
            Ok(edid_data) => ("AUX", edid_data),
            Err(err) => {
                log::debug!("DDI {} failed to read EDID from AUX: {}", ddi.name, err);
                match gmbus_read_edid(ddi) {
                    Ok(edid_data) => ("GMBUS", edid_data),
                    Err(err) => {
                        log::debug!("DDI {} failed to read EDID from GMBUS: {}", ddi.name, err);
                        match gpio_read_edid(ddi) {
                            Ok(edid_data) => ("GPIO", edid_data),
                            Err(err) => {
                                log::debug!("DDI {} failed to read EDID from GPIO: {}", ddi.name, err);
                                // Will try again but not fail the driver
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        };

        let edid = match edid::parse(&edid_data).to_full_result() {
            Ok(edid) => {
                log::info!("DDI {} EDID from {}: {:?}", ddi.name, source, edid);
                edid
            },
            Err(err) => {
                log::warn!("DDI {} failed to parse EDID from {}: {:?}", ddi.name, source, err);
                // Will try again but not fail the driver
                return Ok(false);
            }
        };

        let mut timing_opt = None;
        for desc in edid.descriptors.iter() {
            match desc {
                edid::Descriptor::DetailedTiming(timing) => {
                    timing_opt = Some(timing);
                    break;
                }
                _ => {}
            }
        }
        let Some(timing) = timing_opt else {
            log::warn!("DDI {} EDID from {} missing detailed timing", ddi.name, source);
            // Will try again but not fail the driver
            return Ok(false);
        };

        let mut modeset = |ddi: &mut Ddi, input: VideoInput| -> Result<()> {
            // IHD-OS-TGL-Vol 12-1.22-Rev2.0 "Sequences for HDMI and DVI"

            // Power wells should already be enabled

            //TODO: Type-C needs aux power enabled and max lanes set
            
            // Enable port PLL without SSC. Not required on Type-C ports
            if let Some(clock_shift) = ddi.dpclka_cfgcr0_clock_shift {
                // Find free DPLL
                let dpll = self.dplls.iter_mut().find(|dpll| {
                    !dpll.enable.readf(DPLL_ENABLE_ENABLE)
                }).ok_or_else(|| {
                    log::error!("failed to find free DPLL");
                    Error::new(EIO)
                })?;

                // DPLL power guard
                let mut dpll_enable = unsafe { MmioPtr::new(dpll.enable.as_mut_ptr()) };
                let dpll_power_guard = CallbackGuard::new(
                    &mut dpll_enable,
                    |dpll_enable| {
                        // Enable DPLL power
                        dpll_enable.writef(DPLL_ENABLE_POWER_ENABLE, true);
                        //TODO: timeout not specified in docs, should be very fast
                        let timeout = Timeout::from_micros(1);
                        while !dpll_enable.readf(DPLL_ENABLE_POWER_STATE) {
                            timeout.run().map_err(|()| {
                                log::debug!("timeout while enabling DPLL {} power", dpll.name);
                                Error::new(EIO)
                            })?;
                        }
                        Ok(())
                    },
                    |dpll_enable| {
                        // Disable DPLL power
                        dpll_enable.writef(DPLL_ENABLE_POWER_ENABLE, false);
                    }
                )?;

                match input {
                    VideoInput::Hdmi => {
                        // Set SSC enable/disable. For HDMI, always disable
                        dpll.ssc.writef(DPLL_SSC_ENABLE, false);

                        // Configure DPLL frequency
                        dpll.set_freq_hdmi(self.ref_freq, &timing)?;
                    },
                    VideoInput::Dp => {
                        log::warn!("DPLL for DisplayPort not implemented");
                        return Err(Error::new(EIO));
                    }
                }

                //TODO: "Sequence Before Frequency Change"

                // Enable DPLL
                //TODO: use guard?
                {
                    dpll.enable.writef(DPLL_ENABLE_ENABLE, true);
                    let timeout = Timeout::from_micros(50);
                    while !dpll.enable.readf(DPLL_ENABLE_LOCK) {
                        timeout.run().map_err(|()| {
                            log::debug!("timeout while enabling DPLL {}", dpll.name);
                            Error::new(EIO)
                        })?;
                    }
                }

                //TODO: "Sequence After Frequency Change"

                // Update DPLL mapping
                if let Some(dpclka_cfgcr0) = &mut self.dpclka_cfgcr0 {
                    const DPCLKA_CFGCR0_CLOCK_MASK: u32 = 0b11;

                    let mut v = dpclka_cfgcr0.read();
                    v &= !(DPCLKA_CFGCR0_CLOCK_MASK << clock_shift);
                    v |= (dpll.dpclka_cfgcr0_clock_value << clock_shift);
                    dpclka_cfgcr0.write(v);
                }

                // Continue to allow DPLL power
                mem::forget(dpll_power_guard);
            }

            // Enable DPLL clock (must be done separately from PLL mapping)
            if let Some(dpclka_cfgcr0) = &mut self.dpclka_cfgcr0 {
                if let Some(clock_off) = ddi.dpclka_cfgcr0_clock_off {
                    dpclka_cfgcr0.writef(clock_off, false);
                }
            }

            // Enable IO power
            //TODO: the request can be shared by multiple DDIs
            //TODO: skip if TBT
            let pwr_well_ctl_ddi_request = ddi.pwr_well_ctl_ddi_request;
            let pwr_well_ctl_ddi_state = ddi.pwr_well_ctl_ddi_state;
            let mut pwr_well_ctl_ddi = unsafe { MmioPtr::new(self.power_wells.ctl_ddi.as_mut_ptr()) };
            let pwr_guard = CallbackGuard::new(
                &mut pwr_well_ctl_ddi,
                |pwr_well_ctl_ddi| {
                    // Enable IO power
                    pwr_well_ctl_ddi.writef(pwr_well_ctl_ddi_request, true);
                    let timeout = Timeout::from_micros(30);
                    while !pwr_well_ctl_ddi.readf(pwr_well_ctl_ddi_state) {
                        timeout.run().map_err(|()| {
                            log::debug!("timeout while requesting DDI {} IO power", ddi.name);
                            Error::new(EIO)
                        })?;
                    }
                    Ok(())
                },
                |pwr_well_ctl_ddi| {
                    // Disable IO power
                    pwr_well_ctl_ddi.writef(pwr_well_ctl_ddi_request, false);
                }
            )?;

            //TODO: Type-C DP_MODE

            // Enable planes, pipe, and transcoder
            {
                // Find free transcoder with free pipe
                let mut transcoder_pipe = None;
                for (transcoder, pipe) in self.transcoders.iter_mut().zip(self.pipes.iter_mut()) {
                    if transcoder.conf.readf(TRANS_CONF_ENABLE) {
                        continue;
                    }
                    //TODO: how would we know if pipe is in use?
                    transcoder_pipe = Some((transcoder, pipe));
                    break;
                }
                let Some((transcoder, pipe)) = transcoder_pipe else {
                    log::error!("free transcoder and pipe not found");
                    return Err(Error::new(EIO));
                };

                // Enable pipe and transcoder power wells
                self.power_wells.enable_well_by_pipe(pipe.name)?;
                self.power_wells.enable_well_by_transcoder(transcoder.name)?;

                // Configure transcoder clock select
                if let Some(transcoder_index) = ddi.transcoder_index {
                    transcoder.clk_sel.write(transcoder_index << transcoder.clk_sel_shift);
                }

                // Set pipe bottom color to blue for debugging
                pipe.bottom_color.write(0x3FF);

                // Configure and enable planes 
                //TODO: THIS IS HACKY
                if let Some(plane) = pipe.planes.first_mut() {
                    //TODO: enable DBUF if more buffers needed
                    //TODO: more blocks would mean better power usage
                    // Minimum is 8 blocks for linear planes, 160 blocks is recommended for pre-OS init
                    let buffer_size = 160;
                    let buffer = self.alloc_buffers.allocate_range(buffer_size).map_err(|err| {
                        log::warn!("failed to allocate {} buffer blocks: {:?}", buffer_size, err);
                        Error::new(EIO)
                    })?;
                    plane.buf_cfg.write(buffer.start | (buffer.end << 16));

                    let width = timing.horizontal_active_pixels as u32;
                    let height = timing.vertical_active_lines as u32;
                    plane.size.write((width - 1) | ((height - 1) << 16));

                    //TODO: documentation on this is not great
                    let stride_16 = (width + 15) / 16;
                    plane.stride.write(stride_16);
                    let stride = stride_16 * 16;

                    //TODO: how is memory allocated for PLANE_SURF?
                    let surf_size = (stride * height * 4).next_multiple_of(4096);
                    let surf = self.alloc_surfaces.allocate_range(surf_size).map_err(|err| {
                        log::warn!("failed to allocate surface of size {}: {:?}", surf_size, err);
                        Error::new(EIO)
                    })?;
                    plane.surf.write(surf.start);

                    //TODO: correct watermark calculation
                    plane.wm[0].write(
                        PLANE_WM_ENABLE |
                        (2 << PLANE_WM_LINES_SHIFT) |
                        buffer_size
                    );
                    for i in 1..plane.wm.len() {
                        plane.wm[i].writef(PLANE_WM_ENABLE, false);
                    }
                    plane.wm_trans.writef(PLANE_WM_ENABLE, false);

                    self.framebuffers.push(unsafe {
                        DeviceFb::new(
                            (self.gm.virt + surf.start as usize) as *mut u32,
                            width as usize,
                            height as usize,
                            stride as usize,
                            true
                        )
                    });

                    // Disable gamma
                    if let Some(color_ctl) = &mut plane.color_ctl {
                        color_ctl.write(plane.color_ctl_gamma_disable);
                    }

                    //TODO: more PLANE_CTL bits
                    plane.ctl.write(
                        PLANE_CTL_ENABLE |
                        plane.ctl_source_rgb_8888
                    );
                }

                //TODO: VGA and panel fitter steps?

                // Configure transcoder timings and other pipe and transcoder settings
                transcoder.modeset(pipe, &timing);

                // Configure and enable TRANS_DDI_FUNC_CTL
                {
                    let mut ddi_func_ctl = 
                        TRANS_DDI_FUNC_CTL_ENABLE |
                        //TODO: allow different bits per color
                        TRANS_DDI_FUNC_CTL_BPC_8 |
                        //TODO: correct port width selection
                        TRANS_DDI_FUNC_CTL_PORT_WIDTH_4;
                    
                    if let Some(transcoder_index) = ddi.transcoder_index {
                        ddi_func_ctl |= (transcoder_index << transcoder.ddi_func_ctl_ddi_shift);
                    }
                    
                    match input {
                        VideoInput::Hdmi => {
                            ddi_func_ctl |= TRANS_DDI_FUNC_CTL_MODE_HDMI;

                            // Set HDMI scrambling and high TMDS char rate based on symbol rate > 340 MHz
                            if timing.pixel_clock > 340_000 {
                                ddi_func_ctl |= 
                                    transcoder.ddi_func_ctl_hdmi_scrambling |
                                    transcoder.ddi_func_ctl_high_tmds_char_rate;
                            }
                        },
                        VideoInput::Dp => {
                            //TODO: MST
                            ddi_func_ctl |= TRANS_DDI_FUNC_CTL_MODE_DP_SST;
                        }
                    }
                    
                    match (timing.features >> 3) & 0b11 {
                        // Digital sync, separate
                        0b11 => {
                            if (timing.features & (1 << 2)) != 0 {
                                ddi_func_ctl |= TRANS_DDI_FUNC_CTL_SYNC_POLARITY_VSHIGH;
                            }
                            if (timing.features & (1 << 1)) != 0 {
                                ddi_func_ctl |= TRANS_DDI_FUNC_CTL_SYNC_POLARITY_HSHIGH;
                            }
                        },
                        unsupported => {
                            log::warn!("unsupported sync {:#x}", unsupported);
                        }
                    }

                    transcoder.ddi_func_ctl.write(ddi_func_ctl);
                }

                // Configure and enable TRANS_CONF
                let mut conf = transcoder.conf.read();
                // Set mode to progressive
                conf &= !TRANS_CONF_MODE_MASK;
                // Enable transcoder
                conf |= TRANS_CONF_ENABLE;
                transcoder.conf.write(conf);
                //TODO: what is the correct timeout?
                let timeout = Timeout::from_millis(100);
                while !transcoder.conf.readf(TRANS_CONF_STATE) {
                    timeout.run().map_err(|()| {
                        log::error!("timeout on DDI {} transcoder {} enable", ddi.name, transcoder.name);
                        Error::new(EIO)
                    })?;
                }
            }

            // Enable port
            {
                // Configure voltage swing and related IO settings
                match input {
                    VideoInput::Hdmi => {
                        ddi.voltage_swing_hdmi(&self.gttmm, &timing)?;
                    },
                    VideoInput::Dp => {
                        //TODO ddi.voltage_swing_dp(&self.gttmm)?;
                        log::error!("voltage swing for DP not implemented");
                        return Err(Error::new(EIO));
                    }
                }

                // Configure PORT_CL_DW10 static power down to power up all lanes
                //TODO: only power up required lanes
                if let Some(mut port_cl_dw10) = ddi.port_cl(PortClReg::Dw10) {
                    port_cl_dw10.writef(0b1111 << 4, false);
                }

                // Configure and enable DDI_BUF_CTL
                //TODO: more DDI_BUF_CTL bits?
                ddi.buf_ctl.writef(DDI_BUF_CTL_ENABLE, true);

                // Wait for DDI_BUF_CTL IDLE = 0, timeout after 500 us
                let timeout = Timeout::from_micros(500);
                while ddi.buf_ctl.readf(DDI_BUF_CTL_IDLE) {
                    timeout.run().map_err(|()| {
                        log::warn!("timeout while waiting for DDI {} active", ddi.name);
                        Error::new(EIO)
                    })?;
                }
            }

            // Keep IO power on if finished
            mem::forget(pwr_guard);

            Ok(())
        };

        if ddi.buf_ctl.readf(DDI_BUF_CTL_IDLE) {
            log::info!("DDI {} idle, will attempt mode setting", ddi.name);
            const EDID_VIDEO_INPUT_UNDEFINED: u8 = (1 << 7) | 0b0000;
            const EDID_VIDEO_INPUT_DVI: u8 = (1 << 7) | 0b0001;
            const EDID_VIDEO_INPUT_HDMI_A: u8 = (1 << 7) | 0b0010;
            const EDID_VIDEO_INPUT_HDMI_B: u8 = (1 << 7) | 0b0011;
            const EDID_VIDEO_INPUT_DP: u8 = (1 << 7) | 0b0101;
            const EDID_VIDEO_INPUT_MASK: u8 = (1 << 7) | 0b1111;
            let input = match edid_data[20] & EDID_VIDEO_INPUT_MASK {
                //TODO: how to accurately discover input type?
                //TODO: HDMI often shows up as undefined, do others?
                EDID_VIDEO_INPUT_UNDEFINED | EDID_VIDEO_INPUT_DVI | EDID_VIDEO_INPUT_HDMI_A | EDID_VIDEO_INPUT_HDMI_B => {
                    VideoInput::Hdmi
                },
                EDID_VIDEO_INPUT_DP => {
                    VideoInput::Dp
                }
                unknown => {
                    log::warn!("EDID video input 0x{:02X} not supported", unknown);
                    return Err(Error::new(EIO));
                }
            };
            //TODO: DisplayPort modeset not complete
            match modeset(ddi, input) {
                Ok(()) => {
                    log::info!("DDI {} modeset {:?} finished", ddi.name, input);
                },
                Err(err) => {
                    log::warn!("DDI {} modeset {:?} failed: {}", ddi.name, input, err);
                    // Will try again but not fail the driver
                    return Ok(false);
                }
            }
        } else {
            log::info!("DDI {} already active", ddi.name);
        }

        Ok(true)
    }

    pub fn handle_display_irq(&mut self) -> bool {
        let display_ints = self.int.display_int_ctl.read() & !self.int.display_int_ctl_enable;
        if display_ints != 0 {
            log::info!("  display ints {:08X}", display_ints);
            if display_ints & self.int.display_int_ctl_sde != 0 {
                let sde_ints = self.int.sde_interrupt.iir.read();
                self.int.sde_interrupt.iir.write(sde_ints);
                log::info!("    south display engine ints {:08X}", sde_ints);
                for ddi in self.ddis.iter() {
                    if let Some(sde_interrupt_hotplug) = ddi.sde_interrupt_hotplug {
                        if sde_ints & sde_interrupt_hotplug == sde_interrupt_hotplug {
                            self.events.push_back(Event::DdiHotplug(ddi.name));
                        }
                    }
                }
            }
            true
        } else {
            false
        }
    }

    pub fn handle_irq(&mut self) -> bool {
        let had_irq = if let Some(gfx_mstr_intr) = &mut self.int.gfx_mstr_intr {
            let gfx_ints = gfx_mstr_intr.read() & !self.int.gfx_mstr_intr_enable;
            if gfx_ints != 0 {
                log::info!("gfx ints {:08X}", gfx_ints);
                gfx_mstr_intr.write(gfx_ints | self.int.gfx_mstr_intr_enable);

                if gfx_ints & self.int.gfx_mstr_intr_display != 0 {
                    self.handle_display_irq();
                }

                true
            } else {
                false
            }
        } else {
            self.handle_display_irq()
        };

        if had_irq {
            for change_detect in self.int.change_detects.iter_mut() {
                change_detect.check();
            }
        }

        had_irq
    }

    pub fn handle_events(&mut self) {
        while let Some(event) = self.events.pop_front() {
            match event {
                Event::DdiHotplug(ddi_name) => {
                    log::info!("DDI {} plugged", ddi_name);
                    for attempt in 0..4 {
                        //TODO: gmbus times out!
                        match self.probe_ddi(ddi_name) {
                            Ok(true) => {
                                break;
                            },
                            Ok(false) => {
                                log::warn!("timeout probing {}", ddi_name);
                            }
                            Err(err) => {
                                log::warn!("failed to probe {}: {}", ddi_name, err);
                            }
                        }
                        //TODO: do this asynchronously so scheme events can be handled
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            }
        }
    }
}
