use driver_graphics::GraphicsScheme;
use event::{user_data, EventQueue};
use inputd::DisplayHandle;
use pcid_interface::{irq_helpers::pci_allocate_interrupt_vector, PciFunctionHandle};
use std::{
    io::{Read, Write},
    os::fd::AsRawFd,
};

mod device;
use self::device::Device;

fn main() {
    pcid_interface::pci_daemon(daemon);
}

fn daemon(daemon: daemon::Daemon, mut pcid_handle: PciFunctionHandle) -> ! {
    let pci_config = pcid_handle.config();

    let mut name = pci_config.func.name();
    name.push_str("_ihdg");

    common::setup_logging(
        "graphics",
        "pci",
        &name,
        log::LevelFilter::Debug, //common::output_level(),
        common::file_level(),
    );

    log::info!("IHDG {}", pci_config.func.display());

    let device = Device::new(&mut pcid_handle, &pci_config.func)
        .expect("ihdgd: failed to initialize device");

    let irq_file = pci_allocate_interrupt_vector(&mut pcid_handle, "ihdgd");

    let mut inputd_display_handle = DisplayHandle::new(format!("ihdg.{}", name)).unwrap();

    let mut scheme = GraphicsScheme::new(device, format!("display.ihdg.{}", name));

    user_data! {
        enum Source {
            Input,
            Irq,
            Scheme,
        }
    }

    let event_queue: EventQueue<Source> =
        EventQueue::new().expect("ihdgd: failed to create event queue");
    event_queue
        .subscribe(
            inputd_display_handle.inner().as_raw_fd() as usize,
            Source::Input,
            event::EventFlags::READ,
        )
        .unwrap();
    event_queue
        .subscribe(
            irq_file.irq_handle().as_raw_fd() as usize,
            Source::Irq,
            event::EventFlags::READ,
        )
        .unwrap();
    event_queue
        .subscribe(
            scheme.event_handle().raw(),
            Source::Scheme,
            event::EventFlags::READ,
        )
        .unwrap();

    libredox::call::setrens(0, 0).expect("ihdgd: failed to enter null namespace");

    daemon.ready();

    let all = [Source::Input, Source::Irq, Source::Scheme];
    for event in all
        .into_iter()
        .chain(event_queue.map(|e| e.expect("ihdgd: failed to get next event").user_data))
    {
        match event {
            Source::Input => {
                while let Some(vt_event) = inputd_display_handle
                    .read_vt_event()
                    .expect("ihdgd: failed to read display handle")
                {
                    scheme.handle_vt_event(vt_event);
                }
            }
            Source::Irq => {
                let mut irq = [0; 8];
                irq_file.irq_handle().read(&mut irq).unwrap();
                if scheme.adapter_mut().handle_irq() {
                    irq_file.irq_handle().write(&mut irq).unwrap();

                    scheme.adapter_mut().handle_events();
                    scheme.tick().unwrap();
                }
            }
            Source::Scheme => {
                scheme
                    .tick()
                    .expect("ihdgd: failed to handle scheme events");
            }
        }
    }

    std::process::exit(0);
}
