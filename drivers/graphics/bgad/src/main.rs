//! <https://www.qemu.org/docs/master/specs/standard-vga.html>

use common::acquire_port_io_rights;
use inputd::ProducerHandle;
use pcid_interface::PciFunctionHandle;
use redox_scheme::{scheme::register_sync_scheme, RequestKind, SignalBehavior, Socket};

use crate::bga::Bga;
use crate::scheme::BgaScheme;

mod bga;
mod scheme;

// FIXME add a driver-graphics implementation

fn main() {
    common::init();
    pcid_interface::pci_daemon(daemon);
}

fn daemon(daemon: daemon::Daemon, mut pcid_handle: PciFunctionHandle) -> ! {
    let pci_config = pcid_handle.config();

    let mut name = pci_config.func.name();
    name.push_str("_bga");

    common::setup_logging(
        "graphics",
        "pci",
        &name,
        common::output_level(),
        common::file_level(),
    );

    log::info!("BGA {}", pci_config.func.display());

    let socket = Socket::create().expect("bgad: failed to create bga scheme");

    let bar = unsafe { pcid_handle.map_bar(2) }.ptr.as_ptr();

    let mut bga = unsafe { Bga::new(bar) };
    log::debug!("BGA {}x{}", bga.width(), bga.height());

    let mut scheme = BgaScheme {
        bga,
        display: ProducerHandle::new().ok(),
    };

    scheme.update_size();

    register_sync_scheme(&socket, "bga", &mut scheme).expect("bgad: failed to register bga scheme");

    daemon.ready();

    libredox::call::setrens(0, 0).expect("bgad: failed to enter null namespace");

    loop {
        let Some(request) = socket
            .next_request(SignalBehavior::Restart)
            .expect("bgad: failed to get next scheme request")
        else {
            // Scheme likely got unmounted
            std::process::exit(0);
        };
        match request.kind() {
            RequestKind::Call(call) => {
                let response = call.handle_sync(&mut scheme);

                socket
                    .write_response(response, SignalBehavior::Restart)
                    .expect("bgad: failed to write next scheme response");
            }
            RequestKind::OnClose { id } => {
                scheme.on_close(id);
            }
            _ => (),
        }
    }
}
