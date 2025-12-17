# Drivers

- [Libraries](#libraries)
- [Services](#services)
- [Hardware Interfaces](#hardware-interfaces)
- [Devices](#devices)
  - [CPU](#cpu)
  - [Storage](#storage)
  - [Graphics](#graphics)
  - [Input](#input)
  - [Sound](#sound)
  - [Networking](#networking)
  - [Virtualization](#virtualization)
- [System Interfaces](#system-interfaces)
- [System Calls](#system-calls)
- [Schemes](#schemes)
- [Contribution Details](#contribution-details)

## Libraries

- amlserde - Library to provide serialization/deserialization of the AML symbol table from ACPI
- block-io-wrapper - Library used by other drivers
- common - Library with shared driver code
- executor - Library to run Rust futures and integrate the executor in an interrupt+queue model without a separated reactor thread
- graphics/console-draw - Library with shared terminal drawing code
- graphics/driver-graphics - Library with shared graphics code
- graphics/graphics-ipc - Library with graphics IPC shared code
- net/driver-network - Library with shared networking code
- partitionlib - Library with MBR and GPT code
- storage/driver-block - Library with shared storage code

## Services

- graphics/fbbootlogd - Daemon for boot log drawing
- graphics/fbcond - Terminal daemon
- hwd - Handles the ACPI and DeviceTree booting
- inputd - Multiplexes input from multiple input drivers and provides that to Orbital
- pcid-spawner - Daemon for PCI device driver spawn
- storage/lived - Daemon for live disk
- redoxerd - Daemon that send/receive terminal text between the host system and QEMU

## Hardware Interfaces

- acpid - ACPI interface
- pcid - PCI interface with PCI Express extensions

## Devices

### CPU

- rtcd - x86 real time clock

### Storage

- storage/ahcid - SATA interface
- storage/bcm2835-sdhcid - Raspberry Pi 3B+ storage driver
- storage/ided - IDE interface
- storage/nvmed - NVMe interface
- storage/virtio-blkd - VirtIO block device
- usb/usbscsid - USB SCSI

### Graphics

- graphics/bgad - Bochs video driver
- graphics/vesad - VESA interface
- graphics/virtio-gpud - VirtIO GPU device

### Input

- input/ps2d - PS/2 interface
- usb/usbhidd - USB HID
- usb/usbctl - USB control

### Sound

- audio/ac97d - Realtek audio chipsets
- audio/ihdad - Intel HD Audio chipsets
- audio/sb16d - Sound Blaster audio

### Networking

- net/alxd - Qualcomm Atheros ethernet
- net/e1000d - Intel Gigabit ethernet
- net/ixgbed - Intel 10 Gigabit ethernet
- net/rtl8139d, net/rtl8168d - Realtek ethernet
- net/virtio-netd - VirtIO network

### Virtualization

- net/virtio-netd - VirtIO network device
- vboxd - VirtualBox guest driver
- virtio-core - VirtIO core
- usb/xhcid - xHCI USB controller

Some drivers are work-in-progress and incomplete, read [this](https://gitlab.redox-os.org/redox-os/base/-/issues/56) tracking issue to verify.

## System Interfaces

This section explain the system interfaces used by drivers.

### System Calls

- `iopl` : system call that sets the I/O privilege level. x86 has four privilege rings (0/1/2/3), of which the kernel runs in ring 0 and userspace in ring 3. IOPL can only be changed by the kernel, for obvious security reasons, and therefore the Redox kernel needs root to set it. It is unique for each process. Processes with IOPL=3 can access I/O ports, and the kernel can access them as well.

### Schemes

- `/scheme/memory/physical` : Allows mapping physical memory frames to driver-accessible virtual memory pages, with various available memory types:
    - `/scheme/memory/physical` : Default memory type (currently writeback)
    - `/scheme/memory/physical@wb` Writeback cached memory
    - `/scheme/memory/physical@uc` : Uncacheable memory
    - `/scheme/memory/physical@wc` : Write-combining memory
- `/scheme/irq` : Allows getting events from interrupts. It is used primarily by listening for its file descriptors using the `/scheme/event` scheme.

## Contribution Details

### Driver Design

A device driver on Redox is an user-space daemon that use system calls and schemes to work, while operating systems with monolithic kernels drivers use internal kernel APIs instead of common program APIs.

If you want to port a driver from a monolithic operating system to Redox you will need to rewrite the driver with reverse enginnering of the code logic, because the logic is adapted to internal kernel APIs (it's a hard task if the device is complex, datasheets are much more easy).

### Write a Driver

Datasheets are preferable (much more easy depending on device complexity), when they are freely available. Be aware that datasheets are often provided under a [Non-Disclosure Agreement](https://en.wikipedia.org/wiki/Non-disclosure_agreement) from hardware vendors, which can affect the ability to create an MIT-licensed driver.

If datasheets aren't available you need to do reverse-engineering of BSD or Linux drivers (if you want use a Linux driver as reference for your Redox driver please ask in the [Chat](https://doc.redox-os.org/book/chat.html) before the implementation to know/satisfy the license requirements and not waste your time, also if you use a BSD driver not licensed as BSD as reference).

### Libraries

You should use the [redox-scheme](https://crates.io/crates/redox-scheme) and [redox_event](https://crates.io/crates/redox_event) libraries to create your drivers, you can also read the [example driver](https://gitlab.redox-os.org/redox-os/exampled) or read the code of other drivers with the same type of your device.

Before testing your changes be aware of [this](https://doc.redox-os.org/book/coding-and-building.html#how-to-update-initfs).

### References

If you want to reverse enginner the existing drivers, you can access the BSD code using these links:

- [FreeBSD drivers](https://github.com/freebsd/freebsd-src/tree/main/sys/dev)
- [NetBSD drivers](https://github.com/NetBSD/src/tree/trunk/sys/dev)
- [OpenBSD drivers](https://github.com/openbsd/src/tree/master/sys/dev)

## How To Contribute

To learn how to contribute to this system component you need to read the following document:

- [CONTRIBUTING.md](https://gitlab.redox-os.org/redox-os/redox/-/blob/master/CONTRIBUTING.md)

## Development

To learn how to do development with this system component inside the Redox build system you need to read the [Build System](https://doc.redox-os.org/book/build-system-reference.html) and [Coding and Building](https://doc.redox-os.org/book/coding-and-building.html) pages.

### How To Build

To build this system component you need to download the Redox build system, you can learn how to do it on the [Building Redox](https://doc.redox-os.org/book/podman-build.html) page.

This is necessary because they only work with cross-compilation to a Redox virtual machine or real hardware, but you can do some testing from Linux.
