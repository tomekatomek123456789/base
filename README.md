# Base

Repository containing various system daemons, that are considered fundamental for the OS.

You can see what each component does in the following list:

- audiod : Daemon used to process the sound drivers audio
- bootstrap : First code that the kernel executes, responsible for spawning the init daemon
- daemon : Redox daemon library
- drivers
- init : Daemon used to start most system components and programs
- initfs : Filesystem with the necessary system components to run RedoxFS
- ipcd : Daemon used for inter-process communication
- logd : Daemon used to log system components and daemons
- netstack : Daemon used for networking
- ptyd : Daemon used for pseudo-terminal
- ramfs : RAM filesystem
- randd : Daemon used for random number generation
- zerod : Daemon used to discard all writes and fill read buffers with zero

## How To Contribute

To learn how to contribute you need to read the following document:

- [CONTRIBUTING.md](https://gitlab.redox-os.org/redox-os/redox/-/blob/master/CONTRIBUTING.md)

If you want to contribute to drivers read its [README](drivers/README.md)

## Development

To learn how to do development with these system components inside the Redox build system you need to read the [Build System](https://doc.redox-os.org/book/build-system-reference.html) and [Coding and Building](https://doc.redox-os.org/book/coding-and-building.html) pages.

### How To Build

To build this system component you need to download the Redox build system, you can learn how to do it on the [Building Redox](https://doc.redox-os.org/book/podman-build.html) page.

This is necessary because they only work with cross-compilation to a Redox virtual machine or real hardware, but you can do some testing from Linux.
