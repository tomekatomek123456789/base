use std::convert::{TryFrom, TryInto};
use std::fs::{DirEntry, File, Metadata, OpenOptions};
use std::io::{prelude::*, SeekFrom};
use std::path::Path;

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};

use anyhow::{anyhow, Context, Result};
use clap::{App, Arg};

use redox_initfs::types as initfs;

const KIBIBYTE: u64 = 1024;
const MEBIBYTE: u64 = KIBIBYTE * 1024;
const DEFAULT_MAX_SIZE: u64 = 64 * MEBIBYTE;

enum EntryKind {
    File(File),
    Dir(Dir),
}

struct Entry {
    name: Vec<u8>,
    kind: EntryKind,
    metadata: Metadata,
}
struct Dir {
    entries: Vec<Entry>,
}

struct State {
    file: File,
    offset: u64,
    max_size: u64,
    inode_count: u16,
    buffer: Box<[u8]>,
}

fn read_directory(state: &mut State, path: &Path) -> Result<Dir> {
    let read_dir = path
        .read_dir()
        .with_context(|| anyhow!("failed to read directory `{}`", path.to_string_lossy(),))?;

    let entries = read_dir
        .map(|result| {
            let entry = result.with_context(|| {
                anyhow!(
                    "failed to get a directory entry from `{}`",
                    path.to_string_lossy(),
                )
            })?;

            let metadata = entry.metadata().with_context(|| {
                anyhow!(
                    "failed to get metadata for `{}`",
                    entry.path().to_string_lossy(),
                )
            })?;
            let file_type = metadata.file_type();

            let unsupported_type = |ty: &str, entry: &DirEntry| {
                Err(anyhow!(
                    "failed to include {} at `{}`: not supported by redox-initfs",
                    ty,
                    entry.path().to_string_lossy()
                ))
            };
            let name = entry
                .path()
                .file_name()
                .context("expected path to have a valid filename")?
                .as_bytes()
                .to_owned();

            let entry_kind = if file_type.is_symlink() {
                return unsupported_type("symlink", &entry);
            } else if file_type.is_socket() {
                return unsupported_type("socket", &entry);
            } else if file_type.is_fifo() {
                return unsupported_type("FIFO", &entry);
            } else if file_type.is_block_device() {
                return unsupported_type("block device", &entry);
            } else if file_type.is_char_device() {
                return unsupported_type("character device", &entry);
            } else if file_type.is_file() {
                EntryKind::File(File::open(&entry.path()).with_context(|| {
                    anyhow!("failed to open file `{}`", entry.path().to_string_lossy(),)
                })?)
            } else if file_type.is_dir() {
                EntryKind::Dir(read_directory(state, &entry.path())?)
            } else {
                return Err(anyhow!(
                    "unknown file type at `{}`",
                    entry.path().to_string_lossy()
                ));
            };

            // TODO: Allow the user to specify a lower limit than u16::MAX.
            state.inode_count = state
                .inode_count
                .checked_add(1)
                .ok_or_else(|| anyhow!("exceeded the maximum inode limit"))?;

            Ok(Entry {
                kind: entry_kind,
                metadata,
                name,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    Ok(Dir { entries })
}

fn bump_alloc(state: &mut State, size: u64) -> Result<u64> {
    if state.offset + size <= state.max_size {
        let offset = state.offset;
        state.offset += size;
        Ok(offset)
    } else {
        Err(anyhow!("bump allocation failed: max limit reached"))
    }
}
struct WriteResult {
    size: u32,
    offset: u32,
}

fn allocate_and_write_file(state: &mut State, mut file: &File) -> Result<WriteResult> {
    let size = file
        .seek(SeekFrom::End(0))
        .context("failed to seek to end")?;

    let size: u32 = size.try_into().context("file too large")?;

    let offset: u32 = bump_alloc(state, size.into())
        .context("failed to allocate space for file")?
        .try_into()
        .context("file offset too high")?;

    let buffer_size: u32 = state.buffer.len().try_into().context("buffer too large")?;

    file.seek(SeekFrom::Start(0))
        .context("failed to seek to start")?;

    state
        .file
        .seek(SeekFrom::Start(offset.into()))
        .context("failed to seek to offset for image")?;

    let mut relative_offset = 0;

    // TODO: If this would ever turn out to be a bottleneck, then perhaps we could use
    // copy_file_range in `nix`.

    while relative_offset < size {
        let allowed_length = std::cmp::min(buffer_size, size - relative_offset);
        let allowed_length =
            usize::try_from(allowed_length).expect("expected buffer size not to be outside usize");

        file.read(&mut state.buffer[..allowed_length])
            .context("failed to read from source file")?;

        state
            .file
            .write(&state.buffer[..allowed_length])
            .context("failed to write source file into destination image")?;

        relative_offset += buffer_size;
    }

    Ok(WriteResult { size, offset })
}
fn write_inode(
    state: &mut State,
    ty: initfs::InodeType,
    metadata: &Metadata,
    write_result: WriteResult,
    inode_table_offset: u32,
    index: u16,
) -> Result<()> {
    let inode_size: u32 = std::mem::size_of::<initfs::InodeHeader>()
        .try_into()
        .expect("inode header length cannot fit within u32");

    let type_and_mode = ((ty as u32) << initfs::TYPE_SHIFT) | u32::from(metadata.mode() & 0xFFF);

    // TODO: Use main buffer and write in bulk.
    let mut inode_buf = [0_u8; std::mem::size_of::<initfs::InodeHeader>()];

    let inode = plain::from_mut_bytes::<initfs::InodeHeader>(&mut inode_buf)
        .expect("expected inode struct to have alignment 1, and buffer size to match");

    *inode = initfs::InodeHeader {
        type_and_mode: type_and_mode.into(),
        length: write_result.size.into(),
        offset: initfs::Offset(write_result.offset.into()),

        gid: metadata.gid().into(),
        uid: metadata.uid().into(),
    };

    state
        .file
        .write_all_at(
            &inode_buf,
            u64::from(inode_table_offset + u32::from(index) * inode_size),
        )
        .context("failed to write inode struct to disk image")
}
fn allocate_and_write_dir(
    state: &mut State,
    dir: &Dir,
    inode_table_offset: u32,
    start_inode: &mut u16,
) -> Result<WriteResult> {
    let entry_size =
        u16::try_from(std::mem::size_of::<initfs::DirEntry>()).context("entry size too large")?;
    let entry_count = u16::try_from(dir.entries.len()).context("too many subdirectories")?;

    let entry_table_length = u32::from(entry_count)
        .checked_mul(u32::from(entry_size))
        .ok_or_else(|| anyhow!("entry table length too large when multiplying by size"))?;

    let entry_table_offset: u32 = bump_alloc(state, entry_table_length.into())
        .context("failed to allocate entry table")?
        .try_into()
        .context("directory entries offset too high")?;

    let this_start_inode = *start_inode;

    let inode_size: u32 = std::mem::size_of::<initfs::InodeHeader>()
        .try_into()
        .expect("inode header length cannot fit within u32");

    *start_inode += entry_count;

    let inode_table_offset =
        inode_table_offset + u32::from(this_start_inode) * u32::from(inode_size);

    for (index, entry) in dir.entries.iter().enumerate() {
        let (write_result, ty) = match entry.kind {
            EntryKind::Dir(ref subdir) => {
                let write_result =
                    allocate_and_write_dir(state, subdir, inode_table_offset, start_inode)
                        .with_context(|| {
                            anyhow!(
                                "failed to copy directory entries from `{}` into image",
                                String::from_utf8_lossy(&entry.name)
                            )
                        })?;

                (write_result, initfs::InodeType::Dir)
            }

            EntryKind::File(ref file) => {
                let write_result = allocate_and_write_file(state, file)
                    .context("failed to copy file into image")?;

                (write_result, initfs::InodeType::RegularFile)
            }
        };

        let index: u16 = index
            .try_into()
            .expect("expected dir entry count not to exceed u32");

        write_inode(
            state,
            ty,
            &entry.metadata,
            write_result,
            inode_table_offset,
            index,
        )?;

        let (name_offset, name_len) = {
            let name_len: u16 = entry.name.len().try_into().context("file name too long")?;

            let offset: u32 = bump_alloc(state, u64::from(name_len))
                .context("failed to allocate space for file name")?
                .try_into()
                .context("file name offset too high up")?;

            (offset, name_len)
        };
        {
            let mut direntry_buf = [0_u8; std::mem::size_of::<initfs::DirEntry>()];

            let direntry = plain::from_mut_bytes::<initfs::DirEntry>(&mut direntry_buf)
                .expect("expected dir entry struct to have alignment 1, and buffer size to match");

            let inode = this_start_inode + index;

            *direntry = initfs::DirEntry {
                inode: initfs::Inode(inode.into()),
                name_len: name_len.into(),
                name_offset: initfs::Offset(name_offset.into()),
            };

            state
                .file
                .write_all_at(
                    &direntry_buf,
                    u64::from(entry_table_offset + u32::from(index) * u32::from(entry_size)),
                )
                .context("failed to write dir entry struct to image")?;
        }
    }

    Ok(WriteResult {
        size: entry_table_length,
        offset: entry_table_offset,
    })
}
fn allocate_contents_and_write_inodes(
    state: &mut State,
    dir: &Dir,
    inode_table_offset: u32,
    root_metadata: Metadata,
) -> Result<()> {
    let index = 0;
    let mut start_inode = 1;

    let write_result = allocate_and_write_dir(state, dir, inode_table_offset, &mut start_inode)
        .context("failed to allocate and write all directories and files")?;

    write_inode(
        state,
        initfs::InodeType::Dir,
        &root_metadata,
        write_result,
        inode_table_offset,
        index,
    )
}

fn main() -> Result<()> {
    let matches = App::new("redox_initfs_package")
        .help("Package a Redox initfs")
        .arg(
            Arg::with_name("MAX_SIZE")
                .long("--max-size")
                .short("-m")
                .takes_value(true)
                .required(false)
                .help("Set the upper limit for how large the image can become (default 8 MiB)."),
        )
        .arg(
            Arg::with_name("SOURCE")
                .takes_value(true)
                .required(true)
                .help("Specify the source directory to build the image from."),
        )
        .arg(
            Arg::with_name("OUTPUT")
                .takes_value(true)
                .required(true)
                .long("--output")
                .short("-o")
                .help("Specify the path of the new image file."),
        )
        .get_matches();

    let max_size = if let Some(max_size_str) = matches.value_of("MAX_SIZE") {
        max_size_str
            .parse::<u64>()
            .context("expected an integer for MAX_SIZE")?
    } else {
        DEFAULT_MAX_SIZE
    };

    let source = matches
        .value_of("SOURCE")
        .expect("expected the required arg SOURCE to exist");

    let destination = matches
        .value_of("OUTPUT")
        .expect("expected the required arg OUTPUT to exist");

    let destination_path = Path::new(destination);

    let previous_extension = destination_path.extension().map_or("", |ext| {
        ext.to_str()
            .expect("expected destination path to be valid UTF-8")
    });

    if !destination_path
        .metadata()
        .map_or(true, |metadata| metadata.is_file())
    {
        return Err(anyhow!("Destination file must be a file"));
    }

    let destination_temp_path =
        destination_path.with_extension(format!("{}.partial", previous_extension));

    let destination_temp_file = OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .create_new(false)
        .open(destination_temp_path)
        .context("failed to open destination file")?;

    const BUFFER_SIZE: usize = 8192;

    let mut state = State {
        file: destination_temp_file,
        offset: 0,
        max_size,
        inode_count: 0,
        buffer: vec![0_u8; BUFFER_SIZE].into_boxed_slice(),
    };

    let root_path = Path::new(source);
    let root_metadata = root_path
        .metadata()
        .context("failed to obtain metadata for root")?;
    let root = read_directory(&mut state, root_path).context("failed to read root")?;

    // NOTE: The header is always stored at offset zero.
    let header_offset = bump_alloc(
        &mut state,
        std::mem::size_of::<initfs::Header>()
            .try_into()
            .expect("expected header size to fit"),
    )?;

    let inode_table_length = {
        let inode_entry_size: u64 = std::mem::size_of::<initfs::DirEntry>()
            .try_into()
            .expect("expected table entry size to fit");

        inode_entry_size
            .checked_mul(u64::from(state.inode_count))
            .ok_or_else(|| anyhow!("inode table too large"))?
    };

    let inode_table_offset = bump_alloc(&mut state, inode_table_length)?;

    // Finally, write the header to the disk image.

    let inode_table_offset = initfs::Offset(
        u32::try_from(inode_table_offset)
            .with_context(|| "inode table located too far away")?
            .into(),
    );

    allocate_contents_and_write_inodes(
        &mut state,
        &root,
        inode_table_offset.0.get(),
        root_metadata,
    )?;

    let current_system_time = std::time::SystemTime::now();

    let time_since_epoch = current_system_time
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .context("could not calculate timestamp")?;

    {
        let mut header_bytes = [0_u8; std::mem::size_of::<initfs::Header>()];
        let header = plain::from_mut_bytes(&mut header_bytes)
            .expect("expected header size to be sufficient and alignment to be 1");

        *header = initfs::Header {
            magic: initfs::Magic(initfs::MAGIC),
            creation_time: initfs::Timespec {
                sec: time_since_epoch.as_secs().into(),
                nsec: time_since_epoch.subsec_nanos().into(),
            },
            inode_count: state.inode_count.into(),
            inode_table_offset,
        };
        state
            .file
            .write_all_at(&header_bytes, header_offset)
            .context("failed to write header")?;
    }

    Ok(())
}
