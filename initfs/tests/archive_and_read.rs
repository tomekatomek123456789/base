use std::{collections::HashMap, path::Path};

use anyhow::{Context, Result, anyhow};
use redox_initfs::{InitFs, InodeKind, InodeStruct};

#[derive(Debug, Clone, PartialEq)]
enum Node {
    Link { to: Vec<u8> },
    File { data: Vec<u8> },
    Dir(HashMap<Vec<u8>, Node>),
    Unknown,
}

impl Node {
    fn link(to: impl Into<Vec<u8>>) -> Self {
        Node::Link { to: to.into() }
    }

    fn file(data: impl Into<Vec<u8>>) -> Self {
        Node::File { data: data.into() }
    }

    fn dir(entries: impl IntoIterator<Item = (impl Into<Vec<u8>>, Node)>) -> Self {
        Self::Dir(
            entries
                .into_iter()
                .map(|(name, node)| (name.into(), node))
                .collect(),
        )
    }
}

fn build_tree<'a>(fs: InitFs<'a>, inode: InodeStruct<'a>) -> anyhow::Result<Node> {
    use InodeKind::*;
    let node = match inode.kind() {
        File(file) => {
            let data = file.data().context("failed to get file data")?.to_owned();
            Node::File { data }
        }
        Link(link) => {
            let data = link.data().context("failed to get link data")?.to_owned();
            Node::Link { to: data }
        }
        Dir(dir) => {
            let mut entries = HashMap::new();
            for idx in 0..dir
                .entry_count()
                .context("failed to get inode entry count")?
            {
                let entry = dir
                    .get_entry(idx)
                    .context("failed to get entry for index")?
                    .ok_or_else(|| anyhow!("no entry found"))?;

                let entry_name = entry.name().context("failed to get entry name")?;
                let inode = fs
                    .get_inode(entry.inode())
                    .context("failed to load file inode")?;

                let entry_node = build_tree(fs, inode)?;

                entries.insert(entry_name.to_owned(), entry_node);
            }

            Node::Dir(entries)
        }
        Unknown => Node::Unknown,
    };

    Ok(node)
}

#[test]
fn archive_and_read() -> Result<()> {
    env_logger::init();

    let args = archive_common::Args {
        destination_path: Path::new("out.img"),
        source: Path::new("data"),
        bootstrap_code: None,
        max_size: archive_common::DEFAULT_MAX_SIZE,
    };
    archive_common::archive(&args).context("failed to archive")?;

    let data = std::fs::read(args.destination_path).context("failed to read new archive")?;
    let filesystem =
        redox_initfs::InitFs::new(&data, None).context("failed to parse archive header")?;
    let inode = filesystem
        .get_inode(redox_initfs::InitFs::ROOT_INODE)
        .ok_or_else(|| anyhow!("Failed to get root inode"))?;

    let tree = build_tree(filesystem, inode)?;

    let reference_tree = Node::dir([(
        b"foo",
        Node::dir([
            (
                b"file.txt".as_slice(),
                Node::file(b"This is a file meant to be used in a redox-initfs test.\n"),
            ),
            (b"file-link.txt".as_slice(), Node::link(b"foo/file.txt")),
        ]),
    )]);

    assert_eq!(tree, reference_tree);

    Ok(())
}
