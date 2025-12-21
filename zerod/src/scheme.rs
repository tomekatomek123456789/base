use redox_scheme::scheme::SchemeSync;
use redox_scheme::{CallerCtx, OpenResult};
use syscall::schemev2::NewFdFlags;
use syscall::{error::*, MODE_CHR};

use crate::Ty;

pub struct ZeroScheme(pub Ty);

impl SchemeSync for ZeroScheme {
    fn open(&mut self, _path: &str, _flags: usize, _ctx: &CallerCtx) -> Result<OpenResult> {
        Ok(OpenResult::ThisScheme {
            number: 0,
            flags: NewFdFlags::empty(),
        })
    }

    fn read(
        &mut self,
        _file: usize,
        buf: &mut [u8],
        _offset: u64,
        _flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        match self.0 {
            Ty::Null => Ok(0),
            Ty::Zero => {
                buf.fill(0);
                Ok(buf.len())
            }
        }
    }

    fn write(
        &mut self,
        _file: usize,
        buffer: &[u8],
        _offset: u64,
        _flags: u32,
        _ctx: &CallerCtx,
    ) -> Result<usize> {
        Ok(buffer.len())
    }

    fn fcntl(&mut self, _id: usize, _cmd: usize, _arg: usize, _ctx: &CallerCtx) -> Result<usize> {
        Ok(0)
    }
    fn fsize(&mut self, _id: usize, _ctx: &CallerCtx) -> Result<u64> {
        Ok(0)
    }
    fn ftruncate(&mut self, _id: usize, _len: u64, _ctx: &CallerCtx) -> Result<()> {
        Ok(())
    }

    fn fpath(&mut self, _id: usize, buf: &mut [u8], _ctx: &CallerCtx) -> Result<usize> {
        let scheme_path = b"zero:";
        let size = std::cmp::min(buf.len(), scheme_path.len());

        buf[..size].copy_from_slice(&scheme_path[..size]);

        Ok(size)
    }

    fn fsync(&mut self, _file: usize, _ctx: &CallerCtx) -> Result<()> {
        Ok(())
    }

    /// Close the file `number`
    fn on_close(&mut self, _file: usize) {}
    fn fstat(&mut self, _: usize, stat: &mut syscall::Stat, _ctx: &CallerCtx) -> Result<()> {
        stat.st_mode = 0o666 | MODE_CHR;
        stat.st_size = 0;
        stat.st_blocks = 0;
        stat.st_blksize = 4096;
        stat.st_nlink = 1;

        Ok(())
    }
}
