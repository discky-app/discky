//! Directory listing via `getattrlistbulk(2)`: names, kinds and honest sizes in one syscall per batch.

use std::ffi::{CString, OsStr, OsString};
use std::fs::OpenOptions;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::fs::dataless::is_dataless;

// ---- FFI constants ----------------------------------------------------------

/// Per-entry error code attribute. Missing from `libc`.
const ATTR_CMN_ERROR: libc::attrgroup_t = 0x2000_0000;

const COMMON_ATTRS: libc::attrgroup_t = libc::ATTR_CMN_NAME
    | libc::ATTR_CMN_RETURNED_ATTRS
    | ATTR_CMN_ERROR
    | libc::ATTR_CMN_OBJTYPE
    | libc::ATTR_CMN_MODTIME
    | libc::ATTR_CMN_FLAGS
    | libc::ATTR_CMN_FILEID;
const FILE_ATTRS: libc::attrgroup_t =
    libc::ATTR_FILE_LINKCOUNT | libc::ATTR_FILE_DATALENGTH | libc::ATTR_FILE_DATAALLOCSIZE;
/// Interpreted as the extended-common (CMNEXT) group because of `FSOPT_ATTR_CMN_EXTENDED`.
const CMNEXT_ATTRS: libc::attrgroup_t =
    libc::ATTR_CMNEXT_PRIVATESIZE | libc::ATTR_CMNEXT_CLONEID | libc::ATTR_CMNEXT_EXT_FLAGS;
/// The same without PRIVATESIZE, which roughly doubles the kernel's per-entry cost.
const CMNEXT_ATTRS_FAST: libc::attrgroup_t =
    libc::ATTR_CMNEXT_CLONEID | libc::ATTR_CMNEXT_EXT_FLAGS;

const OPTIONS: u64 =
    (libc::FSOPT_NOFOLLOW | libc::FSOPT_PACK_INVAL_ATTRS | libc::FSOPT_ATTR_CMN_EXTENDED) as u64;

const VREG: u32 = 1;
const VDIR: u32 = 2;
const VLNK: u32 = 5;

/// `EF_MAY_SHARE_BLOCKS` from `<sys/attr.h>` (in `ext_flags`): the file may share blocks
/// with a clone, so its private size can be below its allocated size.
pub const EF_MAY_SHARE_BLOCKS: u64 = 0x1;

const INITIAL_BUF: usize = 256 * 1024;
const GIB: u64 = 1 << 30;

// ---- Public types -----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObjKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// One directory entry exactly as the kernel reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawEntry {
    pub name: OsString,
    pub kind: ObjKind,
    /// `ATTR_FILE_DATALENGTH`; 0 for directories.
    pub logical: u64,
    /// `ATTR_FILE_DATAALLOCSIZE`; 0 for directories.
    pub allocated: u64,
    /// `ATTR_CMNEXT_PRIVATESIZE`: bytes freed if deleted (APFS only).
    pub private: Option<u64>,
    /// Modification time, seconds since the epoch.
    pub mtime: i64,
    pub file_id: u64,
    /// 1 for directories.
    pub link_count: u32,
    pub bsd_flags: u32,
    pub clone_id: Option<u64>,
    pub ext_flags: Option<u64>,
    /// `ATTR_CMN_ERROR`: errno hit while reading this entry; other fields are then defaults.
    pub error: Option<i32>,
}

/// Sparse rule: `allocated < logical * 0.9` and `logical - allocated > 1 GiB`.
pub fn is_sparse(logical: u64, allocated: u64) -> bool {
    (allocated as u128) * 10 < (logical as u128) * 9 && logical.saturating_sub(allocated) > GIB
}

/// List `dir` (not following a symlink at `dir`) with one `getattrlistbulk` call per batch.
/// `buf` is scratch space reused across calls; it is grown to 256 KiB if smaller.
pub fn read_dir_bulk(dir: &Path, buf: &mut Vec<u8>) -> io::Result<Vec<RawEntry>> {
    list(&open_dir(dir)?, buf, CMNEXT_ATTRS)
}

/// The scanner's listing call. Differs from [`read_dir_bulk`] in two ways:
///
/// - It first checks the `st_dev` of the opened directory (one `fstat` on the open fd) and
///   returns `Ok(None)` without listing when it differs from `dev`, i.e. when `dir` is a
///   mount point of another volume.
/// - Unless `exact_private` is set, it does not request PRIVATESIZE in bulk (that doubles
///   the listing cost). `private` is then fetched per entry, with `getattrlistat` on the
///   open directory, only for non-dataless files whose `ext_flags` has
///   [`EF_MAY_SHARE_BLOCKS`]; for every other entry it is `None`, meaning "equal to
///   `allocated`". This is clone-aware only: blocks held by APFS snapshots are not seen.
///   With `exact_private`, PRIVATESIZE is requested in bulk for every entry, exactly like
///   [`read_dir_bulk`].
pub fn read_dir_bulk_on_dev(
    dir: &Path,
    dev: u64,
    exact_private: bool,
    buf: &mut Vec<u8>,
) -> io::Result<Option<Vec<RawEntry>>> {
    let file = open_dir(dir)?;
    if file.metadata()?.dev() != dev {
        return Ok(None);
    }
    if exact_private {
        return list(&file, buf, CMNEXT_ATTRS).map(Some);
    }
    let mut entries = list(&file, buf, CMNEXT_ATTRS_FAST)?;
    for e in &mut entries {
        let may_share = e.ext_flags.is_some_and(|f| f & EF_MAY_SHARE_BLOCKS != 0);
        if e.kind == ObjKind::File && may_share && !is_dataless(e.bsd_flags) {
            e.private = private_size_at(&file, &e.name);
        }
    }
    Ok(Some(entries))
}

/// PRIVATESIZE of `name` inside the open directory `dir`; `None` if unavailable.
fn private_size_at(dir: &std::fs::File, name: &OsStr) -> Option<u64> {
    let cname = CString::new(name.as_bytes()).ok()?;
    let mut list = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_RETURNED_ATTRS,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: libc::ATTR_CMNEXT_PRIVATESIZE,
    };
    // u32 length, attribute_set_t (5 × u32), u64 private size.
    let mut out = [0u8; 4 + 20 + 8];
    // SAFETY: `dir` is an open directory fd, `cname` is NUL-terminated, `list` is a valid
    // attrlist and the kernel writes at most `out.len()` bytes into `out`.
    let rc = unsafe {
        libc::getattrlistat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            (&mut list as *mut libc::attrlist).cast(),
            out.as_mut_ptr().cast(),
            out.len(),
            (libc::FSOPT_NOFOLLOW | libc::FSOPT_ATTR_CMN_EXTENDED) as libc::c_ulong,
        )
    };
    if rc != 0 {
        return None;
    }
    let mut r = Reader::new(&out);
    r.skip(4 + 16).ok()?; // length, common/vol/dir/file returned words
    let ret_ext = r.u32().ok()?;
    let private = r.u64().ok()?;
    (ret_ext & libc::ATTR_CMNEXT_PRIVATESIZE != 0).then_some(private)
}

fn open_dir(dir: &Path) -> io::Result<std::fs::File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
}

/// List the open directory, requesting `ext_attrs` from the CMNEXT group (which must
/// contain CLONEID and EXT_FLAGS, and may contain PRIVATESIZE).
fn list(
    file: &std::fs::File,
    buf: &mut Vec<u8>,
    ext_attrs: libc::attrgroup_t,
) -> io::Result<Vec<RawEntry>> {
    if buf.len() < INITIAL_BUF {
        buf.resize(INITIAL_BUF, 0);
    }
    let mut list = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: COMMON_ATTRS,
        volattr: 0,
        dirattr: 0,
        fileattr: FILE_ATTRS,
        forkattr: ext_attrs,
    };
    let mut out = Vec::new();
    loop {
        // SAFETY: the fd is open for the lifetime of `file`; `list` is a valid attrlist;
        // the kernel writes at most `buf.len()` bytes into `buf`.
        let n = unsafe {
            libc::getattrlistbulk(
                file.as_raw_fd(),
                (&mut list as *mut libc::attrlist).cast(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                OPTIONS,
            )
        };
        match n {
            0 => return Ok(out),
            n if n > 0 => parse_batch(buf, n as usize, ext_attrs, &mut out)?,
            _ => {
                let err = io::Error::last_os_error();
                if err.kind() != io::ErrorKind::Interrupted {
                    return Err(err);
                }
            }
        }
    }
}

// ---- Parser -----------------------------------------------------------------

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Parse `count` packed records from the start of `buf`, appending to `out`.
fn parse_batch(
    buf: &[u8],
    count: usize,
    ext_attrs: libc::attrgroup_t,
    out: &mut Vec<RawEntry>,
) -> io::Result<()> {
    let mut rest = buf;
    for _ in 0..count {
        let len = Reader::new(rest).u32()? as usize;
        if len < 4 || len > rest.len() {
            return Err(invalid("getattrlistbulk record length out of bounds"));
        }
        out.push(parse_record(&rest[..len], ext_attrs)?);
        rest = &rest[len..];
    }
    Ok(())
}

/// Parse one record. Layout: length, `attribute_set_t returned`, ERROR, then the common
/// attributes in bit order, the file group (absent for directories), the CMNEXT group.
/// With `FSOPT_PACK_INVAL_ATTRS` every requested field is packed; `returned` says which
/// carry real values. An entry with a non-zero error carries only NAME and ERROR.
fn parse_record(rec: &[u8], ext_attrs: libc::attrgroup_t) -> io::Result<RawEntry> {
    let mut r = Reader::new(rec);
    r.skip(4)?; // length
    let ret_common = r.u32()?;
    r.skip(4 * 2)?; // volattr, dirattr
    let ret_file = r.u32()?;
    let ret_ext = r.u32()?;
    let has = |set: u32, bit: u32| set & bit != 0;

    let mut e = RawEntry {
        name: OsString::new(),
        kind: ObjKind::Other,
        logical: 0,
        allocated: 0,
        private: None,
        mtime: 0,
        file_id: 0,
        link_count: 1,
        bsd_flags: 0,
        clone_id: None,
        ext_flags: None,
        error: None,
    };

    let error = r.u32()?;
    if has(ret_common, ATTR_CMN_ERROR) && error != 0 {
        e.error = Some(error as i32);
    }
    e.name = r.name()?;
    if e.error.is_some() {
        return Ok(e);
    }

    let objtype = r.u32()?;
    if has(ret_common, libc::ATTR_CMN_OBJTYPE) {
        e.kind = match objtype {
            VREG => ObjKind::File,
            VDIR => ObjKind::Dir,
            VLNK => ObjKind::Symlink,
            _ => ObjKind::Other,
        };
    }
    let mtime = r.i64()?;
    r.skip(8)?; // tv_nsec
    if has(ret_common, libc::ATTR_CMN_MODTIME) {
        e.mtime = mtime;
    }
    let flags = r.u32()?;
    if has(ret_common, libc::ATTR_CMN_FLAGS) {
        e.bsd_flags = flags;
    }
    let file_id = r.u64()?;
    if has(ret_common, libc::ATTR_CMN_FILEID) {
        e.file_id = file_id;
    }

    // The kernel omits the file group entirely for directories, even with PACK_INVAL_ATTRS.
    if objtype != VDIR {
        let link_count = r.u32()?;
        let logical = r.u64()?;
        let allocated = r.u64()?;
        if has(ret_file, libc::ATTR_FILE_LINKCOUNT) {
            e.link_count = link_count;
        }
        if has(ret_file, libc::ATTR_FILE_DATALENGTH) {
            e.logical = logical;
        }
        if has(ret_file, libc::ATTR_FILE_DATAALLOCSIZE) {
            e.allocated = allocated;
        }
    }

    // Only requested attributes are packed, so PRIVATESIZE is absent in the fast set.
    let private = if ext_attrs & libc::ATTR_CMNEXT_PRIVATESIZE != 0 {
        r.u64()?
    } else {
        0
    };
    let clone_id = r.u64()?;
    let ext_flags = r.u64()?;
    e.private = has(ret_ext, libc::ATTR_CMNEXT_PRIVATESIZE).then_some(private);
    e.clone_id = has(ret_ext, libc::ATTR_CMNEXT_CLONEID).then_some(clone_id);
    e.ext_flags = has(ret_ext, libc::ATTR_CMNEXT_EXT_FLAGS).then_some(ext_flags);
    Ok(e)
}

/// Bounds-checked cursor over one record. Fields are only 4-byte aligned, so everything
/// is decoded from byte slices rather than by pointer casts.
struct Reader<'a> {
    rec: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(rec: &'a [u8]) -> Self {
        Reader { rec, pos: 0 }
    }

    fn take<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let bytes = self
            .rec
            .get(self.pos..self.pos + N)
            .ok_or_else(|| invalid("getattrlistbulk record truncated"))?;
        self.pos += N;
        Ok(bytes.try_into().expect("slice has length N"))
    }

    fn skip(&mut self, n: usize) -> io::Result<()> {
        if self.pos + n > self.rec.len() {
            return Err(invalid("getattrlistbulk record truncated"));
        }
        self.pos += n;
        Ok(())
    }

    fn u32(&mut self) -> io::Result<u32> {
        self.take::<4>().map(u32::from_ne_bytes)
    }

    fn u64(&mut self) -> io::Result<u64> {
        self.take::<8>().map(u64::from_ne_bytes)
    }

    fn i64(&mut self) -> io::Result<i64> {
        self.take::<8>().map(i64::from_ne_bytes)
    }

    /// `attrreference_t` { i32 offset from the reference itself, u32 length incl. NUL }.
    fn name(&mut self) -> io::Result<OsString> {
        let at = self.pos;
        let offset = i32::from_ne_bytes(self.take::<4>()?);
        let len = self.u32()? as usize;
        let start = at
            .checked_add_signed(offset as isize)
            .ok_or_else(|| invalid("getattrlistbulk name offset out of bounds"))?;
        let bytes = self
            .rec
            .get(start..start + len)
            .ok_or_else(|| invalid("getattrlistbulk name out of bounds"))?;
        let bytes = bytes.split(|&b| b == 0).next().unwrap_or_default();
        Ok(OsString::from_vec(bytes.to_vec()))
    }
}
