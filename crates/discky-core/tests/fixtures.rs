//! Shared test fixture: a small on-disk tree with every case the scanner must get right.
//! Include from a test crate with `mod fixtures;` (or `#[path = ".../fixtures.rs"] mod fixtures;`).
#![allow(dead_code)]

use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

/// Logical size of `big.bin`. The sparse rule needs `logical - allocated > 1 GiB`, so the
/// file is 2 GiB logical with only its first 4 KiB written.
pub const BIG_LOGICAL: u64 = 2048 * MIB;

/// Expected numbers for the tree built by [`build_tree`]. All counts cover everything under
/// the root, excluding the root directory itself.
///
/// - `file_count`: number of non-directory entries (regular files; the fixture has no
///   symlinks). The hard-linked pair `linked/a` + `linked/b` counts as **two** (both names
///   exist). Directories are never counted. Equals the root's `agg_files`.
/// - `allocated_total`: sum of `metadata().blocks() * 512` over every regular file, with the
///   hard-linked pair counted **once**. Includes `big.bin`'s few real blocks, not its
///   logical size. Equals the root's `agg_allocated`.
/// - `logical_total`: sum of `metadata().len()` over the same entries as `file_count`
///   (each hard-link name counted, `big.bin` at its full logical size).
/// - `locked/` is an empty directory with mode `000`. It is not restored on drop, so it
///   stays unreadable even when the `Fixture` is discarded; its owner can still delete it,
///   so `tempfile` cleanup works.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fixture {
    pub file_count: u32,
    pub allocated_total: u64,
    pub logical_total: u64,
}

/// Build the fixture tree under `root` (created if missing):
///
/// ```text
/// proj/Cargo.toml, proj/target/debug/{a,b,c}.rlib      (3 × 1 MiB)
/// web/package.json, web/node_modules/pkg/index.js      (2 MiB)
/// Library/Caches/com.example.app/cache.db              (1 MiB)
/// Library/Application Support/Example/data.sqlite      (512 KiB)
/// big.bin                                              (2 GiB logical, sparse, 4 KiB written)
/// old/notes.txt                                        (dir and file mtime two years ago)
/// linked/a + hard link linked/b                        (64 KiB)
/// locked/                                              (empty, mode 000)
/// ```
pub fn build_tree(root: &Path) -> Fixture {
    let mut fx = Fixture {
        file_count: 0,
        allocated_total: 0,
        logical_total: 0,
    };
    let mut file = |rel: &str, size: u64| {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = File::create(&p).unwrap();
        f.write_all(&vec![0xA5; size as usize]).unwrap();
        f.sync_all().unwrap();
        fx.count(&p);
    };

    file("proj/Cargo.toml", 120);
    file("proj/target/debug/a.rlib", MIB);
    file("proj/target/debug/b.rlib", MIB);
    file("proj/target/debug/c.rlib", MIB);
    file("web/package.json", 80);
    file("web/node_modules/pkg/index.js", 2 * MIB);
    file("Library/Caches/com.example.app/cache.db", MIB);
    file("Library/Application Support/Example/data.sqlite", 512 * KIB);
    file("old/notes.txt", 4 * KIB);
    file("linked/a", 64 * KIB);

    let big = root.join("big.bin");
    let mut f = File::create(&big).unwrap();
    f.write_all(&[0x5A; 4096]).unwrap();
    f.set_len(BIG_LOGICAL).unwrap();
    f.sync_all().unwrap();
    drop(f);
    fx.count(&big);

    // Second name for linked/a: counted as a file, its blocks not counted again.
    fs::hard_link(root.join("linked/a"), root.join("linked/b")).unwrap();
    fx.file_count += 1;
    fx.logical_total += fs::metadata(root.join("linked/b")).unwrap().len();

    let two_years_ago = filetime::FileTime::from_unix_time(now() - 2 * 365 * 24 * 3600, 0);
    filetime::set_file_mtime(root.join("old/notes.txt"), two_years_ago).unwrap();
    filetime::set_file_mtime(root.join("old"), two_years_ago).unwrap();

    let locked = root.join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();

    fx
}

impl Fixture {
    fn count(&mut self, p: &Path) {
        let m = fs::symlink_metadata(p).unwrap();
        self.file_count += 1;
        self.allocated_total += m.blocks() * 512;
        self.logical_total += m.len();
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
