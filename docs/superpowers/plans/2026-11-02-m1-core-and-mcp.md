# Discky Milestone 1: Core + MCP Server — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Rust library (`discky-core`) that scans a Mac with honest APFS byte counts, categorizes findings by data-driven rules, plans and executes removals through official tools, plus a stdio MCP server (`discky-mcp`) exposing it to agents. Usable from Claude Code before any GUI exists.

**Architecture:** `discky-core` holds an arena-based directory index built with `getattrlistbulk`, a TOML rule set that turns index nodes and tool outputs into `Finding`s, a two-phase removal engine (`Plan` → `execute`), a persisted `Snapshot` shared between processes, and a JSONL removal history. `discky-mcp` is a thin `rmcp` server: ten tools, three resources, async scan via `scan_id` polling, progress notifications, and the Tasks extension when the client declares it.

**Tech Stack:** Rust 1.99 (edition 2024), `libc` 0.2 (getattrlistbulk FFI), `rayon` (parallel walk), `serde` + `postcard` (snapshot), `toml`, `globset`, `xxhash-rust` (finding ids), `ureq` 3 (ollama HTTP), `fd-lock` (snapshot lock), `rmcp` 3.8 (`server`, `macros`, `transport-io`), `tokio`, `schemars`, `clap`, `tempfile` + `assert_cmd` for tests.

**Spec:** `docs/superpowers/specs/2026-11-02-discky-design.md` (Russian). This plan implements §4–§7, §12, §12b, §12c and the Milestone 1 line of §12d; it excludes the app uninstaller (§8), mise (§9), treemap (§10) and GUI (§11).

## Global Constraints

- All user-visible strings, rule texts, tool descriptions and docs are **English** (spec §12a).
- Default size everywhere is `allocated` (`ATTR_FILE_DATAALLOCSIZE`); "freed if deleted" is `ATTR_CMNEXT_PRIVATESIZE`, falling back to `allocated` when the attribute is not returned (spec §5).
- Hard links counted once per `ATTR_CMN_FILEID`; duplicates carry size 0 and a flag (spec §5).
- Files with `SF_DATALESS` (0x40000000) are never opened; the process sets `setiopolicy_np(IOPOL_TYPE_VFS_MATERIALIZE_DATALESS_FILES=3, IOPOL_SCOPE_PROCESS=0, IOPOL_MATERIALIZE_DATALESS_FILES_OFF=1)` before scanning (spec §5).
- Sparse flag: `allocated < logical * 0.9` and `logical - allocated > 1 GiB` (spec §5).
- Scan never crosses mount points; never enters `/System`, `/private/var/vm`, `/Volumes` (spec §5).
- Default scan roots: `~`, `/Applications`, `/Library`, `/usr/local`, `/opt/homebrew` (spec §17.7).
- Nodes without a rule never become findings (spec §17.3).
- A failed official command stops the plan; there is no `rm` fallback (spec §7).
- Removal mode setting (`trash` default / `permanent`) applies only to `Trash`/`Remove` steps, never to tool commands (spec §7).
- Trash via `/usr/bin/trash`; minimum macOS 15 (spec §13).
- MCP `execute_plan` refuses everything when `mcp.allow_agent_delete=false`; with it on, skips steps flagged `interactive` and reports them (spec §12c).
- Files: config `~/Library/Application Support/Discky/config.toml`, snapshot `~/Library/Application Support/Discky/snapshot.bin`, log `~/Library/Logs/Discky/removals.log` (spec §4). All overridable by `DISCKY_HOME` env var for tests.
- Snapshot header records format version, time, actor (`app`/`mcp`), roots, no-access paths (spec §12b).
- Performance targets: ≥150k files/s scan, ≤1 GiB RSS for 4M nodes, snapshot load ≤1 s (spec §14).

## Review Focus

Inputs the spec implies but which are easy to get wrong; each has a pinned test in the owning task:

1. **A root the user cannot read** (`~/Library/Mail` without FDA): the node must appear flagged `NO_ACCESS`, listed in `Index::errors`, and the scan must finish with a total — never abort. → Task 3.
2. **A sparse disk image** (OrbStack `data.img.raw`, 460 GB logical / 11 GB allocated): `allocated` is the number shown, `SPARSE` flag set, `logical` kept. → Task 2 (unit) and Task 3 (fixture).
3. **A plan executed after the filesystem changed** (user emptied a cache manually between `plan_removal` and `execute_plan`): execution must refuse with `PlanStale` naming the path, not silently "succeed" on nothing. → Task 10.
4. **An official tool missing** (`cargo-cache` not installed): the finding still shows, `plan_removal` marks the step `tool_missing` with an install hint, `execute_plan` fails that step and stops. → Task 9 and Task 10.
5. **Two processes writing the snapshot concurrently** (app and MCP both finish a scan): the loser must not corrupt the file; the reader must always get a complete snapshot (temp file + rename under lock). → Task 6.

---

## File Structure

```
Cargo.toml                          workspace: members crates/*, shared [workspace.dependencies]
rust-toolchain.toml                 channel = "1.99.1"
crates/discky-core/
  Cargo.toml
  src/lib.rs                        pub mod re-exports; `Engine` facade
  src/paths.rs                      DisckyPaths: config/snapshot/log locations, DISCKY_HOME override
  src/config.rs                     Config (TOML): scan roots, removal mode, thresholds, mcp flag
  src/fs/mod.rs
  src/fs/attr.rs                    getattrlistbulk FFI → RawEntry (one directory at a time)
  src/fs/dataless.rs                set_no_materialize() wrapper for setiopolicy_np
  src/fs/walk.rs                    parallel walker: roots → Index
  src/index/mod.rs                  arena: Node, NodeId, NodeFlags, Index (paths, children, aggregates, find)
  src/index/snapshot.rs             Snapshot {meta, index, findings}; save/load with lock
  src/rules/mod.rs                  Rule, Matcher, Category, SafetyLabel, RuleSet::builtin()/from_toml()
  src/rules/builtin.toml            the shipped rule table
  src/findings/mod.rs               Finding, FindingId, Removal; categorize(): rules over index
  src/findings/builds.rs            project build dirs (marker-file matcher)
  src/findings/large_old.rs         large files / stale dirs outside other categories
  src/findings/app_caches.rs        owner-app grouping under ~/Library/*
  src/findings/models.rs            ollama (HTTP + manifest fallback), HF hub, oMLX, LM Studio
  src/tools/mod.rs                  ToolAdapter: which CLI, is it installed, how to clean
  src/plan/mod.rs                   Plan, Step, StepKind, StepFlags, Fingerprint; plan_removal()
  src/plan/execute.rs               execute_plan(): trash / rm / command / http-delete, stop on failure
  src/history.rs                    JSONL removals log; history(); in_trash()
  src/query.rs                      tree(), search(), disk_overview()
  src/scan.rs                       ScanId, ScanJob, Progress; Engine::start_scan / scan_status / wait
  tests/fixtures.rs                 helper: build a temp tree (sparse file, hard links, build dirs, caches)
  tests/*.rs                        integration tests per task
crates/discky-mcp/
  Cargo.toml
  src/main.rs                       clap args, tracing to stderr, serve over stdio
  src/server.rs                     DisckyServer: #[tool_router], ServerHandler (resources, get_info)
  src/params.rs                     schemars param/output structs for every tool
  src/tasks.rs                      Tasks-extension path for `scan`
  tests/stdio.rs                    end-to-end: spawn binary, initialize, call tools over stdio
```

---

### Task 1: Workspace, paths, config

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `.gitignore`, `crates/discky-core/Cargo.toml`, `crates/discky-core/src/lib.rs`, `crates/discky-core/src/paths.rs`, `crates/discky-core/src/config.rs`
- Test: `crates/discky-core/tests/config.rs`

**Interfaces:**
- Produces:
  - `pub struct DisckyPaths { pub config: PathBuf, pub snapshot: PathBuf, pub log: PathBuf }`
  - `impl DisckyPaths { pub fn resolve() -> DisckyPaths }` — uses `$DISCKY_HOME/{config.toml,snapshot.bin,removals.log}` when the env var is set, else the spec's three locations.
  - `pub enum RemovalMode { Trash, Permanent }`
  - `pub struct Config { pub scan: ScanConfig, pub removal: RemovalConfig, pub thresholds: Thresholds, pub mcp: McpConfig }` with `ScanConfig { roots: Vec<PathBuf>, exclude: Vec<String> }`, `RemovalConfig { mode: RemovalMode, remind_trash: bool }`, `Thresholds { large_file_bytes: u64, old_days: u32 }`, `McpConfig { allow_agent_delete: bool }`. All `serde` + `Default`; defaults are the Global Constraints values (`large_file_bytes = 524_288_000`, `old_days = 365`, `allow_agent_delete = false`, `mode = Trash`, `remind_trash = true`).
  - `impl Config { pub fn load(paths: &DisckyPaths) -> Result<Config, ConfigError>; pub fn save(&self, paths: &DisckyPaths) -> Result<(), ConfigError> }` — missing file ⇒ `Config::default()`; `~` in roots expanded on load.

- [ ] **Step 1: Init git repo and workspace**

```bash
cd <repo> && git init -b main
```
`Cargo.toml`: `[workspace] members = ["crates/*"] resolver = "3"`; `[workspace.package] edition = "2024", license = "MIT", rust-version = "1.99"`; `[workspace.dependencies]` listing every crate from Tech Stack with the versions checked on 2026-11-02: `libc = "0.2"`, `rayon = "1"`, `serde = { version = "1", features = ["derive"] }`, `postcard = { version = "1.1", features = ["use-std"] }`, `toml = "1"`, `globset = "0.4"`, `xxhash-rust = { version = "0.8", features = ["xxh3"] }`, `ureq = { version = "3", features = ["json"] }`, `fd-lock = "4"`, `thiserror = "2"`, `serde_json = "1"`, `rmcp = { version = "3.8", features = ["server", "macros", "transport-io"] }`, `tokio = { version = "1", features = ["rt-multi-thread", "macros", "sync", "time", "process"] }`, `schemars = "1"`, `clap = { version = "4", features = ["derive"] }`, `tracing = "0.1"`, `tracing-subscriber = { version = "0.3", features = ["env-filter"] }`, `tempfile = "3"`, `assert_cmd = "2"`.
`.gitignore`: `/target`, `.superpowers/`, `.DS_Store`.

- [ ] **Step 2: Write the failing test** `crates/discky-core/tests/config.rs`

```rust
#[test]
fn defaults_match_spec() {
    let c = discky_core::Config::default();
    assert_eq!(c.thresholds.large_file_bytes, 524_288_000);
    assert_eq!(c.thresholds.old_days, 365);
    assert!(!c.mcp.allow_agent_delete);
    assert!(matches!(c.removal.mode, discky_core::RemovalMode::Trash));
    assert_eq!(c.scan.roots.len(), 5);
}

#[test]
fn load_missing_file_gives_default_and_save_roundtrips() {
    let dir = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("DISCKY_HOME", dir.path()) };
    let paths = discky_core::DisckyPaths::resolve();
    assert_eq!(paths.config, dir.path().join("config.toml"));
    let mut c = discky_core::Config::load(&paths).unwrap();
    c.mcp.allow_agent_delete = true;
    c.save(&paths).unwrap();
    assert!(discky_core::Config::load(&paths).unwrap().mcp.allow_agent_delete);
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `cargo test -p discky-core --test config`
Expected: compile error, `Config` not found.

- [ ] **Step 4: Implement `paths.rs` and `config.rs`** per Interfaces; `lib.rs` declares `pub mod paths; pub mod config;` and re-exports `DisckyPaths, Config, RemovalMode`.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test -p discky-core --test config`
Expected: 2 passed.

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(core): workspace, paths and config"
```

---

### Task 2: `getattrlistbulk` FFI and dataless policy

**Files:**
- Create: `crates/discky-core/src/fs/mod.rs`, `crates/discky-core/src/fs/attr.rs`, `crates/discky-core/src/fs/dataless.rs`
- Test: `crates/discky-core/tests/attr.rs`

**Interfaces:**
- Produces:
  - `pub enum ObjKind { File, Dir, Symlink, Other }`
  - `pub struct RawEntry { pub name: OsString, pub kind: ObjKind, pub logical: u64, pub allocated: u64, pub private: Option<u64>, pub mtime: i64, pub file_id: u64, pub link_count: u32, pub bsd_flags: u32, pub clone_id: Option<u64>, pub ext_flags: Option<u64>, pub error: Option<i32> }`
  - `pub fn read_dir_bulk(dir: &Path, buf: &mut Vec<u8>) -> io::Result<Vec<RawEntry>>` — opens with `O_RDONLY|O_DIRECTORY|O_NOFOLLOW`, calls `libc::getattrlistbulk` in a loop until it returns 0, options `FSOPT_NOFOLLOW | FSOPT_PACK_INVAL_ATTRS | FSOPT_ATTR_CMN_EXTENDED`; requested groups: common `NAME|RETURNED_ATTRS|ERROR|OBJTYPE|MODTIME|FLAGS|FILEID`, file `LINKCOUNT|DATALENGTH|DATAALLOCSIZE`, forkattr (extended) `PRIVATESIZE|CLONEID|EXT_FLAGS`. `buf` is reused across calls (start 256 KiB). Attributes absent from `returned_attrs` yield `None`/0; `ATTR_CMN_ERROR` is surfaced per entry, not as a failed call.
  - `pub const SF_DATALESS: u32 = 0x4000_0000;` `pub fn is_dataless(bsd_flags: u32) -> bool`
  - `pub fn is_sparse(logical: u64, allocated: u64) -> bool` — the Global Constraints rule.
  - `pub fn set_no_materialize() -> io::Result<()>` in `dataless.rs` — `extern "C" { fn setiopolicy_np(iotype: c_int, scope: c_int, policy: c_int) -> c_int; }` with constants `3, 0, 1`.

Note for the implementer: parse order inside each record is `u32 length`, `attribute_set_t returned`, then common attrs in bit order, then file attrs, then forkattr; `ATTR_CMN_NAME` is an `attrreference_t` (offset relative to its own position). `ATTR_CMN_ERROR` must be read before any other common attr after `RETURNED_ATTRS`. `libc` 0.2 lacks `ATTR_CMN_ERROR` (0x20000000) and `SF_DATALESS`; define them locally.

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/attr.rs`

```rust
use discky_core::fs::attr::{read_dir_bulk, ObjKind, is_sparse};
use std::os::unix::fs::MetadataExt;

#[test]
fn reads_names_kinds_and_sizes() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("a.txt"), vec![7u8; 10_000]).unwrap();
    std::fs::create_dir(d.path().join("sub")).unwrap();
    std::os::unix::fs::symlink("a.txt", d.path().join("ln")).unwrap();
    let mut buf = Vec::new();
    let mut e = read_dir_bulk(d.path(), &mut buf).unwrap();
    e.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(e.len(), 3);
    assert_eq!(e[0].name, "a.txt"); assert!(matches!(e[0].kind, ObjKind::File));
    assert_eq!(e[0].logical, 10_000);
    assert_eq!(e[0].allocated, std::fs::metadata(d.path().join("a.txt")).unwrap().blocks() * 512);
    assert!(matches!(e[1].kind, ObjKind::Symlink));
    assert!(matches!(e[2].kind, ObjKind::Dir));
}

#[test]
fn sparse_file_reports_small_allocation() {
    let d = tempfile::tempdir().unwrap();
    let f = std::fs::File::create(d.path().join("disk.img")).unwrap();
    f.set_len(4 * 1024 * 1024 * 1024).unwrap(); // 4 GiB logical, ~0 allocated
    let mut buf = Vec::new();
    let e = read_dir_bulk(d.path(), &mut buf).unwrap();
    assert_eq!(e[0].logical, 4 * 1024 * 1024 * 1024);
    assert!(e[0].allocated < 1024 * 1024);
    assert!(is_sparse(e[0].logical, e[0].allocated));
    assert!(e[0].private.is_some(), "APFS should return PRIVATESIZE");
}

#[test]
fn hard_links_share_file_id_and_report_link_count() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("x"), b"hello").unwrap();
    std::fs::hard_link(d.path().join("x"), d.path().join("y")).unwrap();
    let mut buf = Vec::new();
    let e = read_dir_bulk(d.path(), &mut buf).unwrap();
    assert_eq!(e[0].file_id, e[1].file_id);
    assert_eq!(e[0].link_count, 2);
}

#[test]
fn unreadable_dir_is_an_error_not_a_panic() {
    assert!(read_dir_bulk(std::path::Path::new("/nonexistent-discky"), &mut Vec::new()).is_err());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p discky-core --test attr`
Expected: compile error, module `fs` not found.

- [ ] **Step 3: Implement `fs/attr.rs` and `fs/dataless.rs`** per Interfaces. Add `pub mod fs;` to `lib.rs`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p discky-core --test attr`
Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add -A && git commit -m "feat(core): getattrlistbulk FFI with APFS private size, sparse and dataless detection"
```

---

### Task 3: Arena index and parallel walker

**Files:**
- Create: `crates/discky-core/src/index/mod.rs`, `crates/discky-core/src/fs/walk.rs`, `crates/discky-core/tests/fixtures.rs`
- Test: `crates/discky-core/tests/walk.rs`

**Interfaces:**
- Consumes: `read_dir_bulk`, `RawEntry`, `is_sparse`, `is_dataless`, `set_no_materialize` (Task 2).
- Produces:
  - `#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)] pub struct NodeId(pub u32);`
  - `bitflags! pub struct NodeFlags: u16 { SPARSE, DATALESS, HARDLINK_DUP, NO_ACCESS, CLONE_SHARED, ROOT }` (use the `bitflags` crate, add to workspace deps).
  - `pub struct Node { pub parent: Option<NodeId>, pub name: (u32, u16) /* offset,len into Index::names */, pub kind: ObjKind, pub logical: u64, pub allocated: u64, pub private: u64, pub mtime: i64, pub flags: NodeFlags, pub first_child: Option<NodeId>, pub next_sibling: Option<NodeId>, pub agg_allocated: u64, pub agg_private: u64, pub agg_logical: u64, pub agg_files: u32, pub max_mtime: i64 }` (`Serialize, Deserialize`).
  - `pub struct Index { pub nodes: Vec<Node>, pub names: Vec<u8>, pub roots: Vec<NodeId>, pub scanned_at: i64, pub errors: Vec<ScanError> }` with `pub struct ScanError { pub path: PathBuf, pub errno: i32 }`.
  - `impl Index { pub fn name(&self, id: NodeId) -> &OsStr; pub fn path(&self, id: NodeId) -> PathBuf; pub fn children(&self, id: NodeId) -> impl Iterator<Item = NodeId> + '_; pub fn find(&self, path: &Path) -> Option<NodeId>; pub fn node(&self, id: NodeId) -> &Node; pub fn total_allocated(&self) -> u64; pub fn len(&self) -> usize }`.
  - `pub struct ScanOptions { pub roots: Vec<PathBuf>, pub exclude: globset::GlobSet, pub threads: usize /* 0 = available_parallelism */ }`
  - `pub struct Progress { pub files: u64, pub dirs: u64, pub allocated: u64, pub current: Option<PathBuf> }`
  - `pub fn walk(opts: &ScanOptions, on_progress: &(dyn Fn(&Progress) + Sync)) -> Index` in `fs/walk.rs` — rayon scope; each directory enumerated with `read_dir_bulk` into a per-directory `Vec<RawEntry>` sent over a channel to a single builder thread that appends to the arena; progress callback at most every 50 ms; skips `/System`, `/private/var/vm`, `/Volumes`; does not descend when the child's `st_dev` differs (compare `libc::fstatat` dev of root vs dir — one `fstat` on the open dirfd per directory is acceptable); dataless entries recorded with `DATALESS`, never opened; hard-link duplicates (same `file_id`, `link_count > 1`, already seen) get `allocated = private = 0` and `HARDLINK_DUP`; EACCES/EPERM/ENOENT on a directory ⇒ node flagged `NO_ACCESS`, pushed to `errors`, walk continues; after the walk, aggregates computed bottom-up (`agg_*`, `max_mtime`).
  - `tests/fixtures.rs`: `pub fn build_tree(root: &Path) -> Fixture` creating: `proj/Cargo.toml` + `proj/target/` (3 MiB), `web/package.json` + `web/node_modules/` (2 MiB), `Library/Caches/com.example.app/` (1 MiB), `Library/Application Support/Example/` (512 KiB), `big.bin` (600 MiB sparse via `set_len`, so it is both large and sparse), `old/` dir with mtime set to 2 years ago (`filetime` crate, add to dev-deps), `linked/a` + hard link `linked/b` (64 KiB), `locked/` dir with mode 000 (restored in `Drop`). Returns expected totals so tests can assert.

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/walk.rs`

```rust
mod fixtures;
use discky_core::{fs::walk::{walk, ScanOptions}, index::NodeFlags};

fn opts(root: &std::path::Path) -> ScanOptions {
    ScanOptions { roots: vec![root.to_path_buf()], exclude: globset::GlobSet::empty(), threads: 0 }
}

#[test]
fn walk_counts_every_file_once_and_sums_allocated() {
    let d = tempfile::tempdir().unwrap();
    let fx = fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    assert_eq!(idx.roots.len(), 1);
    let root = idx.node(idx.roots[0]);
    assert_eq!(root.agg_files, fx.file_count);
    assert_eq!(root.agg_allocated, fx.allocated_total, "hard link counted once, sparse by blocks");
}

#[test]
fn sparse_and_hardlink_flags_are_set() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    let big = idx.find(&d.path().join("big.bin")).unwrap();
    assert!(idx.node(big).flags.contains(NodeFlags::SPARSE));
    assert!(idx.node(big).logical > idx.node(big).allocated * 100);
    let a = idx.find(&d.path().join("linked/a")).unwrap();
    let b = idx.find(&d.path().join("linked/b")).unwrap();
    let dups = [a, b].iter().filter(|n| idx.node(**n).flags.contains(NodeFlags::HARDLINK_DUP)).count();
    assert_eq!(dups, 1);
}

#[test]
fn unreadable_dir_is_flagged_and_reported_not_fatal() {
    let d = tempfile::tempdir().unwrap();
    let _fx = fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    let locked = idx.find(&d.path().join("locked")).unwrap();
    assert!(idx.node(locked).flags.contains(NodeFlags::NO_ACCESS));
    assert!(idx.errors.iter().any(|e| e.path.ends_with("locked") && e.errno == libc::EACCES));
}

#[test]
fn path_roundtrip_and_children() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let idx = walk(&opts(d.path()), &|_| {});
    let t = idx.find(&d.path().join("proj/target")).unwrap();
    assert_eq!(idx.path(t), d.path().join("proj/target"));
    let proj = idx.find(&d.path().join("proj")).unwrap();
    assert!(idx.children(proj).any(|c| c == t));
}

#[test]
fn exclude_glob_prunes_subtree() {
    let d = tempfile::tempdir().unwrap();
    fixtures::build_tree(d.path());
    let mut b = globset::GlobSetBuilder::new();
    b.add(globset::Glob::new("**/node_modules").unwrap());
    let o = ScanOptions { exclude: b.build().unwrap(), ..opts(d.path()) };
    let idx = walk(&o, &|_| {});
    assert!(idx.find(&d.path().join("web/node_modules")).is_none());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p discky-core --test walk`
Expected: compile error, `index`/`walk` not found.

- [ ] **Step 3: Implement `index/mod.rs`, `fs/walk.rs`, `tests/fixtures.rs`** per Interfaces.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test -p discky-core --test walk`
Expected: 5 passed.

- [ ] **Step 5: Add a throughput smoke benchmark (ignored test)** in `tests/walk.rs`:

```rust
#[test] #[ignore]
fn home_scan_throughput() {
    let home = std::env::var("HOME").unwrap();
    let t = std::time::Instant::now();
    let idx = walk(&opts(std::path::Path::new(&home)), &|_| {});
    let secs = t.elapsed().as_secs_f64();
    eprintln!("{} nodes in {:.1}s = {:.0} files/s", idx.len(), secs, idx.len() as f64 / secs);
    assert!(idx.len() as f64 / secs > 150_000.0);
}
```
Run once: `cargo test -p discky-core --release --test walk -- --ignored home_scan_throughput --nocapture`
Expected: prints a rate ≥ 150 000 files/s on the owner's machine. If below, profile before moving on (likely causes: builder thread as bottleneck, too-small buffer, per-entry allocations).

- [ ] **Step 6: Commit**

```bash
git add -A && git commit -m "feat(core): arena index and parallel getattrlistbulk walker"
```

---

### Task 4: Rule set (data) and matcher

**Files:**
- Create: `crates/discky-core/src/rules/mod.rs`, `crates/discky-core/src/rules/builtin.toml`
- Test: `crates/discky-core/tests/rules.rs`

**Interfaces:**
- Produces:
  - `pub enum Category { Apps, AppCaches, Models, DevCaches, ProjectBuilds, LanguageVersions, LargeOld }` (serde `snake_case`, `Display` = the English sidebar names: "Applications", "App caches", "Models", "Dev caches", "Project builds", "Language versions", "Large & old").
  - `pub enum SafetyLabel { Regenerates, AppData, NeedsPassword, AppRunning, DoNotTouch }` (serde `snake_case`).
  - `pub enum Matcher { Path { path: PathBuf }, Glob { glob: String }, BuildDir { name: String, marker: String } }`
  - `pub struct RuleCommand { pub tool: String, pub argv: Vec<String>, pub install_hint: Option<String>, pub freed_note: Option<String> }`
  - `pub struct Rule { pub id: String, pub category: Category, pub matcher: Matcher, pub label: SafetyLabel, pub title: String, pub explain: String, pub command: Option<RuleCommand>, pub per_child: bool /* each direct child is its own finding, e.g. HF hub repos */ }`
  - `pub struct RuleSet { rules: Vec<Rule>, globs: GlobSet /* compiled Glob matchers in rule order */ }`
  - `impl RuleSet { pub fn builtin() -> RuleSet; pub fn from_toml(s: &str) -> Result<RuleSet, RuleError>; pub fn match_path(&self, path: &Path) -> Option<&Rule> /* first Path or Glob hit, Path rules before Glob rules */; pub fn build_rules(&self) -> impl Iterator<Item=&Rule>; pub fn get(&self, id: &str) -> Option<&Rule> }`. `~` in `Path`/`Glob` matchers is expanded with `$HOME` at load.
  - `builtin.toml` contents (TOML array `[[rule]]`, English texts). Required entries, verbatim ids:
    - DevCaches / Regenerates: `cargo-registry` (`~/.cargo/registry`, tool `cargo-cache`, argv `["cargo","cache","--autoclean"]`, hint "cargo install cargo-cache"), `cargo-git` (`~/.cargo/git`, same tool), `rustup-toolchains` (`~/.rustup/toolchains`, no command ⇒ Trash), `npm-cache` (`~/.npm/_cacache`, `npm cache clean --force`), `pnpm-store` (`~/Library/pnpm/store`, `pnpm store prune`), `pnpm-cache` (`~/Library/Caches/pnpm`), `yarn-cache` (`~/Library/Caches/Yarn`, `yarn cache clean`), `pip-cache` (`~/Library/Caches/pip`, `pip3 cache purge`), `uv-cache` (`~/.cache/uv`, `uv cache clean`), `go-modcache` (`~/go/pkg/mod`, `go clean -modcache`), `gem-cache` (`~/.gem`, no command), `cocoapods-cache` (`~/Library/Caches/CocoaPods`, `pod cache clean --all`), `swiftpm-cache` (`~/Library/Caches/org.swift.swiftpm`, `swift package purge-cache`), `gradle-caches` (`~/.gradle/caches`), `xcode-deriveddata` (`~/Library/Developer/Xcode/DerivedData`), `xcode-devicesupport` (`~/Library/Developer/Xcode/iOS DeviceSupport`), `xcode-archives` (`~/Library/Developer/Xcode/Archives`, label AppData), `coresimulator` (`~/Library/Developer/CoreSimulator`, `xcrun simctl delete unavailable`, freed_note "Only runtimes no longer supported by the current Xcode are removed"), `homebrew-cache` (`~/Library/Caches/Homebrew`, `brew cleanup --prune=all`), `playwright-browsers` (`~/Library/Caches/ms-playwright`), `docker-desktop-disk` (`~/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw`, `docker system prune -f`, label AppData, freed_note "Frees space inside the VM; the host image shrinks later"), `orbstack-disk` (`~/Library/Group Containers/HUAQ24HBR6.dev.orbstack/data/data.img.raw`, `docker system prune -f`, AppData, same note), `codex-runtimes` (`~/.cache/codex-runtimes`), `codebase-memory-cache` (`~/.cache/codebase-memory-mcp`).
    - Models: `ollama-models` (`~/.ollama/models`, handled by `findings/models.rs`, `per_child = false`, label AppData), `hf-hub` (`~/.cache/huggingface/hub`, `per_child = true`, tool `hf`, argv template `["hf","cache","rm","{repo}","-y"]`, hint "pip install -U huggingface_hub"), `omlx-models` (`~/.omlx/models`, per_child), `lmstudio-models` (`~/.lmstudio/models`, per_child), `macwhisper-models` (`~/Library/Application Support/MacWhisper/models`, per_child, AppData).
    - ProjectBuilds / Regenerates, `BuildDir`: `cargo-target` (`target`/`Cargo.toml`, command `cargo clean` run with cwd = project), `node-modules` (`node_modules`/`package.json`), `python-venv` (`.venv`/`pyproject.toml`), `python-venv-legacy` (`venv`/`requirements.txt`), `next-build` (`.next`/`package.json`), `gradle-build` (`build`/`build.gradle`), `gradle-build-kts` (`build`/`build.gradle.kts`), `dist` (`dist`/`package.json`).
    - AppCaches (matched structurally in Task 7, but these overrides exist as rules): `claude-vm-bundles` (`~/Library/Application Support/Claude/vm_bundles`, AppData, explain "Claude Desktop VM images; re-downloaded when needed"), `vscode-shipit` (`~/Library/Caches/com.microsoft.VSCode.ShipIt`, Regenerates), `slack-shipit` (`~/Library/Caches/com.tinyspeck.slackmacgap.ShipIt`, Regenerates), `chrome-profile` (`~/Library/Application Support/Google/Chrome`, DoNotTouch), `drivefs-cache` (`~/Library/Application Support/Google/DriveFS`, AppData).
    - DoNotTouch: `keychains` (`~/Library/Keychains`), `mail` (`~/Library/Mail`), `messages` (`~/Library/Messages`), `photos-library` (`~/Pictures/*.photoslibrary` glob), `icloud` (`~/Library/Mobile Documents`), `cloudstorage` (`~/Library/CloudStorage`).

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/rules.rs`

```rust
use discky_core::rules::{RuleSet, Category, SafetyLabel, Matcher};
use std::path::Path;

#[test]
fn builtin_parses_and_has_required_ids() {
    let rs = RuleSet::builtin();
    for id in ["cargo-registry","hf-hub","cargo-target","orbstack-disk","keychains","coresimulator"] {
        assert!(rs.get(id).is_some(), "missing rule {id}");
    }
}

#[test]
fn path_rule_matches_expanded_home() {
    let rs = RuleSet::builtin();
    let home = std::env::var("HOME").unwrap();
    let r = rs.match_path(Path::new(&format!("{home}/.cargo/registry"))).unwrap();
    assert_eq!(r.id, "cargo-registry");
    assert!(matches!(r.category, Category::DevCaches));
    assert!(matches!(r.label, SafetyLabel::Regenerates));
    assert_eq!(r.command.as_ref().unwrap().argv[0], "cargo");
}

#[test]
fn glob_rule_matches_photoslibrary() {
    let rs = RuleSet::builtin();
    let home = std::env::var("HOME").unwrap();
    let r = rs.match_path(Path::new(&format!("{home}/Pictures/Photos Library.photoslibrary"))).unwrap();
    assert!(matches!(r.label, SafetyLabel::DoNotTouch));
}

#[test]
fn build_rules_are_exposed_separately() {
    let rs = RuleSet::builtin();
    let t = rs.build_rules().find(|r| r.id == "cargo-target").unwrap();
    assert!(matches!(&t.matcher, Matcher::BuildDir { name, marker } if name == "target" && marker == "Cargo.toml"));
}

#[test]
fn bad_toml_is_an_error_with_rule_id() {
    let e = RuleSet::from_toml("[[rule]]\nid = \"x\"\ncategory = \"nope\"").unwrap_err();
    assert!(e.to_string().contains("x") || e.to_string().contains("category"));
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p discky-core --test rules` → compile error.

- [ ] **Step 3: Implement `rules/mod.rs` and write `rules/builtin.toml`** (embedded with `include_str!`).

- [ ] **Step 4: Run to verify it passes** — `cargo test -p discky-core --test rules` → 5 passed.

- [ ] **Step 5: Commit** — `git commit -am "feat(core): data-driven rule set with builtin table"` (after `git add -A`).

---

### Task 5: Findings model and rule-based categorization

**Files:**
- Create: `crates/discky-core/src/findings/mod.rs`, `crates/discky-core/src/findings/builds.rs`, `crates/discky-core/src/findings/large_old.rs`
- Test: `crates/discky-core/tests/findings.rs`

**Interfaces:**
- Consumes: `Index`, `NodeId`, `NodeFlags` (Task 3); `RuleSet`, `Rule`, `Category`, `SafetyLabel` (Task 4); `Thresholds` (Task 1).
- Produces:
  - `pub struct FindingId(pub String)` — 16 hex chars of `xxh3_64` over `"{kind}:{canonical path or model name}"`; `kind` is `"path"`, `"ollama"`, `"hf"`, `"lmstudio"`, `"omlx"`.
  - `pub enum Removal { Trash { paths: Vec<PathBuf> }, Command { tool: String, argv: Vec<String>, cwd: Option<PathBuf>, install_hint: Option<String>, freed_note: Option<String> }, OllamaDelete { model: String }, None }`
  - `pub struct Finding { pub id: FindingId, pub category: Category, pub title: String, pub subtitle: Option<String>, pub path: Option<PathBuf>, pub node: Option<NodeId>, pub allocated: u64, pub logical: u64, pub freed_if_deleted: u64, pub modified: Option<i64>, pub label: SafetyLabel, pub rule_id: String, pub explain: String, pub removal: Removal, pub flags: Vec<String> /* "sparse", "no_access", "hardlinks" */ }`
  - `pub struct Categorizer<'a> { pub index: &'a Index, pub rules: &'a RuleSet, pub thresholds: &'a Thresholds }`
  - `impl Categorizer { pub fn run(&self) -> Vec<Finding> }` — order of passes: (1) rule paths/globs over every node (per_child rules emit one finding per direct child dir); (2) `builds::find(index, rules)` — a dir whose name matches a `BuildDir` rule and whose parent contains the marker file, and which is not inside `~/Library`, `~/.vscode`, `~/.cursor`, `~/.npm/_npx`, or another finding; `modified` = parent project's `max_mtime` excluding the build dir; (3) `large_old::find(index, thresholds, claimed: &HashSet<NodeId>)` — files `> large_file_bytes` or dirs with `max_mtime` older than `old_days` whose parent is not already in a finding, excluding DoNotTouch subtrees and `~/Library`; `~/Downloads` children always included with subtitle "Downloads". Every node under an earlier finding is marked claimed and skipped by later passes. Findings sorted by `freed_if_deleted` desc.
  - Helper: `pub fn finding_for_node(index, id, rule, cwd: Option<PathBuf>) -> Finding` — computes sizes from `agg_*`, `freed_if_deleted = agg_private`, flags from `NodeFlags`, removal from rule command or `Trash{paths:[path]}` when `command` is `None`, `Removal::None` for `DoNotTouch`.

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/findings.rs`

```rust
mod fixtures;
use discky_core::{fs::walk::{walk, ScanOptions}, rules::{RuleSet, Category, SafetyLabel}, findings::{Categorizer, Removal}, config::Thresholds};

fn scan(root: &std::path::Path) -> discky_core::index::Index {
    walk(&ScanOptions { roots: vec![root.into()], exclude: globset::GlobSet::empty(), threads: 0 }, &|_| {})
}

#[test]
fn build_dirs_become_project_build_findings_with_cwd_command() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let idx = scan(d.path());
    let f = Categorizer { index: &idx, rules: &RuleSet::builtin(), thresholds: &Thresholds::default() }.run();
    let t = f.iter().find(|f| f.rule_id == "cargo-target").expect("cargo target finding");
    assert!(matches!(t.category, Category::ProjectBuilds));
    assert!(matches!(&t.removal, Removal::Command { argv, cwd: Some(c), .. } if argv == &["cargo","clean"] && c == &d.path().join("proj")));
    assert!(f.iter().any(|f| f.rule_id == "node-modules"));
}

#[test]
fn large_file_is_found_with_sparse_flag_and_honest_size() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let idx = scan(d.path());
    let th = Thresholds { large_file_bytes: 100 * 1024 * 1024, old_days: 365 };
    let f = Categorizer { index: &idx, rules: &RuleSet::builtin(), thresholds: &th }.run();
    let big = f.iter().find(|f| f.path.as_deref() == Some(&d.path().join("big.bin"))).unwrap();
    assert!(matches!(big.category, Category::LargeOld));
    assert!(big.flags.iter().any(|x| x == "sparse"));
    assert!(big.allocated < 1024 * 1024 && big.logical >= 600 * 1024 * 1024);
}

#[test]
fn old_dir_is_found_and_claimed_nodes_are_not_double_reported() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let idx = scan(d.path());
    let f = Categorizer { index: &idx, rules: &RuleSet::builtin(), thresholds: &Thresholds::default() }.run();
    assert!(f.iter().any(|f| f.path.as_deref() == Some(&d.path().join("old")) && matches!(f.category, Category::LargeOld)));
    let target = d.path().join("proj/target");
    assert_eq!(f.iter().filter(|f| f.path.as_deref().map_or(false, |p| p.starts_with(&target))).count(), 1);
}

#[test]
fn finding_ids_are_stable_across_scans() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let rs = RuleSet::builtin(); let th = Thresholds::default();
    let a = Categorizer { index: &scan(d.path()), rules: &rs, thresholds: &th }.run();
    let b = Categorizer { index: &scan(d.path()), rules: &rs, thresholds: &th }.run();
    let ids = |v: &Vec<discky_core::findings::Finding>| v.iter().map(|f| f.id.0.clone()).collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids(&a), ids(&b));
}

#[test]
fn do_not_touch_rules_yield_no_removal() {
    let d = tempfile::tempdir().unwrap();
    let toml = format!("[[rule]]\nid=\"kc\"\ncategory=\"app_caches\"\nlabel=\"do_not_touch\"\ntitle=\"Keychains\"\nexplain=\"Never.\"\n[rule.matcher]\nkind=\"path\"\npath=\"{}\"\n", d.path().join("kc").display());
    std::fs::create_dir(d.path().join("kc")).unwrap();
    let rs = RuleSet::from_toml(&toml).unwrap();
    let idx = scan(d.path());
    let f = Categorizer { index: &idx, rules: &rs, thresholds: &Thresholds::default() }.run();
    assert!(matches!(f[0].removal, Removal::None));
    assert!(matches!(f[0].label, SafetyLabel::DoNotTouch));
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p discky-core --test findings` → compile error.

- [ ] **Step 3: Implement `findings/mod.rs`, `builds.rs`, `large_old.rs`** per Interfaces.

- [ ] **Step 4: Run to verify it passes** — 5 passed.

- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): findings model, build dirs, large & old"`.

---

### Task 6: Snapshot persistence with lock and actor

**Files:**
- Create: `crates/discky-core/src/index/snapshot.rs`
- Test: `crates/discky-core/tests/snapshot.rs`

**Interfaces:**
- Consumes: `Index` (Task 3), `Finding` (Task 5), `DisckyPaths` (Task 1).
- Produces:
  - `pub enum Actor { App, Mcp }` (serde `lowercase`, `Display`).
  - `pub struct SnapshotMeta { pub format_version: u32 /* = 1 */, pub created_at: i64, pub actor: Actor, pub roots: Vec<PathBuf>, pub no_access: Vec<PathBuf>, pub node_count: u32 }`
  - `pub struct Snapshot { pub meta: SnapshotMeta, pub index: Index, pub findings: Vec<Finding> }`
  - `impl Snapshot { pub fn save(&self, path: &Path) -> Result<(), SnapshotError>; pub fn load(path: &Path) -> Result<Snapshot, SnapshotError>; pub fn peek_meta(path: &Path) -> Result<SnapshotMeta, SnapshotError> }` — file layout: 8-byte magic `DISCKY01`, `u32` meta length, postcard(meta), postcard(index + findings). `save` writes to `path.with_extension("bin.tmp")` while holding `fd_lock::RwLock` write on `path.with_extension("lock")`, then `rename`. `load` takes the read lock. `peek_meta` reads only the header. Wrong magic / version ⇒ `SnapshotError::Incompatible`.

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/snapshot.rs`

```rust
mod fixtures;
use discky_core::{index::snapshot::{Snapshot, SnapshotMeta, Actor}, fs::walk::{walk, ScanOptions}};

fn snap(root: &std::path::Path, actor: Actor) -> Snapshot {
    let index = walk(&ScanOptions { roots: vec![root.into()], exclude: globset::GlobSet::empty(), threads: 0 }, &|_| {});
    let no_access = index.errors.iter().map(|e| e.path.clone()).collect();
    Snapshot { meta: SnapshotMeta { format_version: 1, created_at: 0, actor, roots: vec![root.into()], no_access, node_count: index.len() as u32 }, index, findings: vec![] }
}

#[test]
fn roundtrip_preserves_nodes_and_meta() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let s = snap(d.path(), Actor::Mcp);
    let p = d.path().join("snapshot.bin");
    s.save(&p).unwrap();
    let l = Snapshot::load(&p).unwrap();
    assert_eq!(l.index.len(), s.index.len());
    assert!(matches!(l.meta.actor, Actor::Mcp));
    assert!(l.meta.no_access.iter().any(|x| x.ends_with("locked")));
    assert!(matches!(Snapshot::peek_meta(&p).unwrap().actor, Actor::Mcp));
    assert!(!p.with_extension("bin.tmp").exists());
}

#[test]
fn concurrent_saves_never_leave_a_corrupt_file() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let p = d.path().join("snapshot.bin");
    let a = snap(d.path(), Actor::App); let b = snap(d.path(), Actor::Mcp);
    std::thread::scope(|s| {
        for _ in 0..5 { s.spawn(|| a.save(&p).unwrap()); s.spawn(|| b.save(&p).unwrap()); }
    });
    assert!(Snapshot::load(&p).is_ok());
}

#[test]
fn wrong_magic_is_incompatible() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("snapshot.bin");
    std::fs::write(&p, b"GARBAGEGARBAGE").unwrap();
    assert!(matches!(Snapshot::load(&p), Err(discky_core::index::snapshot::SnapshotError::Incompatible)));
}
```

- [ ] **Step 2: Run to verify it fails** → compile error.
- [ ] **Step 3: Implement `index/snapshot.rs`.**
- [ ] **Step 4: Run to verify it passes** → 3 passed.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): locked snapshot persistence with actor metadata"`.

---

### Task 7: App caches by owner app

**Files:**
- Create: `crates/discky-core/src/findings/app_caches.rs`
- Modify: `crates/discky-core/src/findings/mod.rs` (add pass between rules and builds)
- Test: `crates/discky-core/tests/app_caches.rs`

**Interfaces:**
- Consumes: `Index`, `Categorizer` internals (Task 5).
- Produces:
  - `pub struct OwnerHint { pub bundle_id: Option<String>, pub app_name: String }`
  - `pub fn owner_of(container_parent: &str, dir_name: &str) -> OwnerHint` — pure function: for `Caches`/`Containers`/`HTTPStorages`/`WebKit`/`Saved Application State` the dir name is a bundle id (`com.openai.codex` ⇒ app_name "codex", title-cased last component; `.savedState` suffix stripped); for `Group Containers` strip the leading team id (`HUAQ24HBR6.dev.orbstack` ⇒ bundle `dev.orbstack`, name "orbstack"; `group.net.whatsapp.WhatsApp.shared` ⇒ name "WhatsApp"); for `Application Support` the dir name is the app name and bundle id is `None`.
  - `pub fn find(index: &Index, home: &Path, claimed: &mut HashSet<NodeId>) -> Vec<Finding>` — one finding per direct child of `~/Library/{Caches, Application Support, Group Containers, Containers, HTTPStorages, WebKit, Saved Application State, Logs}` that is ≥ 1 MiB allocated and not already claimed by a rule; `category = AppCaches`; `label = Regenerates` for `Caches`, `AppData` otherwise; `title = app_name`, `subtitle = "<parent dir> · <bundle id or dir name>"`; `rule_id = "app-cache:<parent-dir-slug>"`; `explain` = fixed English sentence per parent dir (e.g. Caches: "Cache data the app can rebuild. Safe to remove; the app may start slower once."); `removal = Trash`.

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/app_caches.rs`

```rust
use discky_core::findings::app_caches::owner_of;

#[test]
fn owner_parsing() {
    assert_eq!(owner_of("Caches", "com.openai.codex").app_name, "Codex");
    assert_eq!(owner_of("Caches", "com.openai.codex").bundle_id.as_deref(), Some("com.openai.codex"));
    let o = owner_of("Group Containers", "HUAQ24HBR6.dev.orbstack");
    assert_eq!(o.bundle_id.as_deref(), Some("dev.orbstack")); assert_eq!(o.app_name, "Orbstack");
    assert_eq!(owner_of("Group Containers", "group.net.whatsapp.WhatsApp.shared").app_name, "WhatsApp");
    assert_eq!(owner_of("Application Support", "MacWhisper").app_name, "MacWhisper");
    assert_eq!(owner_of("Saved Application State", "com.apple.Preview.savedState").bundle_id.as_deref(), Some("com.apple.Preview"));
}

#[test]
fn library_children_become_app_cache_findings() {
    let d = tempfile::tempdir().unwrap();
    let lib = d.path().join("Library");
    for (p, kb) in [("Caches/com.example.big", 2048), ("Caches/com.example.tiny", 4), ("Application Support/Example", 1536)] {
        let dir = lib.join(p); std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blob"), vec![1u8; kb * 1024]).unwrap();
    }
    let idx = discky_core::fs::walk::walk(&discky_core::fs::walk::ScanOptions { roots: vec![d.path().into()], exclude: globset::GlobSet::empty(), threads: 0 }, &|_| {});
    let mut claimed = std::collections::HashSet::new();
    let f = discky_core::findings::app_caches::find(&idx, d.path(), &mut claimed);
    assert_eq!(f.len(), 2, "tiny cache below 1 MiB is skipped");
    let big = f.iter().find(|f| f.title == "Big").unwrap();
    assert!(matches!(big.label, discky_core::rules::SafetyLabel::Regenerates));
    assert!(f.iter().any(|f| f.title == "Example" && matches!(f.label, discky_core::rules::SafetyLabel::AppData)));
}
```

- [ ] **Step 2: Run to verify it fails.** — compile error.
- [ ] **Step 3: Implement `app_caches.rs`; wire into `Categorizer::run` after the rule pass** (so rule overrides like `claude-vm-bundles` win and the parent `Claude` folder is still reported minus claimed children — compute the finding's sizes as `agg_*` of the dir minus `agg_*` of claimed descendants).
- [ ] **Step 4: Run** `cargo test -p discky-core --test app_caches --test findings` → all pass.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): app caches grouped by owner app"`.

---

### Task 8: Model stores (ollama, HF hub, oMLX, LM Studio)

**Files:**
- Create: `crates/discky-core/src/findings/models.rs`
- Modify: `crates/discky-core/src/findings/mod.rs` (models pass replaces per_child handling for `ollama-models`, `hf-hub`, `omlx-models`, `lmstudio-models`)
- Test: `crates/discky-core/tests/models.rs`

**Interfaces:**
- Produces:
  - `pub struct OllamaModel { pub name: String, pub size: u64, pub modified_at: i64, pub digest: String }`
  - `pub fn ollama_list(base_url: &str) -> Result<Vec<OllamaModel>, ModelError>` — `GET {base_url}/api/tags` with 1 s timeout via `ureq`; parse `models[].{name,size,modified_at,digest}`.
  - `pub fn ollama_list_from_manifests(models_dir: &Path) -> Vec<OllamaModel>` — fallback when the server is down: walk `manifests/<registry>/<ns>/<name>/<tag>`; name = `ns/name:tag` with `library/` prefix dropped; size = sum of `layers[].size + config.size` from the manifest JSON.
  - `pub fn hf_repos(hub_dir: &Path) -> Vec<(String /* "org/name" */, PathBuf)>` — dirs named `models--org--name` ⇒ `org/name`.
  - `pub fn find(index: &Index, rules: &RuleSet, home: &Path, ollama_url: &str, claimed: &mut HashSet<NodeId>) -> Vec<Finding>` — ollama: one finding per model, `title = name`, `subtitle = "ollama · <quantization or family if present>"`, `allocated = size` from API (blobs are shared across models, so `freed_if_deleted` = size of blobs **not referenced by any other manifest**; compute from manifests when available, else = size), `removal = OllamaDelete{model}`, `path = None`, `node = None`, `flags = ["shared-blobs"]` when freed < size; `rule_id = "ollama-models"`. HF: one per repo dir, `removal = Command{tool:"hf", argv:["hf","cache","rm","org/name","-y"], install_hint}` if `hf` on PATH else `Trash`. oMLX / LM Studio: one per direct model dir, `Trash`. In-app model dirs (`macwhisper-models`) keep the generic per_child path from Task 5.

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/models.rs`

```rust
use discky_core::findings::models::{ollama_list_from_manifests, hf_repos, ollama_list};

#[test]
fn manifests_fallback_lists_models_with_sizes() {
    let d = tempfile::tempdir().unwrap();
    let m = d.path().join("manifests/registry.ollama.ai/library/qwen3/4b");
    std::fs::create_dir_all(m.parent().unwrap()).unwrap();
    std::fs::write(&m, r#"{"config":{"size":488},"layers":[{"size":1000},{"size":2000}]}"#).unwrap();
    let v = ollama_list_from_manifests(d.path());
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].name, "qwen3:4b");
    assert_eq!(v[0].size, 3488);
}

#[test]
fn hf_repo_names_are_decoded() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("models--Systran--faster-whisper-base")).unwrap();
    let v = hf_repos(d.path());
    assert_eq!(v[0].0, "Systran/faster-whisper-base");
}

#[test]
fn ollama_down_is_an_error_not_a_hang() {
    let t = std::time::Instant::now();
    assert!(ollama_list("http://127.0.0.1:9").is_err());
    assert!(t.elapsed().as_secs() < 3);
}

#[test] #[ignore]
fn ollama_live_matches_cli() {
    let v = ollama_list("http://127.0.0.1:11434").unwrap();
    assert!(v.iter().any(|m| m.name.starts_with("qwen3")));
}
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement `models.rs`; wire the pass into `Categorizer::run`** (models pass runs before the generic rule pass claims `~/.ollama/models`; the ollama base URL comes from `OLLAMA_HOST` env or default `http://127.0.0.1:11434`).
- [ ] **Step 4: Run** `cargo test -p discky-core --test models` → 3 passed, 1 ignored. Then `cargo test -p discky-core --test models -- --ignored` on the owner's machine → passes.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): model stores: ollama, HF hub, oMLX, LM Studio"`.

---

### Task 9: Tool adapters and plan building

**Files:**
- Create: `crates/discky-core/src/tools/mod.rs`, `crates/discky-core/src/plan/mod.rs`
- Test: `crates/discky-core/tests/plan.rs`

**Interfaces:**
- Consumes: `Finding`, `Removal` (Task 5); `Config`, `RemovalMode` (Task 1).
- Produces:
  - `pub fn tool_path(name: &str) -> Option<PathBuf>` in `tools/mod.rs` — PATH lookup plus fixed extras `/opt/homebrew/bin`, `/usr/local/bin`, `~/.cargo/bin`, `~/.local/bin`; `cargo-cache` is "installed" when `cargo cache --version` exits 0 (cache the result per process).
  - `pub fn running_app_bundle_ids() -> HashSet<String>` — `lsappinfo list` is slow; use `ps -axo comm` and map `/Applications/X.app/Contents/MacOS/*` ⇒ bundle id via `Info.plist` (`plist` crate, add to deps). Used only to set `AppRunning` label later; in M1 returns ids for the running-app warning on app-cache findings.
  - `pub struct PlanId(pub String)` (xxh3 of created_at + finding ids, 16 hex).
  - `bitflags! pub struct StepFlags: u8 { INTERACTIVE, PERMANENT, TOOL_MISSING }`
  - `pub enum StepKind { Quit { bundle_id: String }, Trash { paths: Vec<PathBuf> }, Remove { paths: Vec<PathBuf> }, Command { argv: Vec<String>, cwd: Option<PathBuf> }, OllamaDelete { url: String, model: String } }`
  - `pub struct Fingerprint { pub path: PathBuf, pub exists: bool, pub mtime: i64, pub allocated: u64 }` with `pub fn take(path: &Path) -> Fingerprint` (lstat; `blocks*512`).
  - `pub struct Step { pub index: usize, pub finding: FindingId, pub description: String, pub kind: StepKind, pub freed: Option<u64>, pub freed_note: Option<String>, pub flags: StepFlags, pub warnings: Vec<String>, pub fingerprints: Vec<Fingerprint> }`
  - `pub struct Plan { pub id: PlanId, pub created_at: i64, pub steps: Vec<Step>, pub total_freed: u64, pub skipped: Vec<(FindingId, String)> /* DoNotTouch or unknown ids */ }`
  - `pub fn plan_removal(findings: &[&Finding], cfg: &Config) -> Plan` — per finding, by `removal`: `Trash` ⇒ `StepKind::Trash` when `cfg.removal.mode == Trash` else `StepKind::Remove` + `PERMANENT`; `Command` ⇒ `StepKind::Command`, `TOOL_MISSING` + warning `"<tool> not found. <install_hint>"` when `tool_path` is `None`, `freed = None` with `freed_note` when the rule has one (Docker/OrbStack), else `freed = Some(freed_if_deleted)`; `OllamaDelete` ⇒ step; `None` ⇒ pushed to `skipped` with reason "Marked do-not-touch". `INTERACTIVE` is set on `Quit` steps and any step whose paths are outside `$HOME` (would need admin). `total_freed` = sum of `Some(freed)`. Order: all `Quit` first, then tool commands, then trash/remove.
  - `impl Plan { pub fn to_json(&self) -> serde_json::Value }` (used by MCP and the future GUI).

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/plan.rs`

```rust
use discky_core::{plan::{plan_removal, StepKind, StepFlags}, findings::{Finding, FindingId, Removal}, rules::{Category, SafetyLabel}, config::{Config, RemovalMode}};

fn finding(id: &str, removal: Removal, freed: u64, label: SafetyLabel) -> Finding {
    Finding { id: FindingId(id.into()), category: Category::DevCaches, title: id.into(), subtitle: None, path: Some(std::env::temp_dir().join(id)), node: None,
        allocated: freed, logical: freed, freed_if_deleted: freed, modified: None, label, rule_id: "t".into(), explain: String::new(), removal, flags: vec![] }
}

#[test]
fn trash_mode_makes_trash_steps_and_permanent_mode_flags_them() {
    let p = std::env::temp_dir().join("discky-plan-a"); std::fs::create_dir_all(&p).unwrap();
    let f = finding("discky-plan-a", Removal::Trash { paths: vec![p.clone()] }, 10, SafetyLabel::Regenerates);
    let mut cfg = Config::default();
    let plan = plan_removal(&[&f], &cfg);
    assert!(matches!(plan.steps[0].kind, StepKind::Trash { .. }));
    assert_eq!(plan.total_freed, 10);
    assert_eq!(plan.steps[0].fingerprints[0].path, p);
    cfg.removal.mode = RemovalMode::Permanent;
    let plan = plan_removal(&[&f], &cfg);
    assert!(matches!(plan.steps[0].kind, StepKind::Remove { .. }));
    assert!(plan.steps[0].flags.contains(StepFlags::PERMANENT));
}

#[test]
fn missing_tool_is_flagged_with_hint_and_note_suppresses_freed() {
    let f = finding("x", Removal::Command { tool: "definitely-not-a-tool".into(), argv: vec!["definitely-not-a-tool".into(), "clean".into()], cwd: None,
        install_hint: Some("brew install nothing".into()), freed_note: Some("Frees space inside the VM".into()) }, 5_000, SafetyLabel::AppData);
    let plan = plan_removal(&[&f], &Config::default());
    let s = &plan.steps[0];
    assert!(s.flags.contains(StepFlags::TOOL_MISSING));
    assert!(s.warnings[0].contains("brew install nothing"));
    assert_eq!(s.freed, None);
    assert_eq!(plan.total_freed, 0);
}

#[test]
fn do_not_touch_is_skipped_and_outside_home_is_interactive() {
    let f1 = finding("k", Removal::None, 1, SafetyLabel::DoNotTouch);
    let mut f2 = finding("sys", Removal::Trash { paths: vec!["/Library/Logs/X".into()] }, 1, SafetyLabel::AppData);
    f2.path = Some("/Library/Logs/X".into());
    let plan = plan_removal(&[&f1, &f2], &Config::default());
    assert_eq!(plan.skipped.len(), 1);
    assert!(plan.steps[0].flags.contains(StepFlags::INTERACTIVE));
}

#[test]
fn ollama_and_quit_ordering() {
    let f = finding("m", Removal::OllamaDelete { model: "qwen3:4b".into() }, 2, SafetyLabel::AppData);
    let plan = plan_removal(&[&f], &Config::default());
    assert!(matches!(&plan.steps[0].kind, StepKind::OllamaDelete { model, .. } if model == "qwen3:4b"));
}
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement `tools/mod.rs` and `plan/mod.rs`.**
- [ ] **Step 4: Run** `cargo test -p discky-core --test plan` → 4 passed.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): tool detection and removal planning"`.

---

### Task 10: Plan execution, trash, history

**Files:**
- Create: `crates/discky-core/src/plan/execute.rs`, `crates/discky-core/src/history.rs`
- Test: `crates/discky-core/tests/execute.rs`

**Interfaces:**
- Consumes: `Plan`, `Step`, `StepKind`, `StepFlags`, `Fingerprint` (Task 9); `DisckyPaths` (Task 1); `Actor` (Task 6).
- Produces:
  - `pub enum StepStatus { Done, Failed, Skipped, NotRun }`
  - `pub struct StepResult { pub index: usize, pub status: StepStatus, pub output: String /* last 4 KiB of stdout+stderr */, pub freed: u64, pub reason: Option<String> }`
  - `pub struct ExecutionReport { pub plan: PlanId, pub results: Vec<StepResult>, pub freed_total: u64, pub trashed_bytes: u64, pub stopped_at: Option<usize>, pub log_path: PathBuf }`
  - `pub struct ExecuteOptions { pub allow_interactive: bool, pub only_steps: Option<Vec<usize>>, pub actor: Actor, pub trash_bin: PathBuf /* default /usr/bin/trash */ }`
  - `pub enum ExecuteError { PlanStale { path: PathBuf }, Io(std::io::Error) }`
  - `pub fn execute_plan(plan: &Plan, opts: &ExecuteOptions, paths: &DisckyPaths) -> Result<ExecutionReport, ExecuteError>` — before anything: every fingerprint re-taken and compared (`exists`, `mtime`, `allocated`); any difference ⇒ `Err(PlanStale)`. Then steps in order: `INTERACTIVE` without `allow_interactive` ⇒ `Skipped` with reason "Needs an interactive session; run from Discky.app"; `TOOL_MISSING` ⇒ `Failed` and **stop** (remaining `NotRun`, `stopped_at = Some(i)`); `Trash` ⇒ spawn `trash_bin` with the paths, `Done` iff exit 0; `Remove` ⇒ `std::fs::remove_dir_all`/`remove_file`; `Command` ⇒ `std::process::Command` with `cwd`, 10-minute timeout; `OllamaDelete` ⇒ `DELETE {url}/api/delete` body `{"model":...}`; `Quit` ⇒ `osascript -e 'tell application id "<bundle>" to quit'`. Any `Failed` stops the plan. `freed` per step = sum of fingerprint `allocated` of paths that no longer exist after the step (for commands: allocated before minus after over the step's paths). Each step appended to history before moving on.
  - `history.rs`: `pub struct HistoryRecord { pub ts: i64, pub actor: Actor, pub plan: PlanId, pub step: usize, pub kind: String, pub paths: Vec<PathBuf>, pub argv: Option<Vec<String>>, pub status: StepStatus, pub freed: u64, pub output_tail: String, pub trash_paths: Vec<PathBuf> /* ~/.Trash/<basename> for Trash steps */ }`; `pub fn append(paths: &DisckyPaths, rec: &HistoryRecord) -> io::Result<()>` (JSON line, create dirs); `pub fn read(paths: &DisckyPaths, limit: usize) -> io::Result<Vec<HistoryRecord>>` (newest first); `pub fn in_trash(paths: &DisckyPaths) -> io::Result<Vec<(PathBuf, u64)>>` — trash_paths that still exist, with current allocated size.

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/execute.rs` (use a fake trash binary: a shell script written to the temp dir that `mv`s its args into `$DISCKY_FAKE_TRASH`, so tests never touch the real Trash)

```rust
use discky_core::{plan::{plan_removal, execute::{execute_plan, ExecuteOptions, ExecuteError, StepStatus}}, findings::{Finding, FindingId, Removal}, rules::{Category, SafetyLabel}, config::Config, index::snapshot::Actor, DisckyPaths, history};

fn setup() -> (tempfile::TempDir, DisckyPaths, std::path::PathBuf) {
    let d = tempfile::tempdir().unwrap();
    unsafe { std::env::set_var("DISCKY_HOME", d.path()) };
    let bin = d.path().join("trash"); let bin_dir = d.path().join("trashed"); std::fs::create_dir(&bin_dir).unwrap();
    std::fs::write(&bin, format!("#!/bin/sh\nmv \"$@\" \"{}\"/\n", bin_dir.display())).unwrap();
    std::fs::set_permissions(&bin, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
    (d, DisckyPaths::resolve(), bin)
}
fn trash_finding(p: &std::path::Path) -> Finding {
    Finding { id: FindingId("f1".into()), category: Category::AppCaches, title: "c".into(), subtitle: None, path: Some(p.into()), node: None,
        allocated: 4096, logical: 4096, freed_if_deleted: 4096, modified: None, label: SafetyLabel::Regenerates, rule_id: "r".into(), explain: String::new(),
        removal: Removal::Trash { paths: vec![p.into()] }, flags: vec![] }
}

#[test]
fn trash_step_moves_dir_and_logs_history() {
    let (d, paths, bin) = setup();
    let target = d.path().join("cache"); std::fs::create_dir(&target).unwrap(); std::fs::write(target.join("x"), [0u8; 4096]).unwrap();
    let plan = plan_removal(&[&trash_finding(&target)], &Config::default());
    let rep = execute_plan(&plan, &ExecuteOptions { allow_interactive: false, only_steps: None, actor: Actor::Mcp, trash_bin: bin }, &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Done));
    assert!(!target.exists()); assert!(d.path().join("trashed/cache").exists());
    assert!(rep.freed_total >= 4096);
    let h = history::read(&paths, 10).unwrap();
    assert_eq!(h.len(), 1); assert!(matches!(h[0].actor, Actor::Mcp));
}

#[test]
fn stale_plan_is_refused() {
    let (d, paths, bin) = setup();
    let target = d.path().join("cache"); std::fs::create_dir(&target).unwrap();
    let plan = plan_removal(&[&trash_finding(&target)], &Config::default());
    std::fs::remove_dir(&target).unwrap();
    let e = execute_plan(&plan, &ExecuteOptions { allow_interactive: false, only_steps: None, actor: Actor::App, trash_bin: bin }, &paths).unwrap_err();
    assert!(matches!(e, ExecuteError::PlanStale { path } if path == target));
}

#[test]
fn failed_command_stops_the_plan() {
    let (d, paths, bin) = setup();
    let later = d.path().join("later"); std::fs::create_dir(&later).unwrap();
    let f1 = Finding { removal: Removal::Command { tool: "sh".into(), argv: vec!["sh".into(), "-c".into(), "exit 3".into()], cwd: None, install_hint: None, freed_note: None }, ..trash_finding(&d.path().join("nope")) };
    let f2 = trash_finding(&later);
    let plan = plan_removal(&[&f1, &f2], &Config::default());
    let rep = execute_plan(&plan, &ExecuteOptions { allow_interactive: false, only_steps: None, actor: Actor::App, trash_bin: bin }, &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Failed));
    assert!(matches!(rep.results[1].status, StepStatus::NotRun));
    assert_eq!(rep.stopped_at, Some(0));
    assert!(later.exists());
}

#[test]
fn interactive_steps_are_skipped_without_permission() {
    let (d, paths, bin) = setup();
    let mut f = trash_finding(&d.path().join("x")); std::fs::create_dir(d.path().join("x")).unwrap();
    f.path = Some("/Library/Logs/Discky-test".into());
    f.removal = Removal::Trash { paths: vec!["/Library/Logs/Discky-test".into()] };
    let plan = plan_removal(&[&f], &Config::default());
    let rep = execute_plan(&plan, &ExecuteOptions { allow_interactive: false, only_steps: None, actor: Actor::Mcp, trash_bin: bin }, &paths).unwrap();
    assert!(matches!(rep.results[0].status, StepStatus::Skipped));
    assert!(rep.results[0].reason.as_deref().unwrap().contains("Discky.app"));
}
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement `plan/execute.rs` and `history.rs`.**
- [ ] **Step 4: Run** `cargo test -p discky-core --test execute` → 4 passed.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): plan execution with stale check, stop-on-failure and history"`.

---

### Task 11: Queries: overview, tree, search

**Files:**
- Create: `crates/discky-core/src/query.rs`
- Test: `crates/discky-core/tests/query.rs`

**Interfaces:**
- Consumes: `Snapshot` (Task 6), `Finding` (Task 5), `Category`.
- Produces:
  - `pub struct VolumeInfo { pub mount: PathBuf, pub total: u64, pub used: u64, pub available: u64 }` via `libc::statfs` on `/System/Volumes/Data` (fallback `/`).
  - `pub struct Overview { pub volume: VolumeInfo, pub snapshot_at: Option<i64>, pub actor: Option<Actor>, pub scanned_allocated: u64, pub by_category: Vec<(Category, u64)>, pub safe_to_free: u64 /* sum freed_if_deleted of Regenerates findings */, pub no_access: usize }`
  - `pub fn disk_overview(snap: Option<&Snapshot>) -> Overview`
  - `pub struct TreeEntry { pub name: String, pub path: PathBuf, pub kind: ObjKind, pub allocated: u64, pub logical: u64, pub freed_if_deleted: u64, pub files: u32, pub modified: i64, pub flags: Vec<String>, pub finding: Option<FindingId> }`
  - `pub fn tree(snap: &Snapshot, path: &Path, limit: usize) -> Result<Vec<TreeEntry>, QueryError>` — direct children sorted by `allocated` desc; `QueryError::NotInSnapshot(path)` when `find` fails.
  - `pub struct SearchQuery { pub name_glob: Option<String>, pub min_allocated: Option<u64>, pub older_than_days: Option<u32>, pub kind: Option<ObjKind>, pub under: Option<PathBuf>, pub limit: usize }`
  - `pub fn search(snap: &Snapshot, q: &SearchQuery) -> Vec<TreeEntry>` — linear scan over nodes (4M nodes ≈ tens of ms), glob on the name only, results sorted by `allocated` desc, capped at `limit`.
  - `pub fn findings_in(snap: &Snapshot, category: Option<Category>, label: Option<SafetyLabel>, min_allocated: u64, older_than_days: Option<u32>, offset: usize, limit: usize) -> (Vec<&Finding>, usize /* total */)`

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/query.rs`

```rust
mod fixtures;
use discky_core::{query::{tree, search, disk_overview, SearchQuery}, index::snapshot::{Snapshot, SnapshotMeta, Actor}, fs::walk::{walk, ScanOptions}, fs::attr::ObjKind, rules::RuleSet, findings::Categorizer, config::Thresholds};

fn snap(root: &std::path::Path) -> Snapshot {
    let index = walk(&ScanOptions { roots: vec![root.into()], exclude: globset::GlobSet::empty(), threads: 0 }, &|_| {});
    let findings = Categorizer { index: &index, rules: &RuleSet::builtin(), thresholds: &Thresholds::default() }.run();
    Snapshot { meta: SnapshotMeta { format_version: 1, created_at: 1, actor: Actor::App, roots: vec![root.into()], no_access: vec![], node_count: 0 }, index, findings }
}

#[test]
fn tree_lists_children_largest_first_with_finding_links() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let s = snap(d.path());
    let t = tree(&s, &d.path().join("proj"), 10).unwrap();
    assert_eq!(t[0].name, "target");
    assert!(t[0].finding.is_some());
    assert!(tree(&s, std::path::Path::new("/definitely/missing"), 10).is_err());
}

#[test]
fn search_by_glob_size_and_kind() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let s = snap(d.path());
    let r = search(&s, &SearchQuery { name_glob: Some("*.bin".into()), min_allocated: None, older_than_days: None, kind: Some(ObjKind::File), under: None, limit: 10 });
    assert_eq!(r.len(), 1); assert_eq!(r[0].name, "big.bin");
    let r = search(&s, &SearchQuery { name_glob: Some("node_modules".into()), min_allocated: Some(1024 * 1024), older_than_days: None, kind: Some(ObjKind::Dir), under: Some(d.path().join("web")), limit: 10 });
    assert_eq!(r.len(), 1);
}

#[test]
fn overview_sums_categories_and_safe_bytes() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(d.path());
    let s = snap(d.path());
    let o = disk_overview(Some(&s));
    assert!(o.volume.total > 0 && o.volume.used <= o.volume.total);
    assert!(o.safe_to_free >= 5 * 1024 * 1024, "target + node_modules regenerate");
    assert!(o.by_category.iter().any(|(c, b)| matches!(c, discky_core::rules::Category::ProjectBuilds) && *b > 0));
    assert!(disk_overview(None).snapshot_at.is_none());
}
```

- [ ] **Step 2: Run to verify it fails.** — compile error.
- [ ] **Step 3: Implement `query.rs`.**
- [ ] **Step 4: Run** `cargo test -p discky-core --test query` → 3 passed.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): overview, tree and search queries"`.

---

### Task 12: Engine facade with async scan jobs

**Files:**
- Create: `crates/discky-core/src/scan.rs`
- Modify: `crates/discky-core/src/lib.rs` (export `Engine`)
- Test: `crates/discky-core/tests/engine.rs`

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `pub struct ScanId(pub String)` (8 hex from time + counter).
  - `pub enum ScanStatus { Running { progress: Progress, started_at: i64 }, Done { finished_at: i64, duration_ms: u64, node_count: u32, findings: usize, no_access: usize }, Failed { error: String }, Unknown }`
  - `pub struct Engine { paths: DisckyPaths, config: RwLock<Config>, rules: RuleSet, actor: Actor, snapshot: RwLock<Option<Arc<Snapshot>>>, scans: Mutex<HashMap<ScanId, ScanJob>> }`
  - `impl Engine { pub fn open(actor: Actor) -> Result<Engine, EngineError> /* loads config + snapshot if present (Incompatible snapshot ⇒ ignored with a tracing::warn) */; pub fn config(&self) -> Config; pub fn set_config(&self, c: Config) -> Result<(), ConfigError>; pub fn snapshot(&self) -> Option<Arc<Snapshot>>; pub fn start_scan(&self, roots: Option<Vec<PathBuf>>) -> ScanId /* spawns a std thread: set_no_materialize, walk, categorize, save snapshot, swap into self.snapshot; only one Running scan at a time — a second call returns the running id */; pub fn scan_status(&self, id: &ScanId) -> ScanStatus; pub fn wait_scan(&self, id: &ScanId, timeout: Duration) -> ScanStatus /* polls every 100 ms */; pub fn overview(&self) -> Overview; pub fn findings(&self, ...) same signature as query::findings_in but returning owned clones; pub fn inspect(&self, id_or_path: &str) -> Option<Inspection>; pub fn plan(&self, ids: &[String]) -> Result<Plan, EngineError> /* unknown ids ⇒ Plan.skipped */; pub fn execute(&self, plan: &Plan, allow_interactive: bool, only_steps: Option<Vec<usize>>) -> Result<ExecutionReport, ExecuteError> /* keeps the last 20 plans in memory keyed by PlanId; after execution re-takes fingerprints and removes vanished nodes' findings from the in-memory snapshot */; pub fn get_plan(&self, id: &PlanId) -> Option<Plan>; pub fn history(&self, limit: usize) -> Vec<HistoryRecord>; pub fn in_trash(&self) -> Vec<(PathBuf, u64)> }`
  - `pub struct Inspection { pub finding: Option<Finding>, pub entry: Option<TreeEntry>, pub children: Vec<TreeEntry> /* top 20 */, pub rule: Option<(String, String) /* title, explain */>, pub owner_app: Option<String>, pub in_snapshot: bool }`

- [ ] **Step 1: Write the failing tests** `crates/discky-core/tests/engine.rs`

```rust
mod fixtures;
use discky_core::{Engine, index::snapshot::Actor, scan::ScanStatus};
use std::time::Duration;

fn engine_in(d: &tempfile::TempDir) -> Engine {
    unsafe { std::env::set_var("DISCKY_HOME", d.path()) };
    let e = Engine::open(Actor::Mcp).unwrap();
    let mut c = e.config(); c.scan.roots = vec![d.path().join("tree")]; e.set_config(c).unwrap();
    e
}

#[test]
fn scan_runs_async_persists_and_is_reloaded() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(&d.path().join("tree"));
    let e = engine_in(&d);
    assert!(e.snapshot().is_none());
    let id = e.start_scan(None);
    assert!(matches!(e.scan_status(&id), ScanStatus::Running { .. } | ScanStatus::Done { .. }));
    let st = e.wait_scan(&id, Duration::from_secs(30));
    assert!(matches!(st, ScanStatus::Done { findings, .. } if findings > 0));
    assert!(d.path().join("snapshot.bin").exists());
    drop(e);
    let e2 = Engine::open(Actor::App).unwrap();
    assert!(matches!(e2.snapshot().unwrap().meta.actor, Actor::Mcp));
}

#[test]
fn second_start_while_running_returns_same_id_and_unknown_id_is_unknown() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(&d.path().join("tree"));
    let e = engine_in(&d);
    let a = e.start_scan(None); let b = e.start_scan(None);
    assert_eq!(a.0, b.0);
    e.wait_scan(&a, Duration::from_secs(30));
    assert!(matches!(e.scan_status(&discky_core::scan::ScanId("nope".into())), ScanStatus::Unknown));
}

#[test]
fn plan_then_execute_updates_findings() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(&d.path().join("tree"));
    let e = engine_in(&d);
    let id = e.start_scan(None); e.wait_scan(&id, Duration::from_secs(30));
    let (f, _) = e.findings(Some(discky_core::rules::Category::ProjectBuilds), None, 0, None, 0, 10);
    let nm = f.iter().find(|f| f.rule_id == "node-modules").unwrap().id.0.clone();
    let plan = e.plan(&[nm.clone()]).unwrap();
    assert_eq!(plan.steps.len(), 1);
    let mut c = e.config(); c.removal.mode = discky_core::RemovalMode::Permanent; e.set_config(c).unwrap();
    let plan = e.plan(&[nm.clone()]).unwrap();
    let rep = e.execute(&plan, false, None).unwrap();
    assert!(matches!(rep.results[0].status, discky_core::plan::execute::StepStatus::Done));
    assert!(e.inspect(&nm).unwrap().finding.is_none(), "finding removed after deletion");
    assert_eq!(e.history(10).len(), 1);
}
```

- [ ] **Step 2: Run to verify it fails.**
- [ ] **Step 3: Implement `scan.rs` and the `Engine`** per Interfaces.
- [ ] **Step 4: Run** `cargo test -p discky-core` → all tests across the crate pass.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(core): Engine facade with async scan jobs"`.

---

### Task 13: MCP server — tools over stdio

**Files:**
- Create: `crates/discky-mcp/Cargo.toml`, `crates/discky-mcp/src/main.rs`, `crates/discky-mcp/src/server.rs`, `crates/discky-mcp/src/params.rs`
- Test: `crates/discky-mcp/tests/stdio.rs`

**Interfaces:**
- Consumes: `Engine` and its methods (Task 12).
- Produces: binary `discky-mcp` (`clap`: `--log-level`, `--home <dir>` sets `DISCKY_HOME`), tracing to **stderr only** (stdout is the protocol). `DisckyServer { engine: Arc<Engine> }` with `#[tool_router]` + `#[tool_handler] impl ServerHandler` (`get_info` sets `ServerCapabilities::builder().enable_tools().enable_resources()` and `instructions` = one paragraph: what Discky is, call `disk_overview` first, scan if stale, always `plan_removal` before `execute_plan`, sizes are bytes actually allocated on disk).
  Tools (names, params in `params.rs` as `schemars` structs, outputs as `Json<T>`):
  - `disk_overview()` → `Overview` + `snapshot_age_seconds: Option<u64>` + `stale: bool` (age > 1 h).
  - `scan(roots: Option<Vec<String>>, wait_seconds: Option<u32> /* 0..=60 */)` → `{ scan_id, status }`; if `wait_seconds > 0` calls `wait_scan`. Progress: if `context.meta` carries a `progressToken`, spawn a tokio task that calls `context.peer.notify_progress(ProgressNotificationParam { progress_token, progress: files as f64, total: None, message: Some(current path) })` every 500 ms until done.
  - `scan_status(scan_id: String)` → `ScanStatus`.
  - `findings(category: Option<Category>, label: Option<SafetyLabel>, min_bytes: Option<u64>, older_than_days: Option<u32>, offset: Option<usize>, limit: Option<usize> /* default 25, max 200 */)` → `{ items: Vec<FindingOut>, total, offset }` where `FindingOut` = `Finding` minus `node`, plus `human_size`.
  - `tree(path: String, limit: Option<usize> /* default 20 */)` → `Vec<TreeEntry>`; path not in snapshot ⇒ tool error text "Path is not in the last snapshot. Run `scan` with this root or choose a path under: <roots>".
  - `search(name_glob, min_bytes, older_than_days, kind, under, limit)` → `Vec<TreeEntry>`.
  - `inspect(target: String /* finding id, absolute path, or app name */)` → `Inspection`.
  - `plan_removal(finding_ids: Vec<String>)` → `Plan::to_json()` plus `human_total`.
  - `execute_plan(plan_id: String, only_steps: Option<Vec<usize>>)` → when `!config.mcp.allow_agent_delete` ⇒ `CallToolResult::error` with text "Agent deletion is disabled. Enable it in Discky → Settings → MCP server (`mcp.allow_agent_delete = true` in config.toml)"; `PlanStale` ⇒ error "Files changed since planning (<path>). Call plan_removal again."; otherwise `ExecutionReport` + `skipped_interactive: Vec<{index, description}>`.
  - `history(limit: Option<usize>)` → `{ records, in_trash: Vec<{path, bytes}>, trash_total }`.
  Resources: `discky://snapshot/summary` (JSON of `disk_overview`), `discky://config` (TOML text), `discky://log/removals` (last 200 lines).
  Tool `description`s: one or two English sentences each, stating side effects (none / "starts a scan" / "DELETES files").

- [ ] **Step 1: Write the failing end-to-end test** `crates/discky-mcp/tests/stdio.rs` — spawn the built binary with `--home <tmp>` and a prepared fixture tree (reuse `discky-core/tests/fixtures.rs` via `#[path]`), speak JSON-RPC over stdin/stdout by hand (write `initialize`, `notifications/initialized`, then `tools/call`), parse responses line by line:

```rust
#[path = "../../discky-core/tests/fixtures.rs"] mod fixtures;
use std::io::{BufRead, Write};

struct Mcp { child: std::process::Child, out: std::io::BufReader<std::process::ChildStdout>, next: u64 }
impl Mcp {
    fn start(home: &std::path::Path) -> Mcp { /* assert_cmd::cargo::cargo_bin("discky-mcp"), args ["--home", home], piped stdio */ unimplemented!() }
    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value { /* write one line, read lines until a response with matching id; ignore notifications */ unimplemented!() }
    fn tool(&mut self, name: &str, args: serde_json::Value) -> serde_json::Value {
        let r = self.call("tools/call", serde_json::json!({"name": name, "arguments": args}));
        serde_json::from_str(r["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }
}

#[test]
fn full_flow_scan_findings_plan_refused_then_allowed() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(&d.path().join("tree"));
    std::fs::write(d.path().join("config.toml"), format!("[scan]\nroots = [\"{}\"]\n", d.path().join("tree").display())).unwrap();
    let mut m = Mcp::start(d.path());
    let init = m.call("initialize", serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}));
    assert!(init["result"]["capabilities"]["tools"].is_object());
    let tools = m.call("tools/list", serde_json::json!({}));
    let names: Vec<_> = tools["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
    for n in ["disk_overview","scan","scan_status","findings","tree","search","inspect","plan_removal","execute_plan","history"] { assert!(names.contains(&n.to_string()), "{n}"); }

    let ov = m.tool("disk_overview", serde_json::json!({}));
    assert!(ov["snapshot_at"].is_null());
    let sc = m.tool("scan", serde_json::json!({"wait_seconds": 30}));
    assert_eq!(sc["status"]["kind"], "done");
    let f = m.tool("findings", serde_json::json!({"category":"project_builds"}));
    let id = f["items"][0]["id"].as_str().unwrap().to_string();
    let plan = m.tool("plan_removal", serde_json::json!({"finding_ids":[id]}));
    let plan_id = plan["id"].as_str().unwrap().to_string();
    let r = m.call("tools/call", serde_json::json!({"name":"execute_plan","arguments":{"plan_id":plan_id}}));
    assert_eq!(r["result"]["isError"], true);
    assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("allow_agent_delete"));

    std::fs::write(d.path().join("config.toml"), format!("[scan]\nroots = [\"{}\"]\n[mcp]\nallow_agent_delete = true\n[removal]\nmode = \"permanent\"\n", d.path().join("tree").display())).unwrap();
    let mut m = Mcp::start(d.path());
    m.call("initialize", serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}));
    let ov = m.tool("disk_overview", serde_json::json!({}));
    assert!(ov["snapshot_at"].is_number(), "snapshot persisted across processes");
    let plan = m.tool("plan_removal", serde_json::json!({"finding_ids":[f["items"][0]["id"]]}));
    let rep = m.tool("execute_plan", serde_json::json!({"plan_id": plan["id"]}));
    assert_eq!(rep["results"][0]["status"], "done");
    let h = m.tool("history", serde_json::json!({}));
    assert_eq!(h["records"].as_array().unwrap().len(), 1);
}

#[test]
fn tree_outside_snapshot_is_a_helpful_error() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(&d.path().join("tree"));
    let mut m = Mcp::start(d.path());
    m.call("initialize", serde_json::json!({"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}));
    let r = m.call("tools/call", serde_json::json!({"name":"tree","arguments":{"path":"/nowhere"}}));
    assert_eq!(r["result"]["isError"], true);
}
```

- [ ] **Step 2: Run to verify it fails** — `cargo test -p discky-mcp` → binary not found / compile error.
- [ ] **Step 3: Implement the crate** per Interfaces (`serve_server(DisckyServer::new(engine), rmcp::transport::io::stdio()).await?.waiting().await?` in `main`). `ScanStatus` serializes with `#[serde(tag = "kind", rename_all = "snake_case")]`.
- [ ] **Step 4: Run** `cargo test -p discky-mcp` → 2 passed.
- [ ] **Step 5: Manual check with Claude Code on the owner's machine**

```bash
cargo build --release -p discky-mcp
claude mcp add discky -- "$PWD/target/release/discky-mcp"
```
Then in a Claude Code session: ask "what is eating my disk?" and confirm the agent calls `disk_overview` → `scan` → `findings`. Record the transcript's tool-call order in the commit message body.

- [ ] **Step 6: Commit** — `git add -A && git commit -m "feat(mcp): stdio server with ten tools and three resources"`.

---

### Task 14: Tasks extension for `scan`

**Files:**
- Create: `crates/discky-mcp/src/tasks.rs`
- Modify: `crates/discky-mcp/src/server.rs` (`scan` returns `CallToolResponse::Task` when supported; `get_task` delegated to `TaskManager`; `get_info` adds `.enable_tasks()`)
- Test: extend `crates/discky-mcp/tests/stdio.rs`

**Interfaces:**
- Consumes: `rmcp::task_manager::TaskManager`, `ClientCapabilities::supports_tasks()`, `CallToolResponse::Task(CreateTaskResult)`, `ServerHandler::get_task`.
- Produces: in `scan`, `if context.client_capabilities().supports_tasks() && wait_seconds.unwrap_or(0) == 0` ⇒ spawn via `TaskManager` an operation that `wait_scan`s to completion and resolves with the same JSON the sync path returns; return the task handle. `tasks.rs` holds the `TaskManager` construction (`ttl_ms = 30 min`) and the adapter from `ScanStatus` to the task result. Everything else unchanged, so clients without the extension keep `scan_id` polling.

- [ ] **Step 1: Write the failing test** (append to `stdio.rs`)

```rust
#[test]
fn clients_declaring_tasks_get_a_task_handle_for_scan() {
    let d = tempfile::tempdir().unwrap(); fixtures::build_tree(&d.path().join("tree"));
    std::fs::write(d.path().join("config.toml"), format!("[scan]\nroots = [\"{}\"]\n", d.path().join("tree").display())).unwrap();
    let mut m = Mcp::start(d.path());
    m.call("initialize", serde_json::json!({"protocolVersion":"2026-07-28","capabilities":{"extensions":{"io.modelcontextprotocol/tasks":{}}},"clientInfo":{"name":"t","version":"0"}}));
    let r = m.call("tools/call", serde_json::json!({"name":"scan","arguments":{}}));
    assert_eq!(r["result"]["resultType"], "task");
    let task_id = r["result"]["task"]["taskId"].as_str().unwrap().to_string();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let g = m.call("tasks/get", serde_json::json!({"taskId": task_id}));
        let status = g["result"]["status"].as_str().unwrap_or("");
        if status == "completed" { assert_eq!(g["result"]["result"]["content"][0]["type"], "text"); break; }
        assert!(std::time::Instant::now() < deadline, "task never completed: {g}");
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
```
If `rmcp` 3.8's `tasks/get` result shape differs from the assertion, adjust the assertion to the shape documented in `rmcp::model::GetTaskResult` and note it in the commit.

- [ ] **Step 2: Run to verify it fails** — `cargo test -p discky-mcp clients_declaring_tasks` → `resultType` is `"complete"`.
- [ ] **Step 3: Implement `tasks.rs` and wire `scan`/`get_task`/`get_info`.**
- [ ] **Step 4: Run** `cargo test -p discky-mcp` → 3 passed; `cargo test --workspace` → all green.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "feat(mcp): Tasks extension for async scan when the client supports it"`.

---

### Task 15: Release build, Homebrew formula stub, README

**Files:**
- Create: `README.md`, `packaging/homebrew/discky-mcp.rb`, `.github/workflows/ci.yml`
- Modify: `crates/discky-mcp/Cargo.toml` (`[[bin]] name = "discky-mcp"`, `[profile.release] lto = "thin", codegen-units = 1, strip = true`)

**Interfaces:** none new. README (English): what Discky is, M1 status ("MCP server only; GUI in progress"), install from source, `claude mcp add discky -- /opt/homebrew/bin/discky-mcp`, Claude Desktop / Codex / Cursor JSON snippets, the ten tools, safety model (`allow_agent_delete`, plan/execute, Trash default), file locations, how rules work (`builtin.toml`) and how to propose one via issue. Formula: `discky-mcp.rb` building from the GitHub tarball with `cargo install --locked --root #{prefix} --path crates/discky-mcp`; untestable until the repo is public — mark `# TODO: sha256 after first tag`.

- [ ] **Step 1: CI** — `ci.yml` on `macos-15` runner: `cargo fmt --check`, `cargo clippy --workspace -- -D warnings`, `cargo test --workspace`.
- [ ] **Step 2: Run locally** — `cargo fmt --check && cargo clippy --workspace -- -D warnings && cargo test --workspace --release` → clean.
- [ ] **Step 3: Measure** — `cargo test -p discky-core --release --test walk -- --ignored --nocapture` and `/usr/bin/time -l target/release/discky-mcp --self-test-scan` (add this hidden flag: runs one scan of configured roots, prints node count, duration, max RSS from `getrusage`, exits). Expected on the owner's Mac: ≥150k files/s, max RSS ≤ 1 GiB. Paste numbers into README "Performance".
- [ ] **Step 4: Commit** — `git add -A && git commit -m "chore: README, CI, Homebrew formula stub, release profile"`.

---

## Self-Review Notes

- **Spec coverage (M1 scope):** §4 crates/files (T1, T13); §5 scanner, sizes, hard links, dataless, sparse, no-access, boundaries (T2, T3); §6 categories except Apps/LanguageVersions (T4, T5, T7, T8), granularity rule and Docker note (T4 `freed_note`, T9); labels (T4, T5, T7); §7 plan/execute, modes, stop-on-failure, history (T9, T10); §12 tools, ids, async scan, resources (T13, T14); §12b snapshot actor/lock (T6), app file-watch is GUI work (M2); §12c flags (T9, T10, T13); §13 min macOS 15 (T15 README), signing/cask for the .app is M2; §14 targets (T3 step 5, T15 step 3). `AppRunning` label: `running_app_bundle_ids` exists (T9) but is only attached as a warning in M1 — full label wiring lands with the uninstaller in M3.
- **Type consistency:** `ObjKind` lives in `fs::attr` and is re-used by `Node`, `TreeEntry`, `SearchQuery`; `Actor` lives in `index::snapshot`; `StepStatus` in `plan::execute`; `ScanStatus` in `scan`. `Engine::findings` returns `(Vec<Finding>, usize)`; `query::findings_in` returns borrowed — T12 clones.
- **Proportion:** ~15 tasks, test code dominates; function bodies are not transcribed.
