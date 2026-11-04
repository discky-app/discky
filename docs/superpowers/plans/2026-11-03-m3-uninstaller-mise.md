# Milestone 3: App uninstaller + mise language versions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fill the two empty categories: **Applications** (every `.app` with its source, last-used date and leftovers, plus "leftovers of removed apps") and **Language versions** (mise installs with who requests them), removable through the official routes (`brew uninstall --zap`, `pkgutil --forget`, `launchctl bootout`, `defaults delete`, `mise uninstall`) from both the GUI and the MCP server.

**Architecture:** Findings gain **components** (app bundle, each leftover, each requesting project) so the inspector can show them with checkboxes and the planner can act on a selection. Two new core adapters (`findings/apps/*`, `findings/mise.rs`) run inside the categorizer after the walk, using the in-memory index for every size and date and short external commands for facts the filesystem does not carry (brew JSON, pkg receipts, Spotlight, `mise ls`). The planner composes ordered steps per app source; the executor only learns one new route (admin-privileged commands). GUI and MCP consume the same `Finding.components` and `Engine::plan_items`.

**Tech Stack:** Rust 1.99, existing crates (`plist`, `serde_json`, `globset`); `brew`, `pkgutil`, `mdfind`, `lsappinfo`, `launchctl`, `defaults`, `mise` invoked read-only during scans; gpui-kit 0.9.0 for the GUI.

**Spec:** `docs/superpowers/specs/2026-11-02-discky-design.md` §6 (categories, labels), §7 (plan order, official commands), §8 (uninstaller), §9 (mise), §11 (inspector components with checkboxes), §12c, §17. Ground truth from the owner's machine: the session scratchpad (`m3-research.md`) (copied into the SDD workspace as `m3-research.md` at execution time).

## Global Constraints

- Only official removal mechanisms; a failed step stops the plan; never fall back to `rm`; Keychain items are never touched (spec §7, §8, §17.4/5).
- Plan order per app (spec §7/§8): own uninstaller script → quit the app → `brew uninstall --zap` / pkg files → app bundle → `launchctl bootout` → leftovers → `defaults delete` → `pkgutil --forget`.
- Settings are removed with `defaults delete <domain>`, never by trashing the plist; LaunchAgents/Daemons are `launchctl bootout`-ed before their plist is trashed (spec §8).
- `/System/Applications/*`, bundles with the `restricted` flag, symlinked bundles (Safari) and bundles nested inside other bundles never become findings (spec §8).
- A globally active mise version cannot be uninstalled while it is global (spec §9); mise data comes only from the mise CLI, never from its internal files.
- All sizes and dates come from the index (no `du`); external commands during a scan are bounded (each ≤ 5 s, killed on timeout) and their absence degrades gracefully (no brew → no cask info; no Spotlight → "unknown").
- The MCP server stays at `allow_interactive = false`; GUI runs plans with `allow_interactive = true` (spec §12c). Every new `Finding`/`Plan` field is serialized for MCP automatically.
- Snapshot format bumps to **3** (new `Finding` fields); format 1/2 files are `Incompatible`.
- Owner rules (unchanged from M2): automated runs never steal focus; no full-screen screenshots; `cargo test` opens no window and never touches real data; at most one short manual app launch per GUI task; **no test or implementer may run `brew uninstall`, `pkgutil --forget`, `launchctl bootout`, `defaults delete` or `mise uninstall` against the real system** — planners are tested as pure functions, executors through fakes.
- English copy; theme colours only; no new env reads in the app; `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green after every task; commit after each task.

## Review Focus

1. **A leftover shared by two apps** (e.g. `~/Library/Application Support/Google` used by Chrome and Drive): removing one app must not trash a folder another installed app still uses. → Task 3 (`shared_leftover_is_attached_to_no_app`).
2. **Root-owned app bundles** (Chrome, Google apps, AmneziaVPN are `root:wheel` on the owner's Mac): the plan must mark the bundle step "needs administrator password" and route it via Finder, never fail silently. → Task 4 (`root_owned_bundle_step_is_interactive`).
3. **Name-based matching false positives** (`LogiZoomBridge` matched "zoom"): name matching is confined to exact folder names in `Application Support`/`Logs`; everything else needs a bundle-id prefix or a cask zap path. → Task 3 (`name_match_is_exact_only`).
4. **Spotlight knows nothing** (4 of 10 apps): "last opened" must show "never*" / an estimate from leftovers with an asterisk, and the 180-day filter must treat unknown as "not opened". → Task 2 (`last_used_unknown_falls_back_to_leftovers_with_estimate_flag`).
5. **mise version referenced only by a file mise does not track** (`heavy/mise.toml`, stray `.node-version`): the version must show the file as "not tracked by mise" and must not be labelled "not referenced". → Task 5 (`untracked_version_file_is_reported`).

---

## File structure

Core (`crates/discky-core`):
- `src/findings/mod.rs` — `Component`, `ComponentKind`, `ComponentRemoval`, `Finding.components`, `AppSource`, `Removal::App`, `Removal::MiseUninstall`; categorizer order.
- `src/findings/apps/mod.rs` — `find()` entry: inventory → leftovers → findings (apps, leftover groups, orphan receipts).
- `src/findings/apps/inventory.rs` — bundle enumeration from the index, `Info.plist`, MAS receipt, exclusions.
- `src/findings/apps/cask.rs` — `brew info --cask --json=v2 --installed` parsing (`OneOrMany`), Caskroom offline fallback, zap path expansion.
- `src/findings/apps/pkg.rs` — `pkgutil` reverse index, orphan receipts.
- `src/findings/apps/last_used.rs` — `mdfind -attr kMDItemLastUsedDate`, fallback estimate.
- `src/findings/apps/leftovers.rs` — leftover candidates per bundle id, launch agents/daemons, preferences domains, shared-folder guard.
- `src/findings/mise.rs` — `mise ls --json`, `mise ls --all-sources --json`, untracked version files, findings.
- `src/plan/mod.rs` — `PlanItem`, `plan_items`, app/mise step composition, `Step.component`.
- `src/plan/execute.rs` — admin route for INTERACTIVE `Command` steps.
- `src/engine.rs` — `plan_items`, `mise_prune_dry_run`.
- `src/index/snapshot.rs` — `SNAPSHOT_FORMAT = 3`.
- `src/tools/mod.rs` — `running_app_bundle_ids` via `lsappinfo`, `run_capture(cmd, timeout)`.

MCP (`crates/discky-mcp`): `params.rs` (`components`), `server.rs` (`plan_removal`, `inspect`, INSTRUCTIONS), `tests/stdio.rs`.

App (`crates/discky-app`): `category/table.rs` (per-category columns), `category/mod.rs` (Apps filter tabs), `inspector.rs` (components with checkboxes, selection → plan), `removal/{mod,model}.rs` (`PlanItem`s), `settings/version_manager.rs` (`mise prune` dry run), `overview/model.rs` + `sidebar.rs` (Apps count), `app.rs` wiring.

Docs: `README.md`, `docs/superpowers/plans/2026-11-03-m2-followups.md` (checked items), `packaging/macos/Info.plist`.

---

### Task 1: Components, app/mise removals, plan items, admin command route

**Files:**
- Modify: `crates/discky-core/src/findings/mod.rs`, `src/plan/mod.rs`, `src/plan/execute.rs`, `src/engine.rs`, `src/index/snapshot.rs`, `src/lib.rs`
- Modify: `crates/discky-mcp/src/server.rs` (compile only: `Plan::to_json` shape unchanged except new fields)
- Test: `crates/discky-core/tests/plan.rs`, `tests/execute.rs`, `tests/snapshot.rs`, unit tests in `plan/execute.rs`

**Interfaces:**
- Produces:
  ```rust
  // findings/mod.rs
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")]
  pub enum ComponentKind { AppBundle, ApplicationSupport, Caches, Preferences, Container, GroupContainer, SavedState, HttpStorage, WebKit, Cookies, Logs, LaunchAgent, LaunchDaemon, ApplicationScript, PrivilegedHelper, Receipt, OwnUninstaller, Project, Other }
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")]
  pub enum ComponentRemoval {
      Trash,                                   // the component's path
      Defaults { domain: String },             // `defaults delete <domain>` (the plist is not trashed)
      Bootout { label: String, system: bool }, // `launchctl bootout gui/<uid>/<label>` or `system/<label>` (admin), then Trash the plist
      PkgForget { pkg_id: String },            // `pkgutil --forget <id>` (admin)
      None,                                    // shown only (Project, OwnUninstaller, shared folders)
  }
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct Component {
      pub kind: ComponentKind,
      pub title: String,                 // "Application Support", "LaunchDaemon · active", "requested by mise.toml"
      pub path: Option<PathBuf>,
      pub allocated: u64,
      pub freed_if_deleted: u64,
      pub modified: Option<i64>,
      pub default_on: bool,              // pre-checked in the inspector
      pub removal: ComponentRemoval,
      pub note: Option<String>,          // "needs administrator password", "shared with Google Drive", "not tracked by mise"
  }
  // Finding gains: #[serde(default)] pub components: Vec<Component>
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")]
  pub enum AppSource { Cask { token: String, full_token: String }, Pkg { pkg_ids: Vec<String> }, AppStore, Dragged }
  // Removal gains:
  //   App { source: AppSource, bundle: PathBuf, bundle_id: Option<String> }   — components carry the leftovers
  //   MiseUninstall { tool: String, version: String }                          — `mise uninstall <tool>@<version>`
  // plan/mod.rs
  #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
  pub struct PlanItem { pub id: String, /// Component indices to act on; `None` = every `default_on` component.
                        pub components: Option<Vec<usize>> }
  // Step gains: #[serde(default)] pub component: Option<usize>
  pub fn plan_items(items: &[PlanItem], findings: &[&Finding], cfg: &Config) -> Plan;  // `plan_removal(findings, cfg)` = plan_items with components None
  // engine.rs
  impl Engine { pub fn plan_items(&self, items: &[PlanItem]) -> Result<Plan, EngineError>; }  // `plan(ids)` delegates with components None
  // execute.rs
  pub(crate) fn admin_command_script(argv: &[&str]) -> String;  // `do shell script "<shell-quoted argv>" with administrator privileges`
  ```
- Behaviour: a `Command` step with `INTERACTIVE` and `allow_interactive = true` runs via `/usr/bin/osascript -e <admin_command_script>` (same UTF-8/absolute-path/trailing-slash checks as the Trash/Remove routes; argv[0] must be absolute). `plan_items` for `Removal::App`/`MiseUninstall` in this task only emits the main step (Trash of the bundle / `mise uninstall`) — Task 4 composes the full sequence; here the point is the data model, selection plumbing and the executor route. A `PlanItem` whose index is out of range is listed in `plan.skipped` with "Unknown component index". `SNAPSHOT_FORMAT = 3`.

- [ ] **Step 1: Failing tests** — `tests/plan.rs`: `plan_items_with_no_selection_uses_default_on_components` (a finding with two components, one `default_on`, yields one Trash step with `component == Some(0)`), `plan_items_rejects_bad_component_index`; `tests/execute.rs`: `interactive_command_is_skipped_without_permission`; unit: `admin_command_script_quotes_argv` (`["/usr/sbin/pkgutil","--forget","us.zoom.pkg"]` → `do shell script "/usr/sbin/pkgutil --forget us.zoom.pkg" with administrator privileges`; an arg with `'` is `'\''`-quoted); `tests/snapshot.rs`: `format_3_round_trips_components`, format-2 header → `Incompatible`.
- [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement.** — [ ] **Step 4: `cargo test --workspace`, clippy, fmt.**
- [ ] **Step 5: Commit** — `core: finding components, app/mise removals, plan items, admin command route`

---

### Task 2: App inventory: bundles, sources, last used

**Files:**
- Create: `crates/discky-core/src/findings/apps/mod.rs` (module decls + `AppInfo`), `apps/inventory.rs`, `apps/cask.rs`, `apps/pkg.rs`, `apps/last_used.rs`
- Modify: `crates/discky-core/src/tools/mod.rs` (`run_capture`, `lsappinfo`)
- Test: `crates/discky-core/tests/apps_inventory.rs` + unit tests with fixtures copied from the research file

**Interfaces:**
- Produces:
  ```rust
  // tools/mod.rs
  pub fn run_capture(program: &Path, args: &[&str], timeout: Duration) -> Option<String>; // stdout on exit 0 within timeout; None otherwise (child killed)
  pub fn running_app_bundle_ids() -> HashSet<String>; // now `lsappinfo list` (type "Foreground" and "UIElement"); falls back to the old `ps` scan when lsappinfo is missing
  // apps/mod.rs
  pub struct AppInfo { pub bundle: PathBuf, pub node: NodeId, pub name: String, pub bundle_id: Option<String>, pub version: Option<String>,
                       pub source: AppSource, pub last_used: LastUsed, pub own_uninstaller: Option<PathBuf>, pub root_owned: bool }
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)] #[serde(rename_all = "snake_case")]
  pub enum LastUsed { Spotlight(i64), Estimated(i64) /* max mtime of leftovers */, Unknown }
  // inventory.rs
  pub fn app_bundles(index: &Index, home: &Path) -> Vec<(NodeId, PathBuf)>; // `.app` dirs directly under /Applications, /Applications/<subdir>/, ~/Applications; excludes symlinks, nested bundles, `/System/Applications`, SF_RESTRICTED (lstat st_flags & 0x80000)
  pub fn read_bundle(bundle: &Path) -> BundleMeta;  // Info.plist via `plist` crate: CFBundleIdentifier, CFBundleName, CFBundleShortVersionString, LSUIElement; `mas_receipt: bool` (Contents/_MASReceipt exists); `root_owned` (uid 0); `own_uninstaller`: first match of Contents/Resources/Uninstall*.{app,scpt,sh} or a sibling `Uninstall*.app`
  // cask.rs
  pub struct Cask { pub token: String, pub full_token: String, pub installed: Option<String>, pub app_targets: Vec<PathBuf>, pub uninstall: Vec<Directive>, pub zap: Vec<Directive> }
  pub struct Directive { pub quit: Vec<String>, pub launchctl: Vec<String>, pub pkgutil: Vec<String>, pub delete: Vec<String>, pub trash: Vec<String>, pub rmdir: Vec<String>, pub signal: Vec<(String, String)>, pub script: Option<Script>, pub login_item: Vec<String> }
  pub struct Script { pub executable: String, pub args: Vec<String>, pub must_succeed: bool }
  pub fn parse_casks(json: &str) -> Result<Vec<Cask>, String>;           // `brew info --cask --json=v2 --installed`; every list-ish value is string-or-array
  pub fn installed_casks(brew: Option<&Path>) -> Vec<Cask>;              // runs brew (HOMEBREW_NO_AUTO_UPDATE=1, 5 s); on failure reads `<caskroom>/<token>/.metadata/<ver>/<ts>/Casks/<token>.json` for each `brew list --cask` token (or Caskroom dir listing when brew is absent)
  pub fn expand_zap_path(pattern: &str, home: &Path) -> Vec<PathBuf>;    // `~` → home, brace expansion, `*` glob against the filesystem (existing paths only)
  pub fn cask_for_bundle<'a>(casks: &'a [Cask], bundle: &Path) -> Option<&'a Cask>; // by `app_targets` match or Caskroom symlink target
  // pkg.rs
  pub struct PkgReceipt { pub id: String, pub version: String, pub volume: PathBuf, pub location: PathBuf, pub install_time: Option<i64>, pub files: Vec<PathBuf> /* absolute */ }
  pub fn parse_pkg_info(text: &str) -> Option<(String, String, PathBuf, PathBuf, Option<i64>)>;
  pub fn receipts(pkgutil: Option<&Path>) -> Vec<PkgReceipt>;            // non-`com.apple.*` ids only; `--pkg-info` + `--files` per id (≤ 5 s total budget; stops early when exceeded)
  pub fn pkgs_for_bundle<'a>(receipts: &'a [PkgReceipt], bundle: &Path) -> Vec<&'a PkgReceipt>; // receipts whose files include the bundle path or anything under it
  pub fn orphan_receipts<'a>(receipts: &'a [PkgReceipt], installed: &HashSet<PathBuf>) -> Vec<&'a PkgReceipt>; // receipts whose every file under /Applications is gone
  // last_used.rs
  pub fn spotlight_last_used(mdfind: Option<&Path>, roots: &[&Path]) -> HashMap<PathBuf, i64>; // one `mdfind -attr kMDItemLastUsedDate "kMDItemContentType == 'com.apple.application-bundle'" -onlyin <root>` per root; parses `<path>   kMDItemLastUsedDate = YYYY-MM-DD HH:MM:SS +0000`
  pub fn parse_mdfind_line(line: &str) -> Option<(PathBuf, i64)>;
  pub fn estimate_from(leftover_mtimes: &[i64]) -> LastUsed;             // max → Estimated, empty → Unknown
  pub fn inventory(index: &Index, home: &Path, tools: &ToolPaths) -> Vec<AppInfo>; // glue; `ToolPaths { brew, pkgutil, mdfind, lsappinfo }` from `tools::tool_path`
  ```
- Source priority: Cask > Pkg > AppStore > Dragged (spec §8). `version` from the bundle (brew's recorded version may lag behind auto-updaters).

- [ ] **Step 1: Failing tests** (fixtures: the raycast/hex/zoom/teamviewer JSON, the `pkg-info` text and `mdfind` lines from the research file, written under `tests/fixtures/apps/`): `parse_casks_handles_string_or_array_directives` (zoom's `delete` string and list, `signal` pairs, `script` object), `expand_zap_path_expands_tilde_braces_and_globs` (temp dirs), `cask_for_bundle_matches_app_target`, `parse_pkg_info_reads_location_and_time`, `pkgs_for_bundle_matches_files_under_bundle`, `orphan_receipts_detects_missing_apps`, `parse_mdfind_line`, `last_used_unknown_falls_back_to_leftovers_with_estimate_flag`, `app_bundles_skips_symlinks_nested_and_system` (temp tree with `A.app`, `A.app/Contents/Frameworks/B.app`, a symlink `S.app`, scanned with `walk`), `read_bundle_reads_plist_and_receipt`.
- [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement.** No external command runs in tests (pass `None` tool paths). — [ ] **Step 4: Suite, clippy, fmt.**
- [ ] **Step 5: Commit** — `core: app inventory (bundles, cask/pkg/app-store sources, Spotlight last-used)`

---

### Task 3: Leftovers, app findings, leftover groups, orphan receipts; categorizer wiring

**Files:**
- Create: `crates/discky-core/src/findings/apps/leftovers.rs`
- Modify: `crates/discky-core/src/findings/apps/mod.rs` (`find`), `src/findings/mod.rs` (categorizer order), `src/rules/builtin.toml` (no new rules; only if an `apps` exclusion list is cleaner as data)
- Test: `crates/discky-core/tests/apps_findings.rs`

**Interfaces:**
- Produces:
  ```rust
  // leftovers.rs
  pub const USER_LOCATIONS: [(&str, ComponentKind); 12]; // ~/Library/{Application Support, Caches, Preferences, Containers, Group Containers, Saved Application State, HTTPStorages, WebKit, Cookies, Logs, LaunchAgents, Application Scripts}
  pub const SYSTEM_LOCATIONS: [(&str, ComponentKind); 5];  // /Library/{LaunchAgents, LaunchDaemons, Application Support, PrivilegedHelperTools, Preferences}
  pub struct LeftoverQuery<'a> { pub bundle_id: Option<&'a str>, pub name: &'a str, pub zap_paths: &'a [PathBuf], pub cask_launchctl: &'a [String] }
  pub fn leftovers_for(index: &Index, home: &Path, q: &LeftoverQuery, installed_ids: &HashSet<String>) -> Vec<Component>;
  pub fn launchd_label(plist: &Path) -> Option<(String, Vec<String> /* AssociatedBundleIdentifiers */)>;
  pub fn is_loaded(label: &str, system: bool, launchctl: Option<&Path>) -> bool; // `launchctl print gui/<uid>/<label>` / `system/<label>` exit 0
  pub fn preference_domains(home: &Path, bundle_id: &str) -> Vec<(String, PathBuf)>; // `~/Library/Preferences/<id>*.plist` → (domain, path); never `defaults domains`
  // apps/mod.rs
  pub fn find(index: &Index, home: &Path, claimed: &mut HashSet<NodeId>, running: &HashSet<String>) -> Vec<Finding>;
  pub const UNUSED_DAYS: u32 = 180;
  ```
- Matching rules (Review Focus 1, 3): a leftover attaches to an app when (a) its folder/plist name starts with the app's bundle id (`com.raycast.macos`, `com.raycast.macos.plist`, `SY64MV22J9.com.raycast.macos.shared` after team-prefix strip), or (b) it is a cask zap path, or (c) it is an **exact** case-insensitive folder-name match of the app name in `Application Support` or `Logs` only. A candidate that also matches another installed app's bundle id prefix (`com.google` shared folders, `~/Library/Application Support/Google`) gets `removal: None`, `default_on: false`, `note: "shared with <Other app>"`. LaunchAgents/Daemons match by label prefix, `AssociatedBundleIdentifiers`, or cask `launchctl` labels; `title` carries "· active" when loaded; daemons and `/Library/*` are `note: "needs administrator password"`. `default_on` = true for everything except shared folders, `Container` dirs with `note` "may hold documents" when > 100 MB, and `OwnUninstaller`.
- Findings: one per `AppInfo` (`Category::Apps`, `title` = app name, `subtitle` = "cask · raycast" / "pkg" / "App Store" / "drag & drop" plus "last opened 3 months ago" / "never*" / "14 months ago*" for estimates, `path` = bundle, `allocated` = bundle + default_on leftovers, `freed_if_deleted` likewise from `private`, `modified` = last-used timestamp when known, `label` = `AppData` (or `NeedsPassword` when root-owned / a daemon is selected, `AppRunning` when running — flag `"app-running"` as the planner expects), `removal: Removal::App { source, bundle, bundle_id }`, `components` = [AppBundle first, then leftovers sorted by size], `explain` = the source sentence from spec §8). Apps are **not** claimed (their leftovers stay visible under App caches; spec §6 lists both).
- Leftover groups ("leftovers of removed apps"): group unclaimed `USER_LOCATIONS` entries by bundle-id prefix (team prefix stripped) whose prefix matches no installed app's bundle id (bundle ids of all `.app`s under /Applications, ~/Applications **and** `/System/Applications`), no running process (`running`) and no loaded launchd label; one finding per group (`title` = humanised last component of the bundle id, `subtitle` = "leftovers of a removed app · N items", `rule_id` = "app-leftovers", `label` = `AppData`, `removal: Removal::Trash { paths }` of all components, components listed, `explain` = "No installed app uses these files."). These **claim** their nodes (so App caches does not list them twice); `find` therefore runs **before** `app_caches::find` in `Categorizer::run_with_home`. Orphan pkg receipts become one finding "Package receipts of removed apps" with `Receipt` components (`PkgForget`, `default_on: true`), `allocated = 0`.

- [ ] **Step 1: Failing tests** (temp tree + `walk`; no real commands: pass `None` tool paths, `running` set built by the test): `app_finding_lists_bundle_and_leftovers`, `shared_leftover_is_attached_to_no_app`, `name_match_is_exact_only` (`LogiZoomBridge` not attached to "zoom"), `running_app_gets_app_running_label`, `leftover_group_for_removed_app_claims_its_nodes` (and App caches no longer lists them), `orphan_receipts_become_one_finding`, `launchd_label_reads_label_and_associated_ids` (fixture plist).
- [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Suite, clippy, fmt; run `cargo run -p discky-mcp -- --self-test-scan` once and record the added scan time (target ≤ 3 s over M2).**
- [ ] **Step 5: Commit** — `core: app findings with leftovers, leftover groups and orphan receipts`

---

### Task 4: Planner: app removal sequences

**Files:**
- Modify: `crates/discky-core/src/plan/mod.rs`
- Test: `crates/discky-core/tests/plan_apps.rs`

**Interfaces:**
- Consumes: `Removal::App`, `Component`, `PlanItem`, `tools::tool_path`.
- Produces: `plan_items` composes, for an `App` finding and its selected components, this order (spec §7/§8), each step carrying `component: Some(i)` where applicable:
  1. `OwnUninstaller` script (cask `uninstall.script` or a `.scpt`/`.sh` under the bundle) → `Command` (`/usr/bin/osascript <path>` for `.scpt`, `/bin/sh <path>` for `.sh`), `must_succeed=false` scripts get `freed_note: "Optional vendor step"`; `Uninstall*.app` → no step, `warnings` gets "Run <name>'s own uninstaller first (Contents/Resources/<X>.app)".
  2. `Quit { bundle_id }` when the finding has `"app-running"` (INTERACTIVE) — plus cask `uninstall.quit` ids.
  3. Source step: `Cask` → `Command { argv: [brew, "uninstall", "--cask", "--zap", full_token] }` with `freed = bundle + zap components` and the zap components' Trash steps **omitted** (brew does them); env `HOMEBREW_NO_AUTO_UPDATE=1` (add `env: Vec<(String,String)>` to `StepKind::Command`, serialized). `Pkg` → `Trash` of every receipt file under `/Applications` or `~` (one step, `component` = AppBundle) then, after the leftovers, `Command { argv: [/usr/sbin/pkgutil, "--forget", id] }` per id with INTERACTIVE. `AppStore`/`Dragged` → `Trash { paths: [bundle] }` (INTERACTIVE when `needs_admin`).
  4. Per selected `LaunchAgent`/`LaunchDaemon` component: `Command` `launchctl bootout gui/<uid>/<label>` (or `system/<label>` + INTERACTIVE) **only when loaded**, then `Trash` of the plist (INTERACTIVE for `/Library`).
  5. Per selected Trash component: `Trash` (respecting `RemovalMode::Permanent` → `Remove` + PERMANENT), paths needing admin → INTERACTIVE.
  6. Per selected `Preferences` component: `Command` `/usr/bin/defaults delete <domain>`.
  7. `PkgForget` components (orphan receipts or pkg source): `Command` `/usr/sbin/pkgutil --forget <id>` INTERACTIVE.
  `MiseUninstall` → `Command { argv: [mise, "uninstall", "<tool>@<version>"] }` with `freed = finding.freed_if_deleted`, `TOOL_MISSING` when mise is absent; a global version (Removal::None) is skipped with "Global version — change it in ~/.config/mise/config.toml first".
  Steps of one plan keep the group order Quit → commands/source → trash → defaults/forget across findings (extend the existing three buckets to five).

- [ ] **Step 1: Failing tests** (pure: synthetic findings, `tool_path` not needed — pass a `ToolPaths` with fake absolute paths via a new `plan_items_with_tools(items, findings, cfg, tools)` that `plan_items` calls with real lookups): `cask_plan_runs_brew_zap_and_skips_zap_components`, `pkg_plan_trashes_files_then_forgets`, `dragged_plan_is_a_trash_step`, `root_owned_bundle_step_is_interactive`, `loaded_daemon_gets_bootout_then_trash`, `preferences_use_defaults_delete`, `unselected_components_produce_no_steps`, `mise_uninstall_step_and_global_skip`, `own_uninstaller_app_becomes_a_warning`.
- [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement** (+ `Command.env` honoured in `execute.rs::run_command` and shown by `Plan::to_json`). — [ ] **Step 4: Suite, clippy, fmt.**
- [ ] **Step 5: Commit** — `core: plan app removals per source with leftover, launchd, defaults and pkgutil steps`

---

### Task 5: mise adapter

**Files:**
- Create: `crates/discky-core/src/findings/mise.rs`
- Modify: `crates/discky-core/src/findings/mod.rs` (categorizer: after apps, before app_caches), `src/engine.rs` (`mise_prune_dry_run`)
- Test: `crates/discky-core/tests/mise.rs` with JSON fixtures from the research file (`tests/fixtures/mise/{ls.json,all_sources.json}`)

**Interfaces:**
- Produces:
  ```rust
  pub struct MiseVersion { pub tool: String, pub version: String, pub install_path: PathBuf, pub installed: bool, pub active: bool, pub sources: Vec<MiseSource> }
  pub struct MiseSource { pub kind: String /* "mise.toml" | ".tool-versions" | "idiomatic-version-file" */, pub path: PathBuf, pub requested: String }
  pub fn parse_ls(json: &str) -> Result<Vec<MiseVersion>, String>;              // `mise ls --json` (singular `source`)
  pub fn merge_sources(mut versions: Vec<MiseVersion>, all_sources_json: &str) -> Vec<MiseVersion>; // adds `sources[]` from `mise ls --all-sources --json`; keeps installed-but-unreferenced versions; drops `installed: false` entries
  #[derive(Debug, Clone, PartialEq, Eq)] pub enum VersionStatus { Global, Pinned(usize), Unreferenced }
  pub fn status_of(v: &MiseVersion, home: &Path) -> VersionStatus;            // Global when a source path == home/.config/mise/config.toml
  pub fn untracked_version_files(index: &Index, home: &Path, tracked: &HashSet<PathBuf>) -> Vec<(PathBuf, String /* tool */, String /* requested */)>; // files named .nvmrc/.node-version/.ruby-version/.python-version/.tool-versions/mise.toml/.mise.toml under home (skipping ~/Library, node_modules, .git), first line / `[tools]` entries parsed, not in `tracked`
  pub fn find(index: &Index, home: &Path, mise: Option<&Path>, claimed: &mut HashSet<NodeId>) -> Vec<Finding>;
  impl Engine { pub fn mise_prune_dry_run(&self) -> Result<String, String>; }  // `mise prune -n`, 5 s; Err when mise is missing ("mise is not installed")
  ```
- Finding per installed version: `title` = "node 19.9.0", `subtitle` = "global" / "pinned in N projects" / "not referenced" (+ " · M untracked files" when applicable), `path` = `install_path`, sizes from the index node (symlink aliases `19`, `lts-*` are separate nodes — ignore them), `label` = `AppData`, `rule_id` = "mise-version", `removal` = `Removal::MiseUninstall { tool, version }` or `Removal::None` for Global (explain "Global version; change it in ~/.config/mise/config.toml first"), `components` = one `Project` component per source (`title` = "requested by <kind>", `path` = file, `removal: None`, `default_on: false`) plus one per untracked file matching the version (`note: "not tracked by mise"`). The version's install dir is **claimed**.

- [ ] **Step 1: Failing tests**: `parse_ls_reads_versions_and_single_source`, `merge_sources_keeps_unreferenced_and_drops_missing`, `status_global_pinned_unreferenced`, `untracked_version_file_is_reported`, `global_version_is_not_removable`, `findings_size_from_index_ignoring_alias_symlinks`.
- [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Suite, clippy, fmt.**
- [ ] **Step 5: Commit** — `core: mise language versions with requesting projects and untracked version files`

---

### Task 6: MCP: components, plan items, instructions

**Files:**
- Modify: `crates/discky-mcp/src/params.rs`, `src/server.rs`, `README.md` (tool table), `tests/stdio.rs`

**Interfaces:**
- `PlanParams` gains `components: Option<HashMap<String, Vec<usize>>>` (finding id → component indices) and the tool calls `engine.plan_items`. `inspect` output includes `components` (serde of the finding already does; make sure `InspectOut` carries the full finding). `findings` rows gain `source`/`status` only through `subtitle` (no schema change). INSTRUCTIONS: add "Applications and Language versions findings carry `components`; pass `components` to `plan_removal` to remove only some of them; steps that need an administrator or quit an app are skipped for agents." `scan_status`/`disk_overview` unchanged.
- [ ] **Step 1: Failing e2e test** in `tests/stdio.rs`: `plan_removal_with_components_selects_steps` (fixture app finding built through a scratch home with a fake `.app` and a fake leftover; no brew; the plan has the bundle Trash step and only the selected leftover). — [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Suite, clippy, fmt.**
- [ ] **Step 5: Commit** — `mcp: component selection in plan_removal, components in inspect`

---

### Task 7: App: per-category columns, Apps filter tabs, sidebar count

**Files:**
- Modify: `crates/discky-app/src/category/table.rs`, `category/mod.rs`, `overview/model.rs`, `sidebar.rs`, `format.rs`
- Test: unit tests for the pure column/row text helpers

**Interfaces:**
- `table.rs`: `pub enum Layout { Default, Apps, Versions }` chosen by `Category`; `Apps` columns: check · Name (app name + bundle id muted) · Source ("cask · raycast", "pkg", "App Store", "drag & drop") · Last opened (`relative` or "never*" / "N months ago*" for estimates) · Total (allocated, with "app X + leftovers Y" muted second line); `Versions` columns: check · Name ("node 19.9.0") · Status ("global" / "pinned in 3 projects" / "not referenced") · Where (install path, mono) · Size. Sort tabs for Apps: "Size / Last opened / Name"; for Versions: "Size / Tool".
- `category/mod.rs`: Apps toolbar gets `TabBar::segmented()` "Not opened in 6 months (N) / All (M) / Leftovers (K)" (default "Not opened in 6 months"; `UNUSED_DAYS` from core; unknown last-used counts as not opened; "Leftovers" = `rule_id == "app-leftovers"` + the receipts finding). `pub fn apps_filter(findings, now, tab) -> Vec<&Finding>` tested.
- Sidebar weight for Applications = **count** of "not opened in 6 months" apps (e.g. "19"), not bytes; Overview card for Applications: header "Applications · N not opened in 6 months", rows = top 4 by allocated of that subset, disk-bar segment for Apps = bundle bytes only (`by_category` already sums `allocated`; add `Overview.apps_unused: usize` in core `query.rs`).
- [ ] **Step 1: Failing tests**: `apps_filter_treats_unknown_as_unused`, `source_text_forms`, `last_opened_text_marks_estimates`, `versions_status_text`.
- [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Suite, clippy, fmt, `--self-check`; one manual launch with `DISCKY_START_ROUTE=apps` on the real snapshot (look only).**
- [ ] **Step 5: Commit** — `app: Applications and Language versions tables, Apps filter tabs, unused-app count in the sidebar`

---

### Task 8: App: inspector components with checkboxes, selection-aware plan and removal

**Files:**
- Modify: `crates/discky-app/src/inspector.rs`, `removal/mod.rs`, `removal/model.rs`, `app.rs`, `category/mod.rs`
- Test: unit tests for the selection model

**Interfaces:**
- Inspector: a "Components" section replaces "Contents" for findings with `components`: one row per component (checkbox bound to a `HashSet<usize>` initialised from `default_on`; disabled when `removal == None` with the `note` shown; title, path mono, size, "· active" / "needs administrator password" notes). The plan preview recomputes on every toggle through `Engine::plan_items(&[PlanItem { id, components: Some(selected) }])` (background). Footer "Remove…" emits `InspectorEvent::RemoveItems(Vec<PlanItem>)`.
- Removal dialog takes `Vec<PlanItem>` (the category table's checkboxes map to `components: None`); `RemovalModel.rows` show the component title when `step.component` is set ("TeamViewer → Application Support").
- `pub struct ComponentSelection { on: HashSet<usize> }` with `toggle`, `items(id) -> PlanItem`, `summary(components) -> (count, bytes)`; tests `defaults_from_default_on`, `none_removal_cannot_be_selected`.
- [ ] **Step 1: Failing tests.** — [ ] **Step 2: Run, verify failure.** — [ ] **Step 3: Implement.** — [ ] **Step 4: Suite, clippy, fmt, `--self-check`; one manual launch with `DISCKY_START_ROUTE=apps DISCKY_START_INSPECT="Raycast"` (look only).**
- [ ] **Step 5: Commit** — `app: component checkboxes in the inspector, selection-aware plans and removal`

---

### Task 9: App: Version manager page: `mise prune` dry run; Settings copy

**Files:**
- Modify: `crates/discky-app/src/settings/version_manager.rs`, `settings/mod.rs`
- Test: none beyond compile (the page calls `Engine::mise_prune_dry_run` on `background_spawn`)

- Button "mise prune (dry run)" → output in a dialog titled "What mise would prune" (mono, scrollable, "Close"); errors as a warning toast. Help text: "Runs `mise prune -n`; nothing is removed." The page also links to the Language versions category ("Show installed versions").
- [ ] **Step 1: Implement.** — [ ] **Step 2: clippy, fmt, `--self-check`.** — [ ] **Step 3: Commit** — `app: mise prune dry run in Settings → Version manager`

---

### Task 10: Hygiene: M2 follow-ups, README, plist

**Files:**
- Modify: `README.md`, `packaging/macos/Info.plist`, `crates/discky-core/src/engine.rs`, `crates/discky-app/src/category/mod.rs`, `docs/superpowers/plans/2026-11-03-m2-followups.md`

- README: fix the ⌘Q sentence ("are refused with a notification while a removal runs"); document Applications/Language versions, component selection in MCP `plan_removal`, the Automation prompt now also covering `pkgutil --forget`/`launchctl bootout system` admin prompts; Status → Milestone 3. `Info.plist`: Apple-Events text mentions Empty Trash and quitting apps. Core: apply `drop_gone` in `reload_snapshot` too. App: move the displaced doc comment in `category/mod.rs`. Follow-ups doc: tick what M3 closed.
- [ ] **Step 1: Implement (+ a test that `reload_snapshot` drops gone findings).** — [ ] **Step 2: Suite, clippy, fmt.** — [ ] **Step 3: Commit** — `docs/core: M2 follow-ups (README wording, reload drop_gone, plist text)`

---

## Self-review notes

- Spec coverage: §8 sources/priority (T2), leftovers list + `defaults delete` + `bootout` + Keychain untouched (T3/T4; Keychain detection itself is **deferred** — ruling: no `security` calls in M3, the inspector shows a static "Keychain items are never touched" note for apps), own uninstaller first (T4), exclusions (T2), last-used + estimate (T2), leftovers of removed apps (T3); §9 mise ls/all-sources/prune (T5, T9), statuses, untracked files (T5), `mise uninstall` only + global rule (T4/T5), Settings copy unchanged; §11 inspector components with checkboxes (T8); §12c component selection for agents (T6).
- Deviations (rulings): Keychain detection deferred; legacy files are labelled "not tracked by mise" (what the CLI can tell) instead of "legacy, disabled in mise"; `pkgutil --file-info` replaced by a receipts reverse index (macOS 26 returns no pkgid); running apps via `lsappinfo`; Apps findings do not claim their leftovers (both categories show them), leftover groups do claim.
- Type consistency: `Component`/`PlanItem` (T1) ↔ T3/T4/T6/T8; `AppInfo`/`LastUsed` (T2) ↔ T3/T7; `MiseVersion` (T5) ↔ T7; `InspectorEvent::RemoveItems(Vec<PlanItem>)` (T8) ↔ removal dialog; `Overview.apps_unused` (T7 core change) ↔ sidebar.
