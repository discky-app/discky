# Launch Preparation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One Homebrew command installs Discky.app with `discky-mcp` inside it, a tag builds the release, the first launch walks the user through Full Disk Access, and a failed removal step stops only its own item.

**Architecture:** `cargo xtask bundle` adds the release `discky-mcp` to `Discky.app/Contents/MacOS` and signs it before the bundle, so the cask's `binary` stanza can symlink it. A new `crate::access` module owns the Full Disk Access probe (moved out of Settings), the pure `AccessNotice` decision and the relaunch helper; `OverviewView` renders the notice (onboarding card, relaunch card or a dismissable banner) and re-probes when the window is activated or a scan finishes. A release workflow runs on `v*` tags: bundle (imported Apple Development certificate when the secrets exist, ad-hoc otherwise), zip, sha256, render the cask from a template, publish a GitHub release and, with a token, push the cask to the tap `AlxGolubev/homebrew-discky`.

**Tech Stack:** Rust 1.99.1, gpui-kit `=0.9.0` (gpui-pre 0.3.11), GitHub Actions `macos-15`, Homebrew cask DSL, `codesign`, `ditto`.

**Spec:** `docs/superpowers/specs/2026-11-02-discky-design.md` §3 (Full Disk Access cannot be requested; detect and open the pane), §11 (Overview), §13 (distribution: tap cask installs the app and symlinks `discky-mcp`, signing not ad-hoc, `--no-quarantine`), §17. Owner decisions 2026-11-04 (this session): no paid Apple account, so no notarization; GitHub user `AlxGolubev`; tap repository `AlxGolubev/homebrew-discky`; onboarding lives on the Overview, no separate wizard window; the `discky-mcp` formula stub is dropped (MCP-only users build with `cargo install`).

## Global Constraints

- Minimum macOS 15; Rust pinned by `rust-toolchain.toml` (1.99.1); gpui only through `gpui-kit =0.9.0`; theme colours only.
- **No MCP changes:** no new tool, parameter or output field; snapshot format stays 3. Bundling the binary is allowed, changing it is not.
- English UI copy, no telemetry, no "coming soon" labels.
- Owner rules: `cargo test` opens no window; `--self-check` keeps windows hidden and never calls `cx.activate`; at most one short manual app launch per GUI task, quit by the implementer; no synthetic clicks or keys; window-only screenshots, deleted after use, never pasted into reports.
- Tests and implementers never touch the real Trash or home data, never run `brew install`/`brew uninstall`/`tccutil`, never change System Settings; read-only probes (`read_dir`, `codesign --verify`, `brew style`) are allowed.
- Fixtures and docs carry no owner paths (the owner's home folder, cloud-synced folders, session scratchpads).
- The app must still build and run when `discky-mcp` is absent from the bundle (`cargo run -p discky-app`).
- Conventional Commits with the crate as scope.

## Review Focus

1. A fresh account without `~/Library/Mail` and `~/Library/Safari` probes as `Unknown`: the Overview must not nag (Task 2 `unknown_access_is_silent`).
2. "Relaunch Discky" while a removal runs must neither quit nor schedule a reopen that fires minutes later (Task 2 `relaunch_plan_refuses_while_removal_runs`, Task 3 wiring).
3. `cargo run -p discky-app` has no bundle: the relaunch plan re-executes the binary itself instead of `open`ing a non-existent `.app` (Task 2 `bundle_root_outside_a_bundle`).
4. A tag that disagrees with `crates/discky-app/Cargo.toml` must fail the release before anything is uploaded (Task 5 `version` guard step, Task 1 `xtask version`).
5. A rendered cask with a placeholder left in it must not reach the tap (Task 4 `render-cask.sh` exits non-zero on missing arguments; CI runs `brew style` on a rendered file).
6. A queue of several items: one item's failed command must not leave the other items unrun, the failed item's later steps must not fall back to trashing, and a failed Trash step must not block anything (Task 0 `failed_step_skips_the_rest_of_its_item_only`, `failed_trash_step_blocks_nothing`).

---

### Task 0: A failed step stops its item, not the queue

**Files:**
- Modify: `crates/discky-core/src/plan/execute.rs` (module doc, the step loop around `stopped_at`, a `failed: HashSet<&str>` of finding ids beside `gates`), `crates/discky-app/src/removal/model.rs` (`Summary`, the toast), `crates/discky-mcp/src/params.rs:426` (doc comment of `stopped_at` only; no schema change), `README.md:25` and `:105` (wording).
- Test: `crates/discky-core/tests/execute.rs` (new tests in the file's existing fixture style).

**Interfaces:**
- Produces: `pub const FAILED_STEP_REASON: &str = "an earlier command of this item failed"` in `plan::execute`. `ExecutionReport` keeps its fields; `stopped_at` now means "the whole queue stopped here" and is set only when the removal log cannot be written. **Blocking rule:** a `Failed` step blocks the later non-`Quit` steps of its own finding only when it is a step the later ones depend on: a `GATE` step (`Quit`, vendor script) or a `Command`/`OllamaDelete` step (the tool's own removal; spec §7: no trashing after the official command failed). A failed `Trash`/`Remove` step blocks nothing: the item's other paths and every other item still run. Blocked steps are `Skipped` with `FAILED_STEP_REASON` (a failed `Quit` keeps `QUIT_FIRST_REASON`). `Summary` in the app gains `failed: usize` and `skipped: usize` (counted from `results`).

- [ ] **Step 1: Write the failing tests** (`tests/execute.rs`)

```rust
#[test]
fn failed_step_skips_the_rest_of_its_item_only() {
    // Item A: a command that fails (`/usr/bin/false`), then a Trash step for `a`.
    // Item B: a Trash step for `b`. Both files exist in a temp dir; DISCKY_TRASH_BIN is
    // the fixture trash used by the other tests in this file.
    let report = run(plan_with(&[cmd_false("A"), trash("A", &a), trash("B", &b)]));
    assert_eq!(statuses(&report), [StepStatus::Failed, StepStatus::Skipped, StepStatus::Done]);
    assert_eq!(report.results[1].reason.as_deref(), Some(FAILED_STEP_REASON));
    assert!(a.exists(), "the failed item's trash step must not run");
    assert!(!b.exists(), "the other item still runs");
    assert_eq!(report.stopped_at, None);
    // The removal log keeps the failure and the skip with their reasons: one record per
    // step, in order, with `status`, `reason` and the command's `output_tail`.
    let records = read_log(&paths.log);
    assert_eq!(records[0].status, StepStatus::Failed);
    assert!(records[0].reason.is_some(), "a failed step records why");
    assert!(records[0].output_tail.contains("false") || !records[0].output_tail.is_empty() || records[0].reason.is_some());
    assert_eq!(records[1].status, StepStatus::Skipped);
    assert_eq!(records[1].reason.as_deref(), Some(FAILED_STEP_REASON));
    assert_eq!(records[2].status, StepStatus::Done);
}

#[test]
fn failed_trash_step_blocks_nothing() {
    // Item A: Trash `a1` (the fixture trash script exits 1 for a path whose name contains
    // "fail"), then Trash `a2`. Item B: Trash `b`.
    let report = run(plan_with(&[trash("A", &a1_fail), trash("A", &a2), trash("B", &b)]));
    assert_eq!(statuses(&report), [StepStatus::Failed, StepStatus::Done, StepStatus::Done]);
    assert!(!a2.exists() && !b.exists());
    assert_eq!(report.stopped_at, None);
}

#[test]
fn history_write_failure_still_stops_the_queue() {
    // The log path is a directory, so the first append fails: stopped_at == Some(0) and
    // every later step is NotRun. (Keep or adapt the existing test if one covers it.)
}
```

- [ ] **Step 2: Run**: `cargo test -p discky-core --test execute failed_step` — FAIL (second step is `NotRun`, `stopped_at == Some(0)`).
- [ ] **Step 3: Implement** in the loop: on `StepStatus::Failed`, when the step is a `GATE` or a `Command`/`OllamaDelete`, insert `step.finding` into `failed` (never set `stopped_at`); `blocked` (or a second closure consulted after it) returns `FAILED_STEP_REASON` for a non-`Quit` step whose finding is in `failed`; `stopped_at` is set only by the history-write branch. Update the module doc's "the first failure stops the plan" sentence to the blocking rule above.
- [ ] **Step 4: App dialog** (`removal/model.rs`): `Summary { failed, skipped, .. }`; the toast after a run: `stopped_at` → unchanged "Stopped at step N: …"; else when `failed > 0` → warning "{failed} of {total} steps failed; the rest ran. See the list for why." (singular "1 step failed"); the skipped rows show `FAILED_STEP_REASON` like the gate reasons today. Existing `stopped_toast` tests adjusted, one new test for the failed-count toast.
- [ ] **Step 5: Docs**: README line 25 → "A failed tool command skips that item's remaining steps (there is no fallback to `rm`); a failed Trash step and every other item still run, and each failure is listed with its reason." Line 105 → "cancelling it fails that step; the item's remaining steps are skipped and the other items still run." `params.rs` doc: "Index of the step at which the whole queue stopped (the removal log could not be written); a failed step only skips the rest of its own item."
- [ ] **Step 6: Verify**: `cargo test --workspace`, clippy clean, `cargo run -p discky-mcp -- --help` unchanged.
- [ ] **Step 7: Commit** `fix(core,app): a failed step skips the rest of its item; other items still run`

---

### Task 1: `discky-mcp` inside the bundle, `xtask version`, bundle in CI

**Files:**
- Modify: `crates/xtask/src/bundle.rs` (`run`, new `sign`), `crates/xtask/src/main.rs` (`version` command, USAGE), `.github/workflows/ci.yml`, `CONTRIBUTING.md` (CI paragraph, lines 88-90).
- Test: `crates/xtask/src/bundle.rs` tests module.

**Interfaces:**
- Produces: `cargo xtask version` prints discky-app's manifest version and a newline, nothing else. `target/Discky.app/Contents/MacOS/discky-mcp` exists after `cargo xtask bundle`. `pub fn helper_binaries() -> [&'static str; 1]` returns `["discky-mcp"]` (the list the cask and CI rely on).

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn helper_binaries_lists_the_mcp_server() {
    assert_eq!(helper_binaries(), ["discky-mcp"]);
}
```

- [ ] **Step 2: Run it**: `cargo test -p xtask helper_binaries` — FAIL: not found.

- [ ] **Step 3: Implement in `bundle.rs`**
  - `pub fn helper_binaries() -> [&'static str; 1]`.
  - `run`: build with `cargo build -p discky-app -p discky-mcp --release`; copy `target/release/<helper>` to `macos.join(helper)` for each helper; keep the mode executable (`std::fs::copy` preserves it).
  - Signing order: for each helper run `codesign --force --sign <id> <helper path>` **before** the bundle's `codesign --force --deep --sign`; verification becomes `codesign --verify --deep --strict --verbose`. Reason: extra Mach-O files in `Contents/MacOS` are not covered by `--deep` and fail strict verification unsigned.
- [ ] **Step 4: `xtask version`** in `main.rs`: `Some("version") => bundle::print_version(&workspace_root())`, which prints `app_version(root)?` with `println!`. USAGE becomes `usage: cargo xtask <icon | bundle [--release] | install | version>`. Update the module doc list.
- [ ] **Step 5: Verify locally** (one real bundle, signs with the owner's identity, nothing installed):

```sh
cargo test -p xtask
cargo xtask bundle
test -x target/Discky.app/Contents/MacOS/discky-mcp
target/Discky.app/Contents/MacOS/discky-mcp --help | grep -q "Discky MCP server"
codesign --verify --deep --strict target/Discky.app && echo verified
cargo xtask version   # prints 0.1.0
```

- [ ] **Step 6: CI** (`ci.yml`), replacing the last comment line with:

```yaml
      - run: DISCKY_SIGN_IDENTITY=- cargo xtask bundle
      - run: test -x target/Discky.app/Contents/MacOS/discky-mcp
      - run: target/Discky.app/Contents/MacOS/discky-mcp --help | grep -q "Discky MCP server"
      - run: codesign --verify --deep --strict target/Discky.app
      - run: test "$(cargo xtask version)" = "$(grep -m1 '^version' crates/discky-mcp/Cargo.toml | cut -d'"' -f2)"
```

The last line keeps the two crates' versions equal, because the bundle ships both. CONTRIBUTING's CI paragraph: bundle now runs in CI ad-hoc; the sentence "`cargo xtask bundle` stays out of CI" goes.

- [ ] **Step 7: Commit** `feat(xtask): ship discky-mcp inside Discky.app; xtask version; bundle in CI`

---

### Task 2: `access` module — probe, notice decision, relaunch plan

**Files:**
- Create: `crates/discky-app/src/access.rs`
- Modify: `crates/discky-app/src/lib.rs` (`pub mod access;`), `crates/discky-app/src/settings/model.rs` (remove `FdaStatus`, `fda_status_from_results`, `probe_fda`, `FDA_SETTINGS_URL` and their tests; re-import from `crate::access`), `crates/discky-app/src/settings/mod.rs`, `crates/discky-app/src/settings/disk_access.rs` (imports only).
- Test: `crates/discky-app/src/access.rs` tests module (moved FDA tests plus the new ones).

**Interfaces:**
- Produces, all in `crate::access`:
  - `pub enum FdaStatus { Granted, Denied, Unknown }`, `pub fn probe_fda(home: &Path) -> FdaStatus`, `pub fn fda_status_from_results(..)`, `pub const FDA_SETTINGS_URL` — unchanged semantics, new home.
  - `#[derive(Clone, Copy, PartialEq, Eq, Debug)] pub enum AccessNotice { Hidden, Onboarding, Relaunch, Banner }`
  - `pub fn notice(fda: Option<FdaStatus>, has_snapshot: bool, saw_denied: bool, dismissed: bool) -> AccessNotice`
  - `pub fn bundle_root(exe: &Path) -> Option<PathBuf>`: `Some(x.app)` when `exe` is `<x>.app/Contents/MacOS/<name>`, else `None`.
  - `#[derive(Debug, PartialEq, Eq)] pub enum RelaunchPlan { Open(PathBuf), Exec(PathBuf), Busy }` and `pub fn relaunch_plan(exe: &Path, removal_running: bool) -> RelaunchPlan`.
  - `pub fn reveal_target(exe: &Path) -> Option<PathBuf>`: the bundle (`bundle_root`) to show in Finder; `None` outside a bundle. `pub fn open_fda_settings(cx: &mut App)`: `cx.open_url(FDA_SETTINGS_URL)`, then, when `reveal_target(current_exe)` is `Some`, spawns `open -R <bundle>` (stdio null, errors ignored) so Finder shows Discky.app next to the settings pane for a drag into the list.
  - `pub fn relaunch(plan: &RelaunchPlan, pid: u32) -> std::io::Result<()>`: spawns a detached `/bin/sh -c` that waits for `pid` to exit, then `open "<app>"` (Open) or `exec "<exe>"` (Exec); `Busy` is an `Err(io::ErrorKind::WouldBlock)`. The caller quits afterwards.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn unknown_access_is_silent() {
    assert_eq!(notice(None, false, false, false), AccessNotice::Hidden);
    assert_eq!(notice(Some(FdaStatus::Unknown), false, false, false), AccessNotice::Hidden);
    assert_eq!(notice(Some(FdaStatus::Granted), false, false, false), AccessNotice::Hidden);
}

#[test]
fn denied_shows_onboarding_then_banner() {
    assert_eq!(notice(Some(FdaStatus::Denied), false, true, false), AccessNotice::Onboarding);
    assert_eq!(notice(Some(FdaStatus::Denied), true, true, false), AccessNotice::Banner);
    assert_eq!(notice(Some(FdaStatus::Denied), true, true, true), AccessNotice::Hidden);
    // Dismissing hides the banner only; onboarding has no close button.
    assert_eq!(notice(Some(FdaStatus::Denied), false, true, true), AccessNotice::Onboarding);
}

#[test]
fn granted_after_denied_asks_to_relaunch() {
    assert_eq!(notice(Some(FdaStatus::Granted), false, true, false), AccessNotice::Relaunch);
    assert_eq!(notice(Some(FdaStatus::Granted), true, true, true), AccessNotice::Relaunch);
}

#[test]
fn bundle_root_outside_a_bundle() {
    assert_eq!(
        bundle_root(Path::new("/Applications/Discky.app/Contents/MacOS/Discky")),
        Some(PathBuf::from("/Applications/Discky.app"))
    );
    assert_eq!(bundle_root(Path::new("/tmp/discky/target/debug/discky-app")), None);
    assert_eq!(bundle_root(Path::new("/x/Contents/MacOS/Discky")), None);
}

#[test]
fn relaunch_plan_refuses_while_removal_runs() {
    let exe = Path::new("/Applications/Discky.app/Contents/MacOS/Discky");
    assert_eq!(relaunch_plan(exe, true), RelaunchPlan::Busy);
    assert_eq!(relaunch_plan(exe, false), RelaunchPlan::Open("/Applications/Discky.app".into()));
    assert_eq!(
        relaunch_plan(Path::new("/t/debug/discky-app"), false),
        RelaunchPlan::Exec("/t/debug/discky-app".into())
    );
}
```

- [ ] **Step 2: Run**: `cargo test -p discky-app access::` — FAIL: module missing.
- [ ] **Step 3: Implement `access.rs`**; move the three FDA items and `FDA_SETTINGS_URL` with their existing tests (`fda_status_from_errors`) from `settings/model.rs`; `settings` imports them from `crate::access`. `relaunch` shell: `sh -c 'while kill -0 "$1" 2>/dev/null; do sleep 0.1; done; open "$2"' sh <pid> <app>` (Exec variant: `exec "$2"`), `Stdio::null()` everywhere, `spawn()` and drop the child.
- [ ] **Step 4: Run** `cargo test -p discky-app` and `cargo clippy -p discky-app --all-targets -- -D warnings` — PASS, clean.
- [ ] **Step 5: Commit** `feat(app): access module with the Full Disk Access notice and relaunch plan`

---

### Task 3: Overview onboarding, banner and relaunch

**Files:**
- Create: `crates/discky-app/src/overview/access_notice.rs` (the three elements)
- Modify: `crates/discky-app/src/overview/mod.rs` (`OverviewView` fields, `new(app, scan, window, cx)`, `check_access`, render), `crates/discky-app/src/app.rs` (`OverviewView::new` call passes `window`; `pub fn relaunch_app(window: &mut Window, cx: &mut App)`).
- Test: none beyond Task 2 (GUI); self-check must stay green.

**Interfaces:**
- Consumes: `crate::access::{AccessNotice, FdaStatus, notice, probe_fda, relaunch_plan, relaunch, FDA_SETTINGS_URL}`, `ScanMsg::Finished`, `cx.observe_window_activation(window, ..)`, `window.is_window_active()`, `OverviewModel.no_access: usize` (present; add it if `model::build` does not expose the count yet, from `Overview.no_access`).
- Produces: `app::relaunch_app`: on `RelaunchPlan::Busy` shows `Notification::warning(BUSY_MESSAGE)` in the window and returns; otherwise calls `access::relaunch` and `cx.quit()`; a spawn error becomes `Notification::error(format!("Could not relaunch: {e}"))` without quitting.

- [ ] **Step 1: State and probing** in `OverviewView`: fields `fda: Option<FdaStatus>`, `saw_denied: bool`, `banner_dismissed: bool`, `_fda_task: Task<()>`, `_activation: Subscription`. `fn check_access(&mut self, cx)` copies the `SettingsView::check_fda` pattern (background `probe_fda(home)` with `discky_core::paths::home_dir().unwrap_or_default()`), sets `saw_denied |= status == Denied`. Called from `new`, from the activation observer when `window.is_window_active()`, and in the existing `scan_events` subscription on `ScanMsg::Finished`.
- [ ] **Step 2: Debug override**: `#[cfg(debug_assertions)]` `DISCKY_FDA` replaces the probe result (same style as `DISCKY_START_ROUTE`): a comma list of `denied|granted|unknown` consumed one value per probe, the last value repeating (`DISCKY_FDA=denied,granted` shows the onboarding card, then the relaunch card after the window is re-activated). Documented in CONTRIBUTING "Debug variables" (Task 6 copies the line).
- [ ] **Step 3: Elements** in `access_notice.rs`, theme colours only, each a method on `OverviewView` returning `impl IntoElement`:
  - **Onboarding card** (replaces the "No scan yet" empty state when `notice == Onboarding`): logo 128 px, title "Give Discky Full Disk Access", body "Without it macOS hides Mail, Safari and other apps' containers from the scan. macOS does not let apps ask for it.", then three numbered lines in muted text: "1. Open the settings pane below. Discky is usually already in the list, switched off, because it just tried to read ~/Library.", "2. Turn it on. If it is not listed, drag Discky.app from the Finder window that opens next to it.", "3. Come back here: Discky notices the change and offers to relaunch." Buttons `Button::new("open-fda").primary().label("Open Full Disk Access settings")` → `access::open_fda_settings(cx)` and `rescan_button("scan-anyway", "Scan anyway").ghost()`. The Settings → Disk access "Open System Settings" button calls the same helper.
  - **Relaunch card** (`Relaunch`; shown above the toolbar whether or not a snapshot exists): title "Full Disk Access granted", body "macOS applies it to a new process. Relaunch Discky, then scan.", `Button::new("relaunch").primary().label("Relaunch Discky")` → `app::relaunch_app(window, cx)`.
  - **Banner** (`Banner`; the warning-style row already used for `last_error`): text "Full Disk Access is off: {n} folders were skipped." when `no_access > 0`, else "Full Disk Access is off: parts of ~/Library were skipped."; `Button::new("banner-open-fda").small().label("Open settings")`; `Button::new("banner-dismiss").ghost().small()` with `Icon::new(IconName::Close)` → `banner_dismissed = true` (in-memory, resets next launch).
- [ ] **Step 4: Render wiring** in `OverviewView::render`: compute `let n = notice(self.fda, has_snapshot, self.saw_denied, self.banner_dismissed)`; `Relaunch` card first child; `Banner` right after `last_error`; `Onboarding` replaces `empty_state()` (the `Scan anyway` button keeps the "No scan yet" flow reachable). Nothing is rendered while `fda.is_none()`.
- [ ] **Step 5: Verify**: `cargo test -p discky-app`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo build -p discky-app && target/debug/discky-app --self-check` prints `self-check ok`. One short manual launch on a scratch home, quit by the implementer: `DISCKY_HOME=<scratch> DISCKY_FDA=denied,granted cargo run -p discky-app` shows the onboarding card; after the implementer switches to another app and back, the relaunch card. The banner (`DISCKY_FDA=denied` with an existing scratch snapshot) and the Relaunch button itself are owner checks (the button quits the app).
- [ ] **Step 6: Commit** `feat(app): Full Disk Access onboarding, banner and relaunch on the Overview`

---

### Task 4: Homebrew cask template and renderer

**Files:**
- Create: `packaging/homebrew/discky.rb.tmpl`, `packaging/homebrew/render-cask.sh` (executable)
- Delete: `packaging/homebrew/discky-mcp.rb`
- Modify: `.github/workflows/ci.yml` (two steps), `CONTRIBUTING.md` CI paragraph (one clause).

**Interfaces:**
- Produces: `render-cask.sh <version> <sha256> > discky.rb` replaces `@VERSION@` and `@SHA256@`; exits 2 with a usage line when an argument is missing or empty; exits 3 if the output still contains `@`. Task 5 calls it; README (Task 6) names the tap.

- [ ] **Step 1: Template** (`discky.rb.tmpl`):

```ruby
cask "discky" do
  version "@VERSION@"
  sha256 "@SHA256@"

  url "https://github.com/AlxGolubev/discky/releases/download/v#{version}/Discky-#{version}.zip"
  name "Discky"
  desc "Disk cleanup for macOS that only uses official removal mechanisms, with an MCP server"
  homepage "https://github.com/AlxGolubev/discky"

  depends_on macos: ">= :sequoia"

  app "Discky.app"
  binary "#{appdir}/Discky.app/Contents/MacOS/discky-mcp"

  zap trash: [
    "~/Library/Application Support/Discky",
    "~/Library/Saved Application State/com.alxgol.discky.savedState",
  ]

  caveats <<~EOS
    Discky is not notarized (no paid Apple developer account). Install with
    --no-quarantine, or allow it once in System Settings → Privacy & Security.
    Grant Full Disk Access on first launch so the scan can see all of ~/Library.
    Connect the MCP server to Claude Code with:
      claude mcp add discky -- #{HOMEBREW_PREFIX}/bin/discky-mcp
  EOS
end
```

- [ ] **Step 2: Renderer** `render-cask.sh`: `set -euo pipefail`, `sed -e "s/@VERSION@/$1/" -e "s/@SHA256@/$2/"` over the template next to the script, the two exit codes above.
- [ ] **Step 3: Verify locally**

```sh
packaging/homebrew/render-cask.sh 0.1.0 0000000000000000000000000000000000000000000000000000000000000000 > ${TMPDIR:-/tmp}/discky-cask-check.rb
brew style --cask ${TMPDIR:-/tmp}/discky-cask-check.rb && echo style-ok
packaging/homebrew/render-cask.sh 0.1.0; echo "exit=$?"   # 2
rm ${TMPDIR:-/tmp}/discky-cask-check.rb
```

- [ ] **Step 4: CI steps** after the bundle checks: render with the dummy sha into `${{ runner.temp }}/discky.rb` and run `brew style --cask` on it.
- [ ] **Step 5: `git rm packaging/homebrew/discky-mcp.rb`**; CONTRIBUTING's CI paragraph gains "and `brew style` on the rendered cask".
- [ ] **Step 6: Commit** `feat(packaging): Homebrew cask template for the tap; drop the formula stub`

---

### Task 5: Release workflow

**Files:**
- Create: `.github/workflows/release.yml`, `docs/release.md`
- Modify: `CONTRIBUTING.md` (new "Releasing" section pointing at `docs/release.md`).

**Interfaces:**
- Consumes: `cargo xtask version`, `cargo xtask bundle` with `DISCKY_SIGN_IDENTITY`, `packaging/homebrew/render-cask.sh`.
- Produces: release `v<version>` with assets `Discky-<version>.zip`, `Discky-<version>.zip.sha256`, `discky.rb`; on `workflow_dispatch` the same files as workflow artifacts and no release.

- [ ] **Step 1: Workflow** `release.yml`, one job on `macos-15`, `permissions: contents: write`, triggers `push: tags: ['v*']` and `workflow_dispatch`:
  1. checkout, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`.
  2. **Version guard**: `VERSION=$(cargo xtask version)`; on a tag, `test "v$VERSION" = "$GITHUB_REF_NAME"` or fail with "tag … does not match crates/discky-app/Cargo.toml version …".
  3. **Signing identity**: env `P12: ${{ secrets.MACOS_SIGN_P12 }}`, `P12_PASSWORD: ${{ secrets.MACOS_SIGN_P12_PASSWORD }}`. If `P12` is non-empty: decode to `$RUNNER_TEMP/sign.p12`, `security create-keychain -p "" build.keychain`, `security set-keychain-settings -lut 3600 build.keychain`, `security unlock-keychain -p "" build.keychain`, `security import … -k build.keychain -P "$P12_PASSWORD" -T /usr/bin/codesign`, `security set-key-partition-list -S apple-tool:,apple: -s -k "" build.keychain`, `security list-keychains -d user -s build.keychain login.keychain`, then `DISCKY_SIGN_IDENTITY=$(security find-identity -v -p codesigning build.keychain | awk 'NR==1{print $2}')` into `$GITHUB_ENV`. Else `DISCKY_SIGN_IDENTITY=-` and a `::warning::` that the build is ad-hoc signed (Full Disk Access must be granted again after each update).
  4. `cargo xtask bundle`; `codesign --verify --deep --strict target/Discky.app`.
  5. `ditto -c -k --keepParent target/Discky.app "Discky-$VERSION.zip"`; `shasum -a 256 "Discky-$VERSION.zip" | tee "Discky-$VERSION.zip.sha256"`; `SHA=$(cut -d' ' -f1 "Discky-$VERSION.zip.sha256")`; `packaging/homebrew/render-cask.sh "$VERSION" "$SHA" > discky.rb`; `brew style --cask discky.rb`.
  6. On a tag: `gh release create "$GITHUB_REF_NAME" --verify-tag --title "Discky $VERSION" --generate-notes "Discky-$VERSION.zip" "Discky-$VERSION.zip.sha256" discky.rb` (`GH_TOKEN: ${{ github.token }}`). On dispatch: `actions/upload-artifact@v4` with the three files.
  7. **Tap update**, tag only, env `TAP_TOKEN: ${{ secrets.TAP_TOKEN }}`, step `if: env.TAP_TOKEN != ''`: `git clone https://x-access-token:$TAP_TOKEN@github.com/AlxGolubev/homebrew-discky "$RUNNER_TEMP/tap"`, copy `discky.rb` to `Casks/discky.rb`, commit `discky <version>` as `github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>`, push. Without the token the job summary says: "Copy discky.rb from the release to AlxGolubev/homebrew-discky/Casks/discky.rb".
  8. Always: delete `build.keychain` when it was created (`if: always()`).
- [ ] **Step 2: `docs/release.md`**: bump `version` in `crates/discky-core`, `discky-mcp`, `discky-app`, `xtask` manifests and `Cargo.lock` (`cargo update -w`), commit `chore: release 0.1.1`, `git tag v0.1.1`, `git push origin main v0.1.1`; what the workflow produces; the three optional secrets (`MACOS_SIGN_P12` = `base64 -i cert.p12` of the Apple Development certificate exported from Keychain Access with its private key, `MACOS_SIGN_P12_PASSWORD`, `TAP_TOKEN` = fine-grained PAT with contents write on `homebrew-discky`); the manual tap update; why ad-hoc builds lose Full Disk Access on update and Apple Development builds keep it (the designated requirement is the Team ID, which survives certificate renewal).
- [ ] **Step 3: Verify**: `actionlint .github/workflows/release.yml` if `actionlint` is installed (`brew list actionlint` to check; do not install), otherwise `ruby -ryaml -e 'YAML.load_file(".github/workflows/release.yml")'`; `bash -n` on every inline script extracted to a scratch file. A real run happens only after the owner pushes a tag.
- [ ] **Step 4: Commit** `ci: release workflow builds the bundle, publishes the zip, sha256 and cask`

---

### Task 6: README, CONTRIBUTING, spec amendment

**Files:**
- Modify: `README.md` (Install section lines 41-76; "Connect to your agent" line 115; "Prompts, quitting and upgrading"), `CONTRIBUTING.md` (Debug variables: `DISCKY_FDA`; Releasing link), `docs/superpowers/specs/2026-11-02-discky-design.md` §13 (a "Поправка 2026-11-04" paragraph in the spec's language), `crates/discky-app/src/settings/mcp.rs:27` copy.

- [ ] **Step 1: README Install** becomes:
  - **Homebrew** (first): 
    ```sh
    brew install --cask --no-quarantine AlxGolubev/discky/discky
    ```
    One sentence each: installs `/Applications/Discky.app` and symlinks `discky-mcp` into Homebrew's `bin`; `--no-quarantine` because the app is not notarized (no paid Apple account) and macOS would otherwise refuse to open it until allowed in Privacy & Security; upgrade with `brew upgrade --cask discky`; builds are ad-hoc signed until the release workflow has a certificate, so macOS asks for Full Disk Access again after an update (one line, honest).
  - **From source**: the existing `cargo xtask install` text, plus "`discky-mcp` is inside the bundle at `/Applications/Discky.app/Contents/MacOS/discky-mcp`; Settings → MCP shows the exact `claude mcp add` line. For the server alone: `cargo install --path crates/discky-mcp`."
  - **Full Disk Access**: "The first launch asks for it on the Overview and opens the right System Settings pane; after granting, press Relaunch Discky." Keep the manual path sentence.
  - Remove "A Homebrew cask is coming…" and the formula-stub paragraph; keep "Build `discky-mcp` and Discky.app from the same version…" (now automatic with the cask).
- [ ] **Step 2: "Connect to your agent"**: the Homebrew path sentence now reads "the cask's symlink (`/opt/homebrew/bin/discky-mcp`, `/usr/local/bin` on Intel)".
- [ ] **Step 3: Settings → MCP** "not found" copy: `not found · brew install --cask AlxGolubev/discky/discky or cargo install --path crates/discky-mcp`.
- [ ] **Step 4: Spec §13 amendment** (Russian, 4-6 lines): tap `AlxGolubev/homebrew-discky`, cask `app` + `binary` from inside the bundle, no notarization and `--no-quarantine` in the install line, release signing with the imported Apple Development certificate (ad-hoc fallback with the documented cost), onboarding on the Overview as §3's "shows status in Settings" extension.
- [ ] **Step 5: Verify**: links resolve (`grep -o '\](\([^)]*\))' README.md` paths exist), no old slug, no "coming soon"/"coming once". `cargo test --workspace` green.
- [ ] **Step 6: Commit** `docs: install with one Homebrew command; onboarding and release notes`

---

## Owner steps (outside the plan)

1. Create the GitHub repositories `AlxGolubev/discky` and `AlxGolubev/homebrew-discky` (the tap: empty, a `Casks/` folder arrives with the first release).
2. Optional secrets on `discky`: `MACOS_SIGN_P12` + `MACOS_SIGN_P12_PASSWORD` (export your Apple Development certificate with its private key from Keychain Access as .p12), `TAP_TOKEN`.
3. Push `main`, wait for CI, push `v0.1.0`; if `TAP_TOKEN` is absent, copy `discky.rb` from the release into the tap.
4. Live checklist: the onboarding card on a scratch home, the relaunch card after a real grant, the banner after a scan without access, `brew install --cask --no-quarantine AlxGolubev/discky/discky` on this Mac after the first release.
