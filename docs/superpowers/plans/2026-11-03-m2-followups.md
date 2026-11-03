# Milestone 2 follow-ups (carried into Milestone 3 planning)

Collected from the per-task reviews, the whole-branch review and the fix-wave re-review of `m2/gui` (2026-11-03). Nothing here blocks M2; each item was reviewer-verified and left open on purpose.

## Owner checks before relying on the app

Subagents could not press keys or click (owner rule: automated runs never steal focus), so these were verified by reading the code only:

- **Scan:** ⌘R on the real home; the duck scene appears ~1.5 s in without flicker, enters from the left, faces left walking out and right walking back, stack sizes vary, a drag trip with a rope appears for `~/Library`, the lid closes and the number appears; Cancel works; a tiny root shows no scene; Reduce motion takes effect after a relaunch only.
- **Overview:** "N more →" and card rows open the category; the "N folders could not be read · Settings → Disk access" link; the "Snapshot updated by discky-mcp" banner + Reload while `discky-mcp --self-test-scan` runs.
- **Category table:** checkbox → bottom bar; DoNotTouch checkbox inert; Size/Age/Name tabs; ⌘F filter, Escape; space/backspace keys; "Show in Finder"; "(M hidden by filter)"; checked rows survive a rescan.
- **Inspector:** row click opens it, same row again does not reset it; Esc/close; metadata, contents, "What will run" incl. the Finder/sudo routes for admin-owned items.
- **Removal dialog (on a scratch `DISCKY_HOME` + `DISCKY_TRASH_BIN` fixture, never on real data first):** Run → live statuses → toast; Stale → Re-plan; expired plan → Re-plan; Empty Trash confirmation; ⌘Q / window close / ⌘R refused with a toast while running; permanent-mode strip.
- **Settings:** section list left-aligned; Trash/Permanent flips `config.toml` and the bottom-bar text; roots add/remove (last disabled); exclude add + invalid-glob toast; thresholds Enter/Blur + error text; Copy snippet; FDA status matches reality; links; Reveal log; failed save (read-only `config.toml`) reverts the control.
- **Bundle:** `cargo xtask install`, the Dock icon, and the three Apple-Event routes on the **signed** bundle (Finder Trash for admin-owned items, Quit steps, Empty Trash) — macOS should show an Automation prompt once (`NSAppleEventsUsageDescription` is set).

## Known limitations (documented in README)

- Quitting from the Dock, logging out or restarting during a removal interrupts the running step; the log gets an "interrupted" record (gpui has no `applicationShouldTerminate:`; the `on_app_quit` window is ~200 ms, a very slow disk could lose the record). The README sentence saying ⌘Q "waits" is wrong: ⌘Q and window close are refused with a toast — fix the wording. **(done in M3: README wording fixed)**
- A format-1 `snapshot.bin` is ignored after upgrade (first launch shows "No scan yet"); the app and `discky-mcp` must come from the same milestone.
- Removed Ollama models (path-less findings) reappear after relaunch until the next scan; path findings are dropped on load (`drop_gone`), but `reload_snapshot` does not apply `drop_gone`. **(`drop_gone` in `reload_snapshot`: done in M3; path-less findings still reappear until the next scan)**

## Core

- `Config::save`: fixed tmp name (`config.toml.tmp`) can interleave between two processes → per-pid suffix; a dangling symlinked `config.toml` is replaced by a regular file; the atomic-save test has no failure-path assertion.
- Progress sinks are not wrapped in `catch_unwind` (a panicking sink fails the scan; the app's sink never panics).
- `reload_snapshot` misses a same-second rescan (`created_at` is whole seconds) and returns `Err` when the file vanishes between peek and load.
- `StepEvent` is emitted for Skipped/TOOL_MISSING steps too — document; panicking-sink test prints panic noise; no newline-in-path builder test; no engine-level `on_step` test.
- `drop_gone` runs on the main thread at startup (one `lstat` per path finding).
- An orphaned executor thread (dialog dropped mid-run) could set a stale "current step" for the interrupted-record logic (very unlikely).
- `/usr/bin/trash` literal duplicated in `discky-mcp/src/main.rs`; `paths::home_dir()` could replace the `HOME` reads in `config.rs`/`tools`.
- MCP: task→scan map can leak an entry; cancelling one task cancels a shared scan (document on `cancel`).

## App

- `app.rs` is ~930 lines: split `startup_error.rs` and the actions/menus; `AppView::new` depends on the `MainScan` global being set first; self-check prints ok even when the startup-error window opened; startup dialog title/Reset button wrong for non-Config `EngineError` (unreachable today).
- Overview: unscanned used space drawn like Free; stringly-typed bar segments; zero-byte "Other scanned" legend entry; `volume_name` reads `/Volumes` per build; "12 months ago" for 360–364 days; sidebar `CATEGORIES` duplicates the core order (export the const).
- Scan: watcher clones the full meta every 2 s; actor name duplicated; menu Rescan enabled during a scan (harmless no-op); no thousands separator in "Scanning… N files"; redundant stale hint + scanned line; no async tests; a removal can be opened while a scan runs (safe via the `ptr_eq` guard, but not refused).
- Duck: `paint_sprite` allocates via `rasterize(…, 1)` per paint and the LOGO is re-rasterised per repaint; the Overview re-renders every animation frame; ground line/shadow not device-snapped; the scene freezes while the Overview is off-route; the finish-timing test is not at the documented worst case; first visible state is WalkBack (duck enters carrying); untested FSM paths (big_bytes, key-change reset, finish in Throw/Shove, progress after finish).
- Category: view re-renders on every table notify (`Engine::config` clone + O(all) summary per render); `apply_filter` clones `Finding`s per keystroke; first-frame flex-width jump; Escape hides the filter only from inside the field; Where/Modified text computed twice; `hide_filter` applies the filter twice; `tracing` has no subscriber.
- Inspector: `refresh()` shows "Preparing…" over an existing plan; `navigate()` closes the inspector before the route changes and focuses the old table; previews churn `PLAN_HISTORY`; no per-id plan cache; 750-line file (command formatting could be a submodule); ~~displaced doc comment in `category/mod.rs` (`selection_text`)~~ **(done in M3)**.
- Removal dialog: Enter closes it via the kit's default `on_ok` (never runs the plan); failed-output height approximate; Stale button order; no dialog-glue tests; settings saves `fsync` on the main thread.
- Settings: invalid threshold text stays in the field after Blur; a failed save reloads both threshold fields; double probe when opening Disk access/Version manager via `open_settings`; `find_mcp_binary` runs once at startup and uses `exists()`; only the selected removal mode's description is shown; picker errors silently dropped; `mise_info` untested (extract the poll/timeout helper).
- ~~Plist Apple-Events text does not mention Empty Trash.~~ **(done in M3: also mentions quitting apps)**

## xtask / packaging

- `manifest_version` takes the first `version =` line anywhere in the manifest; an empty `DISCKY_SIGN_IDENTITY=` is accepted; `install` uses `ditto` onto an existing bundle (merges, does not replace); hard-coded `target/release` path; CI has never run (repo not public); `.icns` bytes are not CI-checked by design.

## Plan deviations worth a decision

- ~~Inspector component checkboxes (spec §11)~~ **(done in M3)**; per-item Dev-cache adapters remain open.
- Window-level Quit refusal is impossible through gpui-kit; the "interrupted" log record is the mitigation.
- Future GUI milestones should add "OS permission prompts (Info.plist keys, Apple Events)" and "every way the process can exit" to the plan's Review Focus.
