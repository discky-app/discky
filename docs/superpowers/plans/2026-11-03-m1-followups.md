# Milestone 1 follow-ups (carried into Milestone 2 planning)

Collected from the per-task and whole-branch reviews of `m1/core-and-mcp` (2026-11-02/03). Nothing here blocks M1; each item is a known gap with a reviewer-verified description.

## Must land with the GUI (M2 blockers)

- **Core API for the app:** `Engine::open_with(EngineOptions { paths, trash_bin, home, actor })` instead of `DISCKY_HOME` / `DISCKY_TRASH_BIN` / `HOME` / `OLLAMA_HOST` env reads; `Engine::execute(&PlanId, …)` instead of `execute(&Plan)` so only server-side plans can run; progress subscription (callback/channel) instead of polling; scan cancellation; per-step callback during `execute` for the live status sheet; reload when the snapshot file changes (spec §12b).
- **Interactive steps are unimplemented:** with `allow_interactive = true`, root-owned paths still go to `/usr/bin/trash` or `remove_dir_all`. The Finder/osascript admin route (spec §7) and `launchctl bootout` / `defaults delete` steps arrive with the uninstaller (M3) but the executor hooks belong to M2.
- **`Config::save` is not atomic** (`fs::write`); switch to tmp + rename before the GUI writes settings.
- **Non-UTF-8 paths policy:** keep `PathBuf` in core; serialize through one lossy helper at every serde boundary (`Finding.path`, `TreeEntry.path`, `Progress.current`, `Plan::to_json`, `HistoryRecord`, `SnapshotMeta.roots/no_access`); `plan_removal` skips non-UTF-8 paths with "remove it from Discky.app"; replace the `json!`/unwrap in `Plan::to_json`.
- **Nested user rule hides a builtin `DoNotTouch`** (rule pass: highest match wins). Needed before user rules are exposed.
- **Record `exact_private_size` in `SnapshotMeta`** while the format is unreleased (bump `SNAPSHOT_FORMAT` to 2).

## Honesty / safety polish

- Command-step measurement walks the target subtree before and after (hard links and clones counted per entry, no device check, outside the 10-minute timeout); consider the index-based size and a device guard.
- Partially absent multi-path Trash steps credit the full planned `freed`.
- "Already absent" Trash steps still record `trash_paths`; `in_trash` matches by basename only (best effort).
- Ollama shared blobs land in the "Other data in Ollama" residual row (documented approximation).
- `rustup-toolchains` / `gem-cache` are `app_data` now; review other labels when adding rules.
- Only `com.apple.TimeMachine*` snapshots switch on exact PRIVATESIZE mode; other APFS snapshot vendors (CCC) do not.
- A scan root that is an ancestor of home (e.g. `/`) yields no large/old or build findings (home guard is root-based).
- Concurrent `execute` calls are not serialized; a scan racing an `execute` can resurrect deleted findings until the next scan.
- Timeout kills only the direct child process (no process group).

## Scanner / index

- Roots are not checked against `exclude` / `SKIP_DIRS`; `set_no_materialize` failure is silent; narrowing casts lack `debug_assert`s; no tests for mount-point skip, dataless, `max_mtime`, `agg_private`.
- Memory: 1.24 GiB RSS on 4.85 M nodes (≈274 B/node); target was 1 GiB at 4 M. Candidates: smaller `Node`, name interning, dropping `agg_logical`.
- Throughput: 142 k files/s; the critical path is one 282 k-entry directory. Spec target 150 k.

## MCP

- `history` reads the whole log on the async thread and its `limit` is uncapped; `tail()` fails on an invalid UTF-8 line.
- `expand_tilde` duplicated in three places; not applied to `search.under`.
- `scan` with explicit roots while a scan runs silently returns the running id.
- `ObjKind` serializes PascalCase while every other enum is snake_case; schemars `uint64` format warnings on Claude Code's stderr.
- No automated test for progress notifications or for every tool publishing an `outputSchema`; `tasks/cancel` does not stop the scan (needs engine cancel).
- `DISCKY_TRASH_BIN` honoured in release binaries (startup warning exists).

## Tests / repo hygiene

- `tests/plan.rs` leaves `discky-plan-*` dirs in the system temp dir.
- `second_start_while_running_returns_same_id` is timing-dependent.
- HF planner test asserts `TOOL_MISSING` only when `hf` is absent.
- README: throughput causal claim unsupported; tool descriptions paraphrased; `exact_private_size` `null` case; Intel Homebrew path.
- CI and the Homebrew formula have never run (repo not public; `OWNER/discky` placeholders, TODO sha256).

## Plan deviations worth a decision

- `findings` has no `sort`/`cursor` and `search` has no category filter (spec §12 lists them; the plan dropped them).
- Dev caches are one finding per cache (per-item adapters deferred, spec §6).
