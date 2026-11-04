# Milestone 3 follow-ups (carried into Milestone 4 planning)

Collected from the per-task reviews, the whole-branch review, the fix wave and the targeted fix of `m3/uninstaller-mise` (2026-11-03). Nothing here blocks M3; every item is reviewer-verified and left open on purpose.

## Owner checks before relying on the uninstaller

Subagents could not click or press keys (owner rule), so verify once on real data, **on a scratch home with `DISCKY_TRASH_BIN` first**, then for real:

- **Applications table:** tabs "Not opened in 6 months (9) / All (47) / Leftovers (…)", sidebar "9", sources (cask · raycast / pkg / App Store / drag & drop), "Last opened" with `*` estimates, Total with the "app X + leftovers Y" line.
- **Language versions table:** widths, Status ("global" / "pinned in N projects" / "not referenced"), mono Where column.
- **Overview:** the Applications card "N not opened in 6 months".
- **Inspector:** components with checkboxes (Raycast: 13 components, 12 on by default, ~588 MB), "removed by brew zap" / "shown only" notes, the static "Keychain items" line, toggling updates the dimmed preview and the summary line, Remove… disabled when nothing is checked, "Refreshing…" after a rescan; a mise version with disabled "requested by …" rows.
- **Removal dialog:** rows "Raycast → Application Support", warnings ("Homebrew zap skipped: …", "Homebrew will also: …", "Package X also installed Y.app; receipt kept"), the vendor-uninstaller step appears only when you check its component, administrator password prompts for system-level steps (`pkgutil --forget`, `launchctl bootout system`, `/Library/*`), the plan stops at the first failed step.
- **Settings → Version manager:** "mise prune (dry run)" dialog, "Show installed versions".
- **MCP (Claude Code):** `inspect` shows components; `plan_removal` with `components` plans only the selected ones; steps needing an admin, a Quit or the vendor script are reported as "run them in Discky.app" and the finding's later steps are skipped with them.

## Known limitations (documented in README / spec)

- "Installed app" means a bundle Spotlight knows (one `mdfind` call) plus `/Applications`, `~/Applications`, `/System/Applications` and running apps; without Spotlight, leftover groups are shown with every checkbox off and a note (spec §8 amendment).
- Keychain items are never detected or touched (static note only).
- Cask `uninstall.script` directives are run by brew itself; Discky lists them in the brew step's warnings but does not run them separately.
- `brew uninstall --zap` is used only when the zap stanza was read from the installed caskfile and every existing zap path lies inside a checked component; otherwise brew runs without `--zap` and Discky trashes the checked leftovers itself.
- A vendor uninstaller script is opt-in, runs as the user without a terminal (a script that calls `sudo` fails instead of prompting) and is a gate: if it is skipped, the finding's later steps are skipped too.
- User-domain `launchctl bootout` steps are ordered before the vendor script, so under MCP they can run while the gated script and bundle are skipped (jobs unloaded, nothing deleted).

## Core

- Planner: "Nothing selected" when all selected paths are gone (should read "Already gone") (done in M4); lone-Quit plans; the brew step credits covered components whose path is gone; package-installed prefs plists are trashed instead of `defaults delete`; pkg files are not cross-checked against other receipts; one administrator prompt per admin step (batching wanted); `installed_zap` picks the newest timestamp across all version dirs; `defaults_target` `with_extension("")` on a dotted name without `.plist`; `plan/app.rs` ≈ 900 lines, duplicated `BREW_ENV` / launchctl target building / pkgutil budget closure; `too_many_arguments` allow.
- Leftovers: `is_loaded` without an overall budget (cache per label); `id_stem` duplicates `app_caches::owner_of`; rule-pass descendant overlap double-counts bytes in groups; "never opened*" wording; `sharing()` decides "owned" by length comparison (fail-safe); unrelated running-only ids mark jobs shared (fail-safe); `leftovers.rs` ≈ 880 lines (groups → `groups.rs`); `forget_removed` drops a path-less group when one step's paths are gone.
- Inventory: `installed_casks` fallback may take 3 × 5 s; no direct tests for `/System/Applications` and SF_RESTRICTED exclusion; detached reader thread on timeout; `read_caskroom` may show an older cached JSON (display only); per-bundle `read_dir` for sibling uninstallers.
- mise: `~/.tool-versions`, `~/.config/mise/conf.d/*`, `config.local.toml` count as "pinned", not global; `.tool-versions` fallback versions ignored; `.mise/config.toml` counts as its own project and bypasses the depth cap; XDG/symlinked home not recognised for Global; trailing period on the Global explain; two sequential 5 s commands worst case.
- Snapshot: a reload between the inspector's click-time check and the dialog's plan could re-map indices (the dialog shows the real steps; a parts signature in `PlanItem` would close it) (done in M4).

## MCP

- `skipped_interactive` lists only the gate step, not the steps it blocked (they are in `results` with the reason).
- `ComponentOut.removal` strings hand-typed; `ComponentOut.path` lossy `String` vs `FindingOut.path` `PathBuf`; `disk_overview` lacks `apps_unused`.
- e2e test ≈ 7 s, dominated by read-only host probes.

## App

- Apps tab switch drops the selection (treat the tab as a filter) (done in M4); `apps_filter` runs three times per toolbar render; the Applications card is hidden when 0 apps are unused even if leftovers exist; Default layout's Frees second line now truncates; `table.rs` ≈ 820 lines.
- Inspector: Remove… enabled when components exist but none is selectable (non-mise); summary sums `freed_if_deleted` while rows show `allocated`; same-id `set_finding` does not replan; no test of the `planned()` titles path; "Needs administrator password" shown on Quit steps in "What will run"; the brew "Homebrew will also: quit …" warning duplicates Discky's Quit step; `NOTE_RUN_SCRIPT` does not raise the safety label.
- Settings: literal backticks in the prune help text; prune output wraps instead of scrolling.
- Dev override hint says "run from Discky.app" inside Discky.app.

## Docs / tests

- README "cancelling it stops the removal at that step" is consistent with the osascript failure path but unverified live; the spec amendment says "LaunchServices/Spotlight" while the code asks Spotlight plus a folder walk.
- Stale test name `own_uninstaller_script_is_interactive_and_selectable` (the step is `gui_only`, not interactive).
- Review-Focus lesson for future plans: list "every way an agent can run a step the GUI hides" and "every root-privileged argv source" as explicit items.
