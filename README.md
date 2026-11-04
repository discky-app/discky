<p align="center"><img src="assets/logo.png" width="160" alt="Discky, a pixel robo-duck"></p>

<h1 align="center">Discky</h1>

<p align="center">Find what is eating your Mac's disk and clear it safely, by hand or through an AI agent.</p>

<p align="center">
  <a href="https://github.com/AlxGolubev/discky/stargazers"><img src="https://img.shields.io/github/stars/AlxGolubev/discky?style=flat&logo=github" alt="GitHub stars"></a>
  <a href="https://github.com/AlxGolubev/discky/actions/workflows/ci.yml"><img src="https://github.com/AlxGolubev/discky/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/macOS-15%2B-lightgrey?logo=apple" alt="macOS 15+">
  <img src="https://img.shields.io/badge/Rust-1.99-orange?logo=rust" alt="Rust 1.99">
</p>

<p align="center"><img src="assets/scan.gif" width="480" alt="While a scan runs, the robo-duck carries paper stacks and drags a crate into the bin"></p>

Discky is three parts: a Rust scanner and rule engine that says what each big thing on your disk is and whether it is safe to remove, a desktop app (`Discky.app`), and an MCP server (`discky-mcp`) so an AI agent can do the same work in a chat.

## Why Discky

A Mac fills up with things nobody remembers creating: package-manager caches, downloaded AI models, Xcode data, `node_modules` and `target` folders in old projects, files left behind by apps you deleted, VM disk images. Most disk tools show sizes that do not add up: a sparse disk image is reported at its claimed size, cloned and hard-linked files are counted twice, and iCloud files that live only in the cloud (dataless) are shown as if they took space.

What Discky does differently:

- **Honest bytes.** Every size is bytes allocated on disk. Discky tracks the claimed (logical) size separately, flags sparse files, and knows which blocks are shared by APFS clones and hard links, so "frees if deleted" is what removing an item really frees. Dataless iCloud files count as zero on disk.
- **Explained findings.** Each finding comes from a rule with a category, a safety label (`regenerates`, `app_data`, `do_not_touch`, …) and a plain-language explanation.
- **Official removal only.** Where a tool owns the data, Discky runs that tool: `cargo cache --autoclean`, `npm cache clean --force`, `brew cleanup`, `brew uninstall --cask`, `mise uninstall`, Ollama's own delete API, `hf cache rm`, `docker system prune`, and so on. Everything else goes to the Trash (or is deleted, if you choose). A failed tool command or app bundle removal skips that item's remaining steps (there is no fallback to `rm`); a failed Trash of a leftover file and every other item still run, and each failure is listed with its reason.
- **Agent-ready.** `discky-mcp` exposes the scanner, findings, planner and executor as ten MCP tools. Deletion by an agent is off until you turn it on.
- **Local only, no telemetry.** Discky itself sends nothing. Its only network calls are to your Ollama server (`OLLAMA_HOST`, local by default) to list and delete models; tools it runs on your behalf (`brew`, `docker`, `hf`…) may use the network as they normally do.

## What it finds

| Category | What is in it |
| --- | --- |
| Applications | Installed apps (Homebrew casks, App Store, installer packages, dragged-in bundles) with their last use and the files they left in `~/Library` and `/Library`, plus leftovers of apps that are already gone. |
| App caches | App caches and update downloads (Slack, VS Code, Google Drive, Claude Desktop VM images), plus app data that is shown but never removed (Chrome profile, Keychains, Mail, Messages, Photos, iCloud Drive, cloud storage). |
| Models | AI models from Ollama, the Hugging Face hub, LM Studio, oMLX and MacWhisper. |
| Dev caches | Package and build caches: Cargo, npm, pnpm, Yarn, pip, uv, Go, CocoaPods, SwiftPM, Gradle, Homebrew, Xcode, iOS Simulator, Docker and OrbStack disk images, and more. |
| Project builds | Rebuildable folders inside projects: Rust `target`, `node_modules`, Python virtual environments, Next.js, Gradle and `dist` output. |
| Language versions | Tool versions installed by mise, with which ones are global or used by a project. |
| Large & old | What no other rule claimed in your home folder (outside `~/Library`): files over 500 MB, folders not changed for a year (both configurable), and everything in `~/Downloads`. |

## Install

Discky needs Apple Silicon, macOS 15 or newer (APFS). Building from source needs the Rust toolchain; `rust-toolchain.toml` pins Rust 1.99, and `rustup` picks it up on its own.

### Homebrew

```sh
brew install --cask AlxGolubev/discky/discky
```

This installs `/Applications/Discky.app` and symlinks `discky-mcp` into Homebrew's `bin`. The app is not notarized (there is no paid Apple account), so the cask removes the macOS quarantine attribute from it after installing; for a copy installed another way, run `xattr -dr com.apple.quarantine /Applications/Discky.app` or allow it once in System Settings → Privacy & Security → Open Anyway. Upgrade with `brew upgrade --cask discky`. Builds are ad-hoc signed until the release workflow has a certificate, so macOS asks for Full Disk Access again after an update.

### From source

```sh
git clone https://github.com/AlxGolubev/discky
cd discky
cargo xtask install
```

This builds a release `target/Discky.app`, signs it and copies it to `/Applications/Discky.app`. `cargo xtask bundle` stops after signing; `cargo xtask icon` regenerates `assets/AppIcon.icns` and `assets/logo.png` from the pixel logo.

`discky-mcp` is inside the bundle at `/Applications/Discky.app/Contents/MacOS/discky-mcp`; Settings → MCP shows the exact `claude mcp add` line. For the server alone: `cargo install --path crates/discky-mcp`.

Signing needs a stable identity, so that Full Disk Access survives rebuilds (macOS ties the grant to the signature). `xtask` picks the first `Apple Development` or `Developer ID Application` identity in your keychain; set `DISCKY_SIGN_IDENTITY="<name or SHA-1>"` to choose another. Without one it stops and explains how to create a self-signed Code Signing certificate in Keychain Access. `DISCKY_SIGN_IDENTITY=-` signs ad-hoc: fine for a quick try, but Full Disk Access has to be granted again after every rebuild.

### Full Disk Access

Without it macOS hides parts of `~/Library` (Mail, Safari, other apps' containers) from the scan. The first launch asks for it on the Overview and opens the right System Settings pane; after granting, press Relaunch Discky. To do it by hand: System Settings → Privacy & Security → Full Disk Access (add Discky with `+`), then rescan.

Build `discky-mcp` and Discky.app from the same version (the cask does this for you). They share the snapshot file, and each ignores a snapshot in another format.

## Use the app

**Overview** shows the volume, how much each category takes and how much is safe to free. **Scan now** (⌘R) rescans the configured roots.

**Categories.** Each of the seven categories in the sidebar lists its findings, largest first. Select a row to open the **inspector**: what the thing is, its sizes, the rule that matched and, before you remove anything, the exact steps the removal would run. Check rows (Space) and press Remove (⌫) to open the **removal dialog**, which lists every step and how much it frees; nothing runs until you press Run. Settings (⌘,) → Removal chooses between moving to the Trash (the default) and deleting permanently, and whether to remind you to empty the Trash.

**Applications and Language versions.** The inspector shows each removable part of an app (bundle, caches, settings, launch agents, package receipts…) as a checkbox: uncheck a leftover to keep it. An app is removed only through official mechanisms: its vendor's uninstaller script first when it ships one and you check it (it runs as you from the app, never with administrator rights, and may ask for a password itself), then `brew uninstall --cask` (with `--zap` only when every path the cask's zap stanza removes is listed and checked), the installer package's file list, or the Trash; a language version through `mise uninstall`. Keychain items are never touched. mise is the only version manager supported today.

### Disk map

**Disk map** in the sidebar draws the last scan as a treemap: each tile is a folder or file, sized by its bytes.

- **Colour:** *Category* (the finding the tile belongs to, grey when none), *Age* (time since the newest change inside: under a month, six months, a year, two years, older, unknown) or *Files* (how many files it holds).
- **Weight:** *On disk* (allocated bytes; dataless iCloud files weigh nothing) or *Claimed* (logical size; dataless files appear as dashed tiles labelled "in the cloud", but the folder total above the map leaves them out). Hard-link duplicates count once. Sparse files get a warning border and "· sparse".
- **Depth:** 1 to 4 levels of nested tiles (default 3); ⌘] adds a level, ⌘[ removes one. Small items are merged into one "N more" tile.
- **Navigate:** hover for a tooltip (on disk, claimed, files, modified, category, flags); double-click a folder to open it; ⌘↑ or the breadcrumbs to go back up.
- **Click** a tile to open it in the inspector. A tile that is a finding opens that finding. Any other path shows its sizes, **Show in Finder**, **Show in {category}** when a finding owns it, and **Move to Trash…**. Paths removed from the map always go to the Trash, even with **Delete permanently** chosen in Settings: permanent deletion is only for what a rule found. A path that needs an administrator is moved to the Trash by Finder. A removed tile disappears from the map until the next scan, and the findings inside it leave their categories.

The map refuses to remove, and says why:

- a scan root;
- an iCloud file that is only in the cloud;
- a protected location: `~/Library` itself, anything in `~/Library/Keychains`, `~/Library/Mobile Documents`, `~/Library/CloudStorage` or `~/Library/Preferences`, `/Library/Keychains`, `/System`, or a folder that contains one of these;
- anything inside, or containing, a finding that Discky removes another way (an official command, an uninstaller, including an app's leftovers such as its LaunchAgents) → "Managed by Dev caches; remove it from there". Use **Show in {category}** to remove it the proper way;
- anything inside or containing something Discky never removes (do-not-touch app data, the global mise version) → "Discky never removes {title}" (or "Contains {title}, which Discky never removes").

### Prompts, quitting and upgrading

**Automation prompt.** Some removals go through Apple Events: Finder moves admin-owned items to the Trash, apps are asked to quit before their files are removed, and Empty Trash asks Finder. The first time, macOS asks whether Discky may control Finder (or that app); allow it, or those steps fail. The choice can be changed in System Settings → Privacy & Security → Automation. System-level steps such as `pkgutil --forget` and `launchctl bootout system` show an administrator password prompt instead; cancelling it fails that step; the item's remaining steps are skipped and the other items still run.

**Quitting during a removal.** ⌘Q and closing the window are refused with a notification while a removal runs; quitting from the Dock or logging out interrupts the running step and the log records it (`"kind": "interrupted"`). The next scan shows what is left.

**Upgrading.** When the snapshot format changes (it is format 3 now), an older `snapshot.bin` is ignored, so the first launch shows "No scan yet" until you rescan.

## For agents (MCP)

### Connect to your agent

`discky-mcp` speaks MCP over stdio. Use the cask's symlink (`/opt/homebrew/bin/discky-mcp`), the copy inside the app (`/Applications/Discky.app/Contents/MacOS/discky-mcp`) or the `cargo install` path (`~/.cargo/bin/discky-mcp`; some clients need it written out absolutely).

The easiest way: open Discky, go to Settings (⌘,) → MCP, pick your client in the tabs and copy the snippet. It is built for the `discky-mcp` the app found on this Mac (inside its own bundle first, then Homebrew, then `~/.cargo/bin`), so the path is always right.

**Claude Code**

```sh
claude mcp add discky -- /opt/homebrew/bin/discky-mcp
# or, without Homebrew:
claude mcp add discky -- /Applications/Discky.app/Contents/MacOS/discky-mcp
# or, after cargo install:
claude mcp add discky -- ~/.cargo/bin/discky-mcp
```

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "discky": {
      "command": "/opt/homebrew/bin/discky-mcp"
    }
  }
}
```

**Codex** (`~/.codex/config.toml`)

```toml
[mcp_servers.discky]
command = "/opt/homebrew/bin/discky-mcp"
```

**Cursor** (`.cursor/mcp.json`, or `~/.cursor/mcp.json` for all projects)

```json
{
  "mcpServers": {
    "discky": {
      "command": "/opt/homebrew/bin/discky-mcp"
    }
  }
}
```

Applications and Language versions findings list their removable parts as `components` (see `inspect`); an agent can pass `components` to `plan_removal` to remove only some of them, and steps that need an administrator or quit an app are skipped for agents (run them in Discky.app).

Optional flags: `--home <dir>` (sets `DISCKY_HOME`) and `--log-level <filter>` (stderr logs, default `warn`).

### Tools

| Tool | What it does | Side effects |
| --- | --- | --- |
| `disk_overview` | Disk usage summary from the last scan: volume size and free space, bytes per category, bytes safe to free, and whether the snapshot is stale. Call this first. | None |
| `scan` | Starts a scan of the configured roots (or `roots`) in the background and returns its id; with `wait_seconds` it waits for the result. | Reads the disk only, never removes anything |
| `scan_status` | Status of a scan started with `scan`: running (with progress), done, failed, cancelled or unknown. | None |
| `findings` | Removable things found by the last scan, largest first, with size, safety label and removal method; filter by category, label, size or age. | None |
| `tree` | The largest children of a directory in the last snapshot, with allocated and freed-if-deleted bytes. | None |
| `search` | Search the last snapshot for files and directories by name glob, size, age, kind or parent path, largest first. | None |
| `inspect` | Everything known about a finding id, an absolute path or an app name: the finding, its rule explanation, size and largest children. | None |
| `plan_removal` | Plans the removal of the given findings (optionally only chosen `components` of an app or language version) and returns the ordered steps and the bytes they free. | Removes nothing |
| `execute_plan` | Runs a plan from `plan_removal` (moving items to the Trash or deleting them, per the user's settings). Refused unless the user enabled agent deletion in Discky settings; steps needing an admin prompt are skipped. | **Deletes files** |
| `history` | Removals Discky has run, newest first, and the items it moved to the Trash that are still there. | None |

### A typical conversation

1. `disk_overview` to see whether the snapshot is stale; if it is, `scan` with `wait_seconds` (at most 60), then `scan_status` until it is done.
2. `findings`, for example `label: "regenerates"` and `min_bytes` to list what is safe and big.
3. `inspect` a finding to explain it to you and list its components.
4. `plan_removal` with the ids you agreed on. The agent shows you the steps and the bytes they free.
5. `execute_plan` with the plan id, only after you say yes, and only if you set `allow_agent_delete = true` (see [Safety model](#safety-model)).

Under MCP, steps that need an administrator password or quit a running app are skipped and reported; run them from Discky.app. Removing arbitrary paths (the disk map) is only in the app; agents remove findings.

## Automate a nightly report

A scheduled agent can tell you every morning what could be cleaned, without cleaning anything. It has to run on your Mac: a cloud routine cannot see your disk.

[`docs/automation/`](docs/automation/nightly-report.md) has a worked example: a `launchd` agent runs [`nightly-report.sh`](docs/automation/nightly-report.sh) at 09:00. The script runs `claude -p` with every built-in tool off (`--tools ""`), `--mcp-config` pointing at `discky-mcp` and an allow-list of only `mcp__discky__scan`, `mcp__discky__scan_status`, `mcp__discky__disk_overview` and `mcp__discky__findings`. It asks Claude to scan, then report the five largest safe-to-remove findings over 1 GB, ending with a `SUMMARY:` line that the script itself posts as a macOS notification titled "Discky". Nothing in it can plan or execute a removal: the report says what *can* be cleaned, and you decide in the app or in a chat. The job keeps its own snapshot (`discky-mcp --home ~/Library/Application Support/Discky/nightly`), because it runs without Discky.app's Full Disk Access and must not replace the app's fuller scan. For Slack instead of a notification, replace the script's `osascript` call with a `curl` to a Slack incoming webhook.

## Safety model

- **Plan, then execute.** The agent must call `plan_removal`, show the plan to you, and only then call `execute_plan`. A plan whose removal mode changed since it was made is refused.
- **Deletion is off by default.** `execute_plan` is refused until you set `allow_agent_delete = true` in `config.toml`:

  ```toml
  [mcp]
  allow_agent_delete = true
  ```

  The config is re-read on every call, so no restart is needed.
- **Trash by default.** `removal.mode` is `"trash"` unless you set `"permanent"`. Permanent deletion applies only to what a rule found: a path removed from the disk map always goes to the Trash.
- **Interactive steps are never run by the agent.** Steps that need an admin prompt are skipped.
- **Official tools, no `rm` fallback.** Where a tool owns the data (for example `cargo cache --autoclean`), the rule runs that tool. If it is not installed, the step reports an install hint instead of falling back to `rm`.
- **Honest sizes.** Every size is bytes allocated on disk. `freed_if_deleted` is what removing the item really frees; clones and hard links shared with files that stay are not counted. `disk_overview` reports `exact_private_size`: `true` when `freed_if_deleted` was measured exactly, `false` when it is clone-aware only; it is recorded in the snapshot, so it is `null` only before the first scan.
- Paths labelled `do_not_touch` (Keychains, Mail, Messages, ...) are listed so you know they were seen, but have no removal method and are never removed, not even with the folder around them from the disk map.

## Files

| What | Default path |
| --- | --- |
| Config | `~/Library/Application Support/Discky/config.toml` |
| Snapshot | `~/Library/Application Support/Discky/snapshot.bin` |
| Removal log | `~/Library/Logs/Discky/removals.log` |

Set `DISCKY_HOME=<dir>` (or pass `--home <dir>`) to keep all three directly inside `<dir>` instead.

Config keys and defaults (all optional; a missing file means defaults):

```toml
[scan]
roots = ["~", "/Applications", "/Library", "/usr/local", "/opt/homebrew"]
exclude = []

[removal]
mode = "trash"        # or "permanent"
remind_trash = true

[thresholds]
large_file_bytes = 524288000
old_days = 365

[mcp]
allow_agent_delete = false
```

## How rules work

Most findings come from declarative rules in [`crates/discky-core/src/rules/builtin.toml`](crates/discky-core/src/rules/builtin.toml). Each rule has a category (`dev_caches`, `models`, `project_builds`, `app_caches`), a safety label (`regenerates`, `app_data`, `do_not_touch`), a plain-language explanation, a matcher (`path`, `glob` or `build_dir`) and, optionally, the official command that removes it:

```toml
[[rule]]
id = "cargo-registry"
category = "dev_caches"
label = "regenerates"
title = "Cargo registry"
explain = "Downloaded crate sources and archives. Cargo re-downloads them on demand."
[rule.matcher]
kind = "path"
path = "~/.cargo/registry"
[rule.command]
tool = "cargo-cache"
argv = ["cargo", "cache", "--autoclean"]
install_hint = "cargo install cargo-cache"
```

To propose a rule, open an issue with the path, what creates it, and how it is regenerated.

## Performance

Measured on 2026-11-03 on an Apple Silicon Mac, macOS 26.2, APFS, release build, scanning the default roots (`~`, `/Applications`, `/Library`, `/usr/local`, `/opt/homebrew`) with no config.

| Measurement | Result |
| --- | --- |
| `discky-mcp --self-test-scan` | 4,846,442 nodes in 34.1 s = 142,216 nodes/s |
| Peak memory, same run (`/usr/bin/time -l` max resident set size) | 1,326,170,112 bytes (about 1.24 GiB) |
| `home_scan_throughput` (`~` only) | 4,327,492 nodes in 30.7 s = 140,732 files/s |

Memory is above the 1 GiB target: a full scan of about 4.8M nodes peaks at roughly 1.24 GiB resident. Throughput is bound by a few very large directories, not by CPU (most of the time is system time in the kernel).

## Contributing

Bug reports, new rules and pull requests are welcome. Before a PR, run `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace`. Tests never touch your real home folder or Trash.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the toolchain, test rules, how to add a rule and the PR checklist. Other version managers (asdf, pyenv, nvm, …): open an issue.

## License

MIT. See [LICENSE](LICENSE).
