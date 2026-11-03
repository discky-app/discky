# Discky

![Discky](assets/logo.png)

Discky finds what is eating your Mac's disk and lets an AI agent clear it safely: a Rust scanner, a rule-based "what is this and is it safe to remove" engine, and an MCP server.

## Status

Milestone 3: app uninstaller and mise versions, on top of Discky.app (Overview, categories, inspector, removal, settings) and the MCP server. Requires macOS 15 or newer (Apple Silicon or Intel, APFS).

## Build the app

```sh
cargo xtask install
```

This builds a release `target/Discky.app`, signs it and copies it to `/Applications/Discky.app`. `cargo xtask bundle` stops after signing; `cargo xtask icon` regenerates `assets/AppIcon.icns` and `assets/logo.png` from the pixel logo.

Signing needs a stable identity, so that Full Disk Access survives rebuilds (macOS ties the grant to the signature). `xtask` picks the first `Apple Development` or `Developer ID Application` identity in your keychain; set `DISCKY_SIGN_IDENTITY="<name or SHA-1>"` to choose another. Without one it stops and explains how to create a self-signed Code Signing certificate in Keychain Access. `DISCKY_SIGN_IDENTITY=-` signs ad-hoc: fine for a quick try, but Full Disk Access has to be granted again after every rebuild.

**Full Disk Access.** Without it macOS hides parts of `~/Library` (Mail, Safari, other apps' containers) from the scan. Grant it in System Settings → Privacy & Security → Full Disk Access (add Discky with `+`), then rescan.

**Applications and Language versions.** Applications lists installed apps (Homebrew casks, App Store, installer packages and dragged-in bundles) with their last use and the files they left in `~/Library` and `/Library`, plus leftovers of apps that are already gone. Language versions lists the tool versions mise installed, with which ones are global or used by a project. The inspector shows each removable part of an app (bundle, caches, settings, launch agents, package receipts…) as a checkbox: uncheck a leftover to keep it. An app is removed only through official mechanisms: its vendor's uninstaller script first when it ships one (a checkable step that runs interactively and may ask for an administrator password), then `brew uninstall --cask` (with `--zap` only when every path the cask's zap stanza removes is listed and checked), the installer package's file list, or the Trash; a language version through `mise uninstall`. Keychain items are never touched.

**Automation prompt.** Some removals go through Apple Events: Finder moves admin-owned items to the Trash, apps are asked to quit before their files are removed, and Empty Trash asks Finder. The first time, macOS asks whether Discky may control Finder (or that app); allow it, or those steps fail. The choice can be changed in System Settings → Privacy & Security → Automation. System-level steps such as `pkgutil --forget` and `launchctl bootout system` show an administrator password prompt instead; cancelling it stops the removal at that step.

**Quitting during a removal.** ⌘Q and closing the window are refused with a notification while a removal runs; quitting from the Dock or logging out interrupts the running step and the log records it (`"kind": "interrupted"`). The next scan shows what is left.

**Upgrading from an earlier milestone.** The snapshot format changed (now format 3): an older `snapshot.bin` is ignored, so the first launch shows "No scan yet" until you rescan. Build `discky-mcp` and Discky.app from the same milestone; they share the snapshot file, and each ignores a snapshot in the other's format.

## Install the MCP server

From source (Rust toolchain required):

```sh
git clone https://github.com/OWNER/discky   # placeholder: the repo is not public yet
cd discky
cargo install --path crates/discky-mcp
```

This installs `~/.cargo/bin/discky-mcp`.

Homebrew: a formula stub lives in `packaging/homebrew/discky-mcp.rb`; the tap is coming once the repo is public.

## Connect to your agent

`discky-mcp` speaks MCP over stdio. Use the Homebrew path (`/opt/homebrew/bin/discky-mcp`) or the `cargo install` path (`~/.cargo/bin/discky-mcp`; some clients need it written out absolutely).

**Claude Code**

```sh
claude mcp add discky -- /opt/homebrew/bin/discky-mcp
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

## Tools

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

## Safety model

- **Plan, then execute.** The agent must call `plan_removal`, show the plan to you, and only then call `execute_plan`. A plan whose removal mode changed since it was made is refused.
- **Deletion is off by default.** `execute_plan` is refused until you set `allow_agent_delete = true` in `config.toml`:

  ```toml
  [mcp]
  allow_agent_delete = true
  ```

  The config is re-read on every call, so no restart is needed.
- **Trash by default.** `removal.mode` is `"trash"` unless you set `"permanent"`.
- **Interactive steps are never run by the agent.** Steps that need an admin prompt are skipped.
- **Official tools, no `rm` fallback.** Where a tool owns the data (for example `cargo cache --autoclean`), the rule runs that tool. If it is not installed, the step reports an install hint instead of falling back to `rm`.
- **Honest sizes.** Every size is bytes allocated on disk. `freed_if_deleted` is what removing the item really frees; clones and hard links shared with files that stay are not counted. `disk_overview` reports `exact_private_size`: `true` when `freed_if_deleted` was measured exactly, `false` when it is clone-aware only; it is recorded in the snapshot, so it is `null` only before the first scan.
- Paths labelled `do_not_touch` (Keychains, Mail, Messages, ...) are listed so you know they were seen, but have no removal method and are never removed.

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

Findings come from declarative rules in `crates/discky-core/src/rules/builtin.toml`. Each rule has a category (`dev_caches`, `models`, `project_builds`, `app_caches`), a safety label (`regenerates`, `app_data`, `do_not_touch`), a plain-language explanation, a matcher (`path`, `glob` or `build_dir`) and, optionally, the official command that removes it:

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

## Development

```sh
cargo test --workspace
```

Three tests are `#[ignore]`d because they touch the real machine; run them in release mode:

```sh
cargo test -p discky-core --release --test walk -- --ignored home_scan_throughput --nocapture   # scans $HOME
cargo test -p discky-core --release --test findings -- --ignored --nocapture                   # categorizes $HOME
cargo test -p discky-core --release --test models -- --ignored --nocapture                     # needs Ollama installed
```

A hidden flag runs one scan of the configured roots and prints the node count, duration and peak RSS:

```sh
cargo run --release -p discky-mcp -- --self-test-scan
```

Debug builds of the app read a few `DISCKY_START_*` variables so a screen can be opened without clicking: `DISCKY_START_ROUTE` (`overview`, `settings` or a category), `DISCKY_START_SETTINGS` (a settings page), `DISCKY_START_INSPECT` (a finding) and `DISCKY_START_REMOVE` (findings for the removal dialog). Release builds ignore them.

```sh
DISCKY_START_ROUTE=dev_caches cargo run -p discky-app
```

Three removal routes use Apple Events from child `osascript` processes: the Finder Trash route for admin-owned items, Quit steps, and Empty Trash. macOS grants Automation to the signed bundle, not to `cargo run`, so check all three on the signed `Discky.app` (`cargo xtask bundle`) after changing them or `packaging/macos/Info.plist` (`NSAppleEventsUsageDescription`).

CI (`.github/workflows/ci.yml`) runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` on macOS 15, then builds the app and runs `cargo xtask icon`, which regenerates both `assets/AppIcon.icns` and `assets/logo.png`; only `logo.png` is byte-checked against the committed file (the `.icns` bytes depend on the macOS version's `iconutil`), and the `.icns` must exist and be non-empty.

## License

MIT. See [LICENSE](LICENSE).
