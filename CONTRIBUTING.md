# Contributing to Discky

Thanks for helping. Discky removes files from people's Macs, so the bar is: every size is honest, every removal goes through an official mechanism, and no test ever touches the real machine.

## Toolchain

- macOS 15 or newer (Apple Silicon or Intel, APFS).
- Rust 1.99, pinned in [`rust-toolchain.toml`](rust-toolchain.toml) with `rustfmt` and `clippy`; `rustup` installs it on first build.

The workspace has four crates: `discky-core` (scanner, rules, findings, planner, executor), `discky-mcp` (the MCP server), `discky-app` (the GPUI desktop app) and `xtask` (`cargo xtask icon|bundle|install`).

## The three commands

All three must be green before a PR, and CI runs the same:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

### Tests on the real machine

A few tests are `#[ignore]`d because they read the real machine (they change nothing). Run them by hand, in release mode where they scan:

```sh
cargo test -p discky-core --release --test walk -- --ignored home_scan_throughput --nocapture   # scans $HOME
cargo test -p discky-core --release --test findings -- --ignored --nocapture                   # categorizes $HOME
cargo test -p discky-core --release --test models -- --ignored --nocapture                     # needs Ollama installed
cargo test -p discky-core --test mise -- --ignored --nocapture                                 # needs mise installed
cargo test -p discky-core --test apps_inventory -- --ignored --nocapture                       # lists this Mac's apps
cargo test -p discky-core --test apps_findings -- --ignored --nocapture                        # app findings on this Mac
```

### Self-tests

```sh
cargo run --release -p discky-mcp -- --self-test-scan   # one scan of the configured roots: node count, duration, peak RSS
cargo run -p discky-app -- --self-check                 # opens the app in a hidden window, shows the disk map, prints "self-check ok" and quits
```

### Debug variables

Debug builds of the app read a few `DISCKY_START_*` variables so a screen can be opened without clicking. Release builds ignore them.

| Variable | Value |
| --- | --- |
| `DISCKY_START_ROUTE` | `overview`, `map`, `settings` or a category (`apps`, `app_caches`, `models`, `dev_caches`, `project_builds`, `language_versions`, `large_old`) |
| `DISCKY_START_SETTINGS` | a settings page: `scanning`, `removal`, `version_manager`, `mcp`, `disk_access`, `about` |
| `DISCKY_START_INSPECT` | a finding (id, absolute path or title) to open in the inspector; an absolute path that is no finding's own opens the path inspector |
| `DISCKY_START_REMOVE` | comma-separated findings for the removal dialog; absolute paths that are no finding's own are planned as disk-map paths. It only plans: nothing runs until Run is pressed |

```sh
DISCKY_START_ROUTE=map cargo run -p discky-app
```

Two core variables make a safe sandbox for trying removals:

- `DISCKY_HOME=<dir>` keeps `config.toml`, `snapshot.bin` and `removals.log` directly inside `<dir>` instead of `~/Library` (`discky-mcp --home <dir>` sets it). Point `[scan] roots` in that config at a scratch folder.
- `DISCKY_TRASH_BIN=<path>` replaces `/usr/bin/trash` for Trash steps with your own program (for example a script that moves its arguments into a scratch folder), so trials never reach the real Trash. Tests and development only.

## Test rules

- Tests never touch the real home folder or the real Trash. Use temp directories, `DISCKY_HOME` and a fake `DISCKY_TRASH_BIN`.
- Tests never run `brew`, `pkgutil --forget`, `launchctl bootout`, `defaults delete` or `mise uninstall`, or anything else that changes the machine.
- Tests and self-checks never open visible windows or steal focus.
- Fixtures carry no real user paths, user names or project names: use neutral names (`a`, `b`, `disk.img`, `Example`).
- New behaviour comes with a test that fails without it.

## Adding a rule

Rules live in [`crates/discky-core/src/rules/builtin.toml`](crates/discky-core/src/rules/builtin.toml) and are parsed by [`crates/discky-core/src/rules/mod.rs`](crates/discky-core/src/rules/mod.rs). Copy an existing rule as the template; `cargo-registry` (the first one) shows every field: `id`, `category`, `label`, `title`, `explain`, a `[rule.matcher]` (`path`, `glob` or `build_dir`) and, when a tool owns the data, a `[rule.command]` with the `tool` it needs, its `argv`, an `install_hint` and, when the command frees less than the whole folder, a `freed_note`.

- Pick the label honestly: `regenerates` only when the owner re-creates the data on its own (a cache), `app_data` when removing it loses something the user may want (toolchains, VM images), `do_not_touch` for things to show but never remove (Keychains, Mail).
- The `explain` text says what the thing is and what happens after removal, in one or two plain sentences.
- Add or extend a test in [`crates/discky-core/tests/rules.rs`](crates/discky-core/tests/rules.rs) for the new rule's matcher.

To propose a rule without writing it, open an issue with the path, what creates it and how it is regenerated.

## The removal principle

Discky removes data only through the mechanism its owner provides: the tool's own command (`cargo cache --autoclean`, `brew uninstall --cask`, `mise uninstall`, Ollama's delete API…), a vendor uninstaller, an installer package's file list, or the Trash. If the tool is missing, the step reports an install hint. A failed command stops the plan; it never falls back to `rm`. Keychain items are never touched.

## Apple Events

Three removal routes use Apple Events from child `osascript` processes: the Finder Trash route for admin-owned items, Quit steps, and Empty Trash. macOS grants Automation to the signed bundle, not to `cargo run`, so check all three on the signed `Discky.app` (`cargo xtask bundle`) after changing them or `packaging/macos/Info.plist` (`NSAppleEventsUsageDescription`).

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` on macOS 15, then builds the app and runs `cargo xtask icon`, which regenerates both `assets/AppIcon.icns` and `assets/logo.png`; only `logo.png` is byte-checked against the committed file (the `.icns` bytes depend on the macOS version's `iconutil`), and the `.icns` must exist and be non-empty. `cargo xtask bundle` stays out of CI: it needs a code-signing identity.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), with the crate as the scope, as in `git log`: `feat(app): …`, `fix(core,app): …`, `docs: …`. The subject says what changed, in the imperative or as a noun phrase, without a trailing period.

## Pull requests

- [ ] The three commands are green.
- [ ] New behaviour has a test; no test touches the real home, Trash or system tools.
- [ ] Any new removal uses an official mechanism, with no `rm` fallback.
- [ ] Sizes stay honest: allocated bytes, clones and hard links counted once.
- [ ] User-facing text is plain English.
- [ ] README updated if behaviour a user sees changed.
- [ ] Apple Events routes checked on the signed bundle, if touched.

## Design docs

The design spec lives in [`docs/superpowers/specs`](docs/superpowers/specs) and the milestone plans in [`docs/superpowers/plans`](docs/superpowers/plans). Read the spec before a large change, and open an issue to discuss one first.
