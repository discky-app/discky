# Releasing Discky

Releases are built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) on macOS 15 when a `v*` tag is pushed. GitHub's `macos-15` runners are arm64, so the release is Apple Silicon only (the cask declares `depends_on arch: :arm64`).

## Cutting a release

Example for 0.1.1:

1. Bump `version` to `0.1.1` in `crates/discky-core/Cargo.toml`, `crates/discky-mcp/Cargo.toml`, `crates/discky-app/Cargo.toml` and `crates/xtask/Cargo.toml`.
2. Refresh `Cargo.lock`: `cargo update -w`.
3. Commit: `git commit -am "chore: release 0.1.1"`.
4. Tag: `git tag v0.1.1`.
5. Push both: `git push origin main v0.1.1`.

The workflow fails early if the tag does not match the version printed by `cargo xtask version` (the `discky-app` manifest).

## What the workflow produces

- `cargo xtask pkg` runs `cargo xtask bundle`, which builds `target/Discky.app` with `discky-mcp` inside, then wraps the bundle with `pkgbuild` into `target/Discky-<version>.pkg`: install location `/Applications`, identifier `com.alxgol.discky`, and a component plist that marks the bundle non-relocatable, so the package always installs (or upgrades) `/Applications/Discky.app` rather than some other copy of the app the system has seen. `codesign --verify --deep --strict` checks the bundle; `pkgutil --payload-files` checks that the package carries `discky-mcp` and `pkgutil --expand` that it has no `<relocate>` entry.
- The package is never signed: `productsign` needs a Developer ID Installer certificate, which only the paid Apple Developer Program issues. On macOS 15 Control-click → Open no longer bypasses Gatekeeper, so users allow it under System Settings → Privacy & Security → Open Anyway (or install with `sudo installer -pkg … -target /`); the README says so.
- The bundle is zipped with `ditto` into `Discky-<version>.zip`; the SHA-256 of the zip and of the package go to `Discky-<version>.zip.sha256` and `Discky-<version>.pkg.sha256`, and `packaging/homebrew/render-cask.sh` renders the cask `discky.rb` (from the zip's hash), which `brew style` checks.
- On a tag push: a GitHub release `v<version>` titled `Discky <version>` with generated notes and those five files as assets, then the tap update (below). Re-running the workflow for a tag whose release already exists replaces the release's assets instead of failing.
- On a manual run (`workflow_dispatch`): the same five files as a workflow artifact; no release and no tap update.

## Secrets (all optional)

Set them under the repository's Settings → Secrets and variables → Actions.

| Secret | Value |
| --- | --- |
| `MACOS_SIGN_P12` | `base64 -i cert.p12` of your Apple Development certificate, exported from Keychain Access together with its private key as `cert.p12` |
| `MACOS_SIGN_P12_PASSWORD` | The password chosen when exporting `cert.p12` |
| `TAP_TOKEN` | A fine-grained personal access token with Contents: read and write on `discky-app/homebrew-tap` only |

Without `MACOS_SIGN_P12` the build is ad-hoc signed and the run shows a warning. Without `TAP_TOKEN` the job summary says to update the tap by hand. The secrets reach only the steps that use them.

If the first signed run fails with "0 valid identities found", the runner lacks Apple's WWDR G3 intermediate certificate: import `AppleWWDRCAG3.cer` (from Apple's certificate authority page) into `build.keychain` in the same step, before `security find-identity`.

## Updating the tap by hand

Download `discky.rb` from the release and commit it as `Casks/discky.rb` in `discky-app/homebrew-tap` with the message `discky <version>`.

## Why the signature matters for Full Disk Access

macOS ties a Full Disk Access grant to the app's designated requirement. An ad-hoc signature has no identity, so its designated requirement is the exact code hash: every update is a different app to macOS, and the user has to grant Full Disk Access again. A build signed with an Apple Development certificate has a designated requirement that names the signing identity instead of a hash: it is pinned to the certificate's subject (your developer identity) under Apple's chain, which a renewed certificate keeps. Every build you sign matches it, and the grant carries over across updates. Check it with `codesign -d -r- /Applications/Discky.app`.
