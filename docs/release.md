# Releasing Discky

Releases are built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) on macOS 15 when a `v*` tag is pushed.

## Cutting a release

Example for 0.1.1:

1. Bump `version` to `0.1.1` in `crates/discky-core/Cargo.toml`, `crates/discky-mcp/Cargo.toml`, `crates/discky-app/Cargo.toml` and `crates/xtask/Cargo.toml`.
2. Refresh `Cargo.lock`: `cargo update -w`.
3. Commit: `git commit -am "chore: release 0.1.1"`.
4. Tag: `git tag v0.1.1`.
5. Push both: `git push origin main v0.1.1`.

The workflow fails early if the tag does not match the version printed by `cargo xtask version` (the `discky-app` manifest).

## What the workflow produces

- `cargo xtask bundle` builds `target/Discky.app` with `discky-mcp` inside, and `codesign --verify --deep --strict` checks it.
- The bundle is zipped with `ditto` into `Discky-<version>.zip`, its SHA-256 goes to `Discky-<version>.zip.sha256`, and `packaging/homebrew/render-cask.sh` renders the cask `discky.rb`, which `brew style` checks.
- On a tag push: a GitHub release `v<version>` titled `Discky <version>` with generated notes and those three files as assets, then the tap update (below).
- On a manual run (`workflow_dispatch`): the same three files as a workflow artifact; no release and no tap update.

## Secrets (all optional)

Set them under the repository's Settings → Secrets and variables → Actions.

| Secret | Value |
| --- | --- |
| `MACOS_SIGN_P12` | `base64 -i cert.p12` of your Apple Development certificate, exported from Keychain Access together with its private key as `cert.p12` |
| `MACOS_SIGN_P12_PASSWORD` | The password chosen when exporting `cert.p12` |
| `TAP_TOKEN` | A fine-grained personal access token with Contents: read and write on `AlxGolubev/homebrew-discky` only |

Without `MACOS_SIGN_P12` the build is ad-hoc signed and the run shows a warning. Without `TAP_TOKEN` the job summary says to update the tap by hand.

## Updating the tap by hand

Download `discky.rb` from the release and commit it as `Casks/discky.rb` in `AlxGolubev/homebrew-discky` with the message `discky <version>`.

## Why the signature matters for Full Disk Access

macOS ties a Full Disk Access grant to the app's designated requirement. An ad-hoc signature has no identity, so its designated requirement is the exact code hash: every update is a different app to macOS, and the user has to grant Full Disk Access again. A build signed with an Apple Development certificate has a designated requirement that names the signing identity (Apple's certificate chain plus your developer identity, tied to your Team ID) instead of a hash, so every build you sign matches it, renewing the certificate keeps it, and the grant carries over across updates. Check it with `codesign -d -r- /Applications/Discky.app`.
