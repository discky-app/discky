//! `cargo xtask bundle` / `install`: assemble and sign `Discky.app`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The bundle's Info.plist template (`@VERSION@` is filled from discky-app's manifest).
const PLIST_TEMPLATE: &str = include_str!("../../../packaging/macos/Info.plist");

const NO_IDENTITY: &str = "No stable signing identity. Create one in Keychain Access \
(Certificate Assistant → Create a Certificate, type Code Signing) and pass \
DISCKY_SIGN_IDENTITY, or pass DISCKY_SIGN_IDENTITY=- for an ad-hoc build (Full Disk \
Access will not survive rebuilds).";

/// Binaries built next to the app and shipped in `Contents/MacOS`; the Homebrew cask
/// and CI rely on this list.
pub fn helper_binaries() -> [&'static str; 1] {
    ["discky-mcp"]
}

/// Build the release binaries, assemble `target/Discky.app` and sign it; returns the
/// bundle's path. Bundles are always release builds; `--release` is accepted for
/// symmetry with cargo.
pub fn run(root: &Path, args: &[String]) -> Result<PathBuf, String> {
    if let Some(bad) = args.iter().find(|a| a.as_str() != "--release") {
        return Err(format!("unknown bundle argument `{bad}`\n{}", crate::USAGE));
    }
    // Resolve the identity first: a missing one fails before a minutes-long build.
    let identity = signing_identity()?;
    crate::run_inherit(
        Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(root)
            .args(["build", "-p", "discky-app", "-p", "discky-mcp", "--release"]),
    )?;

    let target = crate::target_dir(root);
    let app = target.join("Discky.app");
    if app.exists() {
        std::fs::remove_dir_all(&app)
            .map_err(|e| format!("cannot clear {}: {e}", app.display()))?;
    }
    let contents = app.join("Contents");
    let macos = contents.join("MacOS");
    let resources = contents.join("Resources");
    for dir in [&macos, &resources] {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let version = app_version(root)?;
    let plist = contents.join("Info.plist");
    std::fs::write(&plist, render_plist(PLIST_TEMPLATE, &version))
        .map_err(|e| format!("cannot write {}: {e}", plist.display()))?;
    copy(&target.join("release/discky-app"), &macos.join("Discky"))?;
    for helper in helper_binaries() {
        copy(&target.join("release").join(helper), &macos.join(helper))?;
    }
    copy(
        &root.join("assets/AppIcon.icns"),
        &resources.join("AppIcon.icns"),
    )?;

    if identity.id == "-" {
        eprintln!(
            "warning: signing ad-hoc (DISCKY_SIGN_IDENTITY=-): Full Disk Access will not \
             survive rebuilds"
        );
    }
    // Extra Mach-O files in Contents/MacOS are not covered by `--deep` and fail strict
    // verification unsigned, so each helper is signed before the bundle.
    for helper in helper_binaries() {
        crate::run_capture(
            Command::new("codesign")
                .args(["--force", "--sign", &identity.id])
                .arg(macos.join(helper)),
        )?;
    }
    crate::run_capture(
        Command::new("codesign")
            .args(["--force", "--deep", "--sign", &identity.id])
            .arg(&app),
    )?;
    crate::run_capture(
        Command::new("codesign")
            .args(["--verify", "--deep", "--strict", "--verbose"])
            .arg(&app),
    )?;
    println!("signed {} with {}", app.display(), identity.name);
    Ok(app)
}

/// `cargo xtask version`: print discky-app's manifest version and nothing else.
pub fn print_version(root: &Path) -> Result<(), String> {
    println!("{}", app_version(root)?);
    Ok(())
}

/// `bundle`, then copy the app over `/Applications/Discky.app`.
pub fn install(root: &Path) -> Result<(), String> {
    let app = run(root, &[])?;
    let dest = "/Applications/Discky.app";
    crate::run_capture(Command::new("ditto").arg(&app).arg(dest))?;
    println!("installed {dest}");
    Ok(())
}

/// `template` with every `@VERSION@` replaced by `version`.
pub fn render_plist(template: &str, version: &str) -> String {
    template.replace("@VERSION@", version)
}

/// A codesigning identity: what `codesign --sign` gets and what is shown to the user.
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    id: String,
    name: String,
}

/// `DISCKY_SIGN_IDENTITY` if set (`-` = ad-hoc), else the first Apple Development or
/// Developer ID Application identity in the keychain; never ad-hoc by default.
fn signing_identity() -> Result<Identity, String> {
    if let Some(id) = std::env::var_os("DISCKY_SIGN_IDENTITY") {
        let id = id.to_string_lossy().into_owned();
        let name = if id == "-" {
            "ad-hoc".to_owned()
        } else {
            id.clone()
        };
        return Ok(Identity { id, name });
    }
    let listing = crate::run_capture(Command::new("security").args([
        "find-identity",
        "-v",
        "-p",
        "codesigning",
    ]))?;
    pick_identity(&listing).ok_or_else(|| NO_IDENTITY.to_owned())
}

/// The first stable identity in `security find-identity -v` output, whose lines read
/// `  1) <SHA-1> "Apple Development: Name (TEAM)"`. Signs by hash, so two certificates
/// with the same name do not make codesign ambiguous.
fn pick_identity(listing: &str) -> Option<Identity> {
    listing.lines().find_map(|line| {
        let (_, rest) = line.trim_start().split_once(") ")?;
        let (hash, quoted) = rest.split_once(' ')?;
        let name = quoted.trim().strip_prefix('"')?.strip_suffix('"')?;
        let stable =
            name.starts_with("Apple Development:") || name.starts_with("Developer ID Application:");
        stable.then(|| Identity {
            id: hash.to_owned(),
            name: name.to_owned(),
        })
    })
}

/// discky-app's version: the first `version = "…"` line of its manifest.
pub fn app_version(root: &Path) -> Result<String, String> {
    let manifest = root.join("crates/discky-app/Cargo.toml");
    let text = std::fs::read_to_string(&manifest)
        .map_err(|e| format!("cannot read {}: {e}", manifest.display()))?;
    manifest_version(&text).ok_or_else(|| format!("no `version = \"…\"` in {}", manifest.display()))
}

fn manifest_version(manifest: &str) -> Option<String> {
    manifest.lines().find_map(|line| {
        let value = line
            .trim()
            .strip_prefix("version")?
            .trim_start()
            .strip_prefix('=')?;
        Some(
            value
                .trim()
                .strip_prefix('"')?
                .strip_suffix('"')?
                .to_owned(),
        )
    })
}

fn copy(from: &Path, to: &Path) -> Result<(), String> {
    std::fs::copy(from, to)
        .map(|_| ())
        .map_err(|e| format!("cannot copy {} to {}: {e}", from.display(), to.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_contains_min_system_version_15() {
        let text = render_plist(PLIST_TEMPLATE, "1.2.3");
        assert!(text.contains("<key>LSMinimumSystemVersion</key>\n\t<string>15.0</string>"));
        assert!(text.contains("<key>CFBundleShortVersionString</key>\n\t<string>1.2.3</string>"));
        assert!(text.contains("<key>CFBundleVersion</key>\n\t<string>1.2.3</string>"));
        assert!(text.contains("<key>CFBundleExecutable</key>\n\t<string>Discky</string>"));
        assert!(
            text.contains("<key>CFBundleIdentifier</key>\n\t<string>com.alxgol.discky</string>")
        );
        assert!(!text.contains("@VERSION@"));
    }

    #[test]
    fn plist_explains_apple_events() {
        let text = render_plist(PLIST_TEMPLATE, "1.2.3");
        assert!(text.contains(
            "<key>NSAppleEventsUsageDescription</key>\n\t<string>Discky asks Finder to move \
             admin-owned items to the Trash, asks apps to quit before their files are removed, \
             and empties the Trash when you ask.</string>"
        ));
    }

    #[test]
    fn picks_first_stable_identity_by_hash() {
        let listing = "  1) AAAA \"Apple Distribution: X (T)\"\n  2) BBBB \"Apple Development: me@x (KYV)\"\n  3) CCCC \"Developer ID Application: Me (T)\"\n     3 valid identities found\n";
        assert_eq!(
            pick_identity(listing),
            Some(Identity {
                id: "BBBB".into(),
                name: "Apple Development: me@x (KYV)".into()
            })
        );
        assert_eq!(pick_identity("     0 valid identities found\n"), None);
    }

    #[test]
    fn helper_binaries_lists_the_mcp_server() {
        assert_eq!(helper_binaries(), ["discky-mcp"]);
    }

    #[test]
    fn reads_package_version_line() {
        let manifest =
            "[package]\nname = \"discky-app\"\nversion = \"0.1.0\"\nedition.workspace = true\n";
        assert_eq!(manifest_version(manifest).as_deref(), Some("0.1.0"));
    }
}
