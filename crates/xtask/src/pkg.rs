//! `cargo xtask pkg`: `bundle`, then wrap `target/Discky.app` into a flat installer
//! package `target/Discky-<version>.pkg` with `pkgbuild`, installing to `/Applications`.
//!
//! The package is not signed: `productsign` needs a Developer ID Installer certificate,
//! which only the paid Apple program issues. macOS therefore blocks it on first open;
//! the README tells users to allow it under Privacy & Security → Open Anyway.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bundle;

/// The package identifier, the bundle's id: `pkgutil --pkgs` lists it after install.
pub const PKG_IDENTIFIER: &str = "com.alxgol.discky";

/// The component plist handed to `pkgbuild`: the bundle is *not* relocatable, so the
/// package always installs to `/Applications/Discky.app` (and upgrades the copy there)
/// instead of overwriting whatever copy of the bundle id LaunchServices saw last, say
/// one unzipped in `~/Downloads` or a developer's `target/Discky.app`. Without the plist
/// `pkgbuild --component` defaults to relocatable.
pub const COMPONENT_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
	<dict>
		<key>BundleHasStrictIdentifier</key>
		<true/>
		<key>BundleIsRelocatable</key>
		<false/>
		<key>BundleIsVersionChecked</key>
		<true/>
		<key>BundleOverwriteAction</key>
		<string>upgrade</string>
		<key>RootRelativeBundlePath</key>
		<string>Discky.app</string>
	</dict>
</array>
</plist>
"#;

/// `bundle` (with `args`, see [`bundle::run`]), then build the package and print its path.
pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let app = bundle::run(root, args)?;
    let version = bundle::app_version(root)?;
    let target = crate::target_dir(root);
    // pkgbuild --root packages a directory as the install-location's contents, so stage a
    // directory holding only the bundle.
    let staging = target.join("pkg-root");
    if staging.exists() {
        std::fs::remove_dir_all(&staging)
            .map_err(|e| format!("cannot clear {}: {e}", staging.display()))?;
    }
    std::fs::create_dir_all(&staging)
        .map_err(|e| format!("cannot create {}: {e}", staging.display()))?;
    crate::run_capture(
        Command::new("ditto")
            .arg(&app)
            .arg(staging.join("Discky.app")),
    )?;
    let plist = target.join("pkg-component.plist");
    std::fs::write(&plist, COMPONENT_PLIST)
        .map_err(|e| format!("cannot write {}: {e}", plist.display()))?;
    let out = output_path(root, &version);
    let mut cmd = Command::new("pkgbuild");
    cmd.args(pkgbuild_args(&staging, &plist, &version, &out));
    crate::run_capture(&mut cmd)?;
    println!("wrote {}", out.display());
    Ok(())
}

/// The `pkgbuild` arguments: the contents of `staging` installed to `/Applications`
/// as described by the component `plist`, stamped with [`PKG_IDENTIFIER`] and
/// `version`, written to `out`.
pub fn pkgbuild_args(staging: &Path, plist: &Path, version: &str, out: &Path) -> Vec<OsString> {
    vec![
        "--root".into(),
        staging.into(),
        "--component-plist".into(),
        plist.into(),
        "--install-location".into(),
        "/Applications".into(),
        "--identifier".into(),
        PKG_IDENTIFIER.into(),
        "--version".into(),
        version.into(),
        out.into(),
    ]
}

/// Where `pkg` writes: `<target dir>/Discky-<version>.pkg`.
pub fn output_path(root: &Path, version: &str) -> PathBuf {
    crate::target_dir(root).join(format!("Discky-{version}.pkg"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkgbuild_installs_the_staged_root_into_applications_with_the_bundle_id() {
        let args = pkgbuild_args(
            Path::new("/t/pkg-root"),
            Path::new("/t/c.plist"),
            "0.1.0",
            Path::new("/t/Discky-0.1.0.pkg"),
        );
        let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--root",
                "/t/pkg-root",
                "--component-plist",
                "/t/c.plist",
                "--install-location",
                "/Applications",
                "--identifier",
                "com.alxgol.discky",
                "--version",
                "0.1.0",
                "/t/Discky-0.1.0.pkg",
            ]
        );
    }

    #[test]
    fn identifier_is_the_bundle_identifier_of_the_app_plist() {
        let plist = bundle::PLIST_TEMPLATE;
        let after_key = plist
            .split("<key>CFBundleIdentifier</key>")
            .nth(1)
            .expect("CFBundleIdentifier key");
        let value = after_key
            .split("<string>")
            .nth(1)
            .and_then(|s| s.split("</string>").next())
            .expect("CFBundleIdentifier value");
        assert_eq!(value, PKG_IDENTIFIER);
    }

    #[test]
    fn component_plist_pins_the_bundle_in_place() {
        let dict = COMPONENT_PLIST;
        assert!(dict.contains("<key>BundleIsRelocatable</key>\n\t\t<false/>"));
        assert!(
            dict.contains("<key>RootRelativeBundlePath</key>\n\t\t<string>Discky.app</string>")
        );
        assert!(dict.contains("<key>BundleOverwriteAction</key>\n\t\t<string>upgrade</string>"));
    }

    #[test]
    fn output_is_named_after_the_version() {
        assert!(output_path(Path::new("/w"), "1.2.3").ends_with("Discky-1.2.3.pkg"));
    }
}
