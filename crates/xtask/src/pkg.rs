//! `cargo xtask pkg`: `bundle`, then wrap `target/Discky.app` into a flat installer
//! package `target/Discky-<version>.pkg` with `pkgbuild`, installing to `/Applications`.
//!
//! The package is not signed: `productsign` needs a Developer ID Installer certificate,
//! which only the paid Apple program issues. macOS therefore shows an unidentified
//! developer warning; the README tells users how to open it anyway.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bundle;

/// The package identifier, the bundle's id: `pkgutil --pkgs` lists it after install.
pub const PKG_IDENTIFIER: &str = "com.alxgol.discky";

/// `bundle` (with `args`, see [`bundle::run`]), then build the package and print its path.
pub fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let app = bundle::run(root, args)?;
    let version = bundle::app_version(root)?;
    let out = output_path(root, &version);
    let mut cmd = Command::new("pkgbuild");
    cmd.args(pkgbuild_args(&app, &version, &out));
    crate::run_capture(&mut cmd)?;
    println!("wrote {}", out.display());
    Ok(())
}

/// The `pkgbuild` arguments: a component package of `app`, installed to `/Applications`,
/// stamped with [`PKG_IDENTIFIER`] and `version`, written to `out`.
pub fn pkgbuild_args(app: &Path, version: &str, out: &Path) -> Vec<String> {
    vec![
        "--component".into(),
        app.display().to_string(),
        "--install-location".into(),
        "/Applications".into(),
        "--identifier".into(),
        PKG_IDENTIFIER.into(),
        "--version".into(),
        version.into(),
        out.display().to_string(),
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
    fn pkgbuild_installs_the_component_into_applications_with_the_bundle_id() {
        let args = pkgbuild_args(
            Path::new("/t/Discky.app"),
            "0.1.0",
            Path::new("/t/Discky-0.1.0.pkg"),
        );
        assert_eq!(
            args,
            [
                "--component",
                "/t/Discky.app",
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
    fn identifier_matches_the_bundle_plist() {
        let plist = include_str!("../../../packaging/macos/Info.plist");
        assert!(plist.contains(&format!("<string>{PKG_IDENTIFIER}</string>")));
    }

    #[test]
    fn output_is_named_after_the_version_in_target() {
        let out = output_path(Path::new("/w"), "1.2.3");
        assert!(out.ends_with("Discky-1.2.3.pkg"));
        assert!(out.starts_with("/w"));
    }
}
