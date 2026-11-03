//! Homebrew casks: what `brew` (or, offline, the Caskroom) knows about installed casks —
//! which bundles they own and their `uninstall` / `zap` stanzas. Read-only: nothing here
//! ever runs `brew uninstall`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::tools::run_capture_env;

const BREW_TIMEOUT: Duration = Duration::from_secs(5);
/// Keep `brew` from updating itself or phoning home during a scan.
const BREW_ENV: [(&str, &str); 2] = [
    ("HOMEBREW_NO_AUTO_UPDATE", "1"),
    ("HOMEBREW_NO_ANALYTICS", "1"),
];
/// Where the cask apps go unless `--appdir` was used.
const APPDIR: &str = "/Applications";
/// Caskroom locations tried when `brew --caskroom` cannot be asked.
const DEFAULT_CASKROOMS: [&str; 2] = ["/opt/homebrew/Caskroom", "/usr/local/Caskroom"];

/// One installed (or, from a lookup, known) cask.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cask {
    /// Short name, e.g. `hex`.
    pub token: String,
    /// Tap-qualified name, e.g. `anomalyco/tap/hex` (equals `token` for homebrew/cask).
    pub full_token: String,
    /// The installed version (the Caskroom directory name); `None` when not installed.
    pub installed: Option<String>,
    /// Absolute paths of the app bundles the cask installed (`app` artifacts, plus the
    /// targets of the Caskroom's `<App>.app` symlinks).
    pub app_targets: Vec<PathBuf>,
    pub uninstall: Vec<Directive>,
    pub zap: Vec<Directive>,
}

/// One `uninstall` / `zap` directive object. Paths are raw patterns (`~`, `*`, braces):
/// see [`expand_zap_path`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directive {
    /// Bundle ids to quit.
    pub quit: Vec<String>,
    /// launchd labels to remove.
    pub launchctl: Vec<String>,
    /// Receipt ids (may contain `*`) to forget, with their files.
    pub pkgutil: Vec<String>,
    pub delete: Vec<String>,
    pub trash: Vec<String>,
    pub rmdir: Vec<String>,
    /// `(signal, bundle_id)` pairs, e.g. `("KILL", "us.zoom.xos")`.
    pub signal: Vec<(String, String)>,
    pub script: Option<Script>,
    /// A script brew runs before everything else in the stanza.
    pub early_script: Option<Script>,
    /// Login item names to remove.
    pub login_item: Vec<String>,
}

/// A `script` / `early_script` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Script {
    pub executable: String,
    pub args: Vec<String>,
    /// brew's default is `true`.
    pub must_succeed: bool,
}

/// A JSON value that is either one `T` or an array of them.
#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(t) => vec![t],
            OneOrMany::Many(v) => v,
        }
    }
}

fn many(v: Option<OneOrMany<String>>) -> Vec<String> {
    v.map(OneOrMany::into_vec).unwrap_or_default()
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawScript {
    Path(String),
    Full {
        executable: String,
        #[serde(default)]
        args: Option<OneOrMany<String>>,
        #[serde(default)]
        must_succeed: Option<bool>,
    },
}

impl From<RawScript> for Script {
    fn from(raw: RawScript) -> Script {
        match raw {
            RawScript::Path(executable) => Script {
                executable,
                args: Vec::new(),
                must_succeed: true,
            },
            RawScript::Full {
                executable,
                args,
                must_succeed,
            } => Script {
                executable,
                args: many(args),
                must_succeed: must_succeed.unwrap_or(true),
            },
        }
    }
}

#[derive(Deserialize)]
struct RawDirective {
    #[serde(default)]
    quit: Option<OneOrMany<String>>,
    #[serde(default)]
    launchctl: Option<OneOrMany<String>>,
    #[serde(default)]
    pkgutil: Option<OneOrMany<String>>,
    #[serde(default)]
    delete: Option<OneOrMany<String>>,
    #[serde(default)]
    trash: Option<OneOrMany<String>>,
    #[serde(default)]
    rmdir: Option<OneOrMany<String>>,
    #[serde(default)]
    signal: Option<Value>,
    #[serde(default)]
    script: Option<RawScript>,
    #[serde(default)]
    early_script: Option<RawScript>,
    #[serde(default)]
    login_item: Option<OneOrMany<String>>,
}

impl From<RawDirective> for Directive {
    fn from(raw: RawDirective) -> Directive {
        Directive {
            quit: many(raw.quit),
            launchctl: many(raw.launchctl),
            pkgutil: many(raw.pkgutil),
            delete: many(raw.delete),
            trash: many(raw.trash),
            rmdir: many(raw.rmdir),
            signal: raw.signal.as_ref().map(signal_pairs).unwrap_or_default(),
            script: raw.script.map(Script::from),
            early_script: raw.early_script.map(Script::from),
            login_item: many(raw.login_item),
        }
    }
}

/// `["KILL","a","TERM","b"]` (flat, as brew's JSON has it) or `[["KILL","a"], …]`.
fn signal_pairs(v: &Value) -> Vec<(String, String)> {
    let Some(items) = v.as_array() else {
        return Vec::new();
    };
    if items.iter().all(Value::is_string) {
        let s: Vec<&str> = items.iter().filter_map(Value::as_str).collect();
        let (pairs, _odd) = s.as_chunks::<2>();
        return pairs
            .iter()
            .map(|[sig, id]| (sig.to_string(), id.to_string()))
            .collect();
    }
    items.iter().flat_map(signal_pairs).collect()
}

/// Parse `brew info --cask --json=v2 [--installed]` output (`{"formulae":[…],"casks":[…]}`).
/// A cask without a `token` or a directive of an unexpected shape is skipped; only
/// malformed JSON or a missing `casks` array is an error.
pub fn parse_casks(json: &str) -> Result<Vec<Cask>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let casks = v
        .get("casks")
        .and_then(Value::as_array)
        .ok_or_else(|| "no `casks` array".to_string())?;
    Ok(casks.iter().filter_map(cask_from_value).collect())
}

/// One cask record: `token`, `full_token`, `installed`, `artifacts` (or an install
/// receipt's `uninstall_artifacts`).
fn cask_from_value(v: &Value) -> Option<Cask> {
    let token = v.get("token")?.as_str()?.to_string();
    let mut cask = Cask {
        full_token: v
            .get("full_token")
            .and_then(Value::as_str)
            .unwrap_or(&token)
            .to_string(),
        installed: v
            .get("installed")
            .and_then(Value::as_str)
            .map(str::to_string),
        token,
        ..Cask::default()
    };
    apply_artifacts(&mut cask, artifacts_of(v));
    Some(cask)
}

fn artifacts_of(v: &Value) -> &[Value] {
    v.get("artifacts")
        .or_else(|| v.get("uninstall_artifacts"))
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// Fill `app_targets`, `uninstall` and `zap` from an artifacts array of single-purpose
/// objects (`{"app":["X.app"],"target":"/Applications/X.app"}`, `{"uninstall":[{…}]}`, …).
fn apply_artifacts(cask: &mut Cask, artifacts: &[Value]) {
    for a in artifacts {
        if let Some(app) = a.get("app").and_then(Value::as_array) {
            let names: Vec<&str> = app.iter().filter_map(Value::as_str).collect();
            // The target is a sibling key (v2) or an `{"target": …}` element (older JSON).
            let target = a.get("target").and_then(Value::as_str).or_else(|| {
                app.iter()
                    .find_map(|e| e.get("target").and_then(Value::as_str))
            });
            match (names.as_slice(), target) {
                ([_], Some(t)) => push_unique(&mut cask.app_targets, app_path(t)),
                _ => {
                    for n in names {
                        push_unique(&mut cask.app_targets, app_path(n));
                    }
                }
            }
        }
        for (key, out) in [("uninstall", &mut cask.uninstall), ("zap", &mut cask.zap)] {
            if let Some(list) = a.get(key).and_then(Value::as_array) {
                out.extend(
                    list.iter()
                        .filter_map(|d| serde_json::from_value::<RawDirective>(d.clone()).ok())
                        .map(Directive::from),
                );
            }
        }
    }
}

/// An `app` name or target: absolute as is, else relative to `/Applications`.
fn app_path(name: &str) -> PathBuf {
    let p = Path::new(name);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        Path::new(APPDIR).join(p)
    }
}

fn push_unique(v: &mut Vec<PathBuf>, p: PathBuf) {
    if !v.contains(&p) {
        v.push(p);
    }
}

/// Installed casks. With `brew`: `brew info --cask --json=v2 --installed` (5 s, no
/// auto-update, no analytics). When that fails, or without brew, the Caskroom is read
/// offline ([`read_caskroom`]) for the tokens of `brew list --cask` (or every Caskroom
/// directory without brew). The Caskroom is `brew --caskroom`, else the first of
/// `/opt/homebrew/Caskroom`, `/usr/local/Caskroom` that exists; its `<App>.app` symlinks
/// add to each cask's `app_targets`. No Caskroom and no brew → empty.
pub fn installed_casks(brew: Option<&Path>) -> Vec<Cask> {
    let capture = |args: &[&str]| run_capture_env(brew?, args, &BREW_ENV, BREW_TIMEOUT);
    let room = capture(&["--caskroom"])
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| p.is_absolute() && p.is_dir())
        .or_else(|| {
            DEFAULT_CASKROOMS
                .iter()
                .map(PathBuf::from)
                .find(|p| p.is_dir())
        });
    if let Some(json) = capture(&["info", "--cask", "--json=v2", "--installed"])
        && let Ok(mut casks) = parse_casks(&json)
    {
        if let Some(room) = &room {
            for c in &mut casks {
                add_caskroom_targets(room, c);
            }
        }
        return casks;
    }
    let Some(room) = room else {
        return Vec::new();
    };
    let tokens: Option<Vec<String>> = capture(&["list", "--cask"]).map(|s| {
        s.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect()
    });
    read_caskroom(&room, tokens.as_deref())
}

/// The `uninstall.quit` bundle ids of cask `token`, read offline from the first default
/// Caskroom that exists (`/opt/homebrew/Caskroom`, `/usr/local/Caskroom`; no `brew` run).
/// Empty when the cask or its metadata is not found.
pub fn caskroom_quit_ids(token: &str) -> Vec<String> {
    DEFAULT_CASKROOMS
        .iter()
        .map(Path::new)
        .find(|p| p.is_dir())
        .and_then(|room| read_caskroom_entry(room, token.to_string()))
        .map(|c| c.uninstall.into_iter().flat_map(|d| d.quit).collect())
        .unwrap_or_default()
}

/// Offline cask records from a Caskroom: for each token (`tokens`, or every visible
/// directory of `room`), `installed` is the newest version directory name; the stanzas
/// come from the newest cached definition `.metadata/<ver>/<timestamp>/Casks/<token>.json`
/// (by timestamp directory name), or — when that is missing or empty — from
/// `.metadata/INSTALL_RECEIPT.json`'s `uninstall_artifacts` (whose `source.tap` gives
/// `full_token` for third-party taps).
pub fn read_caskroom(room: &Path, tokens: Option<&[String]>) -> Vec<Cask> {
    let tokens: Vec<String> = match tokens {
        Some(t) => t.to_vec(),
        None => visible_dirs(room),
    };
    tokens
        .into_iter()
        .filter_map(|token| read_caskroom_entry(room, token))
        .collect()
}

fn read_caskroom_entry(room: &Path, token: String) -> Option<Cask> {
    let dir = room.join(&token);
    if !dir.is_dir() {
        return None;
    }
    let mut cask = Cask {
        full_token: token.clone(),
        installed: visible_dirs(&dir).pop(),
        token,
        ..Cask::default()
    };
    if let Some(def) = newest_cached_definition(&dir, &cask.token)
        && let Some(c) = cask_from_value(&def)
    {
        cask.full_token = c.full_token;
        cask.app_targets = c.app_targets;
        cask.uninstall = c.uninstall;
        cask.zap = c.zap;
    }
    let empty = cask.app_targets.is_empty() && cask.uninstall.is_empty() && cask.zap.is_empty();
    if empty && let Some(receipt) = read_json(&dir.join(".metadata/INSTALL_RECEIPT.json")) {
        apply_artifacts(&mut cask, artifacts_of(&receipt));
        let tap = receipt.pointer("/source/tap").and_then(Value::as_str);
        if cask.full_token == cask.token
            && let Some(tap) = tap.filter(|t| *t != "homebrew/cask" && !t.is_empty())
        {
            cask.full_token = format!("{tap}/{}", cask.token);
        }
    }
    add_caskroom_targets(room, &mut cask);
    Some(cask)
}

/// `.metadata/*/*/Casks/<token>.json` with the greatest timestamp directory name.
fn newest_cached_definition(dir: &Path, token: &str) -> Option<Value> {
    let meta = dir.join(".metadata");
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for ver in visible_dirs(&meta) {
        for ts in visible_dirs(&meta.join(&ver)) {
            let file = meta
                .join(&ver)
                .join(&ts)
                .join("Casks")
                .join(format!("{token}.json"));
            if file.is_file() {
                found.push((ts, file));
            }
        }
    }
    found.sort();
    read_json(&found.pop()?.1)
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Sorted names of the non-hidden subdirectories of `dir`.
fn visible_dirs(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| !n.starts_with('.'))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// `<room>/<token>/<version>/<App>.app` symlinks point at the real bundles.
fn add_caskroom_targets(room: &Path, cask: &mut Cask) {
    let dir = room.join(&cask.token);
    let versions = match &cask.installed {
        Some(v) => vec![v.clone()],
        None => visible_dirs(&dir),
    };
    for v in versions {
        let vdir = dir.join(v);
        let Ok(rd) = std::fs::read_dir(&vdir) else {
            continue;
        };
        for e in rd.flatten() {
            let is_app = e.file_name().to_string_lossy().ends_with(".app");
            if is_app
                && e.file_type().is_ok_and(|t| t.is_symlink())
                && let Ok(target) = std::fs::read_link(e.path())
            {
                push_unique(&mut cask.app_targets, vdir.join(target));
            }
        }
    }
}

/// The installed cask that owns `bundle` (one of its `app_targets`).
pub fn cask_for_bundle<'a>(casks: &'a [Cask], bundle: &Path) -> Option<&'a Cask> {
    casks
        .iter()
        .find(|c| c.installed.is_some() && c.app_targets.iter().any(|t| t == bundle))
}

/// Existing paths matching a zap/uninstall pattern: `~` → `home`, brace alternatives
/// (nested, e.g. `Adobe{/CEP{/extensions,},}`) expanded, then `*` / `?` / `[…]` segments
/// matched against the entries of their parent directory only (never a recursive scan;
/// a wildcard does not match a leading `.`). Relative patterns match nothing. Sorted,
/// deduplicated; broken symlinks count as existing.
pub fn expand_zap_path(pattern: &str, home: &Path) -> Vec<PathBuf> {
    let pattern = if pattern == "~" {
        home.to_string_lossy().into_owned()
    } else if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{}/{rest}", home.to_string_lossy().trim_end_matches('/'))
    } else {
        pattern.to_string()
    };
    let mut out = BTreeSet::new();
    for candidate in expand_braces(&pattern) {
        if !candidate.starts_with('/') {
            continue;
        }
        out.extend(glob_existing(&candidate));
    }
    out.into_iter().collect()
}

/// Shell-style brace expansion, outermost-first; an unmatched `{` is literal.
fn expand_braces(s: &str) -> Vec<String> {
    let Some(open) = s.find('{') else {
        return vec![s.to_string()];
    };
    let mut depth = 0usize;
    let mut close = None;
    let mut commas = Vec::new();
    for (i, c) in s[open..].char_indices() {
        let i = open + i;
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            ',' if depth == 1 => commas.push(i),
            _ => {}
        }
    }
    let Some(close) = close else {
        return vec![s.to_string()];
    };
    let (prefix, suffix) = (&s[..open], &s[close + 1..]);
    let mut bounds = vec![open];
    bounds.extend(commas);
    bounds.push(close);
    bounds
        .windows(2)
        .flat_map(|w| expand_braces(&format!("{prefix}{}{suffix}", &s[w[0] + 1..w[1]])))
        .collect()
}

fn has_glob_meta(segment: &str) -> bool {
    segment.contains(['*', '?', '['])
}

/// Existing paths for one brace-free absolute pattern.
fn glob_existing(pattern: &str) -> Vec<PathBuf> {
    let mut bases = vec![PathBuf::from("/")];
    for seg in pattern.split('/').filter(|s| !s.is_empty()) {
        if !has_glob_meta(seg) {
            for b in &mut bases {
                b.push(seg);
            }
            continue;
        }
        let Ok(glob) = globset::GlobBuilder::new(seg)
            .literal_separator(true)
            .build()
        else {
            return Vec::new();
        };
        let matcher = glob.compile_matcher();
        let dot_ok = seg.starts_with('.');
        let mut next = Vec::new();
        for b in &bases {
            let Ok(rd) = std::fs::read_dir(b) else {
                continue;
            };
            let mut names: Vec<_> = rd.flatten().map(|e| e.file_name()).collect();
            names.sort();
            for n in names {
                let visible = dot_ok || !n.to_string_lossy().starts_with('.');
                if visible && matcher.is_match(&n) {
                    next.push(b.join(&n));
                }
            }
        }
        bases = next;
        if bases.is_empty() {
            break;
        }
    }
    bases
        .into_iter()
        .filter(|p| std::fs::symlink_metadata(p).is_ok())
        .collect()
}
