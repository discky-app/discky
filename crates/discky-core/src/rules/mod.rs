//! Data-driven rule set: which paths become findings and how they are removed.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

const BUILTIN: &str = include_str!("builtin.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Apps,
    AppCaches,
    Models,
    DevCaches,
    ProjectBuilds,
    LanguageVersions,
    LargeOld,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Category::Apps => "Applications",
            Category::AppCaches => "App caches",
            Category::Models => "Models",
            Category::DevCaches => "Dev caches",
            Category::ProjectBuilds => "Project builds",
            Category::LanguageVersions => "Language versions",
            Category::LargeOld => "Large & old",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyLabel {
    Regenerates,
    AppData,
    NeedsPassword,
    AppRunning,
    DoNotTouch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Matcher {
    Path { path: PathBuf },
    Glob { glob: String },
    BuildDir { name: String, marker: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleCommand {
    pub tool: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub install_hint: Option<String>,
    #[serde(default)]
    pub freed_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub category: Category,
    pub matcher: Matcher,
    pub label: SafetyLabel,
    pub title: String,
    pub explain: String,
    #[serde(default)]
    pub command: Option<RuleCommand>,
    /// Each direct child is its own finding (e.g. Hugging Face hub repos).
    #[serde(default)]
    pub per_child: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum RuleError {
    #[error("invalid rule file: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("rule `{id}`: invalid glob `{glob}`: {source}")]
    Glob {
        id: String,
        glob: String,
        source: globset::Error,
    },
    #[error("duplicate rule id `{0}`")]
    Duplicate(String),
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

#[derive(Debug)]
pub struct RuleSet {
    rules: Vec<Rule>,
    by_id: HashMap<String, usize>,
    by_path: HashMap<PathBuf, usize>,
    globs: GlobSet,
    /// Rule index for each glob in `globs`, in insertion (file) order.
    glob_rules: Vec<usize>,
}

fn expand_home(s: &str, home: &str) -> String {
    if s == "~" {
        home.to_string()
    } else if let Some(rest) = s.strip_prefix("~/") {
        format!("{}/{}", home.trim_end_matches('/'), rest)
    } else {
        s.to_string()
    }
}

impl RuleSet {
    /// The rules shipped with Discky. Panics only if the embedded table is invalid.
    pub fn builtin() -> RuleSet {
        RuleSet::from_toml(BUILTIN).expect("embedded builtin.toml must be valid")
    }

    pub fn from_toml(s: &str) -> Result<RuleSet, RuleError> {
        let file: RuleFile = toml::from_str(s)?;
        let home = std::env::var("HOME").unwrap_or_default();
        let mut rules = file.rule;
        let mut by_id = HashMap::new();
        let mut by_path = HashMap::new();
        let mut builder = GlobSetBuilder::new();
        let mut glob_rules = Vec::new();

        for (i, rule) in rules.iter_mut().enumerate() {
            if by_id.insert(rule.id.clone(), i).is_some() {
                return Err(RuleError::Duplicate(rule.id.clone()));
            }
            match &mut rule.matcher {
                Matcher::Path { path } => {
                    let expanded = PathBuf::from(expand_home(&path.to_string_lossy(), &home));
                    *path = expanded.clone();
                    by_path.entry(expanded).or_insert(i);
                }
                Matcher::Glob { glob } => {
                    *glob = expand_home(glob, &home);
                    let compiled: Glob = GlobBuilder::new(glob)
                        .literal_separator(true)
                        .build()
                        .map_err(|source| RuleError::Glob {
                            id: rule.id.clone(),
                            glob: glob.clone(),
                            source,
                        })?;
                    builder.add(compiled);
                    glob_rules.push(i);
                }
                Matcher::BuildDir { .. } => {}
            }
        }
        let globs = builder.build().map_err(|source| RuleError::Glob {
            id: String::new(),
            glob: String::new(),
            source,
        })?;
        Ok(RuleSet {
            rules,
            by_id,
            by_path,
            globs,
            glob_rules,
        })
    }

    /// First hit among `Path` rules, then `Glob` rules in file order.
    /// `BuildDir` rules never match here; see [`RuleSet::build_rules`].
    pub fn match_path(&self, path: &Path) -> Option<&Rule> {
        if let Some(&i) = self.by_path.get(path) {
            return Some(&self.rules[i]);
        }
        self.globs
            .matches(path)
            .into_iter()
            .map(|g| self.glob_rules[g])
            .min()
            .map(|i| &self.rules[i])
    }

    pub fn build_rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules
            .iter()
            .filter(|r| matches!(r.matcher, Matcher::BuildDir { .. }))
    }

    pub fn get(&self, id: &str) -> Option<&Rule> {
        self.by_id.get(id).map(|&i| &self.rules[i])
    }
}
