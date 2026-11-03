//! The "What will run" text: every plan step in its shell form, with its notes.

use std::path::{Path, PathBuf};

use discky_core::plan::{Plan, Step, StepFlags, StepKind};

use crate::format;

/// One entry of the "What will run" block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandLine {
    /// The shell command; empty for a comment-only entry (a skipped finding).
    pub text: String,
    /// Shown muted above the command as `# …` lines: the step's flags ("needs
    /// administrator password", "permanent", "tool not installed: <hint>"), then its
    /// `freed_note`, then each remaining warning ("Homebrew zap skipped: …", a kept
    /// shared receipt, a protected settings domain), each on a line of its own.
    pub comment: Option<String>,
}

/// One [`CommandLine`] per step of `plan`, then one "skipped: <reason>" comment per
/// skipped finding.
pub fn command_lines(plan: &Plan) -> Vec<CommandLine> {
    let home = discky_core::paths::home_dir();
    let steps = plan.steps.iter().map(|step| {
        let mut notes = Vec::new();
        if step.flags.contains(StepFlags::INTERACTIVE) {
            notes.push("needs administrator password".to_string());
        }
        if step.flags.contains(StepFlags::GUI_ONLY) {
            notes.push(
                "runs the vendor's uninstaller as you; it may ask for a password itself"
                    .to_string(),
            );
        }
        if step.flags.contains(StepFlags::PERMANENT) {
            notes.push("permanent".to_string());
        }
        let mut warnings = step.warnings.iter();
        if step.flags.contains(StepFlags::TOOL_MISSING) {
            notes.push(match warnings.next() {
                Some(w) => format!("tool not installed: {w}"),
                None => "tool not installed".to_string(),
            });
        }
        let mut lines: Vec<String> = Vec::new();
        if !notes.is_empty() {
            lines.push(notes.join(" · "));
        }
        lines.extend(step.freed_note.iter().cloned());
        lines.extend(warnings.cloned());
        let comment = (!lines.is_empty()).then(|| lines.join("\n"));
        CommandLine {
            text: command_text_in(&step.kind, step.flags, home.as_deref()),
            comment,
        }
    });
    let skipped = plan.skipped.iter().map(|(_, reason)| CommandLine {
        text: String::new(),
        comment: Some(format!("skipped: {reason}")),
    });
    steps.chain(skipped).collect()
}

/// The shell form of `step` as it really runs, with paths shown relative to the home
/// directory: an `INTERACTIVE` Trash step goes through Finder, an `INTERACTIVE` Remove
/// step runs `rm -rf` behind an administrator prompt.
pub fn command_text_for(step: &Step) -> String {
    command_text_in(
        &step.kind,
        step.flags,
        discky_core::paths::home_dir().as_deref(),
    )
}

/// [`command_text_for`] with an explicit home directory (`None`: paths stay absolute).
fn command_text_in(kind: &StepKind, flags: StepFlags, home: Option<&Path>) -> String {
    let interactive = flags.contains(StepFlags::INTERACTIVE);
    let paths = |program: &str, paths: &[PathBuf]| {
        std::iter::once(program.to_string())
            .chain(paths.iter().map(|p| quote_path(p, home)))
            .collect::<Vec<_>>()
            .join(" ")
    };
    match kind {
        StepKind::Quit { bundle_id } => format!(
            "osascript -e {}",
            quote(&format!("tell application id \"{bundle_id}\" to quit"))
        ),
        StepKind::Trash { paths: p } if interactive => paths("Finder → Trash:", p),
        StepKind::Trash { paths: p } => paths("trash", p),
        StepKind::Remove { paths: p } if interactive => {
            format!("{}  # administrator prompt", paths("sudo rm -rf", p))
        }
        StepKind::Remove { paths: p } => paths("rm -rf", p),
        StepKind::Command { argv, cwd, env } => {
            let line = env
                .iter()
                .map(|(k, v)| format!("{k}={}", quote(v)))
                .chain(argv.iter().map(|a| quote(a)))
                .collect::<Vec<_>>()
                .join(" ");
            match cwd {
                Some(dir) => format!("cd {} && {line}", quote_path(dir, home)),
                None => line,
            }
        }
        StepKind::OllamaDelete { url, model } => {
            let body = serde_json::json!({ "model": model }).to_string();
            format!(
                "curl -X DELETE {}/api/delete -d {}",
                quote(url.trim_end_matches('/')),
                quote(&body)
            )
        }
    }
}

/// `arg` as one shell word: unchanged when it is safe bare, else in single quotes (an
/// embedded `'` becomes `'\''`). Quoted when empty or containing whitespace or `'"\$`.
fn quote(arg: &str) -> String {
    let unsafe_char = |c: char| c.is_whitespace() || matches!(c, '\'' | '"' | '\\' | '$');
    if !arg.is_empty() && !arg.contains(unsafe_char) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', r"'\''"))
}

/// `p` relative to `home` ("~/Library/Caches/x"), quoted like [`quote`]; the `~/` stays
/// outside the quotes so the shell still expands it (`~/'Application Support/X'`).
fn quote_path(p: &Path, home: Option<&Path>) -> String {
    let shown = match home {
        Some(home) => format::home_relative(p, home),
        None => p.to_string_lossy().into_owned(),
    };
    match shown.strip_prefix("~/") {
        Some(rest) => format!("~/{}", quote(rest)),
        None => quote(&shown),
    }
}

#[cfg(test)]
mod tests {
    use super::{CommandLine, command_lines, command_text_for, command_text_in};
    use discky_core::findings::FindingId;
    use discky_core::plan::{Plan, PlanId, Step, StepFlags, StepKind};
    use std::path::{Path, PathBuf};

    const HOME: &str = "/Users/me";

    fn text(kind: StepKind) -> String {
        command_text_in(&kind, StepFlags::empty(), Some(Path::new(HOME)))
    }

    fn step(kind: StepKind, flags: StepFlags, warnings: &[&str]) -> Step {
        Step {
            index: 0,
            finding: FindingId("f".into()),
            description: String::new(),
            kind,
            freed: Some(1),
            freed_note: None,
            flags,
            warnings: warnings.iter().map(|w| w.to_string()).collect(),
            fingerprints: Vec::new(),
            component: None,
        }
    }

    fn plan(steps: Vec<Step>, skipped: Vec<(&str, &str)>) -> Plan {
        Plan {
            id: PlanId("p".into()),
            created_at: 0,
            steps,
            total_freed: 0,
            skipped: skipped
                .into_iter()
                .map(|(id, r)| (FindingId(id.into()), r.into()))
                .collect(),
        }
    }

    fn command(argv: &[&str]) -> StepKind {
        StepKind::Command {
            argv: argv.iter().map(|a| a.to_string()).collect(),
            cwd: None,
            env: Vec::new(),
        }
    }

    #[test]
    fn command_text_quotes_args_with_spaces() {
        assert_eq!(
            text(command(&[
                "/opt/homebrew/bin/brew",
                "cleanup",
                "--prune=all"
            ])),
            "/opt/homebrew/bin/brew cleanup --prune=all"
        );
        assert_eq!(
            text(command(&[
                "tool",
                "two words",
                "it's",
                "$HOME",
                "a\"b",
                "back\\slash"
            ])),
            r#"tool 'two words' 'it'\''s' '$HOME' 'a"b' 'back\slash'"#
        );
        assert_eq!(text(command(&["tool", ""])), "tool ''");
    }

    #[test]
    fn command_text_runs_commands_in_their_directory() {
        let kind = StepKind::Command {
            argv: vec!["cargo".into(), "clean".into()],
            cwd: Some(PathBuf::from("/Users/me/My Projects/app")),
            env: Vec::new(),
        };
        assert_eq!(text(kind), "cd ~/'My Projects/app' && cargo clean");
    }

    #[test]
    fn command_text_forms() {
        assert_eq!(
            text(StepKind::Quit {
                bundle_id: "com.example.App".into()
            }),
            r#"osascript -e 'tell application id "com.example.App" to quit'"#
        );
        assert_eq!(
            text(StepKind::Trash {
                paths: vec![
                    PathBuf::from("/Users/me/Library/Caches/pnpm"),
                    PathBuf::from("/Users/me/Library/Application Support/X"),
                    PathBuf::from("/Library/Logs/Y Z"),
                ]
            }),
            "trash ~/Library/Caches/pnpm ~/'Library/Application Support/X' '/Library/Logs/Y Z'"
        );
        assert_eq!(
            text(StepKind::Remove {
                paths: vec![PathBuf::from("/Users/me/.cache/x")]
            }),
            "rm -rf ~/.cache/x"
        );
        assert_eq!(
            text(StepKind::OllamaDelete {
                url: "http://127.0.0.1:11434/".into(),
                model: "llama3:8b".into()
            }),
            r#"curl -X DELETE http://127.0.0.1:11434/api/delete -d '{"model":"llama3:8b"}'"#
        );
    }

    #[test]
    fn interactive_steps_show_their_real_route() {
        let home = Some(Path::new(HOME));
        let trash = StepKind::Trash {
            paths: vec![
                PathBuf::from("/Library/Logs/Y Z"),
                PathBuf::from("/Users/me/Library/Caches/x"),
            ],
        };
        assert_eq!(
            command_text_in(&trash, StepFlags::INTERACTIVE, home),
            "Finder → Trash: '/Library/Logs/Y Z' ~/Library/Caches/x"
        );
        let remove = StepKind::Remove {
            paths: vec![PathBuf::from("/Library/Logs/X")],
        };
        assert_eq!(
            command_text_in(&remove, StepFlags::INTERACTIVE | StepFlags::PERMANENT, home),
            "sudo rm -rf /Library/Logs/X  # administrator prompt"
        );
        // A Quit step is interactive too, but only asks the app.
        let quit = StepKind::Quit {
            bundle_id: "com.example.App".into(),
        };
        assert_eq!(
            command_text_in(&quit, StepFlags::INTERACTIVE, home),
            text(quit.clone())
        );
        let s = step(remove, StepFlags::INTERACTIVE, &[]);
        assert!(command_text_for(&s).starts_with("sudo rm -rf "));
    }

    #[test]
    fn command_lines_annotate_flags() {
        let p = plan(
            vec![
                step(
                    StepKind::Remove {
                        paths: vec![PathBuf::from("/Library/Logs/X")],
                    },
                    StepFlags::INTERACTIVE | StepFlags::PERMANENT,
                    &[],
                ),
                step(
                    command(&["uv", "cache", "clean"]),
                    StepFlags::TOOL_MISSING,
                    &["uv not found. brew install uv"],
                ),
                step(command(&["x"]), StepFlags::TOOL_MISSING, &[]),
                step(
                    StepKind::Trash {
                        paths: vec![PathBuf::from("/tmp/a")],
                    },
                    StepFlags::empty(),
                    &[],
                ),
            ],
            vec![],
        );
        let lines = command_lines(&p);
        assert_eq!(lines.len(), 4);
        let first = lines[0].comment.as_deref().unwrap();
        assert!(first.contains("needs administrator password"), "{first}");
        assert!(first.contains("permanent"), "{first}");
        assert_eq!(first, "needs administrator password · permanent");
        assert_eq!(
            lines[0].text,
            "sudo rm -rf /Library/Logs/X  # administrator prompt"
        );
        assert_eq!(
            lines[1].comment.as_deref(),
            Some("tool not installed: uv not found. brew install uv")
        );
        assert_eq!(lines[2].comment.as_deref(), Some("tool not installed"));
        assert_eq!(lines[3].comment, None);
    }

    #[test]
    fn command_lines_add_freed_note_and_skipped() {
        let mut s = step(
            command(&["docker", "system", "prune"]),
            StepFlags::empty(),
            &[],
        );
        s.freed_note = Some("Docker reports what it freed".into());
        let mut t = step(command(&["y"]), StepFlags::PERMANENT, &[]);
        t.freed_note = Some("note".into());
        let lines = command_lines(&plan(vec![s, t], vec![("abc", "Do not touch")]));
        assert_eq!(
            lines,
            vec![
                CommandLine {
                    text: "docker system prune".into(),
                    comment: Some("Docker reports what it freed".into()),
                },
                CommandLine {
                    text: "y".into(),
                    comment: Some("permanent\nnote".into()),
                },
                CommandLine {
                    text: String::new(),
                    comment: Some("skipped: Do not touch".into()),
                },
            ]
        );
    }

    #[test]
    fn command_lines_show_warnings_as_comments() {
        let mut s = step(
            command(&["/opt/homebrew/bin/brew", "uninstall", "--cask", "raycast"]),
            StepFlags::empty(),
            &["Homebrew zap skipped: it would also remove 2 paths not listed here"],
        );
        s.freed_note = Some("note".into());
        let t = step(
            command(&["mise", "uninstall", "node@20"]),
            StepFlags::TOOL_MISSING,
            &[
                "mise not found.",
                "Package x also installed Y.app; receipt kept",
            ],
        );
        let lines = command_lines(&plan(vec![s, t], vec![]));
        assert_eq!(
            lines[0].comment.as_deref(),
            Some("note\nHomebrew zap skipped: it would also remove 2 paths not listed here")
        );
        assert_eq!(
            lines[1].comment.as_deref(),
            Some(
                "tool not installed: mise not found.\nPackage x also installed Y.app; receipt kept"
            )
        );
    }
}
