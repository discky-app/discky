//! Which of a finding's components the inspector includes in its removal, free of GPUI.

use std::collections::HashSet;

use discky_core::PlanItem;
use discky_core::findings::{Component, ComponentKind, ComponentRemoval};
use discky_core::plan::parts_signature;

/// The checked components of one finding, by index into `Finding::components`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComponentSelection {
    on: HashSet<usize>,
}

impl ComponentSelection {
    /// The pre-checked selection: every component that is `default_on` and can be removed.
    pub fn from_components(components: &[Component]) -> Self {
        let on = (0..components.len())
            .filter(|&i| components[i].default_on && selectable(&components[i]))
            .collect();
        ComponentSelection { on }
    }

    /// Whether component `i` is checked.
    pub fn is_on(&self, i: usize) -> bool {
        self.on.contains(&i)
    }

    /// Check or uncheck component `i`; refused (false) for an index out of range or a
    /// component that is only shown. True when the selection changed.
    pub fn set(&mut self, i: usize, on: bool, components: &[Component]) -> bool {
        if !components.get(i).is_some_and(selectable) {
            return false;
        }
        if on {
            self.on.insert(i)
        } else {
            self.on.remove(&i)
        }
    }

    /// Flip component `i` (see [`ComponentSelection::set`]).
    pub fn toggle(&mut self, i: usize, components: &[Component]) -> bool {
        let on = !self.is_on(i);
        self.set(i, on, components)
    }

    /// Drop indices that no longer name a selectable component (fresh data after a scan).
    pub fn retain_valid(&mut self, components: &[Component]) {
        self.on
            .retain(|&i| components.get(i).is_some_and(selectable));
    }

    /// The plan request for finding `id` with exactly the checked components, ascending,
    /// signed with the `components` they index (the plan refuses it if they changed).
    pub fn items(&self, id: &str, components: &[Component]) -> PlanItem {
        let mut chosen: Vec<usize> = self.on.iter().copied().collect();
        chosen.sort_unstable();
        PlanItem {
            id: id.to_string(),
            components: Some(chosen),
            parts: Some(parts_signature(components)),
        }
    }

    /// How many components are checked and the bytes they free.
    pub fn summary(&self, components: &[Component]) -> (usize, u64) {
        self.on
            .iter()
            .filter_map(|&i| components.get(i))
            .fold((0, 0), |(n, bytes), c| (n + 1, bytes + c.freed_if_deleted))
    }
}

/// Whether `a` and `b` list the same parts in the same order (kind, path, removal), so
/// a selection made for one applies to the other.
pub fn same_parts(a: &[Component], b: &[Component]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| x.kind == y.kind && x.path == y.path && x.removal == y.removal)
}

/// Whether a selection made on the `shown` components still names the same parts in the
/// snapshot's `current` ones (`None`: the finding is gone).
pub fn selection_current(shown: &[Component], current: Option<&[Component]>) -> bool {
    current.is_some_and(|c| same_parts(shown, c))
}

/// Whether "Remove…" is available: the finding can be removed, it is not being refreshed
/// (its component indices could be stale), and when components can be checked at least
/// one is.
pub fn remove_enabled(
    checkable: bool,
    has_selectable: bool,
    count: usize,
    refreshing: bool,
) -> bool {
    checkable && !refreshing && (!has_selectable || count > 0)
}

/// Whether `c` can be part of a removal (not a shown-only component): trash, settings,
/// launch jobs, receipts and the vendor's uninstaller script (`RunScript`).
pub fn selectable(c: &Component) -> bool {
    c.removal != ComponentRemoval::None
}

/// The small muted tag of a component row ("Application Support", "LaunchAgent").
pub fn kind_label(kind: &ComponentKind) -> &'static str {
    match kind {
        ComponentKind::AppBundle => "Application",
        ComponentKind::ApplicationSupport => "Application Support",
        ComponentKind::Caches => "Caches",
        ComponentKind::Preferences => "Preferences",
        ComponentKind::Container => "Container",
        ComponentKind::GroupContainer => "Group Container",
        ComponentKind::SavedState => "Saved State",
        ComponentKind::HttpStorage => "HTTP Storage",
        ComponentKind::WebKit => "WebKit",
        ComponentKind::Cookies => "Cookies",
        ComponentKind::Logs => "Logs",
        ComponentKind::LaunchAgent => "LaunchAgent",
        ComponentKind::LaunchDaemon => "LaunchDaemon",
        ComponentKind::ApplicationScript => "Application Script",
        ComponentKind::PrivilegedHelper => "Privileged Helper",
        ComponentKind::Receipt => "Receipt",
        ComponentKind::OwnUninstaller => "Uninstaller",
        ComponentKind::Project => "Project",
        ComponentKind::Other => "Other",
    }
}

/// The kind tag shown next to `c`'s title; `None` when the title already says it
/// ("Application Support" titled "Application Support").
pub fn kind_tag(c: &Component) -> Option<&'static str> {
    let label = kind_label(&c.kind);
    (!c.title.eq_ignore_ascii_case(label)).then_some(label)
}

/// The muted note line under a component row: its own note, then "removed by brew zap"
/// when the cask's zap covers it, then "shown only" when it cannot be selected.
pub fn component_note(c: &Component) -> Option<String> {
    let mut parts: Vec<String> = c.note.iter().cloned().collect();
    if c.covered_by_cask {
        parts.push("removed by brew zap".to_string());
    }
    if !selectable(c) {
        parts.push("shown only".to_string());
    }
    (!parts.is_empty()).then(|| parts.join(" · "))
}

#[cfg(test)]
mod tests {
    use super::{ComponentSelection, component_note, kind_label};
    use discky_core::PlanItem;
    use discky_core::findings::{Component, ComponentKind, ComponentRemoval};
    use discky_core::plan::parts_signature;
    use std::path::PathBuf;

    fn comp(
        kind: ComponentKind,
        freed: u64,
        default_on: bool,
        removal: ComponentRemoval,
    ) -> Component {
        Component {
            title: format!("{kind:?}"),
            kind,
            path: Some(PathBuf::from("/tmp/x")),
            allocated: freed,
            freed_if_deleted: freed,
            modified: None,
            default_on,
            removal,
            note: None,
            covered_by_cask: false,
        }
    }

    /// Bundle (on), Application Support (on), Container (off), Keychain-like shown-only
    /// item that claims default_on, a Project (shown only, off).
    fn app() -> Vec<Component> {
        vec![
            comp(ComponentKind::AppBundle, 100, true, ComponentRemoval::Trash),
            comp(
                ComponentKind::ApplicationSupport,
                20,
                true,
                ComponentRemoval::Trash,
            ),
            comp(ComponentKind::Container, 5, false, ComponentRemoval::Trash),
            comp(ComponentKind::Other, 1, true, ComponentRemoval::None),
            comp(ComponentKind::Project, 0, false, ComponentRemoval::None),
        ]
    }

    #[test]
    fn defaults_from_default_on() {
        let s = ComponentSelection::from_components(&app());
        assert!(s.is_on(0));
        assert!(s.is_on(1));
        assert!(!s.is_on(2));
        // default_on but shown only: never pre-checked.
        assert!(!s.is_on(3));
        assert!(!s.is_on(4));
        assert_eq!(
            ComponentSelection::from_components(&[]),
            ComponentSelection::default()
        );
    }

    #[test]
    fn none_removal_cannot_be_selected() {
        let c = app();
        let mut s = ComponentSelection::from_components(&c);
        assert!(!s.toggle(3, &c));
        assert!(!s.is_on(3));
        assert!(!s.set(4, true, &c));
        assert!(!s.is_on(4));
        // Out of range is refused too.
        assert!(!s.toggle(9, &c));
        // Selectable ones flip both ways.
        assert!(s.toggle(2, &c));
        assert!(s.is_on(2));
        assert!(s.toggle(2, &c));
        assert!(!s.is_on(2));
        // Setting the current value is no change.
        assert!(!s.set(0, true, &c));
        assert!(s.set(0, false, &c));
        assert!(!s.is_on(0));
    }

    #[test]
    fn items_are_sorted_indices() {
        let c = app();
        let mut s = ComponentSelection::from_components(&c);
        s.toggle(2, &c);
        s.toggle(0, &c);
        assert_eq!(
            s.items("abc", &c),
            PlanItem {
                id: "abc".into(),
                components: Some(vec![1, 2]),
                parts: Some(parts_signature(&c)),
            }
        );
        s.set(1, false, &c);
        s.set(2, false, &c);
        assert_eq!(s.items("abc", &c).components, Some(vec![]));
    }

    #[test]
    fn items_carry_the_parts_signature() {
        let comps = app();
        let s = ComponentSelection::from_components(&comps);
        assert_eq!(s.items("id", &comps).parts, Some(parts_signature(&comps)));
        // Another component list (a reload re-mapped the indices) signs differently.
        assert_ne!(
            s.items("id", &comps[1..]).parts,
            Some(parts_signature(&comps))
        );
    }

    #[test]
    fn summary_sums_freed() {
        let c = app();
        let mut s = ComponentSelection::from_components(&c);
        assert_eq!(s.summary(&c), (2, 120));
        s.toggle(2, &c);
        assert_eq!(s.summary(&c), (3, 125));
        // An index that no longer exists counts for nothing and is dropped by retain_valid.
        let shorter = &c[..2];
        assert_eq!(s.summary(shorter), (2, 120));
        s.retain_valid(shorter);
        assert_eq!(s.items("x", shorter).components, Some(vec![0, 1]));
    }

    #[test]
    fn notes_explain_zap_and_shown_only() {
        let mut c = comp(ComponentKind::Caches, 1, true, ComponentRemoval::Trash);
        assert_eq!(component_note(&c), None);
        c.covered_by_cask = true;
        assert_eq!(component_note(&c).as_deref(), Some("removed by brew zap"));
        c.note = Some("needs administrator password".into());
        assert_eq!(
            component_note(&c).as_deref(),
            Some("needs administrator password · removed by brew zap")
        );
        let p = comp(ComponentKind::Project, 0, false, ComponentRemoval::None);
        assert_eq!(component_note(&p).as_deref(), Some("shown only"));
        assert_eq!(kind_label(&ComponentKind::LaunchAgent), "LaunchAgent");
        // The tag is left out when it repeats the title.
        let mut t = comp(
            ComponentKind::ApplicationSupport,
            0,
            true,
            ComponentRemoval::Trash,
        );
        t.title = "Application Support".into();
        assert_eq!(super::kind_tag(&t), None);
        t.title = "com.raycast.macos".into();
        assert_eq!(super::kind_tag(&t), Some("Application Support"));
        assert_eq!(
            kind_label(&ComponentKind::ApplicationSupport),
            "Application Support"
        );
    }

    #[test]
    fn own_uninstaller_script_is_checkable() {
        // Opt-in: not pre-checked.
        let mut script = comp(
            ComponentKind::OwnUninstaller,
            0,
            false,
            ComponentRemoval::RunScript,
        );
        script.note =
            Some("runs the vendor's uninstaller as you; it may ask for a password itself".into());
        let parts = vec![
            comp(ComponentKind::AppBundle, 100, true, ComponentRemoval::Trash),
            script,
        ];
        let mut s = ComponentSelection::from_components(&parts);
        assert!(!s.is_on(1));
        assert!(s.toggle(1, &parts));
        assert!(s.is_on(1));
        assert_eq!(
            component_note(&parts[1]).as_deref(),
            Some("runs the vendor's uninstaller as you; it may ask for a password itself")
        );
    }

    #[test]
    fn remove_disabled_while_loading() {
        use super::remove_enabled;
        assert!(remove_enabled(true, true, 2, false));
        assert!(!remove_enabled(true, true, 2, true));
        assert!(!remove_enabled(true, true, 0, false));
        assert!(!remove_enabled(false, true, 2, false));
        // A mise version: nothing selectable, still removable.
        assert!(remove_enabled(true, false, 0, false));
    }

    #[test]
    fn changed_parts_invalidate_the_selection() {
        use super::{same_parts, selection_current};
        let shown = app();
        let mut resized = app();
        resized[1].allocated = 999;
        resized[1].freed_if_deleted = 999;
        assert!(same_parts(&shown, &resized));
        assert!(selection_current(&shown, Some(&resized)));
        // Component 0 removed: every later index shifts.
        assert!(!selection_current(&shown, Some(&shown[1..])));
        let mut moved = app();
        moved.swap(1, 2);
        assert!(!selection_current(&shown, Some(&moved)));
        assert!(!selection_current(&shown, None));
    }
}
