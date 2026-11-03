//! The checked findings of a category view, keyed by [`FindingId`] so sorting, filtering
//! and rescans never change what is checked.

use std::collections::HashSet;
use std::path::PathBuf;

use discky_core::findings::{Finding, FindingId, Removal};
use discky_core::rules::SafetyLabel;

/// The set of checked findings.
#[derive(Default, Debug)]
pub struct Selection {
    ids: HashSet<FindingId>,
}

/// Totals of the checked findings, for the bottom bar.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SelectionSummary {
    /// How many checked findings are present.
    pub count: usize,
    /// Sum of `allocated`.
    pub allocated: u64,
    /// Sum of `freed_if_deleted`: what removing them gives back.
    pub frees: u64,
    /// The path of the first checked finding (in the given order) that has one.
    pub first_path: Option<PathBuf>,
}

/// Whether Discky may ever remove `f`: never a `DoNotTouch` finding or one without a
/// removal method.
pub fn is_checkable(f: &Finding) -> bool {
    f.label != SafetyLabel::DoNotTouch && f.removal != Removal::None
}

impl Selection {
    /// Check or uncheck `f`. Returns `false` (and changes nothing) for a finding that
    /// cannot be removed, see [`is_checkable`].
    pub fn toggle(&mut self, f: &Finding) -> bool {
        if !is_checkable(f) {
            return false;
        }
        if !self.ids.remove(&f.id) {
            self.ids.insert(f.id.clone());
        }
        true
    }

    /// Whether the finding `id` is checked.
    pub fn contains(&self, id: &FindingId) -> bool {
        self.ids.contains(id)
    }

    /// Drop checked ids that are no longer among `findings` (after a rescan or refresh).
    pub fn retain_present(&mut self, findings: &[Finding]) {
        let present: HashSet<&FindingId> = findings.iter().map(|f| &f.id).collect();
        self.ids.retain(|id| present.contains(id));
    }

    /// Uncheck everything.
    pub fn clear(&mut self) {
        self.ids.clear();
    }

    /// Totals of the checked findings among `findings`.
    pub fn summary(&self, findings: &[Finding]) -> SelectionSummary {
        let mut s = SelectionSummary::default();
        for f in findings.iter().filter(|f| self.ids.contains(&f.id)) {
            s.count += 1;
            s.allocated += f.allocated;
            s.frees += f.freed_if_deleted;
            if s.first_path.is_none() {
                s.first_path = f.path.clone();
            }
        }
        s
    }

    /// The checked ids as strings, sorted, for `Engine::plan`.
    pub fn ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.ids.iter().map(|id| id.0.clone()).collect();
        ids.sort();
        ids
    }
}

#[cfg(test)]
mod tests {
    // Explicit imports, like the crate's other test modules (see `app.rs`).
    use super::Selection;
    use crate::category::fixtures::finding;
    use crate::category::table::{SortBy, filter, sort};
    use discky_core::findings::Removal;
    use discky_core::rules::SafetyLabel;

    #[test]
    fn do_not_touch_is_not_selectable() {
        let mut sel = Selection::default();
        let mut keep = finding("a", "Keep me", 10);
        keep.label = SafetyLabel::DoNotTouch;
        assert!(!sel.toggle(&keep));
        assert!(!sel.contains(&keep.id));

        let mut no_removal = finding("b", "Seen only", 10);
        no_removal.removal = Removal::None;
        assert!(!sel.toggle(&no_removal));
        assert!(!sel.contains(&no_removal.id));

        let ok = finding("c", "Cache", 10);
        assert!(sel.toggle(&ok));
        assert!(sel.contains(&ok.id));
        assert!(sel.toggle(&ok));
        assert!(!sel.contains(&ok.id));
    }

    #[test]
    fn selection_survives_sort_and_filter() {
        let mut rows = vec![
            finding("a", "Alpha", 30),
            finding("b", "Beta x", 20),
            finding("c", "Gamma", 10),
        ];
        rows[0].modified = Some(300);
        rows[1].modified = Some(100);
        let mut sel = Selection::default();
        assert!(sel.toggle(&rows[0]));
        assert!(sel.toggle(&rows[2]));
        let (a, b, c) = (rows[0].id.clone(), rows[1].id.clone(), rows[2].id.clone());

        sort(&mut rows, SortBy::Age);
        let shown = filter(&rows, "x");
        assert_eq!(shown.len(), 1);
        assert!(sel.contains(&a));
        assert!(!sel.contains(&b));
        assert!(sel.contains(&c));

        // A rescan without "Gamma" drops only it.
        rows.retain(|f| f.id != c);
        sel.retain_present(&rows);
        assert!(sel.contains(&a));
        assert!(!sel.contains(&c));
        assert_eq!(sel.ids(), vec![a.0.clone()]);
    }

    #[test]
    fn summary_sums_frees_not_allocated() {
        let mut rows = vec![
            finding("a", "Alpha", 1_000),
            finding("b", "Beta", 2_000),
            finding("c", "Gamma", 4_000),
        ];
        rows[0].freed_if_deleted = 600;
        rows[1].freed_if_deleted = 2_000;
        rows[1].path = None;
        rows[2].freed_if_deleted = 4_000;
        let mut sel = Selection::default();
        sel.toggle(&rows[1]);
        sel.toggle(&rows[0]);
        let s = sel.summary(&rows);
        assert_eq!(s.count, 2);
        assert_eq!(s.allocated, 3_000);
        assert_eq!(s.frees, 2_600);
        assert_eq!(s.first_path, rows[0].path);

        sel.clear();
        assert_eq!(sel.summary(&rows).count, 0);
        assert!(sel.ids().is_empty());
    }
}
