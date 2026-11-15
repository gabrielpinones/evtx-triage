//! Detection rules. Each rule walks the sorted timeline and attaches flags.

use jiff::SignedDuration;

use crate::model::TimelineEvent;

/// Tunables shared by the rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectOptions {
    /// How far back a correlation rule looks for the earlier event.
    pub window: SignedDuration,
    /// Failed logons from one origin inside the window that count as a burst.
    pub burst_threshold: usize,
}

impl Default for DetectOptions {
    fn default() -> Self {
        Self {
            window: SignedDuration::from_mins(5),
            burst_threshold: 5,
        }
    }
}

/// A detection rule.
///
/// `apply` receives the whole timeline sorted by `TimelineEvent::sort_key` and
/// pushes onto `TimelineEvent::flags`. It must not reorder, add or remove
/// events.
pub trait Rule {
    /// Stable id written to `Flag::rule`.
    fn id(&self) -> &'static str;
    fn apply(&self, events: &mut [TimelineEvent]);
}

/// Every built-in rule, configured with `options`.
pub fn default_rules(_options: &DetectOptions) -> Vec<Box<dyn Rule>> {
    Vec::new()
}

/// Runs the rules in order over a sorted timeline.
pub fn run(events: &mut [TimelineEvent], rules: &[Box<dyn Rule>]) {
    for rule in rules {
        rule.apply(events);
    }
}
