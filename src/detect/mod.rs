//! Detection rules. Each rule walks the sorted timeline and attaches flags.

pub mod encoded_powershell;
pub mod extras;
pub mod remote_logon_service;

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
pub fn default_rules(options: &DetectOptions) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(remote_logon_service::RemoteLogonThenService::new(
            options.window,
        )),
        Box::new(encoded_powershell::EncodedPowershell),
        Box::new(extras::LogCleared),
        Box::new(extras::ServiceSuspiciousPath),
        Box::new(extras::FailedLogonBurst::new(
            options.window,
            options.burst_threshold,
        )),
        Box::new(extras::LogonAfterFailedBurst::new(
            options.window,
            options.burst_threshold,
        )),
        Box::new(extras::ExecFromTmp),
    ]
}

/// Runs the rules in order over a sorted timeline.
pub fn run(events: &mut [TimelineEvent], rules: &[Box<dyn Rule>]) {
    for rule in rules {
        rule.apply(events);
    }
}

pub(crate) fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use jiff::Timestamp;

    use super::*;
    use crate::model::{EventKind, SourceKind};

    #[test]
    fn default_rules_returns_each_rule_id_exactly_once() {
        let rules = default_rules(&DetectOptions::default());
        let ids: Vec<&'static str> = rules.iter().map(|r| r.id()).collect();
        let unique: HashSet<&'static str> = ids.iter().copied().collect();

        assert_eq!(
            ids.len(),
            unique.len(),
            "duplicate rule id in default_rules"
        );
        assert_eq!(
            unique,
            HashSet::from([
                "remote_logon_then_service",
                "encoded_powershell",
                "log_cleared",
                "service_suspicious_path",
                "failed_logon_burst",
                "logon_after_failed_burst",
                "exec_from_tmp",
            ])
        );
    }

    #[test]
    fn run_preserves_event_order() {
        let t0 = Timestamp::from_second(1_700_000_000).unwrap();
        let t1 = Timestamp::from_second(1_700_000_010).unwrap();
        let t2 = Timestamp::from_second(1_700_000_020).unwrap();

        let mut e0 = TimelineEvent::new(t0, "SRV1", SourceKind::Evtx, EventKind::LogonSuccess, "a");
        e0.record_id = Some(10);
        e0.logon_type = Some(3);
        e0.src_ip = Some("10.0.0.5".into());
        e0.user = Some("CORP\\alice".into());

        let mut e1 =
            TimelineEvent::new(t1, "SRV1", SourceKind::Evtx, EventKind::ServiceInstall, "b");
        e1.record_id = Some(20);
        e1.target = Some("PSEXESVC".into());
        e1.command_line = Some(r"cmd.exe /c powershell -enc SQBFAFgAKAApAA==".into());

        let mut e2 = TimelineEvent::new(t2, "SRV1", SourceKind::Evtx, EventKind::LogClear, "c");
        e2.record_id = Some(30);
        e2.user = Some("CORP\\alice".into());

        let mut events = vec![e0, e1, e2];
        let rules = default_rules(&DetectOptions::default());
        run(&mut events, &rules);

        let record_ids: Vec<_> = events.iter().map(|e| e.record_id).collect();
        assert_eq!(record_ids, vec![Some(10), Some(20), Some(30)]);
        assert!(events[0].flags.is_empty());
        assert!(!events[1].flags.is_empty());
        assert_eq!(events[2].flags.len(), 1);
    }
}
