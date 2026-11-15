//! Detects PsExec-style lateral movement: a network logon followed shortly by
//! a service installation on the same host.

use std::collections::HashMap;

use jiff::{SignedDuration, Timestamp};

use crate::detect::{Rule, non_empty};
use crate::model::{EventKind, EventRef, Flag, Severity, TimelineEvent};

/// Flags a `ServiceInstall` preceded within `window` by a non-loopback,
/// non-anonymous type-3 `LogonSuccess` on the same host.
pub struct RemoteLogonThenService {
    window: SignedDuration,
}

impl RemoteLogonThenService {
    pub fn new(window: SignedDuration) -> Self {
        Self { window }
    }
}

struct LogonInfo {
    ts: Timestamp,
    user: Option<String>,
    src_ip: String,
    event_ref: EventRef,
}

impl Rule for RemoteLogonThenService {
    fn id(&self) -> &'static str {
        "remote_logon_then_service"
    }

    fn apply(&self, events: &mut [TimelineEvent]) {
        if self.window.is_negative() {
            return;
        }

        let mut latest_by_host: HashMap<String, LogonInfo> = HashMap::new();
        // Separate cursor ensures equal-timestamp logons sorted after the
        // service event are still visible while keeping total work O(N).
        let mut logon_cursor = 0usize;

        for i in 0..events.len() {
            if events[i].kind != EventKind::ServiceInstall {
                continue;
            }
            let service_ts = events[i].ts;
            while logon_cursor < events.len() && events[logon_cursor].ts <= service_ts {
                if let Some(info) = qualifying_logon(&events[logon_cursor]) {
                    latest_by_host.insert(events[logon_cursor].host.to_ascii_lowercase(), info);
                }
                logon_cursor += 1;
            }

            let host_key = events[i].host.to_ascii_lowercase();
            let Some(logon) = latest_by_host.get(&host_key) else {
                continue;
            };
            let within_window = match service_ts.checked_sub(self.window) {
                Ok(cutoff) => logon.ts >= cutoff,
                Err(_) => true,
            };
            if within_window && logon.ts <= service_ts {
                let delta = service_ts.duration_since(logon.ts);
                let svc_name = non_empty(events[i].target.as_deref()).unwrap_or("unknown");
                let user = non_empty(logon.user.as_deref()).unwrap_or("unknown user");
                events[i].flags.push(Flag {
                    rule: self.id(),
                    severity: Severity::High,
                    reason: format!(
                        "Service \"{svc_name}\" installed {delta:#} after a network logon by {user} from {}",
                        logon.src_ip
                    ),
                    related: vec![logon.event_ref.clone()],
                });
            }
        }
    }
}

fn qualifying_logon(event: &TimelineEvent) -> Option<LogonInfo> {
    if event.kind != EventKind::LogonSuccess || event.logon_type != Some(3) {
        return None;
    }
    let ip = non_empty(event.src_ip.as_deref())?;
    if is_loopback(ip) || is_anonymous_logon(event.user.as_deref()) {
        return None;
    }
    Some(LogonInfo {
        ts: event.ts,
        user: event.user.clone(),
        src_ip: ip.to_owned(),
        event_ref: event.as_ref(),
    })
}

fn is_loopback(ip: &str) -> bool {
    ip == "127.0.0.1" || ip == "::1" || ip.starts_with("127.")
}

fn is_anonymous_logon(user: Option<&str>) -> bool {
    let Some(user) = user else {
        return false;
    };
    let name = user.rsplit_once('\\').map_or(user, |(_, name)| name);
    name.eq_ignore_ascii_case("ANONYMOUS LOGON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceKind;

    fn make_logon(
        ts_sec: i64,
        host: &str,
        logon_type: Option<u32>,
        ip: Option<&str>,
        user: Option<&str>,
        record_id: u64,
    ) -> TimelineEvent {
        let mut ev = TimelineEvent::new(
            Timestamp::from_second(ts_sec).unwrap(),
            host,
            SourceKind::Evtx,
            EventKind::LogonSuccess,
            "Security.evtx",
        );
        ev.channel = Some("Security".into());
        ev.record_id = Some(record_id);
        ev.logon_type = logon_type;
        ev.src_ip = ip.map(str::to_owned);
        ev.user = user.map(str::to_owned);
        ev
    }

    fn make_service(ts_sec: i64, host: &str, name: &str, record_id: u64) -> TimelineEvent {
        let mut ev = TimelineEvent::new(
            Timestamp::from_second(ts_sec).unwrap(),
            host,
            SourceKind::Evtx,
            EventKind::ServiceInstall,
            "System.evtx",
        );
        ev.channel = Some("System".into());
        ev.record_id = Some(record_id);
        ev.target = Some(name.into());
        ev
    }

    #[test]
    fn flags_service_shortly_after_network_logon_case_insensitive_host() {
        let rule = RemoteLogonThenService::new(SignedDuration::from_mins(5));
        let mut events = vec![
            make_logon(
                1000,
                "WS01",
                Some(3),
                Some("10.0.0.5"),
                Some(r"CORP\alice"),
                11,
            ),
            make_logon(
                1002,
                "WS01",
                Some(3),
                Some("10.0.0.9"),
                Some(r"CORP\bob"),
                12,
            ),
            make_service(1006, "ws01", "PSEXESVC", 99),
        ];

        rule.apply(&mut events);

        assert_eq!(events[2].flags.len(), 1);
        let flag = &events[2].flags[0];
        assert_eq!(flag.rule, "remote_logon_then_service");
        assert_eq!(flag.severity, Severity::High);
        assert_eq!(
            flag.reason,
            r#"Service "PSEXESVC" installed 4s after a network logon by CORP\bob from 10.0.0.9"#
        );
        assert_eq!(flag.related, vec![events[1].as_ref()]);
    }

    #[test]
    fn flags_exactly_at_window_edge_and_ignores_one_second_outside() {
        let rule = RemoteLogonThenService::new(SignedDuration::from_secs(300));
        let mut at_edge = vec![
            make_logon(
                1000,
                "H1",
                Some(3),
                Some("10.0.0.5"),
                Some(r"CORP\alice"),
                1,
            ),
            make_service(1300, "H1", "SVC", 2),
        ];
        rule.apply(&mut at_edge);
        assert_eq!(at_edge[1].flags.len(), 1);

        let mut outside = vec![
            make_logon(
                1000,
                "H1",
                Some(3),
                Some("10.0.0.5"),
                Some(r"CORP\alice"),
                1,
            ),
            make_service(1301, "H1", "SVC", 2),
        ];
        rule.apply(&mut outside);
        assert!(outside[1].flags.is_empty());
    }

    #[test]
    fn ignores_wrong_host_and_logon_after_service() {
        let rule = RemoteLogonThenService::new(SignedDuration::from_mins(5));
        let mut events = vec![
            make_logon(
                1000,
                "OTHER",
                Some(3),
                Some("10.0.0.5"),
                Some(r"CORP\alice"),
                1,
            ),
            make_service(1005, "TARGET", "SVC", 2),
            make_logon(
                1006,
                "TARGET",
                Some(3),
                Some("10.0.0.5"),
                Some(r"CORP\alice"),
                3,
            ),
        ];
        rule.apply(&mut events);
        assert!(events[1].flags.is_empty());
    }

    #[test]
    fn ignores_loopback_missing_ip_wrong_logon_type_and_anonymous_logon() {
        let rule = RemoteLogonThenService::new(SignedDuration::from_mins(5));
        let mut events = vec![
            make_logon(
                1000,
                "H1",
                Some(3),
                Some("127.0.0.1"),
                Some(r"CORP\alice"),
                1,
            ),
            make_logon(
                1001,
                "H1",
                Some(3),
                Some("127.0.1.1"),
                Some(r"CORP\alice"),
                2,
            ),
            make_logon(1002, "H1", Some(3), Some("::1"), Some(r"CORP\alice"), 3),
            make_logon(1003, "H1", Some(3), None, Some(r"CORP\alice"), 4),
            make_logon(
                1004,
                "H1",
                Some(2),
                Some("10.0.0.5"),
                Some(r"CORP\alice"),
                5,
            ),
            make_logon(
                1005,
                "H1",
                Some(3),
                Some("10.0.0.5"),
                Some(r"NT AUTHORITY\anonymous logon"),
                6,
            ),
            make_logon(
                1006,
                "H1",
                Some(3),
                Some("10.0.0.5"),
                Some("ANONYMOUS LOGON"),
                7,
            ),
            make_service(1010, "H1", "SVC", 8),
        ];
        rule.apply(&mut events);
        assert!(events[7].flags.is_empty());
    }

    #[test]
    fn matches_equal_timestamp_logon_even_if_ordered_after_service_and_skips_ignored_later_logon() {
        let rule = RemoteLogonThenService::new(SignedDuration::from_mins(5));
        let mut events = vec![
            make_logon(995, "H1", Some(3), Some("10.0.0.5"), Some(r"CORP\alice"), 1),
            // Loopback logon right after must not overwrite the qualifying logon.
            make_logon(998, "H1", Some(3), Some("127.0.0.1"), Some(r"CORP\bob"), 2),
            make_service(1000, "H1", "SVC1", 3),
            // Equal-timestamp logon sorted after SVC2.
            make_service(2000, "H2", "SVC2", 4),
            make_logon(
                2000,
                "H2",
                Some(3),
                Some("10.0.0.8"),
                Some(r"CORP\carol"),
                5,
            ),
        ];
        rule.apply(&mut events);
        assert_eq!(events[2].flags.len(), 1);
        assert_eq!(events[2].flags[0].related, vec![events[0].as_ref()]);
        assert_eq!(events[3].flags.len(), 1);
        assert_eq!(events[3].flags[0].related, vec![events[4].as_ref()]);
    }
}
