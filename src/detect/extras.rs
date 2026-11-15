//! Additional triage rules: audit log clearing, suspicious service paths,
//! failed logon bursts, successful logons after bursts, and execution from
//! world-writable directories.

use std::collections::{HashMap, VecDeque};

use jiff::{SignedDuration, Timestamp};

use crate::detect::{Rule, non_empty};
use crate::model::{EventKind, EventRef, Flag, Severity, SourceKind, TimelineEvent};

const SUSPICIOUS_SERVICE_PATTERNS: &[&str] = &[
    r"\temp\",
    r"\appdata\",
    r"\users\public\",
    r"\programdata\",
    "admin$",
    "%comspec%",
    "cmd.exe /c",
    "cmd /c",
    "powershell",
    "pwsh",
    "rundll32",
    "regsvr32",
    "mshta",
    r"\\.\pipe\",
];

const TMP_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/"];

/// Programs that run the script given as their first non-option argument.
const INTERPRETERS: &[&str] = &[
    "sh", "bash", "dash", "zsh", "ksh", "python", "python2", "python3", "perl", "ruby", "php",
    "node",
];

/// Flags every `LogClear` event.
pub struct LogCleared;

impl Rule for LogCleared {
    fn id(&self) -> &'static str {
        "log_cleared"
    }

    fn apply(&self, events: &mut [TimelineEvent]) {
        for event in events {
            if event.kind != EventKind::LogClear {
                continue;
            }
            let reason = match non_empty(event.user.as_deref()) {
                Some(user) => format!("Security audit log cleared by {user}"),
                None => "Security audit log cleared by an unknown user".to_owned(),
            };
            event.flags.push(Flag {
                rule: self.id(),
                severity: Severity::High,
                reason,
                related: Vec::new(),
            });
        }
    }
}

/// Flags `ServiceInstall` events whose image path points to a suspicious
/// directory, interpreter, named pipe or UNC share.
pub struct ServiceSuspiciousPath;

impl Rule for ServiceSuspiciousPath {
    fn id(&self) -> &'static str {
        "service_suspicious_path"
    }

    fn apply(&self, events: &mut [TimelineEvent]) {
        for event in events {
            if event.kind != EventKind::ServiceInstall {
                continue;
            }
            let Some(cmd) = non_empty(event.command_line.as_deref()) else {
                continue;
            };
            let lower = cmd.to_lowercase();
            let matched = SUSPICIOUS_SERVICE_PATTERNS
                .iter()
                .copied()
                .find(|pat| lower.contains(pat))
                .or_else(|| is_unc_path(&lower).then_some("UNC path"));

            let Some(pattern) = matched else {
                continue;
            };
            let svc_name = non_empty(event.target.as_deref()).unwrap_or("unknown");
            event.flags.push(Flag {
                rule: self.id(),
                severity: Severity::Medium,
                reason: format!(
                    "Service \"{svc_name}\" runs from a suspicious location or interpreter: {pattern}"
                ),
                related: Vec::new(),
            });
        }
    }
}

fn is_unc_path(lower_cmd: &str) -> bool {
    let trimmed = lower_cmd.trim_start();
    let unquoted = trimmed.strip_prefix('"').unwrap_or(trimmed);
    if unquoted.starts_with(r"\\.\") || unquoted.starts_with(r"\\?\") {
        return false;
    }
    let Some(after_slashes) = unquoted.strip_prefix(r"\\") else {
        return false;
    };
    after_slashes
        .split_once('\\')
        .is_some_and(|(host, share)| !host.is_empty() && !share.is_empty())
}

/// Flags the event that reaches `burst_threshold` failed logons from the same
/// origin on the same host within `window`, at most once until the window
/// empties.
pub struct FailedLogonBurst {
    window: SignedDuration,
    burst_threshold: usize,
}

impl FailedLogonBurst {
    pub fn new(window: SignedDuration, burst_threshold: usize) -> Self {
        Self {
            window,
            burst_threshold,
        }
    }
}

#[derive(Default)]
struct FailureBurstState {
    timestamps: VecDeque<Timestamp>,
    flagged_in_window: bool,
}

impl Rule for FailedLogonBurst {
    fn id(&self) -> &'static str {
        "failed_logon_burst"
    }

    fn apply(&self, events: &mut [TimelineEvent]) {
        if self.window.is_negative() || self.burst_threshold == 0 {
            return;
        }

        let mut states: HashMap<(String, String), FailureBurstState> = HashMap::new();

        for event in events {
            if event.kind != EventKind::LogonFailure {
                continue;
            }
            let Some(origin) = burst_origin(event) else {
                continue;
            };
            let key = (event.host.to_ascii_lowercase(), origin.to_owned());
            let state = states.entry(key).or_default();

            prune_older(&mut state.timestamps, event.ts, self.window);
            if state.timestamps.is_empty() {
                state.flagged_in_window = false;
            }
            state.timestamps.push_back(event.ts);

            if !state.flagged_in_window && state.timestamps.len() >= self.burst_threshold {
                state.flagged_in_window = true;
                let count = state.timestamps.len();
                let reason = match non_empty(event.user.as_deref()) {
                    Some(user) => format!(
                        "{count} failed logons from {origin} within {:#} (last user: {user})",
                        self.window
                    ),
                    None => format!(
                        "{count} failed logons from {origin} within {:#}",
                        self.window
                    ),
                };
                event.flags.push(Flag {
                    rule: self.id(),
                    severity: Severity::Medium,
                    reason,
                    related: Vec::new(),
                });
            }
        }
    }
}

/// Flags the first `LogonSuccess` on a host from an origin that produced a
/// failed-logon burst, within `window` after the last failure of that burst.
pub struct LogonAfterFailedBurst {
    window: SignedDuration,
    burst_threshold: usize,
}

impl LogonAfterFailedBurst {
    pub fn new(window: SignedDuration, burst_threshold: usize) -> Self {
        Self {
            window,
            burst_threshold,
        }
    }
}

#[derive(Default)]
struct BurstSuccessState {
    failures: VecDeque<Timestamp>,
    burst_active: bool,
    burst_count: usize,
    last_failure: Option<(Timestamp, EventRef)>,
    success_flagged: bool,
}

impl Rule for LogonAfterFailedBurst {
    fn id(&self) -> &'static str {
        "logon_after_failed_burst"
    }

    fn apply(&self, events: &mut [TimelineEvent]) {
        if self.window.is_negative() || self.burst_threshold == 0 {
            return;
        }

        let mut states: HashMap<(String, String), BurstSuccessState> = HashMap::new();

        for event in events {
            match event.kind {
                EventKind::LogonFailure => {
                    let Some(origin) = network_origin(event) else {
                        continue;
                    };
                    let key = (event.host.to_ascii_lowercase(), origin.to_owned());
                    let state = states.entry(key).or_default();

                    prune_older(&mut state.failures, event.ts, self.window);
                    if state.failures.is_empty() {
                        state.burst_active = false;
                        state.burst_count = 0;
                        state.success_flagged = false;
                    }
                    state.failures.push_back(event.ts);
                    state.burst_count = state.burst_count.saturating_add(1);
                    state.last_failure = Some((event.ts, event.as_ref()));
                    if !state.burst_active && state.failures.len() >= self.burst_threshold {
                        state.burst_active = true;
                    }
                }
                EventKind::LogonSuccess => {
                    let Some(origin) = network_origin(event) else {
                        continue;
                    };
                    let key = (event.host.to_ascii_lowercase(), origin.to_owned());
                    let Some(state) = states.get_mut(&key) else {
                        continue;
                    };
                    if !state.burst_active || state.success_flagged {
                        continue;
                    }
                    let Some((last_ts, last_ref)) = &state.last_failure else {
                        continue;
                    };
                    let within_window = match event.ts.checked_sub(self.window) {
                        Ok(cutoff) => *last_ts >= cutoff,
                        Err(_) => true,
                    };
                    if within_window && *last_ts <= event.ts {
                        let user = non_empty(event.user.as_deref()).unwrap_or("unknown user");
                        event.flags.push(Flag {
                            rule: self.id(),
                            severity: Severity::High,
                            reason: format!(
                                "Successful logon by {user} from {origin} after {} failed attempts",
                                state.burst_count
                            ),
                            related: vec![last_ref.clone()],
                        });
                        state.success_flagged = true;
                    }
                }
                _ => {}
            }
        }
    }
}

/// Flags Linux process executions originating from `/tmp`, `/var/tmp` or
/// `/dev/shm`.
pub struct ExecFromTmp;

impl Rule for ExecFromTmp {
    fn id(&self) -> &'static str {
        "exec_from_tmp"
    }

    fn apply(&self, events: &mut [TimelineEvent]) {
        for event in events {
            if !matches!(event.source, SourceKind::Auditd | SourceKind::Journald)
                || !matches!(
                    event.kind,
                    EventKind::ProcessCreate | EventKind::PrivilegedCommand
                )
            {
                continue;
            }
            let Some(path) = tmp_exec_path(event) else {
                continue;
            };
            event.flags.push(Flag {
                rule: self.id(),
                severity: Severity::Medium,
                reason: format!("Execution from a world-writable directory: {path}"),
                related: Vec::new(),
            });
        }
    }
}

fn tmp_exec_path(event: &TimelineEvent) -> Option<String> {
    if let Some(proc_path) = non_empty(event.process.as_deref())
        && starts_with_tmp(proc_path)
    {
        return Some(proc_path.to_owned());
    }
    let first_tok = event
        .command_line
        .as_deref()
        .and_then(|cmd| cmd.split_whitespace().next())
        .map(|tok| {
            let unquoted = tok.strip_prefix('"').unwrap_or(tok);
            if tok.starts_with('"') {
                unquoted.strip_suffix('"').unwrap_or(unquoted)
            } else {
                unquoted
            }
        });
    if let Some(tok) = first_tok {
        if starts_with_tmp(tok) {
            return Some(tok.to_owned());
        }
        // `/bin/bash /tmp/x.sh`: the interpreter is a trusted binary, the
        // script is what runs from the writable directory.
        let program = tok.rsplit('/').next().unwrap_or(tok);
        if INTERPRETERS.contains(&program)
            && let Some(script) = event
                .command_line
                .as_deref()
                .and_then(|cmd| {
                    cmd.split_whitespace()
                        .skip(1)
                        .find(|arg| !arg.starts_with('-'))
                })
                .map(|arg| arg.trim_matches('"'))
            && starts_with_tmp(script)
        {
            return Some(script.to_owned());
        }
        if let Some(rel) = tok.strip_prefix("./")
            && let Some(cwd) = event
                .details
                .get("cwd")
                .and_then(|v| v.as_str())
                .and_then(|s| non_empty(Some(s)))
            && is_tmp_dir(cwd)
        {
            return Some(format!("{}/{}", cwd.trim_end_matches('/'), rel));
        }
    }
    None
}

fn starts_with_tmp(path: &str) -> bool {
    TMP_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

fn is_tmp_dir(dir: &str) -> bool {
    matches!(dir, "/tmp" | "/var/tmp" | "/dev/shm")
        || TMP_PREFIXES.iter().any(|prefix| dir.starts_with(prefix))
}

fn network_origin(event: &TimelineEvent) -> Option<&str> {
    non_empty(event.src_ip.as_deref()).or_else(|| {
        event
            .details
            .get("workstation")
            .and_then(|v| v.as_str())
            .and_then(|s| non_empty(Some(s)))
    })
}

fn burst_origin(event: &TimelineEvent) -> Option<&str> {
    network_origin(event).or_else(|| non_empty(event.user.as_deref()))
}

fn prune_older(queue: &mut VecDeque<Timestamp>, now: Timestamp, window: SignedDuration) {
    let Ok(cutoff) = now.checked_sub(window) else {
        return;
    };
    while let Some(&front) = queue.front() {
        if front < cutoff {
            queue.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exec_from_tmp_sees_a_script_run_through_an_interpreter() {
        use crate::detect::Rule as _;
        use crate::model::{EventKind, SourceKind, TimelineEvent};

        let ts = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        let mut script =
            TimelineEvent::new(ts, "h", SourceKind::Auditd, EventKind::ProcessCreate, "f");
        script.process = Some("/bin/bash".into());
        script.command_line = Some("/bin/bash -x /tmp/x.sh \"secret payload\"".into());
        let mut inline = script.clone();
        inline.command_line = Some("/bin/bash -c /usr/bin/id".into());
        let mut events = [script, inline];
        super::ExecFromTmp.apply(&mut events);
        assert_eq!(events[0].flags.len(), 1);
        assert!(events[0].flags[0].reason.ends_with("/tmp/x.sh"));
        assert!(events[1].flags.is_empty());
    }

    use serde_json::Value;

    use super::*;

    fn ts(sec: i64) -> Timestamp {
        Timestamp::from_second(sec).unwrap()
    }

    fn failure(
        sec: i64,
        host: &str,
        ip: Option<&str>,
        workstation: Option<&str>,
        user: Option<&str>,
        record_id: u64,
    ) -> TimelineEvent {
        let mut ev = TimelineEvent::new(
            ts(sec),
            host,
            SourceKind::Evtx,
            EventKind::LogonFailure,
            "Security.evtx",
        );
        ev.channel = Some("Security".into());
        ev.record_id = Some(record_id);
        ev.src_ip = ip.map(str::to_owned);
        ev.user = user.map(str::to_owned);
        if let Some(ws) = workstation {
            ev.details
                .insert("workstation".into(), Value::String(ws.to_owned()));
        }
        ev
    }

    fn success(
        sec: i64,
        host: &str,
        ip: Option<&str>,
        workstation: Option<&str>,
        user: Option<&str>,
        record_id: u64,
    ) -> TimelineEvent {
        let mut ev = TimelineEvent::new(
            ts(sec),
            host,
            SourceKind::Evtx,
            EventKind::LogonSuccess,
            "Security.evtx",
        );
        ev.channel = Some("Security".into());
        ev.record_id = Some(record_id);
        ev.src_ip = ip.map(str::to_owned);
        ev.user = user.map(str::to_owned);
        if let Some(ws) = workstation {
            ev.details
                .insert("workstation".into(), Value::String(ws.to_owned()));
        }
        ev
    }

    #[test]
    fn log_cleared_flags_known_and_unknown_user() {
        let mut known = TimelineEvent::new(
            ts(100),
            "DC01",
            SourceKind::Evtx,
            EventKind::LogClear,
            "Security.evtx",
        );
        known.user = Some(r"CORP\admin".into());

        let unknown = TimelineEvent::new(
            ts(101),
            "DC01",
            SourceKind::Evtx,
            EventKind::LogClear,
            "Security.evtx",
        );
        let other = TimelineEvent::new(
            ts(102),
            "DC01",
            SourceKind::Evtx,
            EventKind::LogonSuccess,
            "Security.evtx",
        );

        let mut events = vec![known, unknown, other];
        LogCleared.apply(&mut events);

        assert_eq!(events[0].flags.len(), 1);
        assert_eq!(events[0].flags[0].severity, Severity::High);
        assert_eq!(
            events[0].flags[0].reason,
            r"Security audit log cleared by CORP\admin"
        );
        assert_eq!(events[1].flags.len(), 1);
        assert_eq!(
            events[1].flags[0].reason,
            "Security audit log cleared by an unknown user"
        );
        assert!(events[2].flags.is_empty());
    }

    #[test]
    fn service_suspicious_path_flags_patterns_and_unc_but_not_benign() {
        let cases = [
            (r"C:\Users\bob\AppData\Local\Temp\evil.exe", Some(r"\temp\")),
            (
                r"C:\Windows\System32\cmd.exe /c powershell -nop",
                Some("cmd.exe /c"),
            ),
            (r"\\10.0.0.5\share\svc.exe", Some("UNC path")),
            (r"\\.\pipe\my_pipe", Some(r"\\.\pipe\")),
            (r"\\?\C:\Program Files\Legit\svc.exe", None),
            (r"\\.\PhysicalDrive0", None),
            (r"C:\Windows\System32\svchost.exe -k netsvcs", None),
        ];

        let mut events: Vec<TimelineEvent> = cases
            .iter()
            .enumerate()
            .map(|(idx, (cmd, _))| {
                let mut ev = TimelineEvent::new(
                    ts(100 + idx as i64),
                    "WS01",
                    SourceKind::Evtx,
                    EventKind::ServiceInstall,
                    "System.evtx",
                );
                ev.target = Some("x".into());
                ev.command_line = Some((*cmd).to_owned());
                ev
            })
            .collect();

        ServiceSuspiciousPath.apply(&mut events);

        for (idx, (_, expected)) in cases.iter().enumerate() {
            match expected {
                Some(pat) => {
                    assert_eq!(events[idx].flags.len(), 1, "case {idx} should flag");
                    assert_eq!(events[idx].flags[0].severity, Severity::Medium);
                    assert_eq!(
                        events[idx].flags[0].reason,
                        format!(
                            "Service \"x\" runs from a suspicious location or interpreter: {pat}"
                        )
                    );
                }
                None => assert!(
                    events[idx].flags.is_empty(),
                    "case {idx} should not flag: {:?}",
                    events[idx].flags
                ),
            }
        }
    }

    #[test]
    fn failed_logon_burst_flags_once_per_burst_and_rearms_after_window_empties() {
        let rule = FailedLogonBurst::new(SignedDuration::from_mins(2), 5);
        let mut events = vec![
            // First burst (5 failures within 2m, plus 2 extra in same window).
            failure(0, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 1),
            failure(20, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 2),
            failure(40, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 3),
            failure(60, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 4),
            failure(80, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 5),
            failure(90, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 6),
            failure(100, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 7),
            // Window empties after >120s since t=100 (at t=221s).
            failure(221, "DC01", Some("10.0.0.5"), None, Some(r"CORP\bob"), 8),
            failure(222, "DC01", Some("10.0.0.5"), None, Some(r"CORP\bob"), 9),
            failure(223, "DC01", Some("10.0.0.5"), None, Some(r"CORP\bob"), 10),
            failure(224, "DC01", Some("10.0.0.5"), None, Some(r"CORP\bob"), 11),
            failure(225, "DC01", Some("10.0.0.5"), None, Some(r"CORP\bob"), 12),
        ];

        rule.apply(&mut events);

        let flagged: Vec<usize> = events
            .iter()
            .enumerate()
            .filter_map(|(i, e)| (!e.flags.is_empty()).then_some(i))
            .collect();
        assert_eq!(flagged, vec![4, 11]);
        assert_eq!(
            events[4].flags[0].reason,
            r"5 failed logons from 10.0.0.5 within 2m (last user: CORP\alice)"
        );
        assert_eq!(
            events[11].flags[0].reason,
            r"5 failed logons from 10.0.0.5 within 2m (last user: CORP\bob)"
        );
    }

    #[test]
    fn failed_logon_burst_edge_cases_threshold_minus_one_window_edge_and_origin_fallback() {
        let rule = FailedLogonBurst::new(SignedDuration::from_secs(60), 5);
        let mut events = vec![
            // Threshold minus one (4 failures) -> no flag.
            failure(0, "H1", Some("10.0.0.1"), None, Some("u1"), 1),
            failure(10, "H1", Some("10.0.0.1"), None, Some("u1"), 2),
            failure(20, "H1", Some("10.0.0.1"), None, Some("u1"), 3),
            failure(30, "H1", Some("10.0.0.1"), None, Some("u1"), 4),
            // 5th failure 61s after 1st: 1st expires so only 4 remain in window -> no flag.
            failure(61, "H1", Some("10.0.0.1"), None, Some("u1"), 5),
            // Different host does not combine.
            failure(62, "H2", Some("10.0.0.1"), None, Some("u1"), 6),
            // Origin fallback to workstation, then user; none is ignored.
            failure(100, "H3", None, Some("WS-A"), None, 7),
            failure(101, "H3", None, Some("WS-A"), None, 8),
            failure(102, "H3", None, Some("WS-A"), None, 9),
            failure(103, "H3", None, Some("WS-A"), None, 10),
            failure(160, "H3", None, Some("WS-A"), None, 11),
            // Ignored (no src_ip, workstation, or user).
            failure(200, "H4", None, None, None, 12),
            failure(201, "H4", None, None, None, 13),
            failure(202, "H4", None, None, None, 14),
            failure(203, "H4", None, None, None, 15),
            failure(204, "H4", None, None, None, 16),
        ];

        rule.apply(&mut events);

        let flagged: Vec<usize> = events
            .iter()
            .enumerate()
            .filter_map(|(i, e)| (!e.flags.is_empty()).then_some(i))
            .collect();
        // Index 10 is exactly 60s after index 6 (at the window edge -> inside!).
        assert_eq!(flagged, vec![10]);
    }

    #[test]
    fn logon_after_failed_burst_flags_first_success_and_tracks_last_failure() {
        let rule = LogonAfterFailedBurst::new(SignedDuration::from_mins(5), 5);
        let mut events = vec![
            failure(10, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 1),
            failure(11, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 2),
            failure(12, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 3),
            failure(13, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 4),
            failure(14, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 5),
            failure(15, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 6),
            failure(16, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 7),
            // Wrong host -> ignored.
            success(20, "OTHER", Some("10.0.0.5"), None, Some(r"CORP\alice"), 8),
            // Wrong origin -> ignored.
            success(21, "DC01", Some("10.0.0.99"), None, Some(r"CORP\alice"), 9),
            // First matching success on same host (case-insensitive) -> flagged.
            success(30, "dc01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 10),
            // Second success in same burst -> not flagged.
            success(40, "DC01", Some("10.0.0.5"), None, Some(r"CORP\alice"), 11),
        ];

        rule.apply(&mut events);

        assert!(events[7].flags.is_empty());
        assert!(events[8].flags.is_empty());
        assert_eq!(events[9].flags.len(), 1);
        assert_eq!(events[9].flags[0].severity, Severity::High);
        assert_eq!(
            events[9].flags[0].reason,
            r"Successful logon by CORP\alice from 10.0.0.5 after 7 failed attempts"
        );
        assert_eq!(events[9].flags[0].related, vec![events[6].as_ref()]);
        assert!(events[10].flags.is_empty());
    }

    #[test]
    fn logon_after_failed_burst_respects_window_edge_and_threshold_minus_one() {
        let rule = LogonAfterFailedBurst::new(SignedDuration::from_secs(60), 5);
        let mut events = vec![
            // Only 4 failures -> no burst.
            failure(0, "H1", None, Some("WS1"), Some("alice"), 1),
            failure(1, "H1", None, Some("WS1"), Some("alice"), 2),
            failure(2, "H1", None, Some("WS1"), Some("alice"), 3),
            failure(3, "H1", None, Some("WS1"), Some("alice"), 4),
            success(5, "H1", None, Some("WS1"), Some("alice"), 5),
            // 5 failures, success 61s after last failure -> outside window.
            failure(100, "H2", Some("10.0.0.2"), None, Some("bob"), 6),
            failure(101, "H2", Some("10.0.0.2"), None, Some("bob"), 7),
            failure(102, "H2", Some("10.0.0.2"), None, Some("bob"), 8),
            failure(103, "H2", Some("10.0.0.2"), None, Some("bob"), 9),
            failure(104, "H2", Some("10.0.0.2"), None, Some("bob"), 10),
            success(165, "H2", Some("10.0.0.2"), None, Some("bob"), 11),
            // New burst after window empties; success at exact 60s edge -> flags.
            failure(300, "H2", Some("10.0.0.2"), None, Some("bob"), 12),
            failure(301, "H2", Some("10.0.0.2"), None, Some("bob"), 13),
            failure(302, "H2", Some("10.0.0.2"), None, Some("bob"), 14),
            failure(303, "H2", Some("10.0.0.2"), None, Some("bob"), 15),
            failure(304, "H2", Some("10.0.0.2"), None, Some("bob"), 16),
            success(364, "H2", Some("10.0.0.2"), None, Some("bob"), 17),
        ];

        rule.apply(&mut events);

        assert!(events[4].flags.is_empty());
        assert!(events[10].flags.is_empty());
        assert_eq!(events[16].flags.len(), 1);
        assert_eq!(events[16].flags[0].related, vec![events[15].as_ref()]);
    }

    #[test]
    fn exec_from_tmp_covers_process_cmdline_quotes_and_cwd() {
        let mut by_proc = TimelineEvent::new(
            ts(10),
            "linux1",
            SourceKind::Auditd,
            EventKind::ProcessCreate,
            "audit.log",
        );
        by_proc.process = Some("/tmp/x.sh".into());

        let mut by_cmd_quoted = TimelineEvent::new(
            ts(11),
            "linux1",
            SourceKind::Journald,
            EventKind::PrivilegedCommand,
            "j.json",
        );
        by_cmd_quoted.command_line = Some("\"/var/tmp/dropper\" --run".into());

        let mut by_cwd = TimelineEvent::new(
            ts(12),
            "linux1",
            SourceKind::Auditd,
            EventKind::ProcessCreate,
            "audit.log",
        );
        by_cwd.command_line = Some("./payload".into());
        by_cwd
            .details
            .insert("cwd".into(), Value::String("/dev/shm/sub".into()));

        let mut evtx_ignored = TimelineEvent::new(
            ts(13),
            "win1",
            SourceKind::Evtx,
            EventKind::ProcessCreate,
            "Sec.evtx",
        );
        evtx_ignored.process = Some("/tmp/x.sh".into());

        let mut lookalike_dir = TimelineEvent::new(
            ts(14),
            "linux1",
            SourceKind::Auditd,
            EventKind::ProcessCreate,
            "audit.log",
        );
        lookalike_dir.command_line = Some("./ok".into());
        lookalike_dir
            .details
            .insert("cwd".into(), Value::String("/tmp_other".into()));

        let mut arg_only = TimelineEvent::new(
            ts(15),
            "linux1",
            SourceKind::Auditd,
            EventKind::ProcessCreate,
            "audit.log",
        );
        arg_only.process = Some("/usr/bin/cat".into());
        arg_only.command_line = Some("/usr/bin/cat /tmp/notes.txt".into());

        let mut by_cwd_exact = TimelineEvent::new(
            ts(16),
            "linux1",
            SourceKind::Journald,
            EventKind::ProcessCreate,
            "j.json",
        );
        by_cwd_exact.command_line = Some("./x.sh".into());
        by_cwd_exact
            .details
            .insert("cwd".into(), Value::String("/tmp".into()));

        let mut events = vec![
            by_proc,
            by_cmd_quoted,
            by_cwd,
            evtx_ignored,
            lookalike_dir,
            arg_only,
            by_cwd_exact,
        ];
        ExecFromTmp.apply(&mut events);

        assert_eq!(events[0].flags.len(), 1);
        assert_eq!(
            events[0].flags[0].reason,
            "Execution from a world-writable directory: /tmp/x.sh"
        );
        assert_eq!(events[1].flags.len(), 1);
        assert_eq!(
            events[1].flags[0].reason,
            "Execution from a world-writable directory: /var/tmp/dropper"
        );
        assert_eq!(events[2].flags.len(), 1);
        assert_eq!(
            events[2].flags[0].reason,
            "Execution from a world-writable directory: /dev/shm/sub/payload"
        );
        assert!(events[3].flags.is_empty());
        assert!(events[4].flags.is_empty());
        assert!(events[5].flags.is_empty());
        assert_eq!(events[6].flags.len(), 1);
        assert_eq!(
            events[6].flags[0].reason,
            "Execution from a world-writable directory: /tmp/x.sh"
        );
    }
}
