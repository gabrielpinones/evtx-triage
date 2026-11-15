//! Normalized timeline model shared by every source, detection rule and writer.

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Serialize, Serializer};
use serde_json::Value;

/// Log format an event was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Evtx,
    Journald,
    Auditd,
}

impl SourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceKind::Evtx => "evtx",
            SourceKind::Journald => "journald",
            SourceKind::Auditd => "auditd",
        }
    }
}

/// What happened, independent of the log format that recorded it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    LogonSuccess,
    LogonFailure,
    ExplicitLogon,
    ProcessCreate,
    ServiceInstall,
    TaskCreate,
    ScriptBlock,
    UserCreate,
    LogClear,
    PrivilegedCommand,
    ServiceStart,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::LogonSuccess => "logon_success",
            EventKind::LogonFailure => "logon_failure",
            EventKind::ExplicitLogon => "explicit_logon",
            EventKind::ProcessCreate => "process_create",
            EventKind::ServiceInstall => "service_install",
            EventKind::TaskCreate => "task_create",
            EventKind::ScriptBlock => "script_block",
            EventKind::UserCreate => "user_create",
            EventKind::LogClear => "log_clear",
            EventKind::PrivilegedCommand => "privileged_command",
            EventKind::ServiceStart => "service_start",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

/// Pointer to another event in the same timeline.
///
/// Record ids are only unique inside one channel of one host, so the channel
/// and timestamp travel with the id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventRef {
    #[serde(serialize_with = "serialize_ts")]
    pub ts: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<u64>,
}

/// A suspicion raised by a detection rule on one event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Flag {
    /// Stable rule id, for example `encoded_powershell`.
    pub rule: &'static str,
    pub severity: Severity,
    /// Why the rule fired, written for an analyst.
    pub reason: String,
    /// Earlier events the rule correlated with.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<EventRef>,
}

/// One row of the timeline.
///
/// The fixed fields are the ones worth a CSV column. Anything specific to one
/// event type goes in `details`, which is a `BTreeMap` so output is stable.
/// Absent optional fields are left out of the JSON; `details` and `flags` are
/// always present.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TimelineEvent {
    #[serde(serialize_with = "serialize_ts")]
    pub ts: Timestamp,
    pub host: String,
    pub source: SourceKind,
    /// EVTX channel, journald syslog identifier or auditd record type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<u32>,
    /// EVTX record id or auditd serial. journald has none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<u64>,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_type: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logon_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_process: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ppid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    /// Service name, task name or created account, depending on `kind`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// One human-readable line.
    pub summary: String,
    pub details: BTreeMap<String, Value>,
    pub flags: Vec<Flag>,
    /// Path of the file the event was read from.
    pub file: String,
}

impl TimelineEvent {
    /// Builds an event with every optional field empty.
    pub fn new(
        ts: Timestamp,
        host: impl Into<String>,
        source: SourceKind,
        kind: EventKind,
        file: impl Into<String>,
    ) -> Self {
        Self {
            ts,
            host: host.into(),
            source,
            channel: None,
            provider: None,
            event_id: None,
            record_id: None,
            kind,
            user: None,
            src_ip: None,
            logon_type: None,
            logon_id: None,
            process: None,
            pid: None,
            parent_process: None,
            ppid: None,
            command_line: None,
            target: None,
            summary: String::new(),
            details: BTreeMap::new(),
            flags: Vec::new(),
            file: file.into(),
        }
    }

    /// Reference to this event, for `Flag::related`.
    pub fn as_ref(&self) -> EventRef {
        EventRef {
            ts: self.ts,
            channel: self.channel.clone(),
            record_id: self.record_id,
        }
    }

    /// Total order for the timeline: time first, then fields that make ties
    /// deterministic across runs and thread counts.
    pub fn sort_key(&self) -> (Timestamp, &str, &str, u64, &str) {
        (
            self.ts,
            self.host.as_str(),
            self.channel.as_deref().unwrap_or(""),
            self.record_id.unwrap_or(0),
            self.file.as_str(),
        )
    }
}

/// Formats a timestamp as UTC RFC 3339 with exactly six fractional digits.
pub fn format_ts(ts: &Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

fn serialize_ts<S: Serializer>(ts: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&format_ts(ts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_always_has_six_fractional_digits() {
        let whole = Timestamp::from_second(1_700_000_000).unwrap();
        assert_eq!(format_ts(&whole), "2023-11-14T22:13:20.000000Z");

        let micros = Timestamp::from_microsecond(1_700_000_000_123_456).unwrap();
        assert_eq!(format_ts(&micros), "2023-11-14T22:13:20.123456Z");
    }

    #[test]
    fn event_serializes_with_snake_case_enums() {
        let ts = Timestamp::from_second(0).unwrap();
        let mut event = TimelineEvent::new(
            ts,
            "HOST",
            SourceKind::Evtx,
            EventKind::ServiceInstall,
            "a.evtx",
        );
        event.flags.push(Flag {
            rule: "remote_logon_then_service",
            severity: Severity::High,
            reason: "test".into(),
            related: vec![],
        });
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["source"], "evtx");
        assert_eq!(json["kind"], "service_install");
        assert_eq!(json["flags"][0]["severity"], "high");
        assert_eq!(json["ts"], "1970-01-01T00:00:00.000000Z");
        assert!(json.get("user").is_none(), "absent fields are omitted");
        assert!(json["details"].is_object());
    }

    #[test]
    fn sort_key_orders_by_time_then_record() {
        let t0 = Timestamp::from_second(10).unwrap();
        let t1 = Timestamp::from_second(11).unwrap();
        let mut a = TimelineEvent::new(t1, "H", SourceKind::Evtx, EventKind::LogClear, "f");
        let mut b = TimelineEvent::new(t0, "H", SourceKind::Evtx, EventKind::LogClear, "f");
        let mut c = TimelineEvent::new(t0, "H", SourceKind::Evtx, EventKind::LogClear, "f");
        a.record_id = Some(1);
        b.record_id = Some(9);
        c.record_id = Some(2);
        let mut events = [a, b, c];
        events.sort_by(|x, y| x.sort_key().cmp(&y.sort_key()));
        let ids: Vec<_> = events.iter().map(|e| e.record_id.unwrap()).collect();
        assert_eq!(ids, [2, 9, 1]);
    }

    #[test]
    fn event_ref_omits_absent_channel_and_record_id() {
        let ts = Timestamp::from_second(1_700_000_000).unwrap();

        let journald_ref = EventRef {
            ts,
            channel: Some("sshd".into()),
            record_id: None,
        };
        let journald_json = serde_json::to_value(&journald_ref).unwrap();
        assert_eq!(journald_json["ts"], "2023-11-14T22:13:20.000000Z");
        assert_eq!(journald_json["channel"], "sshd");
        assert!(journald_json.get("record_id").is_none());

        let bare_ref = EventRef {
            ts,
            channel: None,
            record_id: None,
        };
        let bare_json = serde_json::to_value(&bare_ref).unwrap();
        assert_eq!(bare_json["ts"], "2023-11-14T22:13:20.000000Z");
        assert!(bare_json.get("channel").is_none());
        assert!(bare_json.get("record_id").is_none());

        let full_ref = EventRef {
            ts,
            channel: Some("Security".into()),
            record_id: Some(42),
        };
        let full_json = serde_json::to_value(&full_ref).unwrap();
        assert_eq!(full_json["channel"], "Security");
        assert_eq!(full_json["record_id"], 42);
    }
}
