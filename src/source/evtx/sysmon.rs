//! Sysmon EVTX event extractors.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, field_u64_dec, format_summary_with_tail, insert_opt_str, insert_opt_u64,
};

fn sysmon_process_event(meta: &RecordMeta, data: &Value, kind: EventKind) -> TimelineEvent {
    let mut ev = meta.base_event(kind);
    ev.user = field_str(data, "User");
    ev.process = field_str(data, "Image");
    ev.pid = field_u64_dec(data, "ProcessId");
    insert_opt_str(
        &mut ev.details,
        "process_guid",
        field_str(data, "ProcessGuid"),
    );
    insert_opt_str(&mut ev.details, "utc_time", field_str(data, "UtcTime"));
    ev
}

fn sysmon_source_event(meta: &RecordMeta, data: &Value, kind: EventKind) -> TimelineEvent {
    let mut ev = meta.base_event(kind);
    ev.user = field_str(data, "User");
    ev.process = field_str(data, "SourceImage");
    ev.pid = field_u64_dec(data, "SourceProcessId");
    // Sysmon 8 uses `SourceProcessGuid` while Sysmon 10 logs `SourceProcessGUID`.
    let guid = field_str(data, "SourceProcessGuid")
        .or_else(|| field_str(data, "SourceProcessGUID"))
        .or_else(|| field_str(data, "ProcessGuid"));
    insert_opt_str(&mut ev.details, "process_guid", guid);
    insert_opt_str(&mut ev.details, "utc_time", field_str(data, "UtcTime"));
    ev
}

fn sysmon_wmi_event(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut ev = meta.base_event(EventKind::WmiPersistence);
    ev.user = field_str(data, "User");
    insert_opt_str(
        &mut ev.details,
        "process_guid",
        field_str(data, "ProcessGuid"),
    );
    insert_opt_str(&mut ev.details, "utc_time", field_str(data, "UtcTime"));
    insert_opt_str(&mut ev.details, "operation", field_str(data, "Operation"));
    insert_opt_str(
        &mut ev.details,
        "event_namespace",
        field_str(data, "EventNamespace"),
    );
    ev
}

fn insert_sysmon_bool(
    details: &mut BTreeMap<String, Value>,
    key: &str,
    data: &Value,
    src_key: &str,
) {
    let Some(val) = data.get(src_key) else {
        return;
    };
    match val {
        Value::Null => {}
        Value::Bool(b) => {
            details.insert(key.to_string(), Value::Bool(*b));
        }
        Value::String(s) => {
            if s.is_empty() || s == "-" {
                return;
            }
            let normalized = match s.as_str() {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => Value::String(s.clone()),
            };
            details.insert(key.to_string(), normalized);
        }
        other => {
            details.insert(key.to_string(), other.clone());
        }
    }
}

fn insert_opt_port(details: &mut BTreeMap<String, Value>, key: &str, data: &Value, src_key: &str) {
    if let Some(port) = field_u64_dec(data, src_key) {
        insert_opt_u64(details, key, Some(port));
    } else {
        insert_opt_str(details, key, field_str(data, src_key));
    }
}

fn format_endpoint(ip: &str, port: Option<&str>) -> String {
    let is_ipv6 = !ip.starts_with('[') && (ip.parse::<Ipv6Addr>().is_ok() || ip.contains(':'));
    match (is_ipv6, port) {
        (true, Some(p)) => format!("[{ip}]:{p}"),
        (false, Some(p)) => format!("{ip}:{p}"),
        (_, None) => ip.to_string(),
    }
}

fn one_line_summary(raw: &str) -> String {
    format_summary_with_tail(raw, None)
}

fn format_actor_target(
    proc_name: Option<&str>,
    verb: &str,
    target: Option<&str>,
    fallback: &str,
) -> String {
    match (proc_name, target) {
        (Some(p), Some(t)) => format!("{p} {verb} {t}"),
        (Some(p), None) => format!("{p} {verb}"),
        (None, Some(t)) => format!("{fallback}: {t}"),
        (None, None) => fallback.to_string(),
    }
}

/// Unwraps Sysmon's MOF-style ` "..."` WMI quoting for readable summaries.
fn display_wmi(s: &str) -> String {
    let Some(inner) = s
        .strip_prefix(" \"")
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return s.trim().to_string();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(next @ ('\\' | '"')) => out.push(next),
                Some(next) => {
                    out.push('\\');
                    out.push(next);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn wmi_summary(
    kind_label: &str,
    name: Option<&str>,
    op: Option<&str>,
    detail: Option<&str>,
) -> String {
    let op_str = op.map(str::to_ascii_lowercase);
    let action = op_str.as_deref().unwrap_or("activity");
    let prefix = match name.map(display_wmi).filter(|s| !s.is_empty()) {
        Some(n) => format!("WMI {kind_label} \"{n}\" {action}"),
        None => format!("WMI {kind_label} {action}"),
    };
    let tail = detail.map(display_wmi);
    format_summary_with_tail(&prefix, tail.as_deref())
}

/// Sysmon 3: Network connection detected.
pub(crate) fn extract_3(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_process_event(meta, data, EventKind::NetworkConnect);
    let protocol = field_str(data, "Protocol");
    let dest_ip = field_str(data, "DestinationIp");
    let dest_port_str = field_str(data, "DestinationPort");
    ev.target = dest_ip
        .as_deref()
        .map(|ip| format_endpoint(ip, dest_port_str.as_deref()));

    insert_opt_str(&mut ev.details, "protocol", protocol.clone());
    insert_sysmon_bool(&mut ev.details, "initiated", data, "Initiated");
    insert_opt_str(&mut ev.details, "source_ip", field_str(data, "SourceIp"));
    insert_opt_port(&mut ev.details, "source_port", data, "SourcePort");
    insert_opt_str(
        &mut ev.details,
        "source_hostname",
        field_str(data, "SourceHostname"),
    );
    insert_opt_str(&mut ev.details, "destination_ip", dest_ip);
    insert_opt_port(&mut ev.details, "destination_port", data, "DestinationPort");
    insert_opt_str(
        &mut ev.details,
        "destination_hostname",
        field_str(data, "DestinationHostname"),
    );
    insert_opt_str(
        &mut ev.details,
        "destination_port_name",
        field_str(data, "DestinationPortName"),
    );

    let base = format_actor_target(
        ev.process.as_deref(),
        "connected to",
        ev.target.as_deref(),
        "Network connection",
    );
    let raw = match protocol {
        Some(proto) => format!("{base} ({proto})"),
        None => base,
    };
    ev.summary = one_line_summary(&raw);
    Some(ev)
}

/// Sysmon 7: Image loaded.
pub(crate) fn extract_7(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_process_event(meta, data, EventKind::ImageLoad);
    ev.target = field_str(data, "ImageLoaded");

    insert_opt_str(&mut ev.details, "hashes", field_str(data, "Hashes"));
    insert_sysmon_bool(&mut ev.details, "signed", data, "Signed");
    insert_opt_str(&mut ev.details, "signature", field_str(data, "Signature"));
    insert_opt_str(
        &mut ev.details,
        "signature_status",
        field_str(data, "SignatureStatus"),
    );
    insert_opt_str(
        &mut ev.details,
        "original_file_name",
        field_str(data, "OriginalFileName"),
    );

    let suffix = if ev.details.get("signed") == Some(&Value::Bool(false)) {
        " (unsigned)"
    } else {
        ""
    };
    let base = format_actor_target(
        ev.process.as_deref(),
        "loaded",
        ev.target.as_deref(),
        "Image load",
    );
    ev.summary = one_line_summary(&format!("{base}{suffix}"));
    Some(ev)
}

/// Sysmon 8: CreateRemoteThread detected.
pub(crate) fn extract_8(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_source_event(meta, data, EventKind::RemoteThread);
    ev.target = field_str(data, "TargetImage");

    insert_opt_u64(
        &mut ev.details,
        "target_pid",
        field_u64_dec(data, "TargetProcessId"),
    );
    insert_opt_str(
        &mut ev.details,
        "start_address",
        field_str(data, "StartAddress"),
    );
    insert_opt_str(
        &mut ev.details,
        "start_module",
        field_str(data, "StartModule"),
    );
    insert_opt_str(
        &mut ev.details,
        "start_function",
        field_str(data, "StartFunction"),
    );
    insert_opt_str(
        &mut ev.details,
        "source_user",
        field_str(data, "SourceUser"),
    );
    insert_opt_str(
        &mut ev.details,
        "target_user",
        field_str(data, "TargetUser"),
    );

    ev.summary = one_line_summary(&format_actor_target(
        ev.process.as_deref(),
        "created a thread in",
        ev.target.as_deref(),
        "Remote thread",
    ));
    Some(ev)
}

/// Sysmon 10: Process accessed.
pub(crate) fn extract_10(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_source_event(meta, data, EventKind::ProcessAccess);
    ev.target = field_str(data, "TargetImage");

    let granted_access = field_str(data, "GrantedAccess");
    insert_opt_u64(
        &mut ev.details,
        "target_pid",
        field_u64_dec(data, "TargetProcessId"),
    );
    insert_opt_str(&mut ev.details, "granted_access", granted_access.clone());
    insert_opt_str(&mut ev.details, "call_trace", field_str(data, "CallTrace"));
    insert_opt_str(
        &mut ev.details,
        "source_user",
        field_str(data, "SourceUser"),
    );
    insert_opt_str(
        &mut ev.details,
        "target_user",
        field_str(data, "TargetUser"),
    );

    let base = format_actor_target(
        ev.process.as_deref(),
        "opened",
        ev.target.as_deref(),
        "Process access",
    );
    let raw = match granted_access {
        Some(acc) => format!("{base} (access {acc})"),
        None => base,
    };
    ev.summary = one_line_summary(&raw);
    Some(ev)
}

/// Sysmon 11: File created.
pub(crate) fn extract_11(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_process_event(meta, data, EventKind::FileCreate);
    ev.target = field_str(data, "TargetFilename");

    insert_opt_str(
        &mut ev.details,
        "creation_utc_time",
        field_str(data, "CreationUtcTime"),
    );

    ev.summary = one_line_summary(&format_actor_target(
        ev.process.as_deref(),
        "created",
        ev.target.as_deref(),
        "File create",
    ));
    Some(ev)
}

/// Sysmon 12: Registry object added or deleted.
pub(crate) fn extract_12(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_registry(meta, data, 12)
}

/// Sysmon 13: Registry value set.
pub(crate) fn extract_13(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_registry(meta, data, 13)
}

/// Sysmon 14: Registry object renamed.
pub(crate) fn extract_14(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_registry(meta, data, 14)
}

fn extract_registry(meta: &RecordMeta, data: &Value, event_id: u16) -> Option<TimelineEvent> {
    let mut ev = sysmon_process_event(meta, data, EventKind::RegistryChange);
    ev.target = field_str(data, "TargetObject");

    let event_type = field_str(data, "EventType");
    insert_opt_str(&mut ev.details, "event_type", event_type.clone());

    let raw = match event_id {
        13 => {
            let value = field_str(data, "Details");
            insert_opt_str(&mut ev.details, "value", value.clone());
            let base = format_actor_target(
                ev.process.as_deref(),
                "set",
                ev.target.as_deref(),
                "Registry value set",
            );
            match value {
                Some(v) => format!("{base} = {v}"),
                None => base,
            }
        }
        14 => {
            let new_name = field_str(data, "NewName");
            insert_opt_str(&mut ev.details, "new_name", new_name.clone());
            let base = format_actor_target(
                ev.process.as_deref(),
                "renamed",
                ev.target.as_deref(),
                "Registry key renamed",
            );
            match new_name {
                Some(n) => format!("{base} -> {n}"),
                None => base,
            }
        }
        _ => {
            let verb = match event_type.as_deref() {
                Some("CreateKey") => "created key",
                Some("DeleteKey") => "deleted key",
                Some("CreateValue") => "created value",
                Some("DeleteValue") => "deleted value",
                _ => "modified registry",
            };
            format_actor_target(
                ev.process.as_deref(),
                verb,
                ev.target.as_deref(),
                "Registry change",
            )
        }
    };

    ev.summary = one_line_summary(&raw);
    Some(ev)
}

/// Sysmon 17: Named pipe created.
pub(crate) fn extract_17(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_pipe(meta, data, true)
}

/// Sysmon 18: Named pipe connected.
pub(crate) fn extract_18(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_pipe(meta, data, false)
}

fn extract_pipe(meta: &RecordMeta, data: &Value, default_create: bool) -> Option<TimelineEvent> {
    let mut ev = sysmon_process_event(meta, data, EventKind::NamedPipe);
    ev.target = field_str(data, "PipeName");

    let event_type = field_str(data, "EventType");
    insert_opt_str(&mut ev.details, "event_type", event_type.clone());

    let is_create = match event_type.as_deref() {
        Some("CreatePipe") => true,
        Some("ConnectPipe") => false,
        _ => default_create,
    };
    let verb = if is_create {
        "created pipe"
    } else {
        "connected to pipe"
    };
    ev.summary = one_line_summary(&format_actor_target(
        ev.process.as_deref(),
        verb,
        ev.target.as_deref(),
        "Named pipe",
    ));
    Some(ev)
}

/// Sysmon 19: WMI EventFilter activity detected.
pub(crate) fn extract_19(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_wmi_event(meta, data);
    ev.target = field_str(data, "Name");
    let query = field_str(data, "Query");
    insert_opt_str(&mut ev.details, "query", query.clone());

    ev.summary = wmi_summary(
        "filter",
        ev.target.as_deref(),
        ev.details.get("operation").and_then(Value::as_str),
        query.as_deref(),
    );
    Some(ev)
}

/// Sysmon 20: WMI EventConsumer activity detected.
pub(crate) fn extract_20(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_wmi_event(meta, data);
    ev.target = field_str(data, "Name");
    let destination = field_str(data, "Destination");
    ev.command_line = destination.clone();

    insert_opt_str(&mut ev.details, "consumer_type", field_str(data, "Type"));
    insert_opt_str(&mut ev.details, "destination", destination.clone());

    ev.summary = wmi_summary(
        "consumer",
        ev.target.as_deref(),
        ev.details.get("operation").and_then(Value::as_str),
        destination.as_deref(),
    );
    Some(ev)
}

/// Sysmon 21: WMI EventConsumerToFilter activity detected.
pub(crate) fn extract_21(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_wmi_event(meta, data);
    let consumer = field_str(data, "Consumer");
    let filter = field_str(data, "Filter");
    ev.target = consumer.clone();

    insert_opt_str(&mut ev.details, "consumer", consumer.clone());
    insert_opt_str(&mut ev.details, "filter", filter.clone());

    let detail = match (filter.as_deref(), consumer.as_deref()) {
        (Some(f), Some(c)) => Some(format!("{} -> {}", display_wmi(f), display_wmi(c))),
        (Some(f), None) => Some(display_wmi(f)),
        (None, Some(c)) => Some(display_wmi(c)),
        (None, None) => None,
    };
    ev.summary = wmi_summary(
        "binding",
        None,
        ev.details.get("operation").and_then(Value::as_str),
        detail.as_deref(),
    );
    Some(ev)
}

/// Sysmon 22: DNS query executed.
pub(crate) fn extract_22(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_process_event(meta, data, EventKind::DnsQuery);
    ev.target = field_str(data, "QueryName");

    insert_opt_str(
        &mut ev.details,
        "query_status",
        field_str(data, "QueryStatus"),
    );
    insert_opt_str(
        &mut ev.details,
        "query_results",
        field_str(data, "QueryResults"),
    );

    ev.summary = one_line_summary(&format_actor_target(
        ev.process.as_deref(),
        "resolved",
        ev.target.as_deref(),
        "DNS query",
    ));
    Some(ev)
}

/// Sysmon 23: File delete archived.
pub(crate) fn extract_23(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut ev = sysmon_process_event(meta, data, EventKind::FileDelete);
    ev.target = field_str(data, "TargetFilename");

    insert_opt_str(&mut ev.details, "hashes", field_str(data, "Hashes"));
    insert_sysmon_bool(&mut ev.details, "is_executable", data, "IsExecutable");
    insert_sysmon_bool(&mut ev.details, "archived", data, "Archived");

    ev.summary = one_line_summary(&format_actor_target(
        ev.process.as_deref(),
        "deleted",
        ev.target.as_deref(),
        "File delete",
    ));
    Some(ev)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use jiff::Timestamp;
    use serde_json::{Value, json};

    use super::*;
    use crate::model::TimelineEvent;
    use crate::source::evtx::EvtxSource;
    use crate::source::{ReadOptions, Source};

    fn test_meta(event_id: u32) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).expect("valid timestamp"),
            host: "WORKSTATION".to_string(),
            file: "sysmon.evtx".to_string(),
            channel: Some("Microsoft-Windows-Sysmon/Operational".to_string()),
            provider: "Microsoft-Windows-Sysmon".to_string(),
            event_id,
            record_id: 42,
            file_record_id: None,
            user_sid: None,
        }
    }

    fn attack_fixture(name: &str) -> Vec<TimelineEvent> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("attack-samples")
            .join(name);
        let mut events = Vec::new();
        let stats = EvtxSource
            .read(&path, &ReadOptions::default(), &mut events)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
        assert_eq!(stats.errors, 0, "unexpected read errors in {name}");
        events
    }

    fn count_by_id(events: &[TimelineEvent], event_id: u32) -> usize {
        events
            .iter()
            .filter(|e| e.event_id == Some(event_id))
            .count()
    }

    #[test]
    fn sysmon_3_network_connect_ipv4_and_ipv6() {
        let ipv4 = json!({
            "UtcTime": "2024-01-01 00:00:00.000",
            "ProcessGuid": "{11111111-1111-1111-1111-111111111111}",
            "ProcessId": "2048",
            "Image": "C:\\Windows\\System32\\rundll32.exe",
            "User": "CORP\\alice",
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIp": "10.0.0.5",
            "SourcePort": "49152",
            "SourceHostname": "WS01",
            "DestinationIp": "10.0.0.9",
            "DestinationPort": "443",
            "DestinationHostname": "c2.example.com",
            "DestinationPortName": "https"
        });
        let ev = extract_3(&test_meta(3), &ipv4).expect("sysmon 3 ipv4");
        assert_eq!(ev.kind, EventKind::NetworkConnect);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(
            ev.process.as_deref(),
            Some("C:\\Windows\\System32\\rundll32.exe")
        );
        assert_eq!(ev.pid, Some(2048));
        assert_eq!(ev.target.as_deref(), Some("10.0.0.9:443"));
        assert_eq!(ev.details.get("initiated"), Some(&json!(true)));
        assert_eq!(ev.details.get("source_port"), Some(&json!(49152)));
        assert_eq!(ev.details.get("destination_port"), Some(&json!(443)));
        assert_eq!(ev.details.get("protocol"), Some(&json!("tcp")));
        assert_eq!(
            ev.details.get("destination_port_name"),
            Some(&json!("https"))
        );
        assert_eq!(
            ev.summary,
            "C:\\Windows\\System32\\rundll32.exe connected to 10.0.0.9:443 (tcp)"
        );

        let ipv6 = json!({
            "UtcTime": "2019-04-18 16:57:51.884",
            "ProcessGuid": "{365abb72-ac60-5cb8-0000-001037ba0800}",
            "ProcessId": 3900,
            "Image": "C:\\Windows\\System32\\mmc.exe",
            "User": "IEWIN7\\IEUser",
            "Protocol": "tcp",
            "Initiated": false,
            "SourceIp": "fe80:0:0:0:80ac:4126:fa58:1b81",
            "SourceHostname": "IEWIN7",
            "SourcePort": 49158,
            "DestinationIp": "fe80:0:0:0:80ac:4126:fa58:1b81",
            "DestinationHostname": "IEWIN7",
            "DestinationPort": 135,
            "DestinationPortName": "epmap"
        });
        let ev6 = extract_3(&test_meta(3), &ipv6).expect("sysmon 3 ipv6");
        assert_eq!(
            ev6.target.as_deref(),
            Some("[fe80:0:0:0:80ac:4126:fa58:1b81]:135")
        );
        assert_eq!(ev6.details.get("initiated"), Some(&json!(false)));
        assert_eq!(
            ev6.summary,
            "C:\\Windows\\System32\\mmc.exe connected to [fe80:0:0:0:80ac:4126:fa58:1b81]:135 (tcp)"
        );
    }

    #[test]
    fn sysmon_7_image_load_unsigned_and_signed() {
        let unsigned = json!({
            "UtcTime": "2019-05-26 04:01:42.505",
            "ProcessGuid": "{365abb72-0fa6-5cea-0000-001049b50a00}",
            "ProcessId": 3836,
            "Image": "C:\\Users\\IEUser\\Desktop\\x.exe",
            "ImageLoaded": "C:\\Users\\IEUser\\Desktop\\evil.dll",
            "Hashes": "SHA256=DEAD",
            "Signed": "false",
            "Signature": "",
            "SignatureStatus": "Unavailable"
        });
        let ev = extract_7(&test_meta(7), &unsigned).expect("sysmon 7 unsigned");
        assert_eq!(ev.kind, EventKind::ImageLoad);
        assert_eq!(
            ev.target.as_deref(),
            Some("C:\\Users\\IEUser\\Desktop\\evil.dll")
        );
        assert_eq!(ev.details.get("signed"), Some(&json!(false)));
        assert!(!ev.details.contains_key("signature"));
        assert!(!ev.details.contains_key("original_file_name"));
        assert_eq!(
            ev.details.get("signature_status"),
            Some(&json!("Unavailable"))
        );
        assert_eq!(
            ev.summary,
            "C:\\Users\\IEUser\\Desktop\\x.exe loaded C:\\Users\\IEUser\\Desktop\\evil.dll (unsigned)"
        );

        let signed = json!({
            "UtcTime": "2020-10-20 11:50:51.739",
            "ProcessGuid": "{23f38d93-ceb4-5f8e-9f08-000000000c00}",
            "ProcessId": 9392,
            "Image": "C:\\Windows\\System32\\mmc.exe",
            "ImageLoaded": "C:\\Windows\\System32\\UIAutomationCore.dll",
            "OriginalFileName": "UIAutomationCore.dll",
            "Hashes": "MD5=1234",
            "Signed": "true",
            "Signature": "Microsoft Windows",
            "SignatureStatus": "Valid"
        });
        let ev2 = extract_7(&test_meta(7), &signed).expect("sysmon 7 signed");
        assert_eq!(ev2.details.get("signed"), Some(&json!(true)));
        assert_eq!(
            ev2.details.get("original_file_name"),
            Some(&json!("UIAutomationCore.dll"))
        );
        assert!(!ev2.summary.contains("(unsigned)"));
    }

    #[test]
    fn sysmon_8_remote_thread() {
        let rec = json!({
            "UtcTime": "2019-05-26 04:01:43.567",
            "SourceProcessGuid": "{365abb72-0fa6-5cea-0000-0010fec30a00}",
            "SourceProcessId": 3884,
            "SourceImage": "C:\\Users\\IEUser\\a.exe",
            "TargetProcessGuid": "{365abb72-0fa7-5cea-0000-001064c60a00}",
            "TargetProcessId": 3908,
            "TargetImage": "C:\\Windows\\System32\\b.exe",
            "StartAddress": "0x00060000",
            "StartModule": "C:\\Windows\\System32\\kernel32.dll",
            "StartFunction": "LoadLibraryA",
            "SourceUser": "CORP\\alice",
            "TargetUser": "NT AUTHORITY\\SYSTEM"
        });
        let ev = extract_8(&test_meta(8), &rec).expect("sysmon 8");
        assert_eq!(ev.kind, EventKind::RemoteThread);
        assert_eq!(ev.process.as_deref(), Some("C:\\Users\\IEUser\\a.exe"));
        assert_eq!(ev.pid, Some(3884));
        assert_eq!(ev.target.as_deref(), Some("C:\\Windows\\System32\\b.exe"));
        assert_eq!(
            ev.details.get("process_guid"),
            Some(&json!("{365abb72-0fa6-5cea-0000-0010fec30a00}"))
        );
        assert_eq!(ev.details.get("target_pid"), Some(&json!(3908)));
        assert_eq!(ev.details.get("start_address"), Some(&json!("0x00060000")));
        assert_eq!(
            ev.details.get("start_module"),
            Some(&json!("C:\\Windows\\System32\\kernel32.dll"))
        );
        assert_eq!(
            ev.details.get("start_function"),
            Some(&json!("LoadLibraryA"))
        );
        assert_eq!(ev.details.get("source_user"), Some(&json!("CORP\\alice")));
        assert_eq!(
            ev.details.get("target_user"),
            Some(&json!("NT AUTHORITY\\SYSTEM"))
        );
        assert_eq!(
            ev.summary,
            "C:\\Users\\IEUser\\a.exe created a thread in C:\\Windows\\System32\\b.exe"
        );
    }

    #[test]
    fn sysmon_10_process_access_uppercase_guid_and_hex_string() {
        let rec = json!({
            "UtcTime": "2019-04-18 16:58:14.801",
            "SourceProcessGUID": "{365abb72-ac28-5cb8-0000-0010f3f70700}",
            "SourceProcessId": 1200,
            "SourceImage": "C:\\Temp\\a.exe",
            "TargetProcessGUID": "{365abb72-29b3-5cb9-0000-001087490000}",
            "TargetProcessId": 472,
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+4595c|C:\\Windows\\system32\\KERNELBASE.dll+8185"
        });
        let ev = extract_10(&test_meta(10), &rec).expect("sysmon 10");
        assert_eq!(ev.kind, EventKind::ProcessAccess);
        assert_eq!(ev.process.as_deref(), Some("C:\\Temp\\a.exe"));
        assert_eq!(ev.pid, Some(1200));
        assert_eq!(
            ev.target.as_deref(),
            Some("C:\\Windows\\System32\\lsass.exe")
        );
        assert_eq!(
            ev.details.get("process_guid"),
            Some(&json!("{365abb72-ac28-5cb8-0000-0010f3f70700}"))
        );
        assert_eq!(ev.details.get("target_pid"), Some(&json!(472)));
        assert_eq!(ev.details.get("granted_access"), Some(&json!("0x1010")));
        assert!(ev.details.contains_key("call_trace"));
        assert_eq!(
            ev.summary,
            "C:\\Temp\\a.exe opened C:\\Windows\\System32\\lsass.exe (access 0x1010)"
        );
    }

    #[test]
    fn sysmon_11_file_create() {
        let rec = json!({
            "UtcTime": "2024-02-01 12:00:00.000",
            "ProcessGuid": "{aaaa}",
            "ProcessId": 555,
            "Image": "C:\\Temp\\a.exe",
            "TargetFilename": "C:\\Users\\Public\\x.exe",
            "CreationUtcTime": "2024-02-01 11:59:59.000",
            "User": "CORP\\bob"
        });
        let ev = extract_11(&test_meta(11), &rec).expect("sysmon 11");
        assert_eq!(ev.kind, EventKind::FileCreate);
        assert_eq!(ev.user.as_deref(), Some("CORP\\bob"));
        assert_eq!(ev.target.as_deref(), Some("C:\\Users\\Public\\x.exe"));
        assert_eq!(
            ev.details.get("creation_utc_time"),
            Some(&json!("2024-02-01 11:59:59.000"))
        );
        assert_eq!(
            ev.summary,
            "C:\\Temp\\a.exe created C:\\Users\\Public\\x.exe"
        );
    }

    #[test]
    fn sysmon_12_13_14_registry_changes_and_long_details() {
        let r12 = json!({
            "EventType": "CreateKey",
            "UtcTime": "2024-01-01 00:00:01.000",
            "ProcessGuid": "{12}",
            "ProcessId": 100,
            "Image": "C:\\Windows\\System32\\reg.exe",
            "TargetObject": "HKLM\\Software\\Example"
        });
        let ev12 = extract_12(&test_meta(12), &r12).expect("sysmon 12");
        assert_eq!(ev12.kind, EventKind::RegistryChange);
        assert_eq!(ev12.details.get("event_type"), Some(&json!("CreateKey")));
        assert_eq!(
            ev12.summary,
            "C:\\Windows\\System32\\reg.exe created key HKLM\\Software\\Example"
        );

        let long_val = format!("line1\n{}", "A".repeat(260));
        let r13 = json!({
            "EventType": "SetValue",
            "UtcTime": "2024-01-01 00:00:02.000",
            "ProcessGuid": "{13}",
            "ProcessId": 101,
            "Image": "C:\\Windows\\System32\\reg.exe",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x",
            "Details": long_val
        });
        let ev13 = extract_13(&test_meta(13), &r13).expect("sysmon 13");
        assert_eq!(ev13.details.get("event_type"), Some(&json!("SetValue")));
        assert_eq!(ev13.details.get("value"), Some(&json!(long_val)));
        assert!(ev13.summary.chars().count() <= 200);
        assert!(ev13.summary.ends_with("..."));
        assert!(!ev13.summary.contains('\n'));
        assert!(ev13.summary.starts_with(
            "C:\\Windows\\System32\\reg.exe set HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x = "
        ));

        let r14 = json!({
            "EventType": "RenameKey",
            "UtcTime": "2024-01-01 00:00:03.000",
            "ProcessGuid": "{14}",
            "ProcessId": 102,
            "Image": "C:\\Windows\\System32\\reg.exe",
            "TargetObject": "HKCU\\Software\\OldName",
            "NewName": "HKCU\\Software\\NewName"
        });
        let ev14 = extract_14(&test_meta(14), &r14).expect("sysmon 14");
        assert_eq!(ev14.details.get("event_type"), Some(&json!("RenameKey")));
        assert_eq!(
            ev14.details.get("new_name"),
            Some(&json!("HKCU\\Software\\NewName"))
        );
        assert_eq!(
            ev14.summary,
            "C:\\Windows\\System32\\reg.exe renamed HKCU\\Software\\OldName -> HKCU\\Software\\NewName"
        );
    }

    #[test]
    fn sysmon_17_18_named_pipes() {
        let p17 = json!({
            "EventType": "CreatePipe",
            "UtcTime": "2020-05-11 23:21:56.507",
            "ProcessGuid": "{17}",
            "ProcessId": 4200,
            "PipeName": "\\RoguePotato\\pipe\\epmapper",
            "Image": "C:\\Tools\\RoguePotato.exe"
        });
        let ev17 = extract_17(&test_meta(17), &p17).expect("sysmon 17");
        assert_eq!(ev17.kind, EventKind::NamedPipe);
        assert_eq!(ev17.details.get("event_type"), Some(&json!("CreatePipe")));
        assert_eq!(
            ev17.target.as_deref(),
            Some("\\RoguePotato\\pipe\\epmapper")
        );
        assert_eq!(
            ev17.summary,
            "C:\\Tools\\RoguePotato.exe created pipe \\RoguePotato\\pipe\\epmapper"
        );

        let p18 = json!({
            "EventType": "ConnectPipe",
            "UtcTime": "2020-05-11 23:21:56.554",
            "ProcessGuid": "{18}",
            "ProcessId": 4,
            "PipeName": "\\PSEXESVC",
            "Image": "C:\\Windows\\System32\\services.exe"
        });
        let ev18 = extract_18(&test_meta(18), &p18).expect("sysmon 18");
        assert_eq!(ev18.kind, EventKind::NamedPipe);
        assert_eq!(ev18.details.get("event_type"), Some(&json!("ConnectPipe")));
        assert_eq!(
            ev18.summary,
            "C:\\Windows\\System32\\services.exe connected to pipe \\PSEXESVC"
        );

        // Older Sysmon v1 schemas omit EventType on Event 18.
        let p18_legacy = json!({
            "UtcTime": "2019-04-30 20:26:51.793",
            "ProcessGuid": "{18-old}",
            "ProcessId": 4,
            "PipeName": "\\ntsvcs",
            "Image": "System"
        });
        let ev18_old = extract_18(&test_meta(18), &p18_legacy).expect("sysmon 18 legacy");
        assert!(!ev18_old.details.contains_key("event_type"));
        assert_eq!(ev18_old.summary, "System connected to pipe \\ntsvcs");
    }

    #[test]
    fn sysmon_19_20_21_wmi_persistence() {
        let r19 = json!({
            "EventType": "WmiFilterEvent",
            "UtcTime": "2019-05-11 17:58:39.746",
            "Operation": "Created",
            "User": "IEWIN7\\IEUser",
            "EventNamespace": " \"root\\\\cimv2\"",
            "Name": " \"BotFilter82\"",
            "Query": " \"SELECT * FROM __InstanceModificationEvent\""
        });
        let ev19 = extract_19(&test_meta(19), &r19).expect("sysmon 19");
        assert_eq!(ev19.kind, EventKind::WmiPersistence);
        assert_eq!(ev19.user.as_deref(), Some("IEWIN7\\IEUser"));
        assert_eq!(ev19.process, None);
        assert_eq!(ev19.pid, None);
        assert_eq!(ev19.target.as_deref(), Some(" \"BotFilter82\""));
        assert_eq!(ev19.details.get("operation"), Some(&json!("Created")));
        assert!(ev19.details.contains_key("event_namespace"));
        assert!(ev19.details.contains_key("query"));
        assert_eq!(
            ev19.summary,
            "WMI filter \"BotFilter82\" created: SELECT * FROM __InstanceModificationEvent"
        );

        let r20 = json!({
            "EventType": "WmiConsumerEvent",
            "UtcTime": "2024-01-01 00:00:00.000",
            "Operation": "Created",
            "User": "CORP\\admin",
            "Name": "x",
            "Type": "Command Line",
            "Destination": "powershell -enc SQBFAFgA"
        });
        let ev20 = extract_20(&test_meta(20), &r20).expect("sysmon 20");
        assert_eq!(ev20.kind, EventKind::WmiPersistence);
        assert_eq!(ev20.user.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev20.process, None);
        assert_eq!(ev20.target.as_deref(), Some("x"));
        assert_eq!(
            ev20.command_line.as_deref(),
            Some("powershell -enc SQBFAFgA")
        );
        assert_eq!(
            ev20.details.get("consumer_type"),
            Some(&json!("Command Line"))
        );
        assert_eq!(
            ev20.details.get("destination"),
            Some(&json!("powershell -enc SQBFAFgA"))
        );
        assert_eq!(
            ev20.summary,
            "WMI consumer \"x\" created: powershell -enc SQBFAFgA"
        );

        let r21 = json!({
            "EventType": "WmiBindingEvent",
            "UtcTime": "2019-05-11 17:58:23.418",
            "Operation": "Created",
            "User": "IEWIN7\\IEUser",
            "Consumer": " \"CommandLineEventConsumer.Name=\\\"BotConsumer23\\\"\"",
            "Filter": " \"__EventFilter.Name=\\\"BotFilter82\\\"\""
        });
        let ev21 = extract_21(&test_meta(21), &r21).expect("sysmon 21");
        assert_eq!(ev21.kind, EventKind::WmiPersistence);
        assert_eq!(
            ev21.target.as_deref(),
            Some(" \"CommandLineEventConsumer.Name=\\\"BotConsumer23\\\"\"")
        );
        assert!(ev21.details.contains_key("consumer"));
        assert!(ev21.details.contains_key("filter"));
        assert_eq!(
            ev21.summary,
            "WMI binding created: __EventFilter.Name=\"BotFilter82\" -> CommandLineEventConsumer.Name=\"BotConsumer23\""
        );
    }

    #[test]
    fn sysmon_22_and_23_and_bool_preservation() {
        let r22 = json!({
            "UtcTime": "2020-10-20 11:50:59.461",
            "ProcessGuid": "{22}",
            "ProcessId": 2428,
            "QueryName": "evil.example.com",
            "QueryStatus": "0",
            "QueryResults": "type: 1 203.0.113.10;",
            "Image": "C:\\Temp\\a.exe"
        });
        let ev22 = extract_22(&test_meta(22), &r22).expect("sysmon 22");
        assert_eq!(ev22.kind, EventKind::DnsQuery);
        assert_eq!(ev22.target.as_deref(), Some("evil.example.com"));
        assert_eq!(ev22.details.get("query_status"), Some(&json!("0")));
        assert_eq!(
            ev22.details.get("query_results"),
            Some(&json!("type: 1 203.0.113.10;"))
        );
        assert_eq!(ev22.summary, "C:\\Temp\\a.exe resolved evil.example.com");

        let r23 = json!({
            "UtcTime": "2020-10-20 11:50:55.457",
            "ProcessGuid": "{23}",
            "ProcessId": 8736,
            "User": "DESKTOP\\den",
            "Image": "C:\\Temp\\a.exe",
            "TargetFilename": "C:\\Temp\\x.exe",
            "Hashes": "SHA256=ABCD",
            "IsExecutable": true,
            "Archived": "false"
        });
        let ev23 = extract_23(&test_meta(23), &r23).expect("sysmon 23");
        assert_eq!(ev23.kind, EventKind::FileDelete);
        assert_eq!(ev23.user.as_deref(), Some("DESKTOP\\den"));
        assert_eq!(ev23.target.as_deref(), Some("C:\\Temp\\x.exe"));
        assert_eq!(ev23.details.get("is_executable"), Some(&json!(true)));
        assert_eq!(ev23.details.get("archived"), Some(&json!(false)));
        assert_eq!(ev23.summary, "C:\\Temp\\a.exe deleted C:\\Temp\\x.exe");

        // Non-"true"/"false" values on boolean fields are preserved as-is.
        let r23_odd = json!({
            "Image": "C:\\Temp\\a.exe",
            "TargetFilename": "C:\\Temp\\y.bin",
            "IsExecutable": "unknown",
            "Archived": 2
        });
        let ev23_odd = extract_23(&test_meta(23), &r23_odd).expect("sysmon 23 odd");
        assert_eq!(
            ev23_odd.details.get("is_executable"),
            Some(&json!("unknown"))
        );
        assert_eq!(ev23_odd.details.get("archived"), Some(&json!(2)));
    }

    #[test]
    fn all_extractors_handle_null_input_without_panicking() {
        type ExtractorFn = fn(&RecordMeta, &Value) -> Option<TimelineEvent>;
        let extractors: [(u32, ExtractorFn); 15] = [
            (3, extract_3),
            (7, extract_7),
            (8, extract_8),
            (10, extract_10),
            (11, extract_11),
            (12, extract_12),
            (13, extract_13),
            (14, extract_14),
            (17, extract_17),
            (18, extract_18),
            (19, extract_19),
            (20, extract_20),
            (21, extract_21),
            (22, extract_22),
            (23, extract_23),
        ];
        for (eid, func) in extractors {
            let ev = func(&test_meta(eid), &Value::Null)
                .unwrap_or_else(|| panic!("extractor {eid} returned None on Null"));
            assert!(!ev.summary.is_empty());
            assert!(!ev.summary.contains('\n'));
            assert!(ev.details.values().all(|v| !v.is_null()));
        }
    }

    #[test]
    fn fixture_babyshark_mimikatz_powershell() {
        let events = attack_fixture("babyshark_mimikatz_powershell.evtx");
        assert_eq!(count_by_id(&events, 1), 7);
        assert_eq!(count_by_id(&events, 3), 1);
        assert_eq!(count_by_id(&events, 7), 11);
        assert_eq!(count_by_id(&events, 10), 2);
        assert_eq!(count_by_id(&events, 11), 3);
        assert_eq!(count_by_id(&events, 12), 4);

        let net = events
            .iter()
            .find(|e| e.event_id == Some(3))
            .expect("sysmon 3 event");
        assert_eq!(net.kind, EventKind::NetworkConnect);
        assert_eq!(
            net.target.as_deref(),
            Some("[fe80:0:0:0:80ac:4126:fa58:1b81]:135")
        );
        assert_eq!(net.details.get("initiated"), Some(&json!(false)));

        let lsass = events
            .iter()
            .find(|e| e.event_id == Some(10))
            .expect("sysmon 10 event");
        assert_eq!(
            lsass.target.as_deref(),
            Some("C:\\Windows\\system32\\lsass.exe")
        );
        assert_eq!(lsass.details.get("granted_access"), Some(&json!("0x1010")));
        assert!(lsass.details.contains_key("process_guid"));
    }

    #[test]
    fn fixture_sysmon_20_21_command_line_consumer() {
        let events = attack_fixture("sysmon_20_21_1_CommandLineEventConsumer.evtx");
        assert_eq!(count_by_id(&events, 1), 9);
        assert_eq!(count_by_id(&events, 10), 2);
        assert_eq!(count_by_id(&events, 19), 2);
        assert_eq!(count_by_id(&events, 20), 2);
        assert_eq!(count_by_id(&events, 21), 2);

        let wmi20 = events
            .iter()
            .find(|e| {
                e.event_id == Some(20) && e.details.get("operation") == Some(&json!("Created"))
            })
            .expect("sysmon 20 Created");
        assert_eq!(wmi20.kind, EventKind::WmiPersistence);
        assert_eq!(wmi20.user.as_deref(), Some("IEWIN7\\IEUser"));
        assert_eq!(wmi20.process, None);
        assert_eq!(
            wmi20.command_line.as_deref(),
            Some(" \"c:\\\\Windows\\\\System32\\\\cmd.exe\"")
        );
        assert_eq!(
            wmi20.details.get("consumer_type"),
            Some(&json!("Command Line"))
        );
        assert_eq!(
            wmi20.summary,
            "WMI consumer \"BotConsumer23\" created: c:\\Windows\\System32\\cmd.exe"
        );
    }

    #[test]
    fn fixture_privesc_roguepotato_sysmon_17_18() {
        let events = attack_fixture("privesc_roguepotato_sysmon_17_18.evtx");
        assert_eq!(count_by_id(&events, 1), 4);
        assert_eq!(count_by_id(&events, 17), 1);
        assert_eq!(count_by_id(&events, 18), 1);

        let pipe17 = events
            .iter()
            .find(|e| e.event_id == Some(17))
            .expect("sysmon 17");
        assert_eq!(pipe17.kind, EventKind::NamedPipe);
        assert_eq!(
            pipe17.target.as_deref(),
            Some("\\RoguePotato\\pipe\\epmapper")
        );
        assert_eq!(pipe17.details.get("event_type"), Some(&json!("CreatePipe")));

        let pipe18 = events
            .iter()
            .find(|e| e.event_id == Some(18))
            .expect("sysmon 18");
        assert_eq!(pipe18.kind, EventKind::NamedPipe);
        assert_eq!(
            pipe18.details.get("event_type"),
            Some(&json!("ConnectPipe"))
        );
        assert_eq!(
            pipe18.summary,
            "System connected to pipe \\RoguePotato\\pipe\\epmapper"
        );
    }

    #[test]
    fn fixture_apt10_jjs_sysmon_1_7_8_13() {
        let events = attack_fixture(
            "apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx",
        );
        assert_eq!(count_by_id(&events, 1), 3);
        assert_eq!(count_by_id(&events, 7), 2);
        assert_eq!(count_by_id(&events, 8), 1);
        assert_eq!(count_by_id(&events, 13), 3);

        let img = events
            .iter()
            .find(|e| e.event_id == Some(7))
            .expect("sysmon 7");
        assert_eq!(img.details.get("signed"), Some(&json!(false)));
        assert!(img.summary.ends_with("(unsigned)"));

        let thread = events
            .iter()
            .find(|e| e.event_id == Some(8))
            .expect("sysmon 8");
        assert_eq!(thread.kind, EventKind::RemoteThread);
        assert_eq!(
            thread.target.as_deref(),
            Some("C:\\Windows\\System32\\svchost.exe")
        );
        assert_eq!(thread.details.get("target_pid"), Some(&json!(3908)));

        let reg = events
            .iter()
            .find(|e| {
                e.event_id == Some(13)
                    && e.target
                        .as_deref()
                        .is_some_and(|t| t.ends_with("ImagePath"))
            })
            .expect("sysmon 13 ImagePath");
        assert_eq!(
            reg.details.get("value"),
            Some(&json!("\"C:\\Users\\IEUser\\Desktop\\info.rar\\jjs.exe\""))
        );
    }

    #[test]
    fn fixture_sysmon_uacme_64() {
        let events = attack_fixture("Sysmon_UACME_64.evtx");
        assert_eq!(count_by_id(&events, 1), 3);
        assert_eq!(count_by_id(&events, 7), 511);
        assert_eq!(count_by_id(&events, 10), 1);
        assert_eq!(count_by_id(&events, 11), 2);
        assert_eq!(count_by_id(&events, 12), 7);
        assert_eq!(count_by_id(&events, 22), 1);
        assert_eq!(count_by_id(&events, 23), 3);

        let dns = events
            .iter()
            .find(|e| e.event_id == Some(22))
            .expect("sysmon 22");
        assert_eq!(dns.kind, EventKind::DnsQuery);
        assert_eq!(dns.target.as_deref(), Some("wpad"));
        assert_eq!(dns.details.get("query_status"), Some(&json!("9003")));
        assert!(!dns.details.contains_key("query_results"));

        let del = events
            .iter()
            .find(|e| e.event_id == Some(23))
            .expect("sysmon 23");
        assert_eq!(del.kind, EventKind::FileDelete);
        assert_eq!(del.user.as_deref(), Some("DESKTOP-NTSSLJD\\den"));
        assert_eq!(del.details.get("is_executable"), Some(&json!(true)));
        assert_eq!(del.details.get("archived"), Some(&json!(true)));
    }
}
