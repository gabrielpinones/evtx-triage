//! Remote access, BITS transfer and WMI-Activity EVTX event extractors.

use std::fmt::Write as _;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, field_u64_dec, format_summary_with_tail, insert_opt_str, insert_opt_u64,
    user_from_fields,
};

static WMI_QUOTED_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r#"(?is)\bCommandLineTemplate\s*[:=]\s*"((?:\\.|[^"\\])*)""#,
        r#"(?is)\bCommandLine\s*[:=]\s*"((?:\\.|[^"\\])*)""#,
        r#"(?is)\bExecutablePath\s*[:=]\s*"((?:\\.|[^"\\])*)""#,
    ]
    .into_iter()
    .filter_map(|pat| Regex::new(pat).ok())
    .collect()
});

static WMI_UNQUOTED_PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?i)\bCommandLineTemplate\s*[:=]\s*([^;\r\n]+)",
        r"(?i)\bCommandLine\s*[:=]\s*([^;\r\n]+)",
        r"(?i)\bExecutablePath\s*[:=]\s*([^;\r\n]+)",
        r"(?i)\bCommandLineEventConsumer\s*:\s*([^\r\n]+)",
    ]
    .into_iter()
    .filter_map(|pat| Regex::new(pat).ok())
    .collect()
});

fn clean_address(data: &Value, key: &str, ignore_local: bool) -> Option<String> {
    field_str(data, key)
        .map(|raw| raw.trim().to_string())
        .filter(|addr| {
            !addr.is_empty() && addr != "-" && !(ignore_local && addr.eq_ignore_ascii_case("LOCAL"))
        })
}

/// TerminalServices-RemoteConnectionManager 1149: RDP user authentication succeeded.
pub(crate) fn extract_rdp_1149(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::RdpConnect);
    event.user = user_from_fields(data, "Param2", "Param1");
    // Preserve loopback/link-local addresses as reported; tunneled RDP appears as 127.0.0.1.
    event.src_ip = clean_address(data, "Param3", false);

    let mut summary = String::from("RDP connection authenticated");
    if let Some(user) = &event.user {
        let _ = write!(summary, " for {user}");
    }
    if let Some(ip) = &event.src_ip {
        let _ = write!(summary, " from {ip}");
    }
    event.summary = format_summary_with_tail(&summary, None);
    Some(event)
}

fn extract_lsm_session(meta: &RecordMeta, data: &Value, action: &str) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::RdpSession);
    event.user = field_str(data, "User");
    event.src_ip = clean_address(data, "Address", true);

    let session_id = field_u64_dec(data, "SessionID");
    insert_opt_u64(&mut event.details, "session_id", session_id);
    event
        .details
        .insert("action".to_string(), Value::String(action.to_string()));

    let mut summary = String::from("RDP session");
    if let Some(id) = session_id {
        let _ = write!(summary, " {id}");
    }
    let _ = write!(summary, " {action}");
    if let Some(user) = &event.user {
        let _ = write!(summary, " for {user}");
    }
    if let Some(ip) = &event.src_ip {
        let _ = write!(summary, " from {ip}");
    }
    event.summary = format_summary_with_tail(&summary, None);
    event
}

/// TerminalServices-LocalSessionManager 21: Remote desktop session logon succeeded.
pub(crate) fn extract_lsm_21(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_lsm_session(meta, data, "logon"))
}

/// TerminalServices-LocalSessionManager 24: Remote desktop session disconnected.
pub(crate) fn extract_lsm_24(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_lsm_session(meta, data, "disconnect"))
}

/// TerminalServices-LocalSessionManager 25: Remote desktop session reconnected.
pub(crate) fn extract_lsm_25(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_lsm_session(meta, data, "reconnect"))
}

fn extract_bits_transfer(
    meta: &RecordMeta,
    data: &Value,
    action: &str,
    verb: &str,
) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::BitsJob);
    event.target = field_str(data, "url");

    let job_name = field_str(data, "name");
    insert_opt_str(&mut event.details, "job_name", job_name.clone());
    insert_opt_str(&mut event.details, "job_id", field_str(data, "Id"));
    insert_opt_str(
        &mut event.details,
        "transfer_id",
        field_str(data, "transferId"),
    );
    event
        .details
        .insert("action".to_string(), Value::String(action.to_string()));
    // Keep `hr` verbatim via scalar_str (real EVTX stores 0 as an integer).
    insert_opt_str(&mut event.details, "result", field_str(data, "hr"));
    insert_opt_u64(
        &mut event.details,
        "bytes_total",
        field_u64_dec(data, "bytesTotal"),
    );
    insert_opt_u64(
        &mut event.details,
        "bytes_transferred",
        field_u64_dec(data, "bytesTransferred"),
    );

    let mut summary = String::from("BITS job");
    if let Some(name) = &job_name {
        let _ = write!(summary, " \"{name}\"");
    }
    let _ = write!(summary, " {verb} transfer");
    if let Some(url) = &event.target {
        let _ = write!(summary, " from {url}");
    }
    event.summary = format_summary_with_tail(&summary, None);
    event
}

/// BITS-Client 59: BITS file transfer started.
pub(crate) fn extract_bits_59(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_bits_transfer(meta, data, "start", "started"))
}

/// BITS-Client 60: BITS file transfer stopped.
pub(crate) fn extract_bits_60(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_bits_transfer(meta, data, "stop", "stopped"))
}

/// Unescapes MOF string escapes (`\\` and `\"`) while keeping single Windows path backslashes.
fn unescape_mof_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn match_command_in_texts(patterns: &[Regex], texts: &[&str], unescape: bool) -> Option<String> {
    for re in patterns {
        for text in texts {
            if let Some(val) = re.captures(text).and_then(|c| c.get(1)).map(|m| m.as_str()) {
                let candidate = if unescape {
                    unescape_mof_string(val)
                } else {
                    val.to_string()
                };
                let trimmed = candidate.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn looks_like_direct_command(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("eventconsumer") || lower.contains(".name=") || lower.starts_with("__") {
        return None;
    }
    let first_token = trimmed
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches('"')
        .to_ascii_lowercase();
    let is_exe_path = (trimmed.len() >= 3 && trimmed.as_bytes().get(1) == Some(&b':'))
        || trimmed.starts_with(r"\\")
        || [".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"]
            .iter()
            .any(|ext| first_token.ends_with(ext))
        || [
            "cmd",
            "powershell",
            "pwsh",
            "mshta",
            "rundll32",
            "regsvr32",
            "wscript",
            "cscript",
        ]
        .contains(&first_token.as_str());
    is_exe_path.then(|| trimmed.to_string())
}

fn extract_wmi_command_line(
    consumer: Option<&str>,
    possible_cause: Option<&str>,
) -> Option<String> {
    let mut texts = Vec::with_capacity(2);
    if let Some(c) = consumer {
        texts.push(c);
    }
    if let Some(p) = possible_cause {
        texts.push(p);
    }
    if texts.is_empty() {
        return None;
    }

    match_command_in_texts(&WMI_QUOTED_PATTERNS, &texts, true)
        .or_else(|| match_command_in_texts(&WMI_UNQUOTED_PATTERNS, &texts, false))
        .or_else(|| consumer.and_then(looks_like_direct_command))
}

/// WMI-Activity 5861: Permanent WMI event consumer to filter binding registered.
pub(crate) fn extract_wmi_5861(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::WmiPersistence);
    let consumer = field_str(data, "CONSUMER");
    let filter = field_str(data, "ESS");
    // Windows WMI-Activity 5861 logs `NamespaceName`, while some references say `Namespace`.
    let namespace = field_str(data, "NamespaceName").or_else(|| field_str(data, "Namespace"));
    let possible_cause = field_str(data, "PossibleCause");

    event.target = consumer.clone();
    event.command_line = extract_wmi_command_line(consumer.as_deref(), possible_cause.as_deref());

    insert_opt_str(&mut event.details, "namespace", namespace.clone());
    insert_opt_str(&mut event.details, "filter", filter.clone());
    insert_opt_str(&mut event.details, "possible_cause", possible_cause);

    let prefix = match (&consumer, &filter, &namespace) {
        (Some(c), Some(f), _) => format!("WMI subscription {c} (filter {f})"),
        (Some(c), None, _) => format!("WMI subscription {c}"),
        (None, Some(f), _) => format!("WMI subscription for filter {f}"),
        (None, None, Some(ns)) => format!("WMI subscription in {ns}"),
        (None, None, None) => String::from("WMI subscription registered"),
    };
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    Some(event)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use jiff::Timestamp;
    use serde_json::json;

    use super::*;
    use crate::source::{Format, ReadOptions, source_for};

    fn meta(provider: &str, event_id: u32) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Operational".into()),
            provider: provider.into(),
            event_id,
            record_id: 1,
            file_record_id: None,
            user_sid: None,
            file: "test.evtx".into(),
        }
    }

    fn fixture_events(parts: &[&str]) -> Vec<TimelineEvent> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        for part in parts {
            path.push(part);
        }
        let mut events = Vec::new();
        let stats = source_for(Format::Evtx)
            .read(&path, &ReadOptions::default(), &mut events)
            .unwrap();
        assert_eq!(stats.errors, 0);
        events
    }

    #[test]
    fn extracts_1149_normal_and_missing_fields() {
        let m = meta(
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
            1149,
        );
        let normal = json!({
            "Param1": "alice",
            "Param2": "CORP",
            "Param3": "203.0.113.7"
        });
        let ev = extract_rdp_1149(&m, &normal).unwrap();
        assert_eq!(ev.kind, EventKind::RdpConnect);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(ev.src_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(
            ev.summary,
            "RDP connection authenticated for CORP\\alice from 203.0.113.7"
        );

        let partial = json!({
            "Param1": "localuser",
            "Param2": "",
            "Param3": "-"
        });
        let ev_partial = extract_rdp_1149(&m, &partial).unwrap();
        assert_eq!(ev_partial.user.as_deref(), Some("localuser"));
        assert_eq!(ev_partial.src_ip, None);
        assert_eq!(
            ev_partial.summary,
            "RDP connection authenticated for localuser"
        );

        let empty = extract_rdp_1149(&m, &json!({})).unwrap();
        assert_eq!(empty.user, None);
        assert_eq!(empty.src_ip, None);
        assert_eq!(empty.summary, "RDP connection authenticated");

        let null_data = extract_rdp_1149(&m, &Value::Null).unwrap();
        assert_eq!(null_data.summary, "RDP connection authenticated");
    }

    #[test]
    fn extracts_lsm_21_24_25_normal_local_and_missing_fields() {
        let prov = "Microsoft-Windows-TerminalServices-LocalSessionManager";

        let logon_data = json!({
            "User": "CORP\\alice",
            "SessionID": 2,
            "Address": "203.0.113.7"
        });
        let ev21 = extract_lsm_21(&meta(prov, 21), &logon_data).unwrap();
        assert_eq!(ev21.kind, EventKind::RdpSession);
        assert_eq!(ev21.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(ev21.src_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(ev21.details["session_id"], json!(2));
        assert_eq!(ev21.details["action"], "logon");
        assert_eq!(
            ev21.summary,
            "RDP session 2 logon for CORP\\alice from 203.0.113.7"
        );

        let local_disconnect = json!({
            "User": "CORP\\alice",
            "SessionID": "2",
            "Address": "LOCAL"
        });
        let ev24 = extract_lsm_24(&meta(prov, 24), &local_disconnect).unwrap();
        assert_eq!(ev24.kind, EventKind::RdpSession);
        assert_eq!(ev24.src_ip, None);
        assert_eq!(ev24.details["session_id"], json!(2));
        assert_eq!(ev24.details["action"], "disconnect");
        assert_eq!(ev24.summary, "RDP session 2 disconnect for CORP\\alice");

        let empty_reconnect = json!({
            "User": "CORP\\alice",
            "SessionID": 5,
            "Address": ""
        });
        let ev25 = extract_lsm_25(&meta(prov, 25), &empty_reconnect).unwrap();
        assert_eq!(ev25.kind, EventKind::RdpSession);
        assert_eq!(ev25.src_ip, None);
        assert_eq!(ev25.details["session_id"], json!(5));
        assert_eq!(ev25.details["action"], "reconnect");
        assert_eq!(ev25.summary, "RDP session 5 reconnect for CORP\\alice");

        let missing = extract_lsm_21(&meta(prov, 21), &json!({})).unwrap();
        assert_eq!(missing.user, None);
        assert_eq!(missing.src_ip, None);
        assert!(!missing.details.contains_key("session_id"));
        assert_eq!(missing.details["action"], "logon");
        assert_eq!(missing.summary, "RDP session logon");

        let null_data = extract_lsm_24(&meta(prov, 24), &Value::Null).unwrap();
        assert_eq!(null_data.summary, "RDP session disconnect");
    }

    #[test]
    fn extracts_bits_59_and_60_query_url_and_missing_fields() {
        let prov = "Microsoft-Windows-Bits-Client";
        let start = json!({
            "transferId": "{11111111-1111-1111-1111-111111111111}",
            "name": "x",
            "Id": "{22222222-2222-2222-2222-222222222222}",
            "url": "https://example.com/a.exe?token=abc&dl=1",
            "bytesTotal": 4096,
            "bytesTransferred": 0
        });
        let ev59 = extract_bits_59(&meta(prov, 59), &start).unwrap();
        assert_eq!(ev59.kind, EventKind::BitsJob);
        assert_eq!(
            ev59.target.as_deref(),
            Some("https://example.com/a.exe?token=abc&dl=1")
        );
        assert_eq!(ev59.details["job_name"], "x");
        assert_eq!(
            ev59.details["job_id"],
            "{22222222-2222-2222-2222-222222222222}"
        );
        assert_eq!(
            ev59.details["transfer_id"],
            "{11111111-1111-1111-1111-111111111111}"
        );
        assert_eq!(ev59.details["action"], "start");
        assert_eq!(ev59.details["bytes_total"], json!(4096));
        assert_eq!(ev59.details["bytes_transferred"], json!(0));
        assert!(!ev59.details.contains_key("result"));
        assert_eq!(
            ev59.summary,
            "BITS job \"x\" started transfer from https://example.com/a.exe?token=abc&dl=1"
        );

        let stop = json!({
            "transferId": "{11111111-1111-1111-1111-111111111111}",
            "name": "x",
            "Id": "{22222222-2222-2222-2222-222222222222}",
            "url": "https://example.com/a.exe?token=abc&dl=1",
            "hr": "0x80072ee7",
            "bytesTotal": 4096,
            "bytesTransferred": 1024
        });
        let ev60 = extract_bits_60(&meta(prov, 60), &stop).unwrap();
        assert_eq!(ev60.details["action"], "stop");
        assert_eq!(ev60.details["result"], "0x80072ee7");
        assert_eq!(ev60.details["bytes_total"], json!(4096));
        assert_eq!(ev60.details["bytes_transferred"], json!(1024));
        assert_eq!(
            ev60.summary,
            "BITS job \"x\" stopped transfer from https://example.com/a.exe?token=abc&dl=1"
        );

        let missing59 = extract_bits_59(&meta(prov, 59), &json!({})).unwrap();
        assert_eq!(missing59.target, None);
        assert_eq!(missing59.details["action"], "start");
        assert!(!missing59.details.contains_key("job_name"));
        assert_eq!(missing59.summary, "BITS job started transfer");

        let null60 = extract_bits_60(&meta(prov, 60), &Value::Null).unwrap();
        assert_eq!(null60.details["action"], "stop");
        assert_eq!(null60.summary, "BITS job stopped transfer");
    }

    #[test]
    fn extracts_wmi_5861_documented_shape_command_line_and_missing_fields() {
        let m = meta("Microsoft-Windows-WMI-Activity", 5861);

        let with_cmd = json!({
            "NamespaceName": "root\\subscription",
            "ESS": "__EventFilter.Name=\"BotFilter82\"",
            "CONSUMER": "CommandLineEventConsumer.Name=\"BotConsumer23\"",
            "PossibleCause": "Binding EventConsumer:\ninstance of CommandLineEventConsumer\n{\n\tCommandLineTemplate = \"C:\\\\Windows\\\\System32\\\\cmd.exe /c \\\"whoami\\\"\";\n\tExecutablePath = \"C:\\\\Windows\\\\System32\\\\cmd.exe\";\n\tName = \"BotConsumer23\";\n};"
        });
        let ev = extract_wmi_5861(&m, &with_cmd).unwrap();
        assert_eq!(ev.kind, EventKind::WmiPersistence);
        assert_eq!(
            ev.target.as_deref(),
            Some("CommandLineEventConsumer.Name=\"BotConsumer23\"")
        );
        assert_eq!(ev.details["namespace"], "root\\subscription");
        assert_eq!(ev.details["filter"], "__EventFilter.Name=\"BotFilter82\"");
        assert!(ev.details.contains_key("possible_cause"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe /c \"whoami\"")
        );
        assert!(!ev.summary.contains('\n'));
        assert!(ev.summary.contains("BotConsumer23"));
        assert!(ev.summary.contains("whoami"));

        // `Namespace` (without `Name` suffix) and consumer-only without command line.
        let without_cmd = json!({
            "Namespace": "root\\cimv2",
            "ESS": "__EventFilter.Name=\"Filter1\"",
            "CONSUMER": "CommandLineEventConsumer.Name=\"Bot\""
        });
        let ev_no_cmd = extract_wmi_5861(&m, &without_cmd).unwrap();
        assert_eq!(ev_no_cmd.details["namespace"], "root\\cimv2");
        assert_eq!(ev_no_cmd.command_line, None);
        assert!(!ev_no_cmd.details.contains_key("possible_cause"));
        assert_eq!(
            ev_no_cmd.summary,
            "WMI subscription CommandLineEventConsumer.Name=\"Bot\" (filter __EventFilter.Name=\"Filter1\")"
        );

        // Fallback to ExecutablePath when CommandLineTemplate is absent.
        let exec_only = json!({
            "NamespaceName": "root\\subscription",
            "CONSUMER": "CommandLineEventConsumer.Name=\"Dropper\"",
            "PossibleCause": "ExecutablePath = \"powershell.exe -enc SQBFAFgA\";"
        });
        let ev_exec = extract_wmi_5861(&m, &exec_only).unwrap();
        assert_eq!(
            ev_exec.command_line.as_deref(),
            Some("powershell.exe -enc SQBFAFgA")
        );

        // Consumer string containing a direct command line without key=value syntax.
        let direct_consumer = json!({
            "Namespace": "root\\subscription",
            "CONSUMER": "powershell.exe -nop -w hidden -c calc.exe"
        });
        let ev_direct = extract_wmi_5861(&m, &direct_consumer).unwrap();
        assert_eq!(
            ev_direct.command_line.as_deref(),
            Some("powershell.exe -nop -w hidden -c calc.exe")
        );

        // Missing fields and Value::Null never skip the record.
        let partial = extract_wmi_5861(&m, &json!({})).unwrap();
        assert_eq!(partial.target, None);
        assert_eq!(partial.command_line, None);
        assert_eq!(partial.summary, "WMI subscription registered");

        let null_data = extract_wmi_5861(&m, &Value::Null).unwrap();
        assert_eq!(null_data.summary, "WMI subscription registered");
    }

    #[test]
    fn fixture_rdp_1149_extracts_all_eleven_including_loopback() {
        let events = fixture_events(&[
            "attack-samples",
            "DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx",
        ]);
        assert_eq!(events.len(), 11);
        for ev in &events {
            assert_eq!(ev.kind, EventKind::RdpConnect);
            assert_eq!(ev.event_id, Some(1149));
            assert_eq!(
                ev.provider.as_deref(),
                Some("Microsoft-Windows-TerminalServices-RemoteConnectionManager")
            );
            assert!(ev.user.is_some());
            assert!(ev.src_ip.is_some());
        }

        let ips: Vec<&str> = events.iter().filter_map(|e| e.src_ip.as_deref()).collect();
        assert!(ips.contains(&"127.0.0.1"));
        assert!(ips.contains(&"fe80::80ac:4126:fa58:1b81%10"));
        assert!(ips.contains(&"10.0.2.15"));
        assert!(ips.contains(&"10.0.2.16"));

        let loopback = events
            .iter()
            .find(|e| e.src_ip.as_deref() == Some("127.0.0.1"))
            .unwrap();
        assert_eq!(loopback.record_id, Some(228));
        assert_eq!(loopback.user.as_deref(), Some("example\\admin01"));
        assert_eq!(
            loopback.summary,
            "RDP connection authenticated for example\\admin01 from 127.0.0.1"
        );
    }

    #[test]
    fn fixture_bits_59_and_60_desktopimgdownldr() {
        let events = fixture_events(&[
            "attack-samples",
            "windows_bits_4_59_60_lolbas desktopimgdownldr.evtx",
        ]);
        assert_eq!(events.len(), 2);

        let started = &events[0];
        assert_eq!(started.kind, EventKind::BitsJob);
        assert_eq!(started.event_id, Some(59));
        assert_eq!(
            started.target.as_deref(),
            Some("https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z")
        );
        assert_eq!(started.details["job_name"], "Download LockScreen Image");
        assert_eq!(
            started.details["job_id"],
            "{ff819706-9ff9-490b-ade5-b069232c5d23}"
        );
        assert_eq!(
            started.details["transfer_id"],
            "{fcc284db-aa62-40bb-b372-b5ba6a5ad840}"
        );
        assert_eq!(started.details["action"], "start");
        assert_eq!(started.details["bytes_total"], json!(162791));
        assert_eq!(started.details["bytes_transferred"], json!(0));
        assert!(!started.details.contains_key("result"));
        assert_eq!(
            started.summary,
            "BITS job \"Download LockScreen Image\" started transfer from https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z"
        );

        let stopped = &events[1];
        assert_eq!(stopped.kind, EventKind::BitsJob);
        assert_eq!(stopped.event_id, Some(60));
        assert_eq!(
            stopped.provider.as_deref(),
            Some("Microsoft-Windows-Bits-Client")
        );
        assert_eq!(
            stopped.target.as_deref(),
            Some("https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z")
        );
        assert_eq!(stopped.details["job_name"], "Download LockScreen Image");
        assert_eq!(
            stopped.details["job_id"],
            "{ff819706-9ff9-490b-ade5-b069232c5d23}"
        );
        assert_eq!(
            stopped.details["transfer_id"],
            "{fcc284db-aa62-40bb-b372-b5ba6a5ad840}"
        );
        assert_eq!(stopped.details["action"], "stop");
        assert_eq!(stopped.details["result"], "0");
        assert_eq!(stopped.details["bytes_total"], json!(162791));
        assert_eq!(stopped.details["bytes_transferred"], json!(162791));
        assert_eq!(
            stopped.summary,
            "BITS job \"Download LockScreen Image\" stopped transfer from https://a.uguu.se/Hv0bgvgHGNeH_Bin.7z"
        );
    }
}
