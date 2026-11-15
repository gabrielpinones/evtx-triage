use std::fmt::Write as _;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, field_u32, field_u64_hex, insert_opt_str, user_from_fields,
};

fn populate_logon_fields(event: &mut TimelineEvent, data: &Value) {
    event.user = user_from_fields(data, "TargetDomainName", "TargetUserName");
    event.src_ip = field_str(data, "IpAddress");
    event.logon_type = field_u32(data, "LogonType");
    event.logon_id = field_str(data, "TargetLogonId");
    event.process = field_str(data, "ProcessName");

    insert_opt_str(
        &mut event.details,
        "workstation",
        field_str(data, "WorkstationName"),
    );
    insert_opt_str(
        &mut event.details,
        "logon_process",
        // Windows pads this name with trailing spaces ("NtLmSsp ").
        field_str(data, "LogonProcessName").map(|name| name.trim().to_string()),
    );
    insert_opt_str(
        &mut event.details,
        "auth_package",
        field_str(data, "AuthenticationPackageName"),
    );
    insert_opt_str(&mut event.details, "src_port", field_str(data, "IpPort"));
    insert_opt_str(
        &mut event.details,
        "subject_user",
        user_from_fields(data, "SubjectDomainName", "SubjectUserName"),
    );
    insert_opt_str(
        &mut event.details,
        "target_sid",
        field_str(data, "TargetUserSid"),
    );
    insert_opt_str(
        &mut event.details,
        "elevated_token",
        field_str(data, "ElevatedToken"),
    );
}

pub(crate) fn extract_4624(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::LogonSuccess);
    populate_logon_fields(&mut event, data);
    event.summary = logon_summary("Logon", &event, None);
    event
}

pub(crate) fn extract_4625(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::LogonFailure);
    populate_logon_fields(&mut event, data);

    let status = field_str(data, "Status");
    let sub_status = field_str(data, "SubStatus");
    let failure = sub_status
        .as_deref()
        .and_then(ntstatus_reason)
        .or_else(|| status.as_deref().and_then(ntstatus_reason));

    insert_opt_str(&mut event.details, "status", status);
    insert_opt_str(&mut event.details, "sub_status", sub_status);
    if let Some(reason) = failure {
        event
            .details
            .insert("failure".to_string(), Value::String(reason.to_string()));
    }

    event.summary = logon_summary("Failed logon", &event, failure);
    event
}

pub(crate) fn extract_4648(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::ExplicitLogon);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.target = user_from_fields(data, "TargetDomainName", "TargetUserName");
    event.logon_id = field_str(data, "SubjectLogonId");
    event.process = field_str(data, "ProcessName");
    event.pid = field_u64_hex(data, "ProcessId");
    event.src_ip = field_str(data, "IpAddress");

    let target_server = field_str(data, "TargetServerName");
    insert_opt_str(&mut event.details, "target_server", target_server.clone());
    insert_opt_str(
        &mut event.details,
        "target_info",
        field_str(data, "TargetInfo"),
    );
    insert_opt_str(&mut event.details, "src_port", field_str(data, "IpPort"));

    let mut summary = String::from(event.user.as_deref().unwrap_or("unknown"));
    summary.push_str(" used explicit credentials");
    if let Some(target) = &event.target {
        let _ = write!(summary, " of {target}");
    }
    if let Some(server) = &target_server {
        let _ = write!(summary, " for server {server}");
    }
    event.summary = summary;
    event
}

fn logon_summary(verb: &str, event: &TimelineEvent, failure: Option<&str>) -> String {
    let mut s = String::from(verb);
    if let Some(lt) = event.logon_type {
        let _ = write!(s, " type {lt}");
    }
    if let Some(user) = &event.user {
        let prep = if failure.is_some() || verb == "Failed logon" {
            "for"
        } else {
            "by"
        };
        let _ = write!(s, " {prep} {user}");
    }
    if let Some(ip) = &event.src_ip {
        let _ = write!(s, " from {ip}");
    }
    if let Some(reason) = failure {
        let _ = write!(s, ": {reason}");
    }
    s
}

fn ntstatus_reason(code: &str) -> Option<&'static str> {
    match code.trim().to_ascii_lowercase().as_str() {
        "0xc0000064" => Some("unknown user"),
        "0xc000006a" => Some("wrong password"),
        "0xc000006d" => Some("bad user name or password"),
        "0xc000006e" => Some("account restriction"),
        "0xc000006f" => Some("outside allowed hours"),
        "0xc0000070" => Some("workstation restriction"),
        "0xc0000071" => Some("password expired"),
        "0xc0000072" => Some("account disabled"),
        "0xc0000133" => Some("clock skew"),
        "0xc000015b" => Some("logon type not granted"),
        "0xc0000193" => Some("account expired"),
        "0xc0000224" => Some("password must change"),
        "0xc0000234" => Some("account locked out"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use serde_json::json;

    fn meta(event_id: u32) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id,
            record_id: 1,
            file_record_id: None,
            user_sid: None,
            file: "test.evtx".into(),
        }
    }

    #[test]
    fn extracts_4624_with_dash_values_omitted() {
        let data = json!({
            "SubjectUserSid": "S-1-0-0",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "TargetUserSid": "S-1-5-21-1-1000",
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x17e29a",
            "LogonType": 3,
            "LogonProcessName": "NtLmSsp",
            "AuthenticationPackageName": "NTLM",
            "WorkstationName": "-",
            "ProcessName": "-",
            "IpAddress": "10.0.0.5",
            "IpPort": "49236",
            "ElevatedToken": "%%1842"
        });
        let ev = extract_4624(&meta(4624), &data);
        assert_eq!(ev.kind, EventKind::LogonSuccess);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(ev.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(ev.logon_type, Some(3));
        assert_eq!(ev.logon_id.as_deref(), Some("0x17e29a"));
        assert_eq!(ev.process, None);
        assert!(!ev.details.contains_key("workstation"));
        assert!(!ev.details.contains_key("subject_user"));
        assert_eq!(ev.details["src_port"], "49236");
        assert_eq!(ev.details["elevated_token"], "%%1842");
        assert_eq!(ev.summary, "Logon type 3 by CORP\\alice from 10.0.0.5");
    }

    #[test]
    fn extracts_4625_prefers_substatus_and_falls_back_to_status() {
        let data = json!({
            "SubjectUserName": "IEUser",
            "SubjectDomainName": "MSEDGEWIN10",
            "TargetUserSid": "S-1-0-0",
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "Status": "0xC000006D",
            "SubStatus": "0xc000006a",
            "LogonType": 3,
            "LogonProcessName": "Chrome",
            "AuthenticationPackageName": "Negotiate",
            "WorkstationName": "MSEDGEWIN10",
            "ProcessName": "C:\\chrome.exe",
            "IpAddress": "10.0.0.5",
            "IpPort": "-"
        });
        let ev = extract_4625(&meta(4625), &data);
        assert_eq!(ev.kind, EventKind::LogonFailure);
        assert_eq!(ev.details["failure"], "wrong password");
        assert_eq!(ev.details["status"], "0xC000006D");
        assert_eq!(ev.details["sub_status"], "0xc000006a");
        assert_eq!(
            ev.summary,
            "Failed logon type 3 for CORP\\alice from 10.0.0.5: wrong password"
        );

        let fallback = json!({
            "TargetUserName": "bob",
            "Status": "0xC0000234",
            "SubStatus": "0x0",
            "LogonType": 2
        });
        let ev2 = extract_4625(&meta(4625), &fallback);
        assert_eq!(ev2.details["failure"], "account locked out");
    }

    #[test]
    fn maps_all_ntstatus_failure_codes_case_insensitively() {
        let cases = [
            ("0xC0000064", "unknown user"),
            ("0xc000006a", "wrong password"),
            ("0xC000006D", "bad user name or password"),
            ("0xc000006e", "account restriction"),
            ("0xC000006F", "outside allowed hours"),
            ("0xc0000070", "workstation restriction"),
            ("0xC0000071", "password expired"),
            ("0xc0000072", "account disabled"),
            ("0xC0000133", "clock skew"),
            ("0xc000015b", "logon type not granted"),
            ("0xC0000193", "account expired"),
            ("0xc0000224", "password must change"),
            ("0xC0000234", "account locked out"),
        ];
        for (code, expected) in cases {
            assert_eq!(ntstatus_reason(code), Some(expected));
        }
        assert_eq!(ntstatus_reason("0x0"), None);
    }

    #[test]
    fn extracts_4648_explicit_logon() {
        let data = json!({
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "TargetUserName": "admin",
            "TargetDomainName": "CORP",
            "TargetServerName": "FS01",
            "TargetInfo": "FS01.corp.local",
            "ProcessId": "0x704",
            "ProcessName": "C:\\Windows\\System32\\runas.exe",
            "IpAddress": "10.0.0.12",
            "IpPort": "50001"
        });
        let ev = extract_4648(&meta(4648), &data);
        assert_eq!(ev.kind, EventKind::ExplicitLogon);
        assert_eq!(ev.user.as_deref(), Some("CORP\\bob"));
        assert_eq!(ev.target.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev.pid, Some(0x704));
        assert_eq!(ev.details["target_server"], "FS01");
        assert_eq!(ev.details["target_info"], "FS01.corp.local");
        assert_eq!(ev.details["src_port"], "50001");
        assert_eq!(
            ev.summary,
            "CORP\\bob used explicit credentials of CORP\\admin for server FS01"
        );
    }
}
