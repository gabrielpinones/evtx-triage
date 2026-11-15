use std::fmt::Write as _;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, field_u32, field_u64_hex, format_summary_with_tail, insert_opt_bool,
    insert_opt_str, user_from_fields,
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

fn base_logoff_event(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::Logoff);
    event.user = user_from_fields(data, "TargetDomainName", "TargetUserName");
    event.logon_id = field_str(data, "TargetLogonId");
    insert_opt_str(
        &mut event.details,
        "target_sid",
        field_str(data, "TargetUserSid"),
    );
    event
}

/// 4634: an account was logged off.
pub(crate) fn extract_4634(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = base_logoff_event(meta, data);
    event.logon_type = field_u32(data, "LogonType");

    let mut summary = String::from("Logoff");
    if let Some(lt) = event.logon_type {
        let _ = write!(summary, " type {lt}");
    }
    if let Some(user) = &event.user {
        let _ = write!(summary, " of {user}");
    }
    event.summary = format_summary_with_tail(&summary, None);
    Some(event)
}

/// 4647: user initiated logoff.
pub(crate) fn extract_4647(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = base_logoff_event(meta, data);
    insert_opt_bool(&mut event.details, "user_initiated", Some(true));

    let summary = format!("{} logged off", event.user.as_deref().unwrap_or("unknown"));
    event.summary = format_summary_with_tail(&summary, None);
    Some(event)
}

/// 4672: special privileges assigned to new logon.
pub(crate) fn extract_4672(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::SpecialPrivileges);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.logon_id = field_str(data, "SubjectLogonId");
    insert_opt_str(
        &mut event.details,
        "subject_sid",
        field_str(data, "SubjectUserSid"),
    );

    let privilege_list = field_str(data, "PrivilegeList");
    let privileges: Vec<&str> = privilege_list
        .as_deref()
        .map(|list| list.split_whitespace().collect())
        .unwrap_or_default();
    if !privileges.is_empty() {
        event.details.insert(
            "privileges".to_string(),
            Value::Array(
                privileges
                    .iter()
                    .map(|p| Value::String((*p).to_string()))
                    .collect(),
            ),
        );
    }

    let mut prefix = String::from("Special privileges");
    if let Some(user) = &event.user {
        let _ = write!(prefix, " for {user}");
    }
    let tail = (!privileges.is_empty()).then(|| privileges.join(", "));
    event.summary = format_summary_with_tail(&prefix, tail.as_deref());
    Some(event)
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

pub(crate) fn ntstatus_reason(code: &str) -> Option<&'static str> {
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

    #[test]
    fn extracts_4634_logoff_normal_missing_and_dash() {
        let normal = json!({
            "TargetUserSid": "S-1-5-21-1-1000",
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x1a2b3",
            "LogonType": 3
        });
        let ev = extract_4634(&meta(4634), &normal).unwrap();
        assert_eq!(ev.kind, EventKind::Logoff);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x1a2b3"));
        assert_eq!(ev.logon_type, Some(3));
        assert_eq!(ev.details["target_sid"], "S-1-5-21-1-1000");
        assert_eq!(ev.summary, "Logoff type 3 of CORP\\alice");

        let missing = extract_4634(&meta(4634), &json!({})).unwrap();
        assert_eq!(missing.kind, EventKind::Logoff);
        assert_eq!(missing.user, None);
        assert_eq!(missing.logon_id, None);
        assert_eq!(missing.logon_type, None);
        assert!(!missing.details.contains_key("target_sid"));
        assert_eq!(missing.summary, "Logoff");

        let dash = json!({
            "TargetUserSid": "-",
            "TargetUserName": "-",
            "TargetDomainName": "-",
            "TargetLogonId": "-",
            "LogonType": 3
        });
        let ev_dash = extract_4634(&meta(4634), &dash).unwrap();
        assert_eq!(ev_dash.user, None);
        assert_eq!(ev_dash.logon_id, None);
        assert_eq!(ev_dash.logon_type, Some(3));
        assert!(!ev_dash.details.contains_key("target_sid"));
        assert_eq!(ev_dash.summary, "Logoff type 3");
    }

    #[test]
    fn extracts_4647_user_initiated_logoff_normal_missing_and_dash() {
        let normal = json!({
            "TargetUserSid": "S-1-5-21-1-1000",
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "TargetLogonId": "0x3e7"
        });
        let ev = extract_4647(&meta(4647), &normal).unwrap();
        assert_eq!(ev.kind, EventKind::Logoff);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x3e7"));
        assert_eq!(ev.logon_type, None);
        assert_eq!(ev.details["target_sid"], "S-1-5-21-1-1000");
        assert_eq!(ev.details["user_initiated"], json!(true));
        assert_eq!(ev.summary, "CORP\\alice logged off");

        let missing = extract_4647(&meta(4647), &json!({})).unwrap();
        assert_eq!(missing.kind, EventKind::Logoff);
        assert_eq!(missing.user, None);
        assert_eq!(missing.logon_id, None);
        assert_eq!(missing.logon_type, None);
        assert!(!missing.details.contains_key("target_sid"));
        assert_eq!(missing.details["user_initiated"], json!(true));
        assert_eq!(missing.summary, "unknown logged off");

        let dash = json!({
            "TargetUserSid": "-",
            "TargetUserName": "-",
            "TargetDomainName": "-",
            "TargetLogonId": "-",
            "LogonType": 3
        });
        let ev_dash = extract_4647(&meta(4647), &dash).unwrap();
        assert_eq!(ev_dash.user, None);
        assert_eq!(ev_dash.logon_id, None);
        assert_eq!(ev_dash.logon_type, None);
        assert!(!ev_dash.details.contains_key("target_sid"));
        assert_eq!(ev_dash.details["user_initiated"], json!(true));
        assert_eq!(ev_dash.summary, "unknown logged off");
    }

    #[test]
    fn extracts_4672_special_privileges_normal_mixed_empty_and_dash() {
        let normal = json!({
            "SubjectUserSid": "S-1-5-21-1-500",
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x1a2b3",
            "PrivilegeList": "  SeSecurityPrivilege\r\n\t\t\tSeBackupPrivilege\n\tSeDebugPrivilege  SeImpersonatePrivilege\r\n"
        });
        let ev = extract_4672(&meta(4672), &normal).unwrap();
        assert_eq!(ev.kind, EventKind::SpecialPrivileges);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x1a2b3"));
        assert_eq!(ev.details["subject_sid"], "S-1-5-21-1-500");
        assert_eq!(
            ev.details["privileges"],
            json!([
                "SeSecurityPrivilege",
                "SeBackupPrivilege",
                "SeDebugPrivilege",
                "SeImpersonatePrivilege"
            ])
        );
        assert_eq!(
            ev.summary,
            "Special privileges for CORP\\alice: SeSecurityPrivilege, SeBackupPrivilege, SeDebugPrivilege, SeImpersonatePrivilege"
        );

        for empty_list in ["", "\r\n\t  \t"] {
            let empty_data = json!({
                "SubjectUserSid": "S-1-5-18",
                "SubjectUserName": "SYSTEM",
                "SubjectDomainName": "NT AUTHORITY",
                "SubjectLogonId": "0x3e7",
                "PrivilegeList": empty_list
            });
            let ev_empty = extract_4672(&meta(4672), &empty_data).unwrap();
            assert!(!ev_empty.details.contains_key("privileges"));
            assert_eq!(
                ev_empty.summary,
                "Special privileges for NT AUTHORITY\\SYSTEM"
            );
        }

        let missing = extract_4672(&meta(4672), &json!({})).unwrap();
        assert_eq!(missing.kind, EventKind::SpecialPrivileges);
        assert_eq!(missing.user, None);
        assert_eq!(missing.logon_id, None);
        assert!(!missing.details.contains_key("subject_sid"));
        assert!(!missing.details.contains_key("privileges"));
        assert_eq!(missing.summary, "Special privileges");

        let dash = json!({
            "SubjectUserSid": "-",
            "SubjectUserName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "-",
            "PrivilegeList": "-"
        });
        let ev_dash = extract_4672(&meta(4672), &dash).unwrap();
        assert_eq!(ev_dash.user, None);
        assert_eq!(ev_dash.logon_id, None);
        assert!(!ev_dash.details.contains_key("subject_sid"));
        assert!(!ev_dash.details.contains_key("privileges"));
        assert_eq!(ev_dash.summary, "Special privileges");

        let many: Vec<String> = (1..=20)
            .map(|i| format!("SePrivilegeNameNumber{i:02}"))
            .collect();
        let long = json!({
            "SubjectUserName": "alice",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x1",
            "PrivilegeList": many.join("\r\n\t\t\t")
        });
        let ev_long = extract_4672(&meta(4672), &long).unwrap();
        assert_eq!(ev_long.details["privileges"].as_array().unwrap().len(), 20);
        assert!(ev_long.summary.chars().count() <= 200);
        assert!(ev_long.summary.ends_with("..."));
        assert!(!ev_long.summary.contains('\n'));
        assert!(!ev_long.summary.contains('\r'));
    }

    fn attack_fixture(name: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("attack-samples")
            .join(name)
    }

    #[test]
    fn fixture_juicy_potato_has_one_4634_logoff() {
        let mut events = Vec::new();
        let stats = crate::source::evtx::reader::read_file(
            &attack_fixture("4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx"),
            &crate::source::ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);

        let logoffs: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::Logoff && e.event_id == Some(4634))
            .collect();
        assert_eq!(logoffs.len(), 1);
        let ev = logoffs[0];
        assert_eq!(ev.user.as_deref(), Some("NT AUTHORITY\\ANONYMOUS LOGON"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x1d12916"));
        assert_eq!(ev.logon_type, Some(3));
        assert_eq!(ev.details["target_sid"], "S-1-5-7");
        assert_eq!(ev.summary, "Logoff type 3 of NT AUTHORITY\\ANONYMOUS LOGON");
    }

    #[test]
    fn fixture_4672_counts_in_attack_samples() {
        let mut lm_events = Vec::new();
        let lm_stats = crate::source::evtx::reader::read_file(
            &attack_fixture("LM_ScheduledTask_ATSVC_target_host.evtx"),
            &crate::source::ReadOptions::default(),
            &mut lm_events,
        )
        .unwrap();
        assert_eq!(lm_stats.errors, 0);
        let lm_privs: Vec<_> = lm_events
            .iter()
            .filter(|e| e.kind == EventKind::SpecialPrivileges && e.event_id == Some(4672))
            .collect();
        assert_eq!(lm_privs.len(), 5);
        for ev in lm_privs {
            assert!(ev.logon_id.is_some());
            assert!(ev.details["subject_sid"].is_string());
            assert!(!ev.details["privileges"].as_array().unwrap().is_empty());
            assert!(ev.summary.starts_with("Special privileges"));
        }

        let mut rdp_events = Vec::new();
        let rdp_stats = crate::source::evtx::reader::read_file(
            &attack_fixture("DE_RDP_Tunnel_5156.evtx"),
            &crate::source::ReadOptions::default(),
            &mut rdp_events,
        )
        .unwrap();
        assert_eq!(rdp_stats.errors, 0);
        let rdp_privs: Vec<_> = rdp_events
            .iter()
            .filter(|e| e.kind == EventKind::SpecialPrivileges && e.event_id == Some(4672))
            .collect();
        assert_eq!(rdp_privs.len(), 3);
    }
}
