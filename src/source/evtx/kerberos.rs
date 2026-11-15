//! Kerberos and NTLM authentication extractors (Security 4768, 4769, 4771, 4776).

use std::fmt::Write as _;
use std::net::Ipv6Addr;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, field_u64_hex, format_summary_with_tail, insert_opt_str,
    user_from_fields,
};

struct StatusOutcome {
    is_failure: bool,
    failure: Option<&'static str>,
}

/// 4768: a Kerberos authentication ticket (TGT) was requested.
pub(crate) fn extract_4768(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::KerberosTgt);
    event.user = user_from_fields(data, "TargetDomainName", "TargetUserName");
    apply_ip(&mut event, data);

    insert_opt_str(&mut event.details, "src_port", field_str(data, "IpPort"));
    insert_opt_str(
        &mut event.details,
        "target_sid",
        field_str(data, "TargetSid"),
    );
    insert_opt_str(
        &mut event.details,
        "service_name",
        field_str(data, "ServiceName"),
    );
    let outcome = apply_status(&mut event, data, |_, code| {
        code.and_then(kerberos_status_reason)
    });
    apply_ticket_encryption(&mut event, data);
    insert_opt_str(
        &mut event.details,
        "pre_auth_type",
        field_str(data, "PreAuthType"),
    );
    insert_opt_str(
        &mut event.details,
        "ticket_options",
        field_str(data, "TicketOptions"),
    );

    let mut prefix = String::from("Kerberos TGT");
    if let Some(user) = &event.user {
        let _ = write!(prefix, " for {user}");
    }
    if let Some(ip) = &event.src_ip {
        let _ = write!(prefix, " from {ip}");
    }
    if outcome.is_failure {
        prefix.push_str(" failed");
    }
    event.summary = format_summary_with_tail(&prefix, outcome.failure);
    Some(event)
}

/// 4769: a Kerberos service ticket was requested.
pub(crate) fn extract_4769(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::KerberosServiceTicket);
    event.user = field_str(data, "TargetUserName");
    event.target = field_str(data, "ServiceName");
    apply_ip(&mut event, data);

    insert_opt_str(&mut event.details, "src_port", field_str(data, "IpPort"));
    insert_opt_str(
        &mut event.details,
        "service_sid",
        field_str(data, "ServiceSid"),
    );
    let outcome = apply_status(&mut event, data, |_, code| {
        code.and_then(kerberos_status_reason)
    });
    let encryption = apply_ticket_encryption(&mut event, data);
    insert_opt_str(
        &mut event.details,
        "ticket_options",
        field_str(data, "TicketOptions"),
    );
    insert_opt_str(
        &mut event.details,
        "logon_guid",
        field_str(data, "LogonGuid"),
    );

    let mut prefix = String::from("Service ticket");
    if let Some(target) = &event.target {
        let _ = write!(prefix, " for {target}");
    }
    if let Some(user) = &event.user {
        let _ = write!(prefix, " requested by {user}");
    }
    if let Some(ip) = &event.src_ip {
        let _ = write!(prefix, " from {ip}");
    }
    if let Some(enc) = encryption {
        let _ = write!(prefix, " ({enc})");
    }
    if outcome.is_failure {
        prefix.push_str(" failed");
    }
    event.summary = format_summary_with_tail(&prefix, outcome.failure);
    Some(event)
}

/// 4771: Kerberos pre-authentication failed.
pub(crate) fn extract_4771(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::KerberosPreauthFailure);
    event.user = field_str(data, "TargetUserName");
    apply_ip(&mut event, data);

    insert_opt_str(&mut event.details, "src_port", field_str(data, "IpPort"));
    insert_opt_str(
        &mut event.details,
        "target_sid",
        field_str(data, "TargetSid"),
    );
    insert_opt_str(
        &mut event.details,
        "service_name",
        field_str(data, "ServiceName"),
    );
    let outcome = apply_status(&mut event, data, |_, code| {
        code.and_then(kerberos_status_reason)
    });
    insert_opt_str(
        &mut event.details,
        "pre_auth_type",
        field_str(data, "PreAuthType"),
    );
    insert_opt_str(
        &mut event.details,
        "ticket_options",
        field_str(data, "TicketOptions"),
    );

    let mut prefix = String::from("Kerberos pre-authentication failed");
    if let Some(user) = &event.user {
        let _ = write!(prefix, " for {user}");
    }
    if let Some(ip) = &event.src_ip {
        let _ = write!(prefix, " from {ip}");
    }
    event.summary = format_summary_with_tail(&prefix, outcome.failure);
    Some(event)
}

/// 4776: the computer attempted to validate the credentials for an account (NTLM).
pub(crate) fn extract_4776(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::NtlmAuth);
    event.user = field_str(data, "TargetUserName");

    let workstation = field_str(data, "Workstation");
    insert_opt_str(&mut event.details, "workstation", workstation.clone());
    insert_opt_str(
        &mut event.details,
        "package",
        field_str(data, "PackageName"),
    );
    let outcome = apply_status(&mut event, data, |raw, _| {
        super::logon::ntstatus_reason(raw)
    });

    let mut prefix = String::from("NTLM validation");
    if let Some(user) = &event.user {
        let _ = write!(prefix, " of {user}");
    }
    if let Some(ws) = &workstation {
        let _ = write!(prefix, " from workstation {ws}");
    }
    if outcome.is_failure {
        prefix.push_str(" failed");
    }
    event.summary = format_summary_with_tail(&prefix, outcome.failure);
    Some(event)
}

/// Unwraps IPv4-mapped IPv6 addresses (`::ffff:10.0.0.5`) into `src_ip`, preserving `ip_raw`
/// only when it differs from the normalized string.
fn apply_ip(event: &mut TimelineEvent, data: &Value) {
    let Some(raw) = field_str(data, "IpAddress") else {
        return;
    };
    let mapped = raw
        .trim()
        .parse::<Ipv6Addr>()
        .ok()
        .and_then(|addr| addr.to_ipv4_mapped())
        .map(|v4| v4.to_string());
    match mapped {
        Some(ipv4) => {
            if ipv4 != raw {
                event
                    .details
                    .insert("ip_raw".to_string(), Value::String(raw));
            }
            event.src_ip = Some(ipv4);
        }
        None => {
            event.src_ip = Some(raw);
        }
    }
}

fn apply_status(
    event: &mut TimelineEvent,
    data: &Value,
    lookup: fn(&str, Option<u64>) -> Option<&'static str>,
) -> StatusOutcome {
    let status = field_str(data, "Status");
    let code = field_u64_hex(data, "Status");
    let is_failure = match (&status, code) {
        (_, Some(0)) => false,
        (Some(_), _) | (None, Some(_)) => true,
        (None, None) => false,
    };
    let failure = if is_failure {
        status.as_deref().and_then(|raw| lookup(raw, code))
    } else {
        None
    };

    insert_opt_str(&mut event.details, "status", status);
    if let Some(reason) = failure {
        event
            .details
            .insert("failure".to_string(), Value::String(reason.to_string()));
    }
    StatusOutcome {
        is_failure,
        failure,
    }
}

fn apply_ticket_encryption(event: &mut TimelineEvent, data: &Value) -> Option<&'static str> {
    let raw = field_str(data, "TicketEncryptionType");
    let enc = field_u64_hex(data, "TicketEncryptionType").and_then(encryption_name);
    insert_opt_str(&mut event.details, "ticket_encryption_type", raw);
    if let Some(name) = enc {
        event
            .details
            .insert("encryption".to_string(), Value::String(name.to_string()));
    }
    enc
}

fn kerberos_status_reason(code: u64) -> Option<&'static str> {
    match code {
        0x6 => Some("unknown principal"),
        0x7 => Some("unknown server"),
        0xc => Some("policy restriction"),
        0x12 => Some("account disabled, expired or locked out"),
        0x17 => Some("password expired"),
        0x18 => Some("wrong password"),
        0x1f => Some("integrity check failed"),
        0x25 => Some("clock skew"),
        _ => None,
    }
}

fn encryption_name(code: u64) -> Option<&'static str> {
    match code {
        0x1 | 0x3 => Some("DES"),
        0x11 => Some("AES128"),
        0x12 => Some("AES256"),
        0x17 => Some("RC4"),
        0x18 => Some("RC4 export"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use jiff::Timestamp;
    use serde_json::json;

    use crate::source::{Format, ReadOptions, source_for};

    use super::*;

    fn meta(event_id: u32) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "DC01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id,
            record_id: 1,
            file_record_id: None,
            user_sid: None,
            file: "sec.evtx".into(),
        }
    }

    fn read_fixture(rel: &str) -> (crate::source::SourceStats, Vec<TimelineEvent>) {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
        let mut events = Vec::new();
        let stats = source_for(Format::Evtx)
            .read(&path, &ReadOptions::default(), &mut events)
            .unwrap();
        (stats, events)
    }

    #[test]
    fn extracts_4768_tgt_success_and_failure() {
        let ok = json!({
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-1-1000",
            "ServiceName": "krbtgt",
            "TicketOptions": "0x40810010",
            "Status": "0x0",
            "TicketEncryptionType": "0x12",
            "PreAuthType": "2",
            "IpAddress": "10.0.0.5",
            "IpPort": "51234"
        });
        let ev = extract_4768(&meta(4768), &ok).unwrap();
        assert_eq!(ev.kind, EventKind::KerberosTgt);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(ev.src_ip.as_deref(), Some("10.0.0.5"));
        assert!(!ev.details.contains_key("ip_raw"));
        assert_eq!(ev.details["src_port"], "51234");
        assert_eq!(ev.details["target_sid"], "S-1-5-21-1-1000");
        assert_eq!(ev.details["service_name"], "krbtgt");
        assert_eq!(ev.details["status"], "0x0");
        assert!(!ev.details.contains_key("failure"));
        assert_eq!(ev.details["ticket_encryption_type"], "0x12");
        assert_eq!(ev.details["encryption"], "AES256");
        assert_eq!(ev.details["pre_auth_type"], "2");
        assert_eq!(ev.details["ticket_options"], "0x40810010");
        assert_eq!(ev.summary, "Kerberos TGT for CORP\\alice from 10.0.0.5");

        let failed = json!({
            "TargetUserName": "alice",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-0-0",
            "ServiceName": "krbtgt/CORP",
            "TicketOptions": "0x10",
            "Status": "0x18",
            "TicketEncryptionType": "0xffffffff",
            "PreAuthType": "-",
            "IpAddress": "::ffff:10.0.0.5",
            "IpPort": "55961"
        });
        let ev_fail = extract_4768(&meta(4768), &failed).unwrap();
        assert_eq!(ev_fail.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(ev_fail.details["ip_raw"], "::ffff:10.0.0.5");
        assert_eq!(ev_fail.details["status"], "0x18");
        assert_eq!(ev_fail.details["failure"], "wrong password");
        assert_eq!(ev_fail.details["ticket_encryption_type"], "0xffffffff");
        assert!(!ev_fail.details.contains_key("encryption"));
        assert!(!ev_fail.details.contains_key("pre_auth_type"));
        assert_eq!(
            ev_fail.summary,
            "Kerberos TGT for CORP\\alice from 10.0.0.5 failed: wrong password"
        );
    }

    #[test]
    fn extracts_4769_service_ticket_success_and_failure() {
        let ok = json!({
            "TargetUserName": "alice@CORP.LOCAL",
            "TargetDomainName": "CORP.LOCAL",
            "ServiceName": "MSSQLSvc/db01",
            "ServiceSid": "S-1-5-21-1-2001",
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": "0x17",
            "IpAddress": "::ffff:10.0.0.5",
            "IpPort": "49812",
            "Status": "0x0",
            "LogonGuid": "{58adc6c7-668e-a999-c52a-384b1cb8e553}"
        });
        let ev = extract_4769(&meta(4769), &ok).unwrap();
        assert_eq!(ev.kind, EventKind::KerberosServiceTicket);
        assert_eq!(ev.user.as_deref(), Some("alice@CORP.LOCAL"));
        assert_eq!(ev.target.as_deref(), Some("MSSQLSvc/db01"));
        assert_eq!(ev.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(ev.details["ip_raw"], "::ffff:10.0.0.5");
        assert_eq!(ev.details["src_port"], "49812");
        assert_eq!(ev.details["service_sid"], "S-1-5-21-1-2001");
        assert_eq!(ev.details["status"], "0x0");
        assert!(!ev.details.contains_key("failure"));
        assert_eq!(ev.details["ticket_encryption_type"], "0x17");
        assert_eq!(ev.details["encryption"], "RC4");
        assert_eq!(ev.details["ticket_options"], "0x40810000");
        assert_eq!(
            ev.details["logon_guid"],
            "{58adc6c7-668e-a999-c52a-384b1cb8e553}"
        );
        assert_eq!(
            ev.summary,
            "Service ticket for MSSQLSvc/db01 requested by alice@CORP.LOCAL from 10.0.0.5 (RC4)"
        );

        let failed = json!({
            "TargetUserName": "alice@CORP.LOCAL",
            "ServiceName": "MSSQLSvc/missing",
            "ServiceSid": "S-1-0-0",
            "TicketOptions": "0x40810000",
            "TicketEncryptionType": "0xffffffff",
            "IpAddress": "::1",
            "IpPort": "49813",
            "Status": "0x7",
            "LogonGuid": "-"
        });
        let ev_fail = extract_4769(&meta(4769), &failed).unwrap();
        assert_eq!(ev_fail.src_ip.as_deref(), Some("::1"));
        assert!(!ev_fail.details.contains_key("ip_raw"));
        assert!(!ev_fail.details.contains_key("logon_guid"));
        assert!(!ev_fail.details.contains_key("encryption"));
        assert_eq!(ev_fail.details["failure"], "unknown server");
        assert_eq!(
            ev_fail.summary,
            "Service ticket for MSSQLSvc/missing requested by alice@CORP.LOCAL from ::1 failed: unknown server"
        );
    }

    #[test]
    fn extracts_4771_preauth_failure_and_dash_address() {
        let failed = json!({
            "TargetUserName": "alice",
            "TargetSid": "S-1-5-21-1-1000",
            "ServiceName": "krbtgt/CORP.LOCAL",
            "TicketOptions": "0x10",
            "PreAuthType": "2",
            "Status": "0x18",
            "IpAddress": "::ffff:10.0.0.5",
            "IpPort": "55001"
        });
        let ev = extract_4771(&meta(4771), &failed).unwrap();
        assert_eq!(ev.kind, EventKind::KerberosPreauthFailure);
        assert_eq!(ev.user.as_deref(), Some("alice"));
        assert_eq!(ev.src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(ev.details["ip_raw"], "::ffff:10.0.0.5");
        assert_eq!(ev.details["src_port"], "55001");
        assert_eq!(ev.details["target_sid"], "S-1-5-21-1-1000");
        assert_eq!(ev.details["service_name"], "krbtgt/CORP.LOCAL");
        assert_eq!(ev.details["status"], "0x18");
        assert_eq!(ev.details["failure"], "wrong password");
        assert_eq!(ev.details["pre_auth_type"], "2");
        assert_eq!(ev.details["ticket_options"], "0x10");
        assert_eq!(
            ev.summary,
            "Kerberos pre-authentication failed for alice from 10.0.0.5: wrong password"
        );

        let no_ip_unknown = json!({
            "TargetUserName": "alice",
            "Status": "0x99",
            "IpAddress": "-",
            "IpPort": "-"
        });
        let ev2 = extract_4771(&meta(4771), &no_ip_unknown).unwrap();
        assert_eq!(ev2.src_ip, None);
        assert!(!ev2.details.contains_key("ip_raw"));
        assert!(!ev2.details.contains_key("src_port"));
        assert_eq!(ev2.details["status"], "0x99");
        assert!(!ev2.details.contains_key("failure"));
        assert_eq!(ev2.summary, "Kerberos pre-authentication failed for alice");
    }

    #[test]
    fn extracts_4776_ntlm_success_and_failure() {
        let ok = json!({
            "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            "TargetUserName": "alice",
            "Workstation": "WS01",
            "Status": "0x0"
        });
        let ev = extract_4776(&meta(4776), &ok).unwrap();
        assert_eq!(ev.kind, EventKind::NtlmAuth);
        assert_eq!(ev.user.as_deref(), Some("alice"));
        assert_eq!(ev.src_ip, None);
        assert_eq!(ev.details["workstation"], "WS01");
        assert_eq!(
            ev.details["package"],
            "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
        );
        assert_eq!(ev.details["status"], "0x0");
        assert!(!ev.details.contains_key("failure"));
        assert_eq!(ev.summary, "NTLM validation of alice from workstation WS01");

        let failed = json!({
            "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            "TargetUserName": "alice",
            "Workstation": "WS01",
            "Status": "0xC000006A"
        });
        let ev_fail = extract_4776(&meta(4776), &failed).unwrap();
        assert_eq!(ev_fail.src_ip, None);
        assert_eq!(ev_fail.details["status"], "0xC000006A");
        assert_eq!(ev_fail.details["failure"], "wrong password");
        assert_eq!(
            ev_fail.summary,
            "NTLM validation of alice from workstation WS01 failed: wrong password"
        );

        let unknown = json!({
            "PackageName": "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0",
            "TargetUserName": "alice",
            "Workstation": "",
            "Status": "0xc0000999"
        });
        let ev_unk = extract_4776(&meta(4776), &unknown).unwrap();
        assert!(!ev_unk.details.contains_key("workstation"));
        assert_eq!(ev_unk.details["status"], "0xc0000999");
        assert!(!ev_unk.details.contains_key("failure"));
        assert_eq!(ev_unk.summary, "NTLM validation of alice failed");
    }

    #[test]
    fn maps_kerberos_status_and_encryption_codes_case_insensitively() {
        let status_cases = [
            ("0x0", None),
            ("0X00", None),
            ("0x6", Some("unknown principal")),
            ("0X06", Some("unknown principal")),
            ("0x7", Some("unknown server")),
            ("0xc", Some("policy restriction")),
            ("0xC", Some("policy restriction")),
            ("0x12", Some("account disabled, expired or locked out")),
            ("0x17", Some("password expired")),
            ("0x18", Some("wrong password")),
            ("0x1f", Some("integrity check failed")),
            ("0X1F", Some("integrity check failed")),
            ("0x25", Some("clock skew")),
            ("0x99", None),
        ];
        for (raw, expected) in status_cases {
            let ev = extract_4768(
                &meta(4768),
                &json!({
                    "TargetUserName": "alice",
                    "Status": raw
                }),
            )
            .unwrap();
            assert_eq!(ev.details["status"], raw);
            assert_eq!(
                ev.details.get("failure").and_then(Value::as_str),
                expected,
                "status {raw}"
            );
            if raw.eq_ignore_ascii_case("0x0") || raw.eq_ignore_ascii_case("0x00") {
                assert!(
                    !ev.summary.contains("failed"),
                    "status {raw}: {}",
                    ev.summary
                );
            } else {
                assert!(
                    ev.summary.contains("failed"),
                    "status {raw}: {}",
                    ev.summary
                );
            }
        }

        let enc_cases = [
            ("0x1", Some("DES")),
            ("0X03", Some("DES")),
            ("0x11", Some("AES128")),
            ("0X12", Some("AES256")),
            ("0x17", Some("RC4")),
            ("0x18", Some("RC4 export")),
            ("0xffffffff", None),
            ("0X99", None),
        ];
        for (raw, expected) in enc_cases {
            let ev = extract_4769(
                &meta(4769),
                &json!({
                    "TargetUserName": "alice@CORP.LOCAL",
                    "ServiceName": "krbtgt",
                    "TicketEncryptionType": raw,
                    "Status": "0x0"
                }),
            )
            .unwrap();
            assert_eq!(ev.details["ticket_encryption_type"], raw);
            assert_eq!(
                ev.details.get("encryption").and_then(Value::as_str),
                expected,
                "enc {raw}"
            );
        }
    }

    #[test]
    fn normalizes_ipv4_mapped_preserves_loopback_and_omits_dash() {
        let cases = [
            ("::ffff:10.0.0.5", Some("10.0.0.5"), Some("::ffff:10.0.0.5")),
            ("::FFFF:10.0.0.5", Some("10.0.0.5"), Some("::FFFF:10.0.0.5")),
            ("10.0.0.5", Some("10.0.0.5"), None),
            ("::1", Some("::1"), None),
            ("fe80::1", Some("fe80::1"), None),
            ("-", None, None),
            ("", None, None),
        ];
        for (raw, expected_ip, expected_raw) in cases {
            let ev = extract_4771(
                &meta(4771),
                &json!({
                    "TargetUserName": "alice",
                    "IpAddress": raw,
                    "Status": "0x18"
                }),
            )
            .unwrap();
            assert_eq!(ev.src_ip.as_deref(), expected_ip, "raw={raw}");
            assert_eq!(
                ev.details.get("ip_raw").and_then(Value::as_str),
                expected_raw,
                "raw={raw}"
            );
        }
    }

    #[test]
    fn handles_sparse_or_hostile_input_safely() {
        for (id, func) in [
            (
                4768,
                extract_4768 as fn(&RecordMeta, &Value) -> Option<TimelineEvent>,
            ),
            (4769, extract_4769),
            (4771, extract_4771),
            (4776, extract_4776),
        ] {
            let ev_null = func(&meta(id), &Value::Null).unwrap();
            assert!(!ev_null.summary.is_empty());

            let long_user = format!("line1\nline2\r\t{}", "a".repeat(250));
            let ev_hostile = func(
                &meta(id),
                &json!({
                    "TargetUserName": long_user,
                    "ServiceName": "svc/host",
                    "Status": "0x18"
                }),
            )
            .unwrap();
            assert!(!ev_hostile.summary.contains(['\n', '\r', '\t']));
            assert!(ev_hostile.summary.chars().count() <= 200);
            assert!(ev_hostile.summary.ends_with("..."));
        }
    }

    #[test]
    fn fixture_kerberos_pwd_spray_4771() {
        let (stats, events) =
            read_fixture("tests/fixtures/attack-samples/kerberos_pwd_spray_4771.evtx");
        assert_eq!(stats.errors, 0);

        let tgts: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::KerberosTgt)
            .collect();
        let preauths: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::KerberosPreauthFailure)
            .collect();
        assert_eq!(tgts.len(), 9);
        assert_eq!(preauths.len(), 2);

        let failed_tgts: Vec<_> = tgts
            .iter()
            .filter(|e| e.details.get("status").and_then(Value::as_str) == Some("0x6"))
            .collect();
        assert_eq!(failed_tgts.len(), 7);
        for ev in failed_tgts {
            assert_eq!(ev.details["failure"], "unknown principal");
            assert_eq!(ev.details["ticket_encryption_type"], "0xffffffff");
            assert!(!ev.details.contains_key("encryption"));
            assert_eq!(ev.src_ip.as_deref(), Some("172.16.66.1"));
        }

        let ok_tgts: Vec<_> = tgts
            .iter()
            .filter(|e| e.details.get("status").and_then(Value::as_str) == Some("0x0"))
            .collect();
        assert_eq!(ok_tgts.len(), 2);
        assert!(ok_tgts.iter().all(|e| e.details["encryption"] == "AES256"));
        assert_eq!(
            ok_tgts
                .iter()
                .filter(|e| e.details.get("ip_raw").and_then(Value::as_str)
                    == Some("::ffff:172.16.66.1"))
                .count(),
            1
        );

        for ev in preauths {
            assert_eq!(ev.details["status"], "0x18");
            assert_eq!(ev.details["failure"], "wrong password");
            assert_eq!(ev.src_ip.as_deref(), Some("172.16.66.1"));
        }
    }

    #[test]
    fn fixture_samaccount_spoofing() {
        let (stats, events) = read_fixture(
            "tests/fixtures/attack-samples/samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx",
        );
        assert_eq!(stats.errors, 0);

        let tgts: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::KerberosTgt)
            .collect();
        let tgs: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::KerberosServiceTicket)
            .collect();
        assert_eq!(tgts.len(), 2);
        assert_eq!(tgs.len(), 2);

        let tgt_encs: Vec<_> = tgts
            .iter()
            .map(|e| e.details["encryption"].as_str().unwrap())
            .collect();
        assert_eq!(tgt_encs, ["AES256", "RC4"]);
        assert!(tgts.iter().all(|e| {
            e.src_ip.as_deref() == Some("172.16.66.19")
                && e.details["ip_raw"] == "::ffff:172.16.66.19"
        }));

        for ev in tgs {
            assert_eq!(ev.target.as_deref(), Some("01566S-WIN16-IR$"));
            assert_eq!(ev.src_ip.as_deref(), Some("172.16.66.19"));
            assert_eq!(ev.details["ip_raw"], "::ffff:172.16.66.19");
            assert_eq!(ev.details["encryption"], "AES256");
            assert!(ev.details.contains_key("logon_guid"));
        }
    }

    #[test]
    fn fixture_lm_scheduled_task_ntlm() {
        let (stats, events) =
            read_fixture("tests/fixtures/attack-samples/LM_ScheduledTask_ATSVC_target_host.evtx");
        assert_eq!(stats.errors, 0);

        let ntlm: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::NtlmAuth)
            .collect();
        assert_eq!(ntlm.len(), 4);
        assert!(ntlm.iter().all(|e| {
            e.src_ip.is_none()
                && e.details["status"] == "0x0"
                && e.details["package"] == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
                && !e.details.contains_key("failure")
        }));
        assert_eq!(
            ntlm.iter()
                .filter(|e| e.details.get("workstation").and_then(Value::as_str)
                    == Some("WIN-77LTAPHIQ1R"))
                .count(),
            1
        );
    }

    #[test]
    fn fixture_security_short_selected_ntlm() {
        let (stats, events) = read_fixture("tests/fixtures/format/Security_short_selected.evtx");
        assert_eq!(stats.errors, 0);

        let ntlm: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::NtlmAuth)
            .collect();
        assert_eq!(ntlm.len(), 1);
        let ev = ntlm[0];
        assert_eq!(ev.user.as_deref(), Some("Administrator"));
        assert_eq!(ev.src_ip, None);
        assert_eq!(ev.details["workstation"], "TEMPORAL");
        assert_eq!(ev.details["status"], "0xc000006a");
        assert_eq!(ev.details["failure"], "wrong password");
        assert_eq!(
            ev.summary,
            "NTLM validation of Administrator from workstation TEMPORAL failed: wrong password"
        );
    }
}
