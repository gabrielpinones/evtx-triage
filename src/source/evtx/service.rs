use std::fmt::Write as _;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, format_summary_with_tail, insert_opt_str, user_from_fields,
};

fn extract_service_install(
    meta: &RecordMeta,
    data: &Value,
    path_key: &str,
    start_type_key: &str,
    account_key: &str,
) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::ServiceInstall);
    let service_name = field_str(data, "ServiceName");
    let image_path = field_str(data, path_key);

    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.logon_id = field_str(data, "SubjectLogonId");
    event.target = service_name.clone();
    event.process = image_path.clone();
    event.command_line = image_path;

    insert_opt_str(
        &mut event.details,
        "service_type",
        field_str(data, "ServiceType"),
    );
    insert_opt_str(
        &mut event.details,
        "start_type",
        field_str(data, start_type_key),
    );
    insert_opt_str(&mut event.details, "account", field_str(data, account_key));
    insert_opt_str(&mut event.details, "user_sid", meta.user_sid.clone());

    let mut prefix = match &service_name {
        Some(name) => format!("Service \"{name}\" installed"),
        None => "Service installed".to_string(),
    };
    if let Some(user) = &event.user {
        let _ = write!(prefix, " by {user}");
    }
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    event
}

pub(crate) fn extract_7045(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    extract_service_install(meta, data, "ImagePath", "StartType", "AccountName")
}

/// 4697: a service was installed in the system.
pub(crate) fn extract_4697(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_service_install(
        meta,
        data,
        "ServiceFileName",
        "ServiceStartType",
        "ServiceAccount",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use serde_json::json;

    #[test]
    fn extracts_7045_service_install() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "WIN-77LTAPHIQ1R".into(),
            channel: Some("System".into()),
            provider: "Service Control Manager".into(),
            event_id: 7045,
            record_id: 1,
            file_record_id: None,
            user_sid: Some("S-1-5-18".into()),
            file: "system.evtx".into(),
        };
        let data = json!({
            "ServiceName": "PSEXESVC",
            "ImagePath": "%SystemRoot%\\PSEXESVC.exe",
            "ServiceType": "user mode service",
            "StartType": "auto start",
            "AccountName": "LocalSystem"
        });
        let ev = extract_7045(&meta, &data);
        assert_eq!(ev.kind, EventKind::ServiceInstall);
        assert_eq!(ev.target.as_deref(), Some("PSEXESVC"));
        assert_eq!(ev.process.as_deref(), Some("%SystemRoot%\\PSEXESVC.exe"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("%SystemRoot%\\PSEXESVC.exe")
        );
        assert_eq!(ev.details["user_sid"], "S-1-5-18");
        assert_eq!(ev.details["account"], "LocalSystem");
        assert_eq!(
            ev.summary,
            "Service \"PSEXESVC\" installed: %SystemRoot%\\PSEXESVC.exe"
        );
    }

    #[test]
    fn extracts_4697_service_install_with_all_fields() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id: 4697,
            record_id: 2,
            file_record_id: None,
            user_sid: Some("S-1-5-18".into()),
            file: "security.evtx".into(),
        };
        let data = json!({
            "SubjectUserSid": "S-1-5-21-1-500",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "ServiceName": "PSEXESVC",
            "ServiceFileName": "%SystemRoot%\\PSEXESVC.exe",
            "ServiceType": "0x10",
            "ServiceStartType": "3",
            "ServiceAccount": "LocalSystem"
        });
        let ev = extract_4697(&meta, &data).unwrap();
        assert_eq!(ev.kind, EventKind::ServiceInstall);
        assert_eq!(ev.user.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x3e7"));
        assert_eq!(ev.target.as_deref(), Some("PSEXESVC"));
        assert_eq!(ev.process.as_deref(), Some("%SystemRoot%\\PSEXESVC.exe"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("%SystemRoot%\\PSEXESVC.exe")
        );
        assert_eq!(ev.details["service_type"], "0x10");
        assert_eq!(ev.details["start_type"], "3");
        assert_eq!(ev.details["account"], "LocalSystem");
        assert_eq!(ev.details["user_sid"], "S-1-5-18");
        assert_eq!(
            ev.summary,
            "Service \"PSEXESVC\" installed by CORP\\admin: %SystemRoot%\\PSEXESVC.exe"
        );
    }

    #[test]
    fn extracts_4697_handles_numeric_fields_and_missing_optionals() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id: 4697,
            record_id: 3,
            file_record_id: None,
            user_sid: None,
            file: "security.evtx".into(),
        };
        let data = json!({
            "SubjectUserName": "svc_deploy",
            "SubjectLogonId": "0x1b4f20",
            "ServiceName": "UpdaterSvc",
            "ServiceFileName": "C:\\ProgramData\\UpdaterSvc.exe",
            "ServiceType": 16,
            "ServiceStartType": 2,
            "ServiceAccount": "-"
        });
        let ev = extract_4697(&meta, &data).unwrap();
        assert_eq!(ev.user.as_deref(), Some("svc_deploy"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x1b4f20"));
        assert_eq!(ev.details["service_type"], "16");
        assert_eq!(ev.details["start_type"], "2");
        assert!(!ev.details.contains_key("account"));
        assert!(!ev.details.contains_key("user_sid"));
        assert_eq!(
            ev.summary,
            "Service \"UpdaterSvc\" installed by svc_deploy: C:\\ProgramData\\UpdaterSvc.exe"
        );
    }
}
