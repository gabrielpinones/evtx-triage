use std::fmt::Write as _;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{RecordMeta, field_str, insert_opt_str, user_from_fields};

pub(crate) fn extract_4720(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::UserCreate);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.target = user_from_fields(data, "TargetDomainName", "TargetUserName");
    event.logon_id = field_str(data, "SubjectLogonId");

    insert_opt_str(
        &mut event.details,
        "sam_account_name",
        field_str(data, "SamAccountName"),
    );
    insert_opt_str(
        &mut event.details,
        "target_sid",
        field_str(data, "TargetSid"),
    );

    let mut summary = String::from("User");
    if let Some(target) = &event.target {
        let _ = write!(summary, " {target}");
    }
    summary.push_str(" created");
    if let Some(user) = &event.user {
        let _ = write!(summary, " by {user}");
    }
    event.summary = summary;
    event
}

pub(crate) fn extract_1102(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::LogClear);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.logon_id = field_str(data, "SubjectLogonId");

    insert_opt_str(
        &mut event.details,
        "subject_sid",
        field_str(data, "SubjectUserSid"),
    );

    let mut summary = String::from("Audit log cleared");
    if let Some(user) = &event.user {
        let _ = write!(summary, " by {user}");
    }
    event.summary = summary;
    event
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use serde_json::json;

    #[test]
    fn extracts_4720_user_create() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "DC01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id: 4720,
            record_id: 10,
            file_record_id: None,
            user_sid: None,
            file: "sec.evtx".into(),
        };
        let data = json!({
            "TargetUserName": "eve",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-1-1001",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "SamAccountName": "eve"
        });
        let ev = extract_4720(&meta, &data);
        assert_eq!(ev.kind, EventKind::UserCreate);
        assert_eq!(ev.user.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev.target.as_deref(), Some("CORP\\eve"));
        assert_eq!(ev.details["sam_account_name"], "eve");
        assert_eq!(ev.details["target_sid"], "S-1-5-21-1-1001");
        assert_eq!(ev.summary, "User CORP\\eve created by CORP\\admin");
    }

    #[test]
    fn extracts_1102_log_clear() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "DC01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Eventlog".into(),
            event_id: 1102,
            record_id: 11,
            file_record_id: None,
            user_sid: None,
            file: "sec.evtx".into(),
        };
        let log_file_cleared = json!({
            "SubjectUserSid": "S-1-5-21-1-500",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x4fd77"
        });
        let ev = extract_1102(&meta, &log_file_cleared);
        assert_eq!(ev.kind, EventKind::LogClear);
        assert_eq!(ev.user.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x4fd77"));
        assert_eq!(ev.details["subject_sid"], "S-1-5-21-1-500");
        assert_eq!(ev.summary, "Audit log cleared by CORP\\admin");
    }
}
