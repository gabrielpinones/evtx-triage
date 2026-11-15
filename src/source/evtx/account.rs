use std::fmt::Write as _;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, format_summary_with_tail, insert_opt_str, user_from_fields,
};

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

fn extract_log_clear(
    meta: &RecordMeta,
    data: &Value,
    label: &str,
    include_channel_target: bool,
) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::LogClear);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.logon_id = field_str(data, "SubjectLogonId");

    insert_opt_str(
        &mut event.details,
        "subject_sid",
        field_str(data, "SubjectUserSid"),
    );
    if include_channel_target {
        event.target = field_str(data, "Channel");
    }
    insert_opt_str(
        &mut event.details,
        "backup_path",
        field_str(data, "BackupPath"),
    );

    let mut summary = String::from(label);
    if let Some(target) = &event.target {
        let _ = write!(summary, " {target}");
    }
    summary.push_str(" cleared");
    if let Some(user) = &event.user {
        let _ = write!(summary, " by {user}");
    }
    event.summary = format_summary_with_tail(&summary, None);
    event
}

fn extract_group_member_add(meta: &RecordMeta, data: &Value, scope: &str) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::GroupMemberAdd);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.logon_id = field_str(data, "SubjectLogonId");
    event.target = user_from_fields(data, "TargetDomainName", "TargetUserName");

    let member_sid = field_str(data, "MemberSid");
    let member_name = field_str(data, "MemberName");
    let group_sid = field_str(data, "TargetSid");

    let member_label = member_name
        .as_deref()
        .or(member_sid.as_deref())
        .unwrap_or("unknown member");

    let mut summary = String::from(member_label);
    summary.push_str(" added to group");
    if let Some(target) = &event.target {
        let _ = write!(summary, " {target}");
    }
    if let Some(user) = &event.user {
        let _ = write!(summary, " by {user}");
    }
    event.summary = format_summary_with_tail(&summary, None);

    insert_opt_str(&mut event.details, "member_sid", member_sid);
    insert_opt_str(&mut event.details, "member_name", member_name);
    insert_opt_str(&mut event.details, "group_sid", group_sid);
    event
        .details
        .insert("group_scope".to_string(), Value::String(scope.to_string()));

    Some(event)
}

pub(crate) fn extract_1102(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    extract_log_clear(meta, data, "Audit log", false)
}

/// 4728: a member was added to a security-enabled global group.
pub(crate) fn extract_4728(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_group_member_add(meta, data, "global")
}

/// 4732: a member was added to a security-enabled local group.
pub(crate) fn extract_4732(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_group_member_add(meta, data, "local")
}

/// 4756: a member was added to a security-enabled universal group.
pub(crate) fn extract_4756(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_group_member_add(meta, data, "universal")
}

/// 104: an event log channel was cleared.
pub(crate) fn extract_104(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_log_clear(meta, data, "Event log", true))
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

    fn sec_meta(event_id: u32, record_id: u64) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "DC01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id,
            record_id,
            file_record_id: None,
            user_sid: None,
            file: "sec.evtx".into(),
        }
    }

    fn read_fixture_events(parts: &[&str]) -> Vec<TimelineEvent> {
        use std::path::PathBuf;

        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("fixtures");
        for part in parts {
            path.push(part);
        }
        let reader = crate::source::source_for(crate::source::Format::Evtx);
        let mut events = Vec::new();
        let stats = reader
            .read(&path, &crate::source::ReadOptions::default(), &mut events)
            .unwrap();
        assert_eq!(stats.errors, 0);
        events
    }

    #[test]
    fn extracts_4728_global_group_member_add_with_member_name() {
        let meta = sec_meta(4728, 12);
        let data = json!({
            "MemberName": "CN=alice,CN=Users,DC=corp,DC=local",
            "MemberSid": "S-1-5-21-1-1001",
            "TargetUserName": "Domain Admins",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-1-512",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7"
        });
        let ev = extract_4728(&meta, &data).unwrap();
        assert_eq!(ev.kind, EventKind::GroupMemberAdd);
        assert_eq!(ev.user.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x3e7"));
        assert_eq!(ev.target.as_deref(), Some("CORP\\Domain Admins"));
        assert_eq!(ev.details["member_sid"], "S-1-5-21-1-1001");
        assert_eq!(
            ev.details["member_name"],
            "CN=alice,CN=Users,DC=corp,DC=local"
        );
        assert_eq!(ev.details["group_sid"], "S-1-5-21-1-512");
        assert_eq!(ev.details["group_scope"], "global");
        assert_eq!(
            ev.summary,
            "CN=alice,CN=Users,DC=corp,DC=local added to group CORP\\Domain Admins by CORP\\admin"
        );
    }

    #[test]
    fn extracts_4732_local_group_member_add_with_dash_member_name() {
        let meta = sec_meta(4732, 13);
        let data = json!({
            "MemberName": "-",
            "MemberSid": "S-1-5-21-1-1001",
            "TargetUserName": "Administrators",
            "TargetDomainName": "BUILTIN",
            "TargetSid": "S-1-5-32-544",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x2f1a"
        });
        let ev = extract_4732(&meta, &data).unwrap();
        assert_eq!(ev.kind, EventKind::GroupMemberAdd);
        assert_eq!(ev.user.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x2f1a"));
        assert_eq!(ev.target.as_deref(), Some("BUILTIN\\Administrators"));
        assert_eq!(ev.details["member_sid"], "S-1-5-21-1-1001");
        assert!(!ev.details.contains_key("member_name"));
        assert_eq!(ev.details["group_sid"], "S-1-5-32-544");
        assert_eq!(ev.details["group_scope"], "local");
        assert_eq!(
            ev.summary,
            "S-1-5-21-1-1001 added to group BUILTIN\\Administrators by CORP\\admin"
        );
    }

    #[test]
    fn extracts_4756_universal_group_member_add() {
        let meta = sec_meta(4756, 14);
        let data = json!({
            "MemberName": "-",
            "MemberSid": "S-1-5-21-1-1002",
            "TargetUserName": "Enterprise Admins",
            "TargetDomainName": "CORP",
            "TargetSid": "S-1-5-21-1-519",
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x400"
        });
        let ev = extract_4756(&meta, &data).unwrap();
        assert_eq!(ev.kind, EventKind::GroupMemberAdd);
        assert_eq!(ev.target.as_deref(), Some("CORP\\Enterprise Admins"));
        assert_eq!(ev.details["group_sid"], "S-1-5-21-1-519");
        assert_eq!(ev.details["group_scope"], "universal");
        assert!(!ev.details.contains_key("member_name"));
        assert_eq!(
            ev.summary,
            "S-1-5-21-1-1002 added to group CORP\\Enterprise Admins by CORP\\admin"
        );
    }

    #[test]
    fn extracts_104_log_clear_with_and_without_backup_path() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("System".into()),
            provider: "Microsoft-Windows-Eventlog".into(),
            event_id: 104,
            record_id: 15,
            file_record_id: None,
            user_sid: Some("S-1-5-21-1-500".into()),
            file: "sys.evtx".into(),
        };
        let without_backup = json!({
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "Channel": "System",
            "BackupPath": Value::Null
        });
        let ev = extract_104(&meta, &without_backup).unwrap();
        assert_eq!(ev.kind, EventKind::LogClear);
        assert_eq!(ev.user.as_deref(), Some("CORP\\admin"));
        assert_eq!(ev.target.as_deref(), Some("System"));
        assert!(!ev.details.contains_key("backup_path"));
        assert_eq!(ev.summary, "Event log System cleared by CORP\\admin");

        let with_backup = json!({
            "SubjectUserName": "admin",
            "SubjectDomainName": "CORP",
            "Channel": "System",
            "BackupPath": "C:\\Windows\\System32\\winevt\\Logs\\Archive-System.evtx"
        });
        let ev = extract_104(&meta, &with_backup).unwrap();
        assert_eq!(
            ev.details["backup_path"],
            "C:\\Windows\\System32\\winevt\\Logs\\Archive-System.evtx"
        );
    }

    #[test]
    fn fixture_4732_network_service_guest_added_to_admins() {
        let events = read_fixture_events(&[
            "attack-samples",
            "Network_Service_Guest_added_to_admins_4732.evtx",
        ]);
        assert_eq!(events.len(), 2);
        for ev in &events {
            assert_eq!(ev.kind, EventKind::GroupMemberAdd);
            assert_eq!(ev.event_id, Some(4732));
            assert_eq!(ev.user.as_deref(), Some("MSEDGEWIN10\\IEUser"));
            assert_eq!(ev.logon_id.as_deref(), Some("0x27a10f"));
            assert_eq!(ev.target.as_deref(), Some("Builtin\\Administrators"));
            assert_eq!(ev.details["group_sid"], "S-1-5-32-544");
            assert_eq!(ev.details["group_scope"], "local");
            assert!(!ev.details.contains_key("member_name"));
        }
        assert_eq!(
            events[0].details["member_sid"],
            "S-1-5-21-3461203602-4096304019-2269080069-501"
        );
        assert_eq!(events[1].details["member_sid"], "S-1-5-20");
    }

    #[test]
    fn fixture_104_system_log_cleared() {
        let events = read_fixture_events(&["attack-samples", "DE_104_system_log_cleared.evtx"]);
        assert_eq!(events.len(), 1);
        let ev = &events[0];
        assert_eq!(ev.kind, EventKind::LogClear);
        assert_eq!(ev.event_id, Some(104));
        assert_eq!(ev.provider.as_deref(), Some("Microsoft-Windows-Eventlog"));
        assert_eq!(ev.channel.as_deref(), Some("System"));
        assert_eq!(ev.target.as_deref(), Some("System"));
        assert_eq!(ev.user.as_deref(), Some("EXAMPLE\\user01"));
        assert!(!ev.details.contains_key("backup_path"));
        assert_eq!(ev.summary, "Event log System cleared by EXAMPLE\\user01");
    }
}
