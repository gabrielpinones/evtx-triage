use std::fmt::Write as _;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, field_u64_dec, field_u64_hex, format_summary_with_tail, insert_opt_str,
    user_from_fields,
};

pub(crate) fn extract_4688(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::ProcessCreate);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.process = field_str(data, "NewProcessName");
    event.pid = field_u64_hex(data, "NewProcessId");
    event.parent_process = field_str(data, "ParentProcessName");
    event.ppid = field_u64_hex(data, "ProcessId");
    event.command_line = field_str(data, "CommandLine");
    event.logon_id = field_str(data, "SubjectLogonId");

    insert_opt_str(
        &mut event.details,
        "token_elevation",
        field_str(data, "TokenElevationType"),
    );
    insert_opt_str(
        &mut event.details,
        "target_user",
        user_from_fields(data, "TargetDomainName", "TargetUserName"),
    );
    insert_opt_str(
        &mut event.details,
        "mandatory_label",
        field_str(data, "MandatoryLabel"),
    );

    event.summary = process_summary(&event);
    event
}

pub(crate) fn extract_sysmon_1(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::ProcessCreate);
    event.user = field_str(data, "User");
    event.process = field_str(data, "Image");
    event.pid = field_u64_dec(data, "ProcessId");
    event.parent_process = field_str(data, "ParentImage");
    event.ppid = field_u64_dec(data, "ParentProcessId");
    event.command_line = field_str(data, "CommandLine");
    event.logon_id = field_str(data, "LogonId");

    insert_opt_str(
        &mut event.details,
        "parent_command_line",
        field_str(data, "ParentCommandLine"),
    );
    insert_opt_str(&mut event.details, "hashes", field_str(data, "Hashes"));
    insert_opt_str(
        &mut event.details,
        "process_guid",
        field_str(data, "ProcessGuid"),
    );
    insert_opt_str(
        &mut event.details,
        "parent_process_guid",
        field_str(data, "ParentProcessGuid"),
    );
    insert_opt_str(
        &mut event.details,
        "integrity_level",
        field_str(data, "IntegrityLevel"),
    );
    insert_opt_str(
        &mut event.details,
        "current_directory",
        field_str(data, "CurrentDirectory"),
    );
    insert_opt_str(
        &mut event.details,
        "original_file_name",
        field_str(data, "OriginalFileName"),
    );
    insert_opt_str(&mut event.details, "utc_time", field_str(data, "UtcTime"));

    event.summary = process_summary(&event);
    event
}

fn process_summary(event: &TimelineEvent) -> String {
    let mut prefix = format!("Process {}", event.process.as_deref().unwrap_or("unknown"));
    if let Some(pid) = event.pid {
        let _ = write!(prefix, " (pid {pid})");
    }
    if let Some(user) = &event.user {
        let _ = write!(prefix, " by {user}");
    }
    format_summary_with_tail(&prefix, event.command_line.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use serde_json::json;

    fn meta(provider: &str, event_id: u32) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Security".into()),
            provider: provider.into(),
            event_id,
            record_id: 1,
            file_record_id: None,
            user_sid: None,
            file: "test.evtx".into(),
        }
    }

    #[test]
    fn extracts_4688_with_empty_command_line() {
        let data = json!({
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "NewProcessId": "0x1092",
            "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
            "TokenElevationType": "%%1936",
            "ProcessId": "0x33c",
            "CommandLine": ""
        });
        let ev = extract_4688(&meta("Microsoft-Windows-Security-Auditing", 4688), &data);
        assert_eq!(ev.kind, EventKind::ProcessCreate);
        assert_eq!(ev.pid, Some(4242));
        assert_eq!(ev.ppid, Some(0x33c));
        assert_eq!(ev.command_line, None);
        assert_eq!(ev.parent_process, None);
        assert!(!ev.details.contains_key("target_user"));
        assert_eq!(
            ev.summary,
            "Process C:\\Windows\\System32\\cmd.exe (pid 4242) by CORP\\bob"
        );
    }

    #[test]
    fn extracts_sysmon_1_with_decimal_pids_and_truncates_summary() {
        let long_cmd = format!("cmd.exe /c {}", "A".repeat(300));
        let data = json!({
            "UtcTime": "2019-04-30 20:26:51.949",
            "ProcessGuid": "{365abb72-af8b-5cc8-0000-00101c1a1900}",
            "ProcessId": 3348,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": long_cmd,
            "CurrentDirectory": "C:\\Windows\\system32\\",
            "User": "NT AUTHORITY\\SYSTEM",
            "LogonId": "0x3e7",
            "IntegrityLevel": "System",
            "Hashes": "SHA256=ABCD",
            "ParentProcessGuid": "{365abb72-2586-5cc9-0000-0010dc530000}",
            "ParentProcessId": 460,
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "ParentCommandLine": "C:\\Windows\\system32\\services.exe",
            "OriginalFileName": "Cmd.Exe"
        });
        let ev = extract_sysmon_1(&meta("Microsoft-Windows-Sysmon", 1), &data);
        assert_eq!(ev.pid, Some(3348));
        assert_eq!(ev.ppid, Some(460));
        assert_eq!(ev.user.as_deref(), Some("NT AUTHORITY\\SYSTEM"));
        assert_eq!(ev.details["original_file_name"], "Cmd.Exe");
        assert_eq!(ev.details["utc_time"], "2019-04-30 20:26:51.949");
        assert!(ev.summary.chars().count() <= 200);
        assert!(ev.summary.ends_with("..."));
    }
}
