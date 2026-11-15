//! Windows Defender EVTX event extractors.

use std::fmt::Write as _;

use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, format_summary_with_tail, insert_opt_str,
};

fn extract_defender_detection(
    meta: &RecordMeta,
    data: &Value,
    stage: &'static str,
    is_action_taken: bool,
) -> Option<TimelineEvent> {
    let threat = field_str(data, "Threat Name");
    let path = field_str(data, "Path");
    let user = field_str(data, "Detection User");
    let process = field_str(data, "Process Name");
    let severity = field_str(data, "Severity Name");
    let category = field_str(data, "Category Name");
    let action = is_action_taken
        .then(|| field_str(data, "Action Name"))
        .flatten();
    let detection_id = field_str(data, "Detection ID");
    // Raw EVTX uses "Origin Name"; keep "Detection Origin" as fallback for synthetic inputs.
    let detection_origin =
        field_str(data, "Origin Name").or_else(|| field_str(data, "Detection Origin"));
    let execution = field_str(data, "Execution Name");

    if threat.is_none()
        && path.is_none()
        && user.is_none()
        && process.is_none()
        && severity.is_none()
        && category.is_none()
        && action.is_none()
        && detection_id.is_none()
        && detection_origin.is_none()
        && execution.is_none()
    {
        return None;
    }

    let mut event = meta.base_event(EventKind::DefenderDetection);
    event.target = threat.clone();
    event.user = user;
    event.process = process;

    insert_opt_str(&mut event.details, "path", path.clone());
    insert_opt_str(&mut event.details, "severity", severity);
    insert_opt_str(&mut event.details, "category", category);
    insert_opt_str(&mut event.details, "action", action.clone());
    insert_opt_str(&mut event.details, "detection_id", detection_id);
    insert_opt_str(&mut event.details, "detection_origin", detection_origin);
    insert_opt_str(&mut event.details, "execution", execution);
    event
        .details
        .insert("stage".to_string(), Value::String(stage.to_string()));

    let mut summary = String::from("Defender");
    if is_action_taken {
        if let Some(act) = &action {
            let _ = write!(summary, " action {act}");
        } else {
            summary.push_str(" action taken");
        }
        if let Some(name) = &threat {
            let _ = write!(summary, " on {name}");
        }
    } else {
        summary.push_str(" detected");
        match (&threat, &path) {
            (Some(name), _) => {
                let _ = write!(summary, " {name}");
            }
            (None, Some(_)) => summary.push_str(" unknown threat"),
            (None, None) => summary.push_str(" threat"),
        }
        if let Some(p) = &path {
            let _ = write!(summary, " in {p}");
        }
    }
    event.summary = format_summary_with_tail(&summary, None);
    Some(event)
}

/// Windows Defender 1116: Malware or unwanted software detected.
pub(crate) fn extract_1116(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_defender_detection(meta, data, "detected", false)
}

/// Windows Defender 1117: Action taken against detected malware or unwanted software.
pub(crate) fn extract_1117(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_defender_detection(meta, data, "action_taken", true)
}

/// Windows Defender 5001: Real-time protection disabled.
pub(crate) fn extract_5001(meta: &RecordMeta, _data: &Value) -> Option<TimelineEvent> {
    let mut event = meta.base_event(EventKind::DefenderConfigChange);
    event.details.insert(
        "setting".to_string(),
        Value::String("real_time_protection".to_string()),
    );
    event
        .details
        .insert("state".to_string(), Value::String("disabled".to_string()));
    event.summary = "Defender real-time protection disabled".to_string();
    Some(event)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use jiff::Timestamp;
    use serde_json::json;

    use super::*;
    use crate::source::{Format, ReadOptions, source_for};

    fn defender_meta(event_id: u32, record_id: u64) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "MSEDGEWIN10".into(),
            channel: Some("Microsoft-Windows-Windows Defender/Operational".into()),
            provider: "Microsoft-Windows-Windows Defender".into(),
            event_id,
            record_id,
            file_record_id: None,
            user_sid: Some("S-1-5-18".into()),
            file: "defender.evtx".into(),
        }
    }

    #[test]
    fn extracts_1116_with_spaced_fields_and_missing_keys() {
        let meta = defender_meta(1116, 10);
        let data = json!({
            "Threat Name": "HackTool:Win32/Mimikatz",
            "Detection User": "CORP\\alice",
            "Process Name": "C:\\Windows\\System32\\cmd.exe",
            "Path": "C:\\Users\\x\\m.exe",
            "Severity Name": "Severe",
            "Category Name": "Tool",
            "Action Name": "NoAction",
            "Detection ID": "{11111111-2222-3333-4444-555555555555}",
            "Origin Name": "%%845",
            "Execution Name": "%%813"
        });
        let ev = extract_1116(&meta, &data).expect("1116 event");
        assert_eq!(ev.kind, EventKind::DefenderDetection);
        assert_eq!(ev.target.as_deref(), Some("HackTool:Win32/Mimikatz"));
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(
            ev.process.as_deref(),
            Some("C:\\Windows\\System32\\cmd.exe")
        );
        assert_eq!(ev.details["path"], "C:\\Users\\x\\m.exe");
        assert_eq!(ev.details["severity"], "Severe");
        assert_eq!(ev.details["category"], "Tool");
        assert!(!ev.details.contains_key("action"));
        assert_eq!(
            ev.details["detection_id"],
            "{11111111-2222-3333-4444-555555555555}"
        );
        assert_eq!(ev.details["detection_origin"], "%%845");
        assert_eq!(ev.details["execution"], "%%813");
        assert_eq!(ev.details["stage"], "detected");
        assert_eq!(
            ev.summary,
            "Defender detected HackTool:Win32/Mimikatz in C:\\Users\\x\\m.exe"
        );

        let minimal = extract_1116(&meta, &json!({"Threat Name": "EICAR", "Path": ""}))
            .expect("minimal 1116");
        assert_eq!(minimal.summary, "Defender detected EICAR");
        assert!(!minimal.details.contains_key("path"));

        assert!(extract_1116(&meta, &json!({})).is_none());
        assert!(extract_1116(&meta, &Value::Null).is_none());
        assert!(extract_1116(&meta, &json!({"Unused": ""})).is_none());
    }

    #[test]
    fn extracts_1117_action_taken_and_fallbacks() {
        let meta = defender_meta(1117, 11);
        let data = json!({
            "Threat Name": "HackTool:Win32/Mimikatz",
            "Action Name": "Quarantine",
            "Detection User": "CORP\\alice",
            "Process Name": "C:\\Users\\x\\m.exe",
            "Path": "file:_C:\\Users\\x\\m.exe",
            "Severity Name": "Severe",
            "Category Name": "Tool",
            "Detection ID": "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
            "Detection Origin": "Local machine",
            "Execution Name": "Interactive"
        });
        let ev = extract_1117(&meta, &data).expect("1117 event");
        assert_eq!(ev.kind, EventKind::DefenderDetection);
        assert_eq!(ev.details["stage"], "action_taken");
        assert_eq!(ev.details["action"], "Quarantine");
        assert_eq!(ev.details["detection_origin"], "Local machine");
        assert_eq!(ev.details["execution"], "Interactive");
        assert_eq!(
            ev.summary,
            "Defender action Quarantine on HackTool:Win32/Mimikatz"
        );

        let no_action = extract_1117(&meta, &json!({"Threat Name": "EICAR"}))
            .expect("1117 without Action Name");
        assert_eq!(no_action.summary, "Defender action taken on EICAR");
        assert!(!no_action.details.contains_key("action"));
    }

    #[test]
    fn extracts_5001_from_synthetic_record() {
        // No fixture contains 5001; Event 5001 is defined by the event ID with few or no fields.
        let meta = defender_meta(5001, 12);
        let ev =
            extract_5001(&meta, &json!({"Product Name": "Windows Defender"})).expect("5001 event");
        assert_eq!(ev.kind, EventKind::DefenderConfigChange);
        assert_eq!(ev.details["setting"], "real_time_protection");
        assert_eq!(ev.details["state"], "disabled");
        assert_eq!(ev.summary, "Defender real-time protection disabled");

        let empty_ev = extract_5001(&meta, &Value::Null).expect("5001 empty");
        assert_eq!(empty_ev.details["setting"], "real_time_protection");
        assert_eq!(empty_ev.details["state"], "disabled");
    }

    #[test]
    fn extracts_1116_and_1117_from_atomic_red_team_fixture() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/attack-samples/WinDefender_Events_1117_1116_AtomicRedTeam.evtx");
        let mut events = Vec::new();
        let stats = source_for(Format::Evtx)
            .read(&path, &ReadOptions::default(), &mut events)
            .unwrap();
        assert_eq!(stats.errors, 0);

        let e1116: Vec<_> = events.iter().filter(|e| e.event_id == Some(1116)).collect();
        let e1117: Vec<_> = events.iter().filter(|e| e.event_id == Some(1117)).collect();
        assert_eq!(e1116.len(), 6);
        assert_eq!(e1117.len(), 5);

        for ev in &events {
            assert_eq!(ev.kind, EventKind::DefenderDetection);
            assert!(ev.summary.chars().count() <= 200);
            assert!(!ev.summary.contains('\n'));
            assert_eq!(ev.user.as_deref(), Some("MSEDGEWIN10\\IEUser"));
            assert_eq!(ev.details["detection_origin"], "%%845");
            assert_eq!(ev.details["execution"], "%%813");
        }
        for ev in &e1116 {
            assert_eq!(ev.details["stage"], "detected");
            assert!(!ev.details.contains_key("action"));
            assert!(ev.summary.starts_with("Defender detected "));
        }
        for ev in &e1117 {
            assert_eq!(ev.details["stage"], "action_taken");
            assert!(ev.details.contains_key("action"));
            assert!(ev.summary.starts_with("Defender action "));
        }

        assert_eq!(
            e1116[0].target.as_deref(),
            Some("Trojan:PowerShell/Powersploit.M")
        );
        assert_eq!(e1116[0].details["severity"], "Severe");
        assert_eq!(e1116[0].details["category"], "Trojan");
        assert_eq!(e1117[0].details["action"], "%%809");
        assert_eq!(e1117[4].details["action"], "%%811");
    }
}
