use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, format_summary_with_tail, insert_opt_str,
};

pub(crate) fn extract_7045(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::ServiceInstall);
    let service_name = field_str(data, "ServiceName");
    let image_path = field_str(data, "ImagePath");

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
        field_str(data, "StartType"),
    );
    insert_opt_str(
        &mut event.details,
        "account",
        field_str(data, "AccountName"),
    );
    insert_opt_str(&mut event.details, "user_sid", meta.user_sid.clone());

    let prefix = match &service_name {
        Some(name) => format!("Service \"{name}\" installed"),
        None => "Service installed".to_string(),
    };
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    event
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
}
