use std::path::Path;

use ::evtx::{EvtxParser, ParserSettings};
use jiff::Timestamp;
use serde_json::Value;

use crate::model::TimelineEvent;
use crate::source::evtx::fields::{RecordMeta, scalar_str};
use crate::source::evtx::powershell::ScriptBlockCollector;
use crate::source::evtx::{account, logon, process, service, task};
use crate::source::{ReadOptions, SourceStats};

pub(crate) fn read_file(
    path: &Path,
    options: &ReadOptions,
    out: &mut Vec<TimelineEvent>,
) -> anyhow::Result<SourceStats> {
    let settings = ParserSettings::new().separate_json_attributes(false);
    let mut parser = EvtxParser::from_path(path)?.with_configuration(settings);

    let file_str = path.to_string_lossy().into_owned();
    let mut stats = SourceStats::default();
    let mut ps_collector = ScriptBlockCollector::default();

    for item in parser.records_json_value() {
        let record = match item {
            Ok(r) => r,
            Err(_) => {
                stats.errors = stats.errors.saturating_add(1);
                continue;
            }
        };
        stats.records_seen = stats.records_seen.saturating_add(1);

        let Some(event_obj) = record.data.get("Event") else {
            continue;
        };
        let Some(system) = event_obj.get("System") else {
            continue;
        };
        let Some(provider) = extract_provider(system) else {
            continue;
        };
        let Some(event_id) = extract_event_id(system) else {
            continue;
        };

        if !is_supported(provider, event_id) {
            continue;
        }

        // A log that was exported or rewritten is renumbered in the record
        // framing, while the XML keeps the id the event had on the source
        // host. The XML id is the one other tools and analysts refer to.
        let xml_record_id = system.get("EventRecordID").and_then(Value::as_u64);
        let record_id = xml_record_id.unwrap_or(record.event_record_id);

        // Same story for the time: exported logs can carry a zeroed FILETIME
        // in the framing, which would put the event in 1601.
        let ts = system
            .get("TimeCreated")
            .and_then(|t| t.get("#attributes"))
            .and_then(|a| a.get("SystemTime"))
            .and_then(Value::as_str)
            .and_then(|text| text.parse::<Timestamp>().ok())
            .unwrap_or(record.timestamp);

        let meta = RecordMeta {
            ts,
            host: system
                .get("Computer")
                .and_then(scalar_str)
                .or_else(|| options.host_fallback.clone())
                .unwrap_or_default(),
            channel: system.get("Channel").and_then(scalar_str),
            provider: provider.to_string(),
            event_id,
            record_id,
            file_record_id: (record_id != record.event_record_id).then_some(record.event_record_id),
            user_sid: system
                .get("Security")
                .and_then(|s| s.get("#attributes"))
                .and_then(|a| a.get("UserID"))
                .and_then(scalar_str),
            file: file_str.clone(),
        };

        let event_data = event_obj.get("EventData").unwrap_or(&Value::Null);
        match (provider, event_id) {
            ("Microsoft-Windows-Security-Auditing", 4624) => {
                out.push(logon::extract_4624(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-Security-Auditing", 4625) => {
                out.push(logon::extract_4625(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-Security-Auditing", 4648) => {
                out.push(logon::extract_4648(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-Security-Auditing", 4688) => {
                out.push(process::extract_4688(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-Security-Auditing", 4698) => {
                out.push(task::extract_4698(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-Security-Auditing", 4720) => {
                out.push(account::extract_4720(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-Eventlog", 1102) => {
                let log_cleared = event_obj
                    .get("UserData")
                    .and_then(|ud| ud.get("LogFileCleared"))
                    .unwrap_or(&Value::Null);
                out.push(account::extract_1102(&meta, log_cleared));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Service Control Manager", 7045) => {
                out.push(service::extract_7045(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-Sysmon", 1) => {
                out.push(process::extract_sysmon_1(&meta, event_data));
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
            ("Microsoft-Windows-PowerShell", 4104) => {
                ps_collector.push(&meta, event_data);
            }
            _ => {}
        }
    }

    let ps_emitted = ps_collector.finish(out);
    stats.events_emitted = stats.events_emitted.saturating_add(ps_emitted);
    Ok(stats)
}

fn is_supported(provider: &str, event_id: u32) -> bool {
    matches!(
        (provider, event_id),
        (
            "Microsoft-Windows-Security-Auditing",
            4624 | 4625 | 4648 | 4688 | 4698 | 4720
        ) | ("Microsoft-Windows-Eventlog", 1102)
            | ("Service Control Manager", 7045)
            | ("Microsoft-Windows-Sysmon", 1)
            | ("Microsoft-Windows-PowerShell", 4104)
    )
}

fn extract_provider(system: &Value) -> Option<&str> {
    system
        .get("Provider")?
        .get("#attributes")?
        .get("Name")?
        .as_str()
}

pub(crate) fn extract_event_id(system: &Value) -> Option<u32> {
    let val = system.get("EventID")?;
    parse_event_id_value(val).or_else(|| val.get("#text").and_then(parse_event_id_value))
}

fn parse_event_id_value(val: &Value) -> Option<u32> {
    match val {
        Value::Number(n) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        Value::String(s) => s.trim().parse::<u32>().ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EventKind;
    use serde_json::json;
    use std::path::PathBuf;

    fn attack_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/attack-samples")
            .join(name)
    }

    fn count_kind(events: &[TimelineEvent], kind: EventKind) -> usize {
        events.iter().filter(|e| e.kind == kind).count()
    }

    #[test]
    fn parses_event_id_as_number_or_object() {
        let num = json!({ "EventID": 4624 });
        assert_eq!(extract_event_id(&num), Some(4624));

        let obj = json!({
            "EventID": {
                "#attributes": { "Qualifiers": 16384 },
                "#text": 7045
            }
        });
        assert_eq!(extract_event_id(&obj), Some(7045));
    }

    #[test]
    fn fixture_lm_remote_service_7045() {
        let mut events = Vec::new();
        let stats = read_file(
            &attack_fixture("LM_Remote_Service02_7045.evtx"),
            &ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(events.len(), 3);
        assert_eq!(count_kind(&events, EventKind::ServiceInstall), 3);
    }

    #[test]
    fn fixture_lm_scheduled_task() {
        let mut events = Vec::new();
        let stats = read_file(
            &attack_fixture("LM_ScheduledTask_ATSVC_target_host.evtx"),
            &ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(count_kind(&events, EventKind::LogClear), 1);
        assert_eq!(count_kind(&events, EventKind::LogonSuccess), 6);
        assert_eq!(count_kind(&events, EventKind::TaskCreate), 1);
        assert_eq!(count_kind(&events, EventKind::ProcessCreate), 4);
        assert_eq!(events.len(), 12);
        assert_eq!(stats.events_emitted, 12);
    }

    #[test]
    fn fixture_de_fake_computer_account_4720() {
        let mut events = Vec::new();
        let stats = read_file(
            &attack_fixture("DE_Fake_ComputerAccount_4720.evtx"),
            &ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(count_kind(&events, EventKind::UserCreate), 2);
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn fixture_ca_4624_4625_chrome() {
        let mut events = Vec::new();
        let stats = read_file(
            &attack_fixture("CA_4624_4625_LogonType2_LogonProc_chrome.evtx"),
            &ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(count_kind(&events, EventKind::LogonFailure), 1);
        assert_eq!(count_kind(&events, EventKind::LogonSuccess), 3);
        assert_eq!(events.len(), 4);
        let failure = events
            .iter()
            .find(|e| e.kind == EventKind::LogonFailure)
            .unwrap();
        assert_eq!(failure.details["failure"], "wrong password");
    }

    #[test]
    fn fixture_de_rdp_tunnel_5156() {
        let mut events = Vec::new();
        let stats = read_file(
            &attack_fixture("DE_RDP_Tunnel_5156.evtx"),
            &ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(count_kind(&events, EventKind::LogClear), 1);
        assert_eq!(count_kind(&events, EventKind::ProcessCreate), 17);
        assert_eq!(count_kind(&events, EventKind::ExplicitLogon), 3);
        assert_eq!(count_kind(&events, EventKind::LogonSuccess), 5);
        assert_eq!(events.len(), 26);
    }

    #[test]
    fn fixture_lm_sysmon_psexec() {
        let mut events = Vec::new();
        let stats = read_file(
            &attack_fixture("LM_sysmon_psexec_smb_meterpreter.evtx"),
            &ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(count_kind(&events, EventKind::ProcessCreate), 3);
    }

    #[test]
    fn fixture_phish_powershell_4104() {
        let mut events = Vec::new();
        let stats = read_file(
            &attack_fixture("phish_windows_credentials_powershell_scriptblockLog_4104.evtx"),
            &ReadOptions::default(),
            &mut events,
        )
        .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.records_seen, 2);
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(count_kind(&events, EventKind::ScriptBlock), 2);
    }

    #[test]
    fn non_evtx_file_returns_err() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp.as_file(), b"not an evtx file").unwrap();
        let mut events = Vec::new();
        let res = read_file(tmp.path(), &ReadOptions::default(), &mut events);
        assert!(res.is_err());
    }

    #[test]
    fn bad_chunk_magic_file_reads_without_panicking() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx");
        let mut events = Vec::new();
        let stats = read_file(&path, &ReadOptions::default(), &mut events).unwrap();
        assert_eq!(stats.records_seen, 301);
        assert_eq!(stats.errors, 3);
    }
}
