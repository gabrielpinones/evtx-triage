//! Single dispatch table mapping `(provider, event_id)` pairs to extractors.

use serde_json::Value;

use crate::model::TimelineEvent;
use crate::source::evtx::fields::RecordMeta;
use crate::source::evtx::powershell::ScriptBlockCollector;
use crate::source::evtx::{account, kerberos, logon, process, service, task};

const SECURITY: &str = "Microsoft-Windows-Security-Auditing";
const EVENTLOG: &str = "Microsoft-Windows-Eventlog";
const SCM: &str = "Service Control Manager";
const SYSMON: &str = "Microsoft-Windows-Sysmon";
const POWERSHELL: &str = "Microsoft-Windows-PowerShell";

enum Handler {
    Event(fn(&RecordMeta, &Value) -> TimelineEvent),
    OptionalEvent(fn(&RecordMeta, &Value) -> Option<TimelineEvent>),
    LogFileCleared(fn(&RecordMeta, &Value) -> TimelineEvent),
    LogFileClearedOptional(fn(&RecordMeta, &Value) -> Option<TimelineEvent>),
    PowerShellScriptBlock,
}

const HANDLERS: &[(&str, u32, Handler)] = &[
    (SECURITY, 4624, Handler::Event(logon::extract_4624)),
    (SECURITY, 4625, Handler::Event(logon::extract_4625)),
    (SECURITY, 4634, Handler::OptionalEvent(logon::extract_4634)),
    (SECURITY, 4647, Handler::OptionalEvent(logon::extract_4647)),
    (SECURITY, 4648, Handler::Event(logon::extract_4648)),
    (SECURITY, 4672, Handler::OptionalEvent(logon::extract_4672)),
    (SECURITY, 4688, Handler::Event(process::extract_4688)),
    (
        SECURITY,
        4697,
        Handler::OptionalEvent(service::extract_4697),
    ),
    (SECURITY, 4698, Handler::Event(task::extract_4698)),
    (SECURITY, 4699, Handler::OptionalEvent(task::extract_4699)),
    (SECURITY, 4702, Handler::OptionalEvent(task::extract_4702)),
    (SECURITY, 4720, Handler::Event(account::extract_4720)),
    (
        SECURITY,
        4728,
        Handler::OptionalEvent(account::extract_4728),
    ),
    (
        SECURITY,
        4732,
        Handler::OptionalEvent(account::extract_4732),
    ),
    (
        SECURITY,
        4756,
        Handler::OptionalEvent(account::extract_4756),
    ),
    (
        SECURITY,
        4768,
        Handler::OptionalEvent(kerberos::extract_4768),
    ),
    (
        SECURITY,
        4769,
        Handler::OptionalEvent(kerberos::extract_4769),
    ),
    (
        SECURITY,
        4771,
        Handler::OptionalEvent(kerberos::extract_4771),
    ),
    (
        SECURITY,
        4776,
        Handler::OptionalEvent(kerberos::extract_4776),
    ),
    (
        EVENTLOG,
        104,
        Handler::LogFileClearedOptional(account::extract_104),
    ),
    (
        EVENTLOG,
        1102,
        Handler::LogFileCleared(account::extract_1102),
    ),
    (SCM, 7045, Handler::Event(service::extract_7045)),
    (SYSMON, 1, Handler::Event(process::extract_sysmon_1)),
    (POWERSHELL, 4104, Handler::PowerShellScriptBlock),
];

fn find_handler(provider: &str, event_id: u32) -> Option<&'static Handler> {
    HANDLERS
        .iter()
        .find(|(p, id, _)| *id == event_id && *p == provider)
        .map(|(_, _, handler)| handler)
}

/// Returns true if `(provider, event_id)` is handled by `dispatch`.
pub(crate) fn is_supported(provider: &str, event_id: u32) -> bool {
    find_handler(provider, event_id).is_some()
}

/// Routes a normalized event record to its extractor and appends any result to `out`.
///
/// Returns `true` when `(meta.provider, meta.event_id)` is in the dispatch table
/// (even if a stub returns `None` or a PowerShell chunk is buffered into `ps_collector`).
pub(crate) fn dispatch(
    meta: &RecordMeta,
    event_data: &Value,
    user_data: &Value,
    ps_collector: &mut ScriptBlockCollector,
    out: &mut Vec<TimelineEvent>,
) -> bool {
    let Some(handler) = find_handler(&meta.provider, meta.event_id) else {
        return false;
    };
    let log_cleared = || user_data.get("LogFileCleared").unwrap_or(&Value::Null);
    match handler {
        Handler::Event(extract) => out.push(extract(meta, event_data)),
        Handler::OptionalEvent(extract) => {
            if let Some(event) = extract(meta, event_data) {
                out.push(event);
            }
        }
        Handler::LogFileCleared(extract) => out.push(extract(meta, log_cleared())),
        Handler::LogFileClearedOptional(extract) => {
            if let Some(event) = extract(meta, log_cleared()) {
                out.push(event);
            }
        }
        Handler::PowerShellScriptBlock => ps_collector.push(meta, event_data),
    }
    true
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use jiff::Timestamp;
    use serde_json::json;

    use crate::model::EventKind;

    use super::*;

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
    fn every_pair_in_supported_list_dispatches_and_outside_pairs_do_not() {
        let mut seen = BTreeSet::new();
        for &(provider, event_id, _) in HANDLERS {
            assert!(
                seen.insert((provider, event_id)),
                "duplicate dispatch entry ({provider}, {event_id})"
            );
            assert!(
                is_supported(provider, event_id),
                "expected ({provider}, {event_id}) to be supported"
            );

            let m = meta(provider, event_id);
            let mut ps = ScriptBlockCollector::default();
            let mut out = Vec::new();
            assert!(
                dispatch(&m, &Value::Null, &Value::Null, &mut ps, &mut out),
                "expected dispatch to handle ({provider}, {event_id})"
            );
        }

        let unsupported = [
            (SECURITY, 9999),
            ("Some-Other-Provider", 4624),
            ("Microsoft-Windows-Kernel-General", 1),
        ];
        for (provider, event_id) in unsupported {
            assert!(!is_supported(provider, event_id));
            let m = meta(provider, event_id);
            let mut ps = ScriptBlockCollector::default();
            let mut out = Vec::new();
            assert!(!dispatch(&m, &Value::Null, &Value::Null, &mut ps, &mut out));
            assert!(out.is_empty());
        }
    }

    #[test]
    fn event_104_only_dispatches_for_eventlog_provider() {
        assert!(is_supported("Microsoft-Windows-Eventlog", 104));
        assert!(!is_supported(
            "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
            104
        ));

        let mut ps = ScriptBlockCollector::default();
        let mut out = Vec::new();

        assert!(dispatch(
            &meta("Microsoft-Windows-Eventlog", 104),
            &Value::Null,
            &json!({"LogFileCleared": {"SubjectUserName": "admin", "Channel": "System"}}),
            &mut ps,
            &mut out
        ));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EventKind::LogClear);
        assert_eq!(out[0].target.as_deref(), Some("System"));
        assert_eq!(out[0].user.as_deref(), Some("admin"));

        assert!(!dispatch(
            &meta("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS", 104),
            &json!({"ClientIP": "10.0.0.1"}),
            &Value::Null,
            &mut ps,
            &mut out
        ));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn event_1102_reads_user_data_log_file_cleared() {
        let mut ps = ScriptBlockCollector::default();
        let mut out = Vec::new();
        let m = meta("Microsoft-Windows-Eventlog", 1102);
        let user_data = json!({
            "LogFileCleared": {
                "SubjectUserName": "admin",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x3e7"
            }
        });

        assert!(dispatch(&m, &Value::Null, &user_data, &mut ps, &mut out));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EventKind::LogClear);
        assert_eq!(out[0].user.as_deref(), Some("CORP\\admin"));
    }

    #[test]
    fn powershell_4104_collects_via_script_block_collector() {
        let mut ps = ScriptBlockCollector::default();
        let mut out = Vec::new();
        let m = meta("Microsoft-Windows-PowerShell", 4104);
        let event_data = json!({
            "MessageNumber": 1,
            "MessageTotal": 1,
            "ScriptBlockId": "sb-1",
            "ScriptBlockText": "Write-Output hi"
        });

        assert!(dispatch(&m, &event_data, &Value::Null, &mut ps, &mut out));
        assert!(out.is_empty());
        let finished = ps.finish(&mut out);
        assert_eq!(finished, 1);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EventKind::ScriptBlock);
    }
}
