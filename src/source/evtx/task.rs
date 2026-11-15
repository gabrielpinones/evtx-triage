use std::fmt::Write as _;
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, format_summary_with_tail, insert_opt_str, user_from_fields,
};

static EXEC_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)<Exec(?:\s[^>]*)?>(.*?)</Exec>").ok());
static CMD_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)<Command(?:\s[^>]*)?>(.*?)</Command>").ok());
static ARGS_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)<Arguments(?:\s[^>]*)?>(.*?)</Arguments>").ok());
static PRINCIPAL_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)<Principal(?:\s[^>]*)?>(.*?)</Principal>").ok());
static USER_ID_RE: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"(?s)<UserId(?:\s[^>]*)?>(.*?)</UserId>").ok());

fn extract_task_event(
    meta: &RecordMeta,
    data: &Value,
    kind: EventKind,
    action: &str,
    content_key: &str,
) -> TimelineEvent {
    let mut event = meta.base_event(kind);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.target = field_str(data, "TaskName");
    event.logon_id = field_str(data, "SubjectLogonId");

    let task_content = field_str(data, content_key);
    if let Some(xml) = &task_content {
        let parsed = parse_task_xml(xml);
        event.command_line = match (&parsed.command, &parsed.arguments) {
            (Some(cmd), Some(args)) => Some(format!("{cmd} {args}")),
            (Some(cmd), None) => Some(cmd.clone()),
            (None, _) => None,
        };
        insert_opt_str(&mut event.details, "task_content", task_content);
        insert_opt_str(&mut event.details, "task_command", parsed.command);
        insert_opt_str(&mut event.details, "task_arguments", parsed.arguments);
        insert_opt_str(&mut event.details, "task_run_as", parsed.run_as);
    }

    let mut prefix = String::from("Scheduled task");
    if let Some(target) = &event.target {
        let _ = write!(prefix, " {target}");
    }
    let _ = write!(prefix, " {action}");
    if let Some(user) = &event.user {
        let _ = write!(prefix, " by {user}");
    }
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    event
}

pub(crate) fn extract_4698(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    extract_task_event(meta, data, EventKind::TaskCreate, "created", "TaskContent")
}

/// 4699: a scheduled task was deleted.
pub(crate) fn extract_4699(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_task_event(
        meta,
        data,
        EventKind::TaskDelete,
        "deleted",
        "TaskContent",
    ))
}

/// 4702: a scheduled task was updated.
pub(crate) fn extract_4702(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    Some(extract_task_event(
        meta,
        data,
        EventKind::TaskUpdate,
        "updated",
        "TaskContentNew",
    ))
}

struct ParsedTaskXml {
    command: Option<String>,
    arguments: Option<String>,
    run_as: Option<String>,
}

fn parse_task_xml(xml: &str) -> ParsedTaskXml {
    let exec_body = EXEC_RE
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .map(|m| m.as_str());
    let command = exec_body.and_then(|b| capture_decoded(CMD_RE.as_ref()?, b));
    let arguments = exec_body.and_then(|b| capture_decoded(ARGS_RE.as_ref()?, b));
    let run_as = PRINCIPAL_RE
        .as_ref()
        .and_then(|re| re.captures(xml))
        .and_then(|c| c.get(1))
        .and_then(|m| capture_decoded(USER_ID_RE.as_ref()?, m.as_str()));

    ParsedTaskXml {
        command,
        arguments,
        run_as,
    }
}

fn capture_decoded(re: &Regex, haystack: &str) -> Option<String> {
    let raw = re.captures(haystack)?.get(1)?.as_str().trim();
    if raw.is_empty() {
        return None;
    }
    let decoded = decode_xml_entities(raw);
    if decoded.is_empty() {
        None
    } else {
        Some(decoded)
    }
}

/// Decodes the five standard XML entities in a single pass so `&amp;lt;` becomes `&lt;`, not `<`.
fn decode_xml_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp..];
        if let Some(rem) = after.strip_prefix("&amp;") {
            out.push('&');
            rest = rem;
        } else if let Some(rem) = after.strip_prefix("&lt;") {
            out.push('<');
            rest = rem;
        } else if let Some(rem) = after.strip_prefix("&gt;") {
            out.push('>');
            rest = rem;
        } else if let Some(rem) = after.strip_prefix("&quot;") {
            out.push('"');
            rest = rem;
        } else if let Some(rem) = after.strip_prefix("&apos;") {
            out.push('\'');
            rest = rem;
        } else {
            out.push('&');
            rest = &after[1..];
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use serde_json::json;

    #[test]
    fn extracts_4698_and_decodes_xml_entities() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id: 4698,
            record_id: 1,
            file_record_id: None,
            user_sid: None,
            file: "test.evtx".into(),
        };
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2">
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
    </Principal>
  </Principals>
  <Actions>
    <Exec>
      <Command>cmd.exe</Command>
      <Arguments>/c echo &quot;hi&quot; &amp; dir &lt;in&gt; &apos;ok&apos; &amp;lt;literal&amp;gt;</Arguments>
    </Exec>
  </Actions>
</Task>"#;
        let data = json!({
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x17e2d2",
            "TaskName": "\\Updater",
            "TaskContent": xml
        });
        let ev = extract_4698(&meta, &data);
        assert_eq!(ev.kind, EventKind::TaskCreate);
        assert_eq!(ev.user.as_deref(), Some("CORP\\bob"));
        assert_eq!(ev.target.as_deref(), Some("\\Updater"));
        assert_eq!(ev.details["task_command"], "cmd.exe");
        assert_eq!(
            ev.details["task_arguments"],
            "/c echo \"hi\" & dir <in> 'ok' &lt;literal&gt;"
        );
        assert_eq!(ev.details["task_run_as"], "S-1-5-18");
        assert_eq!(ev.details["task_content"], xml);
        assert_eq!(
            ev.command_line.as_deref(),
            Some("cmd.exe /c echo \"hi\" & dir <in> 'ok' &lt;literal&gt;")
        );
        assert_eq!(
            ev.summary,
            "Scheduled task \\Updater created by CORP\\bob: cmd.exe /c echo \"hi\" & dir <in> 'ok' &lt;literal&gt;"
        );
    }

    #[test]
    fn handles_4698_without_arguments() {
        let meta = RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id: 4698,
            record_id: 2,
            file_record_id: None,
            user_sid: None,
            file: "test.evtx".into(),
        };
        let data = json!({
            "SubjectUserName": "bob",
            "TaskName": "\\Run",
            "TaskContent": "<Task><Actions><Exec><Command>C:\\evil.exe</Command></Exec></Actions></Task>"
        });
        let ev = extract_4698(&meta, &data);
        assert_eq!(ev.command_line.as_deref(), Some("C:\\evil.exe"));
        assert!(!ev.details.contains_key("task_arguments"));
        assert!(!ev.details.contains_key("task_run_as"));
    }

    fn sec_meta(event_id: u32, record_id: u64) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Security".into()),
            provider: "Microsoft-Windows-Security-Auditing".into(),
            event_id,
            record_id,
            file_record_id: None,
            user_sid: None,
            file: "test.evtx".into(),
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
    fn extracts_4699_task_delete_with_content() {
        let meta = sec_meta(4699, 3);
        let xml = r#"<Task version="1.2"><Principals><Principal id="Author"><UserId>S-1-5-18</UserId></Principal></Principals><Actions><Exec><Command>cmd.exe</Command><Arguments>/C tasklist &gt; C:\Temp\out.tmp</Arguments></Exec></Actions></Task>"#;
        let data = json!({
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x17e2d2",
            "TaskName": "\\Updater",
            "TaskContent": xml
        });
        let ev = extract_4699(&meta, &data).unwrap();
        assert_eq!(ev.kind, EventKind::TaskDelete);
        assert_eq!(ev.user.as_deref(), Some("CORP\\bob"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x17e2d2"));
        assert_eq!(ev.target.as_deref(), Some("\\Updater"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("cmd.exe /C tasklist > C:\\Temp\\out.tmp")
        );
        assert_eq!(ev.details["task_command"], "cmd.exe");
        assert_eq!(
            ev.details["task_arguments"],
            "/C tasklist > C:\\Temp\\out.tmp"
        );
        assert_eq!(ev.details["task_run_as"], "S-1-5-18");
        assert_eq!(ev.details["task_content"], xml);
        assert_eq!(
            ev.summary,
            "Scheduled task \\Updater deleted by CORP\\bob: cmd.exe /C tasklist > C:\\Temp\\out.tmp"
        );
    }

    #[test]
    fn extracts_4699_task_delete_without_content() {
        let meta = sec_meta(4699, 4);
        let data = json!({
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x3e7",
            "TaskName": "\\Updater"
        });
        let ev = extract_4699(&meta, &data).unwrap();
        assert_eq!(ev.kind, EventKind::TaskDelete);
        assert_eq!(ev.user.as_deref(), Some("CORP\\bob"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x3e7"));
        assert_eq!(ev.target.as_deref(), Some("\\Updater"));
        assert!(ev.command_line.is_none());
        assert!(!ev.details.contains_key("task_content"));
        assert!(!ev.details.contains_key("task_command"));
        assert!(!ev.details.contains_key("task_arguments"));
        assert!(!ev.details.contains_key("task_run_as"));
        assert_eq!(ev.summary, "Scheduled task \\Updater deleted by CORP\\bob");
    }

    #[test]
    fn extracts_4702_task_update_with_xml_entities() {
        let meta = sec_meta(4702, 5);
        let xml = r#"<Task version="1.2"><Principals><Principal id="Author"><UserId>SYSTEM</UserId></Principal></Principals><Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c echo &quot;hi&quot; &amp; evil.bat &gt; c:\out.txt &lt;in&gt; &apos;ok&apos;</Arguments></Exec></Actions></Task>"#;
        let data = json!({
            "SubjectUserName": "bob",
            "SubjectDomainName": "CORP",
            "SubjectLogonId": "0x21a8c68",
            "TaskName": "\\Updater",
            "TaskContentNew": xml
        });
        let ev = extract_4702(&meta, &data).unwrap();
        assert_eq!(ev.kind, EventKind::TaskUpdate);
        assert_eq!(ev.user.as_deref(), Some("CORP\\bob"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x21a8c68"));
        assert_eq!(ev.target.as_deref(), Some("\\Updater"));
        assert_eq!(ev.details["task_command"], "cmd.exe");
        assert_eq!(
            ev.details["task_arguments"],
            "/c echo \"hi\" & evil.bat > c:\\out.txt <in> 'ok'"
        );
        assert_eq!(ev.details["task_run_as"], "SYSTEM");
        assert_eq!(ev.details["task_content"], xml);
        assert_eq!(
            ev.command_line.as_deref(),
            Some("cmd.exe /c echo \"hi\" & evil.bat > c:\\out.txt <in> 'ok'")
        );
        assert_eq!(
            ev.summary,
            "Scheduled task \\Updater updated by CORP\\bob: cmd.exe /c echo \"hi\" & evil.bat > c:\\out.txt <in> 'ok'"
        );
    }

    #[test]
    fn fixture_4699_temp_scheduled_task() {
        let events = read_fixture_events(&["attack-samples", "temp_scheduled_task_4698_4699.evtx"]);
        assert_eq!(events.len(), 2);
        let deletes: Vec<_> = events.iter().filter(|e| e.event_id == Some(4699)).collect();
        assert_eq!(deletes.len(), 1);
        let ev = deletes[0];
        assert_eq!(ev.kind, EventKind::TaskDelete);
        assert_eq!(ev.user.as_deref(), Some("EXAMPLE\\Administrator"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x17e2d2"));
        assert_eq!(ev.target.as_deref(), Some("\\CYAlyNSS"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("cmd.exe /C tasklist > %windir%\\Temp\\CYAlyNSS.tmp 2>&1")
        );
        assert_eq!(ev.details["task_run_as"], "S-1-5-18");
    }

    #[test]
    fn fixture_4699_lm_scheduled_task() {
        let events =
            read_fixture_events(&["attack-samples", "LM_ScheduledTask_ATSVC_target_host.evtx"]);
        let deletes: Vec<_> = events.iter().filter(|e| e.event_id == Some(4699)).collect();
        assert_eq!(deletes.len(), 1);
        let ev = deletes[0];
        assert_eq!(ev.kind, EventKind::TaskDelete);
        assert_eq!(ev.user.as_deref(), Some("EXAMPLE\\Administrator"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x17e2d2"));
        assert_eq!(ev.target.as_deref(), Some("\\CYAlyNSS"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("cmd.exe /C tasklist > %windir%\\Temp\\CYAlyNSS.tmp 2>&1")
        );
    }

    #[test]
    fn fixture_4702_remote_task_update() {
        let events = read_fixture_events(&[
            "attack-samples",
            "remote task update 4624 4702 same logonid.evtx",
        ]);
        let updates: Vec<_> = events.iter().filter(|e| e.event_id == Some(4702)).collect();
        assert_eq!(updates.len(), 1);
        let ev = updates[0];
        assert_eq!(ev.kind, EventKind::TaskUpdate);
        assert_eq!(ev.user.as_deref(), Some("3B\\a-jbrown"));
        assert_eq!(ev.logon_id.as_deref(), Some("0x21a8c68"));
        assert_eq!(ev.target.as_deref(), Some("\\LMST"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("cmd.exe /c echo testing > c:\\users\\public\\out.txt")
        );
        assert_eq!(ev.details["task_run_as"], "SYSTEM");
        assert!(
            events
                .iter()
                .any(|e| e.event_id == Some(4624) && e.logon_id.as_deref() == Some("0x21a8c68"))
        );
    }
}
