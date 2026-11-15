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

pub(crate) fn extract_4698(meta: &RecordMeta, data: &Value) -> TimelineEvent {
    let mut event = meta.base_event(EventKind::TaskCreate);
    event.user = user_from_fields(data, "SubjectDomainName", "SubjectUserName");
    event.target = field_str(data, "TaskName");
    event.logon_id = field_str(data, "SubjectLogonId");

    let task_content = field_str(data, "TaskContent");
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
    prefix.push_str(" created");
    if let Some(user) = &event.user {
        let _ = write!(prefix, " by {user}");
    }
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    event
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
}
