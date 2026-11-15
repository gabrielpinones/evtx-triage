use std::collections::BTreeMap;

use jiff::Timestamp;
use serde_json::Value;

use crate::model::{EventKind, SourceKind, TimelineEvent};

const MAX_SUMMARY_CHARS: usize = 200;

/// Common metadata extracted from `Event.System` and the parser record header.
pub(crate) struct RecordMeta {
    pub ts: Timestamp,
    pub host: String,
    pub channel: Option<String>,
    pub provider: String,
    pub event_id: u32,
    /// Id from `System.EventRecordID`, or from the record framing if the XML has none.
    pub record_id: u64,
    /// Id from the record framing, kept only when it differs from `record_id`.
    pub file_record_id: Option<u64>,
    pub user_sid: Option<String>,
    pub file: String,
}

impl RecordMeta {
    pub fn base_event(&self, kind: EventKind) -> TimelineEvent {
        let mut event = TimelineEvent::new(
            self.ts,
            self.host.clone(),
            SourceKind::Evtx,
            kind,
            self.file.clone(),
        );
        event.channel = self.channel.clone();
        event.provider = Some(self.provider.clone());
        event.event_id = Some(self.event_id);
        event.record_id = Some(self.record_id);
        insert_opt_u64(&mut event.details, "file_record_id", self.file_record_id);
        event
    }
}

/// Converts any JSON scalar into a non-empty string, treating `""` and `"-"` as absent.
pub(crate) fn scalar_str(val: &Value) -> Option<String> {
    match val {
        Value::String(s) => {
            if s.is_empty() || s == "-" {
                None
            } else {
                Some(s.clone())
            }
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

pub(crate) fn field_str(data: &Value, key: &str) -> Option<String> {
    data.get(key).and_then(scalar_str)
}

pub(crate) fn field_u32(data: &Value, key: &str) -> Option<u32> {
    match data.get(key)? {
        Value::Number(n) => n.as_u64().and_then(|v| u32::try_from(v).ok()),
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "-" {
                None
            } else {
                trimmed.parse::<u32>().ok()
            }
        }
        _ => None,
    }
}

pub(crate) fn field_u64_dec(data: &Value, key: &str) -> Option<u64> {
    match data.get(key)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "-" {
                None
            } else {
                trimmed.parse::<u64>().ok()
            }
        }
        _ => None,
    }
}

pub(crate) fn field_u64_hex(data: &Value, key: &str) -> Option<u64> {
    match data.get(key)? {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed == "-" {
                return None;
            }
            let hex = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
                .unwrap_or(trimmed);
            u64::from_str_radix(hex, 16).ok()
        }
        _ => None,
    }
}

pub(crate) fn format_user(domain: Option<String>, user: Option<String>) -> Option<String> {
    let user = user?;
    match domain {
        Some(domain) => Some(format!("{domain}\\{user}")),
        None => Some(user),
    }
}

pub(crate) fn user_from_fields(data: &Value, domain_key: &str, user_key: &str) -> Option<String> {
    format_user(field_str(data, domain_key), field_str(data, user_key))
}

pub(crate) fn insert_opt_str(
    details: &mut BTreeMap<String, Value>,
    key: &str,
    val: Option<String>,
) {
    if let Some(v) = val {
        details.insert(key.to_string(), Value::String(v));
    }
}

pub(crate) fn insert_opt_u64(details: &mut BTreeMap<String, Value>, key: &str, val: Option<u64>) {
    if let Some(v) = val {
        details.insert(key.to_string(), Value::from(v));
    }
}

pub(crate) fn insert_opt_bool(details: &mut BTreeMap<String, Value>, key: &str, val: Option<bool>) {
    if let Some(v) = val {
        details.insert(key.to_string(), Value::Bool(v));
    }
}

pub(crate) fn single_line(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut prev_cr = false;
    for c in s.chars() {
        match c {
            '\r' => {
                out.push(' ');
                prev_cr = true;
            }
            '\n' => {
                if !prev_cr {
                    out.push(' ');
                }
                prev_cr = false;
            }
            '\t' => {
                out.push(' ');
                prev_cr = false;
            }
            _ => {
                out.push(c);
                prev_cr = false;
            }
        }
    }
    out
}

pub(crate) fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars <= 3 {
        return s.chars().take(max_chars).collect();
    }
    if s.char_indices().nth(max_chars).is_some() {
        let cut = s
            .char_indices()
            .nth(max_chars - 3)
            .map(|(i, _)| i)
            .unwrap_or(s.len());
        let mut out = String::with_capacity(cut + 3);
        out.push_str(&s[..cut]);
        out.push_str("...");
        out
    } else {
        s.to_string()
    }
}

/// Joins `prefix` and optional `tail` into one line capped at `MAX_SUMMARY_CHARS`.
pub(crate) fn format_summary_with_tail(prefix: &str, tail: Option<&str>) -> String {
    let clean_prefix = single_line(prefix);
    let combined = match tail
        .map(|t| single_line(t.trim()))
        .filter(|t| !t.is_empty())
    {
        Some(clean_tail) => format!("{clean_prefix}: {clean_tail}"),
        None => clean_prefix,
    };
    truncate_chars(&combined, MAX_SUMMARY_CHARS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalar_str_handles_all_scalars_and_sentinels() {
        assert_eq!(scalar_str(&json!("hello")), Some("hello".into()));
        assert_eq!(scalar_str(&json!(42)), Some("42".into()));
        assert_eq!(scalar_str(&json!(true)), Some("true".into()));
        assert_eq!(scalar_str(&json!("")), None);
        assert_eq!(scalar_str(&json!("-")), None);
        assert_eq!(scalar_str(&json!(null)), None);
        assert_eq!(scalar_str(&json!([1, 2])), None);
        assert_eq!(scalar_str(&json!({"a": 1})), None);
    }

    #[test]
    fn parses_hex_and_decimal_pids() {
        let data = json!({
            "HexPid": "0x1a2c",
            "UpperHex": "0XFF",
            "DecPid": 3348,
            "DecStr": "460",
            "Dash": "-",
        });
        assert_eq!(field_u64_hex(&data, "HexPid"), Some(0x1a2c));
        assert_eq!(field_u64_hex(&data, "UpperHex"), Some(0xff));
        assert_eq!(field_u64_hex(&data, "Dash"), None);
        assert_eq!(field_u64_dec(&data, "DecPid"), Some(3348));
        assert_eq!(field_u64_dec(&data, "DecStr"), Some(460));
        assert_eq!(field_u64_dec(&data, "Dash"), None);
    }

    #[test]
    fn formats_user_with_and_without_domain() {
        assert_eq!(
            format_user(Some("CORP".into()), Some("alice".into())),
            Some("CORP\\alice".into())
        );
        assert_eq!(
            format_user(None, Some("alice".into())),
            Some("alice".into())
        );
        assert_eq!(format_user(Some("CORP".into()), None), None);
    }

    #[test]
    fn truncates_on_utf8_boundary() {
        let long = "á".repeat(250);
        let summary = format_summary_with_tail("Cmd", Some(&long));
        assert!(summary.chars().count() <= MAX_SUMMARY_CHARS);
        assert!(summary.ends_with("..."));
        assert!(!summary.contains('\n'));
    }
}
