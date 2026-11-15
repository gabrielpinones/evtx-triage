//! Linux auditd (`audit.log`) source reader.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use jiff::Timestamp;
use serde_json::Value;

use crate::model::{EventKind, SourceKind, TimelineEvent};
use crate::source::{ReadOptions, Source, SourceStats};

const MAX_SUMMARY_CMD_CHARS: usize = 200;

/// Multi-record events waiting for their last record.
///
/// auditd usually does not write `EOE` records to disk, so most events never
/// get an explicit end. Records of one event are written next to each other,
/// which means the oldest pending events are complete: past this many, the
/// older half is flushed. That keeps memory flat on large logs.
const MAX_PENDING_EVENTS: usize = 1024;

pub struct AuditdSource;

impl Source for AuditdSource {
    fn read(
        &self,
        path: &Path,
        options: &ReadOptions,
        out: &mut Vec<TimelineEvent>,
    ) -> anyhow::Result<SourceStats> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let file_label = path.to_string_lossy().into_owned();

        let mut stats = SourceStats::default();
        let mut pending: BTreeMap<(Timestamp, u64), PendingEvent> = BTreeMap::new();
        let mut buf = Vec::new();

        loop {
            buf.clear();
            let read_bytes = reader.read_until(b'\n', &mut buf)?;
            if read_bytes == 0 {
                break;
            }

            let raw_line = String::from_utf8_lossy(&buf);
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }

            stats.records_seen = stats.records_seen.saturating_add(1);

            let Some(record) = parse_record(line) else {
                stats.errors = stats.errors.saturating_add(1);
                continue;
            };

            if record.record_type == "EOE" {
                if let Some(event_data) = pending.remove(&(record.ts, record.serial))
                    && let Some(event) = event_data.into_timeline_event(options, &file_label)
                {
                    out.push(event);
                    stats.events_emitted = stats.events_emitted.saturating_add(1);
                }
                continue;
            }

            if is_single_record_type(record.record_type) {
                if let Some(event) = build_single_record_event(&record, options, &file_label) {
                    out.push(event);
                    stats.events_emitted = stats.events_emitted.saturating_add(1);
                }
                continue;
            }

            let entry = pending
                .entry((record.ts, record.serial))
                .or_insert_with(|| PendingEvent::new(record.ts, record.serial));
            entry.merge(&record);

            if pending.len() > MAX_PENDING_EVENTS {
                while pending.len() > MAX_PENDING_EVENTS / 2 {
                    let Some((_, event_data)) = pending.pop_first() else {
                        break;
                    };
                    if let Some(event) = event_data.into_timeline_event(options, &file_label) {
                        out.push(event);
                        stats.events_emitted = stats.events_emitted.saturating_add(1);
                    }
                }
            }
        }

        for (_, event_data) in pending {
            if let Some(event) = event_data.into_timeline_event(options, &file_label) {
                out.push(event);
                stats.events_emitted = stats.events_emitted.saturating_add(1);
            }
        }

        Ok(stats)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuoteKind {
    None,
    Double,
    Single,
}

#[derive(Debug, Clone, Copy)]
struct RawField<'a> {
    key: &'a str,
    value: &'a str,
    quote: QuoteKind,
}

struct ParsedRecord<'a> {
    node: Option<String>,
    record_type: &'a str,
    ts: Timestamp,
    serial: u64,
    fields: Vec<RawField<'a>>,
    enriched: BTreeMap<&'a str, String>,
}

fn parse_record(line: &str) -> Option<ParsedRecord<'_>> {
    let (node, rest) = if let Some(after_node) = line.strip_prefix("node=") {
        let (node_raw, remainder) = split_first_ws(after_node)?;
        let clean = unquote_simple(node_raw);
        let node = (!clean.is_empty()).then(|| clean.to_string());
        (node, remainder.trim_start())
    } else {
        (None, line)
    };

    let after_type = rest.strip_prefix("type=")?;
    let (record_type, after_record_type) = split_first_ws(after_type)?;
    if record_type.is_empty() {
        return None;
    }

    let rest = after_record_type.trim_start();
    let after_audit = rest.strip_prefix("msg=audit(")?;
    let (inside_parens, after_parens) = after_audit.split_once(')')?;

    let body = if let Some(after_colon) = after_parens.strip_prefix(':') {
        after_colon
    } else if after_parens.is_empty() || after_parens.starts_with(char::is_whitespace) {
        after_parens
    } else {
        return None;
    };

    let (ts_part, serial_part) = inside_parens.split_once(':')?;
    let serial: u64 = serial_part.parse().ok()?;
    let ts = parse_audit_timestamp(ts_part)?;

    // Auditd enriched logs append uppercase translations after ASCII GS (0x1d).
    let (raw_body, enriched_body) = match body.split_once('\x1d') {
        Some((raw, enr)) => (raw, Some(enr)),
        None => (body, None),
    };

    let fields = parse_fields(raw_body);
    let mut enriched = BTreeMap::new();
    if let Some(enr) = enriched_body {
        for f in parse_fields(enr) {
            enriched.insert(f.key, f.value.to_string());
        }
    }

    Some(ParsedRecord {
        node,
        record_type,
        ts,
        serial,
        fields,
        enriched,
    })
}

fn split_first_ws(s: &str) -> Option<(&str, &str)> {
    let idx = s.find(char::is_whitespace)?;
    Some((&s[..idx], &s[idx..]))
}

fn unquote_simple(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(s)
}

fn parse_audit_timestamp(s: &str) -> Option<Timestamp> {
    let (secs_str, frac_str) = s.split_once('.')?;
    if secs_str.is_empty() || frac_str.is_empty() || !frac_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let secs: i64 = secs_str.parse().ok()?;
    let mut nanos: i32 = 0;
    let mut place: i32 = 100_000_000;
    for b in frac_str.bytes().take(9) {
        let digit = i32::from(b - b'0');
        nanos += digit * place;
        place /= 10;
    }
    Timestamp::new(secs, nanos).ok()
}

fn parse_fields(input: &str) -> Vec<RawField<'_>> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = Vec::new();
    let mut i = 0;

    while i < len {
        while i < len && bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if i >= len {
            break;
        }

        let key_start = i;
        while i < len
            && !bytes
                .get(i)
                .is_some_and(|&b| b == b'=' || b.is_ascii_whitespace())
        {
            i += 1;
        }

        if i >= len || bytes.get(i) != Some(&b'=') {
            while i < len && !bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            continue;
        }

        let key = &input[key_start..i];
        i += 1; // skip '='

        if key.is_empty() {
            while i < len && !bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            continue;
        }

        let (value, quote) = match bytes.get(i) {
            Some(&b'"') => {
                i += 1;
                let val_start = i;
                while i < len && bytes.get(i) != Some(&b'"') {
                    i += 1;
                }
                let v = &input[val_start..i];
                if bytes.get(i) == Some(&b'"') {
                    i += 1;
                }
                (v, QuoteKind::Double)
            }
            Some(&b'\'') => {
                i += 1;
                let val_start = i;
                while i < len && bytes.get(i) != Some(&b'\'') {
                    i += 1;
                }
                let v = &input[val_start..i];
                if bytes.get(i) == Some(&b'\'') {
                    i += 1;
                }
                (v, QuoteKind::Single)
            }
            _ => {
                let val_start = i;
                while i < len && !bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
                    i += 1;
                }
                (&input[val_start..i], QuoteKind::None)
            }
        };

        out.push(RawField { key, value, quote });
    }

    out
}

fn is_arg_key(key: &str) -> bool {
    let Some(rest) = key.strip_prefix('a') else {
        return false;
    };
    !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())
}

fn is_hex_key(key: &str) -> bool {
    matches!(
        key,
        "proctitle" | "cmd" | "comm" | "exe" | "cwd" | "name" | "acct"
    ) || is_arg_key(key)
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for &[b_hi, b_lo] in s.as_bytes().as_chunks::<2>().0 {
        let hi = hex_val(b_hi)?;
        let lo = hex_val(b_lo)?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn decode_field_value(key: &str, value: &str, quote: QuoteKind) -> String {
    if quote == QuoteKind::None
        && is_hex_key(key)
        && let Some(bytes) = decode_hex_bytes(value)
    {
        return String::from_utf8_lossy(&bytes).into_owned();
    }
    value.to_string()
}

fn decode_proctitle(value: &str, quote: QuoteKind) -> String {
    let decoded = decode_field_value("proctitle", value, quote);
    decoded.trim_end_matches('\0').replace('\0', " ")
}

fn parse_split_arg_key(key: &str) -> Option<(usize, usize)> {
    let rest = key.strip_prefix('a')?;
    let (arg_idx_str, after_bracket) = rest.split_once('[')?;
    let part_idx_str = after_bracket.strip_suffix(']')?;
    if arg_idx_str.is_empty() || part_idx_str.is_empty() {
        return None;
    }
    let arg_idx: usize = arg_idx_str.parse().ok()?;
    let part_idx: usize = part_idx_str.parse().ok()?;
    Some((arg_idx, part_idx))
}

fn is_unset_id(val: &str) -> bool {
    matches!(
        val,
        "" | "?" | "(none)" | "(null)" | "-1" | "4294967295" | "unset"
    )
}

fn is_absent_text(val: &str) -> bool {
    matches!(val, "" | "?" | "(none)" | "(null)")
}

fn is_single_record_type(record_type: &str) -> bool {
    matches!(
        record_type,
        "USER_LOGIN" | "USER_AUTH" | "USER_CMD" | "ADD_USER" | "SERVICE_START"
    )
}

fn resolve_host(node: Option<&str>, options: &ReadOptions) -> String {
    if let Some(n) = node
        && !n.is_empty()
    {
        return n.to_string();
    }
    if let Some(fallback) = options.host_fallback.as_deref()
        && !fallback.is_empty()
    {
        return fallback.to_string();
    }
    "unknown".to_string()
}

fn truncate_cmd(cmd: &str, max_chars: usize) -> Cow<'_, str> {
    match cmd.char_indices().nth(max_chars) {
        Some((byte_idx, _)) => Cow::Owned(format!("{}...", &cmd[..byte_idx])),
        None => Cow::Borrowed(cmd),
    }
}

#[derive(Default)]
struct PendingEvent {
    ts: Option<Timestamp>,
    serial: u64,
    node: Option<String>,
    has_syscall: bool,
    is_exec_syscall: bool,
    has_execve: bool,
    exe: Option<String>,
    comm: Option<String>,
    pid: Option<u64>,
    ppid: Option<u64>,
    uid: Option<String>,
    enriched_uid: Option<String>,
    auid: Option<String>,
    euid: Option<String>,
    cwd: Option<String>,
    tty: Option<String>,
    ses: Option<String>,
    key: Option<String>,
    success: Option<String>,
    exit: Option<String>,
    execve_args: BTreeMap<usize, String>,
    proctitle: Option<String>,
}

impl PendingEvent {
    fn new(ts: Timestamp, serial: u64) -> Self {
        Self {
            ts: Some(ts),
            serial,
            ..Self::default()
        }
    }

    fn merge(&mut self, record: &ParsedRecord<'_>) {
        if self.node.is_none()
            && let Some(n) = record.node.as_ref()
        {
            self.node = Some(n.clone());
        }

        if let Some(uid_name) = record.enriched.get("UID")
            && !is_unset_id(uid_name)
        {
            self.enriched_uid = Some(uid_name.clone());
        }

        match record.record_type {
            "SYSCALL" => self.merge_syscall(record),
            "EXECVE" => self.merge_execve(record),
            "CWD" => {
                for f in &record.fields {
                    if f.key == "cwd" {
                        let val = decode_field_value(f.key, f.value, f.quote);
                        if !is_absent_text(&val) {
                            self.cwd = Some(val);
                        }
                    }
                }
            }
            "PROCTITLE" => {
                for f in &record.fields {
                    if f.key == "proctitle" {
                        let val = decode_proctitle(f.value, f.quote);
                        if !is_absent_text(&val) {
                            self.proctitle = Some(val);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn merge_syscall(&mut self, record: &ParsedRecord<'_>) {
        self.has_syscall = true;
        if let Some(sys_name) = record.enriched.get("SYSCALL")
            && matches!(sys_name.as_str(), "execve" | "execveat")
        {
            self.is_exec_syscall = true;
        }

        for f in &record.fields {
            match f.key {
                "syscall" => {
                    if matches!(f.value, "59" | "322" | "execve" | "execveat") {
                        self.is_exec_syscall = true;
                    }
                }
                "exe" => {
                    let val = decode_field_value(f.key, f.value, f.quote);
                    if !is_absent_text(&val) {
                        self.exe = Some(val);
                    }
                }
                "comm" => {
                    let val = decode_field_value(f.key, f.value, f.quote);
                    if !is_absent_text(&val) {
                        self.comm = Some(val);
                    }
                }
                "pid" => self.pid = f.value.parse().ok(),
                "ppid" => self.ppid = f.value.parse().ok(),
                "uid" if !is_absent_text(f.value) => {
                    self.uid = Some(f.value.to_string());
                }
                "auid" if !is_unset_id(f.value) => {
                    self.auid = Some(f.value.to_string());
                }
                "euid" if !is_absent_text(f.value) => {
                    self.euid = Some(f.value.to_string());
                }
                "tty" if !is_absent_text(f.value) => {
                    self.tty = Some(f.value.to_string());
                }
                "ses" if !is_unset_id(f.value) => {
                    self.ses = Some(f.value.to_string());
                }
                "key" if !is_absent_text(f.value) => {
                    self.key = Some(f.value.to_string());
                }
                "success" if !f.value.is_empty() => {
                    self.success = Some(f.value.to_string());
                }
                "exit" if !f.value.is_empty() => {
                    self.exit = Some(f.value.to_string());
                }
                _ => {}
            }
        }
    }

    fn merge_execve(&mut self, record: &ParsedRecord<'_>) {
        self.has_execve = true;
        let mut split_parts: BTreeMap<usize, BTreeMap<usize, (&str, QuoteKind)>> = BTreeMap::new();

        for f in &record.fields {
            if let Some((arg_idx, part_idx)) = parse_split_arg_key(f.key) {
                split_parts
                    .entry(arg_idx)
                    .or_default()
                    .insert(part_idx, (f.value, f.quote));
            } else if is_arg_key(f.key)
                && let Some(arg_idx_str) = f.key.strip_prefix('a')
                && let Ok(arg_idx) = arg_idx_str.parse::<usize>()
            {
                let decoded = decode_field_value(f.key, f.value, f.quote);
                self.execve_args.insert(arg_idx, decoded);
            }
        }

        for (arg_idx, parts) in split_parts {
            let mut combined = String::new();
            let mut all_unquoted = true;
            for (part, quote) in parts.values() {
                if *quote != QuoteKind::None {
                    all_unquoted = false;
                }
                combined.push_str(part);
            }
            let decoded = if all_unquoted {
                decode_field_value("a0", &combined, QuoteKind::None)
            } else {
                combined
            };
            self.execve_args.insert(arg_idx, decoded);
        }
    }

    fn into_timeline_event(self, options: &ReadOptions, file_label: &str) -> Option<TimelineEvent> {
        if !(self.is_exec_syscall || self.has_execve) {
            return None;
        }
        let ts = self.ts?;
        let host = resolve_host(self.node.as_deref(), options);
        let mut event = TimelineEvent::new(
            ts,
            host,
            SourceKind::Auditd,
            EventKind::ProcessCreate,
            file_label,
        );
        event.provider = Some("auditd".to_string());
        event.channel = Some(
            if self.has_syscall {
                "SYSCALL"
            } else {
                "EXECVE"
            }
            .to_string(),
        );
        event.record_id = Some(self.serial);
        event.process = self.exe.clone();
        event.pid = self.pid;
        event.ppid = self.ppid;

        event.user = self
            .enriched_uid
            .or_else(|| self.uid.as_deref().map(|u| format!("uid:{u}")));

        event.command_line = format_execve_args(&self.execve_args).or(self.proctitle);

        insert_detail(&mut event.details, "auid", self.auid);
        insert_detail(&mut event.details, "uid", self.uid);
        insert_detail(&mut event.details, "euid", self.euid);
        insert_detail(&mut event.details, "cwd", self.cwd);
        insert_detail(&mut event.details, "tty", self.tty);
        insert_detail(&mut event.details, "session", self.ses);
        insert_detail(&mut event.details, "key", self.key);
        insert_detail(&mut event.details, "success", self.success);
        insert_detail(&mut event.details, "exit", self.exit);
        insert_detail(&mut event.details, "comm", self.comm.clone());

        let proc_label = event
            .process
            .as_deref()
            .or(self.comm.as_deref())
            .unwrap_or("unknown");
        let pid_part = event.pid.map(|p| format!(" (pid {p})")).unwrap_or_default();
        let user_part = event
            .user
            .as_deref()
            .map(|u| format!(" by {u}"))
            .unwrap_or_default();
        let cmd_part = event
            .command_line
            .as_deref()
            .map(|c| format!(": {}", truncate_cmd(c, MAX_SUMMARY_CMD_CHARS)))
            .unwrap_or_default();
        event.summary = format!("Exec {proc_label}{pid_part}{user_part}{cmd_part}");

        Some(event)
    }
}

fn format_execve_args(args: &BTreeMap<usize, String>) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let mut out = String::new();
    for (idx, arg) in args.values().enumerate() {
        if idx > 0 {
            out.push(' ');
        }
        if arg.chars().any(char::is_whitespace) {
            out.push('"');
            out.push_str(arg);
            out.push('"');
        } else {
            out.push_str(arg);
        }
    }
    Some(out)
}

fn insert_detail(details: &mut BTreeMap<String, Value>, key: &str, val: Option<String>) {
    if let Some(v) = val {
        details.insert(key.to_string(), Value::String(v));
    }
}

struct SingleRecordFields {
    pid: Option<u64>,
    uid: Option<String>,
    auid: Option<String>,
    outer_exe: Option<String>,
    inner: BTreeMap<String, String>,
}

fn extract_single_fields(record: &ParsedRecord<'_>) -> SingleRecordFields {
    let mut out = SingleRecordFields {
        pid: None,
        uid: None,
        auid: None,
        outer_exe: None,
        inner: BTreeMap::new(),
    };
    let mut msg_body: Option<&str> = None;

    for f in &record.fields {
        match f.key {
            "pid" => out.pid = f.value.parse().ok(),
            "uid" => {
                if !is_absent_text(f.value) {
                    out.uid = Some(f.value.to_string());
                }
            }
            "auid" => {
                if !is_unset_id(f.value) {
                    out.auid = Some(f.value.to_string());
                }
            }
            "exe" => {
                let decoded = decode_field_value(f.key, f.value, f.quote);
                if !is_absent_text(&decoded) {
                    out.outer_exe = Some(decoded);
                }
            }
            "msg" => msg_body = Some(f.value),
            _ => {}
        }
    }

    if let Some(inner_str) = msg_body {
        for f in parse_fields(inner_str) {
            let decoded = decode_field_value(f.key, f.value, f.quote);
            out.inner.insert(f.key.to_string(), decoded);
        }
    }

    out
}

fn inner_non_absent(inner: &BTreeMap<String, String>, key: &str) -> Option<String> {
    inner.get(key).filter(|v| !is_absent_text(v)).cloned()
}

fn enriched_non_unset(record: &ParsedRecord<'_>, key: &str) -> Option<String> {
    record
        .enriched
        .get(key)
        .filter(|v| !is_unset_id(v))
        .cloned()
}

fn build_single_record_event(
    record: &ParsedRecord<'_>,
    options: &ReadOptions,
    file_label: &str,
) -> Option<TimelineEvent> {
    let parsed = extract_single_fields(record);
    let res = inner_non_absent(&parsed.inner, "res");

    let kind = match record.record_type {
        "USER_LOGIN" => match res.as_deref() {
            Some("success") => EventKind::LogonSuccess,
            Some("failed") => EventKind::LogonFailure,
            _ => return None,
        },
        "USER_AUTH" => match res.as_deref() {
            Some("failed") => EventKind::LogonFailure,
            _ => return None,
        },
        "USER_CMD" => EventKind::PrivilegedCommand,
        "ADD_USER" => EventKind::UserCreate,
        "SERVICE_START" => EventKind::ServiceStart,
        _ => return None,
    };

    let host = resolve_host(record.node.as_deref(), options);
    let mut event = TimelineEvent::new(
        ts_from_record(record),
        host,
        SourceKind::Auditd,
        kind,
        file_label,
    );
    event.provider = Some("auditd".to_string());
    event.channel = Some(record.record_type.to_string());
    event.record_id = Some(record.serial);
    event.process = inner_non_absent(&parsed.inner, "exe").or(parsed.outer_exe);
    event.pid = parsed.pid;

    match record.record_type {
        "USER_LOGIN" | "USER_AUTH" => {
            event.user = inner_non_absent(&parsed.inner, "acct")
                .or_else(|| enriched_non_unset(record, "ACCT"))
                .or_else(|| enriched_non_unset(record, "ID"))
                .or_else(|| {
                    parsed
                        .inner
                        .get("id")
                        .filter(|v| !is_unset_id(v))
                        .map(|id| format!("uid:{id}"))
                });
            event.src_ip = inner_non_absent(&parsed.inner, "addr");

            let terminal = inner_non_absent(&parsed.inner, "terminal");
            let hostname = inner_non_absent(&parsed.inner, "hostname");
            let op = inner_non_absent(&parsed.inner, "op");

            let is_ssh = terminal.as_deref() == Some("ssh")
                || event
                    .process
                    .as_deref()
                    .is_some_and(|p| p.ends_with("/sshd"));
            let user_label = event.user.as_deref().unwrap_or("unknown");
            let from_part = event
                .src_ip
                .as_deref()
                .map(|ip| format!(" from {ip}"))
                .unwrap_or_default();

            event.summary = match kind {
                EventKind::LogonSuccess => {
                    if is_ssh {
                        format!("SSH login for {user_label}{from_part}")
                    } else {
                        format!("Login for {user_label}{from_part}")
                    }
                }
                EventKind::LogonFailure => {
                    format!("Failed login for {user_label}{from_part}")
                }
                _ => String::new(),
            };

            insert_detail(&mut event.details, "terminal", terminal);
            insert_detail(&mut event.details, "hostname", hostname);
            insert_detail(&mut event.details, "op", op);
            insert_detail(&mut event.details, "result", res);
        }
        "USER_CMD" => {
            event.user = enriched_non_unset(record, "AUID")
                .or_else(|| enriched_non_unset(record, "UID"))
                .or_else(|| parsed.uid.as_deref().map(|u| format!("uid:{u}")))
                .or_else(|| parsed.auid.as_deref().map(|u| format!("uid:{u}")));
            event.command_line = inner_non_absent(&parsed.inner, "cmd");

            let cwd = inner_non_absent(&parsed.inner, "cwd");
            let terminal = inner_non_absent(&parsed.inner, "terminal");
            insert_detail(&mut event.details, "cwd", cwd);
            insert_detail(&mut event.details, "terminal", terminal);
            insert_detail(&mut event.details, "result", res);

            let user_label = event.user.as_deref().unwrap_or("unknown");
            let cmd_part = event
                .command_line
                .as_deref()
                .map(|c| format!(": {}", truncate_cmd(c, MAX_SUMMARY_CMD_CHARS)))
                .unwrap_or_default();
            event.summary = format!("sudo by {user_label}{cmd_part}");
        }
        "ADD_USER" => {
            event.target = inner_non_absent(&parsed.inner, "acct")
                .or_else(|| enriched_non_unset(record, "ACCT"))
                .or_else(|| enriched_non_unset(record, "ID"))
                .or_else(|| {
                    parsed
                        .inner
                        .get("id")
                        .filter(|v| !is_unset_id(v))
                        .map(|id| format!("uid:{id}"))
                });
            event.user = enriched_non_unset(record, "AUID")
                .or_else(|| enriched_non_unset(record, "UID"))
                .or_else(|| parsed.uid.as_deref().map(|u| format!("uid:{u}")))
                .or_else(|| parsed.auid.as_deref().map(|u| format!("uid:{u}")));

            insert_detail(&mut event.details, "result", res);

            let target_label = event.target.as_deref().unwrap_or("unknown");
            let user_label = event.user.as_deref().unwrap_or("unknown");
            event.summary = format!("User {target_label} created by {user_label}");
        }
        "SERVICE_START" => {
            event.target = inner_non_absent(&parsed.inner, "unit");
            let comm = inner_non_absent(&parsed.inner, "comm");

            insert_detail(&mut event.details, "comm", comm);
            insert_detail(&mut event.details, "result", res);

            let target_label = event.target.as_deref().unwrap_or("unknown");
            event.summary = format!("Service {target_label} started");
        }
        _ => return None,
    }

    Some(event)
}

fn ts_from_record(record: &ParsedRecord<'_>) -> Timestamp {
    record.ts
}

#[cfg(test)]
mod tests {
    #[test]
    fn events_without_eoe_are_flushed_and_none_is_lost() {
        use std::io::Write as _;

        let total = super::MAX_PENDING_EVENTS * 3;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        for serial in 0..total {
            writeln!(
                file,
                "type=SYSCALL msg=audit(1700000000.000:{serial}): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid={serial} auid=1000 uid=0 comm=\"id\" exe=\"/usr/bin/id\""
            )
            .unwrap();
            writeln!(
                file,
                "type=EXECVE msg=audit(1700000000.000:{serial}): argc=1 a0=\"id\""
            )
            .unwrap();
        }
        file.flush().unwrap();

        let mut events = Vec::new();
        let stats = super::AuditdSource
            .read(file.path(), &super::ReadOptions::default(), &mut events)
            .unwrap();
        assert_eq!(stats.errors, 0);
        assert_eq!(events.len(), total);
        assert!(
            events
                .iter()
                .all(|e| e.command_line.as_deref() == Some("id"))
        );
    }

    use std::io::Write;
    use std::path::PathBuf;

    use tempfile::NamedTempFile;

    use super::*;

    fn read_str(
        content: &str,
        options: &ReadOptions,
    ) -> anyhow::Result<(Vec<TimelineEvent>, SourceStats)> {
        let mut tmp = NamedTempFile::new()?;
        tmp.write_all(content.as_bytes())?;
        tmp.flush()?;
        let mut events = Vec::new();
        let stats = AuditdSource.read(tmp.path(), options, &mut events)?;
        Ok((events, stats))
    }

    #[test]
    fn parses_kv_with_double_single_and_unquoted_values() {
        let fields = parse_fields(
            r#"pid=1234 comm="cafe" msg='op=login acct="alice" addr=10.0.0.5' key="exec" unclosed="tail"#,
        );
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0].key, "pid");
        assert_eq!(fields[0].value, "1234");
        assert_eq!(fields[0].quote, QuoteKind::None);

        assert_eq!(fields[1].key, "comm");
        assert_eq!(fields[1].value, "cafe");
        assert_eq!(fields[1].quote, QuoteKind::Double);

        assert_eq!(fields[2].key, "msg");
        assert_eq!(fields[2].value, r#"op=login acct="alice" addr=10.0.0.5"#);
        assert_eq!(fields[2].quote, QuoteKind::Single);

        assert_eq!(fields[3].key, "key");
        assert_eq!(fields[3].value, "exec");
        assert_eq!(fields[3].quote, QuoteKind::Double);

        assert_eq!(fields[4].key, "unclosed");
        assert_eq!(fields[4].value, "tail");
        assert_eq!(fields[4].quote, QuoteKind::Double);
    }

    #[test]
    fn decodes_hex_only_for_allowed_unquoted_even_hex_keys() {
        // Allowed key, unquoted, even hex -> decoded.
        assert_eq!(
            decode_field_value("cmd", "2F7573722F62696E2F6964", QuoteKind::None),
            "/usr/bin/id"
        );
        assert_eq!(
            decode_field_value("a0", "6375726C", QuoteKind::None),
            "curl"
        );
        assert_eq!(decode_field_value("a12", "2D73", QuoteKind::None), "-s");
        assert_eq!(
            decode_field_value("exe", "2F62696E2F7368", QuoteKind::None),
            "/bin/sh"
        );
        assert_eq!(
            decode_field_value("cwd", "2F746D70", QuoteKind::None),
            "/tmp"
        );
        assert_eq!(
            decode_field_value("comm", "6D7920617070", QuoteKind::None),
            "my app"
        );
        assert_eq!(decode_field_value("name", "666F6F", QuoteKind::None), "foo");
        assert_eq!(
            decode_field_value("acct", "616C696365", QuoteKind::None),
            "alice"
        );

        // Quoted value is literal even if all hex digits.
        assert_eq!(
            decode_field_value("comm", "cafe", QuoteKind::Double),
            "cafe"
        );

        // Non-hex keys are never hex-decoded.
        assert_eq!(decode_field_value("pid", "1234", QuoteKind::None), "1234");
        assert_eq!(decode_field_value("uid", "1000", QuoteKind::None), "1000");

        // Odd number of hex digits is not decoded.
        assert_eq!(decode_field_value("a0", "12345", QuoteKind::None), "12345");

        // Invalid UTF-8 bytes are decoded lossily without error.
        assert_eq!(
            decode_field_value("a0", "FF61", QuoteKind::None),
            "\u{FFFD}a"
        );

        // Proctitle turns NUL separators into spaces and strips trailing NULs.
        assert_eq!(
            decode_proctitle("6375726C002D7300", QuoteKind::None),
            "curl -s"
        );
    }

    #[test]
    fn parses_inner_msg_list_and_login_variants() {
        let log = "\
type=USER_LOGIN msg=audit(1700000100.500:460): pid=900 uid=0 auid=4294967295 ses=4294967295 msg='op=login acct=\"alice\" exe=\"/usr/sbin/sshd\" hostname=? addr=10.0.0.5 terminal=ssh res=failed'
type=USER_LOGIN msg=audit(1700000105.000:461): pid=900 uid=0 auid=1000 ses=3 msg='op=login id=1000 exe=\"/usr/sbin/sshd\" hostname=workstation addr=10.0.0.5 terminal=ssh res=success'
type=USER_AUTH msg=audit(1700000106.000:462): pid=900 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:authentication acct=\"bob\" exe=\"/usr/sbin/sshd\" hostname=? addr=? terminal=ssh res=success'
";
        let (events, stats) = read_str(log, &ReadOptions::default()).unwrap();
        assert_eq!(stats.records_seen, 3);
        assert_eq!(stats.events_emitted, 2);
        assert_eq!(stats.errors, 0);

        assert_eq!(events[0].kind, EventKind::LogonFailure);
        assert_eq!(events[0].user.as_deref(), Some("alice"));
        assert_eq!(events[0].src_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(events[0].process.as_deref(), Some("/usr/sbin/sshd"));
        assert_eq!(events[0].pid, Some(900));
        assert_eq!(
            events[0].details.get("terminal"),
            Some(&Value::String("ssh".into()))
        );
        assert!(!events[0].details.contains_key("hostname"));
        assert_eq!(
            events[0].details.get("op"),
            Some(&Value::String("login".into()))
        );
        assert_eq!(
            events[0].details.get("result"),
            Some(&Value::String("failed".into()))
        );
        assert_eq!(events[0].summary, "Failed login for alice from 10.0.0.5");

        assert_eq!(events[1].kind, EventKind::LogonSuccess);
        assert_eq!(events[1].user.as_deref(), Some("uid:1000"));
        assert_eq!(
            events[1].details.get("hostname"),
            Some(&Value::String("workstation".into()))
        );
        assert_eq!(events[1].summary, "SSH login for uid:1000 from 10.0.0.5");
    }

    #[test]
    fn prefers_enriched_suffix_names_and_ignores_unset() {
        let log = "\
type=SYSCALL msg=audit(1700000000.123:10): arch=c000003e syscall=59 success=yes exit=0 ppid=1200 pid=1234 auid=4294967295 uid=0 euid=0 tty=pts0 ses=4294967295 comm=\"curl\" exe=\"/usr/bin/curl\" key=\"exec\"\x1dSYSCALL=execve AUID=\"unset\" UID=\"root\"
type=EOE msg=audit(1700000000.123:10):
type=USER_CMD msg=audit(1700000010.000:11): pid=2000 uid=0 auid=1000 ses=5 msg='cwd=\"/tmp\" cmd=2F7573722F62696E2F6964 terminal=pts/0 res=success'\x1dUID=\"root\" AUID=\"alice\"
type=ADD_USER msg=audit(1700000020.000:12): pid=2100 uid=0 auid=1000 ses=5 msg='op=adding user id=1001 exe=\"/usr/sbin/useradd\" hostname=? addr=? terminal=? res=success'\x1dAUID=\"alice\" UID=\"root\" ID=\"bob\"
";
        let (events, stats) = read_str(log, &ReadOptions::default()).unwrap();
        assert_eq!(stats.events_emitted, 3);

        assert_eq!(events[0].kind, EventKind::ProcessCreate);
        assert_eq!(events[0].user.as_deref(), Some("root"));
        assert!(!events[0].details.contains_key("auid"));
        assert!(!events[0].details.contains_key("session"));

        assert_eq!(events[1].kind, EventKind::PrivilegedCommand);
        assert_eq!(events[1].user.as_deref(), Some("alice"));
        assert_eq!(events[1].command_line.as_deref(), Some("/usr/bin/id"));
        assert_eq!(events[1].summary, "sudo by alice: /usr/bin/id");

        assert_eq!(events[2].kind, EventKind::UserCreate);
        assert_eq!(events[2].target.as_deref(), Some("bob"));
        assert_eq!(events[2].user.as_deref(), Some("alice"));
        assert_eq!(events[2].summary, "User bob created by alice");
    }

    #[test]
    fn reassembles_split_execve_arguments_before_decoding() {
        // "hello world" (68656C6C6F20776F726C64) split across a1[0] and a1[1],
        // and multi-byte UTF-8 "é" (C3A9) split across hex nibbles in a2[0]/a2[1].
        let log = "\
type=EXECVE msg=audit(1700000000.000:20): argc=3 a0=\"echo\" a1_len=22 a1[1]=6F20776F726C64 a1[0]=68656C6C a2_len=4 a2[0]=C3 a2[1]=A9
type=EOE msg=audit(1700000000.000:20):
";
        let (events, _) = read_str(log, &ReadOptions::default()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ProcessCreate);
        assert_eq!(events[0].channel.as_deref(), Some("EXECVE"));
        assert_eq!(
            events[0].command_line.as_deref(),
            Some("echo \"hello world\" é")
        );
    }

    #[test]
    fn handles_interleaved_events_and_pending_at_eof() {
        let log = "\
type=SYSCALL msg=audit(1700000000.100:1): arch=c000003e syscall=59 success=yes exit=0 ppid=100 pid=101 uid=0 comm=\"first\" exe=\"/bin/first\"
type=SYSCALL msg=audit(1700000000.200:2): arch=c000003e syscall=322 success=no exit=-2 ppid=100 pid=102 uid=1000 comm=\"second\" exe=\"/bin/second\"
type=EXECVE msg=audit(1700000000.100:1): argc=2 a0=\"/bin/first\" a1=\"--flag\"
type=PROCTITLE msg=audit(1700000000.200:2): proctitle=2F62696E2F7365636F6E6400617267
type=EOE msg=audit(1700000000.100:1):
";
        let (events, stats) = read_str(log, &ReadOptions::default()).unwrap();
        assert_eq!(stats.records_seen, 5);
        assert_eq!(stats.events_emitted, 2);

        // Event 1 emitted at EOE.
        assert_eq!(events[0].record_id, Some(1));
        assert_eq!(events[0].command_line.as_deref(), Some("/bin/first --flag"));
        assert_eq!(
            events[0].details.get("success"),
            Some(&Value::String("yes".into()))
        );

        // Event 2 had no EOE and no EXECVE, so it flushed at EOF using proctitle.
        assert_eq!(events[1].record_id, Some(2));
        assert_eq!(events[1].command_line.as_deref(), Some("/bin/second arg"));
        assert_eq!(
            events[1].details.get("success"),
            Some(&Value::String("no".into()))
        );
        assert_eq!(
            events[1].details.get("exit"),
            Some(&Value::String("-2".into()))
        );
    }

    #[test]
    fn resolves_node_host_and_host_fallback() {
        let log = "\
node=web01 type=SERVICE_START msg=audit(1700000000.000:30): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=nginx.service comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" res=success'
type=SERVICE_START msg=audit(1700000001.000:31): pid=1 uid=0 auid=4294967295 ses=4294967295 msg='unit=ssh.service comm=\"systemd\" exe=\"/usr/lib/systemd/systemd\" res=success'
";
        let opts_fallback = ReadOptions {
            host_fallback: Some("fallback-box".to_string()),
        };
        let (events_fb, _) = read_str(log, &opts_fallback).unwrap();
        assert_eq!(events_fb[0].host, "web01");
        assert_eq!(events_fb[1].host, "fallback-box");
        assert_eq!(events_fb[0].summary, "Service nginx.service started");

        let (events_none, _) = read_str(log, &ReadOptions::default()).unwrap();
        assert_eq!(events_none[0].host, "web01");
        assert_eq!(events_none[1].host, "unknown");
    }

    #[test]
    fn converts_timestamps_and_rejects_bad_timestamps() {
        let ts = parse_audit_timestamp("1700000000.123").unwrap();
        assert_eq!(ts, Timestamp::new(1_700_000_000, 123_000_000).unwrap());

        let ts_ms = parse_audit_timestamp("1700000000.005").unwrap();
        assert_eq!(ts_ms, Timestamp::new(1_700_000_000, 5_000_000).unwrap());

        assert!(parse_audit_timestamp("1700000000").is_none());
        assert!(parse_audit_timestamp("1700000000.").is_none());
        assert!(parse_audit_timestamp("notanumber.123").is_none());
        assert!(parse_audit_timestamp("1700000000.abc").is_none());
    }

    #[test]
    fn counts_garbage_lines_as_errors_and_tolerates_invalid_utf8() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"not an audit line\n").unwrap();
        tmp.write_all(b"type=SYSCALL msg=audit(bad:1): pid=1\n")
            .unwrap();
        // Invalid UTF-8 inside a valid record
        tmp.write_all(b"type=USER_CMD msg=audit(1700000000.000:50): pid=10 uid=1000 msg='cmd=\"bad\xFFutf8\" res=success'\n").unwrap();
        tmp.flush().unwrap();

        let mut events = Vec::new();
        let stats = AuditdSource
            .read(tmp.path(), &ReadOptions::default(), &mut events)
            .unwrap();
        assert_eq!(stats.records_seen, 3);
        assert_eq!(stats.errors, 2);
        assert_eq!(stats.events_emitted, 1);
        assert_eq!(events[0].command_line.as_deref(), Some("bad\u{FFFD}utf8"));
    }

    #[test]
    fn truncates_long_commands_in_summary_on_char_boundary() {
        let long_arg = "é".repeat(250);
        let log = format!(
            "type=EXECVE msg=audit(1700000000.000:60): argc=1 a0=\"{long_arg}\"\n\
             type=EOE msg=audit(1700000000.000:60):\n"
        );
        let (events, _) = read_str(&log, &ReadOptions::default()).unwrap();
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.ends_with("..."));
        // Prefix after ": " is 200 'é' chars + "...".
        let after_colon = events[0].summary.split_once(": ").unwrap().1;
        assert_eq!(after_colon.chars().count(), 203);
    }

    #[test]
    fn handles_named_execve_syscall_and_missing_file_error() {
        let log = "\
type=SYSCALL msg=audit(1700000000.000:70): arch=c000003e syscall=execve success=yes exit=0 ppid=10 pid=20 uid=0 comm=\"sh\" exe=\"/bin/sh\"
type=CWD msg=audit(1700000000.000:70): cwd=\"/root\"
type=PROCTITLE msg=audit(1700000000.000:70): proctitle=2F62696E2F7368002D63006964
type=EOE msg=audit(1700000000.000:70):
";
        let (events, _) = read_str(log, &ReadOptions::default()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::ProcessCreate);
        assert_eq!(events[0].command_line.as_deref(), Some("/bin/sh -c id"));
        assert_eq!(
            events[0].details.get("cwd"),
            Some(&Value::String("/root".into()))
        );

        let missing = PathBuf::from("/nonexistent/path/to/audit.log");
        let mut out = Vec::new();
        assert!(
            AuditdSource
                .read(&missing, &ReadOptions::default(), &mut out)
                .is_err()
        );
    }

    #[test]
    fn reads_linux_audit_fixture_with_exact_event_counts() {
        let fixture =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/linux/audit.log");
        let raw_bytes = std::fs::read(&fixture).unwrap();
        assert!(
            raw_bytes.contains(&0x1d),
            "fixture must include a 0x1d enriched separator byte"
        );

        let mut events = Vec::new();
        let opts = ReadOptions {
            host_fallback: Some("linux-host".to_string()),
        };
        let stats = AuditdSource.read(&fixture, &opts, &mut events).unwrap();

        assert_eq!(stats.records_seen, 48);
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.events_emitted, 14);
        assert_eq!(events.len(), 14);

        let count = |kind: EventKind| events.iter().filter(|e| e.kind == kind).count();
        assert_eq!(count(EventKind::LogonFailure), 5);
        assert_eq!(count(EventKind::LogonSuccess), 1);
        assert_eq!(count(EventKind::PrivilegedCommand), 1);
        assert_eq!(count(EventKind::ProcessCreate), 5);
        assert_eq!(count(EventKind::UserCreate), 1);
        assert_eq!(count(EventKind::ServiceStart), 1);

        // Verify enriched sudo command.
        let sudo = events
            .iter()
            .find(|e| e.kind == EventKind::PrivilegedCommand)
            .unwrap();
        assert_eq!(sudo.user.as_deref(), Some("alice"));
        assert_eq!(sudo.command_line.as_deref(), Some("/usr/bin/id"));

        // Verify /tmp/x.sh execution with hex-decoded space argument wrapped in quotes.
        let x_sh = events
            .iter()
            .find(|e| {
                e.kind == EventKind::ProcessCreate
                    && e.command_line
                        .as_deref()
                        .is_some_and(|c| c.contains("/tmp/x.sh \"secret payload\""))
            })
            .unwrap();
        assert_eq!(x_sh.process.as_deref(), Some("/bin/bash"));
        assert_eq!(x_sh.host, "linux-host");
    }
}
