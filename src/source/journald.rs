//! Reader for systemd journal JSON exports (`journalctl -o json`).

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::LazyLock;

use jiff::Timestamp;
use regex::Regex;
use serde_json::{Map, Value};

use crate::model::{EventKind, SourceKind, TimelineEvent};
use crate::source::{ReadOptions, Source, SourceStats};

const SUMMARY_CMD_MAX_CHARS: usize = 200;

static RE_SSHD_ACCEPTED: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+) ssh2\b").ok());
static RE_SSHD_FAILED: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^Failed (\S+) for (invalid user )?(.*) from (\S+) port (\d+) ssh2\b").ok()
});
static RE_SSHD_INVALID_USER: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^Invalid user (.*) from (\S+) port (\d+)(?:\s|$)").ok());
static RE_SU: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
        r"^pam_unix\(su(?:-l)?:session\): session opened for user ([^\s(]+)(?:\(uid=\d+\))? by ([^\s(]+)(?:\(uid=\d+\))?(?:\s|$)",
    )
    .ok()
});
static RE_USERADD: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"^new user: name=([^,]+), UID=(\d+), GID=(\d+), home=([^,]+), shell=([^\s,]+)").ok()
});
static RE_LOGIND: LazyLock<Option<Regex>> =
    LazyLock::new(|| Regex::new(r"^New session (\S+) of user (.+)\.$").ok());

pub struct JournaldSource;

impl Source for JournaldSource {
    fn read(
        &self,
        path: &Path,
        options: &ReadOptions,
        out: &mut Vec<TimelineEvent>,
    ) -> anyhow::Result<SourceStats> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);
        let mut stats = SourceStats::default();
        let mut buf = Vec::new();
        let file_label = path.to_string_lossy().into_owned();

        loop {
            buf.clear();
            let n = reader.read_until(b'\n', &mut buf)?;
            if n == 0 {
                break;
            }
            let line = trim_ascii_bytes(&buf);
            if line.is_empty() {
                continue;
            }
            stats.records_seen += 1;

            let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(line) else {
                stats.errors += 1;
                continue;
            };

            let Some(ts) = parse_timestamp(&map) else {
                stats.errors += 1;
                continue;
            };

            let Some(message) = extract_message(&map) else {
                continue;
            };

            if let Some(event) = build_event(&map, ts, message, options, &file_label) {
                out.push(event);
                stats.events_emitted += 1;
            }
        }

        Ok(stats)
    }
}

fn trim_ascii_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

fn parse_timestamp(map: &Map<String, Value>) -> Option<Timestamp> {
    let raw = map.get("__REALTIME_TIMESTAMP")?.as_str()?;
    let micros = raw.parse::<i64>().ok()?;
    Timestamp::from_microsecond(micros).ok()
}

fn extract_message(map: &Map<String, Value>) -> Option<String> {
    match map.get("MESSAGE")? {
        Value::String(s) => Some(s.clone()),
        Value::Array(arr) => {
            // journalctl encodes non-UTF-8 field values as arrays of byte integers.
            let bytes = arr
                .iter()
                .map(|v| v.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect::<Option<Vec<u8>>>()?;
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

fn get_non_empty_str<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    match map.get(key)? {
        Value::String(s) if !s.is_empty() => Some(s.as_str()),
        Value::Array(arr) => arr
            .first()
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty()),
        _ => None,
    }
}

fn get_u64(map: &Map<String, Value>, key: &str) -> Option<u64> {
    match map.get(key)? {
        Value::String(s) => s.parse::<u64>().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn parse_u64_or_str(s: &str) -> Value {
    s.parse::<u64>()
        .map(Value::from)
        .unwrap_or_else(|_| Value::String(s.to_string()))
}

fn truncate_one_line(s: &str, max_chars: usize) -> String {
    let single_line = s.replace(['\r', '\n'], " ");
    if single_line.chars().count() <= max_chars {
        return single_line;
    }
    let end = single_line
        .char_indices()
        .nth(max_chars)
        .map_or(single_line.len(), |(idx, _)| idx);
    format!("{}...", &single_line[..end])
}

fn build_event(
    map: &Map<String, Value>,
    ts: Timestamp,
    message: String,
    options: &ReadOptions,
    file_label: &str,
) -> Option<TimelineEvent> {
    let program =
        get_non_empty_str(map, "SYSLOG_IDENTIFIER").or_else(|| get_non_empty_str(map, "_COMM"));
    let host = get_non_empty_str(map, "_HOSTNAME")
        .map(str::to_owned)
        .or_else(|| options.host_fallback.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let mut event = match program {
        Some("sshd" | "sshd-session") => match_sshd(ts, &host, file_label, &message),
        Some("sudo") => match_sudo(ts, &host, file_label, &message),
        Some("useradd") => match_useradd(ts, &host, file_label, &message),
        Some("systemd-logind") => match_logind(ts, &host, file_label, &message),
        _ => None,
    };

    if event.is_none() {
        event = match_su(ts, &host, file_label, &message);
    }

    if event.is_none() {
        event = match_unit_start(map, ts, &host, file_label);
    }

    let mut event = event?;
    event.channel = program.map(str::to_owned);
    event.provider = Some("journald".to_string());
    event.process = get_non_empty_str(map, "_EXE").map(str::to_owned);
    event.pid = get_u64(map, "_PID").or_else(|| get_u64(map, "SYSLOG_PID"));
    event
        .details
        .insert("message".to_string(), Value::String(message));
    if let Some(unit) = get_non_empty_str(map, "_SYSTEMD_UNIT") {
        event
            .details
            .insert("unit".to_string(), Value::String(unit.to_string()));
    }

    Some(event)
}

fn match_sshd(ts: Timestamp, host: &str, file: &str, message: &str) -> Option<TimelineEvent> {
    if let Some(caps) = RE_SSHD_ACCEPTED
        .as_ref()
        .and_then(|re| re.captures(message))
    {
        let method = caps.get(1)?.as_str();
        let user = caps.get(2)?.as_str();
        let ip = caps.get(3)?.as_str();
        let port = caps.get(4)?.as_str();

        let mut ev = TimelineEvent::new(
            ts,
            host,
            SourceKind::Journald,
            EventKind::LogonSuccess,
            file,
        );
        ev.user = Some(user.to_string());
        ev.src_ip = Some(ip.to_string());
        ev.details
            .insert("auth_method".to_string(), Value::String(method.to_string()));
        ev.details
            .insert("src_port".to_string(), parse_u64_or_str(port));
        ev.summary = format!("SSH login for {user} from {ip} ({method})");
        return Some(ev);
    }

    if let Some(caps) = RE_SSHD_FAILED.as_ref().and_then(|re| re.captures(message)) {
        let method = caps.get(1)?.as_str();
        let invalid = caps.get(2).is_some();
        let user = caps.get(3)?.as_str();
        let ip = caps.get(4)?.as_str();
        let port = caps.get(5)?.as_str();

        let mut ev = TimelineEvent::new(
            ts,
            host,
            SourceKind::Journald,
            EventKind::LogonFailure,
            file,
        );
        ev.user = Some(user.to_string());
        ev.src_ip = Some(ip.to_string());
        ev.details
            .insert("auth_method".to_string(), Value::String(method.to_string()));
        ev.details
            .insert("src_port".to_string(), parse_u64_or_str(port));
        if invalid {
            ev.details
                .insert("invalid_user".to_string(), Value::Bool(true));
            ev.summary = format!("Failed SSH login for invalid user {user} from {ip}");
        } else {
            ev.summary = format!("Failed SSH login for {user} from {ip}");
        }
        return Some(ev);
    }

    if let Some(caps) = RE_SSHD_INVALID_USER
        .as_ref()
        .and_then(|re| re.captures(message))
    {
        let user = caps.get(1)?.as_str();
        let ip = caps.get(2)?.as_str();
        let port = caps.get(3)?.as_str();

        let mut ev = TimelineEvent::new(
            ts,
            host,
            SourceKind::Journald,
            EventKind::LogonFailure,
            file,
        );
        ev.user = Some(user.to_string());
        ev.src_ip = Some(ip.to_string());
        ev.details
            .insert("invalid_user".to_string(), Value::Bool(true));
        ev.details
            .insert("src_port".to_string(), parse_u64_or_str(port));
        ev.summary = format!("Failed SSH login for invalid user {user} from {ip}");
        return Some(ev);
    }

    None
}

struct SudoLine<'a> {
    user: &'a str,
    problem: Option<&'a str>,
    tty: Option<&'a str>,
    cwd: Option<&'a str>,
    run_as: Option<&'a str>,
    command: &'a str,
}

/// Parses `user : [problem ; ]TTY=.. ; PWD=.. ; USER=.. ; COMMAND=..`.
///
/// Done by hand because every field but the command is optional in real
/// logs: a sudo run without a terminal has no `TTY=`, and a refused one puts
/// free text ("a password is required") where a field would be.
fn parse_sudo(message: &str) -> Option<SudoLine<'_>> {
    let (user, rest) = message.trim_start().split_once(" : ")?;
    let user = user.trim();
    if user.is_empty() || user.contains(char::is_whitespace) {
        return None;
    }
    // COMMAND= is the last field, and the command itself may contain " ; ".
    let (head, command) = match rest.strip_prefix("COMMAND=") {
        Some(command) => ("", command),
        None => rest.split_once(" ; COMMAND=")?,
    };

    let mut line = SudoLine {
        user,
        problem: None,
        tty: None,
        cwd: None,
        run_as: None,
        command,
    };
    for segment in head.split(" ; ").map(str::trim) {
        if let Some(value) = segment.strip_prefix("TTY=") {
            line.tty = Some(value);
        } else if let Some(value) = segment.strip_prefix("PWD=") {
            line.cwd = Some(value);
        } else if let Some(value) = segment.strip_prefix("USER=") {
            line.run_as = Some(value);
        } else if is_sudo_field(segment) {
            // GROUP=, TSID=, ENV= and similar: not used.
        } else if !segment.is_empty() && line.problem.is_none() {
            line.problem = Some(segment);
        }
    }
    Some(line)
}

fn is_sudo_field(segment: &str) -> bool {
    segment.split_once('=').is_some_and(|(key, _)| {
        !key.is_empty() && key.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
    })
}

fn match_sudo(ts: Timestamp, host: &str, file: &str, message: &str) -> Option<TimelineEvent> {
    let line = parse_sudo(message)?;

    let mut ev = TimelineEvent::new(
        ts,
        host,
        SourceKind::Journald,
        EventKind::PrivilegedCommand,
        file,
    );
    ev.user = Some(line.user.to_string());
    ev.command_line = Some(line.command.to_string());
    for (key, value) in [
        ("tty", line.tty),
        ("cwd", line.cwd),
        ("run_as", line.run_as),
        ("problem", line.problem),
    ] {
        if let Some(value) = value {
            ev.details
                .insert(key.to_string(), Value::String(value.to_string()));
        }
    }

    let user = line.user;
    let as_user = line
        .run_as
        .map(|run_as| format!(" as {run_as}"))
        .unwrap_or_default();
    let cmd_short = truncate_one_line(line.command, SUMMARY_CMD_MAX_CHARS);
    ev.summary = match line.problem {
        Some(problem) => format!("sudo by {user}{as_user} failed ({problem}): {cmd_short}"),
        None => format!("sudo by {user}{as_user}: {cmd_short}"),
    };

    Some(ev)
}

fn match_su(ts: Timestamp, host: &str, file: &str, message: &str) -> Option<TimelineEvent> {
    let caps = RE_SU.as_ref()?.captures(message)?;
    let target = caps.get(1)?.as_str();
    let user = caps.get(2)?.as_str();

    let mut ev = TimelineEvent::new(
        ts,
        host,
        SourceKind::Journald,
        EventKind::PrivilegedCommand,
        file,
    );
    ev.user = Some(user.to_string());
    ev.target = Some(target.to_string());
    ev.command_line = Some(format!("su {target}"));
    ev.summary = format!("su to {target} by {user}");
    Some(ev)
}

fn match_useradd(ts: Timestamp, host: &str, file: &str, message: &str) -> Option<TimelineEvent> {
    let caps = RE_USERADD.as_ref()?.captures(message)?;
    let name = caps.get(1)?.as_str();
    let uid = caps.get(2)?.as_str();
    let gid = caps.get(3)?.as_str();
    let home = caps.get(4)?.as_str();
    let shell = caps.get(5)?.as_str();

    let mut ev = TimelineEvent::new(ts, host, SourceKind::Journald, EventKind::UserCreate, file);
    ev.target = Some(name.to_string());
    ev.details.insert("uid".to_string(), parse_u64_or_str(uid));
    ev.details.insert("gid".to_string(), parse_u64_or_str(gid));
    ev.details
        .insert("home".to_string(), Value::String(home.to_string()));
    ev.details
        .insert("shell".to_string(), Value::String(shell.to_string()));
    ev.summary = format!("User {name} created");
    Some(ev)
}

fn match_logind(ts: Timestamp, host: &str, file: &str, message: &str) -> Option<TimelineEvent> {
    let caps = RE_LOGIND.as_ref()?.captures(message)?;
    let session = caps.get(1)?.as_str();
    let user = caps.get(2)?.as_str();

    let mut ev = TimelineEvent::new(
        ts,
        host,
        SourceKind::Journald,
        EventKind::LogonSuccess,
        file,
    );
    ev.user = Some(user.to_string());
    ev.details
        .insert("session".to_string(), Value::String(session.to_string()));
    ev.summary = format!("Session {session} opened for {user}");
    Some(ev)
}

fn match_unit_start(
    map: &Map<String, Value>,
    ts: Timestamp,
    host: &str,
    file: &str,
) -> Option<TimelineEvent> {
    let job_type = get_non_empty_str(map, "JOB_TYPE")?;
    let job_result = get_non_empty_str(map, "JOB_RESULT")?;
    let unit = get_non_empty_str(map, "UNIT")?;
    if job_type != "start" || job_result != "done" || !unit.ends_with(".service") {
        return None;
    }

    let mut ev = TimelineEvent::new(
        ts,
        host,
        SourceKind::Journald,
        EventKind::ServiceStart,
        file,
    );
    ev.target = Some(unit.to_string());
    ev.summary = format!("Service {unit} started");
    Some(ev)
}

#[cfg(test)]
mod tests {
    #[test]
    fn sudo_without_tty_and_with_spaces_in_the_directory() {
        let line = super::parse_sudo(
            "   kripi : a password is required ; PWD=/home/kripi/my notes ; USER=root ; COMMAND=/usr/bin/pacman -Syu",
        )
        .unwrap();
        assert_eq!(line.user, "kripi");
        assert_eq!(line.problem, Some("a password is required"));
        assert_eq!(line.tty, None);
        assert_eq!(line.cwd, Some("/home/kripi/my notes"));
        assert_eq!(line.run_as, Some("root"));
        assert_eq!(line.command, "/usr/bin/pacman -Syu");
    }

    #[test]
    fn sudo_tty_is_not_mistaken_for_a_problem() {
        let line = super::parse_sudo(
            "alice : TTY=pts/6 ; PWD=/srv ; USER=root ; TSID=00000A ; COMMAND=/bin/sh -c 'a ; COMMAND=b'",
        )
        .unwrap();
        assert_eq!(line.problem, None);
        assert_eq!(line.tty, Some("pts/6"));
        assert_eq!(line.command, "/bin/sh -c 'a ; COMMAND=b'");
    }

    #[test]
    fn sudo_pam_session_lines_are_not_commands() {
        assert!(
            super::parse_sudo("pam_unix(sudo:session): session closed for user root").is_none()
        );
    }

    use super::*;
    use crate::source::{Format, detect_format};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn read_lines(lines: &[&str], options: &ReadOptions) -> (Vec<TimelineEvent>, SourceStats) {
        let mut tmp = NamedTempFile::new().unwrap();
        for line in lines {
            writeln!(tmp, "{line}").unwrap();
        }
        tmp.flush().unwrap();
        let mut out = Vec::new();
        let stats = JournaldSource.read(tmp.path(), options, &mut out).unwrap();
        (out, stats)
    }

    #[test]
    fn regexes_compile() {
        assert!(RE_SSHD_ACCEPTED.is_some());
        assert!(RE_SSHD_FAILED.is_some());
        assert!(RE_SSHD_INVALID_USER.is_some());
        assert!(RE_SU.is_some());
        assert!(RE_USERADD.is_some());
        assert!(RE_LOGIND.is_some());
    }

    #[test]
    fn sshd_accepted_ipv6_and_sshd_session() {
        let line = r#"{"__REALTIME_TIMESTAMP":"1700000000000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd-session","_EXE":"/usr/libexec/sshd-session","_PID":"2001","_SYSTEMD_UNIT":"ssh.service","MESSAGE":"Accepted publickey for alice from 2001:db8::1 port 54321 ssh2: ED25519 SHA256:abc"}"#;
        let (events, stats) = read_lines(&[line], &ReadOptions::default());
        assert_eq!(stats.records_seen, 1);
        assert_eq!(stats.events_emitted, 1);
        assert_eq!(stats.errors, 0);

        let ev = &events[0];
        assert_eq!(ev.kind, EventKind::LogonSuccess);
        assert_eq!(ev.source, SourceKind::Journald);
        assert_eq!(ev.provider.as_deref(), Some("journald"));
        assert_eq!(ev.channel.as_deref(), Some("sshd-session"));
        assert_eq!(ev.process.as_deref(), Some("/usr/libexec/sshd-session"));
        assert_eq!(ev.pid, Some(2001));
        assert_eq!(ev.user.as_deref(), Some("alice"));
        assert_eq!(ev.src_ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(ev.details["auth_method"], "publickey");
        assert_eq!(ev.details["src_port"], 54321);
        assert_eq!(ev.details["unit"], "ssh.service");
        assert_eq!(
            ev.summary,
            "SSH login for alice from 2001:db8::1 (publickey)"
        );
    }

    #[test]
    fn sshd_failed_valid_and_invalid_user() {
        let lines = [
            r#"{"__REALTIME_TIMESTAMP":"1700000001000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for alice from 10.0.0.5 port 40001 ssh2"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1700000002000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Failed password for invalid user admin from 10.0.0.5 port 40002 ssh2"}"#,
        ];
        let (events, _) = read_lines(&lines, &ReadOptions::default());
        assert_eq!(events.len(), 2);

        assert_eq!(events[0].kind, EventKind::LogonFailure);
        assert_eq!(events[0].user.as_deref(), Some("alice"));
        assert!(!events[0].details.contains_key("invalid_user"));
        assert_eq!(
            events[0].summary,
            "Failed SSH login for alice from 10.0.0.5"
        );

        assert_eq!(events[1].kind, EventKind::LogonFailure);
        assert_eq!(events[1].user.as_deref(), Some("admin"));
        assert_eq!(events[1].details["invalid_user"], true);
        assert_eq!(
            events[1].summary,
            "Failed SSH login for invalid user admin from 10.0.0.5"
        );
    }

    #[test]
    fn sshd_invalid_user_with_spaces_and_empty() {
        let lines = [
            r#"{"__REALTIME_TIMESTAMP":"1700000001000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Invalid user john from doe from 10.0.0.5 port 40003"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1700000002000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Invalid user  from 10.0.0.5 port 40004"}"#,
        ];
        let (events, _) = read_lines(&lines, &ReadOptions::default());
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].user.as_deref(), Some("john from doe"));
        assert_eq!(events[0].details["invalid_user"], true);
        assert_eq!(events[0].details["src_port"], 40003);

        assert_eq!(events[1].user.as_deref(), Some(""));
        assert_eq!(events[1].details["invalid_user"], true);
        assert_eq!(events[1].details["src_port"], 40004);
    }

    #[test]
    fn sudo_with_problem_and_command_special_chars() {
        let long_arg = "a".repeat(220);
        let line_ok = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1700000001000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/sh -c echo x=1 ; {long_arg}"}}"#
        );
        let line_err = r#"{"__REALTIME_TIMESTAMP":"1700000002000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sudo","MESSAGE":"   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"}"#;
        let (events, _) = read_lines(&[&line_ok, line_err], &ReadOptions::default());
        assert_eq!(events.len(), 2);

        let ev0 = &events[0];
        assert_eq!(ev0.kind, EventKind::PrivilegedCommand);
        assert_eq!(ev0.user.as_deref(), Some("alice"));
        assert_eq!(
            ev0.command_line.as_deref(),
            Some(format!("/bin/sh -c echo x=1 ; {long_arg}").as_str())
        );
        assert_eq!(ev0.details["tty"], "pts/0");
        assert_eq!(ev0.details["cwd"], "/home/alice");
        assert_eq!(ev0.details["run_as"], "root");
        assert!(!ev0.details.contains_key("problem"));
        assert!(ev0.summary.ends_with("..."));
        assert!(ev0.summary.len() < 260);

        let ev1 = &events[1];
        assert_eq!(ev1.details["problem"], "3 incorrect password attempts");
        assert_eq!(
            ev1.summary,
            "sudo by alice as root failed (3 incorrect password attempts): /usr/bin/id"
        );
    }

    #[test]
    fn su_variants() {
        let lines = [
            r#"{"__REALTIME_TIMESTAMP":"1700000001000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"su","MESSAGE":"pam_unix(su:session): session opened for user root(uid=0) by alice(uid=1000)"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1700000002000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"su-l","MESSAGE":"pam_unix(su-l:session): session opened for user deploy by bob"}"#,
        ];
        let (events, _) = read_lines(&lines, &ReadOptions::default());
        assert_eq!(events.len(), 2);

        assert_eq!(events[0].kind, EventKind::PrivilegedCommand);
        assert_eq!(events[0].user.as_deref(), Some("alice"));
        assert_eq!(events[0].target.as_deref(), Some("root"));
        assert_eq!(events[0].command_line.as_deref(), Some("su root"));
        assert_eq!(events[0].summary, "su to root by alice");

        assert_eq!(events[1].user.as_deref(), Some("bob"));
        assert_eq!(events[1].target.as_deref(), Some("deploy"));
        assert_eq!(events[1].command_line.as_deref(), Some("su deploy"));
    }

    #[test]
    fn useradd_and_logind_and_unit_start() {
        let lines = [
            r#"{"__REALTIME_TIMESTAMP":"1700000001000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"useradd","MESSAGE":"new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash"}"#,
            r#"{"__REALTIME_TIMESTAMP":"1700000002000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"systemd-logind","MESSAGE":"New session 12 of user alice."}"#,
            r#"{"__REALTIME_TIMESTAMP":"1700000003000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"systemd","UNIT":"nginx.service","JOB_TYPE":"start","JOB_RESULT":"done","MESSAGE":"Started nginx.service."}"#,
        ];
        let (events, _) = read_lines(&lines, &ReadOptions::default());
        assert_eq!(events.len(), 3);

        assert_eq!(events[0].kind, EventKind::UserCreate);
        assert_eq!(events[0].target.as_deref(), Some("backdoor"));
        assert_eq!(events[0].details["uid"], 1001);
        assert_eq!(events[0].details["gid"], 1001);
        assert_eq!(events[0].details["home"], "/home/backdoor");
        assert_eq!(events[0].details["shell"], "/bin/bash");
        assert_eq!(events[0].summary, "User backdoor created");

        assert_eq!(events[1].kind, EventKind::LogonSuccess);
        assert_eq!(events[1].user.as_deref(), Some("alice"));
        assert_eq!(events[1].details["session"], "12");
        assert_eq!(events[1].summary, "Session 12 opened for alice");

        assert_eq!(events[2].kind, EventKind::ServiceStart);
        assert_eq!(events[2].target.as_deref(), Some("nginx.service"));
        assert_eq!(events[2].summary, "Service nginx.service started");
    }

    #[test]
    fn message_byte_array_and_null_and_errors_and_host_fallback() {
        // "New session 9 of user bob." + trailing invalid UTF-8 byte 0xff
        let mut msg_bytes: Vec<u8> = b"New session 9 of user bob.".to_vec();
        msg_bytes.push(0xff);
        let bytes_json = serde_json::to_string(&msg_bytes).unwrap();
        let line_bytes = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1700000001000000","_COMM":"systemd-logind","SYSLOG_PID":"500","MESSAGE":{bytes_json}}}"#
        );
        // Same valid message as byte array without trailing garbage to verify match:
        let clean_bytes_json =
            serde_json::to_string(&b"New session 9 of user bob.".to_vec()).unwrap();
        let line_clean_bytes = format!(
            r#"{{"__REALTIME_TIMESTAMP":"1700000001500000","_COMM":"systemd-logind","SYSLOG_PID":"500","MESSAGE":{clean_bytes_json}}}"#
        );
        let line_null = r#"{"__REALTIME_TIMESTAMP":"1700000002000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":null}"#;
        let line_missing_ts = r#"{"_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for alice from 10.0.0.5 port 22 ssh2"}"#;
        let line_bad_ts = r#"{"__REALTIME_TIMESTAMP":"not-a-number","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Accepted password for alice from 10.0.0.5 port 22 ssh2"}"#;
        let line_not_json = "not json";
        let line_json_array = "[1, 2, 3]";

        let opts = ReadOptions {
            host_fallback: Some("fallback-host".to_string()),
        };
        let (events, stats) = read_lines(
            &[
                "",
                &line_bytes,
                &line_clean_bytes,
                line_null,
                line_missing_ts,
                line_bad_ts,
                line_not_json,
                line_json_array,
            ],
            &opts,
        );

        assert_eq!(stats.records_seen, 7);
        assert_eq!(stats.errors, 4);
        assert_eq!(stats.events_emitted, 1);
        assert_eq!(events[0].host, "fallback-host");
        assert_eq!(events[0].channel.as_deref(), Some("systemd-logind"));
        assert_eq!(events[0].pid, Some(500));

        // Without host_fallback, defaults to "unknown".
        let (events2, _) = read_lines(&[&line_clean_bytes], &ReadOptions::default());
        assert_eq!(events2[0].host, "unknown");
    }

    #[test]
    fn reads_fixture_and_detects_format() {
        let path = Path::new("tests/fixtures/linux/journald.json");
        assert_eq!(detect_format(path).unwrap(), Some(Format::Journald));

        let mut events = Vec::new();
        let stats = JournaldSource
            .read(path, &ReadOptions::default(), &mut events)
            .unwrap();

        assert_eq!(stats.records_seen, 40);
        assert_eq!(stats.errors, 1);
        assert_eq!(stats.events_emitted, 14);
        assert_eq!(events.len(), 14);

        let count = |kind: EventKind| events.iter().filter(|e| e.kind == kind).count();
        assert_eq!(count(EventKind::LogonFailure), 7);
        assert_eq!(count(EventKind::LogonSuccess), 2);
        assert_eq!(count(EventKind::PrivilegedCommand), 3);
        assert_eq!(count(EventKind::UserCreate), 1);
        assert_eq!(count(EventKind::ServiceStart), 1);
    }
}
