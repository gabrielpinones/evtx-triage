//! End-to-end tests of `evtx-triage timeline` against the fixture logs.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output};

use serde_json::Value;

fn fixtures(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(sub)
}

fn timeline(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evtx-triage"))
        .arg("timeline")
        .args(args)
        .output()
        .expect("the binary runs")
}

fn parse_jsonl(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8(stdout.to_vec())
        .expect("output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line is a JSON object"))
        .collect()
}

fn rules(events: &[Value]) -> Vec<&str> {
    events
        .iter()
        .flat_map(|event| event["flags"].as_array().into_iter().flatten())
        .filter_map(|flag| flag["rule"].as_str())
        .collect()
}

fn golden_windows_events() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/windows.jsonl");
    let bytes = std::fs::read(&path).expect("golden windows.jsonl exists");
    parse_jsonl(&bytes)
}

fn rule_count(events: &[Value], rule: &str) -> usize {
    rules(events).into_iter().filter(|r| *r == rule).count()
}

#[test]
fn windows_samples_give_a_sorted_timeline_with_all_ten_event_types() {
    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let golden = golden_windows_events();
    let expected_total = golden.len();
    let events = parse_jsonl(&output.stdout);
    assert_eq!(events.len(), expected_total);

    let times: Vec<&str> = events.iter().map(|e| e["ts"].as_str().unwrap()).collect();
    assert!(times.is_sorted(), "timeline is ordered by time");
    assert!(times[0] > "2018-01-01", "no event is left in 1601");

    // Sysmon 1 and Security 4688 are both process creations; the other eight
    // baseline ids map to one kind each, plus any newly added event types in golden.
    let ids: BTreeSet<u64> = events
        .iter()
        .map(|e| e["event_id"].as_u64().unwrap())
        .collect();
    let expected_ids: BTreeSet<u64> = golden
        .iter()
        .map(|e| e["event_id"].as_u64().unwrap())
        .collect();
    assert_eq!(ids, expected_ids);
    assert!(
        ids.is_superset(&BTreeSet::from([
            1, 1102, 4104, 4624, 4625, 4648, 4688, 4698, 4720, 7045,
        ])),
        "baseline event IDs missing: {ids:?}"
    );
    for event in &events {
        assert_eq!(event["source"], "evtx");
        assert!(!event["summary"].as_str().unwrap().is_empty());
        assert!(!event["host"].as_str().unwrap().is_empty());
    }

    assert_eq!(
        rule_count(&events, "log_cleared"),
        rule_count(&golden, "log_cleared")
    );
    assert!(rule_count(&events, "encoded_powershell") >= 4);
    assert_eq!(
        rule_count(&events, "service_suspicious_path"),
        rule_count(&golden, "service_suspicious_path")
    );

    let summary = String::from_utf8_lossy(&output.stderr);
    let expected_summary_count = format!("{expected_total} events");
    assert!(
        summary.contains(&expected_summary_count),
        "summary goes to stderr: {summary}"
    );
}

#[test]
fn csv_has_one_row_per_event() {
    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap(), "--format", "csv"]);
    assert_eq!(output.status.code(), Some(0));

    let mut reader = csv::Reader::from_reader(output.stdout.as_slice());
    let headers = reader.headers().unwrap().clone();
    assert_eq!(&headers[0], "ts");
    assert!(headers.iter().any(|h| h == "flags"));
    let rows: Vec<csv::StringRecord> = reader.records().map(Result::unwrap).collect();
    assert_eq!(rows.len(), golden_windows_events().len());
    assert!(rows.iter().all(|row| row.len() == headers.len()));
}

#[test]
fn event_id_filter_and_flagged_only() {
    let golden = golden_windows_events();
    let expected_service_or_task = golden
        .iter()
        .filter(|e| matches!(e["event_id"].as_u64(), Some(7045 | 4698)))
        .count();
    let expected_flagged = golden
        .iter()
        .filter(|e| e["flags"].as_array().is_some_and(|flags| !flags.is_empty()))
        .count();

    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap(), "--event-id", "7045,4698"]);
    let events = parse_jsonl(&output.stdout);
    assert!(!events.is_empty());
    assert_eq!(events.len(), expected_service_or_task);
    assert!(
        events
            .iter()
            .all(|e| matches!(e["event_id"].as_u64(), Some(7045 | 4698)))
    );

    let output = timeline(&[samples.to_str().unwrap(), "--flagged-only"]);
    let events = parse_jsonl(&output.stdout);
    assert!(!events.is_empty());
    assert_eq!(events.len(), expected_flagged);
    assert!(
        events
            .iter()
            .all(|e| !e["flags"].as_array().unwrap().is_empty())
    );
}

#[test]
fn time_range_keeps_from_and_drops_to() {
    let samples = fixtures("attack-samples");
    let all = parse_jsonl(&timeline(&[samples.to_str().unwrap()]).stdout);
    let first = all[0]["ts"].as_str().unwrap();
    let last = all[all.len() - 1]["ts"].as_str().unwrap();

    let output = timeline(&[samples.to_str().unwrap(), "--from", first, "--to", last]);
    let events = parse_jsonl(&output.stdout);
    assert_eq!(events[0]["ts"], first, "--from is inclusive");
    assert!(
        events.iter().all(|e| e["ts"].as_str().unwrap() < last),
        "--to is exclusive"
    );
}

#[test]
fn linux_logs_are_read_and_flagged() {
    let logs = fixtures("linux");
    let output = timeline(&[logs.to_str().unwrap()]);
    // Both fixtures hold one line of garbage on purpose.
    assert_eq!(output.status.code(), Some(2), "{output:?}");

    let events = parse_jsonl(&output.stdout);
    let sources: BTreeSet<&str> = events
        .iter()
        .map(|e| e["source"].as_str().unwrap())
        .collect();
    assert_eq!(sources, BTreeSet::from(["auditd", "journald"]));

    let rules: BTreeSet<&str> = rules(&events).into_iter().collect();
    assert_eq!(
        rules,
        BTreeSet::from([
            "exec_from_tmp",
            "failed_logon_burst",
            "logon_after_failed_burst"
        ])
    );
}

#[test]
fn host_option_fills_in_logs_that_record_no_host() {
    let log = fixtures("linux").join("audit.log");
    let output = timeline(&[log.to_str().unwrap(), "--host", "web01"]);
    let events = parse_jsonl(&output.stdout);
    assert!(!events.is_empty());
    assert!(events.iter().all(|e| e["host"] == "web01"));
}

#[test]
fn output_file_receives_the_timeline_and_stdout_stays_empty() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("timeline.jsonl");
    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap(), "-o", target.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert_eq!(
        parse_jsonl(&std::fs::read(&target).unwrap()).len(),
        golden_windows_events().len()
    );
}

#[test]
fn damaged_evtx_gives_a_partial_timeline() {
    let sample = fixtures("format").join("sample_with_a_bad_chunk_magic.evtx");
    let output = timeline(&[sample.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("3 records could not be read"));
}

#[test]
fn input_with_no_readable_log_is_a_fatal_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("notes.txt"), "not a log\n").unwrap();
    std::fs::write(dir.path().join("empty.evtx"), "").unwrap();
    std::fs::write(dir.path().join("cut.evtx"), b"ElfFile\0").unwrap();

    let output = timeline(&[dir.path().to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));

    let missing = dir.path().join("missing.evtx");
    let output = timeline(&[missing.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing.evtx"));
}

#[test]
fn table_format_is_plain_text_when_not_on_a_terminal() {
    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap(), "--format", "table"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("TIME (UTC)"));
    assert!(!text.contains('\u{1b}'), "no ANSI codes in a pipe");
    assert!(text.contains("! high   log_cleared"));

    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(!stderr.contains('\u{1b}'));
    assert!(
        stderr.contains("log_cleared"),
        "summary lists the rules that fired"
    );
}

#[test]
fn quiet_prints_no_summary() {
    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap(), "--quiet"]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    assert_eq!(
        parse_jsonl(&output.stdout).len(),
        golden_windows_events().len()
    );
}

#[cfg(unix)]
#[test]
fn a_reader_that_stops_early_is_not_an_error() {
    use std::io::Read;
    use std::process::Stdio;

    let samples = fixtures("attack-samples");
    for format in ["jsonl", "csv", "table"] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_evtx-triage"))
            .args(["timeline", samples.to_str().unwrap(), "--format", format])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Read a little, then close the pipe while the writer still has more.
        let mut stdout = child.stdout.take().unwrap();
        let mut first = [0u8; 16];
        stdout.read_exact(&mut first).unwrap();
        drop(stdout);

        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("error:"), "{format}: {stderr}");
        assert_ne!(output.status.code(), Some(1), "{format}");
    }
}

#[test]
fn triage_profile_hides_unflagged_noisy_kinds_and_full_shows_them() {
    let samples = fixtures("attack-samples");
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_evtx-triage"))
            .arg("timeline")
            .arg(&samples)
            .args(extra)
            .env_remove("NO_COLOR")
            .env_remove("CLICOLOR")
            .env_remove("CLICOLOR_FORCE")
            .output()
            .expect("the binary runs")
    };

    let triage_out = run(&[]);
    assert_eq!(triage_out.status.code(), Some(0), "{triage_out:?}");
    let full_out = run(&["--profile", "full"]);
    assert_eq!(full_out.status.code(), Some(0), "{full_out:?}");

    let triage_events = parse_jsonl(&triage_out.stdout);
    let full_events = parse_jsonl(&full_out.stdout);

    let is_unflagged_noisy = |ev: &Value| {
        let noisy = matches!(
            ev["kind"].as_str(),
            Some("image_load" | "file_create" | "registry_change")
        );
        let unflagged = ev["flags"].as_array().is_some_and(|flags| flags.is_empty());
        noisy && unflagged
    };

    assert!(
        !triage_events.iter().any(is_unflagged_noisy),
        "triage profile must hide unflagged image_load, file_create, and registry_change events"
    );

    let hidden_in_full = full_events
        .iter()
        .filter(|ev| is_unflagged_noisy(ev))
        .count();
    assert!(
        hidden_in_full > 0,
        "expected attack-samples to include unflagged noisy events"
    );
    assert_eq!(full_events.len() - triage_events.len(), hidden_in_full);

    let triage_without_noisy: Vec<&Value> = full_events
        .iter()
        .filter(|ev| !is_unflagged_noisy(ev))
        .collect();
    let triage_refs: Vec<&Value> = triage_events.iter().collect();
    assert_eq!(triage_refs, triage_without_noisy);

    let triage_stderr = String::from_utf8(triage_out.stderr).unwrap();
    let noun = if hidden_in_full == 1 {
        "event"
    } else {
        "events"
    };
    let expected_line =
        format!("{hidden_in_full} {noun} hidden by the triage profile (--profile full shows them)");
    assert!(
        triage_stderr.lines().any(|line| line == expected_line),
        "expected {expected_line:?} in stderr:\n{triage_stderr}"
    );

    let full_stderr = String::from_utf8(full_out.stderr).unwrap();
    assert!(
        !full_stderr.contains("hidden by the triage profile"),
        "full profile must not print hidden events line:\n{full_stderr}"
    );
}
