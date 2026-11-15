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

#[test]
fn windows_samples_give_a_sorted_timeline_with_all_ten_event_types() {
    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");

    let events = parse_jsonl(&output.stdout);
    assert_eq!(events.len(), 52);

    let times: Vec<&str> = events.iter().map(|e| e["ts"].as_str().unwrap()).collect();
    assert!(times.is_sorted(), "timeline is ordered by time");
    assert!(times[0] > "2019-01-01", "no event is left in 1601");

    // Sysmon 1 and Security 4688 are both process creations; the other eight
    // ids map to one kind each.
    let ids: BTreeSet<u64> = events
        .iter()
        .map(|e| e["event_id"].as_u64().unwrap())
        .collect();
    assert_eq!(
        ids,
        BTreeSet::from([1, 1102, 4104, 4624, 4625, 4648, 4688, 4698, 4720, 7045])
    );
    for event in &events {
        assert_eq!(event["source"], "evtx");
        assert!(!event["summary"].as_str().unwrap().is_empty());
        assert!(!event["host"].as_str().unwrap().is_empty());
    }

    let rules = rules(&events);
    assert_eq!(rules.iter().filter(|r| **r == "log_cleared").count(), 2);
    assert!(rules.iter().filter(|r| **r == "encoded_powershell").count() >= 4);

    let summary = String::from_utf8_lossy(&output.stderr);
    assert!(
        summary.contains("52 events"),
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
    assert_eq!(rows.len(), 52);
    assert!(rows.iter().all(|row| row.len() == headers.len()));
}

#[test]
fn event_id_filter_and_flagged_only() {
    let samples = fixtures("attack-samples");
    let output = timeline(&[samples.to_str().unwrap(), "--event-id", "7045,4698"]);
    let events = parse_jsonl(&output.stdout);
    assert_eq!(events.len(), 4);
    assert!(
        events
            .iter()
            .all(|e| matches!(e["event_id"].as_u64(), Some(7045 | 4698)))
    );

    let output = timeline(&[samples.to_str().unwrap(), "--flagged-only"]);
    let events = parse_jsonl(&output.stdout);
    assert!(!events.is_empty());
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
    assert_eq!(parse_jsonl(&std::fs::read(&target).unwrap()).len(), 52);
}

#[test]
fn damaged_evtx_gives_a_partial_timeline() {
    let sample = fixtures("format").join("sample_with_a_bad_chunk_magic.evtx");
    let output = timeline(&[sample.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("3 unreadable"));
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
