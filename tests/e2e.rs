//! End-to-end tests running the compiled `evtx-triage` binary against
//! real fixture logs, golden snapshots, and controlled file mutations.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use tempfile::TempDir;

fn repo_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn evtx_triage() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_evtx-triage"));
    // Isolate from any color environment variables set by the CI runner.
    cmd.env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("CLICOLOR_FORCE");
    cmd
}

fn run_timeline(args: &[&str]) -> Output {
    evtx_triage()
        .arg("timeline")
        .args(args)
        .output()
        .expect("evtx-triage timeline runs")
}

fn run_inspect(args: &[&str]) -> Output {
    evtx_triage()
        .arg("inspect")
        .args(args)
        .output()
        .expect("evtx-triage inspect runs")
}

/// Reduces a logged path to its final component regardless of host separator.
fn file_name_only(path_str: &str) -> &str {
    path_str.rsplit(['/', '\\']).next().unwrap_or(path_str)
}

fn normalize_jsonl_event(mut val: Value) -> Value {
    if let Some(file_val) = val.get("file").and_then(Value::as_str) {
        let name = file_name_only(file_val).to_owned();
        val["file"] = Value::String(name);
    }
    val
}

fn parse_jsonl_normalized(stdout: &[u8]) -> Vec<Value> {
    let text = String::from_utf8(stdout.to_vec()).expect("JSONL stdout is valid UTF-8");
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let val: Value = serde_json::from_str(line).expect("each JSONL line is valid JSON");
            normalize_jsonl_event(val)
        })
        .collect()
}

fn parse_csv_normalized(bytes: &[u8]) -> (csv::StringRecord, Vec<csv::StringRecord>) {
    let mut rdr = csv::ReaderBuilder::new().from_reader(bytes);
    let headers = rdr.headers().expect("CSV has header row").clone();
    let file_col = headers
        .iter()
        .position(|h| h == "file")
        .expect("CSV header has a `file` column");

    let rows = rdr
        .records()
        .map(|res| {
            let rec = res.expect("CSV row is valid");
            let mut normalized = csv::StringRecord::new();
            for (idx, field) in rec.iter().enumerate() {
                if idx == file_col {
                    normalized.push_field(file_name_only(field));
                } else {
                    normalized.push_field(field);
                }
            }
            normalized
        })
        .collect();

    (headers, rows)
}

fn assert_jsonl_matches_golden(actual_stdout: &[u8], golden_rel: &str) {
    let actual = parse_jsonl_normalized(actual_stdout);
    let golden_bytes = fs::read(repo_path(golden_rel)).expect("golden JSONL file exists");
    let expected = parse_jsonl_normalized(&golden_bytes);

    assert_eq!(
        actual.len(),
        expected.len(),
        "event count mismatch against {golden_rel}: actual {}, expected {}",
        actual.len(),
        expected.len()
    );

    for (idx, (act, exp)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(
            act, exp,
            "first differing event against {golden_rel} at index {idx}:\nexpected: {exp}\nactual:   {act}"
        );
    }
}

fn assert_csv_matches_golden(actual_stdout: &[u8], golden_rel: &str) {
    let (actual_headers, actual_rows) = parse_csv_normalized(actual_stdout);
    let golden_bytes = fs::read(repo_path(golden_rel)).expect("golden CSV file exists");
    let (expected_headers, expected_rows) = parse_csv_normalized(&golden_bytes);

    assert_eq!(
        actual_headers, expected_headers,
        "CSV header mismatch against {golden_rel}"
    );
    assert_eq!(
        actual_rows.len(),
        expected_rows.len(),
        "CSV row count mismatch against {golden_rel}: actual {}, expected {}",
        actual_rows.len(),
        expected_rows.len()
    );

    for (idx, (act, exp)) in actual_rows.iter().zip(expected_rows.iter()).enumerate() {
        assert_eq!(
            act, exp,
            "first differing CSV row against {golden_rel} at index {idx}:\nexpected: {exp:?}\nactual:   {act:?}"
        );
    }
}

fn first_json_diff(expected: &Value, actual: &Value, path: &str) -> Option<String> {
    if expected == actual {
        return None;
    }
    match (expected, actual) {
        (Value::Object(exp_map), Value::Object(act_map)) => {
            for (k, exp_v) in exp_map {
                let child_path = format!("{path}.{k}");
                match act_map.get(k) {
                    Some(act_v) if act_v != exp_v => {
                        return first_json_diff(exp_v, act_v, &child_path);
                    }
                    None => {
                        return Some(format!(
                            "at {child_path}: missing in actual (expected {exp_v})"
                        ));
                    }
                    _ => {}
                }
            }
            for (k, act_v) in act_map {
                if !exp_map.contains_key(k) {
                    return Some(format!("at {path}.{k}: unexpected key with value {act_v}"));
                }
            }
            None
        }
        (Value::Array(exp_arr), Value::Array(act_arr)) => {
            if exp_arr.len() != act_arr.len() {
                return Some(format!(
                    "at {path}: array length expected {}, actual {}",
                    exp_arr.len(),
                    act_arr.len()
                ));
            }
            for (idx, (exp_v, act_v)) in exp_arr.iter().zip(act_arr.iter()).enumerate() {
                if exp_v != act_v {
                    return first_json_diff(exp_v, act_v, &format!("{path}[{idx}]"));
                }
            }
            None
        }
        _ => Some(format!(
            "at {path}:\nexpected: {expected}\nactual:   {actual}"
        )),
    }
}

fn assert_inspect_json_matches_golden(actual_stdout: &[u8], golden_rel: &str) {
    let actual: Value = serde_json::from_slice(actual_stdout).expect("inspect JSON is valid");
    let golden_bytes = fs::read(repo_path(golden_rel)).expect("golden inspect JSON exists");
    let expected: Value =
        serde_json::from_slice(&golden_bytes).expect("golden inspect JSON is valid");

    if let Some(diff) = first_json_diff(&expected, &actual, "$") {
        panic!("inspect JSON mismatch against {golden_rel}: {diff}");
    }
}

fn write_normalized_jsonl(path: &Path, stdout: &[u8]) {
    let events = parse_jsonl_normalized(stdout);
    let mut out = String::new();
    for event in &events {
        out.push_str(&serde_json::to_string(event).expect("serialize JSONL event"));
        out.push('\n');
    }
    fs::write(path, out).expect("write golden JSONL");
}

fn write_normalized_csv(path: &Path, stdout: &[u8]) {
    let (headers, rows) = parse_csv_normalized(stdout);
    let mut buf = Vec::new();
    {
        let mut wtr = csv::WriterBuilder::new()
            .terminator(csv::Terminator::Any(b'\n'))
            .from_writer(&mut buf);
        wtr.write_record(&headers).expect("write CSV headers");
        for row in &rows {
            wtr.write_record(row).expect("write CSV row");
        }
        wtr.flush().expect("flush CSV writer");
    }
    fs::write(path, buf).expect("write golden CSV");
}

fn is_valid_ts_format(ts: &str) -> bool {
    // YYYY-MM-DDTHH:MM:SS.ffffffZ -> 27 bytes ASCII
    let b = ts.as_bytes();
    if b.len() != 27 {
        return false;
    }
    let digit_positions = [
        0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22, 23, 24, 25,
    ];
    digit_positions.iter().all(|&i| b[i].is_ascii_digit())
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[26] == b'Z'
        && ts.parse::<jiff::Timestamp>().is_ok()
}

fn is_table_event_line(line: &str) -> bool {
    let b = line.as_bytes();
    b.len() >= 19
        && b[0..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[7] == b'-'
        && b[8..10].iter().all(u8::is_ascii_digit)
        && b[10] == b' '
        && b[11..13].iter().all(u8::is_ascii_digit)
        && b[13] == b':'
        && b[14..16].iter().all(u8::is_ascii_digit)
        && b[16] == b':'
        && b[17..19].iter().all(u8::is_ascii_digit)
}

fn write_journald_file(dir: &Path, name: &str, lines: &[Value]) -> PathBuf {
    let path = dir.join(name);
    let mut content = String::new();
    for line in lines {
        content.push_str(&serde_json::to_string(line).expect("serialize journald line"));
        content.push('\n');
    }
    fs::write(&path, content).expect("write journald file");
    path
}

fn collect_flag_tuples(events: &[Value]) -> BTreeSet<(String, String, String)> {
    events
        .iter()
        .flat_map(|e| e["flags"].as_array().into_iter().flatten())
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_owned(),
                f["severity"].as_str().unwrap().to_owned(),
                f["reason"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

#[test]
#[ignore = "run with: cargo test --test e2e -- --ignored regenerate_golden_files"]
fn regenerate_golden_files() {
    let golden_dir = repo_path("tests/golden");
    fs::create_dir_all(&golden_dir).expect("create tests/golden");

    let win_dir = repo_path("tests/fixtures/attack-samples");
    let win_jsonl = run_timeline(&[win_dir.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(win_jsonl.status.code(), Some(0));
    write_normalized_jsonl(&golden_dir.join("windows.jsonl"), &win_jsonl.stdout);

    let win_csv = run_timeline(&[win_dir.to_str().unwrap(), "--format", "csv"]);
    assert_eq!(win_csv.status.code(), Some(0));
    write_normalized_csv(&golden_dir.join("windows.csv"), &win_csv.stdout);

    let linux_dir = repo_path("tests/fixtures/linux");
    let linux_jsonl = run_timeline(&[linux_dir.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(linux_jsonl.status.code(), Some(2));
    write_normalized_jsonl(&golden_dir.join("linux.jsonl"), &linux_jsonl.stdout);

    let bad_magic = repo_path("tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx");
    let inspect_out = run_inspect(&["--json", bad_magic.to_str().unwrap()]);
    assert_eq!(inspect_out.status.code(), Some(2));
    let parsed: Value = serde_json::from_slice(&inspect_out.stdout).expect("inspect JSON is valid");
    let mut formatted = serde_json::to_string_pretty(&parsed).expect("format inspect JSON");
    formatted.push('\n');
    fs::write(golden_dir.join("inspect_bad_chunk_magic.json"), formatted)
        .expect("write golden inspect JSON");
}

#[test]
fn golden_windows_jsonl_matches_current_output() {
    let win_dir = repo_path("tests/fixtures/attack-samples");
    let out = run_timeline(&[win_dir.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_jsonl_matches_golden(&out.stdout, "tests/golden/windows.jsonl");
}

#[test]
fn golden_linux_jsonl_matches_current_output() {
    let linux_dir = repo_path("tests/fixtures/linux");
    let out = run_timeline(&[linux_dir.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_jsonl_matches_golden(&out.stdout, "tests/golden/linux.jsonl");
}

#[test]
fn golden_windows_csv_matches_current_output() {
    let win_dir = repo_path("tests/fixtures/attack-samples");
    let out = run_timeline(&[win_dir.to_str().unwrap(), "--format", "csv"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_csv_matches_golden(&out.stdout, "tests/golden/windows.csv");
}

#[test]
fn golden_inspect_bad_chunk_magic_matches_current_output() {
    let bad_magic = repo_path("tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx");
    let out = run_inspect(&["--json", bad_magic.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_inspect_json_matches_golden(&out.stdout, "tests/golden/inspect_bad_chunk_magic.json");
}

#[test]
fn repeated_runs_produce_byte_identical_stdout() {
    let win_dir = repo_path("tests/fixtures/attack-samples");
    let first = run_timeline(&[win_dir.to_str().unwrap(), "--format", "jsonl"]);
    let second = run_timeline(&[win_dir.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(first.status.code(), Some(0));
    assert_eq!(second.status.code(), Some(0));
    assert_eq!(
        first.stdout, second.stdout,
        "two runs over the same directory produced different stdout bytes"
    );
}

#[test]
fn cli_input_file_order_does_not_change_timeline_output() {
    let inputs = [
        repo_path("tests/fixtures/attack-samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx"),
        repo_path("tests/fixtures/attack-samples/DE_Fake_ComputerAccount_4720.evtx"),
        repo_path("tests/fixtures/attack-samples/DE_RDP_Tunnel_5156.evtx"),
        repo_path("tests/fixtures/attack-samples/LM_Remote_Service02_7045.evtx"),
        repo_path("tests/fixtures/attack-samples/LM_ScheduledTask_ATSVC_target_host.evtx"),
        repo_path("tests/fixtures/attack-samples/LM_sysmon_psexec_smb_meterpreter.evtx"),
        repo_path(
            "tests/fixtures/attack-samples/phish_windows_credentials_powershell_scriptblockLog_4104.evtx",
        ),
        repo_path("tests/fixtures/linux/audit.log"),
        repo_path("tests/fixtures/linux/journald.json"),
    ];
    let forward: Vec<&str> = inputs.iter().map(|p| p.to_str().unwrap()).collect();
    let mut reversed: Vec<&str> = forward.clone();
    reversed.reverse();

    let mut args_fwd = forward;
    args_fwd.extend(["--format", "jsonl"]);
    let mut args_rev = reversed;
    args_rev.extend(["--format", "jsonl"]);

    let out_fwd = run_timeline(&args_fwd);
    let out_rev = run_timeline(&args_rev);
    assert_eq!(out_fwd.status.code(), Some(2));
    assert_eq!(out_rev.status.code(), Some(2));

    let events_fwd = parse_jsonl_normalized(&out_fwd.stdout);
    let events_rev = parse_jsonl_normalized(&out_rev.stdout);
    assert_eq!(events_fwd.len(), events_rev.len());
    for (idx, (a, b)) in events_fwd.iter().zip(events_rev.iter()).enumerate() {
        assert_eq!(
            a, b,
            "input order changed event at index {idx}:\nforward:  {a}\nreversed: {b}"
        );
    }
}

#[test]
fn mixed_windows_and_linux_sources_combine_counts_order_and_flags() {
    let win_dir = repo_path("tests/fixtures/attack-samples");
    let linux_dir = repo_path("tests/fixtures/linux");

    let win_out = run_timeline(&[win_dir.to_str().unwrap(), "--format", "jsonl"]);
    let linux_out = run_timeline(&[linux_dir.to_str().unwrap(), "--format", "jsonl"]);
    let combined_out = run_timeline(&[
        win_dir.to_str().unwrap(),
        linux_dir.to_str().unwrap(),
        "--format",
        "jsonl",
    ]);

    assert_eq!(win_out.status.code(), Some(0));
    assert_eq!(linux_out.status.code(), Some(2));
    assert_eq!(combined_out.status.code(), Some(2));

    let win_events = parse_jsonl_normalized(&win_out.stdout);
    let linux_events = parse_jsonl_normalized(&linux_out.stdout);
    let combined_events = parse_jsonl_normalized(&combined_out.stdout);

    assert_eq!(
        combined_events.len(),
        win_events.len() + linux_events.len(),
        "combined count should equal sum of separate runs"
    );

    let timestamps: Vec<&str> = combined_events
        .iter()
        .map(|e| e["ts"].as_str().unwrap())
        .collect();
    assert!(
        timestamps.is_sorted(),
        "combined timeline must be sorted by ts"
    );

    let sources: BTreeSet<&str> = combined_events
        .iter()
        .map(|e| e["source"].as_str().unwrap())
        .collect();
    assert_eq!(sources, BTreeSet::from(["evtx", "journald", "auditd"]));

    let mut expected_flags = collect_flag_tuples(&win_events);
    expected_flags.extend(collect_flag_tuples(&linux_events));
    let combined_flags = collect_flag_tuples(&combined_events);
    assert_eq!(
        combined_flags, expected_flags,
        "combined flags must be the union of separate runs' flags"
    );
}

#[test]
fn jsonl_csv_and_table_agree_on_count_order_and_flag_count() {
    for rel in ["tests/fixtures/attack-samples", "tests/fixtures/linux"] {
        let dir = repo_path(rel);
        let dir_str = dir.to_str().unwrap();

        let jsonl_out = run_timeline(&[dir_str, "--format", "jsonl"]);
        let csv_out = run_timeline(&[dir_str, "--format", "csv"]);
        let table_out = evtx_triage()
            .env("NO_COLOR", "1")
            .args(["timeline", dir_str, "--format", "table"])
            .output()
            .expect("table timeline runs");

        assert_eq!(jsonl_out.status.code(), csv_out.status.code(), "{rel}");
        assert_eq!(jsonl_out.status.code(), table_out.status.code(), "{rel}");

        let jsonl_events = parse_jsonl_normalized(&jsonl_out.stdout);
        let jsonl_times: Vec<String> = jsonl_events
            .iter()
            .map(|e| e["ts"].as_str().unwrap()[..19].replace('T', " "))
            .collect();
        let jsonl_flag_count: usize = jsonl_events
            .iter()
            .map(|e| e["flags"].as_array().unwrap().len())
            .sum();

        let (csv_headers, csv_rows) = parse_csv_normalized(&csv_out.stdout);
        let flags_col = csv_headers
            .iter()
            .position(|h| h == "flags")
            .expect("CSV has flags column");
        let csv_times: Vec<String> = csv_rows
            .iter()
            .map(|r| r[0][..19].replace('T', " "))
            .collect();
        let csv_flag_count: usize = csv_rows
            .iter()
            .map(|r| {
                if r[flags_col].is_empty() {
                    0
                } else {
                    r[flags_col].split(';').count()
                }
            })
            .sum();

        let table_text = String::from_utf8(table_out.stdout).expect("table is UTF-8");
        let table_times: Vec<String> = table_text
            .lines()
            .filter(|line| is_table_event_line(line))
            .map(|line| line[..19].to_owned())
            .collect();
        let table_flag_count = table_text
            .lines()
            .filter(|line| line.contains("! "))
            .count();

        assert_eq!(csv_times, jsonl_times, "{rel}: CSV vs JSONL times");
        assert_eq!(table_times, jsonl_times, "{rel}: table vs JSONL times");
        assert_eq!(
            csv_flag_count, jsonl_flag_count,
            "{rel}: CSV vs JSONL flag count"
        );
        assert_eq!(
            table_flag_count, jsonl_flag_count,
            "{rel}: table vs JSONL flag count"
        );
    }
}

fn find_null_path(val: &Value, path: &str) -> Option<String> {
    match val {
        Value::Null => Some(path.to_owned()),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(idx, item)| find_null_path(item, &format!("{path}[{idx}]"))),
        Value::Object(map) => map
            .iter()
            .find_map(|(k, v)| find_null_path(v, &format!("{path}.{k}"))),
        _ => None,
    }
}

#[test]
fn every_jsonl_event_across_all_fixtures_matches_schema() {
    let all_fixtures = repo_path("tests/fixtures");
    let out = run_timeline(&[all_fixtures.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let events = parse_jsonl_normalized(&out.stdout);
    assert!(!events.is_empty());

    let readme_kinds = BTreeSet::from([
        "logon_success",
        "logon_failure",
        "explicit_logon",
        "logoff",
        "special_privileges",
        "process_create",
        "task_create",
        "task_delete",
        "task_update",
        "user_create",
        "group_member_add",
        "log_clear",
        "service_install",
        "script_block",
        "privileged_command",
        "service_start",
        "kerberos_tgt",
        "kerberos_service_ticket",
        "kerberos_preauth_failure",
        "ntlm_auth",
        "network_connect",
        "image_load",
        "remote_thread",
        "process_access",
        "file_create",
        "file_delete",
        "registry_change",
        "named_pipe",
        "dns_query",
        "wmi_persistence",
        "rdp_connect",
        "rdp_session",
        "defender_detection",
        "defender_config_change",
        "bits_job",
        "powershell_pipeline",
        "powershell_engine",
    ]);

    for (idx, event) in events.iter().enumerate() {
        let obj = event
            .as_object()
            .unwrap_or_else(|| panic!("event {idx} is not an object: {event}"));

        if let Some(null_path) = find_null_path(event, "$") {
            panic!("event {idx} has null at `{null_path}` instead of omitting it: {event}");
        }

        let ts = obj
            .get("ts")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("event {idx} missing string ts: {event}"));
        assert!(
            is_valid_ts_format(ts),
            "event {idx} ts `{ts}` does not match YYYY-MM-DDTHH:MM:SS.ffffffZ"
        );

        for req in ["host", "source", "kind", "summary", "file"] {
            let s = obj
                .get(req)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("event {idx} missing `{req}`: {event}"));
            assert!(!s.is_empty(), "event {idx} has empty `{req}`: {event}");
        }

        let kind = obj["kind"].as_str().unwrap();
        assert!(
            readme_kinds.contains(kind),
            "event {idx} has undocumented kind `{kind}`"
        );

        let summary = obj["summary"].as_str().unwrap();
        assert!(
            !summary.contains('\n') && !summary.contains('\r'),
            "event {idx} summary contains newline: {summary:?}"
        );

        assert!(
            obj.get("details").is_some_and(Value::is_object),
            "event {idx} `details` must be an object: {event}"
        );

        let flags = obj
            .get("flags")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("event {idx} `flags` must be an array: {event}"));
        for (fidx, flag) in flags.iter().enumerate() {
            let rule = flag.get("rule").and_then(Value::as_str).unwrap_or("");
            assert!(!rule.is_empty(), "event {idx} flag {fidx} empty rule");

            let severity = flag.get("severity").and_then(Value::as_str).unwrap_or("");
            assert!(
                matches!(severity, "low" | "medium" | "high"),
                "event {idx} flag {fidx} invalid severity `{severity}`"
            );

            let reason = flag.get("reason").and_then(Value::as_str).unwrap_or("");
            assert!(!reason.is_empty(), "event {idx} flag {fidx} empty reason");
        }
    }
}

#[test]
fn detection_runs_before_from_filter_and_respects_window_flag() {
    let linux_dir = repo_path("tests/fixtures/linux");
    let baseline = run_timeline(&[linux_dir.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(baseline.status.code(), Some(2));
    let baseline_events = parse_jsonl_normalized(&baseline.stdout);

    let first_success_ts = baseline_events
        .iter()
        .find(|e| e["kind"] == "logon_success")
        .expect("linux fixtures contain a logon_success")["ts"]
        .as_str()
        .unwrap()
        .to_owned();

    let filtered = run_timeline(&[
        linux_dir.to_str().unwrap(),
        "--from",
        &first_success_ts,
        "--format",
        "jsonl",
    ]);
    assert_eq!(filtered.status.code(), Some(2));
    let filtered_events = parse_jsonl_normalized(&filtered.stdout);

    assert!(
        filtered_events
            .iter()
            .all(|e| e["ts"].as_str().unwrap() >= first_success_ts.as_str()),
        "all events before --from should be filtered out"
    );
    let first_filtered = &filtered_events[0];
    assert_eq!(first_filtered["ts"], first_success_ts);
    assert!(
        first_filtered["flags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule"] == "logon_after_failed_burst"),
        "logon_after_failed_burst must still fire when earlier failures are filtered out by --from: {first_filtered}"
    );

    let narrow = run_timeline(&[
        linux_dir.to_str().unwrap(),
        "--window",
        "1s",
        "--format",
        "jsonl",
    ]);
    assert_eq!(narrow.status.code(), Some(2));
    let narrow_events = parse_jsonl_normalized(&narrow.stdout);
    let narrow_rules: BTreeSet<&str> = narrow_events
        .iter()
        .flat_map(|e| e["flags"].as_array().into_iter().flatten())
        .map(|f| f["rule"].as_str().unwrap())
        .collect();
    assert!(
        !narrow_rules.contains("failed_logon_burst")
            && !narrow_rules.contains("logon_after_failed_burst"),
        "--window 1s should suppress both burst rules, got: {narrow_rules:?}"
    );
}

#[test]
fn encoded_powershell_flags_in_windows_samples_explain_decoding() {
    let win_dir = repo_path("tests/fixtures/attack-samples");
    let out = run_timeline(&[win_dir.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(out.status.code(), Some(0));

    let events = parse_jsonl_normalized(&out.stdout);
    let ps_flags: Vec<&Value> = events
        .iter()
        .flat_map(|e| e["flags"].as_array().into_iter().flatten())
        .filter(|f| f["rule"] == "encoded_powershell")
        .collect();

    assert_eq!(
        ps_flags.len(),
        4,
        "expected 4 encoded_powershell flags in attack-samples, got {ps_flags:?}"
    );
    for flag in ps_flags {
        let reason = flag["reason"].as_str().unwrap();
        assert!(
            reason.contains("FromBase64String")
                || reason.starts_with("PowerShell encoded command decodes to:"),
            "unexpected encoded_powershell reason: {reason}"
        );
        assert_eq!(flag["severity"], "medium");
        assert_eq!(
            reason,
            "Script decodes base64 at run time (FromBase64String): gzip-compressed payload"
        );
    }
}

#[test]
fn exported_chrome_log_uses_xml_metadata_and_inspect_reports_zero_record_time() {
    let chrome_evtx =
        repo_path("tests/fixtures/attack-samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx");
    let chrome_str = chrome_evtx.to_str().unwrap();

    let tl_out = run_timeline(&[chrome_str, "--format", "jsonl"]);
    assert_eq!(tl_out.status.code(), Some(0));
    let events = parse_jsonl_normalized(&tl_out.stdout);
    assert_eq!(events.len(), 4);
    for event in &events {
        let ts = event["ts"].as_str().unwrap();
        assert!(
            ts.starts_with("2020-"),
            "exported event timestamp should come from XML (year 2020), got {ts}"
        );
        let record_id = event["record_id"]
            .as_u64()
            .expect("event has XML record_id");
        let file_record_id = event["details"]["file_record_id"]
            .as_u64()
            .expect("event records framing file_record_id");
        assert_ne!(
            record_id, file_record_id,
            "renumbered exported log should preserve both distinct record_id and file_record_id"
        );
    }

    let inspect_out = run_inspect(&["--json", chrome_str]);
    assert_eq!(inspect_out.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&inspect_out.stdout).expect("inspect JSON");
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "zero_record_time" && f["severity"] == "info"),
        "expected info zero_record_time finding in {report}"
    );
}

#[test]
fn inspect_json_omits_records_by_default_and_includes_them_with_records_flag() {
    for rel in [
        "tests/fixtures/format/Security_short_selected.evtx",
        "tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx",
    ] {
        let path = repo_path(rel);
        let path_str = path.to_str().unwrap();

        let without = run_inspect(&["--json", path_str]);
        let with = run_inspect(&["--json", "--records", path_str]);
        assert_eq!(without.status.code(), with.status.code(), "{rel}");

        let without_json: Value = serde_json::from_slice(&without.stdout).expect("valid JSON");
        assert!(
            without_json.get("records").is_none(),
            "{rel}: inspect --json without --records must omit `records`"
        );
        assert!(without_json["file_header"].is_object(), "{rel}");
        assert!(without_json["chunks"].is_array(), "{rel}");
        assert!(without_json["findings"].is_array(), "{rel}");
        let total_records = without_json["summary"]["total_records"]
            .as_u64()
            .expect("summary.total_records is u64");

        let with_json: Value = serde_json::from_slice(&with.stdout).expect("valid JSON");
        let records = with_json["records"]
            .as_array()
            .expect("inspect --json --records includes `records`");
        assert_eq!(
            records.len() as u64,
            total_records,
            "{rel}: records length must equal summary.total_records"
        );
    }
}

#[test]
fn inspect_total_records_is_positive_and_at_least_timeline_event_count_for_clean_evtx() {
    let clean_fixtures = [
        "tests/fixtures/format/Security_short_selected.evtx",
        "tests/fixtures/format/Application_no_crc32.evtx",
        "tests/fixtures/attack-samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx",
        "tests/fixtures/attack-samples/DE_Fake_ComputerAccount_4720.evtx",
        "tests/fixtures/attack-samples/DE_RDP_Tunnel_5156.evtx",
        "tests/fixtures/attack-samples/LM_Remote_Service02_7045.evtx",
        "tests/fixtures/attack-samples/LM_ScheduledTask_ATSVC_target_host.evtx",
        "tests/fixtures/attack-samples/LM_sysmon_psexec_smb_meterpreter.evtx",
        "tests/fixtures/attack-samples/phish_windows_credentials_powershell_scriptblockLog_4104.evtx",
    ];

    for rel in clean_fixtures {
        let path = repo_path(rel);
        let path_str = path.to_str().unwrap();

        let inspect_out = run_inspect(&["--json", path_str]);
        assert_eq!(inspect_out.status.code(), Some(0), "{rel}");
        let report: Value = serde_json::from_slice(&inspect_out.stdout).expect("inspect JSON");
        let total_records = report["summary"]["total_records"]
            .as_u64()
            .expect("summary.total_records is u64");
        assert!(total_records > 0, "{rel}: total_records must be > 0");

        let tl_out = run_timeline(&[path_str, "--format", "jsonl"]);
        assert_eq!(tl_out.status.code(), Some(0), "{rel}");
        let events = parse_jsonl_normalized(&tl_out.stdout);
        assert!(
            total_records >= events.len() as u64,
            "{rel}: total_records ({total_records}) < timeline events ({})",
            events.len()
        );
    }
}

#[test]
fn setting_dirty_bit_triggers_inspect_dirty_flag_while_timeline_matches_original() {
    let orig = repo_path("tests/fixtures/format/Security_short_selected.evtx");
    let dir = TempDir::new().unwrap();
    let dirty = dir.path().join("dirty.evtx");

    let mut bytes = fs::read(&orig).unwrap();
    bytes[0x78] |= 0x1;
    fs::write(&dirty, bytes).unwrap();

    let inspect_out = run_inspect(&["--json", dirty.to_str().unwrap()]);
    assert_eq!(inspect_out.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "dirty_flag"),
        "expected dirty_flag finding in {report}"
    );

    let orig_tl = run_timeline(&[orig.to_str().unwrap(), "--format", "jsonl"]);
    let dirty_tl = run_timeline(&[dirty.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(orig_tl.status.code(), Some(0));
    assert_eq!(dirty_tl.status.code(), Some(0));

    let mut orig_events = parse_jsonl_normalized(&orig_tl.stdout);
    let mut dirty_events = parse_jsonl_normalized(&dirty_tl.stdout);
    for e in orig_events.iter_mut().chain(dirty_events.iter_mut()) {
        e.as_object_mut().unwrap().remove("file");
    }
    assert_eq!(dirty_events, orig_events);
}

#[test]
fn truncated_evtx_never_panics_and_inspect_reports_truncated_file() {
    let orig = repo_path("tests/fixtures/format/Security_short_selected.evtx");
    let dir = TempDir::new().unwrap();
    let half = dir.path().join("half.evtx");

    let mut bytes = fs::read(&orig).unwrap();
    bytes.truncate(bytes.len() / 2);
    fs::write(&half, bytes).unwrap();

    let inspect_out = run_inspect(&["--json", half.to_str().unwrap()]);
    let inspect_code = inspect_out.status.code();
    assert!(
        matches!(inspect_code, Some(0..=2)),
        "inspect panicked or exited unexpectedly: {inspect_code:?}"
    );
    assert_eq!(inspect_code, Some(2));
    let report: Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "truncated_file"),
        "expected truncated_file finding in {report}"
    );

    let tl_out = run_timeline(&[half.to_str().unwrap(), "--format", "jsonl"]);
    let tl_code = tl_out.status.code();
    assert!(
        matches!(tl_code, Some(0..=2)),
        "timeline panicked or exited unexpectedly: {tl_code:?}"
    );
}

#[test]
fn overwriting_first_chunk_magic_reports_bad_chunk_magic_and_timeline_fails_or_warns() {
    let orig = repo_path("tests/fixtures/format/Security_short_selected.evtx");
    let dir = TempDir::new().unwrap();
    let damaged = dir.path().join("bad_magic.evtx");

    let mut bytes = fs::read(&orig).unwrap();
    bytes[4096..4104].copy_from_slice(b"XXXXXXXX");
    fs::write(&damaged, bytes).unwrap();

    let inspect_out = run_inspect(&["--json", damaged.to_str().unwrap()]);
    assert_eq!(inspect_out.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&inspect_out.stdout).unwrap();
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["kind"] == "bad_chunk_magic"),
        "expected bad_chunk_magic finding in {report}"
    );

    let tl_out = run_timeline(&[damaged.to_str().unwrap(), "--format", "jsonl"]);
    assert!(
        matches!(tl_out.status.code(), Some(1 | 2)),
        "expected timeline exit code 1 or 2, got {:?}",
        tl_out.status.code()
    );
}

#[test]
fn empty_and_magic_only_files_given_directly_do_not_panic() {
    let dir = TempDir::new().unwrap();
    let empty = dir.path().join("empty.evtx");
    let magic_only = dir.path().join("magic_only.evtx");
    fs::write(&empty, b"").unwrap();
    fs::write(&magic_only, b"ElfFile\0").unwrap();

    for path in [&empty, &magic_only] {
        let tl_out = run_timeline(&[path.to_str().unwrap()]);
        assert_eq!(
            tl_out.status.code(),
            Some(1),
            "timeline on {} should exit 1, stderr: {}",
            path.display(),
            String::from_utf8_lossy(&tl_out.stderr)
        );

        let inspect_out = run_inspect(&[path.to_str().unwrap()]);
        assert!(
            matches!(inspect_out.status.code(), Some(1 | 2)),
            "inspect on {} should exit 1 or 2, got {:?}",
            path.display(),
            inspect_out.status.code()
        );
    }
}

#[test]
fn output_option_writes_csv_matching_stdout_and_strips_table_ansi_with_clicolor_force() {
    let samples = repo_path("tests/fixtures/attack-samples");
    let samples_str = samples.to_str().unwrap();
    let dir = TempDir::new().unwrap();

    let csv_file = dir.path().join("out.csv");
    let stdout_csv = run_timeline(&[samples_str, "--format", "csv"]);
    let file_csv = run_timeline(&[
        samples_str,
        "--format",
        "csv",
        "-o",
        csv_file.to_str().unwrap(),
    ]);
    assert_eq!(stdout_csv.status.code(), Some(0));
    assert_eq!(file_csv.status.code(), Some(0));
    assert!(
        file_csv.stdout.is_empty(),
        "stdout should remain empty when -o is given"
    );

    let (_, expected_rows) = parse_csv_normalized(&stdout_csv.stdout);
    let (_, actual_rows) = parse_csv_normalized(&fs::read(&csv_file).unwrap());
    assert_eq!(actual_rows, expected_rows);

    let table_file = dir.path().join("out.txt");
    let table_out = evtx_triage()
        .env("CLICOLOR_FORCE", "1")
        .args([
            "timeline",
            samples_str,
            "--format",
            "table",
            "-o",
            table_file.to_str().unwrap(),
        ])
        .output()
        .expect("table -o runs");
    assert_eq!(table_out.status.code(), Some(0));
    assert!(table_out.stdout.is_empty());
    let written_table = fs::read_to_string(&table_file).unwrap();
    assert!(written_table.starts_with("TIME (UTC)"));
    assert!(
        !written_table.contains('\u{1b}'),
        "table written to -o must not contain ANSI escapes even with CLICOLOR_FORCE=1"
    );
}

#[test]
fn hostile_control_characters_are_scrubbed_in_table_and_preserved_in_jsonl() {
    let dir = TempDir::new().unwrap();
    let hostile_cmd = "/bin/echo \u{001b}[2J\u{0007}\towned";
    let line = json!({
        "__REALTIME_TIMESTAMP": "1700000000000000",
        "_HOSTNAME": "web01",
        "SYSLOG_IDENTIFIER": "sudo",
        "_PID": "4242",
        "MESSAGE": format!("   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND={hostile_cmd}")
    });
    let log_path = write_journald_file(dir.path(), "hostile.json", &[line]);

    let table_out = evtx_triage()
        .env("NO_COLOR", "1")
        .args(["timeline", log_path.to_str().unwrap(), "--format", "table"])
        .output()
        .expect("table runs");
    assert_eq!(table_out.status.code(), Some(0));
    let table_text = String::from_utf8(table_out.stdout).unwrap();
    assert!(
        !table_text.contains('\u{1b}') && !table_text.contains('\u{7}'),
        "control characters reached table stdout: {table_text:?}"
    );

    let jsonl_out = run_timeline(&[log_path.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(jsonl_out.status.code(), Some(0));
    let jsonl_raw = String::from_utf8(jsonl_out.stdout.clone()).unwrap();
    assert!(
        jsonl_raw.contains("\\u001b"),
        "JSONL output should JSON-escape ESC as \\u001b: {jsonl_raw}"
    );
    let events = parse_jsonl_normalized(&jsonl_out.stdout);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["command_line"].as_str(), Some(hostile_cmd));
}

#[test]
fn csv_prefixes_formula_injection_while_jsonl_keeps_raw_command() {
    let dir = TempDir::new().unwrap();
    let formula_cmd = "=cmd|' /C calc'!A0";
    let line = json!({
        "__REALTIME_TIMESTAMP": "1700000000000000",
        "_HOSTNAME": "web01",
        "SYSLOG_IDENTIFIER": "sudo",
        "_PID": "4242",
        "MESSAGE": format!("   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND={formula_cmd}")
    });
    let log_path = write_journald_file(dir.path(), "formula.json", &[line]);

    let csv_out = run_timeline(&[log_path.to_str().unwrap(), "--format", "csv"]);
    assert_eq!(csv_out.status.code(), Some(0));
    let (headers, rows) = parse_csv_normalized(&csv_out.stdout);
    let cmd_col = headers
        .iter()
        .position(|h| h == "command_line")
        .expect("CSV has command_line column");
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0][cmd_col].starts_with("'="),
        "CSV command_line must be prefixed with apostrophe, got {:?}",
        &rows[0][cmd_col]
    );
    assert_eq!(&rows[0][cmd_col], "'=cmd|' /C calc'!A0");

    let jsonl_out = run_timeline(&[log_path.to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(jsonl_out.status.code(), Some(0));
    let events = parse_jsonl_normalized(&jsonl_out.stdout);
    assert_eq!(events[0]["command_line"].as_str(), Some(formula_cmd));
}

#[test]
fn directory_with_unknown_files_and_one_good_log_skips_unknowns_and_exits_zero() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("notes.txt"), "just some text\n").unwrap();
    fs::write(dir.path().join("other.json"), "{\"hello\":\"world\"}\n").unwrap();
    fs::write(dir.path().join("blob.bin"), [0u8, 1, 2, 3, 4]).unwrap();

    let line = json!({
        "__REALTIME_TIMESTAMP": "1700000000000000",
        "_HOSTNAME": "web01",
        "SYSLOG_IDENTIFIER": "sudo",
        "_PID": "4242",
        "MESSAGE": "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id"
    });
    write_journald_file(dir.path(), "good.json", &[line]);

    let out = run_timeline(&[dir.path().to_str().unwrap(), "--format", "jsonl"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let events = parse_jsonl_normalized(&out.stdout);
    assert_eq!(events.len(), 1);

    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("3 files skipped"),
        "expected stderr summary to report 3 skipped files, got: {stderr}"
    );
}
