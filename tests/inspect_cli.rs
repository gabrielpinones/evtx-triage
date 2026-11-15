//! End-to-end tests of `evtx-triage inspect` against the fixture logs.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn inspect(args: &[&str], file: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evtx-triage"))
        .arg("inspect")
        .args(args)
        .arg(fixture_path(file))
        .output()
        .expect("the binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn inspect_clean_fixture_exits_zero_and_prints_summary() {
    let output = inspect(&[], "tests/fixtures/format/Security_short_selected.evtx");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let text = stdout(&output);
    assert!(text.contains("File header:"), "{text}");
    assert!(text.contains("Chunks (1):"), "{text}");
    assert!(text.contains("Summary:"), "{text}");
}

#[test]
fn inspect_bad_chunk_magic_exits_two() {
    let output = inspect(
        &[],
        "tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx",
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let text = stdout(&output);
    assert!(text.contains("bad_chunk_magic"), "{text}");
    assert!(text.contains("Summary:"), "{text}");
}

#[test]
fn inspect_text_file_exits_one_with_stderr_message() {
    let output = inspect(&[], "tests/fixtures/SOURCES.md");
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("error:"));
}

#[test]
fn inspect_json_output_parses_as_json() {
    let output = inspect(
        &["--json"],
        "tests/fixtures/format/Security_short_selected.evtx",
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(parsed["summary"]["total_chunks"], 1);
    assert_eq!(parsed["summary"]["total_records"], 7);
    assert!(parsed.get("records").is_none());
}

#[test]
fn inspect_json_with_records_lists_every_record() {
    let output = inspect(
        &["--json", "--records"],
        "tests/fixtures/format/Security_short_selected.evtx",
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        parsed["records"].as_array().unwrap().len() as u64,
        parsed["summary"]["total_records"].as_u64().unwrap()
    );
}

#[test]
fn inspect_records_flag_prints_every_record() {
    let output = inspect(
        &["--records"],
        "tests/fixtures/format/Security_short_selected.evtx",
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(stdout(&output).contains("Records (7):"));
}
