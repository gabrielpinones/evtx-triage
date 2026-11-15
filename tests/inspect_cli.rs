use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

fn fixture_path(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}

#[test]
fn inspect_clean_fixture_exits_zero_and_prints_summary() {
    let fixture = fixture_path("tests/fixtures/format/Security_short_selected.evtx");
    let mut cmd = Command::cargo_bin("evtx-triage").unwrap();
    cmd.args(["inspect"])
        .arg(&fixture)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("File header:"))
        .stdout(predicate::str::contains("Chunks (1):"))
        .stdout(predicate::str::contains("Summary:"));
}

#[test]
fn inspect_bad_chunk_magic_exits_two() {
    let fixture = fixture_path("tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx");
    let mut cmd = Command::cargo_bin("evtx-triage").unwrap();
    cmd.args(["inspect"])
        .arg(&fixture)
        .assert()
        .code(2)
        .stdout(predicate::str::contains("bad_chunk_magic"))
        .stdout(predicate::str::contains("Summary:"));
}

#[test]
fn inspect_text_file_exits_one_with_stderr_message() {
    let text_file = fixture_path("tests/fixtures/SOURCES.md");
    let mut cmd = Command::cargo_bin("evtx-triage").unwrap();
    cmd.args(["inspect"])
        .arg(&text_file)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn inspect_json_output_parses_as_json() {
    let fixture = fixture_path("tests/fixtures/format/Security_short_selected.evtx");
    let mut cmd = Command::cargo_bin("evtx-triage").unwrap();
    let assert = cmd
        .args(["inspect", "--json"])
        .arg(&fixture)
        .assert()
        .code(0);
    let stdout = &assert.get_output().stdout;
    let parsed: serde_json::Value = serde_json::from_slice(stdout).unwrap();
    assert_eq!(parsed["summary"]["total_chunks"], 1);
    assert_eq!(parsed["summary"]["total_records"], 7);
    assert_eq!(parsed["records"].as_array().unwrap().len(), 7);
}

#[test]
fn inspect_records_flag_prints_every_record() {
    let fixture = fixture_path("tests/fixtures/format/Security_short_selected.evtx");
    let mut cmd = Command::cargo_bin("evtx-triage").unwrap();
    cmd.args(["inspect", "--records"])
        .arg(&fixture)
        .assert()
        .code(0)
        .stdout(predicate::str::contains("Records (7):"));
}
