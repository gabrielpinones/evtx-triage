//! Tests for the `evtx-triage` command-line interface: help, version, argument
//! parsing, usage and fatal errors, output streams, colors, and path handling.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use clap::Parser;
use jiff::{SignedDuration, Timestamp};
use serde_json::Value;

use evtx_triage::cli::{Cli, Command as CliCommand, OutputProfile};
use evtx_triage::model::EventKind;
use evtx_triage::pipeline::RunSummary;

fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn base_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_evtx-triage"));
    cmd.env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("TERM");
    cmd
}

fn run_cli(args: &[&str]) -> Output {
    base_cmd()
        .args(args)
        .output()
        .expect("evtx-triage binary runs")
}

fn run_cli_paths<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    base_cmd()
        .args(args)
        .output()
        .expect("evtx-triage binary runs")
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is UTF-8")
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is UTF-8")
}

fn assert_usage_error(output: &Output, context: &str) -> String {
    assert_eq!(
        output.status.code(),
        Some(2),
        "{context}: expected exit code 2, got {:?}\nstderr: {}",
        output.status.code(),
        stderr_str(output)
    );
    assert!(
        output.stdout.is_empty(),
        "{context}: expected empty stdout, got: {}",
        stdout_str(output)
    );
    let stderr = stderr_str(output);
    assert!(!stderr.is_empty(), "{context}: expected message on stderr");
    stderr
}

fn assert_fatal_error(output: &Output, context: &str) -> String {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{context}: expected exit code 1, got {:?}\nstderr: {}",
        output.status.code(),
        stderr_str(output)
    );
    assert!(
        output.stdout.is_empty(),
        "{context}: expected empty stdout, got: {}",
        stdout_str(output)
    );
    let stderr = stderr_str(output);
    assert!(
        stderr.lines().any(|line| line.starts_with("error:")),
        "{context}: expected a line starting with 'error:' on stderr, got:\n{stderr}"
    );
    stderr
}

fn parse_jsonl(bytes: &[u8]) -> Vec<Value> {
    String::from_utf8(bytes.to_vec())
        .expect("output is UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("each line is valid JSON"))
        .collect()
}

fn golden_windows_count() -> usize {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden/windows.jsonl");
    std::fs::read_to_string(path)
        .expect("golden windows.jsonl exists")
        .lines()
        .filter(|line| !line.is_empty())
        .count()
}

fn baseline_event_count(path: &std::path::Path) -> usize {
    let output = run_cli_paths(["timeline".as_ref(), path.as_os_str()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "baseline timeline failed: {}",
        stderr_str(&output)
    );
    let count = parse_jsonl(&output.stdout).len();
    assert!(
        count > 0,
        "baseline fixture {} produced no events",
        path.display()
    );
    count
}

/// Extracts `--flag` names for every `#[arg(...)]` option in `TimelineArgs`
/// from `src/cli.rs` so new options cannot be omitted from help untested.
fn timeline_option_flags_from_source() -> Vec<String> {
    let cli_rs = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/cli.rs");
    let src = fs::read_to_string(&cli_rs).expect("read src/cli.rs");

    let start = src
        .find("pub struct TimelineArgs")
        .expect("TimelineArgs struct exists in src/cli.rs");
    let body = &src[start..];
    let open = body.find('{').expect("TimelineArgs opening brace");
    let close = body[open..]
        .find("\n}")
        .expect("TimelineArgs closing brace");
    let fields_block = &body[open + 1..open + close];

    let mut flags = Vec::new();
    let mut pending_attrs = String::new();
    let mut in_attr = false;
    for raw_line in fields_block.lines() {
        let line = raw_line.trim();
        if line.starts_with("#[arg(") || in_attr {
            pending_attrs.push_str(line);
            pending_attrs.push(' ');
            in_attr = !line.ends_with(']');
            continue;
        }
        if let Some(rest) = line.strip_prefix("pub ")
            && let Some((name, _)) = rest.split_once(':')
        {
            let ident = name.trim();
            if pending_attrs.contains("long") {
                flags.push(format!("--{}", ident.replace('_', "-")));
            }
            if pending_attrs.contains("short")
                && let Some(ch) = ident.chars().next()
            {
                flags.push(format!("-{ch}"));
            }
            pending_attrs.clear();
        } else if !line.starts_with("//") && !line.is_empty() {
            pending_attrs.clear();
        }
    }
    flags
}

// ---------------------------------------------------------------------------
// Help and version
// ---------------------------------------------------------------------------

#[test]
fn top_level_help_exits_zero_and_lists_subcommands_examples_and_exit_status() {
    let long = run_cli(&["--help"]);
    assert_eq!(long.status.code(), Some(0), "status: {:?}", long.status);
    assert!(long.stderr.is_empty(), "stderr: {}", stderr_str(&long));
    let text = stdout_str(&long);
    assert!(text.contains("timeline"), "missing timeline in:\n{text}");
    assert!(text.contains("inspect"), "missing inspect in:\n{text}");
    assert!(text.contains("Examples:"), "missing Examples: in:\n{text}");
    assert!(
        text.contains("Exit status:"),
        "missing Exit status: in:\n{text}"
    );

    let short = run_cli(&["-h"]);
    assert_eq!(short.status.code(), Some(0), "status: {:?}", short.status);
    assert!(short.stderr.is_empty(), "stderr: {}", stderr_str(&short));
    let short_text = stdout_str(&short);
    assert!(
        short_text.contains("timeline") && short_text.contains("inspect"),
        "short help missing subcommands:\n{short_text}"
    );
}

#[test]
fn timeline_help_lists_every_struct_option_format_values_and_window_default() {
    let output = run_cli(&["timeline", "--help"]);
    assert_eq!(output.status.code(), Some(0), "status: {:?}", output.status);
    assert!(output.stderr.is_empty(), "stderr: {}", stderr_str(&output));
    let help = stdout_str(&output);

    let options = timeline_option_flags_from_source();
    assert!(
        options.len() >= 9,
        "expected at least 9 options in TimelineArgs, got {options:?}"
    );
    for opt in &options {
        assert!(
            help.contains(opt.as_str()),
            "option {opt} from TimelineArgs missing from `timeline --help`:\n{help}"
        );
    }

    for fmt in ["table", "jsonl", "csv"] {
        assert!(
            help.contains(fmt),
            "format value {fmt} missing from `timeline --help`:\n{help}"
        );
    }
    assert!(
        help.contains("[default: 5m]"),
        "default window 5m missing from `timeline --help`:\n{help}"
    );
    for profile in ["triage", "full", "[default: triage]"] {
        assert!(
            help.contains(profile),
            "profile token {profile} missing from `timeline --help`:\n{help}"
        );
    }
}

#[test]
fn inspect_help_lists_json_and_records() {
    let output = run_cli(&["inspect", "--help"]);
    assert_eq!(output.status.code(), Some(0), "status: {:?}", output.status);
    assert!(output.stderr.is_empty(), "stderr: {}", stderr_str(&output));
    let help = stdout_str(&output);
    assert!(help.contains("--json"), "missing --json in:\n{help}");
    assert!(help.contains("--records"), "missing --records in:\n{help}");
}

#[test]
fn help_timeline_matches_timeline_help() {
    let a = run_cli(&["help", "timeline"]);
    let b = run_cli(&["timeline", "--help"]);
    assert_eq!(a.status.code(), Some(0));
    assert_eq!(b.status.code(), Some(0));
    assert!(a.stderr.is_empty());
    assert_eq!(
        stdout_str(&a),
        stdout_str(&b),
        "`help timeline` differed from `timeline --help`"
    );
}

#[test]
fn version_flags_print_package_name_and_version() {
    let expected = format!("evtx-triage {}", env!("CARGO_PKG_VERSION"));
    for flag in ["--version", "-V"] {
        let output = run_cli(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}: {:?}", output.status);
        assert!(
            output.stderr.is_empty(),
            "{flag} stderr: {}",
            stderr_str(&output)
        );
        assert_eq!(
            stdout_str(&output).trim(),
            expected,
            "{flag} printed unexpected version"
        );
    }
}

#[test]
fn every_example_in_help_parses_without_error() {
    let output = run_cli(&["--help"]);
    assert_eq!(output.status.code(), Some(0));
    let help = stdout_str(&output);

    let examples_start = help.find("Examples:").expect("Examples: section in --help");
    let examples_section = &help[examples_start..];
    let examples_end = examples_section
        .find("Exit status:")
        .unwrap_or(examples_section.len());
    let examples_block = &examples_section[..examples_end];

    let mut count = 0usize;
    for line in examples_block.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("evtx-triage") {
            count += 1;
            let tokens: Vec<&str> = trimmed.split_whitespace().collect();
            let parsed = Cli::try_parse_from(&tokens);
            assert!(
                parsed.is_ok(),
                "example {trimmed:?} failed to parse: {:?}",
                parsed.err()
            );
        }
    }
    assert!(count > 0, "no examples found under Examples: in:\n{help}");
}

// ---------------------------------------------------------------------------
// Usage errors (exit 2, message on stderr, empty stdout)
// ---------------------------------------------------------------------------

#[test]
fn no_arguments_is_a_usage_error() {
    let output = run_cli(&[]);
    assert_usage_error(&output, "no arguments");
}

#[test]
fn unknown_subcommand_is_a_usage_error() {
    let output = run_cli(&["frobnicate"]);
    assert_usage_error(&output, "unknown subcommand");
}

#[test]
fn unknown_option_is_a_usage_error() {
    let output = run_cli(&["timeline", "--does-not-exist", "a.evtx"]);
    assert_usage_error(&output, "unknown option");
}

#[test]
fn timeline_without_paths_is_a_usage_error() {
    let output = run_cli(&["timeline"]);
    assert_usage_error(&output, "timeline without paths");
}

#[test]
fn inspect_without_file_or_with_two_files_is_a_usage_error() {
    assert_usage_error(&run_cli(&["inspect"]), "inspect without file");
    assert_usage_error(
        &run_cli(&["inspect", "a.evtx", "b.evtx"]),
        "inspect with two files",
    );
}

#[test]
fn invalid_format_lists_possible_values() {
    let output = run_cli(&["timeline", "--format", "xml", "a.evtx"]);
    let stderr = assert_usage_error(&output, "--format xml");
    for allowed in ["table", "jsonl", "csv"] {
        assert!(
            stderr.contains(allowed),
            "expected {allowed} in possible values message, got:\n{stderr}"
        );
    }
}

#[test]
fn invalid_profile_lists_possible_values() {
    let output = run_cli(&["timeline", "--profile", "fast", "a.evtx"]);
    let stderr = assert_usage_error(&output, "--profile fast");
    for allowed in ["triage", "full"] {
        assert!(
            stderr.contains(allowed),
            "expected {allowed} in possible values message, got:\n{stderr}"
        );
    }
}

#[test]
fn unknown_kind_and_exclude_kind_list_valid_names() {
    let cases = [
        vec!["timeline", "--kind", "nope", "a.evtx"],
        vec!["timeline", "--kind", "process_create,nope", "a.evtx"],
        vec!["timeline", "--exclude-kind", "nope", "a.evtx"],
    ];
    for args in &cases {
        let output = run_cli(args);
        let stderr = assert_usage_error(&output, &args.join(" "));
        assert!(
            stderr.contains("nope"),
            "expected bad name in stderr:\n{stderr}"
        );
        for &kind in EventKind::ALL {
            assert!(
                stderr.contains(kind.as_str()),
                "missing valid kind '{}' in error:\n{stderr}",
                kind.as_str()
            );
        }
    }
}

#[test]
fn invalid_from_and_to_timestamps_are_usage_errors() {
    assert_usage_error(
        &run_cli(&["timeline", "--from", "not-a-time", "a.evtx"]),
        "invalid --from",
    );
    assert_usage_error(
        &run_cli(&["timeline", "--to", "yesterday", "a.evtx"]),
        "invalid --to",
    );
}

#[test]
fn invalid_window_duration_is_a_usage_error() {
    assert_usage_error(
        &run_cli(&["timeline", "--window", "forever", "a.evtx"]),
        "invalid --window",
    );
}

#[test]
fn invalid_event_id_is_a_usage_error() {
    assert_usage_error(
        &run_cli(&["timeline", "--event-id", "abc", "a.evtx"]),
        "non-numeric --event-id",
    );
    assert_usage_error(
        &run_cli(&["timeline", "--event-id", "4294967296", "a.evtx"]),
        "overflow --event-id",
    );
}

#[test]
fn option_requiring_value_without_one_is_a_usage_error() {
    assert_usage_error(
        &run_cli(&["timeline", "a.evtx", "-o"]),
        "-o at end of command line",
    );
}

// ---------------------------------------------------------------------------
// Accepted arguments
// ---------------------------------------------------------------------------

#[test]
fn window_accepts_duration_forms() {
    let cases = [
        ("90s", SignedDuration::from_secs(90)),
        ("5m", SignedDuration::from_mins(5)),
        ("1h", SignedDuration::from_hours(1)),
        ("2h30m", SignedDuration::from_secs(2 * 3600 + 30 * 60)),
    ];
    for (raw, expected) in cases {
        let cli = Cli::try_parse_from(["evtx-triage", "timeline", "--window", raw, "a.evtx"])
            .unwrap_or_else(|e| panic!("--window {raw} failed to parse: {e}"));
        let CliCommand::Timeline(args) = cli.command else {
            panic!("expected timeline command");
        };
        assert_eq!(args.window, expected, "--window {raw}");
    }

    let sample = fixture("format/Security_short_selected.evtx");
    let output = run_cli_paths([
        "timeline".as_ref(),
        "--window".as_ref(),
        "2h30m".as_ref(),
        sample.as_os_str(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "binary rejected --window 2h30m: {}",
        stderr_str(&output)
    );
}

#[test]
fn from_accepts_utc_fractional_and_offset_timestamps() {
    let utc_midnight: Timestamp = "2024-05-01T00:00:00Z".parse().unwrap();
    let utc_frac: Timestamp = "2024-05-01T00:00:00.123456Z".parse().unwrap();

    for (raw, expected) in [
        ("2024-05-01T00:00:00Z", utc_midnight),
        ("2024-05-01T00:00:00.123456Z", utc_frac),
        ("2024-05-01T02:00:00+02:00", utc_midnight),
    ] {
        let cli = Cli::try_parse_from(["evtx-triage", "timeline", "--from", raw, "a.evtx"])
            .unwrap_or_else(|e| panic!("--from {raw} failed to parse: {e}"));
        let CliCommand::Timeline(args) = cli.command else {
            panic!("expected timeline command");
        };
        assert_eq!(args.from, Some(expected), "--from {raw}");
    }

    // Events in Security_short_selected.evtx are at 2016-06-29T15:24:36.686000Z.
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);
    let output = run_cli_paths([
        "timeline".as_ref(),
        "--from".as_ref(),
        "2016-06-29T17:24:36+02:00".as_ref(),
        sample.as_os_str(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&output)
    );
    assert_eq!(parse_jsonl(&output.stdout).len(), expected);
}

#[test]
fn event_id_comma_and_repeated_flags_give_same_list() {
    let comma = Cli::try_parse_from([
        "evtx-triage",
        "timeline",
        "--event-id",
        "4624,7045",
        "a.evtx",
    ])
    .expect("comma-separated --event-id parses");
    let repeated = Cli::try_parse_from([
        "evtx-triage",
        "timeline",
        "--event-id",
        "4624",
        "--event-id",
        "7045",
        "a.evtx",
    ])
    .expect("repeated --event-id parses");

    let CliCommand::Timeline(a) = comma.command else {
        panic!("expected timeline");
    };
    let CliCommand::Timeline(b) = repeated.command else {
        panic!("expected timeline");
    };
    assert_eq!(a.event_id, vec![4624, 7045]);
    assert_eq!(a.event_id, b.event_id);
}

#[test]
fn short_and_long_output_and_quiet_flags_are_equivalent() {
    let short = Cli::try_parse_from(["evtx-triage", "timeline", "-o", "out.jsonl", "-q", "a.evtx"])
        .expect("short flags parse");
    let long = Cli::try_parse_from([
        "evtx-triage",
        "timeline",
        "--output",
        "out.jsonl",
        "--quiet",
        "a.evtx",
    ])
    .expect("long flags parse");

    let CliCommand::Timeline(a) = short.command else {
        panic!("expected timeline");
    };
    let CliCommand::Timeline(b) = long.command else {
        panic!("expected timeline");
    };
    assert_eq!(a.output, b.output);
    assert_eq!(a.quiet, b.quiet);
    assert!(a.quiet);

    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("out.jsonl");
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);
    let output = run_cli_paths([
        "timeline".as_ref(),
        "--output".as_ref(),
        out_path.as_os_str(),
        "-q".as_ref(),
        sample.as_os_str(),
    ]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    assert_eq!(parse_jsonl(&fs::read(&out_path).unwrap()).len(), expected);
}

#[test]
fn options_may_precede_or_follow_paths() {
    let before = Cli::try_parse_from([
        "evtx-triage",
        "timeline",
        "--format",
        "csv",
        "--flagged-only",
        "--host",
        "web01",
        "a.evtx",
    ])
    .expect("options before path");
    let after = Cli::try_parse_from([
        "evtx-triage",
        "timeline",
        "a.evtx",
        "--format",
        "csv",
        "--flagged-only",
        "--host",
        "web01",
    ])
    .expect("options after path");

    let CliCommand::Timeline(a) = before.command else {
        panic!("expected timeline");
    };
    let CliCommand::Timeline(b) = after.command else {
        panic!("expected timeline");
    };
    assert_eq!(a.paths, b.paths);
    assert_eq!(a.format, b.format);
    assert_eq!(a.flagged_only, b.flagged_only);
    assert_eq!(a.host, b.host);

    let sample = fixture("format/Security_short_selected.evtx");
    let out_before = run_cli_paths([
        "timeline".as_ref(),
        "--format".as_ref(),
        "csv".as_ref(),
        "--event-id".as_ref(),
        "4625".as_ref(),
        sample.as_os_str(),
    ]);
    let out_after = run_cli_paths([
        "timeline".as_ref(),
        sample.as_os_str(),
        "--format".as_ref(),
        "csv".as_ref(),
        "--event-id".as_ref(),
        "4625".as_ref(),
    ]);
    assert_eq!(out_before.status.code(), Some(0));
    assert_eq!(out_after.status.code(), Some(0));
    assert_eq!(out_before.stdout, out_after.stdout);
}

#[test]
fn path_beginning_with_dash_works_after_double_dash() {
    let parsed = Cli::try_parse_from(["evtx-triage", "timeline", "--", "-weird.evtx"])
        .expect("dash path after -- parses");
    let CliCommand::Timeline(args) = parsed.command else {
        panic!("expected timeline");
    };
    assert_eq!(args.paths, vec![PathBuf::from("-weird.evtx")]);

    let dir = tempfile::tempdir().unwrap();
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);
    let target = dir.path().join("-weird.evtx");
    fs::copy(&sample, &target).unwrap();

    let output = base_cmd()
        .current_dir(dir.path())
        .args(["timeline", "--", "-weird.evtx"])
        .output()
        .expect("binary runs");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&output)
    );
    let events = parse_jsonl(&output.stdout);
    assert_eq!(events.len(), expected);
    assert!(events.iter().all(|event| event["file"] == "-weird.evtx"));
}

// ---------------------------------------------------------------------------
// Fatal errors (exit 1, `error:` line on stderr, empty stdout)
// ---------------------------------------------------------------------------

#[test]
fn timeline_missing_path_exits_one_and_names_path() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("no_such_log.evtx");
    let output = run_cli_paths(["timeline".as_ref(), missing.as_os_str()]);
    let stderr = assert_fatal_error(&output, "timeline missing path");
    assert!(
        stderr.contains("no_such_log.evtx"),
        "expected missing path in stderr:\n{stderr}"
    );
}

#[test]
fn timeline_output_into_missing_directory_exits_one_and_leaves_no_partial_file() {
    let dir = tempfile::tempdir().unwrap();
    let out_file = dir.path().join("absent_subdir").join("timeline.jsonl");
    let sample = fixture("format/Security_short_selected.evtx");

    let output = run_cli_paths([
        "timeline".as_ref(),
        "-o".as_ref(),
        out_file.as_os_str(),
        sample.as_os_str(),
    ]);
    let stderr = assert_fatal_error(&output, "timeline -o missing dir");
    assert!(
        stderr.contains("cannot create"),
        "expected 'cannot create' in stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("timeline.jsonl"),
        "expected output file name in stderr:\n{stderr}"
    );
    assert_eq!(
        fs::read_dir(dir.path()).unwrap().count(),
        0,
        "no file or directory should be created in tempdir"
    );
}

#[test]
fn inspect_missing_directory_and_non_evtx_exit_one_and_name_file() {
    let dir = tempfile::tempdir().unwrap();

    let missing = dir.path().join("missing_inspect.evtx");
    let out_missing = run_cli_paths(["inspect".as_ref(), missing.as_os_str()]);
    let err_missing = assert_fatal_error(&out_missing, "inspect missing file");
    assert!(
        err_missing.contains("missing_inspect.evtx"),
        "expected file name in stderr:\n{err_missing}"
    );

    let sub = dir.path().join("some_dir");
    fs::create_dir(&sub).unwrap();
    let out_dir = run_cli_paths(["inspect".as_ref(), sub.as_os_str()]);
    let err_dir = assert_fatal_error(&out_dir, "inspect directory");
    assert!(
        err_dir.contains("some_dir"),
        "expected dir name in stderr:\n{err_dir}"
    );

    let plain = dir.path().join("not_an_evtx.txt");
    fs::write(&plain, b"hello world\n").unwrap();
    let out_plain = run_cli_paths(["inspect".as_ref(), plain.as_os_str()]);
    let err_plain = assert_fatal_error(&out_plain, "inspect non-EVTX");
    assert!(
        err_plain.contains("not_an_evtx.txt"),
        "expected file name in stderr:\n{err_plain}"
    );
}

#[test]
fn timeline_over_empty_directory_exits_one() {
    let dir = tempfile::tempdir().unwrap();
    let output = run_cli_paths(["timeline".as_ref(), dir.path().as_os_str()]);
    assert_fatal_error(&output, "timeline over empty dir");
}

// ---------------------------------------------------------------------------
// Where output goes
// ---------------------------------------------------------------------------

#[test]
fn timeline_puts_events_on_stdout_and_summary_and_cli_warnings_on_stderr() {
    let dir = tempfile::tempdir().unwrap();
    let skipped = dir.path().join("notes.txt");
    fs::write(&skipped, b"plain text\n").unwrap();
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);

    let output = run_cli_paths(["timeline".as_ref(), sample.as_os_str(), skipped.as_os_str()]);
    assert_eq!(output.status.code(), Some(0), "status: {:?}", output.status);
    let events = parse_jsonl(&output.stdout);
    assert_eq!(events.len(), expected);

    let stderr = stderr_str(&output);
    assert!(
        stderr
            .lines()
            .any(|l| l.starts_with("warning:") && l.contains("notes.txt")),
        "expected warning for skipped CLI file on stderr:\n{stderr}"
    );
    let expected_summary = if expected == 1 {
        "1 event from 1 file".to_owned()
    } else {
        format!("{expected} events from 1 file")
    };
    assert!(
        stderr.contains(&expected_summary),
        "expected summary on stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("1 file skipped"),
        "expected skipped count in summary:\n{stderr}"
    );
}

#[test]
fn timeline_quiet_hides_summary_on_stderr() {
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);
    let output = run_cli_paths(["timeline".as_ref(), "--quiet".as_ref(), sample.as_os_str()]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(parse_jsonl(&output.stdout).len(), expected);
    assert!(
        output.stderr.is_empty(),
        "expected empty stderr with --quiet, got: {}",
        stderr_str(&output)
    );
}

#[test]
fn inspect_writes_report_to_stdout_and_nothing_to_stderr() {
    let clean = fixture("format/Security_short_selected.evtx");
    let damaged = fixture("format/sample_with_a_bad_chunk_magic.evtx");

    for (path, expected_code, args) in [
        (&clean, 0, vec!["inspect"]),
        (&clean, 0, vec!["inspect", "--json"]),
        (&damaged, 2, vec!["inspect"]),
        (&damaged, 2, vec!["inspect", "--json"]),
    ] {
        let mut full_args: Vec<&std::ffi::OsStr> = args.iter().map(AsRef::as_ref).collect();
        full_args.push(path.as_os_str());
        let output = run_cli_paths(full_args);
        assert_eq!(output.status.code(), Some(expected_code));
        assert!(!output.stdout.is_empty(), "expected report on stdout");
        assert!(
            output.stderr.is_empty(),
            "expected empty stderr for inspect, got: {}",
            stderr_str(&output)
        );
    }
}

#[test]
fn inspect_json_omits_records_by_default_and_includes_them_with_records_flag() {
    let clean = fixture("format/Security_short_selected.evtx");
    let without = run_cli_paths(["inspect".as_ref(), "--json".as_ref(), clean.as_os_str()]);
    let with = run_cli_paths([
        "inspect".as_ref(),
        "--json".as_ref(),
        "--records".as_ref(),
        clean.as_os_str(),
    ]);

    assert_eq!(without.status.code(), Some(0));
    assert_eq!(with.status.code(), Some(0));
    let without_json: Value = serde_json::from_slice(&without.stdout).expect("valid JSON");
    assert!(
        without_json.get("records").is_none(),
        "inspect --json without --records must omit `records`"
    );

    let mut with_json: Value = serde_json::from_slice(&with.stdout).expect("valid JSON");
    let total_records = with_json["summary"]["total_records"].as_u64().unwrap();
    let records = with_json["records"]
        .as_array()
        .expect("inspect --json --records must include `records`");
    assert_eq!(records.len() as u64, total_records);

    with_json.as_object_mut().unwrap().remove("records");
    assert_eq!(
        without_json, with_json,
        "--records should only add the `records` field to --json output"
    );
}

// ---------------------------------------------------------------------------
// Colors
// ---------------------------------------------------------------------------

#[test]
fn table_and_summary_have_no_ansi_codes_by_default_or_with_no_color() {
    let samples = fixture("attack-samples");
    let default_out = run_cli_paths([
        "timeline".as_ref(),
        "--format".as_ref(),
        "table".as_ref(),
        samples.as_os_str(),
    ]);
    assert_eq!(default_out.status.code(), Some(0));
    assert!(
        !stdout_str(&default_out).contains('\x1b'),
        "default captured table stdout contained ANSI escape"
    );
    assert!(
        !stderr_str(&default_out).contains('\x1b'),
        "default captured stderr summary contained ANSI escape"
    );

    let no_color_out = base_cmd()
        .env("NO_COLOR", "1")
        .args(["timeline", "--format", "table"])
        .arg(&samples)
        .output()
        .unwrap();
    assert_eq!(no_color_out.status.code(), Some(0));
    assert!(
        !stdout_str(&no_color_out).contains('\x1b'),
        "NO_COLOR=1 table stdout contained ANSI escape"
    );
    assert!(
        !stderr_str(&no_color_out).contains('\x1b'),
        "NO_COLOR=1 stderr summary contained ANSI escape"
    );
}

#[test]
fn table_outputs_ansi_codes_when_clicolor_force_is_set() {
    let samples = fixture("attack-samples");
    let output = base_cmd()
        .env("CLICOLOR_FORCE", "1")
        .args(["timeline", "--format", "table"])
        .arg(&samples)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let stdout = stdout_str(&output);
    assert!(
        stdout.contains("\x1b["),
        "expected ANSI escape codes with CLICOLOR_FORCE=1, got:\n{stdout}"
    );
}

#[test]
fn jsonl_and_csv_never_contain_ansi_codes_even_with_clicolor_force() {
    let clean = fixture("format/Security_short_selected.evtx");
    for format in ["jsonl", "csv"] {
        let output = base_cmd()
            .env("CLICOLOR_FORCE", "1")
            .args(["timeline", "--format", format])
            .arg(&clean)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0));
        let stdout = stdout_str(&output);
        assert!(
            !stdout.contains('\x1b'),
            "{format} stdout contained ANSI escape with CLICOLOR_FORCE=1:\n{stdout}"
        );
    }
}

#[test]
fn inspect_text_has_no_ansi_by_default_and_json_never_has_ansi() {
    let damaged = fixture("format/sample_with_a_bad_chunk_magic.evtx");

    let text_out = run_cli_paths(["inspect".as_ref(), damaged.as_os_str()]);
    assert_eq!(text_out.status.code(), Some(2));
    assert!(
        !stdout_str(&text_out).contains('\x1b'),
        "captured inspect text output contained ANSI escape"
    );

    let json_out = base_cmd()
        .env("CLICOLOR_FORCE", "1")
        .args(["inspect", "--json"])
        .arg(&damaged)
        .output()
        .unwrap();
    assert_eq!(json_out.status.code(), Some(2));
    assert!(
        !stdout_str(&json_out).contains('\x1b'),
        "inspect --json contained ANSI escape with CLICOLOR_FORCE=1"
    );
}

// ---------------------------------------------------------------------------
// Default format
// ---------------------------------------------------------------------------

#[test]
fn default_format_is_jsonl_for_captured_stdout_and_output_file() {
    let clean = fixture("format/Security_short_selected.evtx");

    let stdout_run = run_cli_paths(["timeline".as_ref(), clean.as_os_str()]);
    assert_eq!(stdout_run.status.code(), Some(0));
    let first_line = stdout_str(&stdout_run)
        .lines()
        .next()
        .expect("at least one line")
        .to_string();
    let parsed: Value = serde_json::from_str(&first_line).expect("first stdout line is JSON");
    assert!(parsed.is_object(), "expected JSON object, got {parsed:?}");

    let dir = tempfile::tempdir().unwrap();
    let out_path = dir.path().join("timeline.out");
    let file_run = run_cli_paths([
        "timeline".as_ref(),
        "-o".as_ref(),
        out_path.as_os_str(),
        clean.as_os_str(),
    ]);
    assert_eq!(file_run.status.code(), Some(0));
    assert!(file_run.stdout.is_empty());
    let file_text = fs::read_to_string(&out_path).unwrap();
    let file_first_line = file_text
        .lines()
        .next()
        .expect("file has at least one line");
    let file_parsed: Value =
        serde_json::from_str(file_first_line).expect("first file line is JSON");
    assert!(
        file_parsed.is_object(),
        "expected JSON object in -o file, got {file_parsed:?}"
    );
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

#[test]
fn filename_with_spaces_and_non_ascii_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let name = "registro de auditoría.evtx";
    let target = dir.path().join(name);
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);
    fs::copy(&sample, &target).unwrap();

    let output = run_cli_paths(["timeline".as_ref(), target.as_os_str()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&output)
    );
    let events = parse_jsonl(&output.stdout);
    assert_eq!(events.len(), expected);
    for event in &events {
        let file_field = event["file"].as_str().expect("file field is string");
        assert!(
            file_field.ends_with(name),
            "expected file field to end with {name:?}, got {file_field:?}"
        );
    }
}

#[test]
fn duplicate_file_argument_emits_events_twice() {
    let clean = fixture("format/Security_short_selected.evtx");
    let output = run_cli_paths(["timeline".as_ref(), clean.as_os_str(), clean.as_os_str()]);
    assert_eq!(output.status.code(), Some(0));
    let events = parse_jsonl(&output.stdout);
    assert_eq!(events.len(), 4, "expected each event twice without dedup");
    assert_eq!(events[0], events[1]);
    assert_eq!(events[2], events[3]);
    let stderr = stderr_str(&output);
    assert!(
        stderr.contains("4 events from 2 files"),
        "expected '4 events from 2 files' in stderr:\n{stderr}"
    );
}

#[test]
fn directory_with_and_without_trailing_separator_gives_same_events() {
    let dir = fixture("attack-samples");
    let with_sep = format!("{}{}", dir.display(), std::path::MAIN_SEPARATOR);

    let without_out = run_cli_paths(["timeline".as_ref(), dir.as_os_str()]);
    let with_out = run_cli(&["timeline", &with_sep]);

    assert_eq!(without_out.status.code(), Some(0));
    assert_eq!(with_out.status.code(), Some(0));

    let events_without = parse_jsonl(&without_out.stdout);
    let events_with = parse_jsonl(&with_out.stdout);
    assert!(!events_without.is_empty());
    assert_eq!(events_without.len(), golden_windows_count());
    assert_eq!(
        events_without, events_with,
        "trailing separator changed emitted events"
    );
}

#[cfg(unix)]
#[test]
fn symlink_to_file_given_directly_is_followed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("linked.evtx");
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);
    symlink(&sample, &link).unwrap();

    let output = run_cli_paths(["timeline".as_ref(), link.as_os_str()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&output)
    );
    assert_eq!(parse_jsonl(&output.stdout).len(), expected);
}

#[cfg(unix)]
#[test]
fn symlink_loop_inside_directory_does_not_hang() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir(&sub).unwrap();
    let sample = fixture("format/Security_short_selected.evtx");
    let expected = baseline_event_count(&sample);
    fs::copy(&sample, sub.join("real.evtx")).unwrap();
    symlink(dir.path(), sub.join("loop")).unwrap();

    let output = run_cli_paths(["timeline".as_ref(), dir.path().as_os_str()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        stderr_str(&output)
    );
    assert_eq!(parse_jsonl(&output.stdout).len(), expected);
}

#[test]
fn profile_kind_and_exclude_kind_cli_parsing_and_filtering() {
    let cli = Cli::try_parse_from([
        "evtx-triage",
        "timeline",
        "a.evtx",
        "--profile",
        "full",
        "--kind",
        "logon_success,process_create",
        "--exclude-kind",
        "logoff",
    ])
    .expect("new filter options parse");
    let CliCommand::Timeline(args) = cli.command else {
        panic!("expected timeline");
    };
    assert_eq!(args.profile, OutputProfile::Full);
    assert_eq!(
        args.kind,
        [EventKind::LogonSuccess, EventKind::ProcessCreate]
    );
    assert_eq!(args.exclude_kind, [EventKind::Logoff]);

    let sample = fixture("attack-samples/4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx");
    let full = run_cli_paths([
        "timeline".as_ref(),
        "--profile".as_ref(),
        "full".as_ref(),
        sample.as_os_str(),
    ]);
    assert_eq!(full.status.code(), Some(0));
    let full_events = parse_jsonl(&full.stdout);
    assert!(full_events.len() >= 2);

    let only_clear = run_cli_paths([
        "timeline".as_ref(),
        "--kind".as_ref(),
        "log_clear".as_ref(),
        sample.as_os_str(),
    ]);
    assert_eq!(only_clear.status.code(), Some(0));
    let clear_events = parse_jsonl(&only_clear.stdout);
    assert!(!clear_events.is_empty());
    assert!(clear_events.iter().all(|e| e["kind"] == "log_clear"));

    let excl_clear = run_cli_paths([
        "timeline".as_ref(),
        "--exclude-kind".as_ref(),
        "log_clear".as_ref(),
        sample.as_os_str(),
    ]);
    assert_eq!(excl_clear.status.code(), Some(0));
    let excl_events = parse_jsonl(&excl_clear.stdout);
    assert!(!excl_events.iter().any(|e| e["kind"] == "log_clear"));
    assert_eq!(
        excl_events.len() + clear_events.len(),
        full_events.len(),
        "excluding log_clear should drop only log_clear events"
    );
}

#[test]
fn triage_hidden_stderr_line_matches_contract() {
    let summary = RunSummary {
        files_read: 2,
        events_written: 15,
        events_hidden: 1204,
        ..Default::default()
    };
    let rendered = summary.render();
    let plain = anstream::adapter::strip_str(&rendered).to_string();
    assert!(
        plain
            .lines()
            .any(|line| line
                == "1204 events hidden by the triage profile (--profile full shows them)"),
        "expected hidden count line on its own line, got:\n{plain}"
    );

    let clean = fixture("format/Security_short_selected.evtx");
    let out = run_cli_paths(["timeline".as_ref(), clean.as_os_str()]);
    assert_eq!(out.status.code(), Some(0));
    let stderr = stderr_str(&out);
    assert!(
        !stderr.contains("hidden by the triage profile"),
        "should not print hidden line when 0 events are hidden:\n{stderr}"
    );
}
