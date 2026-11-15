# Contributing to `evtx-triage`

## Scope

`evtx-triage` reads Windows `.evtx` logs, journald JSON exports, and Linux `audit.log` files offline to produce a UTC timeline with simple suspicion flags, plus an `inspect` subcommand for checking `.evtx` structure and checksums. The project exists to keep the EVTX format and triage logic in small, readable Rust code. It will not grow into a Sigma engine, a live analysis agent, or a memory or disk forensics suite.

## Setup

Install stable Rust (the crate targets edition 2024 in `Cargo.toml`). Build and try a change against the fixture logs:

```sh
cargo build
cargo run -- timeline tests/fixtures/attack-samples
cargo run -- inspect tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx
```

## Checks before a pull request

Run the three checks from `.github/workflows/ci.yml` before opening a pull request:

```sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

CI runs these commands on `ubuntu-latest` and `windows-latest`.

## Layout

- `src/main.rs`: CLI entry point, stdout/stderr setup, broken-pipe handling, and exit codes (0, 1, 2).
- `src/cli.rs`: `clap` parser definitions (`Cli`, `Command`, `TimelineArgs`, `InspectArgs`).
- `src/model.rs`: normalized `TimelineEvent`, `EventKind`, `SourceKind`, `Severity`, `Flag`, and `format_ts`.
- `src/pipeline.rs`: `run_timeline`, recursive file collection, filtering, sorting, detection, and `RunSummary`.
- `src/source/mod.rs`: `Source` trait, `Format` enum, `detect_format`, `detect_format_bytes`, and `source_for`.
- `src/source/evtx/`: `EvtxSource`, the dispatch table (`dispatch`) and per-event extractors (`account`, `fields`, `kerberos`, `logon`, `powershell`, `process`, `reader`, `service`, `task`).
- `src/source/journald.rs`: `JournaldSource` for `journalctl -o json` exports.
- `src/source/auditd.rs`: `AuditdSource` for Linux `audit.log` files.
- `src/detect/mod.rs`: `Rule` trait, `DetectOptions`, `default_rules`, and `run`, with rules in `encoded_powershell`, `remote_logon_service`, and `extras`.
- `src/output/mod.rs`: `write_jsonl`, `write_csv`, and `write_table` writers.
- `src/inspect/`: hand-written EVTX header, chunk, and record-framing checker (`inspect_file`, `inspect_bytes`).
- `tests/timeline_cli.rs` and `tests/inspect_cli.rs`: the main results of each subcommand against the fixture logs.
- `tests/cli.rs`: the interface itself: help, usage errors, exit codes, what goes to stdout and stderr, colors, odd paths.
- `tests/e2e.rs`: whole runs compared with the golden files in `tests/golden/`, plus scenarios such as mixed sources, damaged input and hostile text.

When `timeline` runs, `main` parses `Cli` and calls `pipeline::run_timeline`. `collect_files` walks the input paths, `source::detect_format` identifies each file by its bytes, and `source::source_for` returns a `Box<dyn Source>` whose `read` method appends `TimelineEvent` values. `process_events` sorts them by `TimelineEvent::sort_key`, runs every `Rule` from `detect::default_rules` through `detect::run`, and then applies `--from`, `--to`, `--event-id`, and `--flagged-only`. Finally `output::write_jsonl`, `output::write_csv`, or `output::write_table` writes the timeline.

## Rules the code follows

Treat input files as hostile. Avoid `unwrap` or `expect` on log data outside tests, prefix CSV cells starting with `=`, `+`, `-`, `@`, `\t`, or `\r` with an apostrophe in `src/output/csv.rs`, and pass terminal text through `printable` in `src/output/table.rs`, because log text can come from an attacker and end up in a spreadsheet or terminal.

Count and skip bad records instead of failing the run. `Source::read` records unreadable lines, records, or chunks in `SourceStats::errors` and returns `Err` only when a file as a whole cannot be read, so damaged logs still yield a partial timeline with exit status 2.

Dispatch Windows events by provider and event ID. `HANDLERS` in `src/source/evtx/dispatch.rs` keys every entry on `(provider, event_id)` rather than `EventID` alone, because IDs such as `1`, `104` and `4104` mean different things under different providers.

Use `snake_case` keys in `TimelineEvent::details`. Matching the `snake_case` enum serialization keeps JSONL output uniform for downstream tools.

Keep output deterministic. `collect_files` sorts directory entries by file name, `process_events` sorts events by `TimelineEvent::sort_key`, and `TimelineEvent::details` is a `BTreeMap`, so repeated runs produce identical output across platforms.

## Add a Windows event type

1. If no existing `EventKind` in `src/model.rs` fits, add a variant and update `EventKind::as_str`.
2. Write an extractor in the matching `src/source/evtx/*.rs` module with the helpers from `src/source/evtx/fields.rs`, and unit tests built from `serde_json::json!` records in the real shape.
3. Add one line for `(provider, event_id)` to `HANDLERS` in `src/source/evtx/dispatch.rs`. That table is the only list of supported events: the reader's early skip and the dispatch both read it, and its tests check every entry is handled.
4. If a fixture now produces more events, update the per-kind counts in its test in `src/source/evtx/reader.rs` and regenerate the golden files. Totals in the integration tests come from `tests/golden/windows.jsonl`, so they need no edit.
5. Add the event to the `Events` table in `README.md`.

## Add a detection rule

1. Implement `Rule` in `src/detect/extras.rs` or a new submodule of `src/detect/mod.rs`. Return a stable `snake_case` ID from `id`, and push `Flag` values in `apply` without reordering, adding, or removing events.
2. Register the rule in `detect::default_rules` in `src/detect/mod.rs` and add its ID to `default_rules_returns_each_rule_id_exactly_once`.
3. Write unit tests covering boundary conditions such as window edges and thresholds, and update `tests/timeline_cli.rs` if the rule fires on existing fixtures.
4. Add the rule to the `Suspicion flags` table in `README.md`.

## Add a log source

1. Add a variant to `SourceKind` in `src/model.rs` and `Format` in `src/source/mod.rs`.
2. Implement `Source` in a new module under `src/source/`, counting skipped records in `SourceStats::errors`.
3. Wire the format into `detect_format_bytes` and `source_for` in `src/source/mod.rs`, and document it in `README.md`.

## Tests

Unit tests live alongside the code in `src/` and test extractors, rules, format detection, and EVTX header parsing. The files in `tests/` run the compiled binary against `tests/fixtures/`.

`tests/golden/` holds the expected output for the fixture logs. When a change alters the output on purpose, regenerate the files and read the diff before committing it, because the diff is the review of your change:

```sh
cargo test --test e2e -- --ignored regenerate_golden_files
git diff tests/golden
```

Tests must pass on both Linux and Windows:

- Build paths with `Path::join` and normalize separators (`.replace('\\', "/")`) before comparing relative paths as strings, because Windows uses backslashes.
- Do not invoke shell commands or Unix utilities from tests; run the binary directly with `Command::new(env!("CARGO_BIN_EXE_evtx-triage"))`.
- Do not assert on the text of an operating system error. Linux and Windows word them differently; assert on the program's own message and on the file name.
- Set or remove `NO_COLOR` and `CLICOLOR_FORCE` on the `Command` in any test that looks at colors or exact text, because a CI runner may define them.
- Gate Unix-only tests such as symlink loops or broken-pipe tests with `#[cfg(unix)]`, because Windows handles symlinks and pipes differently.
- Leave `.gitattributes` intact (`*.evtx binary` and `tests/fixtures/** -text`), so Git does not alter line endings or bytes in fixture files on Windows.

## Fixtures

The logs in `tests/fixtures/attack-samples/` and `tests/fixtures/format/` are third-party files under their own licenses (GPL-3.0 and Apache-2.0). The ones in `tests/fixtures/linux/` are synthetic and were written for this project. When adding a third-party fixture, record its file name, source repository and commit, license, and SHA-256 hash in `tests/fixtures/SOURCES.md`. Keep those files unmodified so their hashes match upstream; a test that needs a damaged log copies the fixture to a temporary directory and alters the copy. `exclude = ["tests/fixtures"]` in `Cargo.toml` keeps fixtures out of the published crate, and the release workflow packages only the binary, the README and the license files.

## Commits and pull requests

Commit messages use Conventional Commit prefixes (`feat`, `fix`, `test`, `docs`, `ci`, `chore`, with an optional scope). Include a commit body that explains why the change was made.

## Releases

Pushing a version tag (`x.y.z`, no `v` prefix, equal to the `version` in `Cargo.toml`) triggers `.github/workflows/release.yml`, which runs `cargo test --locked`, builds release binaries for `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, and `x86_64-pc-windows-msvc`, packages each archive with `README.md`, `LICENSE-MIT`, and `LICENSE-APACHE`, and creates a GitHub Release with `SHA256SUMS`.

## License of contributions

This project is dual-licensed under `MIT OR Apache-2.0` (see `Cargo.toml`, `LICENSE-MIT`, and `LICENSE-APACHE`). Contributions are accepted under the same terms.
