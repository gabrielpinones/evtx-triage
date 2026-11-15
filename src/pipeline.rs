//! Timeline pipeline: collect files, read, filter, sort, detect, write.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use jiff::{SignedDuration, Timestamp};

use crate::cli::OutputFormat;
use crate::detect::{self, DetectOptions};
use crate::model::TimelineEvent;
use crate::output;
use crate::source::{self, ReadOptions};

/// Everything `run_timeline` needs, already parsed from the command line.
#[derive(Debug, Clone)]
pub struct TimelineOptions {
    /// Files or directories. Directories are walked recursively.
    pub paths: Vec<PathBuf>,
    pub format: OutputFormat,
    /// Inclusive lower bound.
    pub from: Option<Timestamp>,
    /// Exclusive upper bound.
    pub to: Option<Timestamp>,
    /// Empty means every supported event id.
    pub event_ids: Vec<u32>,
    pub flagged_only: bool,
    /// Correlation window handed to the detection rules.
    pub window: SignedDuration,
    pub read: ReadOptions,
}

/// Counters for one run, printed on stderr by `main`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunSummary {
    pub files_read: u64,
    /// Files that are none of the supported formats.
    pub files_skipped: u64,
    /// Files of a supported format that could not be read at all.
    pub files_failed: u64,
    pub records_seen: u64,
    /// Records, lines or chunks skipped because they could not be parsed.
    pub record_errors: u64,
    pub events_written: u64,
    pub events_flagged: u64,
}

impl RunSummary {
    /// True when the timeline is missing data because of damaged input.
    pub fn is_partial(&self) -> bool {
        self.files_failed > 0 || self.record_errors > 0
    }
}

impl fmt::Display for RunSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} events ({} flagged) from {} files; {} records seen, {} unreadable; {} files skipped, {} failed",
            self.events_written,
            self.events_flagged,
            self.files_read,
            self.records_seen,
            self.record_errors,
            self.files_skipped,
            self.files_failed,
        )
    }
}

/// Builds the timeline and writes it to `out`.
///
/// Returns `Err` only when no input file could be read. Damaged records and
/// unreadable files are counted in the summary instead.
pub fn run_timeline(options: &TimelineOptions, out: &mut dyn Write) -> anyhow::Result<RunSummary> {
    let files = collect_files(&options.paths)?;
    let mut summary = RunSummary::default();
    let mut events = Vec::new();

    for input in files {
        match source::detect_format(&input.path) {
            Err(e) => {
                summary.files_failed += 1;
                eprintln!("warning: {}: {e}", input.path.display());
            }
            Ok(None) => {
                summary.files_skipped += 1;
                if input.direct_cli {
                    eprintln!("warning: {}: unknown log format", input.path.display());
                }
            }
            Ok(Some(format)) => {
                match source::source_for(format).read(&input.path, &options.read, &mut events) {
                    Ok(stats) => {
                        summary.files_read += 1;
                        summary.records_seen += stats.records_seen;
                        summary.record_errors += stats.errors;
                    }
                    Err(e) => {
                        summary.files_failed += 1;
                        eprintln!("warning: {}: {e:#}", input.path.display());
                    }
                }
            }
        }
    }

    if summary.files_read == 0 {
        anyhow::bail!(
            "no input files could be read ({} skipped, {} failed)",
            summary.files_skipped,
            summary.files_failed
        );
    }

    let final_events = process_events(events, options);
    match options.format {
        OutputFormat::Jsonl => output::write_jsonl(out, &final_events)?,
        OutputFormat::Csv => output::write_csv(out, &final_events)?,
    }

    summary.events_written = final_events.len() as u64;
    summary.events_flagged = final_events.iter().filter(|e| !e.flags.is_empty()).count() as u64;
    Ok(summary)
}

#[derive(Debug)]
struct InputFile {
    path: PathBuf,
    direct_cli: bool,
}

fn collect_files(paths: &[PathBuf]) -> anyhow::Result<Vec<InputFile>> {
    let mut files = Vec::new();
    for path in paths {
        // Follow symlinks given directly on the CLI, while walk_dir skips
        // symlinks inside directories to avoid loops.
        let meta =
            fs::metadata(path).with_context(|| format!("cannot access {}", path.display()))?;
        if meta.is_dir() {
            walk_dir(path, &mut files);
        } else {
            files.push(InputFile {
                path: path.clone(),
                direct_cli: true,
            });
        }
    }
    Ok(files)
}

fn walk_dir(dir: &Path, files: &mut Vec<InputFile>) {
    let entries = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("warning: {}: {e}", dir.display());
            return;
        }
    };

    let mut children = Vec::new();
    for entry in entries {
        match entry {
            Ok(e) => children.push(e),
            Err(e) => eprintln!("warning: {}: {e}", dir.display()),
        }
    }
    children.sort_by_key(|e| e.file_name());

    for entry in children {
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(ft) => ft,
            Err(e) => {
                eprintln!("warning: {}: {e}", path.display());
                continue;
            }
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk_dir(&path, files);
        } else if file_type.is_file() {
            files.push(InputFile {
                path,
                direct_cli: false,
            });
        }
    }
}

fn process_events(mut events: Vec<TimelineEvent>, options: &TimelineOptions) -> Vec<TimelineEvent> {
    events.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));

    let rules = detect::default_rules(&DetectOptions {
        window: options.window,
        ..Default::default()
    });
    detect::run(&mut events, &rules);

    events.retain(|event| {
        options.from.is_none_or(|from| event.ts >= from)
            && options.to.is_none_or(|to| event.ts < to)
            && (options.event_ids.is_empty()
                || event
                    .event_id
                    .is_some_and(|id| options.event_ids.contains(&id)))
            && (!options.flagged_only || !event.flags.is_empty())
    });

    events
}

#[cfg(test)]
mod tests {
    use std::fs;

    use jiff::{SignedDuration, Timestamp};
    use tempfile::TempDir;

    use crate::cli::OutputFormat;
    use crate::model::{EventKind, Flag, Severity, SourceKind, TimelineEvent};
    use crate::source::ReadOptions;

    use super::{TimelineOptions, collect_files, process_events, run_timeline};

    fn default_options() -> TimelineOptions {
        TimelineOptions {
            paths: Vec::new(),
            format: OutputFormat::Jsonl,
            from: None,
            to: None,
            event_ids: Vec::new(),
            flagged_only: false,
            window: SignedDuration::from_mins(5),
            read: ReadOptions::default(),
        }
    }

    fn make_event(sec: i64, record_id: Option<u64>, event_id: Option<u32>) -> TimelineEvent {
        let ts = Timestamp::from_second(sec).unwrap();
        // A kind that no detection rule flags, so tests control the flags.
        let mut ev = TimelineEvent::new(
            ts,
            "host",
            SourceKind::Evtx,
            EventKind::UserCreate,
            "f.evtx",
        );
        ev.record_id = record_id;
        ev.event_id = event_id;
        ev
    }

    #[test]
    fn process_events_sorts_deterministically() {
        let e1 = make_event(30, Some(1), Some(4624));
        let e2 = make_event(10, Some(5), Some(4624));
        let e3 = make_event(10, Some(2), Some(4624));

        let out = process_events(vec![e1, e2, e3], &default_options());
        let ids: Vec<_> = out
            .iter()
            .map(|e| (e.ts.as_second(), e.record_id))
            .collect();
        assert_eq!(ids, [(10, Some(2)), (10, Some(5)), (30, Some(1))]);
    }

    #[test]
    fn process_events_filters_time_bounds_inclusive_from_exclusive_to() {
        let e1 = make_event(100, Some(1), None);
        let e2 = make_event(200, Some(2), None);
        let e3 = make_event(300, Some(3), None);

        let mut opts = default_options();
        opts.from = Some(Timestamp::from_second(100).unwrap());
        opts.to = Some(Timestamp::from_second(300).unwrap());

        let out = process_events(vec![e1, e2, e3], &opts);
        let secs: Vec<_> = out.iter().map(|e| e.ts.as_second()).collect();
        assert_eq!(secs, [100, 200]);
    }

    #[test]
    fn process_events_filters_event_ids_and_drops_none() {
        let e1 = make_event(10, Some(1), Some(4624));
        let e2 = make_event(20, Some(2), Some(4625));
        let e3 = make_event(30, Some(3), None);

        let mut opts = default_options();
        opts.event_ids = vec![4624];

        let out = process_events(vec![e1, e2, e3], &opts);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record_id, Some(1));
    }

    #[test]
    fn process_events_filters_flagged_only() {
        let e1 = make_event(10, Some(1), Some(4624));
        let mut e2 = make_event(20, Some(2), Some(4625));
        e2.flags.push(Flag {
            rule: "test",
            severity: Severity::Low,
            reason: "why".into(),
            related: vec![],
        });

        let mut opts = default_options();
        opts.flagged_only = true;

        let out = process_events(vec![e1, e2], &opts);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record_id, Some(2));
    }

    #[test]
    fn process_events_combines_all_filters() {
        let mut e1 = make_event(100, Some(1), Some(4624));
        e1.flags.push(Flag {
            rule: "r",
            severity: Severity::Low,
            reason: "x".into(),
            related: vec![],
        });
        let e2 = make_event(150, Some(2), Some(4624));
        let mut e3 = make_event(150, Some(3), Some(4625));
        e3.flags.push(Flag {
            rule: "r",
            severity: Severity::Low,
            reason: "x".into(),
            related: vec![],
        });
        let mut e4 = make_event(200, Some(4), Some(4624));
        e4.flags.push(Flag {
            rule: "r",
            severity: Severity::Low,
            reason: "x".into(),
            related: vec![],
        });

        let mut opts = default_options();
        opts.from = Some(Timestamp::from_second(100).unwrap());
        opts.to = Some(Timestamp::from_second(200).unwrap());
        opts.event_ids = vec![4624];
        opts.flagged_only = true;

        let out = process_events(vec![e1, e2, e3, e4], &opts);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].record_id, Some(1));
    }

    #[test]
    fn collect_files_nested_sorted_and_missing_path_errors() {
        let dir = TempDir::new().unwrap();
        let sub_b = dir.path().join("b");
        let sub_a = dir.path().join("a");
        fs::create_dir_all(&sub_b).unwrap();
        fs::create_dir_all(&sub_a).unwrap();
        fs::write(sub_b.join("z.log"), b"z").unwrap();
        fs::write(sub_a.join("2.log"), b"2").unwrap();
        fs::write(sub_a.join("1.log"), b"1").unwrap();

        let files = collect_files(&[dir.path().to_path_buf()]).unwrap();
        let rels: Vec<_> = files
            .iter()
            .map(|f| {
                f.path
                    .strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect();
        assert_eq!(rels, ["a/1.log", "a/2.log", "b/z.log"]);
        assert!(files.iter().all(|f| !f.direct_cli));

        let missing = dir.path().join("does_not_exist.evtx");
        let err = collect_files(std::slice::from_ref(&missing)).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("does_not_exist.evtx"),
            "unexpected error: {msg}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_files_ignores_symlink_loop_in_directory() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("real.log"), b"ok").unwrap();
        symlink(dir.path(), sub.join("loop")).unwrap();

        let files = collect_files(&[dir.path().to_path_buf()]).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].path.ends_with("real.log"));
    }

    #[test]
    fn run_timeline_errors_when_directory_has_only_unknown_files() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("notes.txt"), b"hello world\n").unwrap();

        let mut opts = default_options();
        opts.paths = vec![dir.path().to_path_buf()];

        let mut out = Vec::new();
        let err = run_timeline(&opts, &mut out).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("1 skipped"), "unexpected error: {msg}");
        assert!(msg.contains("0 failed"), "unexpected error: {msg}");
        assert!(out.is_empty());
    }

    #[test]
    fn run_timeline_does_not_panic_on_empty_file() {
        let dir = TempDir::new().unwrap();
        let empty = dir.path().join("empty.evtx");
        fs::write(&empty, b"").unwrap();

        let mut opts = default_options();
        opts.paths = vec![empty];

        let mut out = Vec::new();
        let err = run_timeline(&opts, &mut out).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("1 skipped"), "unexpected error: {msg}");
        assert!(out.is_empty());
    }
}
