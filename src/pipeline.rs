//! Timeline pipeline: collect files, read, filter, sort, detect, write.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anstyle::{AnsiColor, Style};
use anyhow::Context;
use jiff::{SignedDuration, Timestamp};

use crate::cli::{OutputFormat, OutputProfile};
use crate::detect::{self, DetectOptions};
use crate::model::{EventKind, Severity, TimelineEvent};
use crate::output;
use crate::output::table::severity_style;
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
    pub profile: OutputProfile,
    /// Empty means do not restrict by kind (the profile applies instead).
    pub kinds: Vec<EventKind>,
    /// Kinds dropped after every other filter.
    pub exclude_kinds: Vec<EventKind>,
    /// Correlation window handed to the detection rules.
    pub window: SignedDuration,
    pub read: ReadOptions,
}

/// Counters for one run, printed on stderr by `main`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
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
    pub events_hidden: u64,
    /// Flags on the written events, by severity and rule.
    pub flag_counts: BTreeMap<(Severity, &'static str), u64>,
}

impl RunSummary {
    /// True when the timeline is missing data because of damaged input.
    pub fn is_partial(&self) -> bool {
        self.files_failed > 0 || self.record_errors > 0
    }
}

impl RunSummary {
    /// The end-of-run report for stderr, one fact per line.
    ///
    /// The text carries ANSI styles; print it through `anstream`.
    pub fn render(&self) -> String {
        let bold = Style::new().bold();
        let warn = AnsiColor::Yellow.on_default();
        let mut out = String::new();

        let _ = write!(
            out,
            "{bold}{}{bold:#} from {}",
            count(self.events_written, "event", "events"),
            count(self.files_read, "file", "files"),
        );
        if self.events_flagged > 0 {
            let _ = write!(out, ", {bold}{} flagged{bold:#}", self.events_flagged);
        }
        out.push('\n');

        // Highest severity first.
        for ((severity, rule), hits) in self.flag_counts.iter().rev() {
            let style = severity_style(*severity);
            let _ = writeln!(
                out,
                "  {style}{:<6}{style:#}  {hits:>4}  {rule}",
                severity.as_str()
            );
        }

        if self.events_hidden > 0 {
            let _ = writeln!(
                out,
                "{} hidden by the triage profile (--profile full shows them)",
                count(self.events_hidden, "event", "events")
            );
        }

        if self.files_skipped > 0 {
            let _ = writeln!(
                out,
                "{} skipped: not a supported log format",
                count(self.files_skipped, "file", "files")
            );
        }
        if self.record_errors > 0 {
            let _ = writeln!(
                out,
                "{warn}{} could not be read: the timeline is incomplete{warn:#}",
                count(self.record_errors, "record", "records")
            );
        }
        if self.files_failed > 0 {
            let _ = writeln!(
                out,
                "{warn}{} could not be read: the timeline is incomplete{warn:#}",
                count(self.files_failed, "file", "files")
            );
        }
        out
    }
}

fn count(n: u64, singular: &str, plural: &str) -> String {
    if n == 1 {
        format!("1 {singular}")
    } else {
        format!("{n} {plural}")
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

    let (final_events, hidden) = process_events(events, options);
    match options.format {
        OutputFormat::Jsonl => output::write_jsonl(out, &final_events)?,
        OutputFormat::Csv => output::write_csv(out, &final_events)?,
        OutputFormat::Table => output::write_table(out, &final_events)?,
    }

    summary.events_hidden = hidden;
    summary.events_written = final_events.len() as u64;
    summary.events_flagged = final_events.iter().filter(|e| !e.flags.is_empty()).count() as u64;
    for flag in final_events.iter().flat_map(|event| &event.flags) {
        *summary
            .flag_counts
            .entry((flag.severity, flag.rule))
            .or_default() += 1;
    }
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

fn is_triage_noisy(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::ImageLoad | EventKind::FileCreate | EventKind::RegistryChange
    )
}

fn process_events(
    mut events: Vec<TimelineEvent>,
    options: &TimelineOptions,
) -> (Vec<TimelineEvent>, u64) {
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

    let mut hidden_by_profile = 0u64;
    if !options.kinds.is_empty() {
        events.retain(|event| options.kinds.contains(&event.kind));
    } else if options.profile == OutputProfile::Triage {
        events.retain(|event| {
            let hide = is_triage_noisy(event.kind) && event.flags.is_empty();
            if hide {
                hidden_by_profile = hidden_by_profile.saturating_add(1);
            }
            !hide
        });
    }

    if !options.exclude_kinds.is_empty() {
        events.retain(|event| !options.exclude_kinds.contains(&event.kind));
    }

    (events, hidden_by_profile)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use jiff::{SignedDuration, Timestamp};
    use tempfile::TempDir;

    use crate::cli::{OutputFormat, OutputProfile};
    use crate::model::{EventKind, Flag, Severity, SourceKind, TimelineEvent};
    use crate::source::ReadOptions;

    use super::{RunSummary, TimelineOptions, collect_files, process_events, run_timeline};

    fn default_options() -> TimelineOptions {
        TimelineOptions {
            paths: Vec::new(),
            format: OutputFormat::Jsonl,
            from: None,
            to: None,
            event_ids: Vec::new(),
            flagged_only: false,
            profile: OutputProfile::Triage,
            kinds: Vec::new(),
            exclude_kinds: Vec::new(),
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

        let (out, hidden) = process_events(vec![e1, e2, e3], &default_options());
        assert_eq!(hidden, 0);
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

        let (out, _) = process_events(vec![e1, e2, e3], &opts);
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

        let (out, _) = process_events(vec![e1, e2, e3], &opts);
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

        let (out, _) = process_events(vec![e1, e2], &opts);
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

        let (out, _) = process_events(vec![e1, e2, e3, e4], &opts);
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

    fn make_kind_event(sec: i64, record_id: u64, kind: EventKind) -> TimelineEvent {
        let ts = Timestamp::from_second(sec).unwrap();
        let mut ev = TimelineEvent::new(ts, "host", SourceKind::Evtx, kind, "f.evtx");
        ev.record_id = Some(record_id);
        ev
    }

    fn sample_flag() -> Flag {
        Flag {
            rule: "test_rule",
            severity: Severity::Medium,
            reason: "suspicious".into(),
            related: vec![],
        }
    }

    #[test]
    fn triage_profile_drops_unflagged_noisy_kinds_and_counts_them() {
        let keep_proc = make_kind_event(10, 1, EventKind::ProcessCreate);
        let drop_img = make_kind_event(20, 2, EventKind::ImageLoad);
        let mut keep_img_flagged = make_kind_event(30, 3, EventKind::ImageLoad);
        keep_img_flagged.flags.push(sample_flag());
        let drop_file = make_kind_event(40, 4, EventKind::FileCreate);
        let mut keep_reg_flagged = make_kind_event(50, 5, EventKind::RegistryChange);
        keep_reg_flagged.flags.push(sample_flag());
        let drop_reg = make_kind_event(60, 6, EventKind::RegistryChange);
        let keep_del = make_kind_event(70, 7, EventKind::FileDelete);

        let (out, hidden) = process_events(
            vec![
                keep_proc,
                drop_img,
                keep_img_flagged,
                drop_file,
                keep_reg_flagged,
                drop_reg,
                keep_del,
            ],
            &default_options(),
        );
        let ids: Vec<_> = out.iter().filter_map(|e| e.record_id).collect();
        assert_eq!(ids, [1, 3, 5, 7]);
        assert_eq!(hidden, 3);
    }

    #[test]
    fn full_profile_keeps_all_events_and_hides_zero() {
        let events = vec![
            make_kind_event(10, 1, EventKind::ProcessCreate),
            make_kind_event(20, 2, EventKind::ImageLoad),
            make_kind_event(30, 3, EventKind::FileCreate),
            make_kind_event(40, 4, EventKind::RegistryChange),
        ];

        let mut opts = default_options();
        opts.profile = OutputProfile::Full;

        let (out, hidden) = process_events(events, &opts);
        assert_eq!(out.len(), 4);
        assert_eq!(hidden, 0);
    }

    #[test]
    fn kind_filter_overrides_triage_profile() {
        let events = vec![
            make_kind_event(10, 1, EventKind::ProcessCreate),
            make_kind_event(20, 2, EventKind::ImageLoad),
            make_kind_event(30, 3, EventKind::FileCreate),
        ];

        let mut opts = default_options();
        opts.profile = OutputProfile::Triage;
        opts.kinds = vec![EventKind::ImageLoad];

        let (out, hidden) = process_events(events, &opts);
        let ids: Vec<_> = out.iter().filter_map(|e| e.record_id).collect();
        assert_eq!(ids, [2]);
        assert_eq!(hidden, 0);
    }

    #[test]
    fn exclude_kind_applies_after_kind_and_profile() {
        let events = vec![
            make_kind_event(10, 1, EventKind::ProcessCreate),
            make_kind_event(20, 2, EventKind::ImageLoad),
            make_kind_event(30, 3, EventKind::FileCreate),
            make_kind_event(40, 4, EventKind::NetworkConnect),
        ];

        let mut opts = default_options();
        opts.kinds = vec![EventKind::ImageLoad, EventKind::NetworkConnect];
        opts.exclude_kinds = vec![EventKind::ImageLoad];

        let (out, hidden) = process_events(events.clone(), &opts);
        let ids: Vec<_> = out.iter().filter_map(|e| e.record_id).collect();
        assert_eq!(ids, [4]);
        assert_eq!(hidden, 0);

        let mut full_opts = default_options();
        full_opts.profile = OutputProfile::Full;
        full_opts.exclude_kinds = vec![EventKind::FileCreate];

        let (out, hidden) = process_events(events, &full_opts);
        let ids: Vec<_> = out.iter().filter_map(|e| e.record_id).collect();
        assert_eq!(ids, [1, 2, 4]);
        assert_eq!(hidden, 0);
    }

    #[test]
    fn summary_render_prints_hidden_count_line_only_when_nonzero() {
        let mut summary = RunSummary {
            files_read: 1,
            events_written: 10,
            ..Default::default()
        };
        assert!(!summary.render().contains("hidden by the triage profile"));

        summary.events_hidden = 1;
        assert!(
            summary
                .render()
                .contains("1 event hidden by the triage profile (--profile full shows them)\n")
        );

        summary.events_hidden = 1204;
        assert!(
            summary
                .render()
                .contains("1204 events hidden by the triage profile (--profile full shows them)\n")
        );
    }
}
