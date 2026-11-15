//! Timeline pipeline: collect files, read, filter, sort, detect, write.

use std::fmt;
use std::io::Write;
use std::path::PathBuf;

use jiff::{SignedDuration, Timestamp};

use crate::cli::OutputFormat;
use crate::source::ReadOptions;

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
pub fn run_timeline(
    _options: &TimelineOptions,
    _out: &mut dyn Write,
) -> anyhow::Result<RunSummary> {
    anyhow::bail!("timeline is not implemented yet")
}
