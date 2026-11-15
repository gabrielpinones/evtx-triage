//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use jiff::{SignedDuration, Timestamp};

use crate::model::EventKind;

const EXAMPLES: &str = "\
Examples:
  evtx-triage timeline Security.evtx System.evtx
  evtx-triage timeline ./winevt/Logs --flagged-only
  evtx-triage timeline ./logs --profile full
  evtx-triage timeline ./logs --kind process_create,logon_success --exclude-kind logoff
  evtx-triage timeline ./logs --format csv -o timeline.csv
  evtx-triage timeline ./logs --from 2024-05-01T00:00:00Z --to 2024-05-02T00:00:00Z
  evtx-triage timeline audit.log --host web01
  evtx-triage inspect Security.evtx

Exit status:
  0  everything was read
  1  nothing could be produced
  2  output was produced, but some input was damaged or unreadable
     (for inspect: the file shows damage or signs of tampering)

Colors follow the NO_COLOR and CLICOLOR_FORCE environment variables.";

/// Forensic timeline from Windows EVTX, journald and auditd logs
///
/// Reads logs offline, keeps the events that matter for triage (logons,
/// process creation, new services, scheduled tasks, PowerShell script blocks,
/// account creation, log clearing), orders them by time and flags a few
/// suspicious patterns.
#[derive(Debug, Parser)]
#[command(name = "evtx-triage", version, after_help = EXAMPLES)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Build a timeline from .evtx, journald JSON or auditd logs
    Timeline(TimelineArgs),
    /// Parse the EVTX file and chunk headers by hand and report anomalies
    Inspect(InspectArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Aligned text for reading on a terminal
    Table,
    /// One JSON object per line, lossless
    Jsonl,
    /// Spreadsheet-friendly, one row per event
    Csv,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputProfile {
    /// Drop unflagged image_load, file_create and registry_change events
    #[default]
    Triage,
    /// Keep every extracted event
    Full,
}

#[derive(Debug, Args)]
pub struct TimelineArgs {
    /// Log files or directories (searched recursively)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Write the timeline to this file instead of stdout
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Output format [default: table on a terminal, jsonl otherwise]
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Keep events at or after this UTC time (RFC 3339)
    #[arg(long)]
    pub from: Option<Timestamp>,

    /// Keep events before this UTC time (RFC 3339)
    #[arg(long)]
    pub to: Option<Timestamp>,

    /// Keep only these Windows event ids (comma separated)
    #[arg(long, value_delimiter = ',')]
    pub event_id: Vec<u32>,

    /// Keep only events that raised at least one flag
    #[arg(long)]
    pub flagged_only: bool,

    /// Output profile controlling high-volume events
    #[arg(long, value_enum, default_value_t = OutputProfile::Triage)]
    pub profile: OutputProfile,

    /// Keep only these event kinds (comma separated; disables the profile)
    #[arg(long, value_delimiter = ',')]
    pub kind: Vec<EventKind>,

    /// Drop these event kinds (comma separated; applied after everything else)
    #[arg(long, value_delimiter = ',')]
    pub exclude_kind: Vec<EventKind>,

    /// Correlation window for detection rules, for example 5m or 90s
    #[arg(long, default_value = "5m")]
    pub window: SignedDuration,

    /// Host name for logs that do not record one
    #[arg(long)]
    pub host: Option<String>,

    /// Do not print the run summary on stderr
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    /// EVTX file to inspect
    pub file: PathBuf,

    /// Print the report as JSON
    #[arg(long)]
    pub json: bool,

    /// List every record of every chunk
    #[arg(long)]
    pub records: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_consistent() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_timeline_arguments() {
        let cli = Cli::parse_from([
            "evtx-triage",
            "timeline",
            "a.evtx",
            "logs/",
            "--format",
            "csv",
            "--event-id",
            "4624,7045",
            "--window",
            "90s",
            "--from",
            "2024-01-01T00:00:00Z",
        ]);
        let Command::Timeline(args) = cli.command else {
            panic!("expected timeline");
        };
        assert_eq!(args.paths.len(), 2);
        assert_eq!(args.format, Some(OutputFormat::Csv));
        assert_eq!(args.event_id, [4624, 7045]);
        assert_eq!(args.window, SignedDuration::from_secs(90));
        assert!(args.from.is_some());
    }

    #[test]
    fn window_defaults_to_five_minutes() {
        let cli = Cli::parse_from(["evtx-triage", "timeline", "a.evtx"]);
        let Command::Timeline(args) = cli.command else {
            panic!("expected timeline");
        };
        assert_eq!(args.window, SignedDuration::from_mins(5));
        assert_eq!(args.format, None);
        assert_eq!(args.profile, OutputProfile::Triage);
        assert!(args.kind.is_empty());
        assert!(args.exclude_kind.is_empty());
        assert!(!args.quiet);
    }

    #[test]
    fn parses_profile_and_kind_filters() {
        let cli = Cli::parse_from([
            "evtx-triage",
            "timeline",
            "a.evtx",
            "--profile",
            "full",
            "--kind",
            "process_create,network_connect",
            "--exclude-kind",
            "logoff,image_load",
        ]);
        let Command::Timeline(args) = cli.command else {
            panic!("expected timeline");
        };
        assert_eq!(args.profile, OutputProfile::Full);
        assert_eq!(
            args.kind,
            [EventKind::ProcessCreate, EventKind::NetworkConnect]
        );
        assert_eq!(args.exclude_kind, [EventKind::Logoff, EventKind::ImageLoad]);
    }
}
