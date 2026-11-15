//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use jiff::{SignedDuration, Timestamp};

#[derive(Debug, Parser)]
#[command(name = "evtx-triage", version, about)]
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
    Jsonl,
    Csv,
}

#[derive(Debug, Args)]
pub struct TimelineArgs {
    /// Log files or directories (searched recursively)
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Write the timeline to this file instead of stdout
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Jsonl)]
    pub format: OutputFormat,

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

    /// Correlation window for detection rules, for example 5m or 90s
    #[arg(long, default_value = "5m")]
    pub window: SignedDuration,

    /// Host name for logs that do not record one
    #[arg(long)]
    pub host: Option<String>,
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
        assert_eq!(args.format, OutputFormat::Csv);
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
    }
}
