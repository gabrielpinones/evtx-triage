use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;

use evtx_triage::cli::{Cli, Command, InspectArgs, TimelineArgs};
use evtx_triage::pipeline::{self, TimelineOptions};
use evtx_triage::{inspect, source};

/// Everything was read.
const EXIT_OK: u8 = 0;
/// Nothing useful could be produced.
const EXIT_FATAL: u8 = 1;
/// A timeline or report was produced, but some input was unreadable or damaged.
const EXIT_PARTIAL: u8 = 2;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Timeline(args) => run_timeline(args),
        Command::Inspect(args) => run_inspect(args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(EXIT_FATAL)
        }
    }
}

fn run_timeline(args: TimelineArgs) -> anyhow::Result<u8> {
    let options = TimelineOptions {
        paths: args.paths,
        format: args.format,
        from: args.from,
        to: args.to,
        event_ids: args.event_id,
        flagged_only: args.flagged_only,
        window: args.window,
        read: source::ReadOptions {
            host_fallback: args.host,
        },
    };

    let mut out: Box<dyn Write> = match &args.output {
        Some(path) => Box::new(BufWriter::new(
            File::create(path).with_context(|| format!("cannot create {}", path.display()))?,
        )),
        None => Box::new(BufWriter::new(io::stdout().lock())),
    };
    let summary = pipeline::run_timeline(&options, &mut out)?;
    out.flush().context("cannot write the timeline")?;

    eprintln!("{summary}");
    Ok(if summary.is_partial() {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    })
}

fn run_inspect(args: InspectArgs) -> anyhow::Result<u8> {
    let report = inspect::inspect_file(&args.file)
        .with_context(|| format!("cannot inspect {}", args.file.display()))?;
    let mut out = io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", report.render_text(args.records))?;
    }
    Ok(if report.has_findings() {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    })
}
