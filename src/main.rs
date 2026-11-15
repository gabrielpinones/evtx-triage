use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::process::ExitCode;

use anstyle::{AnsiColor, Style};
use anyhow::Context;
use clap::Parser;

use evtx_triage::cli::{Cli, Command, InspectArgs, OutputFormat, TimelineArgs};
use evtx_triage::pipeline::{self, TimelineOptions};
use evtx_triage::{inspect, source};

/// Everything was read.
const EXIT_OK: u8 = 0;
/// Nothing useful could be produced.
const EXIT_FATAL: u8 = 1;
/// A timeline or report was produced, but some input was unreadable or damaged.
const EXIT_PARTIAL: u8 = 2;

const ERROR: Style = AnsiColor::Red.on_default().bold();

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Timeline(args) => run_timeline(args),
        Command::Inspect(args) => run_inspect(args),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        // The reader went away (`| head`): that is the reader's choice, not a failure.
        Err(error) if is_broken_pipe(&error) => ExitCode::from(EXIT_OK),
        Err(error) => {
            anstream::eprintln!("{ERROR}error:{ERROR:#} {error:#}");
            ExitCode::from(EXIT_FATAL)
        }
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    // The JSON and CSV writers wrap the I/O error in their own type.
    error.chain().any(|cause| {
        let kind = if let Some(io_error) = cause.downcast_ref::<io::Error>() {
            Some(io_error.kind())
        } else if let Some(json_error) = cause.downcast_ref::<serde_json::Error>() {
            json_error.io_error_kind()
        } else if let Some(csv_error) = cause.downcast_ref::<csv::Error>() {
            match csv_error.kind() {
                csv::ErrorKind::Io(io_error) => Some(io_error.kind()),
                _ => None,
            }
        } else {
            None
        };
        kind == Some(io::ErrorKind::BrokenPipe)
    })
}

fn run_timeline(args: TimelineArgs) -> anyhow::Result<u8> {
    // A person at a terminal gets the readable table; a pipe or a file gets
    // JSONL, which is what the next tool wants.
    let format = args.format.unwrap_or_else(|| {
        if args.output.is_none() && io::stdout().is_terminal() {
            OutputFormat::Table
        } else {
            OutputFormat::Jsonl
        }
    });

    let options = TimelineOptions {
        paths: args.paths,
        format,
        from: args.from,
        to: args.to,
        event_ids: args.event_id,
        flagged_only: args.flagged_only,
        window: args.window,
        read: source::ReadOptions {
            host_fallback: args.host,
        },
    };

    // `anstream` drops the table's ANSI styles when the destination is a file
    // or a pipe, and honors NO_COLOR.
    let mut out: Box<dyn Write> = match &args.output {
        Some(path) => {
            let file =
                File::create(path).with_context(|| format!("cannot create {}", path.display()))?;
            Box::new(BufWriter::new(anstream::StripStream::new(file)))
        }
        None => Box::new(BufWriter::new(anstream::stdout().lock())),
    };
    let summary = pipeline::run_timeline(&options, &mut out)?;
    out.flush().context("cannot write the timeline")?;
    drop(out);

    if !args.quiet {
        anstream::eprint!("{}", summary.render());
    }
    Ok(if summary.is_partial() {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    })
}

fn run_inspect(args: InspectArgs) -> anyhow::Result<u8> {
    let report = inspect::inspect_file(&args.file)
        .with_context(|| format!("cannot inspect {}", args.file.display()))?;
    let mut out = BufWriter::new(anstream::stdout().lock());
    if args.json {
        serde_json::to_writer_pretty(&mut out, &report)?;
        writeln!(out)?;
    } else {
        write!(out, "{}", report.render_text(args.records))?;
    }
    out.flush()?;
    Ok(if report.has_findings() {
        EXIT_PARTIAL
    } else {
        EXIT_OK
    })
}
