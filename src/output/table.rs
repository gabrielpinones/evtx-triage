//! Timeline for a person reading a terminal: one line per event, and one
//! indented line per flag under it.

use std::io::Write;

use anstyle::{AnsiColor, Style};

use crate::model::{Severity, TimelineEvent};

const HOST_MAX: usize = 24;
const KIND_WIDTH: usize = 18;

const HEADER: Style = Style::new().bold().underline();
const DIM: Style = Style::new().dimmed();
const FLAGGED: Style = Style::new().bold();

/// Style for a severity, shared with the run summary.
pub fn severity_style(severity: Severity) -> Style {
    match severity {
        Severity::High => AnsiColor::Red.on_default().bold(),
        Severity::Medium => AnsiColor::Yellow.on_default(),
        Severity::Low => AnsiColor::Cyan.on_default(),
    }
}

/// Makes log text safe to print on a terminal.
///
/// Log content is written by whoever generated the events, attackers
/// included. Printed raw, an escape sequence in a command line could move the
/// cursor, recolor or overwrite what the analyst sees. Every control
/// character becomes a middle dot.
pub fn printable(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '\u{b7}' } else { c })
        .collect()
}

pub fn write(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    let host_width = events
        .iter()
        .map(|event| event.host.chars().count())
        .max()
        .unwrap_or(0)
        .clamp(4, HOST_MAX);

    writeln!(
        out,
        "{HEADER}{:<19}{HEADER:#}  {HEADER}{:<host_width$}{HEADER:#}  {HEADER}{:>5}{HEADER:#}  {HEADER}{:<KIND_WIDTH$}{HEADER:#}  {HEADER}SUMMARY{HEADER:#}",
        "TIME (UTC)", "HOST", "ID", "EVENT"
    )?;

    for event in events {
        let time = event.ts.strftime("%Y-%m-%d %H:%M:%S");
        let host = fit(&printable(&event.host), host_width);
        let id = event
            .event_id
            .map_or_else(|| "-".to_string(), |id| id.to_string());
        let kind = event.kind.as_str();
        let summary = printable(&event.summary);
        let style = if event.flags.is_empty() {
            Style::new()
        } else {
            FLAGGED
        };

        writeln!(
            out,
            "{DIM}{time}{DIM:#}  {host}  {id:>5}  {kind:<KIND_WIDTH$}  {style}{summary}{style:#}"
        )?;
        for flag in &event.flags {
            let color = severity_style(flag.severity);
            writeln!(
                out,
                "{:19}  {color}! {:<6} {}{color:#}: {}",
                "",
                flag.severity.as_str(),
                flag.rule,
                printable(&flag.reason)
            )?;
        }
    }
    Ok(())
}

/// Pads or cuts `text` to exactly `width` characters.
fn fit(text: &str, width: usize) -> String {
    let count = text.chars().count();
    if count <= width {
        return format!("{text:<width$}");
    }
    let mut cut: String = text.chars().take(width.saturating_sub(1)).collect();
    cut.push('\u{2026}');
    cut
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;

    use super::*;
    use crate::model::{EventKind, Flag, SourceKind};

    fn render(events: &[TimelineEvent]) -> String {
        let mut raw = Vec::new();
        write(&mut raw, events).unwrap();
        // Tests read the text the way a file or pipe would receive it.
        let mut plain = anstream::StripStream::new(Vec::new());
        plain.write_all(&raw).unwrap();
        String::from_utf8(plain.into_inner()).unwrap()
    }

    fn event(summary: &str) -> TimelineEvent {
        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        let mut event = TimelineEvent::new(
            ts,
            "HOST01",
            SourceKind::Evtx,
            EventKind::ServiceInstall,
            "f",
        );
        event.event_id = Some(7045);
        event.summary = summary.to_string();
        event
    }

    #[test]
    fn one_line_per_event_and_one_per_flag() {
        let mut flagged = event("Service \"x\" installed: cmd.exe /c evil");
        flagged.flags.push(Flag {
            rule: "service_suspicious_path",
            severity: Severity::Medium,
            reason: "runs from cmd.exe /c".into(),
            related: vec![],
        });
        let text = render(&[event("Service \"ok\" installed"), flagged]);
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("TIME (UTC)"));
        assert_eq!(
            lines[1],
            "2023-11-14 22:13:20  HOST01   7045  service_install     Service \"ok\" installed"
        );
        assert!(lines[3].contains("! medium service_suspicious_path: runs from cmd.exe /c"));
    }

    #[test]
    fn control_characters_from_logs_never_reach_the_terminal() {
        let mut hostile = event("cmd \u{1b}[2J\u{1b}[1;1H cleared \u{7} \u{9b}31m");
        hostile.host = "H\u{1b}[31m".into();
        hostile.flags.push(Flag {
            rule: "r",
            severity: Severity::High,
            reason: "why\u{1b}]0;title\u{7}".into(),
            related: vec![],
        });

        let mut raw = Vec::new();
        write(&mut raw, &[hostile]).unwrap();
        let raw = String::from_utf8(raw).unwrap();

        // The only escape sequences left are the styles this module writes.
        let ours = raw.matches("\u{1b}[").count();
        let mut plain = anstream::StripStream::new(Vec::new());
        plain.write_all(raw.as_bytes()).unwrap();
        let plain = String::from_utf8(plain.into_inner()).unwrap();
        assert!(ours > 0);
        assert!(!plain.contains('\u{1b}'));
        assert!(!plain.contains('\u{7}'));
        assert!(!plain.contains('\u{9b}'));
        assert!(plain.contains("cmd \u{b7}[2J"));
    }

    #[test]
    fn long_host_names_are_cut_to_keep_columns_aligned() {
        let mut long = event("x");
        long.host = "a-very-long-host-name.corp.example.internal".into();
        let text = render(&[long]);
        let line = text.lines().nth(1).unwrap();
        assert!(line.contains("a-very-long-host-name.c\u{2026}  "));
    }

    #[test]
    fn empty_timeline_prints_only_the_header() {
        assert_eq!(render(&[]).lines().count(), 1);
    }
}
