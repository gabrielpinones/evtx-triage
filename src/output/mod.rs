//! Timeline writers.

mod csv;
mod jsonl;
pub mod table;

use std::io::Write;

use crate::model::TimelineEvent;

/// Writes one JSON object per line.
pub fn write_jsonl(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    jsonl::write(out, events)
}

/// Writes an aligned, styled listing for a terminal.
///
/// The text carries ANSI styles; send it through `anstream` so they are
/// dropped when the destination is not a terminal.
pub fn write_table(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    table::write(out, events)
}

/// Writes a header row and one CSV row per event.
pub fn write_csv(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    csv::write(out, events)
}
