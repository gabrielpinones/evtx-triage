//! Timeline writers.

mod csv;
mod jsonl;

use std::io::Write;

use crate::model::TimelineEvent;

/// Writes one JSON object per line.
pub fn write_jsonl(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    jsonl::write(out, events)
}

/// Writes a header row and one CSV row per event.
pub fn write_csv(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    csv::write(out, events)
}
