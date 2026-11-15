//! Timeline writers.

use std::io::Write;

use crate::model::TimelineEvent;

/// Writes one JSON object per line.
pub fn write_jsonl(_out: &mut dyn Write, _events: &[TimelineEvent]) -> anyhow::Result<()> {
    anyhow::bail!("jsonl output is not implemented yet")
}

/// Writes a header row and one CSV row per event.
pub fn write_csv(_out: &mut dyn Write, _events: &[TimelineEvent]) -> anyhow::Result<()> {
    anyhow::bail!("csv output is not implemented yet")
}
