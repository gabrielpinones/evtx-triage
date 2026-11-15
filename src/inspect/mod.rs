//! Hand-written reader for the EVTX file header, chunk headers and record
//! framing. It does not use the `evtx` crate.

use std::path::Path;

use serde::Serialize;

/// Result of inspecting one EVTX file.
#[derive(Debug, Clone, Serialize)]
pub struct InspectReport {}

impl InspectReport {
    /// True when the file shows damage or signs of tampering: dirty flag,
    /// checksum mismatch, bad chunk magic, record id gaps, inconsistent sizes.
    pub fn has_findings(&self) -> bool {
        false
    }

    /// Human-readable report. `show_records` lists every record.
    pub fn render_text(&self, _show_records: bool) -> String {
        String::new()
    }
}

/// Reads and checks the structure of an EVTX file.
///
/// Returns `Err` only when the file cannot be opened or is not EVTX at all.
/// Damage inside the file is reported in the `InspectReport`.
pub fn inspect_file(_path: &Path) -> anyhow::Result<InspectReport> {
    anyhow::bail!("inspect is not implemented yet")
}
