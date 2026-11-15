//! Log sources. Each one reads a file and appends normalized events.

pub mod auditd;
pub mod evtx;
pub mod journald;

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::model::TimelineEvent;

/// Input formats the tool can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Evtx,
    Journald,
    Auditd,
}

/// Per-file counters, reported on stderr at the end of a run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SourceStats {
    /// Records or lines looked at.
    pub records_seen: u64,
    /// Events appended to the timeline.
    pub events_emitted: u64,
    /// Records, lines or chunks that could not be parsed and were skipped.
    pub errors: u64,
}

/// Options that apply to every source.
#[derive(Debug, Clone, Default)]
pub struct ReadOptions {
    /// Host name to use when the log does not carry one (auditd without
    /// `node=`). Never overrides a host found in the log.
    pub host_fallback: Option<String>,
}

/// A log format reader.
///
/// `read` must not fail on a single bad record: it counts it in
/// `SourceStats::errors` and goes on. It returns `Err` only when the file as
/// a whole cannot be read.
pub trait Source {
    fn read(
        &self,
        path: &Path,
        options: &ReadOptions,
        out: &mut Vec<TimelineEvent>,
    ) -> anyhow::Result<SourceStats>;
}

/// Returns the reader for a format.
pub fn source_for(format: Format) -> Box<dyn Source> {
    match format {
        Format::Evtx => Box::new(evtx::EvtxSource),
        Format::Journald => Box::new(journald::JournaldSource),
        Format::Auditd => Box::new(auditd::AuditdSource),
    }
}

const EVTX_MAGIC: &[u8; 8] = b"ElfFile\0";

/// Identifies a file by content, never by extension.
///
/// Returns `Ok(None)` for a file that is none of the known formats.
pub fn detect_format(path: &Path) -> std::io::Result<Option<Format>> {
    let mut head = [0u8; 4096];
    let mut file = File::open(path)?;
    let mut filled = 0;
    while filled < head.len() {
        match file.read(&mut head[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(detect_format_bytes(&head[..filled]))
}

/// Same as [`detect_format`], over the first bytes of a file.
pub fn detect_format_bytes(head: &[u8]) -> Option<Format> {
    if head.starts_with(EVTX_MAGIC) {
        return Some(Format::Evtx);
    }
    let text = String::from_utf8_lossy(head);
    let first_line = text.lines().find(|line| !line.trim().is_empty())?.trim();
    if first_line.starts_with('{') && first_line.contains("\"__REALTIME_TIMESTAMP\"") {
        return Some(Format::Journald);
    }
    if first_line.contains("msg=audit(")
        && (first_line.starts_with("type=") || first_line.starts_with("node="))
    {
        return Some(Format::Auditd);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_evtx_by_magic() {
        let mut head = b"ElfFile\0".to_vec();
        head.extend_from_slice(&[0u8; 64]);
        assert_eq!(detect_format_bytes(&head), Some(Format::Evtx));
    }

    #[test]
    fn detects_journald_json_export() {
        let head = br#"{"__CURSOR":"s=1","__REALTIME_TIMESTAMP":"1700000000000000","MESSAGE":"x"}
"#;
        assert_eq!(detect_format_bytes(head), Some(Format::Journald));
    }

    #[test]
    fn detects_auditd_with_and_without_node() {
        let plain = b"type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59\n";
        let node = b"node=web01 type=USER_LOGIN msg=audit(1700000000.123:457): pid=1\n";
        assert_eq!(detect_format_bytes(plain), Some(Format::Auditd));
        assert_eq!(detect_format_bytes(node), Some(Format::Auditd));
    }

    #[test]
    fn rejects_unknown_content() {
        assert_eq!(detect_format_bytes(b""), None);
        assert_eq!(detect_format_bytes(b"\n\n"), None);
        assert_eq!(
            detect_format_bytes(b"Nov 14 10:00:00 host sshd[1]: hi\n"),
            None
        );
        assert_eq!(detect_format_bytes(b"{\"some\":\"json\"}\n"), None);
    }
}
