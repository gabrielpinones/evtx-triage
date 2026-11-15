use std::fmt::Write;

use anstyle::{AnsiColor, Style};
use jiff::Timestamp;
use serde::Serialize;

use crate::model::format_ts;

use super::chunk_header::{ChunkHeader, ChunkStatus};
use super::file_header::FileHeader;
use super::records::RecordSummary;
use super::serialize_opt_ts;

/// Severity of an inspection finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Error,
}

impl FindingSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            FindingSeverity::Info => "info",
            FindingSeverity::Warning => "warning",
            FindingSeverity::Error => "error",
        }
    }
}

/// Anomaly, flag or structural error detected while inspecting an EVTX file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: FindingSeverity,
    pub kind: &'static str,
    pub chunk_index: Option<usize>,
    pub message: String,
}

/// Summary of one 64 KiB chunk slot in the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChunkReport {
    pub index: usize,
    pub file_offset: u64,
    pub byte_len: usize,
    pub status: ChunkStatus,
    pub header: Option<ChunkHeader>,
    pub records_walked: usize,
    pub first_record_id_walked: Option<u64>,
    pub last_record_id_walked: Option<u64>,
    #[serde(serialize_with = "serialize_opt_ts")]
    pub first_timestamp: Option<Timestamp>,
    #[serde(serialize_with = "serialize_opt_ts")]
    pub last_timestamp: Option<Timestamp>,
}

/// Aggregate counts and time span across the inspected file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InspectSummary {
    pub total_chunks: usize,
    pub valid_chunks: usize,
    pub unused_chunks: usize,
    pub bad_chunks: usize,
    pub total_records: usize,
    #[serde(serialize_with = "serialize_opt_ts")]
    pub first_timestamp: Option<Timestamp>,
    #[serde(serialize_with = "serialize_opt_ts")]
    pub last_timestamp: Option<Timestamp>,
    pub info_count: usize,
    pub warning_count: usize,
    pub error_count: usize,
}

/// Result of inspecting one EVTX file.
#[derive(Debug, Clone, Serialize)]
pub struct InspectReport {
    pub file_size: u64,
    pub file_header: Option<FileHeader>,
    pub chunks: Vec<ChunkReport>,
    pub records: Vec<RecordSummary>,
    pub findings: Vec<Finding>,
    pub summary: InspectSummary,
}

impl InspectReport {
    /// True when the file shows damage or signs of tampering: dirty flag,
    /// checksum mismatch, bad chunk magic, record id gaps, inconsistent sizes.
    pub fn has_findings(&self) -> bool {
        self.findings.iter().any(|f| {
            matches!(
                f.severity,
                FindingSeverity::Warning | FindingSeverity::Error
            )
        })
    }

    /// Human-readable report. `show_records` lists every record.
    pub fn render_text(&self, show_records: bool) -> String {
        let mut out = String::new();
        self.write_file_header(&mut out);
        self.write_chunks_table(&mut out);
        if show_records {
            self.write_records_table(&mut out);
        }
        self.write_findings(&mut out);
        self.write_summary(&mut out);
        out
    }

    fn write_file_header(&self, out: &mut String) {
        let _ = writeln!(out, "File header:");
        let _ = writeln!(out, "  file size: {} bytes", self.file_size);
        let Some(fh) = &self.file_header else {
            let _ = writeln!(
                out,
                "  status: truncated (fewer than 128 bytes available for file header)"
            );
            return;
        };
        let _ = writeln!(out, "  version: {}.{}", fh.major_version, fh.minor_version);
        let _ = writeln!(
            out,
            "  header size: {}, block size: {}",
            fh.header_size, fh.header_block_size
        );
        let _ = writeln!(
            out,
            "  chunks: first={}, last={}, count={}",
            fh.first_chunk_number, fh.last_chunk_number, fh.chunk_count
        );
        let _ = writeln!(out, "  next record id: {}", fh.next_record_id);
        let _ = writeln!(out, "  flags: {}", fh.format_flags());
        let crc_status = if fh.no_crc32 {
            "disabled"
        } else if fh.checksum_matches() {
            "ok"
        } else {
            "mismatch"
        };
        let _ = writeln!(
            out,
            "  crc32: stored={:#010x} computed={:#010x} ({crc_status})",
            fh.stored_crc32, fh.computed_crc32
        );
    }

    fn write_chunks_table(&self, out: &mut String) {
        let _ = writeln!(out, "Chunks ({}):", self.chunks.len());
        if self.chunks.is_empty() {
            let _ = writeln!(out, "  (none)");
            return;
        }
        let _ = writeln!(
            out,
            "  {:>4}  {:<10}  {:<9}  {:>7}  {:<17}  {:<8}  {:<8}  {:>8}  time_range",
            "idx", "offset", "status", "records", "ids", "hdr_crc", "data_crc", "free_off"
        );
        for chunk in &self.chunks {
            let status = match chunk.status {
                ChunkStatus::Valid => "valid",
                ChunkStatus::Unused => "unused",
                ChunkStatus::BadMagic => "bad_magic",
                ChunkStatus::Truncated => "truncated",
            };
            let (records, ids, hdr_crc, data_crc, free_off) = match &chunk.header {
                Some(h) => {
                    let ids = match (chunk.first_record_id_walked, chunk.last_record_id_walked) {
                        (Some(first), Some(last)) => format!("{first}..={last}"),
                        _ => "-".to_string(),
                    };
                    let hdr_crc = if h.no_crc32 {
                        "disabled"
                    } else if h.header_checksum_matches() {
                        "ok"
                    } else {
                        "mismatch"
                    };
                    let data_crc = if h.no_crc32 {
                        "disabled"
                    } else {
                        match h.data_checksum_matches() {
                            Some(true) => "ok",
                            Some(false) => "mismatch",
                            None => "n/a",
                        }
                    };
                    (
                        chunk.records_walked.to_string(),
                        ids,
                        hdr_crc,
                        data_crc,
                        h.free_space_offset.to_string(),
                    )
                }
                None => ("-".to_string(), "-".to_string(), "-", "-", "-".to_string()),
            };
            let time_range = format_time_range(chunk.first_timestamp, chunk.last_timestamp);
            let _ = writeln!(
                out,
                "  {:>4}  {:#010x}  {:<9}  {:>7}  {:<17}  {:<8}  {:<8}  {:>8}  {}",
                chunk.index,
                chunk.file_offset,
                status,
                records,
                ids,
                hdr_crc,
                data_crc,
                free_off,
                time_range
            );
        }
    }

    fn write_records_table(&self, out: &mut String) {
        let _ = writeln!(out, "Records ({}):", self.records.len());
        if self.records.is_empty() {
            let _ = writeln!(out, "  (none)");
            return;
        }
        let _ = writeln!(
            out,
            "  {:>5}  {:>10}  {:<27}  {:>7}  offset",
            "chunk", "record_id", "timestamp", "size"
        );
        for rec in &self.records {
            let ts = rec
                .timestamp
                .as_ref()
                .map(format_ts)
                .unwrap_or_else(|| "<invalid>".to_string());
            let _ = writeln!(
                out,
                "  {:>5}  {:>10}  {:<27}  {:>7}  {:#010x}",
                rec.chunk_index, rec.record_id, ts, rec.size, rec.file_offset
            );
        }
    }

    fn write_findings(&self, out: &mut String) {
        let _ = writeln!(out, "Findings ({}):", self.findings.len());
        if self.findings.is_empty() {
            let _ = writeln!(out, "  none");
            return;
        }
        for finding in &self.findings {
            let style = match finding.severity {
                FindingSeverity::Error => AnsiColor::Red.on_default().bold(),
                FindingSeverity::Warning => AnsiColor::Yellow.on_default(),
                FindingSeverity::Info => Style::new().dimmed(),
            };
            let place = finding
                .chunk_index
                .map(|idx| format!(" (chunk {idx})"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "  {style}{:<7} {}{style:#}{place}: {}",
                finding.severity.as_str(),
                finding.kind,
                finding.message
            );
        }
    }

    fn write_summary(&self, out: &mut String) {
        let s = &self.summary;
        let time_range = format_time_range(s.first_timestamp, s.last_timestamp);
        let _ = writeln!(
            out,
            "Summary: {} chunk(s) ({} valid, {} unused, {} bad), {} record(s), time range {}, findings: {} error, {} warning, {} info",
            s.total_chunks,
            s.valid_chunks,
            s.unused_chunks,
            s.bad_chunks,
            s.total_records,
            time_range,
            s.error_count,
            s.warning_count,
            s.info_count
        );
    }
}

fn format_time_range(first: Option<Timestamp>, last: Option<Timestamp>) -> String {
    match (first, last) {
        (Some(a), Some(b)) => format!("{}..{}", format_ts(&a), format_ts(&b)),
        _ => "none".to_string(),
    }
}
