//! Hand-written reader for the EVTX file header, chunk headers and record
//! framing. It does not use the `evtx` crate.

pub mod chunk_header;
pub mod file_header;
pub mod records;
pub mod report;

use std::path::Path;

use anyhow::Context;
use jiff::Timestamp;
use serde::Serializer;

use crate::model::format_ts;

pub use chunk_header::{
    CHUNK_HEADER_SIZE, CHUNK_MAGIC, CHUNK_SIZE, ChunkHeader, ChunkStatus, classify_chunk,
    format_magic,
};
pub use file_header::{EVTX_MAGIC, FILE_HEADER_BLOCK_SIZE, FILE_HEADER_SIZE, FileHeader};
pub use records::{RecordSummary, filetime_to_timestamp, walk_chunk_records};
pub use report::{ChunkReport, Finding, FindingSeverity, InspectReport, InspectSummary};

use records::describe_id_gap;

/// Reads and checks the structure of an EVTX file.
///
/// Returns `Err` only when the file cannot be read or does not start with the
/// EVTX magic. Damage inside the file is reported in the `InspectReport`.
pub fn inspect_file(path: &Path) -> anyhow::Result<InspectReport> {
    let data = std::fs::read(path)
        .with_context(|| format!("failed to read EVTX file {}", path.display()))?;
    inspect_bytes(&data)
}

/// Parses and validates an EVTX file already loaded into memory.
///
/// Returns `Err` only when `data` does not start with the EVTX file magic.
pub fn inspect_bytes(data: &[u8]) -> anyhow::Result<InspectReport> {
    if !data.starts_with(EVTX_MAGIC) {
        anyhow::bail!("not an EVTX file (missing ElfFile\\0 magic)");
    }

    let file_size = data.len() as u64;
    let file_header = FileHeader::parse(data);
    let mut file_findings = Vec::new();

    if data.len() < FILE_HEADER_BLOCK_SIZE {
        file_findings.push(Finding {
            severity: FindingSeverity::Error,
            kind: "truncated_file",
            chunk_index: None,
            message: format!(
                "file is shorter than the {FILE_HEADER_BLOCK_SIZE}-byte header block ({} bytes)",
                data.len()
            ),
        });
    } else if let Some(after_header) = data.len().checked_sub(FILE_HEADER_BLOCK_SIZE) {
        let remainder = after_header % CHUNK_SIZE;
        if remainder != 0 {
            file_findings.push(Finding {
                severity: FindingSeverity::Error,
                kind: "truncated_file",
                chunk_index: None,
                message: format!(
                    "size after {FILE_HEADER_BLOCK_SIZE}-byte header ({after_header} bytes) is not a multiple of {CHUNK_SIZE} (trailing {remainder} bytes)"
                ),
            });
        }
    }

    let mut chunk_reports = Vec::new();
    let mut chunk_findings = Vec::new();
    let mut all_records = Vec::new();
    let mut chunk_spans: Vec<ChunkIdSpan> = Vec::new();
    let mut zero_time_records = 0usize;

    let file_no_crc32 = file_header.as_ref().is_some_and(|h| h.no_crc32);

    let mut offset = FILE_HEADER_BLOCK_SIZE;
    let mut chunk_index = 0usize;
    while offset < data.len() {
        let end = offset.saturating_add(CHUNK_SIZE).min(data.len());
        let Some(slice) = data.get(offset..end) else {
            break;
        };

        let (status, bad_magic) = classify_chunk(slice);
        match status {
            ChunkStatus::Unused => {
                chunk_reports.push(empty_chunk_report(
                    chunk_index,
                    offset as u64,
                    slice.len(),
                    ChunkStatus::Unused,
                ));
            }
            ChunkStatus::BadMagic => {
                let detail = match bad_magic {
                    Some([0, 0, 0, 0, 0, 0, 0, 0]) => format!(
                        "chunk {chunk_index} at offset {offset:#x} has zeroed header magic 00 00 00 00 00 00 00 00 with non-zero payload"
                    ),
                    Some(magic) => format!(
                        "chunk {chunk_index} at offset {offset:#x} has invalid magic {}",
                        format_magic(&magic)
                    ),
                    None => format!("chunk {chunk_index} at offset {offset:#x} has invalid magic"),
                };
                chunk_findings.push(Finding {
                    severity: FindingSeverity::Error,
                    kind: "bad_chunk_magic",
                    chunk_index: Some(chunk_index),
                    message: detail,
                });
                chunk_reports.push(empty_chunk_report(
                    chunk_index,
                    offset as u64,
                    slice.len(),
                    ChunkStatus::BadMagic,
                ));
            }
            ChunkStatus::Truncated => {
                if !slice.iter().all(|&b| b == 0)
                    && slice.len() < 8
                    && !CHUNK_MAGIC.starts_with(slice)
                {
                    let hex: Vec<String> = slice.iter().map(|b| format!("{b:02x}")).collect();
                    chunk_findings.push(Finding {
                        severity: FindingSeverity::Error,
                        kind: "bad_chunk_magic",
                        chunk_index: Some(chunk_index),
                        message: format!(
                            "chunk {chunk_index} at offset {offset:#x} is truncated ({} bytes) with non-matching magic {}",
                            slice.len(),
                            hex.join(" ")
                        ),
                    });
                }
                chunk_reports.push(empty_chunk_report(
                    chunk_index,
                    offset as u64,
                    slice.len(),
                    ChunkStatus::Truncated,
                ));
            }
            ChunkStatus::Valid => {
                let header = ChunkHeader::parse(slice);
                if let Some(ref hdr) = header {
                    check_chunk_checksums(chunk_index, hdr, file_no_crc32, &mut chunk_findings);

                    let walk = walk_chunk_records(
                        slice,
                        chunk_index,
                        offset as u64,
                        hdr.free_space_offset,
                    );
                    for recovered in &walk.recovered_errors {
                        chunk_findings.push(Finding {
                            severity: FindingSeverity::Error,
                            kind: "record_framing_error",
                            chunk_index: Some(chunk_index),
                            message: format!("chunk {chunk_index}: {recovered}"),
                        });
                    }
                    let walk_stopped_early = walk.stop_error.is_some();
                    if let Some(stop_err) = walk.stop_error {
                        chunk_findings.push(Finding {
                            severity: FindingSeverity::Error,
                            kind: "record_framing_error",
                            chunk_index: Some(chunk_index),
                            message: format!(
                                "chunk {chunk_index}: {stop_err}; the rest of the chunk was not walked"
                            ),
                        });
                    }
                    zero_time_records += walk
                        .records
                        .iter()
                        .filter(|r| r.timestamp.is_none())
                        .count();
                    for gap in walk.id_gaps {
                        chunk_findings.push(Finding {
                            severity: FindingSeverity::Warning,
                            kind: "record_id_gap",
                            chunk_index: Some(chunk_index),
                            message: format!(
                                "chunk {chunk_index}: {}",
                                describe_id_gap(gap.prev_id, gap.curr_id)
                            ),
                        });
                    }

                    let records_walked = walk.records.len();
                    let first_id = walk.records.first().map(|r| r.record_id);
                    let last_id = walk.records.last().map(|r| r.record_id);
                    let first_ts = walk.records.iter().filter_map(|r| r.timestamp).min();
                    let last_ts = walk.records.iter().filter_map(|r| r.timestamp).max();

                    check_chunk_header_consistency(
                        chunk_index,
                        hdr,
                        records_walked,
                        first_id,
                        last_id,
                        &mut chunk_findings,
                    );

                    if let (Some(first), Some(last)) = (first_id, last_id) {
                        chunk_spans.push(ChunkIdSpan {
                            chunk_index,
                            first_id: first,
                            // A walk that stopped early did not reach the last
                            // record. The header value keeps the comparison
                            // with the next chunk from reporting a false gap.
                            last_id: if walk_stopped_early {
                                hdr.last_event_record_id.max(last)
                            } else {
                                last
                            },
                        });
                    }

                    all_records.extend(walk.records);
                    chunk_reports.push(ChunkReport {
                        index: chunk_index,
                        file_offset: offset as u64,
                        byte_len: slice.len(),
                        status: ChunkStatus::Valid,
                        header,
                        records_walked,
                        first_record_id_walked: first_id,
                        last_record_id_walked: last_id,
                        first_timestamp: first_ts,
                        last_timestamp: last_ts,
                    });
                } else {
                    chunk_reports.push(empty_chunk_report(
                        chunk_index,
                        offset as u64,
                        slice.len(),
                        ChunkStatus::Truncated,
                    ));
                }
            }
        }

        let Some(next_offset) = offset.checked_add(CHUNK_SIZE) else {
            break;
        };
        offset = next_offset;
        chunk_index += 1;
    }

    if let Some(ref fh) = file_header {
        check_file_header(fh, chunk_reports.len(), &mut file_findings);
    }

    check_cross_chunk_id_gaps(&mut chunk_spans, &mut chunk_findings);

    if zero_time_records > 0 {
        file_findings.push(Finding {
            severity: FindingSeverity::Info,
            kind: "zero_record_time",
            chunk_index: None,
            message: format!(
                "{zero_time_records} record(s) have no written time in their framing, which is typical of an exported log; the event time is only in the XML"
            ),
        });
    }

    let mut findings = file_findings;
    findings.extend(chunk_findings);

    let summary = build_summary(&chunk_reports, &all_records, &findings);

    Ok(InspectReport {
        file_size,
        file_header,
        chunks: chunk_reports,
        records: all_records,
        findings,
        summary,
    })
}

#[derive(Debug, Clone, Copy)]
struct ChunkIdSpan {
    chunk_index: usize,
    first_id: u64,
    last_id: u64,
}

fn empty_chunk_report(
    index: usize,
    file_offset: u64,
    byte_len: usize,
    status: ChunkStatus,
) -> ChunkReport {
    ChunkReport {
        index,
        file_offset,
        byte_len,
        status,
        header: None,
        records_walked: 0,
        first_record_id_walked: None,
        last_record_id_walked: None,
        first_timestamp: None,
        last_timestamp: None,
    }
}

fn check_file_header(fh: &FileHeader, chunks_found: usize, findings: &mut Vec<Finding>) {
    let header_chunks = usize::from(fh.chunk_count);
    let count_differs = header_chunks != chunks_found;

    if fh.is_dirty {
        let message = if count_differs {
            format!(
                "file has the dirty flag set (not closed cleanly; header counters can be stale, explaining header chunk count {header_chunks} vs {chunks_found} chunk slots found)"
            )
        } else {
            "file has the dirty flag set (not closed cleanly; header counters can be stale)"
                .to_string()
        };
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            kind: "dirty_flag",
            chunk_index: None,
            message,
        });
    } else if count_differs {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            kind: "chunk_count_mismatch",
            chunk_index: None,
            message: format!(
                "file header reports {header_chunks} chunk(s), but {chunks_found} chunk slot(s) were found"
            ),
        });
    }

    if fh.is_full {
        findings.push(Finding {
            severity: FindingSeverity::Info,
            kind: "full_flag",
            chunk_index: None,
            message: "file has the full flag set (log reached capacity and wrapped)".to_string(),
        });
    }

    if fh.no_crc32 {
        findings.push(Finding {
            severity: FindingSeverity::Info,
            kind: "checksums_disabled",
            chunk_index: None,
            message: "file header has the no-CRC32 flag set; checksum validation skipped"
                .to_string(),
        });
    } else if !fh.checksum_matches() {
        findings.push(Finding {
            severity: FindingSeverity::Error,
            kind: "file_header_checksum_mismatch",
            chunk_index: None,
            message: format!(
                "file header CRC32 mismatch: stored {:#010x}, computed {:#010x}",
                fh.stored_crc32, fh.computed_crc32
            ),
        });
    }
}

fn check_chunk_checksums(
    chunk_index: usize,
    hdr: &ChunkHeader,
    file_no_crc32: bool,
    findings: &mut Vec<Finding>,
) {
    if hdr.no_crc32 {
        if !file_no_crc32 {
            findings.push(Finding {
                severity: FindingSeverity::Info,
                kind: "checksums_disabled",
                chunk_index: Some(chunk_index),
                message: format!(
                    "chunk {chunk_index} has the no-CRC32 flag set; chunk checksum validation skipped"
                ),
            });
        }
        return;
    }

    if !hdr.header_checksum_matches() {
        findings.push(Finding {
            severity: FindingSeverity::Error,
            kind: "chunk_header_checksum_mismatch",
            chunk_index: Some(chunk_index),
            message: format!(
                "chunk {chunk_index} header CRC32 mismatch: stored {:#010x}, computed {:#010x}",
                hdr.stored_header_crc32, hdr.computed_header_crc32
            ),
        });
    }

    match hdr.data_checksum_matches() {
        Some(true) => {}
        Some(false) => {
            let computed = hdr.computed_data_crc32.unwrap_or(0);
            findings.push(Finding {
                severity: FindingSeverity::Error,
                kind: "chunk_data_checksum_mismatch",
                chunk_index: Some(chunk_index),
                message: format!(
                    "chunk {chunk_index} data CRC32 mismatch: stored {:#010x}, computed {computed:#010x}",
                    hdr.stored_data_crc32
                ),
            });
        }
        None => {
            // If free_space_offset is out of the 64 KiB chunk bounds, the header offset itself
            // is corrupt; if within 64 KiB but past a truncated slice, `truncated_file` explains it.
            let free_off = hdr.free_space_offset as usize;
            if !(CHUNK_HEADER_SIZE..=CHUNK_SIZE).contains(&free_off) {
                findings.push(Finding {
                    severity: FindingSeverity::Error,
                    kind: "chunk_data_checksum_mismatch",
                    chunk_index: Some(chunk_index),
                    message: format!(
                        "chunk {chunk_index} data CRC32 cannot be verified: invalid free_space_offset ({free_off})"
                    ),
                });
            }
        }
    }
}

fn check_chunk_header_consistency(
    chunk_index: usize,
    hdr: &ChunkHeader,
    records_walked: usize,
    first_id: Option<u64>,
    last_id: Option<u64>,
    findings: &mut Vec<Finding>,
) {
    let walked_u64 = records_walked as u64;
    let mut diffs = Vec::new();

    match hdr.expected_record_count() {
        Some(expected) if expected == walked_u64 => {}
        Some(expected) => diffs.push(format!(
            "header record count {expected} != walked {walked_u64}"
        )),
        None => diffs.push(format!(
            "header record number range {}..={} is inverted (walked {walked_u64})",
            hdr.first_event_record_number, hdr.last_event_record_number
        )),
    }

    match (first_id, last_id) {
        (Some(first), Some(last)) => {
            if hdr.first_event_record_id != first {
                diffs.push(format!(
                    "header first record id {} != walked {first}",
                    hdr.first_event_record_id
                ));
            }
            if hdr.last_event_record_id != last {
                diffs.push(format!(
                    "header last record id {} != walked {last}",
                    hdr.last_event_record_id
                ));
            }
        }
        _ => {
            if hdr.first_event_record_id != 0 || hdr.last_event_record_id != 0 {
                diffs.push(format!(
                    "header record id range {}..={} has 0 walked records",
                    hdr.first_event_record_id, hdr.last_event_record_id
                ));
            }
        }
    }

    if !diffs.is_empty() {
        findings.push(Finding {
            severity: FindingSeverity::Warning,
            kind: "chunk_header_mismatch",
            chunk_index: Some(chunk_index),
            message: format!("chunk {chunk_index}: {}", diffs.join("; ")),
        });
    }
}

fn check_cross_chunk_id_gaps(spans: &mut [ChunkIdSpan], findings: &mut Vec<Finding>) {
    spans.sort_by_key(|s| (s.first_id, s.chunk_index));
    for pair in spans.windows(2) {
        let prev = pair[0];
        let curr = pair[1];
        if Some(curr.first_id) != prev.last_id.checked_add(1) {
            findings.push(Finding {
                severity: FindingSeverity::Warning,
                kind: "record_id_gap",
                chunk_index: Some(curr.chunk_index),
                message: format!(
                    "between chunk {} (last id {}) and chunk {} (first id {}): {}",
                    prev.chunk_index,
                    prev.last_id,
                    curr.chunk_index,
                    curr.first_id,
                    describe_id_gap(prev.last_id, curr.first_id)
                ),
            });
        }
    }
}

fn build_summary(
    chunks: &[ChunkReport],
    records: &[RecordSummary],
    findings: &[Finding],
) -> InspectSummary {
    let mut valid_chunks = 0usize;
    let mut unused_chunks = 0usize;
    let mut bad_chunks = 0usize;
    for chunk in chunks {
        match chunk.status {
            ChunkStatus::Valid => valid_chunks += 1,
            ChunkStatus::Unused => unused_chunks += 1,
            ChunkStatus::BadMagic | ChunkStatus::Truncated => bad_chunks += 1,
        }
    }

    let first_timestamp = records.iter().filter_map(|r| r.timestamp).min();
    let last_timestamp = records.iter().filter_map(|r| r.timestamp).max();

    let mut info_count = 0usize;
    let mut warning_count = 0usize;
    let mut error_count = 0usize;
    for finding in findings {
        match finding.severity {
            FindingSeverity::Info => info_count += 1,
            FindingSeverity::Warning => warning_count += 1,
            FindingSeverity::Error => error_count += 1,
        }
    }

    InspectSummary {
        total_chunks: chunks.len(),
        valid_chunks,
        unused_chunks,
        bad_chunks,
        total_records: records.len(),
        first_timestamp,
        last_timestamp,
        info_count,
        warning_count,
        error_count,
    }
}

pub(super) fn read_array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    data.get(offset..end)?.try_into().ok()
}

pub(super) fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    read_array::<2>(data, offset).map(u16::from_le_bytes)
}

pub(super) fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    read_array::<4>(data, offset).map(u32::from_le_bytes)
}

pub(super) fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    read_array::<8>(data, offset).map(u64::from_le_bytes)
}

pub(super) fn serialize_opt_ts<S: Serializer>(
    ts: &Option<Timestamp>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match ts {
        Some(t) => serializer.serialize_str(&format_ts(t)),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_path(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
    }

    fn fixture_bytes(rel: &str) -> Vec<u8> {
        std::fs::read(fixture_path(rel)).unwrap()
    }

    #[test]
    fn clean_fixture_has_no_findings_and_matches_evtx_crate_count() {
        let path = fixture_path("tests/fixtures/format/Security_short_selected.evtx");
        let report = inspect_file(&path).unwrap();
        assert!(
            !report.has_findings(),
            "unexpected findings: {:?}",
            report.findings
        );
        assert!(report.findings.is_empty());

        let mut parser = ::evtx::EvtxParser::from_path(&path).unwrap();
        let evtx_count = parser.records().filter(Result::is_ok).count();
        assert_eq!(report.summary.total_records, evtx_count);
        assert_eq!(report.records.len(), evtx_count);
    }

    #[test]
    fn no_crc32_fixture_skips_checksums_without_warnings_or_errors() {
        let path = fixture_path("tests/fixtures/format/Application_no_crc32.evtx");
        let report = inspect_file(&path).unwrap();
        assert!(
            !report.has_findings(),
            "unexpected findings: {:?}",
            report.findings
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].kind, "checksums_disabled");
        assert_eq!(report.findings[0].severity, FindingSeverity::Info);
        assert_eq!(report.summary.total_records, 17);
    }

    #[test]
    fn setting_dirty_bit_gives_dirty_flag_and_no_header_checksum_error() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        bytes[0x78] |= 0x1;
        let report = inspect_bytes(&bytes).unwrap();
        assert!(report.has_findings());
        assert!(report.findings.iter().any(|f| f.kind == "dirty_flag"));
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.kind == "file_header_checksum_mismatch")
        );
    }

    #[test]
    fn dirty_flag_explains_chunk_count_mismatch() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        bytes[0x2A..0x2C].copy_from_slice(&9u16.to_le_bytes());
        let crc = crc32fast::hash(&bytes[..120]);
        bytes[0x7C..0x80].copy_from_slice(&crc.to_le_bytes());

        let clean_mismatch = inspect_bytes(&bytes).unwrap();
        assert!(
            clean_mismatch
                .findings
                .iter()
                .any(|f| f.kind == "chunk_count_mismatch")
        );

        bytes[0x78] |= 0x1;
        let dirty_mismatch = inspect_bytes(&bytes).unwrap();
        assert!(
            !dirty_mismatch
                .findings
                .iter()
                .any(|f| f.kind == "chunk_count_mismatch")
        );
        let dirty = dirty_mismatch
            .findings
            .iter()
            .find(|f| f.kind == "dirty_flag")
            .unwrap();
        assert!(dirty.message.contains("9"));
    }

    #[test]
    fn corrupting_first_120_bytes_gives_file_header_checksum_mismatch() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        bytes[0x18] ^= 0x01;
        let report = inspect_bytes(&bytes).unwrap();
        assert!(report.has_findings());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "file_header_checksum_mismatch")
        );
    }

    #[test]
    fn overwriting_chunk_magic_gives_bad_chunk_magic_and_keeps_other_chunks() {
        let mut bytes = fixture_bytes("tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx");
        // Corrupt chunk 8's magic (`ElfChnk\0`), leaving chunk 9 intact.
        let chunk8_off = 4096 + 8 * 65536;
        bytes[chunk8_off..chunk8_off + 8].copy_from_slice(b"BADCHUNK");
        let report = inspect_bytes(&bytes).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "bad_chunk_magic" && f.chunk_index == Some(8))
        );
        assert_eq!(report.chunks[8].status, ChunkStatus::BadMagic);
        assert_eq!(report.chunks[9].status, ChunkStatus::Valid);
        assert!(report.chunks[9].records_walked > 0);
    }

    #[test]
    fn changing_binxml_byte_gives_chunk_data_checksum_mismatch() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        // First record starts at 4096 + 512; binary XML starts at +24.
        bytes[4096 + 512 + 24] ^= 0x01;
        let report = inspect_bytes(&bytes).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "chunk_data_checksum_mismatch" && f.chunk_index == Some(0))
        );
    }

    #[test]
    fn changing_record_id_with_stale_crc_gives_record_id_gap() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        let rec1_size =
            u32::from_le_bytes(bytes[4096 + 512 + 4..4096 + 512 + 8].try_into().unwrap()) as usize;
        // Change second record's id from 2 to 99.
        let rec2_id_off = 4096 + 512 + rec1_size + 8;
        bytes[rec2_id_off..rec2_id_off + 8].copy_from_slice(&99u64.to_le_bytes());

        let report = inspect_bytes(&bytes).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "record_id_gap" && f.message.contains("missing"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "chunk_data_checksum_mismatch")
        );
    }

    #[test]
    fn corrupting_trailing_size_copy_gives_record_framing_error() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        let rec1_off = 4096 + 512;
        let rec1_size =
            u32::from_le_bytes(bytes[rec1_off + 4..rec1_off + 8].try_into().unwrap()) as usize;
        let tail_off = rec1_off + rec1_size - 4;
        bytes[tail_off..tail_off + 4].copy_from_slice(&0u32.to_le_bytes());

        let report = inspect_bytes(&bytes).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "record_framing_error" && f.chunk_index == Some(0))
        );
        // The leading size still lands on the next record, so the walk goes on
        // and no record id gap is invented.
        let clean = inspect_bytes(&fixture_bytes(
            "tests/fixtures/format/Security_short_selected.evtx",
        ))
        .unwrap();
        assert_eq!(
            report.chunks[0].records_walked,
            clean.chunks[0].records_walked
        );
        assert!(!report.findings.iter().any(|f| f.kind == "record_id_gap"));
    }

    #[test]
    fn corrupting_leading_size_stops_the_walk() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        let rec1_off = 4096 + 512;
        let rec1_size = u32::from_le_bytes(bytes[rec1_off + 4..rec1_off + 8].try_into().unwrap());
        bytes[rec1_off + 4..rec1_off + 8].copy_from_slice(&(rec1_size + 8).to_le_bytes());

        let report = inspect_bytes(&bytes).unwrap();
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "record_framing_error" && f.message.contains("was not walked"))
        );
        assert_eq!(report.chunks[0].records_walked, 0);
    }

    #[test]
    fn zero_written_time_is_reported_and_left_out_of_the_time_range() {
        let report = inspect_file(&fixture_path(
            "tests/fixtures/attack-samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx",
        ))
        .unwrap();
        assert!(!report.has_findings());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "zero_record_time" && f.severity == FindingSeverity::Info)
        );
        let earliest: Timestamp = "2019-01-01T00:00:00Z".parse().unwrap();
        assert!(report.summary.first_timestamp.unwrap() > earliest);
    }

    #[test]
    fn dropping_last_100_bytes_gives_truncated_file() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        bytes.truncate(bytes.len() - 100);
        let report = inspect_bytes(&bytes).unwrap();
        assert!(report.has_findings());
        assert!(report.findings.iter().any(|f| f.kind == "truncated_file"));
    }

    #[test]
    fn short_input_with_valid_magic_does_not_panic() {
        let report = inspect_bytes(b"ElfFile\0\x01\x02").unwrap();
        assert!(report.has_findings());
        assert!(report.findings.iter().any(|f| f.kind == "truncated_file"));
        assert!(report.file_header.is_none());
        let text = report.render_text(true);
        assert!(text.contains("Summary:"));
    }

    #[test]
    fn wrong_magic_returns_err() {
        assert!(inspect_bytes(b"NotAnEvtxFile").is_err());
        assert!(inspect_bytes(b"Elf").is_err());
        assert!(inspect_bytes(b"").is_err());
    }

    #[test]
    fn bad_chunk_magic_fixture_reports_bad_chunk_magic() {
        let path = fixture_path("tests/fixtures/format/sample_with_a_bad_chunk_magic.evtx");
        let report = inspect_file(&path).unwrap();
        assert!(report.has_findings());
        assert!(report.findings.iter().any(|f| f.kind == "bad_chunk_magic"));
        assert_eq!(report.summary.bad_chunks, 2);
        assert_eq!(report.summary.valid_chunks, 4);
        assert_eq!(report.summary.unused_chunks, 10);
    }

    #[test]
    fn render_text_with_records_lists_every_record() {
        let path = fixture_path("tests/fixtures/format/Security_short_selected.evtx");
        let report = inspect_file(&path).unwrap();
        let text_without = report.render_text(false);
        let text_with = report.render_text(true);
        assert!(!text_without.contains("Records ("));
        assert!(text_with.contains("Records (7):"));
        assert!(text_with.contains("Summary: 1 chunk(s)"));
    }

    #[test]
    fn as_json_omits_records_unless_requested() {
        let path = fixture_path("tests/fixtures/format/Security_short_selected.evtx");
        let report = inspect_file(&path).unwrap();

        let without = serde_json::to_value(report.as_json(false)).unwrap();
        assert!(without.get("records").is_none());
        assert_eq!(without["summary"]["total_records"], 7);
        assert!(without["file_header"].is_object());
        assert!(without["chunks"].is_array());
        assert!(without["findings"].is_array());

        let with = serde_json::to_value(report.as_json(true)).unwrap();
        assert_eq!(with["records"].as_array().unwrap().len(), 7);

        let full = serde_json::to_value(&report).unwrap();
        assert_eq!(with, full);
    }

    #[test]
    fn record_ids_and_timestamps_match_evtx_crate_across_clean_fixtures() {
        for rel in [
            "tests/fixtures/format/Security_short_selected.evtx",
            "tests/fixtures/format/Application_no_crc32.evtx",
            "tests/fixtures/attack-samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx",
            "tests/fixtures/attack-samples/DE_Fake_ComputerAccount_4720.evtx",
            "tests/fixtures/attack-samples/DE_RDP_Tunnel_5156.evtx",
            "tests/fixtures/attack-samples/LM_Remote_Service02_7045.evtx",
            "tests/fixtures/attack-samples/LM_ScheduledTask_ATSVC_target_host.evtx",
            "tests/fixtures/attack-samples/LM_sysmon_psexec_smb_meterpreter.evtx",
            "tests/fixtures/attack-samples/phish_windows_credentials_powershell_scriptblockLog_4104.evtx",
        ] {
            let path = fixture_path(rel);
            let report = inspect_file(&path).unwrap();
            assert!(!report.has_findings(), "{rel}: {:?}", report.findings);

            let mut parser = ::evtx::EvtxParser::from_path(&path).unwrap();
            let evtx_records: Vec<(u64, i64)> = parser
                .records()
                .map(|r| {
                    let r = r.unwrap();
                    (r.event_record_id, r.timestamp.as_microsecond())
                })
                .collect();
            let ours: Vec<(u64, i64)> = report
                .records
                .iter()
                .map(|r| {
                    // A zero FILETIME is reported as no time; the crate keeps
                    // it as 1601-01-01.
                    let micros = r
                        .timestamp
                        .map_or(-11_644_473_600_000_000, |t| t.as_microsecond());
                    (r.record_id, micros)
                })
                .collect();
            assert_eq!(ours, evtx_records, "mismatch for {rel}");
        }
    }

    #[test]
    fn full_flag_is_info_only_and_chunk_header_crc_and_mismatch_are_reported() {
        let mut bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        bytes[0x78] |= 0x2;
        let report = inspect_bytes(&bytes).unwrap();
        assert!(!report.has_findings());
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.kind == "full_flag" && f.severity == FindingSeverity::Info)
        );

        // Corrupt chunk header's last_event_record_id without updating chunk header CRC.
        bytes[4096 + 0x20..4096 + 0x28].copy_from_slice(&99u64.to_le_bytes());
        let bad_crc = inspect_bytes(&bytes).unwrap();
        assert!(
            bad_crc
                .findings
                .iter()
                .any(|f| f.kind == "chunk_header_checksum_mismatch")
        );
        assert!(
            bad_crc
                .findings
                .iter()
                .any(|f| f.kind == "chunk_header_mismatch")
        );
    }

    #[test]
    fn cross_chunk_record_id_gap_orders_by_first_record_id() {
        let base = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        let chunk_template = base[4096..4096 + CHUNK_SIZE].to_vec();

        // Build a 2-chunk wrapped file: chunk 0 has records 8..=14, chunk 1 has records 1..=7.
        let mut chunk0 = chunk_template.clone();
        let mut pos = 512usize;
        for new_id in 8u64..=14 {
            let sz = u32::from_le_bytes(chunk0[pos + 4..pos + 8].try_into().unwrap()) as usize;
            chunk0[pos + 8..pos + 16].copy_from_slice(&new_id.to_le_bytes());
            pos += sz;
        }
        chunk0[0x18..0x20].copy_from_slice(&8u64.to_le_bytes());
        chunk0[0x20..0x28].copy_from_slice(&14u64.to_le_bytes());
        let free_off = u32::from_le_bytes(chunk0[0x30..0x34].try_into().unwrap()) as usize;
        let data_crc = crc32fast::hash(&chunk0[512..free_off]);
        chunk0[0x34..0x38].copy_from_slice(&data_crc.to_le_bytes());
        let mut h = crc32fast::Hasher::new();
        h.update(&chunk0[..120]);
        h.update(&chunk0[128..512]);
        chunk0[0x7C..0x80].copy_from_slice(&h.finalize().to_le_bytes());

        let mut wrapped = base[..4096].to_vec();
        wrapped.extend_from_slice(&chunk0);
        wrapped.extend_from_slice(&chunk_template);
        wrapped[0x08..0x10].copy_from_slice(&1u64.to_le_bytes());
        wrapped[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
        wrapped[0x18..0x20].copy_from_slice(&15u64.to_le_bytes());
        wrapped[0x2A..0x2C].copy_from_slice(&2u16.to_le_bytes());
        let hdr_crc = crc32fast::hash(&wrapped[..120]);
        wrapped[0x7C..0x80].copy_from_slice(&hdr_crc.to_le_bytes());

        let ok_wrapped = inspect_bytes(&wrapped).unwrap();
        assert!(
            !ok_wrapped.has_findings(),
            "wrapped chunks should have no gap: {:?}",
            ok_wrapped.findings
        );

        // Now bump chunk 0's first record id from 8 to 10 (leaving a gap 8..=9 across chunks).
        let mut gapped = wrapped;
        let c0 = 4096usize;
        let mut p = c0 + 512;
        for new_id in 10u64..=16 {
            let sz = u32::from_le_bytes(gapped[p + 4..p + 8].try_into().unwrap()) as usize;
            gapped[p + 8..p + 16].copy_from_slice(&new_id.to_le_bytes());
            p += sz;
        }
        gapped[c0 + 0x18..c0 + 0x20].copy_from_slice(&10u64.to_le_bytes());
        gapped[c0 + 0x20..c0 + 0x28].copy_from_slice(&16u64.to_le_bytes());
        let report_gap = inspect_bytes(&gapped).unwrap();
        assert!(
            report_gap
                .findings
                .iter()
                .any(|f| f.kind == "record_id_gap" && f.message.contains("8..=9"))
        );
    }
}
