use jiff::Timestamp;
use serde::Serialize;

use super::chunk_header::CHUNK_HEADER_SIZE;
use super::{read_u32_le, read_u64_le, serialize_opt_ts};

pub const RECORD_MAGIC: &[u8; 4] = b"\x2a\x2a\x00\x00";
pub const MIN_RECORD_SIZE: u32 = 28;
const FILETIME_UNIX_EPOCH_100NS: u64 = 116_444_736_000_000_000;

/// Metadata for one framed EVTX event record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecordSummary {
    pub chunk_index: usize,
    pub record_id: u64,
    #[serde(serialize_with = "serialize_opt_ts")]
    pub timestamp: Option<Timestamp>,
    pub size: u32,
    pub file_offset: u64,
}

/// Non-consecutive record id pair observed during a walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdTransition {
    pub prev_id: u64,
    pub curr_id: u64,
}

/// Result of walking the framed records inside a single chunk.
#[derive(Debug, Clone)]
pub struct RecordWalk {
    pub records: Vec<RecordSummary>,
    /// Why the walk ended before the free space offset, if it did.
    pub stop_error: Option<String>,
    /// Damaged records the walk could step over.
    pub recovered_errors: Vec<String>,
    pub id_gaps: Vec<IdTransition>,
}

/// Converts a Windows FILETIME (100 ns ticks since 1601-01-01 UTC) to a UTC `Timestamp`.
pub fn filetime_to_timestamp(filetime: u64) -> Option<Timestamp> {
    let diff_100ns = i128::from(filetime).checked_sub(i128::from(FILETIME_UNIX_EPOCH_100NS))?;
    let unix_micros = i64::try_from(diff_100ns.div_euclid(10)).ok()?;
    Timestamp::from_microsecond(unix_micros).ok()
}

/// Describes missing or out-of-order record ids between two consecutive records.
pub fn describe_id_gap(prev_id: u64, curr_id: u64) -> String {
    if let Some(expected) = prev_id.checked_add(1)
        && curr_id > expected
    {
        let first_missing = expected;
        let last_missing = curr_id - 1;
        if first_missing == last_missing {
            return format!("missing record id {first_missing}");
        }
        return format!("missing record ids {first_missing}..={last_missing}");
    }
    let expected = prev_id.saturating_add(1);
    format!("non-consecutive id {curr_id} after {prev_id} (expected {expected})")
}

/// Walks records from chunk offset 512 up to `free_space_offset`, stopping on the first framing error.
pub fn walk_chunk_records(
    chunk: &[u8],
    chunk_index: usize,
    chunk_file_offset: u64,
    free_space_offset: u32,
) -> RecordWalk {
    let mut records = Vec::new();
    let mut id_gaps = Vec::new();
    let mut recovered_errors = Vec::new();

    let Ok(free_off) = usize::try_from(free_space_offset) else {
        return RecordWalk {
            records,
            stop_error: Some(format!(
                "free_space_offset ({free_space_offset}) exceeds addressable size"
            )),
            id_gaps,
            recovered_errors,
        };
    };

    if free_off < CHUNK_HEADER_SIZE {
        return RecordWalk {
            records,
            stop_error: Some(format!(
                "free_space_offset ({free_off}) is inside the 512-byte chunk header"
            )),
            id_gaps,
            recovered_errors,
        };
    }

    let walk_limit = free_off.min(chunk.len());
    let mut pos = CHUNK_HEADER_SIZE;
    let mut prev_id: Option<u64> = None;
    let mut stop_error = None;

    while pos < walk_limit {
        let file_off = chunk_file_offset.saturating_add(pos as u64);

        let Some(min_end) = pos.checked_add(MIN_RECORD_SIZE as usize) else {
            stop_error = Some(format!(
                "offset overflow at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        };
        if min_end > walk_limit {
            stop_error = Some(format!(
                "truncated record framing at chunk offset {pos} (file offset {file_off:#x}): fewer than 28 bytes remain before limit {walk_limit}"
            ));
            break;
        }

        let Some(magic) = chunk.get(pos..pos + 4) else {
            stop_error = Some(format!(
                "truncated record magic at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        };
        if magic != RECORD_MAGIC {
            stop_error = Some(format!(
                "bad record magic {:02x?} at chunk offset {pos} (file offset {file_off:#x})",
                magic
            ));
            break;
        }

        let Some(size) = read_u32_le(chunk, pos + 4) else {
            stop_error = Some(format!(
                "truncated record size at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        };
        if size < MIN_RECORD_SIZE {
            stop_error = Some(format!(
                "record size {size} (< 28) at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        }

        let Ok(size_usize) = usize::try_from(size) else {
            stop_error = Some(format!(
                "record size {size} exceeds addressable size at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        };
        let Some(record_end) = pos.checked_add(size_usize) else {
            stop_error = Some(format!(
                "record size {size} overflows offset at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        };
        if record_end > walk_limit {
            let reason = if record_end > free_off && record_end > chunk.len() {
                format!(
                    "runs past free_space_offset ({free_off}) and chunk end ({})",
                    chunk.len()
                )
            } else if record_end > free_off {
                format!("runs past free_space_offset ({free_off})")
            } else {
                format!("runs past chunk end ({})", chunk.len())
            };
            stop_error = Some(format!(
                "record at chunk offset {pos} (file offset {file_off:#x}) of size {size} {reason}"
            ));
            break;
        }

        let tail_size = record_end
            .checked_sub(4)
            .and_then(|off| read_u32_le(chunk, off));
        if tail_size != Some(size) {
            let found = tail_size
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_string());
            let message = format!(
                "record at chunk offset {pos} (file offset {file_off:#x}) trailing size copy ({found}) differs from leading size ({size})"
            );
            // The leading size is still trustworthy when it lands exactly on
            // the next record or on the end of the data: report the damage
            // and keep walking, so one bad record does not hide the rest of
            // the chunk and fake a gap in the record ids.
            let lands_on_record = chunk.get(record_end..record_end.saturating_add(4))
                == Some(RECORD_MAGIC.as_slice());
            if record_end == walk_limit || lands_on_record {
                recovered_errors.push(message);
            } else {
                stop_error = Some(message);
                break;
            }
        }

        let Some(record_id) = read_u64_le(chunk, pos + 8) else {
            stop_error = Some(format!(
                "truncated record id at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        };
        let Some(filetime) = read_u64_le(chunk, pos + 16) else {
            stop_error = Some(format!(
                "truncated record timestamp at chunk offset {pos} (file offset {file_off:#x})"
            ));
            break;
        };

        if let Some(prev) = prev_id
            && Some(record_id) != prev.checked_add(1)
        {
            id_gaps.push(IdTransition {
                prev_id: prev,
                curr_id: record_id,
            });
        }
        prev_id = Some(record_id);

        records.push(RecordSummary {
            chunk_index,
            record_id,
            // An exported log can leave the written time at zero; the event
            // time then exists only inside the XML.
            timestamp: (filetime != 0)
                .then(|| filetime_to_timestamp(filetime))
                .flatten(),
            size,
            file_offset: file_off,
        });

        pos = record_end;
    }

    if stop_error.is_none() && pos < free_off {
        stop_error = Some(format!(
            "record walk stopped at chunk offset {pos} (chunk end {}) before free_space_offset ({free_off})",
            chunk.len()
        ));
    }

    RecordWalk {
        records,
        stop_error,
        id_gaps,
        recovered_errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_known_filetime_values() {
        assert_eq!(
            filetime_to_timestamp(FILETIME_UNIX_EPOCH_100NS),
            Some(Timestamp::UNIX_EPOCH)
        );
        // 2023-11-14T22:13:20.123456Z -> 1_700_000_000_123_456 us
        let ft = 1_700_000_000_123_456u64 * 10 + FILETIME_UNIX_EPOCH_100NS;
        let ts = filetime_to_timestamp(ft).unwrap();
        assert_eq!(crate::model::format_ts(&ts), "2023-11-14T22:13:20.123456Z");

        // Windows epoch 1601-01-01T00:00:00Z
        assert_eq!(
            crate::model::format_ts(&filetime_to_timestamp(0).unwrap()),
            "1601-01-01T00:00:00.000000Z"
        );
        assert_eq!(filetime_to_timestamp(u64::MAX), None);
    }

    #[test]
    fn stops_on_bad_magic_and_short_size() {
        let mut chunk = vec![0u8; 600];
        chunk[512..516].copy_from_slice(b"BAD!");
        let walk = walk_chunk_records(&chunk, 0, 4096, 560);
        assert!(walk.records.is_empty());
        assert!(
            walk.stop_error
                .as_deref()
                .unwrap()
                .contains("bad record magic")
        );

        chunk[512..516].copy_from_slice(RECORD_MAGIC);
        chunk[516..520].copy_from_slice(&24u32.to_le_bytes());
        let walk = walk_chunk_records(&chunk, 0, 4096, 560);
        assert!(walk.records.is_empty());
        assert!(walk.stop_error.as_deref().unwrap().contains("< 28"));
    }
}
