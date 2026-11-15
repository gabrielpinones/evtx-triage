use serde::Serialize;

use super::{read_array, read_u32_le, read_u64_le};

pub const CHUNK_SIZE: usize = 65536;
pub const CHUNK_HEADER_SIZE: usize = 512;
pub const CHUNK_MAGIC: &[u8; 8] = b"ElfChnk\0";

// Bit 0x1 is set on active chunks even in clean exported logs; only 0x4 (no CRC32)
// controls chunk checksum verification.
pub const CHUNK_FLAG_NO_CRC32: u32 = 0x4;

/// Classification of a 64 KiB chunk slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChunkStatus {
    Valid,
    Unused,
    BadMagic,
    Truncated,
}

/// Parsed 512-byte EVTX chunk header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChunkHeader {
    pub first_event_record_number: u64,
    pub last_event_record_number: u64,
    pub first_event_record_id: u64,
    pub last_event_record_id: u64,
    pub header_size: u32,
    pub last_event_record_data_offset: u32,
    pub free_space_offset: u32,
    pub stored_data_crc32: u32,
    pub flags: u32,
    pub no_crc32: bool,
    pub stored_header_crc32: u32,
    pub computed_header_crc32: u32,
    pub computed_data_crc32: Option<u32>,
}

impl ChunkHeader {
    /// Parses a chunk header from a chunk slice of at least 512 bytes.
    pub fn parse(chunk: &[u8]) -> Option<Self> {
        let header = chunk.get(0..CHUNK_HEADER_SIZE)?;
        if !header.starts_with(CHUNK_MAGIC) {
            return None;
        }

        let first_event_record_number = read_u64_le(header, 0x08)?;
        let last_event_record_number = read_u64_le(header, 0x10)?;
        let first_event_record_id = read_u64_le(header, 0x18)?;
        let last_event_record_id = read_u64_le(header, 0x20)?;
        let header_size = read_u32_le(header, 0x28)?;
        let last_event_record_data_offset = read_u32_le(header, 0x2C)?;
        let free_space_offset = read_u32_le(header, 0x30)?;
        let stored_data_crc32 = read_u32_le(header, 0x34)?;
        let flags = read_u32_le(header, 0x78)?;
        let stored_header_crc32 = read_u32_le(header, 0x7C)?;

        let mut hasher = crc32fast::Hasher::new();
        hasher.update(header.get(0..120)?);
        hasher.update(header.get(128..CHUNK_HEADER_SIZE)?);
        let computed_header_crc32 = hasher.finalize();

        let computed_data_crc32 = usize::try_from(free_space_offset)
            .ok()
            .and_then(|end| chunk.get(CHUNK_HEADER_SIZE..end))
            .map(crc32fast::hash);

        Some(Self {
            first_event_record_number,
            last_event_record_number,
            first_event_record_id,
            last_event_record_id,
            header_size,
            last_event_record_data_offset,
            free_space_offset,
            stored_data_crc32,
            flags,
            no_crc32: (flags & CHUNK_FLAG_NO_CRC32) != 0,
            stored_header_crc32,
            computed_header_crc32,
            computed_data_crc32,
        })
    }

    /// Record count implied by the header's record number range, or `None` if inverted.
    pub fn expected_record_count(&self) -> Option<u64> {
        if self.first_event_record_number == 0 && self.last_event_record_number == 0 {
            return Some(0);
        }
        self.last_event_record_number
            .checked_sub(self.first_event_record_number)?
            .checked_add(1)
    }

    pub fn header_checksum_matches(&self) -> bool {
        self.no_crc32 || self.stored_header_crc32 == self.computed_header_crc32
    }

    pub fn data_checksum_matches(&self) -> Option<bool> {
        if self.no_crc32 {
            return Some(true);
        }
        self.computed_data_crc32
            .map(|computed| computed == self.stored_data_crc32)
    }
}

/// Classifies a chunk slot as valid, unused, bad magic, or truncated.
pub fn classify_chunk(chunk: &[u8]) -> (ChunkStatus, Option<[u8; 8]>) {
    if chunk.starts_with(CHUNK_MAGIC) {
        if chunk.len() < CHUNK_HEADER_SIZE {
            return (ChunkStatus::Truncated, None);
        }
        return (ChunkStatus::Valid, None);
    }

    if chunk.iter().all(|&b| b == 0) {
        if chunk.len() == CHUNK_SIZE {
            return (ChunkStatus::Unused, None);
        }
        return (ChunkStatus::Truncated, None);
    }

    match read_array::<8>(chunk, 0) {
        Some(magic) => (ChunkStatus::BadMagic, Some(magic)),
        None => (ChunkStatus::Truncated, None),
    }
}

/// Formats an 8-byte magic sequence for analyst messages.
pub fn format_magic(magic: &[u8; 8]) -> String {
    let hex: Vec<String> = magic.iter().map(|b| format!("{b:02x}")).collect();
    let ascii: String = magic
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    format!("{} ({ascii:?})", hex.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_bytes(rel: &str) -> Vec<u8> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
        std::fs::read(path).unwrap()
    }

    #[test]
    fn parses_clean_chunk_header() {
        let bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        let chunk = &bytes[4096..4096 + CHUNK_SIZE];
        let hdr = ChunkHeader::parse(chunk).unwrap();
        assert_eq!(hdr.first_event_record_id, 1);
        assert_eq!(hdr.last_event_record_id, 7);
        assert_eq!(hdr.expected_record_count(), Some(7));
        assert_eq!(hdr.free_space_offset, 8784);
        assert!(!hdr.no_crc32);
        assert!(hdr.header_checksum_matches());
        assert_eq!(hdr.data_checksum_matches(), Some(true));
    }

    #[test]
    fn no_crc32_chunk_sets_chunk_flag_and_zero_crcs() {
        let bytes = fixture_bytes("tests/fixtures/format/Application_no_crc32.evtx");
        let chunk = &bytes[4096..4096 + CHUNK_SIZE];
        let hdr = ChunkHeader::parse(chunk).unwrap();
        assert!(hdr.no_crc32);
        assert_eq!(hdr.stored_header_crc32, 0);
        assert_eq!(hdr.stored_data_crc32, 0);
        assert_eq!(hdr.first_event_record_number, 1);
        assert_eq!(hdr.last_event_record_number, 17);
        assert_eq!(hdr.first_event_record_id, 426);
        assert_eq!(hdr.last_event_record_id, 442);
        assert!(hdr.header_checksum_matches());
        assert_eq!(hdr.data_checksum_matches(), Some(true));
    }

    #[test]
    fn unused_vs_zeroed_header_bad_magic() {
        let zeros = vec![0u8; CHUNK_SIZE];
        assert_eq!(classify_chunk(&zeros), (ChunkStatus::Unused, None));

        let mut partial_zero = vec![0u8; CHUNK_SIZE];
        partial_zero[57345] = 0x58;
        assert_eq!(
            classify_chunk(&partial_zero),
            (ChunkStatus::BadMagic, Some([0u8; 8]))
        );
    }
}
