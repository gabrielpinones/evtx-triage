use serde::Serialize;

use super::{read_u16_le, read_u32_le, read_u64_le};

pub const EVTX_MAGIC: &[u8; 8] = b"ElfFile\0";
pub const FILE_HEADER_SIZE: usize = 128;
pub const FILE_HEADER_BLOCK_SIZE: usize = 4096;
const FILE_HEADER_CRC_LEN: usize = 120;

pub const FLAG_DIRTY: u32 = 0x1;
pub const FLAG_FULL: u32 = 0x2;
pub const FLAG_NO_CRC32: u32 = 0x4;

/// Parsed 128-byte EVTX file header at offset 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileHeader {
    pub first_chunk_number: u64,
    pub last_chunk_number: u64,
    pub next_record_id: u64,
    pub header_size: u32,
    pub minor_version: u16,
    pub major_version: u16,
    pub header_block_size: u16,
    pub chunk_count: u16,
    pub flags: u32,
    pub is_dirty: bool,
    pub is_full: bool,
    pub no_crc32: bool,
    pub stored_crc32: u32,
    pub computed_crc32: u32,
}

impl FileHeader {
    /// Parses the fixed 128-byte EVTX file header.
    ///
    /// Returns `None` if `data` is shorter than 128 bytes or does not start with
    /// the EVTX file magic.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let header = data.get(0..FILE_HEADER_SIZE)?;
        if !header.starts_with(EVTX_MAGIC) {
            return None;
        }

        let first_chunk_number = read_u64_le(header, 0x08)?;
        let last_chunk_number = read_u64_le(header, 0x10)?;
        let next_record_id = read_u64_le(header, 0x18)?;
        let header_size = read_u32_le(header, 0x20)?;
        let minor_version = read_u16_le(header, 0x24)?;
        let major_version = read_u16_le(header, 0x26)?;
        let header_block_size = read_u16_le(header, 0x28)?;
        let chunk_count = read_u16_le(header, 0x2A)?;
        let flags = read_u32_le(header, 0x78)?;
        let stored_crc32 = read_u32_le(header, 0x7C)?;
        let computed_crc32 = crc32fast::hash(header.get(0..FILE_HEADER_CRC_LEN)?);

        Some(Self {
            first_chunk_number,
            last_chunk_number,
            next_record_id,
            header_size,
            minor_version,
            major_version,
            header_block_size,
            chunk_count,
            flags,
            is_dirty: (flags & FLAG_DIRTY) != 0,
            is_full: (flags & FLAG_FULL) != 0,
            no_crc32: (flags & FLAG_NO_CRC32) != 0,
            stored_crc32,
            computed_crc32,
        })
    }

    pub fn checksum_matches(&self) -> bool {
        self.no_crc32 || self.stored_crc32 == self.computed_crc32
    }

    pub fn format_flags(&self) -> String {
        let mut names = Vec::new();
        if self.is_dirty {
            names.push("dirty");
        }
        if self.is_full {
            names.push("full");
        }
        if self.no_crc32 {
            names.push("no_crc32");
        }
        let known_mask = FLAG_DIRTY | FLAG_FULL | FLAG_NO_CRC32;
        if (self.flags & !known_mask) != 0 {
            names.push("unknown");
        }
        if names.is_empty() {
            format!("{:#010x} (none)", self.flags)
        } else {
            format!("{:#010x} ({})", self.flags, names.join(", "))
        }
    }
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
    fn parses_clean_file_header() {
        let bytes = fixture_bytes("tests/fixtures/format/Security_short_selected.evtx");
        let hdr = FileHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.major_version, 3);
        assert_eq!(hdr.minor_version, 1);
        assert_eq!(hdr.header_size, 128);
        assert_eq!(hdr.header_block_size, 4096);
        assert_eq!(hdr.chunk_count, 1);
        assert_eq!(hdr.next_record_id, 8);
        assert!(!hdr.is_dirty);
        assert!(!hdr.is_full);
        assert!(!hdr.no_crc32);
        assert!(hdr.checksum_matches());
    }

    #[test]
    fn parses_no_crc32_file_header() {
        let bytes = fixture_bytes("tests/fixtures/format/Application_no_crc32.evtx");
        let hdr = FileHeader::parse(&bytes).unwrap();
        assert_eq!(hdr.major_version, 3);
        assert_eq!(hdr.minor_version, 2);
        assert!(hdr.no_crc32);
        assert_eq!(hdr.stored_crc32, 0);
        assert_ne!(hdr.computed_crc32, 0);
        assert!(hdr.checksum_matches());
    }

    #[test]
    fn rejects_short_or_wrong_magic_header() {
        assert!(FileHeader::parse(b"ElfFile\0\x01\x02").is_none());
        let mut wrong = vec![0u8; 4096];
        wrong[..8].copy_from_slice(b"NotEvtx!");
        assert!(FileHeader::parse(&wrong).is_none());
    }
}
