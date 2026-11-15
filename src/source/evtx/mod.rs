//! Windows EVTX event log source.

mod account;
mod dispatch;
mod fields;
mod kerberos;
mod logon;
mod powershell;
mod process;
mod reader;
mod service;
mod task;

use std::path::Path;

use crate::model::TimelineEvent;
use crate::source::{ReadOptions, Source, SourceStats};

pub struct EvtxSource;

impl Source for EvtxSource {
    fn read(
        &self,
        path: &Path,
        options: &ReadOptions,
        out: &mut Vec<TimelineEvent>,
    ) -> anyhow::Result<SourceStats> {
        reader::read_file(path, options, out)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::source::{Format, ReadOptions, source_for};

    #[test]
    fn evtx_source_counts_seen_vs_emitted() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/attack-samples/DE_RDP_Tunnel_5156.evtx");
        let src = source_for(Format::Evtx);
        let mut events = Vec::new();
        let stats = src
            .read(&path, &ReadOptions::default(), &mut events)
            .unwrap();
        assert_eq!(stats.errors, 0);
        assert!(!events.is_empty());
        assert_eq!(stats.events_emitted, events.len() as u64);
        assert!(stats.records_seen > stats.events_emitted);
    }

    #[test]
    fn exported_log_uses_time_and_record_id_from_the_xml() {
        // This sample was re-exported: its record framing is renumbered from 1
        // and some records carry a zero FILETIME.
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/attack-samples/CA_4624_4625_LogonType2_LogonProc_chrome.evtx");
        let mut events = Vec::new();
        source_for(Format::Evtx)
            .read(&path, &ReadOptions::default(), &mut events)
            .unwrap();
        assert!(!events.is_empty());
        let earliest: jiff::Timestamp = "2019-01-01T00:00:00Z".parse().unwrap();
        for event in &events {
            assert!(
                event.ts > earliest,
                "bad time {} in {}",
                event.ts,
                event.summary
            );
            assert!(event.details.contains_key("file_record_id"));
        }
    }
}
