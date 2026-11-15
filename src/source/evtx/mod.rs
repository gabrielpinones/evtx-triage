//! Stub. The reader is implemented in a later phase.

use std::path::Path;

use crate::model::TimelineEvent;
use crate::source::{ReadOptions, Source, SourceStats};

pub struct EvtxSource;

impl Source for EvtxSource {
    fn read(
        &self,
        _path: &Path,
        _options: &ReadOptions,
        _out: &mut Vec<TimelineEvent>,
    ) -> anyhow::Result<SourceStats> {
        anyhow::bail!("this source is not implemented yet")
    }
}
