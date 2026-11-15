//! Stub. The reader is implemented in a later phase.

use std::path::Path;

use crate::model::TimelineEvent;
use crate::source::{ReadOptions, Source, SourceStats};

pub struct AuditdSource;

impl Source for AuditdSource {
    fn read(
        &self,
        _path: &Path,
        _options: &ReadOptions,
        _out: &mut Vec<TimelineEvent>,
    ) -> anyhow::Result<SourceStats> {
        anyhow::bail!("this source is not implemented yet")
    }
}
