//! evtx-triage: turns Windows event logs (and a few Linux logs) into a
//! forensic timeline with simple suspicion flags.

pub mod cli;
pub mod detect;
pub mod inspect;
pub mod model;
pub mod output;
pub mod pipeline;
pub mod source;
