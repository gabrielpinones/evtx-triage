use std::io::Write;

use crate::model::TimelineEvent;

pub fn write(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    for event in events {
        serde_json::to_writer(&mut *out, event)?;
        out.write_all(b"\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use serde_json::json;

    use crate::model::{EventKind, Flag, Severity, SourceKind, TimelineEvent};

    use super::write;

    #[test]
    fn empty_timeline_writes_nothing() {
        let mut buf = Vec::new();
        write(&mut buf, &[]).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn writes_one_compact_json_line_per_event() {
        let ts1 = Timestamp::from_second(1_700_000_000).unwrap();
        let ts2 = Timestamp::from_second(1_700_000_001).unwrap();

        let mut e1 = TimelineEvent::new(
            ts1,
            "host1",
            SourceKind::Evtx,
            EventKind::LogClear,
            "a.evtx",
        );
        e1.event_id = Some(1102);
        e1.command_line = Some("wevtutil cl Security".into());
        e1.details.insert("key".into(), json!("val"));
        e1.flags.push(Flag {
            rule: "log_cleared",
            severity: Severity::High,
            reason: "audit log cleared".into(),
            related: vec![],
        });

        let e2 = TimelineEvent::new(
            ts2,
            "host2",
            SourceKind::Auditd,
            EventKind::UserCreate,
            "b.log",
        );

        let mut buf = Vec::new();
        write(&mut buf, &[e1, e2]).unwrap();
        let text = String::from_utf8(buf).unwrap();

        assert!(text.ends_with('\n'));
        assert!(!text.ends_with("\n\n"));

        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        let v1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(v1["host"], "host1");
        assert_eq!(v1["source"], "evtx");
        assert_eq!(v1["event_id"], 1102);
        assert_eq!(v1["command_line"], "wevtutil cl Security");
        assert_eq!(v1["details"]["key"], "val");
        assert_eq!(v1["flags"][0]["rule"], "log_cleared");

        let v2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v2["host"], "host2");
        assert_eq!(v2["source"], "auditd");
        assert!(v2.get("event_id").is_none());
    }
}
