use std::borrow::Cow;
use std::io::Write;

use crate::model::{self, Flag, TimelineEvent};

const HEADER: [&str; 23] = [
    "ts",
    "host",
    "source",
    "channel",
    "provider",
    "event_id",
    "record_id",
    "kind",
    "user",
    "src_ip",
    "logon_type",
    "logon_id",
    "process",
    "pid",
    "parent_process",
    "ppid",
    "command_line",
    "target",
    "summary",
    "flags",
    "flag_reasons",
    "details",
    "file",
];

pub fn write(out: &mut dyn Write, events: &[TimelineEvent]) -> anyhow::Result<()> {
    let mut wtr = ::csv::Writer::from_writer(out);
    wtr.write_record(HEADER)?;

    for event in events {
        let ts = model::format_ts(&event.ts);
        let event_id = opt_num(event.event_id);
        let record_id = opt_num(event.record_id);
        let logon_type = opt_num(event.logon_type);
        let pid = opt_num(event.pid);
        let ppid = opt_num(event.ppid);
        let flags = format_flags(&event.flags);
        let flag_reasons = format_flag_reasons(&event.flags);
        let details = if event.details.is_empty() {
            String::new()
        } else {
            sanitize_cell(&serde_json::to_string(&event.details)?).into_owned()
        };

        wtr.write_record([
            ts.as_str(),
            sanitize_cell(&event.host).as_ref(),
            event.source.as_str(),
            opt_text(event.channel.as_deref()).as_ref(),
            opt_text(event.provider.as_deref()).as_ref(),
            event_id.as_str(),
            record_id.as_str(),
            event.kind.as_str(),
            opt_text(event.user.as_deref()).as_ref(),
            opt_text(event.src_ip.as_deref()).as_ref(),
            logon_type.as_str(),
            opt_text(event.logon_id.as_deref()).as_ref(),
            opt_text(event.process.as_deref()).as_ref(),
            pid.as_str(),
            opt_text(event.parent_process.as_deref()).as_ref(),
            ppid.as_str(),
            opt_text(event.command_line.as_deref()).as_ref(),
            opt_text(event.target.as_deref()).as_ref(),
            sanitize_cell(&event.summary).as_ref(),
            sanitize_cell(&flags).as_ref(),
            flag_reasons.as_str(),
            details.as_str(),
            sanitize_cell(&event.file).as_ref(),
        ])?;
    }

    wtr.flush()?;
    Ok(())
}

// Prefix spreadsheet formula triggers so untrusted log text cannot execute in
// Excel or LibreOffice; the JSONL output is the lossless one.
fn sanitize_cell(value: &str) -> Cow<'_, str> {
    if value.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        Cow::Owned(format!("'{value}"))
    } else {
        Cow::Borrowed(value)
    }
}

fn opt_text(value: Option<&str>) -> Cow<'_, str> {
    match value {
        Some(v) => sanitize_cell(v),
        None => Cow::Borrowed(""),
    }
}

fn opt_num<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

fn format_flags(flags: &[Flag]) -> String {
    flags.iter().map(|f| f.rule).collect::<Vec<_>>().join(";")
}

fn format_flag_reasons(flags: &[Flag]) -> String {
    let joined = flags
        .iter()
        .map(|f| format!("{}: {}", f.rule, f.reason))
        .collect::<Vec<_>>()
        .join(" | ");
    sanitize_cell(&joined).into_owned()
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use serde_json::json;

    use crate::model::{EventKind, Flag, Severity, SourceKind, TimelineEvent};

    use super::{HEADER, write};

    #[test]
    fn empty_timeline_writes_only_header() {
        let mut buf = Vec::new();
        write(&mut buf, &[]).unwrap();

        let mut rdr = ::csv::Reader::from_reader(buf.as_slice());
        assert_eq!(rdr.headers().unwrap().iter().collect::<Vec<_>>(), HEADER);
        assert_eq!(rdr.records().count(), 0);
    }

    #[test]
    fn writes_records_with_escaping_and_empty_absent_cells() {
        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        let mut e1 = TimelineEvent::new(
            ts,
            "host1",
            SourceKind::Evtx,
            EventKind::ProcessCreate,
            "a.evtx",
        );
        e1.channel = Some("Security".into());
        e1.event_id = Some(4688);
        e1.pid = Some(1234);
        e1.command_line = Some("cmd.exe /c \"echo a,b\"\nnext".into());
        e1.summary = "proc".into();
        e1.details
            .insert("note".into(), json!("has, comma \"quote\"\nand newline"));
        e1.flags.push(Flag {
            rule: "r1",
            severity: Severity::Medium,
            reason: "reason one".into(),
            related: vec![],
        });
        e1.flags.push(Flag {
            rule: "r2",
            severity: Severity::High,
            reason: "reason two".into(),
            related: vec![],
        });

        let e2 = TimelineEvent::new(
            ts,
            "host2",
            SourceKind::Journald,
            EventKind::LogonSuccess,
            "b.json",
        );

        let mut buf = Vec::new();
        write(&mut buf, &[e1, e2]).unwrap();

        let mut rdr = ::csv::Reader::from_reader(buf.as_slice());
        assert_eq!(rdr.headers().unwrap().iter().collect::<Vec<_>>(), HEADER);

        let records: Vec<::csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
        assert_eq!(records.len(), 2);

        let r1 = &records[0];
        assert_eq!(&r1[0], "2023-11-14T22:13:20.000000Z");
        assert_eq!(&r1[1], "host1");
        assert_eq!(&r1[2], "evtx");
        assert_eq!(&r1[3], "Security");
        assert_eq!(&r1[4], ""); // provider absent
        assert_eq!(&r1[5], "4688");
        assert_eq!(&r1[6], ""); // record_id absent
        assert_eq!(&r1[7], "process_create");
        assert_eq!(&r1[13], "1234");
        assert_eq!(&r1[16], "cmd.exe /c \"echo a,b\"\nnext");
        assert_eq!(&r1[19], "r1;r2");
        assert_eq!(&r1[20], "r1: reason one | r2: reason two");
        assert_eq!(
            &r1[21],
            "{\"note\":\"has, comma \\\"quote\\\"\\nand newline\"}"
        );
        assert_eq!(&r1[22], "a.evtx");

        let r2 = &records[1];
        assert_eq!(&r2[3], "");
        assert_eq!(&r2[5], "");
        assert_eq!(&r2[16], "");
        assert_eq!(&r2[19], "");
        assert_eq!(&r2[20], "");
        assert_eq!(&r2[21], "");
    }

    #[test]
    fn formula_injection_prefixes_dangerous_text_cells() {
        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        let payloads = [
            ("=cmd|' /C calc'!A0", "'=cmd|' /C calc'!A0"),
            ("@SUM(1)", "'@SUM(1)"),
            ("+1", "'+1"),
            ("-1", "'-1"),
            ("\tcmd", "'\tcmd"),
            ("\rcmd", "'\rcmd"),
            ("cmd.exe /c x", "cmd.exe /c x"),
        ];

        let events: Vec<TimelineEvent> = payloads
            .iter()
            .map(|(cmd, _)| {
                let mut e = TimelineEvent::new(
                    ts,
                    "host",
                    SourceKind::Evtx,
                    EventKind::ProcessCreate,
                    "a.evtx",
                );
                e.command_line = Some((*cmd).into());
                e
            })
            .collect();

        let mut buf = Vec::new();
        write(&mut buf, &events).unwrap();

        let mut rdr = ::csv::Reader::from_reader(buf.as_slice());
        for (rec, (_, expected)) in rdr.records().zip(payloads.iter()) {
            let rec = rec.unwrap();
            assert_eq!(&rec[16], *expected);
        }
    }
}
