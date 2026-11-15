# evtx-triage

A Rust CLI that reads Windows event logs (`.evtx`) offline and produces a timeline for triage, with a few suspicion flags. It also reads journald exports and Linux `audit.log` files.

[Hayabusa](https://github.com/Yamato-Security/hayabusa) and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) do this better: they ship thousands of Sigma rules, cover far more event types and have years of use in real incidents. For a real case, use one of them. This project exists to understand the EVTX format from the inside and to leave that knowledge in code you can read in an afternoon. The section [What is inside an .evtx file](#what-is-inside-an-evtx-file) sums up what I learned.

## Install

Every version tag (`x.y.z`) publishes binaries for Linux (glibc and musl) and Windows on the Releases page, with a `SHA256SUMS` file.

From source, with stable Rust:

```
cargo build --release
./target/release/evtx-triage --help
```

## Usage

```
evtx-triage timeline Security.evtx System.evtx
evtx-triage timeline ./winevt/Logs --flagged-only
evtx-triage timeline ./logs --format csv -o timeline.csv
evtx-triage timeline ./logs --from 2024-05-01T00:00:00Z --to 2024-05-02T00:00:00Z
evtx-triage timeline audit.log --host web01
evtx-triage inspect Security.evtx
```

`timeline` takes files and directories (searched recursively). Each file is recognized by its content, not by its extension. On a terminal it prints a table; into a pipe or with `-o` it writes JSONL, unless `--format` says otherwise.

```
TIME (UTC)           HOST                  ID  EVENT               SUMMARY
2019-02-13 18:01:41  PC01.example.corp   1102  log_clear           Audit log cleared by EXAMPLE\admin01
                     ! high   log_cleared: Security audit log cleared by EXAMPLE\admin01
2019-02-13 18:03:28  PC01.example.corp   4688  process_create      Process C:\Users\user01\Desktop\plink.exe (pid 3324) by EXAMPLE\user01
```

When it finishes, a summary on stderr says how many events came out, which rules fired and whether anything could not be read. `--quiet` hides it.

Exit status: 0 if everything was read, 1 if nothing could be produced, 2 if there is output but part of the input was damaged. For `inspect`, 2 means the file shows damage or signs of tampering.

All times are UTC. Colors follow `NO_COLOR` and `CLICOLOR_FORCE`.

## Events

| Source | Event | Kind in the timeline |
|---|---|---|
| Security | 4624 | `logon_success` |
| Security | 4625 | `logon_failure` |
| Security | 4634, 4647 | `logoff` |
| Security | 4648 | `explicit_logon` |
| Security | 4672 | `special_privileges` |
| Security | 4688 | `process_create` |
| Security | 4697 | `service_install` |
| Security | 4698 | `task_create` |
| Security | 4699 | `task_delete` |
| Security | 4702 | `task_update` |
| Security | 4720 | `user_create` |
| Security | 4728, 4732, 4756 | `group_member_add` |
| Security | 4768 | `kerberos_tgt` |
| Security | 4769 | `kerberos_service_ticket` |
| Security | 4771 | `kerberos_preauth_failure` |
| Security | 4776 | `ntlm_auth` |
| Security | 1102 | `log_clear` |
| System | 104 | `log_clear` |
| System | 7045 | `service_install` |
| Sysmon | 1 | `process_create` |
| Sysmon | 3 | `network_connect` |
| Sysmon | 7 | `image_load` |
| Sysmon | 8 | `remote_thread` |
| Sysmon | 10 | `process_access` |
| Sysmon | 11 | `file_create` |
| Sysmon | 12, 13, 14 | `registry_change` |
| Sysmon | 17, 18 | `named_pipe` |
| Sysmon | 19, 20, 21 | `wmi_persistence` |
| Sysmon | 22 | `dns_query` |
| Sysmon | 23 | `file_delete` |
| TerminalServices-RemoteConnectionManager | 1149 | `rdp_connect` |
| TerminalServices-LocalSessionManager | 21, 24, 25 | `rdp_session` |
| Bits-Client | 59, 60 | `bits_job` |
| WMI-Activity | 5861 | `wmi_persistence` |
| Windows Defender | 1116, 1117 | `defender_detection` |
| Windows Defender | 5001 | `defender_config_change` |
| PowerShell | 4103 | `powershell_pipeline` |
| PowerShell | 4104 | `script_block` |
| Windows PowerShell (classic) | 800 | `powershell_pipeline` |
| Windows PowerShell (classic) | 400, 600 | `powershell_engine` |
| journald | sshd, sudo, su, useradd, logind, unit starts | `logon_*`, `privileged_command`, `user_create`, `service_start` |
| auditd | execve, `USER_LOGIN`, `USER_AUTH`, `USER_CMD`, `ADD_USER`, `SERVICE_START` | `process_create`, `logon_*`, `privileged_command`, `user_create`, `service_start` |

Every other record is counted and dropped.

Sysmon image loads, file creations and registry changes run to millions on a real host. The default profile, `--profile triage`, leaves them out unless a rule flags one, and the summary says how many it left out. `--profile full` keeps them. `--kind` keeps only the kinds you list (the profile then does not apply) and `--exclude-kind` drops kinds.

## Suspicion flags

These are simple heuristics and they give false positives. They help decide where to look first.

| Rule | Severity | Fires when |
|---|---|---|
| `remote_logon_then_service` | high | A service is installed (7045) up to 5 minutes after a network logon (4624 type 3) on the same host. This is the trace PsExec leaves. |
| `encoded_powershell` | high | A command line carries `-EncodedCommand` or any of its abbreviations and the argument decodes to text. The flag includes the decoded command. |
| `encoded_powershell` | medium | A script or command calls `FromBase64String`. |
| `log_cleared` | high | Someone cleared the Security log (1102) or another event log (104). |
| `service_suspicious_path` | medium | A new service runs from `Temp`, `ADMIN$` or a UNC path, runs a command interpreter (`cmd`, PowerShell) or `rundll32` and the like, or has an image path with no directory. |
| `failed_logon_burst` | medium | Five failed logons on one host from the same origin inside the window. |
| `logon_after_failed_burst` | high | A successful logon from that same origin after the burst. |
| `exec_from_tmp` | medium | On Linux, something runs from `/tmp`, `/var/tmp` or `/dev/shm`. |

`--window` changes the correlation window. The rules see the whole timeline before `--from`, `--to` and `--event-id` are applied, so a filter cannot hide the event another one correlates with.

## Output formats

JSONL is the lossless format: one object per event with `ts`, `host`, `source`, `channel`, `provider`, `event_id`, `record_id`, `kind`, `summary`, the common fields that apply (`user`, `src_ip`, `logon_type`, `logon_id`, `process`, `pid`, `parent_process`, `ppid`, `command_line`, `target`), a `details` map with whatever is specific to that event, the `flags` list, and `file`, the path of the log the event came from.

```
evtx-triage timeline ./logs | jq -r 'select(.flags | length > 0) | [.ts, .host, .summary] | @tsv'
```

CSV has one column per field, with `details` as JSON in one cell and the flags in two columns: `flags` (the rule ids) and `flag_reasons`. The content of a log is written by whoever generated the events, the attacker included, and a CSV ends up open in a spreadsheet. So text cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading apostrophe, which keeps them from running as a formula. For the same reason the table replaces control characters before printing: an escape sequence inside a command line never reaches the terminal.

## inspect

`inspect` does not use the `evtx` crate. It reads the file header, each chunk header and the framing of each record by hand, recomputes the three CRC32 checksums and reports what does not add up:

```
$ evtx-triage inspect sample_with_a_bad_chunk_magic.evtx
...
Findings (14):
  warning dirty_flag: file has the dirty flag set (not closed cleanly; header counters can be stale)
  error   chunk_data_checksum_mismatch (chunk 0): chunk 0 data CRC32 mismatch: stored 0xded42440, computed 0x292f55e7
  error   bad_chunk_magic (chunk 6): chunk 6 at offset 0x61000 has zeroed header magic 00 00 00 00 00 00 00 00 with non-zero payload
  warning record_id_gap (chunk 0): between chunk 9 (last id 45949) and chunk 0 (first id 46728): missing record ids 45950..=46727
```

It reports: the dirty flag, a CRC32 mismatch in the file header, a chunk header or the chunk data, an invalid chunk magic, a badly framed record, gaps in the record ids (records may have been removed), header counters that disagree with what was walked, and a truncated file. `--json` gives the report as JSON. `--records` adds every record with its offset, in both forms.

## What is inside an .evtx file

The file starts with a 4096-byte header (`ElfFile\0`), followed by 65536-byte chunks (`ElfChnk\0`). Each chunk has a 512-byte header and then records one after another. A record opens with `2a 2a 00 00`, its size, its id and a FILETIME, carries the event as binary XML and closes with a copy of the size.

What a summary of the format leaves out, and what showed up when testing against real files:

- There are three CRC32 checksums. The file header one covers the first 120 bytes, and the flags sit at offset 0x78, outside that range. Marking a file as dirty does not break its checksum. The chunk header one covers bytes 0 to 120 and 128 to 512, skipping its own field.
- A file can declare that it does not use CRC32 (flag `0x4`). In the samples, each chunk repeats that flag in its own header and stores zero checksums; `inspect` decides by the chunk's flag.
- An unused chunk is 65536 zero bytes. A chunk with a zeroed magic and data further in is damaged. Looking only at the first 8 bytes confuses the two.
- A log exported from Event Viewer is renumbered: the id in the record framing starts at 1, and the original stays in `System.EventRecordID` inside the XML. Some exported records also have a zero FILETIME in the framing. Reading the time from the framing puts those events in the year 1601. The timeline takes the time and the id from the XML, and keeps the framing id in `details.file_record_id` when the two differ.
- The EventID alone does not identify an event. Sysmon's 1 and PowerShell's 4104 exist with other meanings under other providers, so dispatch is by provider and EventID.
- `EventID` arrives as a number or as an object with `Qualifiers` (7045 is one of the second kind).
- 1102 keeps its data in `UserData`, not in `EventData`.
- In 4688, `ProcessId` is the parent process and is written in hexadecimal. `CommandLine` is empty when command line auditing is off, which is the default.
- PowerShell splits a long script across several 4104 records with the same `ScriptBlockId`. They are reassembled before anything is searched in them.
- In `audit.log`, auditd almost never writes the `EOE` record that closes an event, and it hex-encodes any value that contains a space.

## Limits

- About fifty Windows event types. No Sigma engine, no live analysis, no memory or disk forensics.
- 4647, 4697, 4728 and 4756 do not appear in any of the public samples used; their extractors are tested with records built from the documented schema. The same holds for PowerShell 4103, 400 and 600, WMI-Activity 5861, Defender 5001 and the LocalSessionManager events.
- Some fields are logged as references to the provider's message table (`%%1843`, `%%809` in Defender). They are kept as logged, because resolving them needs the message DLLs of a Windows host.
- Binary XML is decoded by the [`evtx`](https://github.com/omerbenamram/evtx) crate. The hand-written parser stops at the record framing.
- `remote_logon_then_service` is tested with hand-built events. Among the 278 public samples used, there is no pair of Security and System logs from the same host and time where it could be seen firing.
- The Linux fixtures are synthetic. The journald reader was also checked against a real export of 20000 entries; the auditd reader has not been run on a real log.
- The selected events are sorted in memory.
- `inspect` stops walking a chunk at the first record whose size does not lead to the next one. The `evtx` crate recovers more records from damaged chunks.

## Tests

```
cargo test
```

The tests read real samples from `tests/fixtures/`: seven logs from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) (GPL-3.0) and three from the `evtx` crate's samples (Apache-2.0), unmodified. `tests/fixtures/SOURCES.md` lists the origin, commit and SHA-256 of each one. They are not part of the package or of the published binaries.

Over the full EVTX-ATTACK-SAMPLES set (278 files, 37364 records) the timeline comes out in 0.4 s on the development machine. A pass of 1200 runs on mutated inputs (flipped bits, truncation, zeroed ranges) ended with no panic.

## License

Code under MIT or Apache-2.0, at your option. The samples in `tests/fixtures/` keep the license of the project they come from.
