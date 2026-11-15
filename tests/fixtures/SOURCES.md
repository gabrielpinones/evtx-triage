# Test fixtures

These files are test data. They are not part of the published crate or of the
release archives, and they keep the license of the project they come from.

## attack-samples/ (GPL-3.0)

Unmodified copies from [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
at commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`. License text: `attack-samples/LICENSE.GPL`.

| File | Original directory | SHA-256 |
|---|---|---|
| `CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | Credential Access | `75f199b68d473172705bf874720b01820317fdd7aa4843545c98720dd6de197f` |
| `DE_Fake_ComputerAccount_4720.evtx` | Defense Evasion | `8b0c2b1998bbd6292fbd23c2fbd954ed2a0db5ae38f39493e718262b215b4da9` |
| `DE_RDP_Tunnel_5156.evtx` | Command and Control | `25853cab2d474dd52159d45e8c7b139c27b55767be558447ccbc6f494daec786` |
| `LM_Remote_Service02_7045.evtx` | Lateral Movement | `af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458` |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | Lateral Movement | `53999570b8edb7f909cb07165fecda1f29bf04e3462d13dc404e31f31a9ab932` |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | Lateral Movement | `18ffdda9c24e593d6b1414b6e05c7f7a5dbffb8588a387c165431b61ab52d76f` |
| `phish_windows_credentials_powershell_scriptblockLog_4104.evtx` | Credential Access | `177db8fa70262b4e2eba4e2902c97e82e3c6943fd111bde2ee522d5f1d57e856` |

## format/ (Apache-2.0)

Unmodified copies from the `samples/` directory of [omerbenamram/evtx](https://github.com/omerbenamram/evtx)
at commit `c72a5fa0bb4fc284fbc0c39b9c2f6b329005ac67`.

| File | SHA-256 |
|---|---|
| `Application_no_crc32.evtx` | `2b128dc61812123a34ab2808502c6d48a0db6018e6b21bfb4f0be12d6dad2596` |
| `Security_short_selected.evtx` | `50c87926d2dfed9776906ffbcc77e61577940910a71fb1c1871860a4e2213456` |
| `sample_with_a_bad_chunk_magic.evtx` | `456d7645be38a8f72e9c9eb6c4fe42eac9c83d6ad34a9d039616af205e3bdc6f` |

## linux/

Synthetic journald and auditd logs written for this project. Same license as
the code.
