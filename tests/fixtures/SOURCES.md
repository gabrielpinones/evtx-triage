# Test fixtures

These files are test data. They are not part of the published crate or of the
release archives, and they keep the license of the project they come from.

## attack-samples/ (GPL-3.0)

Unmodified copies from [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
at commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`. License text: `attack-samples/LICENSE.GPL`.

| File | Original directory | SHA-256 |
|---|---|---|
| `4624 LT3 AnonymousLogon Localhost - JuicyPotato.evtx` | Privilege Escalation | `b058ae02bbed96921cc0bb65088a3692b4ccd1c5b7aa65a318df353f09fcf6da` |
| `apt10_jjs_sideloading_prochollowing_persist_as_service_sysmon_1_7_8_13.evtx` | Defense Evasion | `a623b11315eacd9732da5ebeabdb7c72d0f641fdf0ec5d2ec43e360abd13837e` |
| `babyshark_mimikatz_powershell.evtx` | Credential Access | `3747c33a60a32142bf4e30bf023f155b2c0d6e7a018bce8b7bafbd5aa7ec109c` |
| `CA_4624_4625_LogonType2_LogonProc_chrome.evtx` | Credential Access | `75f199b68d473172705bf874720b01820317fdd7aa4843545c98720dd6de197f` |
| `DE_104_system_log_cleared.evtx` | Defense Evasion | `5579cdca073ee4864ea82d656aa2d25400b5c1e85b8e688db5d85f6dc558c2af` |
| `DE_Fake_ComputerAccount_4720.evtx` | Defense Evasion | `8b0c2b1998bbd6292fbd23c2fbd954ed2a0db5ae38f39493e718262b215b4da9` |
| `DE_RDP_Tunnel_5156.evtx` | Command and Control | `25853cab2d474dd52159d45e8c7b139c27b55767be558447ccbc6f494daec786` |
| `DE_RDP_Tunneling_TerminalServices-RemoteConnectionManagerOperational_1149.evtx` | Command and Control | `b9d6d1a3af56501120d1d6b4dbe3d1fc600d88844f255208b4eff0f1e250b00f` |
| `exec_emotet_ps_800_get-item.evtx` | Other/emotet | `ba6381380022037d657972a6146af844fc2c05bab247d56a605ca0148d59a8b9` |
| `kerberos_pwd_spray_4771.evtx` | Credential Access | `4a0a1c7132e216dbc704c806e9429df9ae3ac00485d5238e50c776e3099ae11d` |
| `LM_Remote_Service02_7045.evtx` | Lateral Movement | `af758eb492b6d5ab6665f7e4c44b31490f57be78c37dc0a8b1da714bb0d3d458` |
| `LM_ScheduledTask_ATSVC_target_host.evtx` | Lateral Movement | `53999570b8edb7f909cb07165fecda1f29bf04e3462d13dc404e31f31a9ab932` |
| `LM_sysmon_psexec_smb_meterpreter.evtx` | Lateral Movement | `18ffdda9c24e593d6b1414b6e05c7f7a5dbffb8588a387c165431b61ab52d76f` |
| `Network_Service_Guest_added_to_admins_4732.evtx` | Persistence | `9619b9d9d7bb8a277080167ff639fd9162e3d88d61d674cf1606beadce17ea5a` |
| `phish_windows_credentials_powershell_scriptblockLog_4104.evtx` | Credential Access | `177db8fa70262b4e2eba4e2902c97e82e3c6943fd111bde2ee522d5f1d57e856` |
| `privesc_roguepotato_sysmon_17_18.evtx` | Privilege Escalation | `21bcc12aed93c390545c1b07005a681e1c9e9dbe5d47983c273518456855595d` |
| `remote task update 4624 4702 same logonid.evtx` | Lateral Movement | `82ef6ef9e7616c441e79059fcad9ea7b53358431769e924a0bba6408ecba5fce` |
| `samaccount_spoofing_CVE-2021-42287_CVE-2021-42278_DC_securitylogs.evtx` | Privilege Escalation | `d3cf4940a0400a615e7e848a16de8d957bd12ccb99f7c9ce247b17a72a55d212` |
| `sysmon_20_21_1_CommandLineEventConsumer.evtx` | Persistence | `136cd2549e4944e66c6f26aabafea84011ba011982ac1cf35cde7cb52d32b358` |
| `Sysmon_UACME_64.evtx` | Privilege Escalation | `b1a47437b3095b0660f069d107800427279c07448a4a470ad7c6c7ca2e27bced` |
| `temp_scheduled_task_4698_4699.evtx` | Execution | `a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70` |
| `WinDefender_Events_1117_1116_AtomicRedTeam.evtx` | AutomatedTestingTools | `d7bebbe4a9bd6fdcfe53e019e7386a983f89c2fc7919fc51ecf249453ed60780` |
| `windows_bits_4_59_60_lolbas desktopimgdownldr.evtx` | Execution | `0269326ab0e308192181a470bd588550d524e7cffd13a60373b29b24c32b1ead` |

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
