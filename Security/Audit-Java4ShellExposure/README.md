# Audit Java4Shell Exposure

Checks a Windows device for **Java4Shell (CVE-2026-114938)**: whether a vulnerable
Java runtime is installed, whether this machine can actually trigger the bug, whether
a mitigation is in place, and whether there are signs someone already tried to
exploit it. Read-only: it changes nothing on the device.

One script, two ways to run it:

| | Interactive | RMM |
|---|---|---|
| Who runs it | You, in an elevated PowerShell window | Your RMM or deployment tool, as SYSTEM, across many devices |
| Settings | Parameters (`-LookbackDays`, `-MaxScanMinutes`) | Parameters or environment variables |
| Output | Progress and a colored report | Plain output with a one-line `Status:` at the end |
| Alerting | Exit code | Exit code 1 when action is needed, `Result: WARNING.` text for warnings |

The script picks the mode automatically. When it runs as SYSTEM or without an
interactive console, which is how RMM tools run scripts, it uses RMM mode; otherwise
it runs interactively. `-Mode Rmm` or `-Mode Interactive` forces one.

## The vulnerability in one paragraph

For a few heavily used methods, the HotSpot JVM swaps in hand-written, CPU-specific
machine code instead of running the Java version. Base64 decoding in
`java.util.Base64` is one of them. On x86-64 CPUs with AVX-512 VBMI, a crafted Base64
input with a short `=` padded tail drives a length counter below zero, the write mask
becomes all ones, and the decoder writes 62 bytes past the end of its buffer. Java's
bounds checks never run on that path, and the damage happens before Java rejects the
malformed input. Anything that decodes untrusted Base64 is a candidate: HTTP Basic
auth, JWTs, SAML, cookies. That makes login pages of Jira, Confluence, Jenkins,
Keycloak and similar apps reachable without authentication.

| Release line | Affected | First fixed build |
|---|---|---|
| 17 | 17.0.6 up to before 17.0.21.1 | 17.0.21.1 |
| 21 | all builds before 21.0.13.1 | 21.0.13.1 |
| 25 | all builds before 25.0.5.1 | 25.0.5.1 |
| 27 | all builds before 27.0.1.1 | 27.0.1.1 |
| 18-20, 22-24, 26 | all builds, end of life | none, move to 21, 25 or 27 |
| 8 | Oracle 8u511-perf (Enterprise Performance Pack) only | 8u513-perf |
| 8 standard, 11, 17.0.0-17.0.5 | not affected | n/a |

All three must be true for a device to be exposed: an affected Java build, a 64-bit
x86 JVM, and a CPU that reports `avx512f`, `avx512bw`, `avx512_vbmi` and `bmi2`. ARM64
and 32-bit JVMs never run the vulnerable code.

## Run it interactively

Open PowerShell with **Run as administrator** (it needs to read every profile,
service and the Security log), then:

```powershell
# Audit this machine
.\Audit-Java4ShellExposure.ps1

# Look back 90 days and save the results as JSON
.\Audit-Java4ShellExposure.ps1 -LookbackDays 90 -ReportPath C:\Temp\java4shell.json

# Get the results as an object
$result = .\Audit-Java4ShellExposure.ps1 -PassThru
$result.Runtimes | Format-Table Path, Version, Verdict

# Audit remote servers (options by position: Mode, LookbackDays, MaxScanMinutes)
$servers = 'APP01', 'APP02'
Invoke-Command -ComputerName $servers -FilePath .\Audit-Java4ShellExposure.ps1 -ArgumentList 'Interactive', 30
```

Pass `'Interactive'` when using `Invoke-Command`, because a remote session has no
interactive console and would otherwise be treated as an RMM run.

If the script is blocked because it was downloaded, run `Unblock-File
.\Audit-Java4ShellExposure.ps1` first, or start PowerShell with `-ExecutionPolicy
Bypass` for that session.

| Parameter | Default | What it does |
|---|---|---|
| `-Mode` | `Auto` | `Auto` detects how it is running. `Rmm` or `Interactive` forces a mode. |
| `-LookbackDays` | 30 | Days of crash logs and event history to check, 1 to 365. |
| `-MaxScanMinutes` | 25 | Time allowed for the drive scan, 1 to 240. Results are marked partial if hit. |
| `-ReportPath` | none | Saves the full results as JSON. |
| `-PassThru` | off | Also returns the results as an object. |

`Get-Help .\Audit-Java4ShellExposure.ps1 -Full` shows the same details.

## Run it from an RMM

Add the script to your RMM as a PowerShell script that runs as **SYSTEM**, and paste
it in unchanged.

- **Timeout:** at least 45 minutes with the default 25-minute scan budget, since the
  JVM checks and event log queries run after the scan. Lower `MaxScanMinutes` if
  your tool has a shorter limit.
- **Settings:** pass `-LookbackDays` and `-MaxScanMinutes` as script arguments, or set
  environment variables named `LookbackDays` and `MaxScanMinutes` if your tool
  passes script variables that way. Arguments win over environment variables.
- **Alerting:** exit code 1 means a runtime is vulnerable, a HIGH exploitation sign
  was found, or the audit failed. Exit code 0 covers both clean and warning results;
  if your tool can match output text, alert on `Result: WARNING.` too.
- **Custom field:** the last line of output is `Status: ...`, one line of up to 255
  characters, ready to copy into a device custom field if your tool supports it.

Run it against all servers and workstations, then sort by status for `FAIL:` first.

## What the results mean

| Result | Exit | Status line example |
|---|---|---|
| Crash in a Base64 decode frame (HIGH sign) | 1 | `FAIL: Java4Shell exploit signs \| 1 found \| see script output \| 2026-11-18` |
| Any runtime VULNERABLE | 1 | `FAIL: Java4Shell vulnerable \| 2 of 3 runtimes \| 2026-11-18` |
| Affected but mitigated, CPU-gated or version unknown | 0, warning | `WARN: Java4Shell affected, not patched \| 1 runtimes \| 2026-11-18` |
| Nothing affected, but weak signs to review | 0, warning | `WARN: Java4Shell patched, review signs \| 2 found \| 2026-11-18` |
| Drive scan ran out of time | 0, warning | `WARN: Java4Shell scan incomplete \| 1 runtimes \| 2026-11-18` |
| Clean | 0 | `OK: Java4Shell not vulnerable \| 3 runtimes \| 2026-11-18` |
| Audit error | 1 | `FAIL: Java4Shell audit error \| see script output \| 2026-11-18` |

Each runtime gets one of: **VULNERABLE** (affected version, 64-bit, CPU exposed or not
confirmed, no mitigation), **MITIGATED, NOT PATCHED** (machine-wide flag, or every
running JVM of that runtime flagged), **AFFECTED VERSION, CPU NOT EXPLOITABLE**,
**VERSION UNKNOWN**, **PATCHED** or **NOT AFFECTED**.

**If you get a HIGH sign:** isolate the device in your EDR, investigate, and rotate
secrets the Java app held in memory (session signing keys, API tokens, database
credentials, TLS private keys), since the bug can leak memory before it gets anywhere
near code execution.

**If a runtime is VULNERABLE:** install the vendor's November 2026 build. Until then,
add `-XX:-UseBASE64Intrinsics` to the service's JVM options and restart it. It turns
off the fast decoder and has no functional impact.

## How it works

1. **Finds runtimes** from the registry (JavaSoft, Adoptium, Azul, Microsoft,
   Corretto, BellSoft, SAP and Oracle keys, plus uninstall entries), machine
   `JAVA_HOME` and `PATH`, running processes, and a scan of every fixed drive for
   `bin\server\jvm.dll`. That catches the Java bundled inside apps, which never shows
   up in installed programs. The scan skips `C:\Windows` (except ServiceProfiles),
   recycle bins and reparse points, goes 12 folders deep, and stops at the time
   budget.
2. **Rates each version** from its `release` file (or the jvm.dll file version) and
   reads the jvm.dll PE header for the architecture.
3. **Checks the CPU** by running `java.exe -Xlog:os+cpu -version` once per affected
   64-bit runtime (up to 10, 30 seconds each). That is the JVM's own report of the
   CPU features it detected, the same information it uses to pick the vulnerable
   decoder. Windows has no built-in way to report AVX-512 VBMI. JVM option variables
   are stripped from this probe because `-XX:UseAVX=2` hides AVX-512 from the report.
   Expect these short `java.exe` launches in your EDR telemetry.
4. **Checks mitigations** (`-XX:-UseBASE64Intrinsics`, `-XX:UseAVX=2` or lower,
   `-XX:DisableIntrinsic=..._base64_decodeBlock`) in machine-wide `JAVA_TOOL_OPTIONS`
   and `_JAVA_OPTIONS`, running JVM command lines, `JDK_JAVA_OPTIONS`, Tomcat procrun
   Java options and service environment values. It finds JVMs running inside service
   wrappers (Jira or Confluence under Tomcat procrun, for example) by looking for a
   loaded `jvm.dll`.
5. **Looks for exploitation signs** within the lookback window: `hs_err_pid*.log`
   crash files on fixed drives and in System32, SysWOW64 and the Windows temp folders;
   Application log event 1000 crashes of `java.exe` or `jvm.dll`; shells and system
   tools (cmd, PowerShell, certutil, mshta, rundll32 and similar) running now as
   children of a JVM; and the same in Security 4688 and Sysmon event 1 history.

## Limitations

- Vendors ship the fix under their own labels (Corretto 17.0.21.1.2, for example). The
  script compares the standard `JAVA_VERSION`, which uses the upstream fixed numbers.
  A distribution that backports the fix under an older number will show as
  VULNERABLE; confirm with that vendor's advisory.
- A machine-wide flag in `JAVA_TOOL_OPTIONS` or `_JAVA_OPTIONS` only protects JVMs
  started after it was set, and Windows services only see new machine variables after
  a reboot.
- The 4688 and Sysmon history lookups match the parent path exactly (case-sensitive)
  and only work when process creation auditing or Sysmon is on. Your EDR's threat
  hunting is the better place for a full hunt of Java-spawned processes.
- Crash files and crash events can come from unrelated JVM bugs. Only a crash with a
  Base64 decode frame is rated HIGH; everything else is listed for review.
- On a virtual machine without AVX-512 VBMI, the verdict can change if the VM moves to
  a newer host.
- Java inside containers, WSL, network shares, removable drives, or folders deeper
  than 12 levels is not covered. Folders the account cannot read are counted and
  skipped.
- Requires Windows PowerShell 5.1 or later. The script relaunches itself as 64-bit
  when started from 32-bit PowerShell, and blocks overlapping runs.

## Sources

Verified 2026-11-18:

- OpenJDK Vulnerability Group advisory and Oracle's November 2026 Critical Security
  Patch Update, as summarized by Tenable, HeroDevs, Datadog Security Labs and AhnLab.
- [Calif, Java4Shell write-up](https://calif.io/java4shell/), for the CPU requirement,
  affected applications and mitigation flags.
- CISA alert "Critical Java Vulnerability Requires Immediate Patching" (2026-11-17).

## License

Copyright 2026 Farid Lavasani. Licensed under the Apache License 2.0, see
[LICENSE](../../LICENSE) and [NOTICE](../../NOTICE). Provided as-is with no warranty.
Review and test it before running it on devices you manage.

Author: [Farid Lavasani](https://github.com/faridlav)
