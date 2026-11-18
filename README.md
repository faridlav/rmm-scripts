# RMM Scripts

PowerShell scripts for managing and securing Windows fleets. Each one runs two ways:
by hand in an elevated PowerShell window, or as a Datto RMM component, with no
changes to the file.

## Scripts

| Category | Script | What it does |
|---|---|---|
| Security | [Audit-Java4ShellExposure](Security/Audit-Java4ShellExposure/) | Finds Java runtimes exposed to Java4Shell (CVE-2026-114938) and looks for exploitation signs. Read-only. |

More categories are coming as scripts are added, such as Windows auditing, installing
and removing apps, and Intune auditing.

## Layout

Each script lives in its own folder under a category, next to a README that explains
what it does, how to run it both ways, what the results mean, and its limitations.

```
<Category>/
  <Verb-Noun>/
    <Verb-Noun>.ps1
    README.md
```

## Two ways to run

**Interactive.** Download the script, open PowerShell with Run as administrator, and
run it. Options are normal PowerShell parameters, and `Get-Help .\<Script>.ps1 -Full`
shows them. If Windows blocks a downloaded script, run `Unblock-File` on it first.

**Datto RMM.** Create a Script component, paste the script in, and add the variables
listed in its README. The script detects the Datto agent (`CS_CC_HOST`,
`CS_ACCOUNT_UID`) and switches to RMM mode: plain output, settings from component
variables, results written to a UDF, and exit codes Datto can alert on. `-Mode Rmm`
or `-Mode Interactive` overrides the detection.

Scripts that only audit say so at the top of their README and change nothing on the
device.

## License

[Apache 2.0](LICENSE). Provided as-is with no warranty. Read and test every script
before running it on devices you manage.

Maintained by [Farid Lavasani](https://github.com/faridlav).
