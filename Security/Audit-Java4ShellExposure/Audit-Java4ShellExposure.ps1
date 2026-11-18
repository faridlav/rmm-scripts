<#
.SYNOPSIS
    Audits a Windows device for Java4Shell (CVE-2026-114938) exposure.

.DESCRIPTION
    Finds every HotSpot Java runtime on fixed drives and in the registry,
    rates each against the CVE-2026-114938 affected builds, the CPU feature
    gate, and mitigation flags, then hunts for exploitation signs. Read-only.

    Runs two ways from the same file:
      Interactive  Run it yourself in an elevated PowerShell window. Shows
                   progress and a colored report.
      RMM          Run it from any RMM or deployment tool as SYSTEM. Plain
                   output, a one-line Status at the end for a custom field,
                   and exit code 1 when action is needed.

.PARAMETER Mode
    Auto (default) picks RMM mode when the script runs as SYSTEM or without
    an interactive console, otherwise Interactive. Rmm or Interactive forces
    a mode.

.PARAMETER LookbackDays
    Days of crash logs and event history to check for exploitation signs.
    Default 30. In RMM mode a LookbackDays environment variable also works.

.PARAMETER MaxScanMinutes
    Time budget for the drive scan before it stops and reports partial
    results. Default 25. In RMM mode a MaxScanMinutes environment variable
    also works. Keep it below your RMM's script timeout.

.PARAMETER ReportPath
    Saves the full results as JSON to this file.

.PARAMETER PassThru
    Also returns the results as an object, for use in a pipeline or with
    Invoke-Command across several machines.

.EXAMPLE
    .\Audit-Java4ShellExposure.ps1

    Audits this machine and prints the report.

.EXAMPLE
    .\Audit-Java4ShellExposure.ps1 -LookbackDays 90 -ReportPath C:\Temp\j4s.json

    Checks 90 days of history and saves the results as JSON.

.EXAMPLE
    $servers = 'APP01', 'APP02'
    $audit = '.\Audit-Java4ShellExposure.ps1'
    Invoke-Command -ComputerName $servers -FilePath $audit -ArgumentList 'Interactive', 30

    Audits two remote servers. -ArgumentList passes options by position:
    Mode, LookbackDays, MaxScanMinutes.

.NOTES
    Settings in RMM mode come from parameters first, then from environment
    variables named LookbackDays and MaxScanMinutes, then the defaults.
    Most RMM tools can pass either one.

    CVE-2026-114938 (Java4Shell), heap out-of-bounds write in the HotSpot
    AVX-512 Base64 decode intrinsic. Affected and first fixed builds:

      Line 17                 17.0.6 to before 17.0.21.1, fixed 17.0.21.1
      Line 21                 all before 21.0.13.1, fixed 21.0.13.1
      Line 25                 all before 25.0.5.1, fixed 25.0.5.1
      Line 27                 all before 27.0.1.1, fixed 27.0.1.1
      Lines 18-20, 22-24, 26  all builds, no fix, move to 21, 25 or 27
      Line 8                  Oracle 8u511-perf only, fixed 8u513-perf
      Line 11 and 8 standard  not affected, intrinsic never backported

    Exploitable only by a 64-bit x86 JVM on a CPU reporting avx512f,
    avx512bw, avx512_vbmi and bmi2. ARM64 and 32-bit JVMs are not affected.
    Temporary mitigations: -XX:-UseBASE64Intrinsics, -XX:UseAVX=2, or
    -XX:DisableIntrinsic=_base64_decodeBlock (diagnostic option).

    Sources, verified 2026-11-18: OpenJDK Vulnerability Group and Oracle
    November 2026 CSPU as summarized by Tenable, HeroDevs, Datadog and AhnLab;
    Calif Java4Shell write-up for the CPU gate and mitigation flags; CISA
    alert of 2026-11-17.

    Author: Farid Lavasani (https://github.com/faridlav)

    Copyright 2026 Farid Lavasani

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Review and test it before running it on endpoints you manage.

.LINK
    https://github.com/faridlav/rmm-scripts
#>

[CmdletBinding()]
param(
    [ValidateSet('Auto', 'Rmm', 'Interactive')]
    [string]$Mode = 'Auto',

    [ValidateRange(1, 365)]
    [int]$LookbackDays = 30,

    [ValidateRange(1, 240)]
    [int]$MaxScanMinutes = 25,

    [string]$ReportPath = '',

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Relaunch under 64-bit PowerShell so registry, System32 and modules are not redirected.
$isWow64Session = [Environment]::Is64BitOperatingSystem -and
    -not [Environment]::Is64BitProcess
if ($isWow64Session -and -not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
    $nativeRelativePath = 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $nativePowerShell = Join-Path $env:WINDIR $nativeRelativePath
    if (Test-Path -LiteralPath $nativePowerShell) {
        $forwardArgs = [System.Collections.Generic.List[string]]::new()
        foreach ($entry in $PSBoundParameters.GetEnumerator()) {
            if ($entry.Value -is [System.Management.Automation.SwitchParameter]) {
                if ($entry.Value.IsPresent) {
                    $forwardArgs.Add("-$($entry.Key)")
                }
                continue
            }
            $forwardArgs.Add("-$($entry.Key)")
            $forwardArgs.Add([string]$entry.Value)
        }
        $relaunchArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath
        )
        & $nativePowerShell @relaunchArgs @forwardArgs
        exit $LASTEXITCODE
    }
}

# Decide the run mode: RMM tools run scripts as SYSTEM or without a console.
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$looksUnattended = $currentIdentity.IsSystem -or -not [Environment]::UserInteractive
switch ($Mode) {
    'Rmm' {
        $script:IsRmm = $true
    }
    'Interactive' {
        $script:IsRmm = $false
    }
    default {
        $script:IsRmm = $looksUnattended
    }
}
if (-not $script:IsRmm) {
    $ProgressPreference = 'Continue'
}

# Settings and CVE reference data.
$script:ReportTitle = 'Java4Shell CVE-2026-114938 Audit'
$script:MaxScanDepth = 12
$script:ProbeTimeoutSeconds = 30
$script:MaxProbes = 10
$script:ModuleScanSeconds = 60
$script:MaxCrashReadChars = 262144
$script:MaxListedRuntimes = 15
$script:MaxListedSigns = 8
$script:MaxHistoryParents = 40
$script:MutexName = 'Global\Java4ShellExposureAudit'
$script:FixedBuilds = @{
    17 = [version]'17.0.21.1'
    21 = [version]'21.0.13.1'
    25 = [version]'25.0.5.1'
    27 = [version]'27.0.1.1'
}
$script:FirstAffected17 = [version]'17.0.6.0'
$script:NoFixLines = @(18, 19, 20, 22, 23, 24, 26)
$script:Java8PerfFixedUpdate = 513
$script:MitigationPattern = '(?i)(-XX:-UseBASE64Intrinsics\b|-XX:UseAVX=[0-2]\b|' +
    '-XX:DisableIntrinsic=\S*_base64_decodeBlock)'
$script:SuspiciousChildren = @(
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
    'curl.exe', 'wget.exe', 'whoami.exe', 'net.exe', 'net1.exe', 'nltest.exe',
    'python.exe', 'bash.exe', 'sh.exe'
)

# Collections shared across the audit.
$script:RuntimeHomes = [System.Collections.Generic.Dictionary[string, object]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$script:CrashFiles = [System.Collections.Generic.List[object]]::new()
$script:CrashFilePaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
$script:Signs = [System.Collections.Generic.List[object]]::new()
$script:DirectoryCount = 0
$script:UnreadableCount = 0
$script:ScanIncomplete = $false
$script:ModuleScanIncomplete = $false
$script:InvalidInputs = [System.Collections.Generic.List[string]]::new()

# Helper functions for safe, bounded output.
function ConvertTo-SafeText {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $singleLine = $Text -replace '[\r\n\t]+', ' '
    $ascii = $singleLine -replace '[^\x20-\x7E]', '?'
    return ($ascii -replace '\s{2,}', ' ').Trim()
}

function Limit-Text {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory = $true)]
        [ValidateRange(4, 255)]
        [int]$MaximumLength
    )

    $safeText = ConvertTo-SafeText -Text $Text
    if ($safeText.Length -le $MaximumLength) {
        return $safeText
    }

    $available = $MaximumLength - 3
    $leftLength = [int][Math]::Ceiling($available / 2)
    $rightLength = $available - $leftLength
    return $safeText.Substring(0, $leftLength) + '...' +
        $safeText.Substring($safeText.Length - $rightLength)
}

function Write-JobLine {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text,

        [string]$Color = ''
    )

    if ($Text.Length -eq 0) {
        Write-Host ''
        return
    }

    $indent = $Text.Length - $Text.TrimStart(' ').Length
    $body = Limit-Text -Text $Text -MaximumLength (80 - $indent)

    # Color only helps a person at a console; RMM job output stays plain.
    if ($Color -ne '' -and -not $script:IsRmm) {
        Write-Host ((' ' * $indent) + $body) -ForegroundColor $Color
        return
    }
    Write-Host ((' ' * $indent) + $body)
}

function Write-Status {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    # Progress lines for interactive runs; RMM output keeps the verdict first.
    if (-not $script:IsRmm) {
        Write-Host $Text -ForegroundColor DarkGray
    }
}

function Get-VerdictColor {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Rank
    )

    if ($Rank -ge 4) {
        return 'Red'
    }
    if ($Rank -ge 2) {
        return 'Yellow'
    }
    return 'Green'
}

function Write-DetailLine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Label,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $prefix = '    ' + ($Label + ':').PadRight(11)
    $valueText = Limit-Text -Text $Value -MaximumLength (80 - $prefix.Length)
    Write-Host ($prefix + $valueText)
}

# Read numeric RMM environment variables with validation and documented defaults.
function Get-IntegerSetting {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [int]$Default,

        [Parameter(Mandatory = $true)]
        [int]$Minimum,

        [Parameter(Mandatory = $true)]
        [int]$Maximum
    )

    $rawValue = [Environment]::GetEnvironmentVariable($Name)
    if ([string]::IsNullOrWhiteSpace($rawValue)) {
        return $Default
    }

    $candidate = 0
    if ([int]::TryParse($rawValue.Trim(), [ref]$candidate) -and
        $candidate -ge $Minimum -and $candidate -le $Maximum) {
        return $candidate
    }

    $script:InvalidInputs.Add("$Name='$rawValue' ignored, using $Default")
    return $Default
}

# Runtime discovery helpers.
function Resolve-JavaHome {
    param(
        [Parameter(Mandatory = $true)]
        [string]$CandidatePath
    )

    try {
        $fullPath = [System.IO.Path]::GetFullPath($CandidatePath.Trim().Trim('"'))
    }
    catch {
        return $null
    }

    $fullPath = $fullPath.TrimEnd('\')
    $layouts = @('', '\jre')
    foreach ($layout in $layouts) {
        foreach ($vmType in @('server', 'client')) {
            $jvmPath = "$fullPath$layout\bin\$vmType\jvm.dll"
            if ([System.IO.File]::Exists($jvmPath)) {
                return [pscustomobject]@{
                    Home    = "$fullPath$layout"
                    JvmPath = $jvmPath
                }
            }
        }
    }

    return $null
}

function Add-RuntimeCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$CandidatePath,

        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    if ([string]::IsNullOrWhiteSpace($CandidatePath)) {
        return
    }

    $resolved = Resolve-JavaHome -CandidatePath $CandidatePath
    if ($null -eq $resolved) {
        return
    }

    if (-not $script:RuntimeHomes.ContainsKey($resolved.Home)) {
        $script:RuntimeHomes[$resolved.Home] = [pscustomobject]@{
            Home    = $resolved.Home
            JvmPath = $resolved.JvmPath
            Sources = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
        }
    }

    [void]$script:RuntimeHomes[$resolved.Home].Sources.Add($Source)
}

function Add-CrashFile {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory = $true)]
        [datetime]$Since
    )

    if ($File.LastWriteTime -lt $Since) {
        return
    }

    if ($script:CrashFilePaths.Add($File.FullName)) {
        $script:CrashFiles.Add($File)
    }
}

function Find-CrashFilesInFolder {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [datetime]$Since
    )

    if (-not [System.IO.Directory]::Exists($Path)) {
        return
    }

    try {
        $folder = [System.IO.DirectoryInfo]::new($Path)
        foreach ($file in $folder.EnumerateFiles('hs_err_pid*.log')) {
            Add-CrashFile -File $file -Since $Since
        }
    }
    catch {
        # An unreadable folder is counted and skipped; the scan continues.
        $script:UnreadableCount++
    }
}

function Get-RegistryJavaCandidates {
    $vendorRoots = @(
        'SOFTWARE\JavaSoft', 'SOFTWARE\Eclipse Adoptium', 'SOFTWARE\Eclipse Foundation',
        'SOFTWARE\AdoptOpenJDK', 'SOFTWARE\Azul Systems', 'SOFTWARE\Microsoft\JDK',
        'SOFTWARE\Amazon', 'SOFTWARE\BellSoft', 'SOFTWARE\SAP', 'SOFTWARE\Oracle'
    )
    $homeValueNames = @('JavaHome', 'Path', 'InstallationPath', 'InstallPath')
    $uninstallRoot = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $productPattern = '(?i)java|jdk|jre|openjdk|corretto|zulu|temurin|adoptium|' +
        'liberica|sapmachine|graalvm|semeru'
    $views = @([Microsoft.Win32.RegistryView]::Registry64)
    if ([Environment]::Is64BitOperatingSystem) {
        $views = @(
            [Microsoft.Win32.RegistryView]::Registry64,
            [Microsoft.Win32.RegistryView]::Registry32
        )
    }

    $candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($view in $views) {
        $baseKey = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine,
                $view
            )

            # Walk vendor keys up to five levels for install path values.
            $pending = [System.Collections.Generic.Stack[object]]::new()
            foreach ($root in $vendorRoots) {
                $pending.Push([pscustomobject]@{ Path = $root; Depth = 0 })
            }
            while ($pending.Count -gt 0) {
                $item = $pending.Pop()
                $key = $baseKey.OpenSubKey($item.Path)
                if ($null -eq $key) {
                    continue
                }
                try {
                    foreach ($valueName in $homeValueNames) {
                        $value = $key.GetValue($valueName)
                        if ($value -is [string]) {
                            $candidates.Add($value)
                        }
                    }
                    if ($item.Depth -lt 5) {
                        foreach ($subKeyName in $key.GetSubKeyNames()) {
                            $pending.Push([pscustomobject]@{
                                Path  = "$($item.Path)\$subKeyName"
                                Depth = $item.Depth + 1
                            })
                        }
                    }
                }
                finally {
                    $key.Close()
                }
            }

            # Uninstall entries for Java products that record an install folder.
            $uninstallKey = $baseKey.OpenSubKey($uninstallRoot)
            if ($null -ne $uninstallKey) {
                try {
                    foreach ($subKeyName in $uninstallKey.GetSubKeyNames()) {
                        $productKey = $uninstallKey.OpenSubKey($subKeyName)
                        if ($null -eq $productKey) {
                            continue
                        }
                        try {
                            $displayName = [string]$productKey.GetValue('DisplayName')
                            $location = [string]$productKey.GetValue('InstallLocation')
                            if ($displayName -match $productPattern -and
                                -not [string]::IsNullOrWhiteSpace($location)) {
                                $candidates.Add($location)
                            }
                        }
                        finally {
                            $productKey.Close()
                        }
                    }
                }
                finally {
                    $uninstallKey.Close()
                }
            }
        }
        catch {
            # A registry view that cannot be read only reduces discovery coverage.
            $script:UnreadableCount++
        }
        finally {
            if ($null -ne $baseKey) {
                $baseKey.Close()
            }
        }
    }

    return $candidates
}

function Invoke-FolderScan {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Roots,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.HashSet[string]]$SkipPaths,

        [Parameter(Mandatory = $true)]
        [datetime]$Deadline,

        [Parameter(Mandatory = $true)]
        [datetime]$Since
    )

    $pending = [System.Collections.Generic.Stack[object]]::new()
    foreach ($root in $Roots) {
        if ([System.IO.Directory]::Exists($root)) {
            $pending.Push([pscustomobject]@{ Path = $root; Depth = 0 })
        }
    }

    while ($pending.Count -gt 0) {
        if ([DateTime]::Now -gt $Deadline) {
            $script:ScanIncomplete = $true
            break
        }

        $item = $pending.Pop()
        $script:DirectoryCount++
        $children = @()
        if (-not $script:IsRmm -and ($script:DirectoryCount % 500) -eq 0) {
            $progressPath = Limit-Text -Text $item.Path -MaximumLength 70
            $progressParams = @{
                Activity = 'Scanning fixed drives for Java runtimes and crash logs'
                Status   = "$($script:DirectoryCount) folders: $progressPath"
            }
            Write-Progress @progressParams
        }

        # Crash logs land in the JVM working folder, so every folder is checked.
        try {
            $folder = [System.IO.DirectoryInfo]::new($item.Path)
            foreach ($file in $folder.EnumerateFiles('hs_err_pid*.log')) {
                Add-CrashFile -File $file -Since $Since
            }

            # A bin\server or bin\client folder holding jvm.dll marks a runtime home.
            $isVmFolder = $folder.Name -eq 'server' -or $folder.Name -eq 'client'
            if ($isVmFolder -and
                [System.IO.File]::Exists((Join-Path $folder.FullName 'jvm.dll'))) {
                $runtimeFolder = $folder.Parent.Parent.FullName
                Add-RuntimeCandidate -CandidatePath $runtimeFolder -Source 'disk'
            }

            if ($item.Depth -lt $script:MaxScanDepth) {
                $children = @($folder.EnumerateDirectories())
            }
        }
        catch {
            # Access denied or a path too long for .NET; skip this branch.
            $script:UnreadableCount++
            continue
        }

        $reparseFlag = [System.IO.FileAttributes]::ReparsePoint
        foreach ($child in $children) {
            try {
                $childPath = $child.FullName
                $isReparse = ($child.Attributes -band $reparseFlag) -ne 0
            }
            catch {
                # A child whose path cannot be resolved is skipped.
                $script:UnreadableCount++
                continue
            }
            if ($isReparse -or $SkipPaths.Contains($childPath.TrimEnd('\'))) {
                continue
            }
            $pending.Push([pscustomobject]@{
                Path  = $childPath
                Depth = $item.Depth + 1
            })
        }
    }

    if (-not $script:IsRmm) {
        $scanActivity = 'Scanning fixed drives for Java runtimes and crash logs'
        Write-Progress -Activity $scanActivity -Completed
    }
}

# Version, architecture and CPU evaluation helpers.
function Get-ReleaseInfo {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JavaHome
    )

    $info = @{}
    $releasePath = Join-Path $JavaHome 'release'
    if (-not [System.IO.File]::Exists($releasePath)) {
        return $info
    }

    try {
        $releaseLines = @(Get-Content -LiteralPath $releasePath -TotalCount 60)
    }
    catch {
        # An unreadable release file falls back to the jvm.dll file version.
        return $info
    }

    foreach ($line in $releaseLines) {
        if ($line -match '^(?<key>[A-Z_]+)="?(?<value>[^"]*)"?\s*$') {
            $info[$Matches['key']] = $Matches['value']
        }
    }
    return $info
}

function ConvertTo-JavaVersion {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VersionText
    )

    $text = $VersionText.Trim().Trim('"')
    if ($text -match '^1\.8\.0(?:_(?<update>\d+))?') {
        $update = 0
        if ($Matches['update']) {
            $update = [int]$Matches['update']
        }
        return [pscustomobject]@{
            Feature = 8
            Version = [version]"8.0.$update.0"
            Update  = $update
            Display = $text
        }
    }

    if ($text -match '^(?<numbers>\d+(?:\.\d+){0,4})') {
        $parts = [System.Collections.Generic.List[string]]::new()
        foreach ($part in ($Matches['numbers'] -split '\.')) {
            if ($parts.Count -lt 4) {
                $parts.Add($part)
            }
        }
        while ($parts.Count -lt 4) {
            $parts.Add('0')
        }
        return [pscustomobject]@{
            Feature = [int]$parts[0]
            Version = [version]($parts -join '.')
            Update  = [int]$parts[2]
            Display = $text
        }
    }

    return $null
}

function Get-VersionStatus {
    param(
        [Parameter(Mandatory = $true)]
        [object]$JavaVersion,

        [Parameter(Mandatory = $true)]
        [bool]$IsPerfBuild
    )

    $feature = $JavaVersion.Feature
    if ($feature -eq 8) {
        if ($IsPerfBuild -and $JavaVersion.Update -lt $script:Java8PerfFixedUpdate) {
            return [pscustomobject]@{ Status = 'Vulnerable'; Fix = 'fixed in 8u513-perf' }
        }
        return [pscustomobject]@{ Status = 'NotAffected'; Fix = '' }
    }

    if ($feature -eq 17 -and $JavaVersion.Version -lt $script:FirstAffected17) {
        return [pscustomobject]@{ Status = 'NotAffected'; Fix = '' }
    }

    if ($script:FixedBuilds.ContainsKey($feature)) {
        $fixedBuild = $script:FixedBuilds[$feature]
        if ($JavaVersion.Version -lt $fixedBuild) {
            return [pscustomobject]@{
                Status = 'Vulnerable'
                Fix    = "fixed in $fixedBuild"
            }
        }
        return [pscustomobject]@{ Status = 'Fixed'; Fix = '' }
    }

    if ($script:NoFixLines -contains $feature) {
        return [pscustomobject]@{
            Status = 'Vulnerable'
            Fix    = 'no fix, move to 21, 25 or 27'
        }
    }

    if ($feature -ge 28) {
        return [pscustomobject]@{ Status = 'Fixed'; Fix = '' }
    }

    return [pscustomobject]@{ Status = 'NotAffected'; Fix = '' }
}

function Get-PeArchitecture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stream = $null
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $stream = [System.IO.File]::Open(
            $Path,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            $share
        )
        $reader = [System.IO.BinaryReader]::new($stream)
        [void]$stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin)
        $peOffset = $reader.ReadInt32()
        [void]$stream.Seek($peOffset + 4, [System.IO.SeekOrigin]::Begin)
        $machine = $reader.ReadUInt16()
        switch ($machine) {
            0x8664 {
                return 'x64'
            }
            0x014C {
                return 'x86'
            }
            0xAA64 {
                return 'ARM64'
            }
            default {
                return 'unknown'
            }
        }
    }
    catch {
        return 'unknown'
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Invoke-JvmProbe {
    param(
        [Parameter(Mandatory = $true)]
        [string]$JavaExe
    )

    # Asks the JVM itself which CPU features it detects and which version it is.
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $JavaExe
    $startInfo.Arguments = '-Xlog:os+cpu -version'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.CreateNoWindow = $true

    # UseAVX=2 hides AVX-512 from the CPU line, so the probe ignores option variables.
    $optionVariables = @('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS')
    foreach ($optionVariable in $optionVariables) {
        if ($startInfo.EnvironmentVariables.ContainsKey($optionVariable)) {
            $startInfo.EnvironmentVariables.Remove($optionVariable)
        }
    }

    $process = $null
    try {
        $process = [System.Diagnostics.Process]::Start($startInfo)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($script:ProbeTimeoutSeconds * 1000)) {
            try {
                $process.Kill()
            }
            catch {
                # The probe may have exited between the timeout and Kill.
                $null = $_
            }
            return $null
        }
        $outputText = $stdoutTask.Result + "`n" + $stderrTask.Result
    }
    catch {
        return $null
    }
    finally {
        if ($null -ne $process) {
            $process.Dispose()
        }
    }

    $cpuMatch = [regex]::Match($outputText, '(?m)\[os,cpu\]\s*CPU:(?<features>.*)$')
    if (-not $cpuMatch.Success) {
        return $null
    }

    $features = $cpuMatch.Groups['features'].Value
    $hasGate = $features -match '\bavx512f\b' -and
        $features -match '\bavx512bw\b' -and
        $features -match '\bavx512_vbmi\b' -and
        $features -match '\bbmi2\b'

    $bannerVersion = ''
    $bannerMatch = [regex]::Match($outputText, 'version "(?<value>[^"]+)"')
    if ($bannerMatch.Success) {
        $bannerVersion = $bannerMatch.Groups['value'].Value
    }

    return [pscustomobject]@{
        CpuGate       = $hasGate
        IsVirtual     = $features -match '\bhv\b'
        BannerVersion = $bannerVersion
    }
}

# Process, service and mitigation helpers.
function Get-JvmHostProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$AllProcesses
    )

    $hosts = [System.Collections.Generic.List[object]]::new()
    $launcherNames = @('java.exe', 'javaw.exe')

    foreach ($process in $AllProcesses) {
        if ($launcherNames -contains $process.Name.ToLowerInvariant() -and
            -not [string]::IsNullOrWhiteSpace($process.ExecutablePath)) {
            $binFolder = [System.IO.Path]::GetDirectoryName($process.ExecutablePath)
            $hosts.Add([pscustomobject]@{
                ProcessId     = [int]$process.ProcessId
                Name          = $process.Name
                CandidateHome = [System.IO.Path]::GetDirectoryName($binFolder)
                CommandLine   = [string]$process.CommandLine
                IsLauncher    = $true
            })
        }
    }

    # Service wrappers such as Tomcat procrun load jvm.dll inside their own process.
    $deadline = [DateTime]::Now.AddSeconds($script:ModuleScanSeconds)
    $commandLines = @{}
    foreach ($process in $AllProcesses) {
        $commandLines[[int]$process.ProcessId] = [string]$process.CommandLine
    }

    foreach ($process in (Get-Process -ErrorAction SilentlyContinue)) {
        if ([DateTime]::Now -gt $deadline) {
            $script:ModuleScanIncomplete = $true
            break
        }
        if ($process.Id -le 4 -or @('java', 'javaw') -contains $process.Name) {
            continue
        }
        try {
            $jvmModule = $process.Modules |
                Where-Object { $_.ModuleName -eq 'jvm.dll' } |
                Select-Object -First 1
        }
        catch {
            # Protected and exiting processes deny module access; skip them.
            continue
        }
        if ($null -ne $jvmModule) {
            $serverFolder = [System.IO.Path]::GetDirectoryName($jvmModule.FileName)
            $binFolder = [System.IO.Path]::GetDirectoryName($serverFolder)
            $hosts.Add([pscustomobject]@{
                ProcessId     = $process.Id
                Name          = "$($process.Name).exe"
                CandidateHome = [System.IO.Path]::GetDirectoryName($binFolder)
                CommandLine   = $commandLines[$process.Id]
                IsLauncher    = $false
            })
        }
    }

    return $hosts
}

function Get-RegistryText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    $textParts = [System.Collections.Generic.List[string]]::new()
    try {
        $properties = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
        foreach ($name in $Names) {
            $value = $properties.$name
            if ($null -ne $value) {
                $textParts.Add(($value -join ' '))
            }
        }
    }
    catch {
        # A missing key simply means no options are configured there.
        $null = $_
    }
    return ($textParts -join ' ')
}

function Get-ServiceJavaOptions {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName
    )

    $procrunRoots = @(
        'HKLM:\SOFTWARE\Apache Software Foundation\Procrun 2.0',
        'HKLM:\SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0'
    )
    $optionText = [System.Collections.Generic.List[string]]::new()
    foreach ($root in $procrunRoots) {
        $javaKey = "$root\$ServiceName\Parameters\Java"
        $optionText.Add((Get-RegistryText -Path $javaKey -Names @('Options', 'Options9')))
    }
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    $optionText.Add((Get-RegistryText -Path $serviceKey -Names @('Environment')))
    return ($optionText -join ' ')
}

# Exploitation sign helpers.
function Get-CrashFileSign {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File
    )

    $content = ''
    $reader = $null
    try {
        $reader = [System.IO.StreamReader]::new($File.FullName)
        $buffer = [char[]]::new($script:MaxCrashReadChars)
        $readCount = $reader.ReadBlock($buffer, 0, $buffer.Length)
        $content = [string]::new($buffer, 0, $readCount)
    }
    catch {
        $content = ''
    }
    finally {
        if ($null -ne $reader) {
            $reader.Dispose()
        }
    }

    $frame = ''
    $framePattern = '(?m)^#\s*Problematic frame:\s*\r?\n#\s*(?<f>.+)$'
    $frameMatch = [regex]::Match($content, $framePattern)
    if ($frameMatch.Success) {
        $frame = $frameMatch.Groups['f'].Value.Trim()
    }

    # A Base64 decode frame on the crashing stack matches the published bug location.
    $stackMatch = [regex]::Match($content, '(?s)(Native|Java) frames:.{0,6000}')
    $stackText = ''
    if ($stackMatch.Success) {
        $stackText = $stackMatch.Value
    }
    $isStrong = $frame -match '(?i)base64|decodeBlock' -or
        $stackText -match '(?i)java\.util\.Base64|base64_decode|decodeBlock'

    return [pscustomobject]@{
        Kind   = 'Crash'
        Strong = $isStrong
        Time   = $File.LastWriteTime
        Detail = $File.FullName
        Frame  = $frame
    }
}

function Get-JavaCrashEvents {
    param(
        [Parameter(Mandatory = $true)]
        [datetime]$Since
    )

    $found = [System.Collections.Generic.List[object]]::new()
    $filter = @{
        LogName   = 'Application'
        Id        = 1000
        StartTime = $Since
    }
    try {
        $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 5000)
    }
    catch {
        # No matching events throws by design; nothing to report.
        return $found
    }

    foreach ($logEvent in $events) {
        if ($logEvent.Properties.Count -lt 4) {
            continue
        }
        $appName = [string]$logEvent.Properties[0].Value
        $moduleName = [string]$logEvent.Properties[3].Value
        $isJava = @('java.exe', 'javaw.exe') -contains $appName.ToLowerInvariant() -or
            $moduleName -eq 'jvm.dll'
        if ($isJava) {
            $found.Add([pscustomobject]@{
                Kind   = 'CrashEvent'
                Strong = $false
                Time   = $logEvent.TimeCreated
                Detail = "$appName faulted in $moduleName (Application 1000)"
                Frame  = ''
            })
        }
    }
    return $found
}

function Get-ChildProcessHistory {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ParentPaths,

        [Parameter(Mandatory = $true)]
        [int]$LookbackDays
    )

    $found = [System.Collections.Generic.List[object]]::new()
    $safePaths = @($ParentPaths | Where-Object { $_ -notmatch "['&<>]" } |
        Select-Object -First $script:MaxHistoryParents)
    if ($safePaths.Count -eq 0) {
        return $found
    }

    $windowMs = [int64]$LookbackDays * 86400000
    $sources = @(
        [pscustomobject]@{
            Log = 'Security'; EventId = 4688
            Parent = 'ParentProcessName'; Child = 'NewProcessName'
        },
        [pscustomobject]@{
            Log = 'Microsoft-Windows-Sysmon/Operational'; EventId = 1
            Parent = 'ParentImage'; Child = 'Image'
        }
    )

    foreach ($source in $sources) {
        for ($index = 0; $index -lt $safePaths.Count; $index = $index + 8) {
            $batch = @($safePaths | Select-Object -Skip $index -First 8)
            $clauses = @($batch | ForEach-Object {
                "Data[@Name='$($source.Parent)']='$_'"
            }) -join ' or '
            $xpath = "*[System[(EventID=$($source.EventId)) and " +
                "TimeCreated[timediff(@SystemTime) <= $windowMs]]] and " +
                "*[EventData[$clauses]]"
            $eventParams = @{
                LogName     = $source.Log
                FilterXPath = $xpath
                MaxEvents   = 200
                ErrorAction = 'Stop'
            }
            try {
                $events = @(Get-WinEvent @eventParams)
            }
            catch {
                # Missing log, auditing disabled or no matches; nothing to add.
                continue
            }
            foreach ($logEvent in $events) {
                $eventXml = [xml]$logEvent.ToXml()
                $childPath = ''
                foreach ($data in $eventXml.Event.EventData.Data) {
                    if ($data.Name -eq $source.Child) {
                        $childPath = [string]$data.'#text'
                    }
                }
                $childName = [System.IO.Path]::GetFileName($childPath).ToLowerInvariant()
                if ($script:SuspiciousChildren -contains $childName) {
                    $found.Add([pscustomobject]@{
                        Kind   = 'ShellHistory'
                        Strong = $false
                        Time   = $logEvent.TimeCreated
                        Detail = "$childName started by Java, " +
                            "$($source.Log) event $($source.EventId)"
                        Frame  = ''
                    })
                }
            }
        }
    }
    return $found
}

# Read settings: parameters first, then RMM environment variables, then defaults.
$lookbackDays = $LookbackDays
$scanMinutes = $MaxScanMinutes
if ($script:IsRmm -and -not $PSBoundParameters.ContainsKey('LookbackDays')) {
    $lookbackParams = @{
        Name    = 'LookbackDays'
        Default = $LookbackDays
        Minimum = 1
        Maximum = 365
    }
    $lookbackDays = Get-IntegerSetting @lookbackParams
}
if ($script:IsRmm -and -not $PSBoundParameters.ContainsKey('MaxScanMinutes')) {
    $scanBudgetParams = @{
        Name    = 'MaxScanMinutes'
        Default = $MaxScanMinutes
        Minimum = 1
        Maximum = 240
    }
    $scanMinutes = Get-IntegerSetting @scanBudgetParams
}
$since = (Get-Date).AddDays(-$lookbackDays)
$stamp = Get-Date -Format 'yyyy-MM-dd'

Write-Host "=== $($script:ReportTitle) ==="

# Interactive runs need elevation to read other profiles, services and the Security log.
if (-not $script:IsRmm) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $adminRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    if (-not $principal.IsInRole($adminRole)) {
        $elevationText = 'Result: FAILED. Run this from an elevated ' +
            '(Run as administrator)'
        Write-Host $elevationText -ForegroundColor Red
        Write-Host 'PowerShell window so it can read every folder, service and log.'
        exit 1
    }
    Write-Status -Text "Mode: interactive. Drive scan budget: $scanMinutes min."
}
if ($ReportPath -ne '') {
    $reportFolder = Split-Path -Path $ReportPath -Parent
    if ($reportFolder -ne '' -and -not (Test-Path -LiteralPath $reportFolder)) {
        $folderText = "Result: FAILED. Report folder not found: $reportFolder"
        Write-JobLine -Text $folderText -Color 'Red'
        exit 1
    }
}

# Prevent overlapping runs from scanning the same disks twice.
$mutex = [System.Threading.Mutex]::new($false, $script:MutexName)
$lockAcquired = $false
try {
    $lockAcquired = $mutex.WaitOne(0)
}
catch [System.Threading.AbandonedMutexException] {
    $lockAcquired = $true
}
if (-not $lockAcquired) {
    Write-Host 'Result: FAILED. Another run of this audit is already in progress.'
    $mutex.Dispose()
    exit 1
}

$exitCode = 0
try {
    $scanWatch = [System.Diagnostics.Stopwatch]::StartNew()

    # Discover runtimes from the registry, environment and PATH.
    Write-Status -Text '[1/5] Checking the registry, JAVA_HOME and PATH'
    foreach ($candidate in (Get-RegistryJavaCandidates)) {
        Add-RuntimeCandidate -CandidatePath $candidate -Source 'registry'
    }
    $javaHomeValue = [Environment]::GetEnvironmentVariable('JAVA_HOME', 'Machine')
    if (-not [string]::IsNullOrWhiteSpace($javaHomeValue)) {
        Add-RuntimeCandidate -CandidatePath $javaHomeValue -Source 'JAVA_HOME'
    }
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    foreach ($pathEntry in ([string]$machinePath -split ';')) {
        if ($pathEntry -match '(?i)\\bin\\?$') {
            $pathHome = [System.IO.Path]::GetDirectoryName($pathEntry.TrimEnd('\'))
            Add-RuntimeCandidate -CandidatePath ([string]$pathHome) -Source 'PATH'
        }
    }

    # Walk every fixed drive for runtimes and JVM crash logs within the time budget.
    Write-Status -Text '[2/5] Scanning fixed drives for runtimes and crash logs'
    $windowsFolder = $env:SystemRoot.TrimEnd('\')
    $skipPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    [void]$skipPaths.Add($windowsFolder)
    $scanRoots = [System.Collections.Generic.List[string]]::new()
    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        if ($drive.DriveType -ne [System.IO.DriveType]::Fixed -or -not $drive.IsReady) {
            continue
        }
        $driveRoot = $drive.RootDirectory.FullName
        $scanRoots.Add($driveRoot)
        $skipNames = @('$Recycle.Bin', 'System Volume Information', 'Config.Msi')
        foreach ($skipName in $skipNames) {
            [void]$skipPaths.Add((Join-Path $driveRoot $skipName))
        }
    }
    $scanRoots.Add((Join-Path $windowsFolder 'ServiceProfiles'))
    $scanDeadline = [DateTime]::Now.AddMinutes($scanMinutes)
    $scanParams = @{
        Roots     = $scanRoots.ToArray()
        SkipPaths = $skipPaths
        Deadline  = $scanDeadline
        Since     = $since
    }
    Invoke-FolderScan @scanParams

    # Services often crash with System32 or the Windows temp folder as working folder.
    foreach ($folderName in @('System32', 'SysWOW64', 'Temp', 'SystemTemp')) {
        Find-CrashFilesInFolder -Path (Join-Path $windowsFolder $folderName) -Since $since
    }
    $scanSeconds = [int]$scanWatch.Elapsed.TotalSeconds

    # Find running JVMs, including service wrappers that host jvm.dll in-process.
    Write-Status -Text '[3/5] Checking running Java processes and services'
    $allProcesses = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop)
    $jvmHosts = @(Get-JvmHostProcesses -AllProcesses $allProcesses)
    foreach ($jvmHost in $jvmHosts) {
        $hostHome = [string]$jvmHost.CandidateHome
        Add-RuntimeCandidate -CandidatePath $hostHome -Source 'running'
    }

    # Map listening TCP ports and Windows services to process IDs.
    $listeningPorts = @{}
    try {
        $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        foreach ($listener in $listeners) {
            $ownerId = [int]$listener.OwningProcess
            if (-not $listeningPorts.ContainsKey($ownerId)) {
                $portSet = [System.Collections.Generic.SortedSet[int]]::new()
                $listeningPorts[$ownerId] = $portSet
            }
            [void]$listeningPorts[$ownerId].Add([int]$listener.LocalPort)
        }
    }
    catch {
        # Port lookup is informational; older systems may lack the cmdlet.
        $null = $_
    }

    $servicesByPid = @{}
    foreach ($service in @(Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
        $servicePid = [int]$service.ProcessId
        if ($servicePid -gt 0) {
            if (-not $servicesByPid.ContainsKey($servicePid)) {
                $serviceNames = [System.Collections.Generic.List[string]]::new()
                $servicesByPid[$servicePid] = $serviceNames
            }
            $servicesByPid[$servicePid].Add([string]$service.Name)
        }
    }

    # Machine-wide JVM option variables apply to every JVM started after they were set.
    $toolOptions = ([string][Environment]::GetEnvironmentVariable(
        'JAVA_TOOL_OPTIONS', 'Machine')) + ' ' +
        ([string][Environment]::GetEnvironmentVariable('_JAVA_OPTIONS', 'Machine'))
    $launcherOptions = [string][Environment]::GetEnvironmentVariable(
        'JDK_JAVA_OPTIONS', 'Machine')
    $machineMitigation = $toolOptions -match $script:MitigationPattern

    # Rate each runtime by version and architecture.
    $runtimes = [System.Collections.Generic.List[object]]::new()
    foreach ($runtimeHome in $script:RuntimeHomes.Values) {
        $release = Get-ReleaseInfo -JavaHome $runtimeHome.Home
        $versionText = ''
        if ($release.ContainsKey('JAVA_VERSION')) {
            $versionText = $release['JAVA_VERSION']
        }
        else {
            $fileInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo(
                $runtimeHome.JvmPath)
            $versionText = '{0}.{1}.{2}.{3}' -f $fileInfo.FileMajorPart,
                $fileInfo.FileMinorPart, $fileInfo.FileBuildPart,
                $fileInfo.FilePrivatePart
        }
        $vendor = 'unknown vendor'
        if ($release.ContainsKey('IMPLEMENTOR')) {
            $vendor = $release['IMPLEMENTOR']
        }
        $perfText = ([string]$release['JAVA_RUNTIME_VERSION']) + ' ' + $runtimeHome.Home
        $javaExe = Join-Path $runtimeHome.Home 'bin\java.exe'
        if (-not [System.IO.File]::Exists($javaExe)) {
            $javaExe = ''
        }

        $runtimes.Add([pscustomobject]@{
            Home        = $runtimeHome.Home
            JavaExe     = $javaExe
            VersionText = $versionText
            Version     = ConvertTo-JavaVersion -VersionText $versionText
            Vendor      = $vendor
            IsPerf      = $perfText -match '(?i)perf'
            Arch        = Get-PeArchitecture -Path $runtimeHome.JvmPath
            Status      = 'Unknown'
            Fix         = ''
            Probe       = $null
            Processes   = [System.Collections.Generic.List[object]]::new()
            Mitigation  = 'none'
            Verdict     = ''
            Rank        = 0
        })
    }

    foreach ($runtime in $runtimes) {
        if ($null -eq $runtime.Version) {
            $runtime.Status = 'Unknown'
            continue
        }
        $statusParams = @{
            JavaVersion = $runtime.Version
            IsPerfBuild = $runtime.IsPerf
        }
        $versionStatus = Get-VersionStatus @statusParams
        $runtime.Status = $versionStatus.Status
        $runtime.Fix = $versionStatus.Fix
    }

    # Probe vulnerable 64-bit runtimes for the CPU gate and their reported version.
    Write-Status -Text '[4/5] Asking affected JVMs which CPU features they see'
    $probeCount = 0
    $cpuGate = $null
    $isVirtual = $false
    foreach ($runtime in $runtimes) {
        $isCandidate = @('Vulnerable', 'Unknown') -contains $runtime.Status -and
            $runtime.Arch -eq 'x64' -and $runtime.JavaExe -ne ''
        if (-not $isCandidate -or $probeCount -ge $script:MaxProbes) {
            continue
        }
        $probeCount++
        $probe = Invoke-JvmProbe -JavaExe $runtime.JavaExe
        $runtime.Probe = $probe
        if ($null -eq $probe) {
            continue
        }
        $cpuGate = $probe.CpuGate
        $isVirtual = $probe.IsVirtual
        if ($probe.BannerVersion -ne '') {
            $bannerVersion = ConvertTo-JavaVersion -VersionText $probe.BannerVersion
            if ($null -ne $bannerVersion) {
                $runtime.Version = $bannerVersion
                $runtime.VersionText = $probe.BannerVersion
                $statusParams = @{
                    JavaVersion = $bannerVersion
                    IsPerfBuild = $runtime.IsPerf
                }
                $versionStatus = Get-VersionStatus @statusParams
                $runtime.Status = $versionStatus.Status
                $runtime.Fix = $versionStatus.Fix
            }
        }
    }

    # Attach running JVMs and decide whether each one carries a mitigation flag.
    foreach ($jvmHost in $jvmHosts) {
        $resolvedHome = Resolve-JavaHome -CandidatePath ([string]$jvmHost.CandidateHome)
        if ($null -eq $resolvedHome) {
            continue
        }
        $owner = $runtimes | Where-Object { $_.Home -eq $resolvedHome.Home } |
            Select-Object -First 1
        if ($null -eq $owner) {
            continue
        }
        # Flags come from the command line, procrun options or the service environment.
        $optionText = [string]$jvmHost.CommandLine
        if ($servicesByPid.ContainsKey($jvmHost.ProcessId)) {
            foreach ($serviceName in $servicesByPid[$jvmHost.ProcessId]) {
                $serviceOptions = Get-ServiceJavaOptions -ServiceName $serviceName
                $optionText = $optionText + ' ' + $serviceOptions
            }
        }
        if ($jvmHost.IsLauncher) {
            $optionText = $optionText + ' ' + $launcherOptions
        }
        $ports = ''
        if ($listeningPorts.ContainsKey($jvmHost.ProcessId)) {
            $portList = @($listeningPorts[$jvmHost.ProcessId]) | Select-Object -First 6
            $ports = $portList -join ', '
        }
        $owner.Processes.Add([pscustomobject]@{
            ProcessId = $jvmHost.ProcessId
            Name      = $jvmHost.Name
            Mitigated = $optionText -match $script:MitigationPattern
            Ports     = $ports
        })
    }

    # Combine version, architecture, CPU gate and mitigation into a verdict.
    foreach ($runtime in $runtimes) {
        $mitigatedCount = @($runtime.Processes | Where-Object { $_.Mitigated }).Count
        $runningCount = $runtime.Processes.Count
        $allRunningMitigated = $runningCount -gt 0 -and $mitigatedCount -eq $runningCount
        if ($machineMitigation) {
            $runtime.Mitigation = 'machine-wide, confirm JVMs restarted since set'
        }
        elseif ($allRunningMitigated) {
            $runtime.Mitigation = 'all running JVMs flagged, new launches are not'
        }
        elseif ($mitigatedCount -gt 0) {
            $runtime.Mitigation = "partial, $mitigatedCount of $runningCount running JVMs"
        }

        $isMitigated = $machineMitigation -or $allRunningMitigated

        switch ($runtime.Status) {
            'Fixed' {
                $runtime.Verdict = 'PATCHED'
                $runtime.Rank = 1
            }
            'NotAffected' {
                $runtime.Verdict = 'NOT AFFECTED'
                $runtime.Rank = 0
            }
            default {
                if ($runtime.Status -eq 'Vulnerable' -and $runtime.Arch -ne 'x64' -and
                    $runtime.Arch -ne 'unknown') {
                    $runtime.Verdict = "NOT AFFECTED ($($runtime.Arch) JVM)"
                    $runtime.Rank = 0
                }
                elseif ($runtime.Status -eq 'Vulnerable' -and $cpuGate -eq $false) {
                    $runtime.Verdict = 'AFFECTED VERSION, CPU NOT EXPLOITABLE'
                    $runtime.Rank = 2
                }
                elseif ($runtime.Status -eq 'Vulnerable' -and $isMitigated) {
                    $runtime.Verdict = 'MITIGATED, NOT PATCHED'
                    $runtime.Rank = 3
                }
                elseif ($runtime.Status -eq 'Vulnerable') {
                    $runtime.Verdict = 'VULNERABLE'
                    $runtime.Rank = 4
                }
                else {
                    $runtime.Verdict = 'VERSION UNKNOWN, CHECK MANUALLY'
                    $runtime.Rank = 3
                }
            }
        }
    }

    # Collect exploitation signs: crash logs, crash events and shells spawned by Java.
    Write-Status -Text '[5/5] Looking for exploitation signs'
    foreach ($crashFile in $script:CrashFiles) {
        $script:Signs.Add((Get-CrashFileSign -File $crashFile))
    }
    foreach ($crashEvent in (Get-JavaCrashEvents -Since $since)) {
        $script:Signs.Add($crashEvent)
    }

    $jvmPids = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($jvmHost in $jvmHosts) {
        [void]$jvmPids.Add([int]$jvmHost.ProcessId)
    }
    foreach ($process in $allProcesses) {
        $childName = ([string]$process.Name).ToLowerInvariant()
        if ($jvmPids.Contains([int]$process.ParentProcessId) -and
            $script:SuspiciousChildren -contains $childName) {
            $script:Signs.Add([pscustomobject]@{
                Kind   = 'ShellNow'
                Strong = $false
                Time   = Get-Date
                Detail = "$childName PID $($process.ProcessId) child of Java PID " +
                    "$($process.ParentProcessId), running now"
                Frame  = ''
            })
        }
    }

    $parentPaths = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    # Only 64-bit runtimes in an affected or recently patched line can have been hit.
    $historyRuntimes = @($runtimes |
        Where-Object { $_.Arch -eq 'x64' -and $_.Rank -ge 1 })
    foreach ($runtime in $historyRuntimes) {
        foreach ($launcher in @('java.exe', 'javaw.exe')) {
            $launcherPath = Join-Path $runtime.Home "bin\$launcher"
            if ([System.IO.File]::Exists($launcherPath)) {
                [void]$parentPaths.Add($launcherPath)
            }
        }
    }
    foreach ($jvmHost in ($jvmHosts | Where-Object { -not $_.IsLauncher })) {
        $hostProcess = $allProcesses |
            Where-Object { [int]$_.ProcessId -eq $jvmHost.ProcessId } |
            Select-Object -First 1
        if ($null -ne $hostProcess -and $hostProcess.ExecutablePath) {
            [void]$parentPaths.Add([string]$hostProcess.ExecutablePath)
        }
    }
    $historyParams = @{
        ParentPaths  = @($parentPaths)
        LookbackDays = $lookbackDays
    }
    foreach ($historySign in (Get-ChildProcessHistory @historyParams)) {
        $script:Signs.Add($historySign)
    }

    # Decide the overall verdict.
    $sortedRuntimes = @($runtimes | Sort-Object -Property @{
        Expression = 'Rank'; Descending = $true
    }, 'Home')
    $vulnerableCount = @($runtimes | Where-Object { $_.Rank -eq 4 }).Count
    $reviewCount = @($runtimes | Where-Object { $_.Rank -eq 2 -or $_.Rank -eq 3 }).Count
    $patchedCount = @($runtimes | Where-Object { $_.Rank -eq 1 }).Count
    $strongSigns = @($script:Signs | Where-Object { $_.Strong })
    $affectedPresent = ($vulnerableCount + $reviewCount) -gt 0
    $runtimeTotal = $runtimes.Count

    if ($strongSigns.Count -gt 0) {
        $resultLine = 'Result: FAILED. Possible Java4Shell exploitation signs found.'
        $statusValue = "FAIL: Java4Shell exploit signs | $($strongSigns.Count) found | " +
            "see script output | $stamp"
        $exitCode = 1
    }
    elseif ($vulnerableCount -gt 0) {
        $resultLine = "Result: FAILED. $vulnerableCount Java runtime(s) vulnerable, " +
            'not mitigated.'
        $statusValue = "FAIL: Java4Shell vulnerable | $vulnerableCount of " +
            "$runtimeTotal runtimes | $stamp"
        $exitCode = 1
    }
    elseif ($reviewCount -gt 0) {
        $resultLine = "Result: WARNING. $reviewCount runtime(s) on an affected version " +
            'but not exposed now.'
        $statusValue = "WARN: Java4Shell affected, not patched | " +
            "$reviewCount runtimes | $stamp"
    }
    elseif ($script:Signs.Count -gt 0) {
        $resultLine = 'Result: WARNING. Not vulnerable now, but Java crash or shell ' +
            'signs to review.'
        $statusValue = "WARN: Java4Shell patched, review signs | " +
            "$($script:Signs.Count) found | $stamp"
    }
    elseif ($script:ScanIncomplete) {
        $resultLine = 'Result: WARNING. Folder scan hit its time budget; results partial.'
        $statusValue = "WARN: Java4Shell scan incomplete | $runtimeTotal runtimes | " +
            "$stamp"
    }
    elseif ($runtimeTotal -eq 0) {
        $resultLine = 'Result: OK. No Java runtime found on this device.'
        $statusValue = "OK: Java4Shell no Java found | $stamp"
    }
    else {
        $resultLine = "Result: OK. No vulnerable Java runtime ($runtimeTotal checked)."
        $statusValue = "OK: Java4Shell not vulnerable | $runtimeTotal runtimes | $stamp"
    }

    $resultLevel = 'OK'
    $resultColor = 'Green'
    if ($resultLine -like 'Result: FAILED*') {
        $resultLevel = 'FAILED'
        $resultColor = 'Red'
    }
    elseif ($resultLine -like 'Result: WARNING*') {
        $resultLevel = 'WARNING'
        $resultColor = 'Yellow'
    }

    # Report the summary.
    if (-not $script:IsRmm) {
        Write-Host ''
    }
    Write-JobLine -Text $resultLine -Color $resultColor
    Write-Host ''

    if ($null -eq $cpuGate -and $probeCount -eq 0) {
        $cpuText = 'not checked, no affected 64-bit runtime to probe'
    }
    elseif ($null -eq $cpuGate) {
        $cpuText = 'not confirmed, treated as exploitable'
    }
    elseif ($cpuGate) {
        $cpuText = 'AVX-512 VBMI present, vulnerable code path active'
    }
    else {
        $cpuText = 'no AVX-512 VBMI, vulnerable code path inactive'
    }
    if ($isVirtual -and $cpuGate -eq $false) {
        $cpuText = $cpuText + ' (VM: can change on host move)'
    }
    $mitigationText = 'none set machine-wide'
    if ($machineMitigation) {
        $mitigationText = 'set machine-wide in JAVA_TOOL_OPTIONS or _JAVA_OPTIONS'
    }
    $scanState = 'complete'
    if ($script:ScanIncomplete) {
        $scanState = 'INCOMPLETE, time budget reached'
    }
    $runtimeSummary = "$runtimeTotal ($vulnerableCount vulnerable, " +
        "$reviewCount review, $patchedCount patched)"

    Write-JobLine -Text "CPU check:        $cpuText"
    Write-JobLine -Text "Mitigation flags: $mitigationText"
    Write-JobLine -Text "Runtimes found:   $runtimeSummary"
    $scanText = "$($script:DirectoryCount) folders in ${scanSeconds}s, $scanState"
    Write-JobLine -Text "Folder scan:      $scanText"
    if ($script:UnreadableCount -gt 0) {
        $unreadableText = "$($script:UnreadableCount) folders or keys skipped"
        Write-JobLine -Text "Unreadable:       $unreadableText"
    }
    if ($script:ModuleScanIncomplete) {
        Write-Host 'Process scan:     partial, in-process JVM check hit its time limit'
    }
    foreach ($invalidInput in $script:InvalidInputs) {
        Write-JobLine -Text "Input:            $invalidInput"
    }

    # Report each runtime, worst first.
    $listIndex = 0
    $listedRuntimes = @($sortedRuntimes | Select-Object -First $script:MaxListedRuntimes)
    foreach ($runtime in $listedRuntimes) {
        $listIndex++
        Write-Host ''
        $verdictColor = Get-VerdictColor -Rank $runtime.Rank
        Write-JobLine -Text "[$listIndex] $($runtime.Verdict)" -Color $verdictColor
        Write-DetailLine -Label 'Path' -Value $runtime.Home
        $versionLine = "$($runtime.VersionText) $($runtime.Vendor) $($runtime.Arch)"
        if ($runtime.Fix -ne '' -and $runtime.Rank -ge 2) {
            $versionLine = "$versionLine, $($runtime.Fix)"
        }
        Write-DetailLine -Label 'Version' -Value $versionLine
        if ($runtime.Processes.Count -gt 0) {
            $pidList = (@($runtime.Processes | Select-Object -First 4 |
                ForEach-Object { "$($_.Name) $($_.ProcessId)" })) -join ', '
            Write-DetailLine -Label 'Running' -Value $pidList
            $portList = (@($runtime.Processes | Where-Object { $_.Ports -ne '' } |
                ForEach-Object { $_.Ports })) -join ', '
            if ($portList -ne '') {
                Write-DetailLine -Label 'Listening' -Value $portList
            }
        }
        if ($runtime.Rank -ge 2) {
            Write-DetailLine -Label 'Mitigated' -Value $runtime.Mitigation
        }
    }
    if ($sortedRuntimes.Count -gt $script:MaxListedRuntimes) {
        $hiddenCount = $sortedRuntimes.Count - $script:MaxListedRuntimes
        Write-Host ''
        Write-JobLine -Text "$hiddenCount more runtime(s) not shown, all rated no worse."
    }

    # Report exploitation signs.
    Write-Host ''
    $signCount = $script:Signs.Count
    Write-JobLine -Text "Exploitation signs, last $lookbackDays days: $signCount"
    $orderedSigns = @($script:Signs | Sort-Object -Property @{
        Expression = 'Strong'; Descending = $true
    }, @{ Expression = 'Time'; Descending = $true })
    foreach ($sign in ($orderedSigns | Select-Object -First $script:MaxListedSigns)) {
        $label = 'Review'
        $labelColor = 'Yellow'
        if ($sign.Strong) {
            $label = 'HIGH'
            $labelColor = 'Red'
        }
        $signTime = $sign.Time.ToString('yyyy-MM-dd HH:mm')
        Write-JobLine -Text "    $label $signTime $($sign.Detail)" -Color $labelColor
        if ($sign.Frame -ne '') {
            Write-JobLine -Text "        Frame: $($sign.Frame)"
        }
    }
    if ($orderedSigns.Count -gt $script:MaxListedSigns) {
        $hiddenSigns = $orderedSigns.Count - $script:MaxListedSigns
        Write-JobLine -Text "    $hiddenSigns more sign(s) not shown."
    }

    # Point the tech at the next step.
    Write-Host ''
    if ($strongSigns.Count -gt 0) {
        Write-Host 'Next: isolate the host in your EDR, investigate, rotate app secrets.'
    }
    elseif ($signCount -gt 0) {
        Write-Host 'Next: review the signs above; unrelated JVM crashes also appear here.'
    }
    if ($affectedPresent) {
        Write-Host 'Next: install the vendor November 2026 Java build for each runtime.'
    }
    if ($vulnerableCount -gt 0) {
        Write-Host 'Until patched: add -XX:-UseBASE64Intrinsics and restart the service.'
    }
    if (-not $affectedPresent -and $signCount -eq 0) {
        Write-Host 'Next: no action needed for CVE-2026-114938.'
    }

    # Structured report for -ReportPath and -PassThru.
    if ($ReportPath -ne '' -or $PassThru) {
        $runtimeRecords = [System.Collections.Generic.List[object]]::new()
        foreach ($runtime in $sortedRuntimes) {
            $processRecords = [System.Collections.Generic.List[object]]::new()
            foreach ($jvmProcess in $runtime.Processes) {
                $processRecords.Add([pscustomobject]@{
                    Name      = $jvmProcess.Name
                    ProcessId = $jvmProcess.ProcessId
                    Mitigated = [bool]$jvmProcess.Mitigated
                    Ports     = $jvmProcess.Ports
                })
            }
            $runtimeRecords.Add([pscustomobject]@{
                Path         = $runtime.Home
                Version      = $runtime.VersionText
                Vendor       = $runtime.Vendor
                Architecture = $runtime.Arch
                Verdict      = $runtime.Verdict
                Fix          = $runtime.Fix
                Mitigation   = $runtime.Mitigation
                Processes    = $processRecords.ToArray()
            })
        }
        $signRecords = [System.Collections.Generic.List[object]]::new()
        foreach ($sign in $orderedSigns) {
            $severity = 'Review'
            if ($sign.Strong) {
                $severity = 'High'
            }
            $signRecords.Add([pscustomobject]@{
                Severity = $severity
                Kind     = $sign.Kind
                Time     = $sign.Time.ToString('o')
                Detail   = $sign.Detail
                Frame    = $sign.Frame
            })
        }
        $report = [pscustomobject]@{
            ComputerName          = $env:COMPUTERNAME
            CheckedAt             = (Get-Date).ToString('o')
            Cve                   = 'CVE-2026-114938'
            Result                = $resultLevel
            Summary               = $resultLine -replace '^Result: [A-Z]+\. ', ''
            CpuCheck              = $cpuText
            MachineWideMitigation = [bool]$machineMitigation
            ScanComplete          = -not $script:ScanIncomplete
            FoldersScanned        = $script:DirectoryCount
            LookbackDays          = $lookbackDays
            Runtimes              = $runtimeRecords.ToArray()
            Signs                 = $signRecords.ToArray()
        }

        if ($ReportPath -ne '') {
            try {
                $reportJson = $report | ConvertTo-Json -Depth 6
                Set-Content -LiteralPath $ReportPath -Value $reportJson -Encoding UTF8
                Write-Host "Report saved: $ReportPath"
            }
            catch {
                $saveError = "Report save failed: $($_.Exception.Message)"
                Write-Host $saveError -ForegroundColor Red
            }
        }
        if ($PassThru) {
            Write-Output $report
        }
    }

    # One-line status an RMM can copy into a custom field, always the last line.
    $statusValue = Limit-Text -Text $statusValue -MaximumLength 255
    Write-Host ''
    Write-Host "Status: $statusValue"
}
catch {
    Write-Host 'Result: FAILED. The audit stopped on an unexpected error.'
    Write-JobLine -Text $_.Exception.Message
    Write-Host ''
    Write-Host "Status: FAIL: Java4Shell audit error | see script output | $stamp"
    $exitCode = 1
}
finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}

# Exit 1 when vulnerable, exploitation signs are found, or the audit failed.
exit $exitCode
