param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$metadata = Get-Content (Join-Path $root 'release-metadata.json') -Raw | ConvertFrom-Json
$artifact = Join-Path (Join-Path $root 'dist') $metadata.windows_artifact.Replace('{version}', $metadata.version)
$executable = Join-Path $root 'dist\windows-x64\gateway-connector.exe'

$reportText = & (Join-Path $PSScriptRoot 'assert-release.ps1') -ExecutablePath $executable -ArchivePath $artifact
$report = $reportText | ConvertFrom-Json
if ($report.subsystem -ne 2 -or $report.resources.icon -lt 1 -or
    $report.resources.group_icon -ne 1 -or $report.resources.version -ne 1 -or
    $report.resources.language -cne '0x0409' -or
    $report.machine -cne '0x8664' -or $report.optional_header -cne '0x20B' -or
    $report.authenticode -cne 'NotSigned' -or $report.certificate_table_size -ne 0 -or
    $report.internal_name -cne $metadata.binary_name) {
    throw "release assertion report omitted decisive PE evidence: $reportText"
}

function Assert-ReleaseCheckFails([string[]]$Arguments, [string]$ExpectedMessage) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new('pwsh')
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in @('-NoProfile', '-File', (Join-Path $PSScriptRoot 'assert-release.ps1')) + $Arguments) {
        $startInfo.ArgumentList.Add($argument)
    }
    $process = [System.Diagnostics.Process]::Start($startInfo)
    $output = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    if ($process.ExitCode -eq 0) {
        throw "release assertions unexpectedly accepted a mutated artifact: $($Arguments -join ' ')"
    }
    if ($output -notmatch $ExpectedMessage) {
        throw "mutated artifact failed for an unexpected reason: $output"
    }
}

function Stop-ChildProcess([System.Diagnostics.Process]$ChildProcess, [string]$Description) {
    if (-not $ChildProcess.HasExited) {
        $ChildProcess.Kill($true)
    }
    if (-not $ChildProcess.WaitForExit(10000)) {
        throw "$Description did not terminate within 10 seconds"
    }
}

$mutated = Join-Path ([System.IO.Path]::GetTempPath()) "gateway-connector-cui-$([guid]::NewGuid()).exe"
try {
    $bytes = [System.IO.File]::ReadAllBytes($executable)
    $peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
    $optionalHeader = $peOffset + 24
    [BitConverter]::GetBytes([uint16]3).CopyTo($bytes, $optionalHeader + 68)
    [System.IO.File]::WriteAllBytes($mutated, $bytes)

    Assert-ReleaseCheckFails @('-ExecutablePath', $mutated) 'PE subsystem expected'
} finally {
    Remove-Item $mutated -Force -ErrorAction SilentlyContinue
}

$mutatedDirectory = Join-Path ([System.IO.Path]::GetTempPath()) "gateway-connector-zip-$([guid]::NewGuid())"
try {
    New-Item $mutatedDirectory -ItemType Directory | Out-Null
    $mutatedArchive = Join-Path $mutatedDirectory ([System.IO.Path]::GetFileName($artifact))
    Copy-Item $artifact $mutatedArchive
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::Open(
        $mutatedArchive,
        [System.IO.Compression.ZipArchiveMode]::Update
    )
    try {
        $entry = $archive.GetEntry('release-metadata.json')
        $entry.Delete()
        $entry = $archive.CreateEntry('release-metadata.json')
        $writer = [System.IO.StreamWriter]::new($entry.Open())
        try {
            $writer.Write('{}')
        } finally {
            $writer.Dispose()
        }
    } finally {
        $archive.Dispose()
    }
    Assert-ReleaseCheckFails @('-ExecutablePath', $executable, '-ArchivePath', $mutatedArchive) 'release ZIP entry content mismatch'
} finally {
    Remove-Item $mutatedDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

$isolatedParent = Join-Path ([System.IO.Path]::GetTempPath()) "gateway-connector-release-$([guid]::NewGuid())"
try {
    New-Item $isolatedParent -ItemType Directory | Out-Null
    $isolatedRoot = Join-Path $isolatedParent 'isolated-root'
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new($executable)
    $startInfo.UseShellExecute = $false
    $startInfo.ArgumentList.Add('--isolated-root')
    $startInfo.ArgumentList.Add($isolatedRoot)
    $process = [System.Diagnostics.Process]::Start($startInfo)
    try {
        $marker = Join-Path $isolatedRoot '.gateway-connector-isolated-root.json'
        $layoutDirectories = @(
            'data', 'state', 'coordinator',
            'agents\claude', 'agents\codex', 'agents\gemini',
            'agents\grokbuild', 'agents\opencode'
        )
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        $ready = $false
        while ([DateTime]::UtcNow -lt $deadline) {
            if (Test-Path $marker -PathType Leaf) {
                $markerValue = Get-Content $marker -Raw | ConvertFrom-Json
                if ($markerValue.kind -cne 'gateway-connector-isolated-root' -or $markerValue.schema_version -ne 1) {
                    throw 'release executable wrote an invalid isolated-root marker'
                }
                $missingDirectories = @($layoutDirectories | Where-Object {
                    -not (Test-Path (Join-Path $isolatedRoot $_) -PathType Container)
                })
                if ($missingDirectories.Count -eq 0) {
                    $ready = $true
                    break
                }
            }
            if ($process.HasExited) {
                break
            }
            Start-Sleep -Milliseconds 100
        }
        if (-not $ready) {
            $exit = if ($process.HasExited) { $process.ExitCode } else { 'still running' }
            throw "release executable did not initialize its exact --isolated-root layout (process: $exit)"
        }
    } finally {
        try {
            Stop-ChildProcess $process 'isolated release executable'
        } finally {
            $process.Dispose()
        }
    }

    $blockedRoot = Join-Path $isolatedParent 'blocked-root'
    New-Item $blockedRoot -ItemType Directory | Out-Null
    Set-Content (Join-Path $blockedRoot 'sentinel') -Value 'do not touch' -NoNewline
    $blockedStart = [System.Diagnostics.ProcessStartInfo]::new($executable)
    $blockedStart.UseShellExecute = $false
    $blockedStart.ArgumentList.Add('--isolated-root')
    $blockedStart.ArgumentList.Add($blockedRoot)
    $blocked = [System.Diagnostics.Process]::Start($blockedStart)
    try {
        if (-not $blocked.WaitForExit(30000)) {
            throw 'release executable did not reject a non-empty unmarked isolated root'
        }
        if ($blocked.ExitCode -eq 0 -or
            (Get-Content (Join-Path $blockedRoot 'sentinel') -Raw) -cne 'do not touch' -or
            (Test-Path (Join-Path $blockedRoot '.gateway-connector-isolated-root.lock'))) {
            throw 'release executable did not fail closed for a non-empty unmarked isolated root'
        }
    } finally {
        try {
            Stop-ChildProcess $blocked 'blocked-root release executable'
        } finally {
            $blocked.Dispose()
        }
    }

    $junctionTarget = Join-Path $isolatedParent 'junction-target'
    $junctionRoot = Join-Path $isolatedParent 'junction-root'
    New-Item $junctionTarget -ItemType Directory | Out-Null
    Set-Content (Join-Path $junctionTarget 'sentinel') -Value 'do not touch' -NoNewline
    $null = & cmd.exe /D /C mklink /J $junctionRoot $junctionTarget
    if ($LASTEXITCODE -ne 0) {
        throw 'could not create the Windows isolated-root junction fixture'
    }
    $junctionStart = [System.Diagnostics.ProcessStartInfo]::new($executable)
    $junctionStart.UseShellExecute = $false
    $junctionStart.ArgumentList.Add('--isolated-root')
    $junctionStart.ArgumentList.Add($junctionRoot)
    $junctionProcess = [System.Diagnostics.Process]::Start($junctionStart)
    try {
        if (-not $junctionProcess.WaitForExit(30000)) {
            throw 'release executable did not reject a junction isolated root'
        }
        if ($junctionProcess.ExitCode -eq 0 -or
            (Get-Content (Join-Path $junctionTarget 'sentinel') -Raw) -cne 'do not touch' -or
            (Test-Path (Join-Path $junctionTarget '.gateway-connector-isolated-root.json'))) {
            throw 'release executable did not fail closed for a junction isolated root'
        }
    } finally {
        try {
            Stop-ChildProcess $junctionProcess 'junction-root release executable'
        } finally {
            $junctionProcess.Dispose()
        }
    }
} finally {
    Remove-Item $isolatedParent -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output $reportText
