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

Write-Output $reportText
