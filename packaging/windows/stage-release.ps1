param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$isWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)
$isX64 = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq [System.Runtime.InteropServices.Architecture]::X64
if (-not $isWindows -or -not $isX64) {
    throw 'this staging script produces only native Windows x64 artifacts'
}

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$metadataPath = Join-Path $root 'release-metadata.json'
$metadata = Get-Content $metadataPath -Raw | ConvertFrom-Json

Push-Location $root
try {
    $cargoMetadataText = & cargo metadata --locked --no-deps --format-version 1
    if ($LASTEXITCODE -ne 0) {
        throw "cargo metadata failed with exit code $LASTEXITCODE"
    }
    $cargoMetadata = $cargoMetadataText | ConvertFrom-Json
    $appPackage = @($cargoMetadata.packages | Where-Object name -eq 'gateway-connector-app')
    if ($appPackage.Count -ne 1) {
        throw 'cargo metadata did not contain exactly one gateway-connector-app package'
    }
    if ($appPackage[0].version -ne $metadata.version) {
        throw "release metadata version $($metadata.version) does not match Cargo version $($appPackage[0].version)"
    }
    if ($metadata.release_mode -ne 'unsigned-manual' -or $metadata.signed -ne $false -or $metadata.updater -ne $false) {
        throw 'release metadata must describe an unsigned manual artifact with no updater'
    }
    if ($metadata.windows_target -ne 'windows-x64' -or
        $metadata.windows_rust_target -ne 'x86_64-pc-windows-msvc') {
        throw 'release metadata must select the native Windows x64 MSVC target'
    }

    $cargoArgs = @(
        'build', '--locked', '--release', '--target', $metadata.windows_rust_target,
        '-p', 'gateway-connector-app', '--features', 'gpui-app', '--bin', 'gateway-connector'
    )
    & cargo @cargoArgs
    if ($LASTEXITCODE -ne 0) {
        throw "cargo release build failed with exit code $LASTEXITCODE"
    }

    $stage = Join-Path $root 'dist\windows-x64'
    if (Test-Path $stage) {
        Remove-Item $stage -Recurse -Force
    }
    New-Item $stage -ItemType Directory | Out-Null
    $releaseDirectory = Join-Path $cargoMetadata.target_directory "$($metadata.windows_rust_target)\release"
    Copy-Item (Join-Path $releaseDirectory 'gateway-connector.exe') $stage
    Copy-Item (Join-Path $root 'LICENSE') $stage
    Copy-Item $metadataPath $stage

    $expected = @('gateway-connector.exe', 'LICENSE', 'release-metadata.json')
    $staged = @(Get-ChildItem $stage -File | ForEach-Object Name | Sort-Object)
    if (Compare-Object ($expected | Sort-Object) $staged) {
        throw "staging directory has unexpected contents: $($staged -join ', ')"
    }

    $artifactName = $metadata.windows_artifact.Replace('{version}', $metadata.version)
    $artifact = Join-Path (Join-Path $root 'dist') $artifactName
    if (Test-Path $artifact) {
        Remove-Item $artifact -Force
    }

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::Open(
        $artifact,
        [System.IO.Compression.ZipArchiveMode]::Create
    )
    try {
        $fixedTimestamp = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
        foreach ($name in $expected) {
            $entry = $archive.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $fixedTimestamp
            $input = [System.IO.File]::OpenRead((Join-Path $stage $name))
            $output = $entry.Open()
            try {
                $input.CopyTo($output)
            } finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }

    Write-Output $artifact
} finally {
    Pop-Location
}
