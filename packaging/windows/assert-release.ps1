param(
    [string]$ExecutablePath,
    [string]$ArchivePath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$metadata = Get-Content (Join-Path $root 'release-metadata.json') -Raw | ConvertFrom-Json
if (-not $ExecutablePath) {
    $ExecutablePath = Join-Path $root 'dist\windows-x64\gateway-connector.exe'
}
$ExecutablePath = (Resolve-Path $ExecutablePath).Path

function Assert-Equal($Actual, $Expected, [string]$Name) {
    if ($Actual -cne $Expected) {
        throw "$Name expected '$Expected', got '$Actual'"
    }
}

$bytes = [System.IO.File]::ReadAllBytes($ExecutablePath)
if ($bytes.Length -lt 512 -or [System.Text.Encoding]::ASCII.GetString($bytes, 0, 2) -ne 'MZ') {
    throw 'release executable is not a valid DOS/PE image'
}
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ($peOffset -lt 0 -or $peOffset + 96 -gt $bytes.Length -or
    [System.Text.Encoding]::ASCII.GetString($bytes, $peOffset, 4) -ne "PE`0`0") {
    throw 'release executable has an invalid PE header offset or signature'
}
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
Assert-Equal $machine ([uint16]0x8664) 'PE machine'
$optionalHeader = $peOffset + 24
if ($optionalHeader + 152 -gt $bytes.Length) {
    throw 'release executable has a truncated PE32+ optional header'
}
$magic = [BitConverter]::ToUInt16($bytes, $optionalHeader)
Assert-Equal $magic ([uint16]0x20b) 'PE optional-header magic'
$subsystem = [BitConverter]::ToUInt16($bytes, $optionalHeader + 68)
Assert-Equal $subsystem ([uint16]2) 'PE subsystem'
$certificateDirectory = $optionalHeader + 112 + (4 * 8)
$certificateOffset = [BitConverter]::ToUInt32($bytes, $certificateDirectory)
$certificateSize = [BitConverter]::ToUInt32($bytes, $certificateDirectory + 4)
if ($certificateOffset -ne 0 -or $certificateSize -ne 0) {
    throw "release executable unexpectedly contains an Authenticode certificate table at $certificateOffset with size $certificateSize"
}

if (-not ('GatewayConnector.ReleaseResourceInspector' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace GatewayConnector {
    public static class ReleaseResourceInspector {
        private delegate bool EnumResNameProc(IntPtr module, IntPtr type, IntPtr name, IntPtr parameter);
        private delegate bool EnumResLangProc(IntPtr module, IntPtr type, IntPtr name, ushort language, IntPtr parameter);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibraryExW(string path, IntPtr file, uint flags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumResourceNamesW(IntPtr module, IntPtr type, EnumResNameProc callback, IntPtr parameter);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool EnumResourceLanguagesW(IntPtr module, IntPtr type, IntPtr name, EnumResLangProc callback, IntPtr parameter);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool FreeLibrary(IntPtr module);

        public static int[] Inspect(string path, int type, ushort expectedLanguage) {
            const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
            const uint LOAD_LIBRARY_AS_IMAGE_RESOURCE = 0x00000020;
            IntPtr module = LoadLibraryExW(path, IntPtr.Zero, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (module == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                int count = 0;
                int unexpectedLanguages = 0;
                int callbackError = 0;
                EnumResNameProc callback = (currentModule, currentType, currentName, ignoredParameter) => {
                    count++;
                    bool sawLanguage = false;
                    EnumResLangProc languageCallback = (ignoredModule, ignoredType, ignoredName, language, ignoredLanguageParameter) => {
                        sawLanguage = true;
                        if (language != expectedLanguage) unexpectedLanguages++;
                        return true;
                    };
                    bool languageOk = EnumResourceLanguagesW(currentModule, currentType, currentName, languageCallback, IntPtr.Zero);
                    int languageError = Marshal.GetLastWin32Error();
                    GC.KeepAlive(languageCallback);
                    if (!languageOk) {
                        callbackError = languageError;
                        return false;
                    }
                    if (!sawLanguage) {
                        callbackError = 1815;
                        return false;
                    }
                    return true;
                };
                bool ok = EnumResourceNamesW(module, new IntPtr(type), callback, IntPtr.Zero);
                int error = Marshal.GetLastWin32Error();
                GC.KeepAlive(callback);
                if (callbackError != 0) throw new Win32Exception(callbackError);
                if (!ok && error != 1813) throw new Win32Exception(error);
                return new int[] { count, unexpectedLanguages };
            } finally {
                FreeLibrary(module);
            }
        }
    }
}
'@
}

$resourceLanguage = [uint16]0x0409
$iconResources = [GatewayConnector.ReleaseResourceInspector]::Inspect($ExecutablePath, 3, $resourceLanguage)
$groupIconResources = [GatewayConnector.ReleaseResourceInspector]::Inspect($ExecutablePath, 14, $resourceLanguage)
$versionResources = [GatewayConnector.ReleaseResourceInspector]::Inspect($ExecutablePath, 16, $resourceLanguage)
$iconCount = $iconResources[0]
$groupIconCount = $groupIconResources[0]
$versionCount = $versionResources[0]
if ($iconCount -ne $metadata.windows_icon_images -or $groupIconCount -ne 1 -or $versionCount -ne 1) {
    throw "required PE resource counts differ: RT_ICON=$iconCount RT_GROUP_ICON=$groupIconCount RT_VERSION=$versionCount"
}
if ($iconResources[1] -ne 0 -or $groupIconResources[1] -ne 0 -or $versionResources[1] -ne 0) {
    throw 'icon and version resources must use the expected Windows language identifier 0x0409'
}

$version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ExecutablePath)
Assert-Equal $version.ProductName $metadata.product_name 'ProductName'
Assert-Equal $version.FileDescription $metadata.file_description 'FileDescription'
Assert-Equal $version.FileVersion $metadata.version 'FileVersion'
Assert-Equal $version.ProductVersion $metadata.version 'ProductVersion'
Assert-Equal $version.OriginalFilename $metadata.original_filename 'OriginalFilename'
Assert-Equal $version.CompanyName $metadata.company_name 'CompanyName'
Assert-Equal $version.LegalCopyright $metadata.legal_copyright 'LegalCopyright'
Assert-Equal $version.InternalName $metadata.binary_name 'InternalName'
$versionParts = @($metadata.version.Split('-')[0].Split('.') | ForEach-Object { [uint16]$_ })
if ($versionParts.Count -gt 4) {
    throw 'release metadata version has more than four numeric components'
}
while ($versionParts.Count -lt 4) {
    $versionParts += [uint16]0
}
Assert-Equal $version.FileMajorPart $versionParts[0] 'FileMajorPart'
Assert-Equal $version.FileMinorPart $versionParts[1] 'FileMinorPart'
Assert-Equal $version.FileBuildPart $versionParts[2] 'FileBuildPart'
Assert-Equal $version.FilePrivatePart $versionParts[3] 'FilePrivatePart'
Assert-Equal $version.ProductMajorPart $versionParts[0] 'ProductMajorPart'
Assert-Equal $version.ProductMinorPart $versionParts[1] 'ProductMinorPart'
Assert-Equal $version.ProductBuildPart $versionParts[2] 'ProductBuildPart'
Assert-Equal $version.ProductPrivatePart $versionParts[3] 'ProductPrivatePart'

$signature = Get-AuthenticodeSignature -LiteralPath $ExecutablePath
Assert-Equal $signature.Status ([System.Management.Automation.SignatureStatus]::NotSigned) 'Authenticode status'

$archiveEntries = @()
if ($ArchivePath) {
    $ArchivePath = (Resolve-Path $ArchivePath).Path
    $expectedArtifact = $metadata.windows_artifact.Replace('{version}', $metadata.version)
    Assert-Equal ([System.IO.Path]::GetFileName($ArchivePath)) $expectedArtifact 'archive filename'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $archiveEntries = @($archive.Entries | ForEach-Object FullName | Sort-Object)
        if ($archive.Entries.Count -ne 3 -or @($archive.Entries | Where-Object { $_.FullName.EndsWith('/') }).Count -ne 0) {
            throw 'release ZIP must contain exactly three file entries and no directories'
        }
        $expectedFiles = @{
            'gateway-connector.exe' = $ExecutablePath
            'LICENSE' = (Join-Path $root 'LICENSE')
            'release-metadata.json' = (Join-Path $root 'release-metadata.json')
        }
        foreach ($name in $expectedFiles.Keys) {
            $matching = @($archive.Entries | Where-Object FullName -CEQ $name)
            if ($matching.Count -ne 1) {
                throw "release ZIP must contain exactly one $name entry"
            }
            $entryStream = $matching[0].Open()
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $archiveHash = [Convert]::ToHexString($sha.ComputeHash($entryStream))
            } finally {
                $sha.Dispose()
                $entryStream.Dispose()
            }
            $fileHash = (Get-FileHash -LiteralPath $expectedFiles[$name] -Algorithm SHA256).Hash
            if ($archiveHash -cne $fileHash) {
                throw "release ZIP entry content mismatch: $name"
            }
        }
    } finally {
        $archive.Dispose()
    }
    $expectedEntries = @('gateway-connector.exe', 'LICENSE', 'release-metadata.json') | Sort-Object
    if (Compare-Object $expectedEntries $archiveEntries) {
        throw "release ZIP has unexpected contents: $($archiveEntries -join ', ')"
    }
}

[pscustomobject]@{
    executable = $ExecutablePath
    machine = ('0x{0:X4}' -f $machine)
    optional_header = ('0x{0:X3}' -f $magic)
    subsystem = $subsystem
    authenticode = $signature.Status.ToString()
    certificate_table_size = $certificateSize
    resources = [pscustomobject]@{
        icon = $iconCount
        group_icon = $groupIconCount
        version = $versionCount
        language = ('0x{0:X4}' -f $resourceLanguage)
    }
    product_name = $version.ProductName
    file_description = $version.FileDescription
    file_version = $version.FileVersion
    product_version = $version.ProductVersion
    original_filename = $version.OriginalFilename
    internal_name = $version.InternalName
    archive = $ArchivePath
    archive_entries = $archiveEntries
} | ConvertTo-Json -Depth 4
