[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ManifestPath,

    [string]$ArchivePath,

    [string]$DestinationRoot,

    [switch]$SkipDeviceCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedTag = 'gpu-tools-v7.1.2-r1'
$expectedAsset = 'pdf-password-recovery-gpu-tools-windows-x64-v7.1.2.zip'
$repositoryRoot = Split-Path -Parent $PSScriptRoot
$downloadsRoot = Join-Path $repositoryRoot 'downloads'
$requiredFiles = @(
    'hashcat-7.1.2\hashcat.exe',
    'hashcat-7.1.2\hashcat.bin',
    'hashcat-7.1.2\docs\license.txt',
    'pdf2john.py',
    'THIRD_PARTY_NOTICES.txt'
)
$requiredDirectories = @('hashcat-7.1.2', 'hashcat-7.1.2\OpenCL', 'hashcat-7.1.2\modules')

function Assert-NotReparsePoint {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Description)

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Description must not be a reparse point: $Path"
    }
}

function Assert-ExistingFile {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Description)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "$Description is missing or is not a file: $Path" }
    Assert-NotReparsePoint -Path $Path -Description $Description
}

function Assert-ExistingDirectory {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Description)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "$Description is missing or is not a directory: $Path" }
    Assert-NotReparsePoint -Path $Path -Description $Description
}

function Assert-PathWithin {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Root)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd('\')
    $prefix = $fullRoot + '\'
    if (-not $fullPath.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Temporary path is outside the controlled downloads root: $fullPath"
    }
}

function Test-TreeHasReparsePoint {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [System.IO.FileAttributes]::ReparsePoint) { return $true }
    return @(
        Get-ChildItem -LiteralPath $Path -Force -Recurse | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        }
    ).Count -gt 0
}

function Remove-OwnedTemporaryPath {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$DownloadsRoot)

    Assert-PathWithin -Path $Path -Root $DownloadsRoot
    if (-not (Test-Path -LiteralPath $Path)) { return }
    if (Test-TreeHasReparsePoint -Path $Path) {
        Write-Warning "Leaving unsafe temporary path for manual inspection: $Path"
        return
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Assert-ReleaseManifest {
    param([Parameter(Mandatory)]$Manifest)

    foreach ($property in @('tag', 'asset', 'url', 'sha256')) {
        if ($null -eq $Manifest.$property -or [string]::IsNullOrWhiteSpace([string]$Manifest.$property)) {
            throw "Manifest property is required: $property"
        }
    }
    if ($Manifest.tag -ne $expectedTag -or $Manifest.asset -ne $expectedAsset) {
        throw 'Manifest does not describe the pinned GPU tools release.'
    }
    if ($Manifest.asset -match '[\\/:]' -or $Manifest.asset -match '^\.+$') {
        throw 'Manifest asset must be a plain file name.'
    }
    $uri = $null
    if (-not [System.Uri]::TryCreate([string]$Manifest.url, [System.UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') {
        throw 'Manifest URL must be an absolute HTTPS URL.'
    }
    if ([string]$Manifest.sha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'Manifest SHA-256 must be a 64-character hexadecimal digest.'
    }
}

function Assert-InstalledLayout {
    param([Parameter(Mandatory)][string]$Root)

    Assert-ExistingDirectory -Path $Root -Description 'GPU tools directory'
    foreach ($relativePath in $requiredDirectories) {
        Assert-ExistingDirectory -Path (Join-Path $Root $relativePath) -Description "Required runtime directory $relativePath"
    }
    foreach ($relativePath in $requiredFiles) {
        Assert-ExistingFile -Path (Join-Path $Root $relativePath) -Description "Required runtime file $relativePath"
    }
    if (Test-TreeHasReparsePoint -Path $Root) { throw "GPU tools directory contains a reparse point: $Root" }
}

function Test-MatchingInstallation {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)]$Manifest)

    if (-not (Test-Path -LiteralPath $Root)) { return $false }
    Assert-ExistingDirectory -Path $Root -Description 'Existing destination'
    $markerPath = Join-Path $Root '.installed.json'
    Assert-ExistingFile -Path $markerPath -Description 'Existing destination marker'
    try { $marker = Get-Content -LiteralPath $markerPath -Raw | ConvertFrom-Json }
    catch { throw "Existing destination marker is invalid: $markerPath" }
    foreach ($property in @('tag', 'asset', 'url', 'sha256')) {
        if ($marker.$property -ne $Manifest.$property) {
            throw "Existing destination is not the requested verified release: $Root"
        }
    }
    Assert-InstalledLayout -Root $Root
    return $true
}

function Assert-SafeZipEntries {
    param([Parameter(Mandatory)][string]$Archive)

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName -replace '/', '\'
            if ($name.StartsWith('\') -or $name -match '^[A-Za-z]:' -or $name -match '(^|\\)\.\.?(\\|$)') {
                throw "Archive contains an unsafe entry path: $($entry.FullName)"
            }
        }
    }
    finally { $zip.Dispose() }
}

if (-not (Test-Path -LiteralPath $downloadsRoot)) { New-Item -ItemType Directory -Path $downloadsRoot | Out-Null }
Assert-ExistingDirectory -Path $downloadsRoot -Description 'Repository downloads directory'
$downloadsRoot = (Resolve-Path -LiteralPath $downloadsRoot).Path

$manifestFullPath = [System.IO.Path]::GetFullPath($ManifestPath)
Assert-ExistingFile -Path $manifestFullPath -Description 'Release manifest'
try { $manifest = Get-Content -LiteralPath $manifestFullPath -Raw | ConvertFrom-Json }
catch { throw "Release manifest is invalid JSON: $manifestFullPath" }
Assert-ReleaseManifest -Manifest $manifest
$manifest.sha256 = ([string]$manifest.sha256).ToLowerInvariant()

if ([string]::IsNullOrWhiteSpace($DestinationRoot)) { $DestinationRoot = Join-Path $downloadsRoot 'gpu-tools' }
$destinationFullPath = [System.IO.Path]::GetFullPath($DestinationRoot)
if (Test-Path -LiteralPath $destinationFullPath) {
    if (Test-MatchingInstallation -Root $destinationFullPath -Manifest $manifest) {
        Write-Host "GPU tools already verified at $destinationFullPath"
        $global:LASTEXITCODE = 0
        return
    }
}

$destinationParent = Split-Path -Parent $destinationFullPath
Assert-ExistingDirectory -Path $destinationParent -Description 'Destination parent directory'

$temporaryArchive = $null
$stagingRoot = Join-Path $downloadsRoot ('.gpu-tools-stage-' + [guid]::NewGuid().ToString('N'))
Assert-PathWithin -Path $stagingRoot -Root $downloadsRoot
try {
    if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
        $temporaryArchive = Join-Path $downloadsRoot ('.gpu-tools-download-' + [guid]::NewGuid().ToString('N') + '.zip')
        Assert-PathWithin -Path $temporaryArchive -Root $downloadsRoot
        Invoke-WebRequest -Uri $manifest.url -OutFile $temporaryArchive -UseBasicParsing
        $archiveFullPath = $temporaryArchive
    }
    else {
        $archiveFullPath = [System.IO.Path]::GetFullPath($ArchivePath)
    }
    Assert-ExistingFile -Path $archiveFullPath -Description 'GPU tools archive'

    $actualSha256 = (Get-FileHash -LiteralPath $archiveFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $expectedSha256 = ([string]$manifest.sha256).ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        Write-Host "Expected SHA256: $expectedSha256"
        Write-Host "Actual SHA256:   $actualSha256"
        throw 'GPU tools archive SHA-256 does not match the release manifest.'
    }

    Assert-SafeZipEntries -Archive $archiveFullPath
    New-Item -ItemType Directory -Path $stagingRoot | Out-Null
    $payloadRoot = Join-Path $stagingRoot 'payload'
    Expand-Archive -LiteralPath $archiveFullPath -DestinationPath $payloadRoot -Force
    Assert-InstalledLayout -Root $payloadRoot

    [ordered]@{
        tag = $manifest.tag
        asset = $manifest.asset
        url = $manifest.url
        sha256 = $expectedSha256
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $payloadRoot '.installed.json') -Encoding utf8

    if (Test-Path -LiteralPath $destinationFullPath) {
        throw "Destination appeared during installation and was preserved: $destinationFullPath"
    }
    Move-Item -LiteralPath $payloadRoot -Destination $destinationFullPath

    if (-not $SkipDeviceCheck) {
        $hashcatDirectory = Join-Path $destinationFullPath 'hashcat-7.1.2'
        $hashcatExecutable = Join-Path $hashcatDirectory 'hashcat.exe'
        try {
            $inventoryStandardOutput = Join-Path $stagingRoot 'hashcat-inventory.stdout'
            $inventoryStandardError = Join-Path $stagingRoot 'hashcat-inventory.stderr'
            $inventoryProcess = Start-Process -FilePath $hashcatExecutable -ArgumentList '-I' -WorkingDirectory $hashcatDirectory -Wait -PassThru -NoNewWindow -RedirectStandardOutput $inventoryStandardOutput -RedirectStandardError $inventoryStandardError
            $inventory = @()
            foreach ($inventoryPath in @($inventoryStandardOutput, $inventoryStandardError)) {
                if (Test-Path -LiteralPath $inventoryPath -PathType Leaf) {
                    $inventory += Get-Content -LiteralPath $inventoryPath -Raw
                }
            }
            $inventoryExitCode = $inventoryProcess.ExitCode
            $inventoryText = @($inventory) -join [Environment]::NewLine
            $hasGpu = $inventoryText -match '(?im)^\s*Type[^:]*:\s*GPU\b'
            if ($inventoryExitCode -ne 0 -or -not $hasGpu) {
                Write-Warning 'GPU tools installed, but hashcat did not report a compatible GPU; CPU fallback remains available.'
            }
            else {
                Write-Host 'GPU device preflight succeeded. Detected GPU devices:'
                $reportedDevices = 0
                foreach ($deviceMatch in [regex]::Matches($inventoryText, '(?ms)^\s*Backend Device ID #(?<id>\d+)\s*\r?\n(?<body>.*?)(?=^\s*Backend Device ID #|\z)')) {
                    if ($deviceMatch.Groups['body'].Value -notmatch '(?im)^\s*Type[^:]*:\s*GPU\b') { continue }
                    $nameMatch = [regex]::Match($deviceMatch.Groups['body'].Value, '(?im)^\s*Name[^:]*:\s*(?<name>[^\r\n]+)')
                    $deviceName = if ($nameMatch.Success) { $nameMatch.Groups['name'].Value.Trim() } else { 'Unnamed GPU' }
                    Write-Host "- Device #$($deviceMatch.Groups['id'].Value): $deviceName"
                    $reportedDevices++
                }
                if ($reportedDevices -eq 0) { Write-Host '- GPU device reported by hashcat (name unavailable)' }
            }
        }
        catch {
            Write-Warning "GPU tools installed, but device preflight could not run: $($_.Exception.Message). CPU fallback remains available."
        }
    }
    Write-Host "GPU tools installed at $destinationFullPath"
    $global:LASTEXITCODE = 0
}
finally {
    if ($temporaryArchive) {
        try { Remove-OwnedTemporaryPath -Path $temporaryArchive -DownloadsRoot $downloadsRoot }
        catch { Write-Warning "Could not remove temporary archive: $($_.Exception.Message)" }
    }
    try { Remove-OwnedTemporaryPath -Path $stagingRoot -DownloadsRoot $downloadsRoot }
    catch { Write-Warning "Could not remove staging directory: $($_.Exception.Message)" }
}
