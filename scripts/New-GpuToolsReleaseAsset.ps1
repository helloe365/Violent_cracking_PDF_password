[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ToolRoot,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory,

    [string]$Repository = 'helloe365/Violent_cracking_PDF_password',

    [ValidateSet('gpu-tools-v7.1.2-r1')]
    [string]$Tag = 'gpu-tools-v7.1.2-r1'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$assetName = 'pdf-password-recovery-gpu-tools-windows-x64-v7.1.2.zip'
$resolvedToolRoot = (Resolve-Path -LiteralPath $ToolRoot).Path
if (-not (Test-Path -LiteralPath $resolvedToolRoot -PathType Container)) {
    throw "ToolRoot must be a directory: $ToolRoot"
}

$hashcatDirectory = Join-Path $resolvedToolRoot 'hashcat-7.1.2'
$hashcatExecutable = Join-Path $hashcatDirectory 'hashcat.exe'
$hashcatData = Join-Path $hashcatDirectory 'hashcat.bin'
$hashcatLicense = Join-Path $hashcatDirectory 'docs\license.txt'
$hashcatModules = Join-Path $hashcatDirectory 'modules'
$hashcatOpenCl = Join-Path $hashcatDirectory 'OpenCL'
$pdf2john = Join-Path $resolvedToolRoot 'pdf2john.py'
foreach ($requiredFile in @($hashcatExecutable, $hashcatData, $hashcatLicense, $pdf2john)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Required GPU tool file is missing: $requiredFile"
    }
}
foreach ($requiredDirectory in @($hashcatDirectory, $hashcatModules, $hashcatOpenCl)) {
    if (-not (Test-Path -LiteralPath $requiredDirectory -PathType Container)) {
        throw "Required hashcat runtime directory is missing: $requiredDirectory"
    }
}

$generatedState = Get-ChildItem -LiteralPath $hashcatDirectory -Recurse -Force | Where-Object {
    (-not $_.PSIsContainer -and $_.Name -match '(?i)\.(log|pid|restore|outfile|potfile)$') -or
    ($_.PSIsContainer -and $_.Name -match '(?i)\.outfiles$')
}
if ($generatedState) {
    throw "Hashcat runtime contains generated state or test output: $($generatedState.FullName -join ', ')"
}

$hashcatVersion = (& $hashcatExecutable --version | Select-Object -First 1).Trim()
if ($LASTEXITCODE -ne 0 -or $hashcatVersion -ne 'v7.1.2') {
    throw "hashcat.exe must report v7.1.2; received: $hashcatVersion"
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}
$resolvedOutputDirectory = (Resolve-Path -LiteralPath $OutputDirectory).Path
if (-not (Test-Path -LiteralPath $resolvedOutputDirectory -PathType Container)) {
    throw "OutputDirectory must be a directory: $OutputDirectory"
}

$stagingDirectory = Join-Path $resolvedOutputDirectory ('.gpu-tools-stage-' + [guid]::NewGuid().ToString('N'))
$archive = Join-Path $resolvedOutputDirectory $assetName
$manifestPath = Join-Path $resolvedOutputDirectory 'gpu-tools-release.json'

try {
    New-Item -ItemType Directory -Path $stagingDirectory | Out-Null
    Copy-Item -LiteralPath $hashcatDirectory -Destination $stagingDirectory -Recurse -Force
    Copy-Item -LiteralPath $pdf2john -Destination (Join-Path $stagingDirectory 'pdf2john.py') -Force

    @(
        'THIRD PARTY NOTICES',
        '',
        'This release asset includes hashcat v7.1.2 from the hashcat project.',
        'Its license is preserved at hashcat-7.1.2/docs/license.txt.',
        '',
        'This release asset includes pdf2john.py from the John the Ripper Jumbo project.',
        'The bundled script identifies its copyright as 2023 Benjamin Dornel.'
    ) | Set-Content -LiteralPath (Join-Path $stagingDirectory 'THIRD_PARTY_NOTICES.txt') -Encoding utf8

    Compress-Archive -Path (Join-Path $stagingDirectory '*') -DestinationPath $archive -Force

    $manifest = [ordered]@{
        tag = $Tag
        asset = $assetName
        url = "https://github.com/$Repository/releases/download/$Tag/$assetName"
        sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $manifest | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding utf8

    $global:LASTEXITCODE = 0
    [pscustomobject]$manifest
}
finally {
    if (Test-Path -LiteralPath $stagingDirectory -PathType Container) {
        Remove-Item -LiteralPath $stagingDirectory -Recurse -Force
    }
}
