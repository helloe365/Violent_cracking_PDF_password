[CmdletBinding()]
param(
    [switch]$CpuOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = $PSScriptRoot
$venvPath = Join-Path $repositoryRoot '.venv'
$venvPython = Join-Path $venvPath 'Scripts\python.exe'

$candidates = @()
$py = Get-Command -Name py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($py) { $candidates += [pscustomobject]@{ Path = $py.Path; Arguments = @('-3.11') } }
$fallback = Get-Command -Name python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($fallback) { $candidates += [pscustomobject]@{ Path = $fallback.Path; Arguments = @() } }

$python = $null
$pythonArguments = @()
foreach ($candidate in $candidates) {
    try {
        $versionOutput = & $candidate.Path @($candidate.Arguments) -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null
        $exitCode = $LASTEXITCODE
    }
    catch { continue }
    if ($exitCode -ne 0) { continue }
    try { $pythonVersion = [version]([string]($versionOutput -join [Environment]::NewLine)).Trim() }
    catch { continue }
    if ($pythonVersion -ge [version]'3.11') {
        $python = $candidate.Path
        $pythonArguments = @($candidate.Arguments)
        break
    }
}
if ($null -eq $python) {
    throw 'No usable Python 3.11+ interpreter was found. Tried py -3.11 and python; install Python 3.11 or newer and try again.'
}

Push-Location -LiteralPath $repositoryRoot
try {
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        & $python @pythonArguments -m venv $venvPath
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create .venv.' }
    }

    & $venvPython -m pip install --upgrade pip
    if ($LASTEXITCODE -ne 0) { throw 'Failed to upgrade pip.' }
    & $venvPython -m pip install -e '.[dev,gpu]'
    if ($LASTEXITCODE -ne 0) { throw 'Failed to install project dependencies.' }

    if (-not $CpuOnly) {
        $setup = Join-Path $repositoryRoot 'scripts\Setup-GpuTools.ps1'
        $manifest = Join-Path $repositoryRoot 'scripts\gpu-tools-release.json'
        & $setup -ManifestPath $manifest
        if ($LASTEXITCODE -ne 0) { throw 'Failed to install GPU tools.' }
    }
}
finally {
    Pop-Location
}

Write-Host 'Next: .\.venv\Scripts\python.exe -m pdf_password_recovery'
