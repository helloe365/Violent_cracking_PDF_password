[CmdletBinding()]
param(
    [switch]$CpuOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = $PSScriptRoot
$venvPath = Join-Path $repositoryRoot '.venv'
$venvPython = Join-Path $venvPath 'Scripts\python.exe'

$py = Get-Command -Name py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($py) {
    $python = $py.Path
    $pythonArguments = @('-3.11')
}
else {
    $fallback = Get-Command -Name python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $fallback) { throw 'Python 3.11 or newer is required. Install Python and try again.' }
    $python = $fallback.Path
    $pythonArguments = @()
}

$versionText = (& $python @pythonArguments -c "import sys; print('.'.join(map(str, sys.version_info[:3])))").Trim()
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or newer is required. Python version check failed.' }
try { $pythonVersion = [version]$versionText }
catch { throw "Python 3.11 or newer is required. Detected: $versionText" }
if ($pythonVersion -lt [version]'3.11') {
    throw "Python 3.11 or newer is required. Detected: $versionText"
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
