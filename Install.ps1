[CmdletBinding()]
param(
    [switch]$CpuOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = $PSScriptRoot
$venvPath = Join-Path $repositoryRoot '.venv'
$venvPython = Join-Path $venvPath 'Scripts\python.exe'

function Get-PythonVersion {
    param([Parameter(Mandatory)][string]$Path, [string[]]$Arguments = @())

    try {
        $versionOutput = & $Path @Arguments -c "import sys; print('.'.join(map(str, sys.version_info[:3])))" 2>$null
        $exitCode = $LASTEXITCODE
    }
    catch { return $null }
    if ($exitCode -ne 0) { return $null }
    try { return [version]([string]($versionOutput -join [Environment]::NewLine)).Trim() }
    catch { return $null }
}

$python = $null
$pythonArguments = @()
$reuseVenv = Test-Path -LiteralPath $venvPath
if ($reuseVenv) {
    if (-not (Test-Path -LiteralPath $venvPython -PathType Leaf)) {
        throw 'Existing .venv is incomplete: Scripts\python.exe is missing. The existing environment was preserved; repair or remove it manually.'
    }
    $pythonVersion = Get-PythonVersion -Path $venvPython
    if ($null -eq $pythonVersion) {
        throw 'Existing .venv Python is not runnable. The existing environment was preserved; repair or remove it manually.'
    }
    if ($pythonVersion -lt [version]'3.11') {
        throw "Existing .venv uses Python $pythonVersion; Python 3.11+ is required. The existing environment was preserved; remove it manually only if you intend to replace it."
    }
}
else {
    $candidates = @()
    $py = Get-Command -Name py -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($py) {
        $candidates += [pscustomobject]@{ Path = $py.Path; Arguments = @('-3.11') }
        $candidates += [pscustomobject]@{ Path = $py.Path; Arguments = @('-3') }
    }
    $fallback = Get-Command -Name python -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($fallback) { $candidates += [pscustomobject]@{ Path = $fallback.Path; Arguments = @() } }

    foreach ($candidate in $candidates) {
        $pythonVersion = Get-PythonVersion -Path $candidate.Path -Arguments $candidate.Arguments
        if ($null -ne $pythonVersion -and $pythonVersion -ge [version]'3.11') {
            $python = $candidate.Path
            $pythonArguments = @($candidate.Arguments)
            break
        }
    }
    if ($null -eq $python) {
        throw 'No usable Python 3.11+ interpreter was found. Tried py -3.11, py -3, and python; install Python 3.11 or newer and try again.'
    }
}

Push-Location -LiteralPath $repositoryRoot
try {
    if (-not $reuseVenv) {
        & $python @pythonArguments -m venv $venvPath
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create .venv.' }
        $createdVersion = Get-PythonVersion -Path $venvPython
        if ($null -eq $createdVersion -or $createdVersion -lt [version]'3.11') {
            throw 'The new .venv does not contain a usable Python 3.11+ interpreter.'
        }
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

Write-Host ('Next: & "{0}" -m pdf_password_recovery' -f $venvPython)
