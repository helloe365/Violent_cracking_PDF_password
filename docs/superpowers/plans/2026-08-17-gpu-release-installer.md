# GPU Release Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the README installation step leave supported Windows computers ready to use the existing hashcat GPU backend without manual tool downloads or `PATH` configuration.

**Architecture:** A reproducible packaging script creates one pinned Windows x64 ZIP and a tracked manifest containing its GitHub Release URL and SHA-256. A focused setup script verifies and atomically installs that asset into the layout already consumed by `discover_toolchain()`. Root `Install.ps1` orchestrates the Python environment and GPU setup while preserving an explicit CPU-only path.

**Tech Stack:** PowerShell 7/Windows PowerShell 5.1-compatible scripts, Python 3.11+, setuptools optional dependencies, GitHub Releases, hashcat 7.1.2, John the Ripper Jumbo `pdf2john.py`.

## File Structure

- `Install.ps1`: the only user-facing installation entry point.
- `scripts/Setup-GpuTools.ps1`: verified download, extraction, idempotency, and GPU preflight.
- `scripts/New-GpuToolsReleaseAsset.ps1`: maintainer-only reproducible Release packaging.
- `scripts/gpu-tools-release.json`: pinned asset identity, URL, and SHA-256 trusted by setup.
- `README.md` and `README_EN.md`: primary installation and troubleshooting instructions.
- `pyproject.toml`: Python GPU dependency extra.
- `tests/test_gpu_*.ps1`: local TDD harnesses excluded from publication per repository policy.

## Global Constraints

- Target Windows 10/11 and Python 3.11+.
- Release tag is `gpu-tools-v7.1.2-r1`.
- Release asset is `pdf-password-recovery-gpu-tools-windows-x64-v7.1.2.zip`.
- Never commit the ZIP or extracted hashcat runtime to Git.
- Preserve third-party license and attribution files in the Release asset.
- Never merge, delete, or overwrite an unknown `downloads/gpu-tools` directory.
- GPU preflight failure warns and preserves CPU fallback; integrity or installation failure exits nonzero.
- Use the repository `.venv\Scripts\python.exe` for package installation and verification.
- Stage and publish only the explicitly listed implementation and documentation files.

---

### Task 1: Reproducible GPU Release Asset Builder

**Files:**
- Create: `scripts/New-GpuToolsReleaseAsset.ps1`
- Create locally, do not publish: `tests/test_gpu_release_asset.ps1`
- Generate during release: `scripts/gpu-tools-release.json`
- Read: `downloads/gpu-tools/hashcat-7.1.2/`
- Read: `downloads/gpu-tools/pdf2john.py`

**Interfaces:**
- Consumes: `-ToolRoot <directory>`, `-OutputDirectory <directory>`, optional `-Repository helloe365/Violent_cracking_PDF_password`, and optional `-Tag gpu-tools-v7.1.2-r1`.
- Produces: the fixed-name ZIP plus JSON fields `tag`, `asset`, `url`, and lowercase `sha256`.

- [ ] **Step 1: Write the failing asset-builder test**

Create a small fake `hashcat-7.1.2/hashcat.exe`, `docs/license.txt`, and
`pdf2john.py`; invoke the missing builder and assert that the ZIP contains the
three runtime paths plus `THIRD_PARTY_NOTICES.txt`, and that the JSON digest
matches `Get-FileHash`.

```powershell
$result = & $Builder -ToolRoot $fixture -OutputDirectory $output
if ($LASTEXITCODE -ne 0) { throw "builder failed" }
$manifest = Get-Content "$output\gpu-tools-release.json" -Raw | ConvertFrom-Json
$actual = (Get-FileHash "$output\$($manifest.asset)" -Algorithm SHA256).Hash.ToLowerInvariant()
if ($manifest.sha256 -ne $actual) { throw "manifest digest mismatch" }
```

- [ ] **Step 2: Run the test and verify RED**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_gpu_release_asset.ps1
```

Expected: FAIL because `scripts/New-GpuToolsReleaseAsset.ps1` does not exist.

- [ ] **Step 3: Implement the minimal builder**

Implement strict parameter validation, a unique staging directory below the
chosen output directory, `Compress-Archive`, `Get-FileHash`, and manifest
generation. Copy only the verified hashcat directory, `pdf2john.py`, hashcat's
license, and a generated notice naming the upstream projects and versions.
Use `try/finally` so only the builder-owned staging directory is removed.

```powershell
$manifest = [ordered]@{
    tag = $Tag
    asset = $assetName
    url = "https://github.com/$Repository/releases/download/$Tag/$assetName"
    sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
}
```

- [ ] **Step 4: Run the asset-builder test and verify GREEN**

Run the command from Step 2. Expected: PASS with a digest match and all required ZIP entries.

- [ ] **Step 5: Build the real asset and inspect it**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\New-GpuToolsReleaseAsset.ps1 `
  -ToolRoot downloads\gpu-tools -OutputDirectory downloads\release
```

Expected: one ZIP below `downloads/release/` and one generated manifest. Expand
the ZIP into an isolated inspection directory and verify `hashcat.exe
--version` reports `v7.1.2`.

- [ ] **Step 6: Install the generated manifest into source**

Copy the generated JSON content to `scripts/gpu-tools-release.json` with
`apply_patch`, then run a Python JSON parse and assert a 64-character lowercase
SHA-256.

- [ ] **Step 7: Commit the builder and manifest**

```powershell
git add -- scripts/New-GpuToolsReleaseAsset.ps1 scripts/gpu-tools-release.json
git commit -m "build: package pinned GPU tools"
```

Do not stage `downloads/` or `tests/`.

---

### Task 2: Verified and Idempotent GPU Tool Installer

**Files:**
- Create: `scripts/Setup-GpuTools.ps1`
- Create locally, do not publish: `tests/test_gpu_tools_setup.ps1`
- Read: `scripts/gpu-tools-release.json`

**Interfaces:**
- Consumes: `-ManifestPath`, optional `-ArchivePath`, optional `-DestinationRoot`, and `-SkipDeviceCheck` for isolated tests.
- Produces: `<DestinationRoot>/hashcat-7.1.2/hashcat.exe`, `<DestinationRoot>/pdf2john.py`, and `<DestinationRoot>/.installed.json`.
- Exit 0: installed/idempotent or installed with no compatible GPU. Exit nonzero: integrity, layout, download, or destination-safety failure.

- [ ] **Step 1: Write failing setup tests**

Use the Task 1 fixture builder to produce a local archive and manifest. Test
these independent cases: successful install, checksum mismatch, missing
`pdf2john.py`, matching marker skips work, and unknown pre-existing destination
is preserved with a nonzero exit.

```powershell
& $Setup -ManifestPath $manifest -ArchivePath $archive `
  -DestinationRoot $destination -SkipDeviceCheck
if ($LASTEXITCODE -ne 0) { throw "setup failed" }
if (-not (Test-Path "$destination\hashcat-7.1.2\hashcat.exe")) { throw "hashcat missing" }
```

- [ ] **Step 2: Run setup tests and verify RED**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_gpu_tools_setup.ps1
```

Expected: FAIL because `scripts/Setup-GpuTools.ps1` does not exist.

- [ ] **Step 3: Implement download and integrity verification**

Parse the manifest with `ConvertFrom-Json`, require HTTPS for production URL,
download with `Invoke-WebRequest -UseBasicParsing`, hash before extraction, and
print expected/actual values on mismatch without printing credentials or
environment variables.

- [ ] **Step 4: Implement staged extraction and destination safety**

Create unique download/staging paths strictly below `downloads/`, reject
reparse points, validate exact required files, and use a final `Move-Item` only
when the destination is absent. If the destination exists, accept it only when
`.installed.json` matches the manifest and required files exist.

- [ ] **Step 5: Implement device preflight**

Run the installed executable from its own directory with `-I`. Treat a nonzero
exit or inventory without `Type...GPU` as a warning and exit zero. Do not
interpret AMD HIP, ADL, or NVML warnings as installation failure when a GPU is
listed.

- [ ] **Step 6: Run setup tests and verify GREEN**

Run the command from Step 2. Expected: all five cases pass and the unknown
destination fixture remains byte-for-byte unchanged.

- [ ] **Step 7: Commit the setup script**

```powershell
git add -- scripts/Setup-GpuTools.ps1
git commit -m "feat: install verified GPU tools"
```

Do not stage local tests.

---

### Task 3: One-Command Project Installer

**Files:**
- Create: `Install.ps1`
- Create locally, do not publish: `tests/test_install_entrypoint.ps1`
- Modify: `pyproject.toml`
- Read: `scripts/Setup-GpuTools.ps1`

**Interfaces:**
- Consumes: optional `-CpuOnly`; otherwise no required arguments.
- Produces: `.venv`, editable install with `dev,gpu` extras, and GPU tools unless `-CpuOnly`.

- [ ] **Step 1: Write the failing entrypoint test**

Run `Install.ps1` in a copied minimal fixture with command shims recording
arguments. Assert Python 3.11 validation, `.venv\Scripts\python.exe -m pip
install -e .[dev,gpu]`, setup invocation by default, and no setup invocation
with `-CpuOnly`.

- [ ] **Step 2: Run the entrypoint test and verify RED**

Run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_install_entrypoint.ps1
```

Expected: FAIL because `Install.ps1` does not exist.

- [ ] **Step 3: Implement `Install.ps1`**

Resolve paths from `$PSScriptRoot`, locate `py -3.11` first and `python` second,
validate `sys.version_info >= (3, 11)`, create `.venv` only if its Python is
missing, upgrade pip, and install `-e ".[dev,gpu]"`. Invoke the setup script
unless `-CpuOnly`, then print the exact next command
`.\.venv\Scripts\python.exe -m pdf_password_recovery`.

- [ ] **Step 4: Retain the optional GPU dependency**

Ensure `pyproject.toml` contains:

```toml
gpu = [
  "pyHanko>=0.36,<0.37",
]
```

- [ ] **Step 5: Run the entrypoint test and verify GREEN**

Run the command from Step 2. Expected: all default and `-CpuOnly` assertions pass.

- [ ] **Step 6: Commit the installation entrypoint and dependency**

```powershell
git add -- Install.ps1 pyproject.toml
git commit -m "feat: add one-command Windows install"
```

---

### Task 4: Installation Documentation

**Files:**
- Modify: `README.md`
- Modify: `README_EN.md`

**Interfaces:**
- Consumes: public commands from Tasks 2 and 3.
- Produces: one primary installation flow with manual troubleshooting retained.

- [ ] **Step 1: Write a failing documentation assertion**

Run a PowerShell assertion requiring both READMEs to contain `Install.ps1`,
`-CpuOnly`, the pinned Release asset name, and explicit `--backend hashcat`
troubleshooting guidance. Expected: FAIL because the current READMEs do not
describe the one-command installer.

- [ ] **Step 2: Rewrite the installation sections**

Make this the primary command in both languages:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install.ps1
```

Explain that it creates `.venv`, installs Python dependencies, downloads a
checksum-verified pinned GPU tool package, and performs preflight. Document
`-CpuOnly`, GPU-driver responsibility, rerun behavior, and the manual discovery
commands as troubleshooting rather than required installation.

- [ ] **Step 3: Run the documentation assertion and verify GREEN**

Expected: both READMEs satisfy all required phrases and commands.

- [ ] **Step 4: Commit the READMEs**

```powershell
git add -- README.md README_EN.md
git commit -m "docs: make GPU setup automatic"
```

---

### Task 5: Local Verification, GitHub Publication, and Clean-Download Acceptance

**Files:**
- Verify: `Install.ps1`
- Verify: `scripts/New-GpuToolsReleaseAsset.ps1`
- Verify: `scripts/Setup-GpuTools.ps1`
- Verify: `scripts/gpu-tools-release.json`
- Verify: `README.md`
- Verify: `README_EN.md`
- Verify: `pyproject.toml`
- Release asset: `downloads/release/pdf-password-recovery-gpu-tools-windows-x64-v7.1.2.zip`

**Interfaces:**
- Consumes: all prior task outputs and authenticated GitHub CLI.
- Produces: merged `main`, tag `gpu-tools-v7.1.2-r1`, public Release asset, and clean-checkout GPU evidence.

- [ ] **Step 1: Run all local automated checks**

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_gpu_release_asset.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_gpu_tools_setup.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File tests\test_install_entrypoint.ps1
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m build
git diff --check
```

Expected: every command exits 0. The release checkout has no tracked Python
test suite, so do not claim a pytest count.

- [ ] **Step 2: Audit the intended publication scope**

```powershell
git status -sb
git diff main...HEAD --name-status
git ls-files downloads tests
```

Expected: only the design/plan, three production scripts, one JSON manifest,
two READMEs, and `pyproject.toml` are tracked; `downloads/` and local `tests/`
are absent.

- [ ] **Step 3: Configure and push the feature branch**

```powershell
git remote add origin https://github.com/helloe365/Violent_cracking_PDF_password.git
git push -u origin agent/gpu-release-installer
```

If `origin` already exists, verify its normalized URL instead of replacing it.

- [ ] **Step 4: Open and merge the pull request**

Create a PR targeting `main` describing automatic GPU installation, integrity
verification, third-party notices, and all validation. Inspect the remote diff,
mark ready, and merge only after required checks are green.

- [ ] **Step 5: Create the GitHub Release and upload the asset**

Create tag `gpu-tools-v7.1.2-r1` on the merged `main` commit. Upload the fixed
ZIP with release notes identifying hashcat 7.1.2, Windows x64, bundled
`pdf2john.py`, the SHA-256 from `scripts/gpu-tools-release.json`, and license
attribution.

- [ ] **Step 6: Verify the public Release metadata**

Use `gh release view` and `gh release download` to confirm the tag, asset name,
reported size, and downloaded SHA-256 match the committed manifest.

- [ ] **Step 7: Run clean-checkout installation acceptance**

Clone `main` into a unique repository-local or system temporary directory, run
`Install.ps1` without temporary `PATH` changes, and assert
`discover_toolchain()` resolves both installed tools beneath that checkout.

- [ ] **Step 8: Run real GPU end-to-end acceptance**

Generate an encrypted one-page PDF with a known synthetic password and a
two-entry matching dictionary. Invoke the installed CLI with explicit
`--backend hashcat`, require a zero exit and matching output file, and report
the actual backend. Tool discovery or `hashcat -I` alone is insufficient.

- [ ] **Step 9: Report exact final state**

Report branch, commits, merged PR URL, Release URL, asset SHA-256, local check
results, clean-download result, and real GPU recovery result. Keep local test
fixtures and plaintext synthetic passwords out of Git.
