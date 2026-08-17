# GPU Release Installer Design

## Goal

After a Windows user completes the README installation step, a supported GPU
must be usable by the PDF recovery program without separately downloading
hashcat, locating pdf2john, or editing `PATH`.

## User Experience

The primary installation command is:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install.ps1
```

`Install.ps1` creates or reuses `.venv`, upgrades pip, installs
`.[dev,gpu]`, installs the pinned GPU tools, and reports the detected hashcat
devices. Re-running it is safe. A `-CpuOnly` switch skips GPU tool installation
for users who intentionally want a CPU-only environment.

GPU tools are installed even when no compatible GPU is detected. In that case,
installation succeeds with a clear warning and the application's existing
`auto` backend falls back to CPU before processing candidates.

## Release Artifact

GitHub Release tag `gpu-tools-v7.1.2-r1` contains one Windows x64 asset:

```text
pdf-password-recovery-gpu-tools-windows-x64-v7.1.2.zip
├── hashcat-7.1.2/
│   ├── hashcat.exe
│   └── ... official runtime files
├── pdf2john.py
└── THIRD_PARTY_NOTICES.txt
```

The asset is built from the locally verified official hashcat 7.1.2 Windows
distribution and John the Ripper Jumbo `pdf2john.py`. It retains the applicable
license and attribution files. The ZIP is a Release asset, never a tracked Git
object.

## Components

### `Install.ps1`

This is the single public entry point. It validates Windows and Python 3.11+,
creates `.venv` when absent, invokes that environment's Python directly, and
installs `.[dev,gpu]`. It then calls `scripts/Setup-GpuTools.ps1` unless
`-CpuOnly` was supplied. A failure in dependency installation, download,
checksum verification, or extraction stops installation with a nonzero exit.

### `scripts/Setup-GpuTools.ps1`

This focused script owns GPU tool installation. Its production defaults pin the
release URL, asset name, and SHA-256 digest. Test-only parameters allow a local
archive path and destination root so behavior can be verified without network
access or modifying the real installation.

The script:

1. Returns early when the expected hashcat and pdf2john files already exist and
   the installed marker matches the pinned asset digest.
2. Downloads to a unique temporary directory within `downloads/` or consumes a
   supplied local archive.
3. Verifies SHA-256 before extraction.
4. Expands into a staging directory and validates the required layout.
5. Moves the validated directory into `downloads/gpu-tools` without merging an
   unknown or partial installation.
6. Runs `hashcat -I` and reports detected devices. Device-preflight failure is a
   warning, not an installation failure.

Temporary and staging paths are always constrained below the repository's
ignored `downloads/` directory. Existing unknown tool directories are never
deleted or overwritten automatically.

## Application Integration

No backend redesign is needed. Existing `discover_toolchain()` already checks
environment variables, `PATH`, then `downloads/gpu-tools/hashcat-*` and
`pdf2john.py`. The installer produces that existing layout. The `gpu` optional
dependency group supplies pyHanko for `pdf2john.py`.

## Error Handling

- Missing Python or Python below 3.11: stop with an actionable message.
- Network or HTTP failure: stop and identify the failed Release URL.
- SHA-256 mismatch: stop before extraction and print expected versus actual.
- Invalid ZIP layout: stop before installation and list the missing required
  files.
- Existing unrecognized destination: stop and ask the user to move or remove it.
- No usable GPU: retain the installed tools, warn that `auto` will use CPU, and
  exit successfully.

No authentication token, PDF password, or user document path is logged or
stored by the installer.

## Testing and Acceptance

Automated PowerShell tests use a small synthetic ZIP and isolated destination
to prove successful install, checksum rejection, invalid-layout rejection,
idempotent rerun, and preservation of an unknown existing destination. The
Python package receives a configuration check for the `gpu` dependency group.

Release acceptance uses a clean checkout and the public Release URL:

1. Run `Install.ps1` without temporary `PATH` changes.
2. Confirm `discover_toolchain()` resolves both tools under
   `downloads/gpu-tools`.
3. Confirm `hashcat -I` identifies the NVIDIA RTX 3050 Laptop GPU.
4. Recover a known password from a generated encrypted PDF using explicit
   `--backend hashcat`.
5. Run Ruff, formatting, package build, and the available automated tests.

GPU discovery or process startup alone is not accepted as end-to-end recovery.

## Documentation and Publication

README.md and README_EN.md make `Install.ps1` the primary installation path,
retain manual setup as troubleshooting guidance, document `-CpuOnly`, and state
that GPU drivers remain a system prerequisite.

Implementation is committed on `agent/gpu-release-installer` using an explicit
file allowlist. After local checks, the branch is pushed, reviewed through a
pull request, merged to `main`, and tagged. The Release asset is uploaded to the
target repository, then downloaded again for final acceptance testing.
