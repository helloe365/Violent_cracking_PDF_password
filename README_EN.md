# PDF Password Recovery

[中文](README.md) | **English**

A Windows-first command-line tool for recovering passwords from local PDF files that you own or are authorized to access. It combines a multiprocessing CPU backend with optional hashcat GPU acceleration, staged smart recovery, bounded candidate generation, and resumable sessions.

> Use this software only with local PDF files you are authorized to access. Do not use it against unauthorized files or systems.

## Highlights

- **Efficient CPU recovery:** multiprocessing workers, streaming candidate generation, and bounded queues keep memory usage predictable.
- **GPU acceleration:** hashcat and `pdf2john` provide real-time speed and progress reporting on supported discrete GPUs.
- **Multiple attack modes:** dictionary, rule mutation, hashcat-style masks, custom character sets, and length-bounded brute force.
- **Smart recovery:** common passwords → high-value mutations → dynamic masks → bounded `alnum` brute force.
- **Safe resume:** CPU checkpoints and native hashcat restore files; state files never store a recovered plaintext password.
- **Bundled dictionary:** the 10-million-entry SecLists `Pwdb_top-10000000.txt` wordlist is available offline.
- **No forced time limit:** stop safely with `Ctrl+C` and resume an explicitly interrupted stage later.

## Requirements

- Windows 10 or Windows 11
- Python 3.11 or later
- CPU recovery needs no external tools; the one-command installer configures the tools needed for GPU recovery.
- You remain responsible for installing and updating GPU drivers; preflight only inspects devices visible to the current toolchain.

## Installation

From the repository root, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install.ps1
```

The script creates or reuses `.venv`, installs the project's `dev` and `gpu` dependencies, downloads `pdf-password-recovery-gpu-tools-windows-x64-v7.1.2.zip` from the pinned `gpu-tools-v7.1.2-r1` Release, verifies its SHA256, installs the GPU tools, and runs hashcat device preflight. Rerunning it reuses the existing virtual environment; a matching installation skips download, extraction, and device preflight. To refresh the device status, manually run `Push-Location .\downloads\gpu-tools\hashcat-7.1.2; try { & .\hashcat.exe -I } finally { Pop-Location }`.

If preflight finds no compatible GPU, it warns and preserves CPU fallback; it does not prove that GPU recovery will succeed. An integrity or installation failure exits nonzero. For CPU-only use, skip the GPU tool download and preflight:

```powershell
powershell -ExecutionPolicy Bypass -File .\Install.ps1 -CpuOnly
```

`-CpuOnly` skips only GPU tool installation and device preflight; it does not force later recovery runs to use the CPU. To force CPU execution, pass `--backend cpu` to the recovery command.

After installation, verify the command-line entry point:

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery --help
```

## Quick Start

### Guided smart recovery

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery
```

Running the command without arguments opens a Chinese-language guided workflow. It asks for the PDF path, minimum and maximum password lengths, and the number of CPU fallback workers. The default length range is `4–6`.

The workflow uses the `auto` backend: it prefers GPU/hashcat and falls back to CPU when the GPU toolchain is unavailable before candidate processing begins. If a matching unfinished smart session exists, the wizard asks whether to resume it or start again. Press `Ctrl+C` whenever you need to stop safely.

### Dictionary attack

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf `
  --attack dictionary `
  --wordlist words.txt `
  --backend auto
```

### Mask attack

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf `
  --attack mask `
  --mask "?u?l?l?l?d?d" `
  --backend auto
```

Supported mask tokens:

| Token | Candidates |
| --- | --- |
| `?d` | Digits |
| `?l` | Lowercase letters |
| `?u` | Uppercase letters |
| `?a` | All 95 printable ASCII characters |
| `??` | A literal question mark |

### Length-bounded brute force

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf `
  --attack brute `
  --charset alnum `
  --min-length 4 `
  --max-length 6 `
  --workers 8 `
  --backend auto
```

Built-in character-set presets are `digits`, `lower`, `upper`, `letters`, and `alnum`. You can also pass a custom character set; duplicate characters are removed while preserving their first-seen order.

Non-interactive runs must specify an attack mode and include `--yes`:

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack brute --charset digits `
  --min-length 1 --max-length 8 --backend cpu --yes
```

## Smart Recovery Workflow

The smart orchestrator applies one password-length range across a fixed sequence:

1. Search the bundled 10-million-entry common-password dictionary.
2. Apply high-value mutations: case changes, capitalization, common numeric and symbol suffixes, and basic leet substitutions.
3. Generate masks for digits, lowercase letters, uppercase letters, and a capitalized word body followed by two digits.
4. Finish with bounded `alnum` brute force without silently increasing the requested maximum length.

The Python API exposes the same workflow:

```python
from pathlib import Path

from pdf_password_recovery.smart import SmartOptions, run_smart

result = run_smart(
    SmartOptions(
        pdf_path=Path(r"C:\docs\protected.pdf"),
        min_length=4,
        max_length=6,
        workers=4,
    ),
    notice=print,
    confirm_resume=lambda: True,
)

print(result.status)
if result.password is not None:
    print(result.password)
```

Smart-session identity includes the PDF, bundled dictionary, mutation-rule version, and password-length range. Only an explicit backend interruption resumes the current stage; ordinary runtime failures restart that stage on the next run, while completed stages remain skipped.

## GPU and hashcat Setup

The one-command installer places the verified, pinned GPU tool package in `downloads/gpu-tools/`, but does not change the calling PowerShell session's `PATH`. The tool discovers hashcat and `pdf2john` in this order; this explains existing manual configuration, not a required post-installation setup step:

1. `PDF_PASSWORD_RECOVERY_HASHCAT` and `PDF_PASSWORD_RECOVERY_PDF2JOHN` environment variables.
2. The current `PATH`.
3. `downloads/gpu-tools/` in a development checkout.

Use the following commands only to troubleshoot an installation or GPU run; they are not required for the one-command installation:

```powershell
Push-Location .\downloads\gpu-tools\hashcat-7.1.2; try { & .\hashcat.exe -I } finally { Pop-Location }
.\.venv\Scripts\python.exe .\downloads\gpu-tools\pdf2john.py .\protected.pdf
.\.venv\Scripts\python.exe -c "from pdf_password_recovery.backends.hashcat import discover_toolchain; print(discover_toolchain())"
```

The hashcat backend selects GPU-class devices only. When both a discrete GPU and a unified-memory integrated GPU are detected, it prefers the discrete device. With `--backend auto`, fallback to CPU happens only before candidate processing starts. With `--backend hashcat`, missing tools, unsupported PDF modes, or incompatible GPU configuration are reported as errors instead of silently falling back.

For the first real GPU task, explicitly use `--backend hashcat` so toolchain or compatibility errors are visible:

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack dictionary --wordlist words.txt --backend hashcat
```

## Interrupt and Resume

Advanced CLI runs can use an explicit session name:

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack brute --charset digits `
  --min-length 1 --max-length 8 --backend cpu --session numeric
```

After stopping with `Ctrl+C`, resume with the same PDF, attack configuration, and session name:

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack brute --charset digits `
  --min-length 1 --max-length 8 --backend cpu --session numeric --resume
```

Resume validation checks the PDF, wordlist, and attack configuration fingerprints. Do not replace input files or change search parameters before resuming.

## Bundled Wordlist

The bundled dictionary comes from SecLists commit `066f6c8b8339fb5c10ffeca1d2f845d054081974`:

- Source: `Passwords/Common-Credentials/Pwdb_top-10000000.txt`
- Entries: `10,000,000`
- Size: `94,461,698` bytes
- SHA-256: `18dc49ca32b62455a61e3398f4ab9f93eb700ff142fa0d4b9fd11a727f3b80e4`
- License: SecLists MIT License, included with the package data

The wordlist ships with the package. It is neither downloaded at runtime nor expanded fully into memory.

## CLI Reference

| Option | Description |
| --- | --- |
| `--attack` | `dictionary`, `mask`, or `brute` |
| `--backend` | `auto`, `hashcat`, or `cpu` |
| `--wordlist` | Dictionary file path |
| `--encoding` | Dictionary encoding; defaults to UTF-8 |
| `--mask` | hashcat-style mask |
| `--charset` | Preset or custom character set |
| `--min-length` / `--max-length` | Inclusive brute-force length range |
| `--workers` | CPU worker count; does not control GPU concurrency |
| `--session` | Checkpoint or hashcat session name |
| `--resume` | Resume a named session; requires `--session` |
| `--output` | Atomically write the recovered password to a file |
| `--yes` | Skip confirmation in non-interactive environments |

## Development and Validation

```powershell
python -m pytest --cov=pdf_password_recovery --cov-fail-under=80
python -m ruff check .
python -m ruff format --check .
python -m build
python benchmarks\benchmark_cpu.py --candidates 1000 --batch-size 100
```

External-tool integration tests are skipped by default. Run them only after confirming that hashcat, `pdf2john`, and a compatible GPU are available:

```powershell
$env:RUN_EXTERNAL_TOOL_TESTS = "1"
python -m pytest tests\test_external_tools.py -v
```

## Security and Data Handling

- The tool reads only the local PDF and wordlist paths explicitly provided to it.
- It contains no network scanning, remote target discovery, bulk target search, stealth, or detection-evasion functionality.
- Checkpoints and smart-session state never store a recovered plaintext password.
- Recovered passwords are printed to the terminal by default and written only when `--output` is specified.
- Session state defaults to the operating system's per-user data directory. Override it with `PDF_PASSWORD_RECOVERY_STATE_DIR` when needed.

## License

Project code is released under the MIT License. SecLists licensing and provenance information for the bundled dictionary are stored in `src/pdf_password_recovery/data/`.
