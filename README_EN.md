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
- No external tools for CPU recovery
- hashcat and John the Ripper Jumbo's `pdf2john` for GPU recovery

## Installation

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e ".[dev]"
```

Verify the command-line entry points:

```powershell
pdf-password-recovery --help
python -m pdf_password_recovery --help
```

## Quick Start

### Guided smart recovery

```powershell
pdf-password-recovery
```

Running the command without arguments opens a Chinese-language guided workflow. It asks for the PDF path, minimum and maximum password lengths, and the number of CPU fallback workers. The default length range is `4–6`.

The workflow uses the `auto` backend: it prefers GPU/hashcat and falls back to CPU when the GPU toolchain is unavailable before candidate processing begins. If a matching unfinished smart session exists, the wizard asks whether to resume it or start again. Press `Ctrl+C` whenever you need to stop safely.

### Dictionary attack

```powershell
pdf-password-recovery protected.pdf `
  --attack dictionary `
  --wordlist words.txt `
  --backend auto
```

### Mask attack

```powershell
pdf-password-recovery protected.pdf `
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
pdf-password-recovery protected.pdf `
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
pdf-password-recovery protected.pdf --attack brute --charset digits `
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

The tool discovers hashcat and `pdf2john` in this order:

1. `PDF_PASSWORD_RECOVERY_HASHCAT` and `PDF_PASSWORD_RECOVERY_PDF2JOHN` environment variables.
2. The current `PATH`.
3. `downloads/gpu-tools/` in a development checkout.

Check the external tools before starting a GPU run:

```powershell
hashcat -I
Get-Command hashcat,pdf2john,pdf2john.py,pdf2john.pl
```

The hashcat backend selects GPU-class devices only. When both a discrete GPU and a unified-memory integrated GPU are detected, it prefers the discrete device. With `--backend auto`, fallback to CPU happens only before candidate processing starts. With `--backend hashcat`, missing tools, unsupported PDF modes, or incompatible GPU configuration are reported as errors instead of silently falling back.

## Interrupt and Resume

Advanced CLI runs can use an explicit session name:

```powershell
pdf-password-recovery protected.pdf --attack brute --charset digits `
  --min-length 1 --max-length 8 --backend cpu --session numeric
```

After stopping with `Ctrl+C`, resume with the same PDF, attack configuration, and session name:

```powershell
pdf-password-recovery protected.pdf --attack brute --charset digits `
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
