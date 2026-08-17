# PDF Password Recovery

**中文** | [English](README.md)

面向自有或已获授权文件的本地 PDF 密码恢复工具。项目提供 Windows 多进程 CPU 后端、可选的 hashcat GPU 后端、字典/规则/掩码/有限穷举策略，以及可恢复的检查点。

> 仅可处理你有权访问的本地 PDF。请勿用于未经授权的文件或系统。

## 功能概览

- CPU：多进程、流式候选、有限队列，不把搜索空间整体载入内存。
- GPU：通过 hashcat 和 pdf2john 使用独立显卡，并实时显示速度与进度。
- 攻击方式：字典、hashcat 风格掩码、自定义字符集和限定长度穷举。
- 智能编排：常用字典 → 高频规则变形 → 动态掩码 → `alnum` 有限穷举。
- 恢复：CPU checkpoint 与 hashcat restore；状态文件不保存找到的明文密码。
- 内置字典：SecLists `Pwdb_top-10000000.txt`，共 1000 万行。
- 无运行时间上限；需要停止时按 `Ctrl+C`，之后可恢复明确中断的阶段。

## 环境要求

- Windows 10/11
- Python 3.11+
- CPU 模式无需外部程序；一键安装会为 GPU 模式配置所需工具。
- GPU 驱动仍由你负责安装和更新；预检只检查当前工具链可见的设备。

## 安装

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\Install.ps1
```

该脚本会创建或复用 `.venv`，安装项目的 `dev` 和 `gpu` 依赖，下载固定 Release `gpu-tools-v7.1.2-r1` 中的 `pdf-password-recovery-gpu-tools-windows-x64-v7.1.2.zip`，校验 SHA256 后安装 GPU 工具，并运行 hashcat 设备预检。重复运行会复用现有虚拟环境；匹配安装会跳过下载、解压和设备预检。需要刷新设备状态时，手工运行 `Push-Location .\downloads\gpu-tools\hashcat-7.1.2; try { & .\hashcat.exe -I } finally { Pop-Location }`。

如果下载速度较慢或经常失败，尤其是在中国大陆，建议在运行安装脚本前配置可用的 HTTP/HTTPS 代理。请将端口替换为代理客户端实际使用的端口：

```powershell
$env:HTTP_PROXY = "http://127.0.0.1:7897"
$env:HTTPS_PROXY = "http://127.0.0.1:7897"
powershell -ExecutionPolicy Bypass -File .\Install.ps1
```

代理可能改善 PyPI 依赖和 GitHub GPU 工具 Release 的访问速度，但实际速度取决于代理节点和网络状况。

预检未发现兼容 GPU 时会发出警告，CPU 回退仍可用；这不表示 GPU 恢复已经验证成功。下载完整性或安装失败会以非零状态退出。若只需要 CPU，跳过 GPU 工具下载和预检：

```powershell
powershell -ExecutionPolicy Bypass -File .\Install.ps1 -CpuOnly
```

`-CpuOnly` 只跳过 GPU 工具安装与设备预检，不会强制之后的恢复任务使用 CPU。若要强制 CPU 运行，请在恢复命令中传入 `--backend cpu`。

安装后查看帮助：

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery --help
```

# 快速开始

# 零参数向导 -- 直接使用这个就可以

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery
```

零参数入口会进入中文智能向导，依次询问 PDF 路径、最小长度、最大长度和 CPU 回退进程数。确认后按“常用字典 → 规则变形 → 动态掩码 → 有限穷举”执行，默认长度为 `4–6`。后端为 `auto`：优先使用 GPU/hashcat，不可用时回退 CPU。

检测到匹配的未完成智能任务时，向导会询问继续恢复还是重新开始。流程没有运行时间上限，需要停止时按 `Ctrl+C`。

### 字典攻击

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf `
  --attack dictionary `
  --wordlist words.txt `
  --backend auto
```

### 掩码攻击

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf `
  --attack mask `
  --mask "?u?l?l?l?d?d" `
  --backend auto
```

掩码标记：

| 标记   | 候选字符               |
| ------ | ---------------------- |
| `?d` | 数字                   |
| `?l` | 小写字母               |
| `?u` | 大写字母               |
| `?a` | 95 个可打印 ASCII 字符 |
| `??` | 字面问号               |

### 有限穷举

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf `
  --attack brute `
  --charset alnum `
  --min-length 4 `
  --max-length 6 `
  --workers 8 `
  --backend auto
```

字符集预设包括 `digits`、`lower`、`upper`、`letters` 和 `alnum`。也可以直接传入自定义字符集；重复字符会按首次出现顺序去重。

非交互运行必须明确指定攻击方式并添加 `--yes`：

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack brute --charset digits `
  --min-length 1 --max-length 8 --backend cpu --yes
```

## 智能流程与 API

智能编排器按以下顺序运行，并对所有阶段应用同一长度范围：

1. 内置 1000 万常用密码字典。
2. 固定高频规则变形，包括大小写、首字母大写、常用数字/符号追加及基础 leet 替换。
3. 按长度生成纯数字、纯小写、纯大写，以及“首字母大写 + 小写主体 + 两位数字”掩码。
4. 最后执行限定长度的 `alnum` 穷举，不自动扩大最大长度。

除零参数向导外，也可通过 Python API 调用：

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

智能状态会校验 PDF、内置字典、规则版本和长度范围。只有后端明确返回中断状态时才恢复当前阶段；普通运行异常会在下次从该阶段重新开始，已经耗尽的阶段仍会跳过。

## GPU/hashcat 配置

一键安装会将已校验的固定 GPU 工具包安装到 `downloads/gpu-tools/`，但不会修改调用者 PowerShell 的 `PATH`。工具仍按以下顺序寻找 hashcat 与 pdf2john；这是已有手工配置的发现顺序说明，不是安装后必须执行的配置：

1. 环境变量 `PDF_PASSWORD_RECOVERY_HASHCAT`、`PDF_PASSWORD_RECOVERY_PDF2JOHN`。
2. 当前 `PATH`。
3. 开发仓库的 `downloads/gpu-tools/`。

以下命令仅用于安装或 GPU 运行异常时的故障排查，并非一键安装的必需步骤：

```powershell
Push-Location .\downloads\gpu-tools\hashcat-7.1.2; try { & .\hashcat.exe -I } finally { Pop-Location }
.\.venv\Scripts\python.exe .\downloads\gpu-tools\pdf2john.py .\protected.pdf
.\.venv\Scripts\python.exe -c "from pdf_password_recovery.backends.hashcat import discover_toolchain; print(discover_toolchain())"
```

hashcat 固定使用 GPU 类型设备。若同时检测到独显和共享内存核显，会优先选择非共享显存设备。`--backend auto` 只会在候选开始前回退 CPU；显式指定 `--backend hashcat` 时，GPU 工具或兼容模式不可用会直接报错。

首次执行真实 GPU 任务时，建议显式指定 `--backend hashcat`，让工具或兼容性问题直接显示：

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack dictionary --wordlist words.txt --backend hashcat
```

## 中断与恢复

高级 CLI 使用安全的会话名保存状态：

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack brute --charset digits `
  --min-length 1 --max-length 8 --backend cpu --session numeric
```

按 `Ctrl+C` 后，使用完全相同的 PDF、攻击参数和会话名恢复：

```powershell
.\.venv\Scripts\python.exe -m pdf_password_recovery protected.pdf --attack brute --charset digits `
  --min-length 1 --max-length 8 --backend cpu --session numeric --resume
```

恢复过程会校验 PDF、字典和攻击配置指纹。不要在恢复前替换输入文件或改变搜索参数。

## 内置字典来源

内置字典来自 SecLists，并固定到提交 `066f6c8b8339fb5c10ffeca1d2f845d054081974`：

- 文件：`Passwords/Common-Credentials/Pwdb_top-10000000.txt`
- 行数：`10,000,000`
- 大小：`94,461,698` 字节
- SHA-256：`18dc49ca32b62455a61e3398f4ab9f93eb700ff142fa0d4b9fd11a727f3b80e4`
- 许可证：SecLists MIT License，随 package data 一同提供

字典随安装包提供，运行时不会联网下载，也不会在内存中整体展开。

## 常用参数

| 参数                                | 说明                                    |
| ----------------------------------- | --------------------------------------- |
| `--attack`                        | `dictionary`、`mask` 或 `brute`   |
| `--backend`                       | `auto`、`hashcat` 或 `cpu`        |
| `--wordlist`                      | 字典文件路径                            |
| `--encoding`                      | 字典编码，默认 UTF-8                    |
| `--mask`                          | hashcat 风格掩码                        |
| `--charset`                       | 预设或自定义字符集                      |
| `--min-length` / `--max-length` | 穷举长度闭区间                          |
| `--workers`                       | CPU 工作进程数；不控制 GPU 并发         |
| `--session`                       | 检查点或 hashcat 会话名                 |
| `--resume`                        | 恢复指定会话，必须同时提供`--session` |
| `--output`                        | 成功后原子写入密码文件                  |
| `--yes`                           | 非交互环境跳过确认                      |

## 开发与验证

```powershell
python -m pytest --cov=pdf_password_recovery --cov-fail-under=80
python -m ruff check .
python -m ruff format --check .
python -m build
python benchmarks\benchmark_cpu.py --candidates 1000 --batch-size 100
```

外部工具集成测试默认跳过。确认本机 hashcat、pdf2john 和 GPU 环境可用后执行：

```powershell
$env:RUN_EXTERNAL_TOOL_TESTS = "1"
python -m pytest tests\test_external_tools.py -v
```

## 安全与数据

- 只读取命令中明确提供的本地 PDF 和字典文件。
- 不包含网络扫描、远程目标发现、批量目标搜索、隐蔽或规避检测功能。
- 检查点与智能状态不保存找到的明文密码。
- 成功密码默认仅输出到终端；只有指定 `--output` 时才写入文件。
- 会话和状态默认保存在系统用户数据目录，可用 `PDF_PASSWORD_RECOVERY_STATE_DIR` 指定其他位置。

## License

项目代码采用 MIT License。内置 SecLists 字典的许可证与来源信息位于 `src/pdf_password_recovery/data/`。
