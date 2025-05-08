# PDF密码暴力破解工具 | PDF Password Brute Force Cracker

## 简介 | Introduction

这是一个用Python编写的PDF密码暴力破解工具，能够通过尝试不同组合的密码来破解受密码保护的PDF文件。该工具利用多进程技术加速破解过程，并按照不同的密码类型和长度有序地尝试可能的组合。

This is a PDF password brute force cracking tool written in Python that can crack password-protected PDF files by trying different password combinations. The tool utilizes multiprocessing technology to accelerate the cracking process and systematically attempts possible combinations according to different password types and lengths.

## 功能特点 | Features

- **多进程支持**：利用多核CPU加速破解过程
- **智能尝试顺序**：按照常见密码类型优先级尝试（纯数字、纯字母、混合字符）
- **进度显示**：实时显示破解进度和预估时间
- **灵活配置**：可自定义密码长度范围和使用的进程数
- **用户友好**：简单的命令行交互界面

---

- **Multiprocessing Support**: Utilizes multi-core CPUs to accelerate the cracking process
- **Intelligent Attempt Order**: Tries passwords based on common password type priorities (digits only, letters only, mixed characters)
- **Progress Display**: Shows real-time cracking progress and estimated time
- **Flexible Configuration**: Customizable password length range and number of processes
- **User-Friendly**: Simple command-line interface

## 安装要求 | Requirements

- Python 3.6+
- PyPDF2
- tqdm

安装依赖：

Install dependencies:

```bash
pip install PyPDF2 tqdm
```

## 使用方法 | Usage

1. 克隆或下载此仓库
2. 运行主程序文件：

---

1. Clone or download this repository
2. Run the main program file:

```bash
python Violent_cracking_PDF_password.py
```

3. 按照提示输入PDF文件路径和参数
4. 等待程序尝试破解密码

---

3. Follow the prompts to enter the PDF file path and parameters
4. Wait for the program to attempt to crack the password

## 参数说明 | Parameters

- **PDF文件路径**：需要破解的PDF文件的完整路径
- **最小密码长度**：尝试的最小密码长度（默认为4）
- **最大密码长度**：尝试的最大密码长度（默认为6）
- **进程数**：用于破解的进程数量（默认为CPU核心数）

---

- **PDF File Path**: Complete path to the PDF file that needs to be cracked
- **Minimum Password Length**: Minimum password length to try (default is 4)
- **Maximum Password Length**: Maximum password length to try (default is 6)
- **Number of Processes**: Number of processes used for cracking (default is the number of CPU cores)

## 示例 | Example

```
请输入PDF文件的完整路径: C:\Users\Documents\protected.pdf
请输入最小密码长度,默认为 [4]: 3
请输入最大密码长度,默认为 [6]: 5
请输入使用的进程数 (1-8) [8]: 4

开始破解密码...
使用 4 个进程进行破解

尝试长度为 3 的密码...

尝试纯数字密码...
可能的组合数: 1000
尝试纯数字: 100%|██████████| 1/1 [00:00<00:00, 10.42it/s]

尝试纯字母(小写)密码...
可能的组合数: 17576
尝试纯字母(小写): 100%|██████████| 2/2 [00:01<00:00,  1.95it/s]

成功! 密码是: abc
密码长度: 3
密码类型: 纯字母(小写)
耗时: 1.03秒

破解成功! PDF密码是: abc
```

## 注意事项 | Notes

- 密码破解时间与密码复杂度和长度成指数关系增长
- 对于长度超过6位的复杂密码，破解可能需要很长时间
- 本工具仅用于合法用途，如找回自己的PDF文件密码
- 请勿用于非法目的或未经授权的文件破解

---

- Password cracking time increases exponentially with password complexity and length
- For complex passwords longer than 6 characters, cracking may take a very long time
- This tool is intended for legitimate purposes only, such as recovering your own PDF file passwords
- Do not use for illegal purposes or unauthorized file cracking

## 许可证 | License

本项目采用 MIT 许可证 - 详情请查看 LICENSE 文件

This project is licensed under the MIT License - see the LICENSE file for details
