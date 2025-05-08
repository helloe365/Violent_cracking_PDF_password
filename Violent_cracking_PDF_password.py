import PyPDF2
import string
import itertools
import time
import multiprocessing
from tqdm import tqdm
import os


def try_password_batch(args):
    """在单独进程中尝试一批密码"""
    pdf_path, passwords = args

    # 每个进程打开自己的PDF文件副本
    pdf_file = open(pdf_path, 'rb')
    pdf_reader = PyPDF2.PdfReader(pdf_file)

    for password in passwords:
        if pdf_reader.decrypt(password) > 0:
            pdf_file.close()
            return password

    pdf_file.close()
    return None


def chunk_generator(generator, chunk_size):
    """将生成器分成多个块"""
    chunk = []
    for item in generator:
        chunk.append(item)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:  # 不要忘记最后一个不完整的块
        yield chunk


def crack_pdf_password(pdf_path, min_length=4, max_length=6, processes=None):
    """使用多进程破解PDF密码"""
    if processes is None:
        # 默认使用CPU核心数
        processes = multiprocessing.cpu_count()

    print(f"使用 {processes} 个进程进行破解")

    # 检查PDF是否加密
    try:
        pdf_file = open(pdf_path, 'rb')
        pdf_reader = PyPDF2.PdfReader(pdf_file)
        if not pdf_reader.is_encrypted:
            print("PDF文件未加密!")
            pdf_file.close()
            return None
        pdf_file.close()
    except FileNotFoundError:
        print(f"错误: 找不到文件 '{pdf_path}'")
        return None
    except Exception as e:
        print(f"打开PDF文件时出错: {e}")
        return None

    # 定义字符集
    digits = string.digits  # 0-9
    letters = string.ascii_letters  # a-z, A-Z

    # 按优先级尝试不同类型的密码
    password_types = [
        ("纯数字", digits),
        ("纯字母(小写)", string.ascii_lowercase),
        ("纯字母(大写)", string.ascii_uppercase),
        ("纯字母", letters),
        ("数字+字母混合", digits + letters)
    ]

    # 创建进程池
    pool = multiprocessing.Pool(processes=processes)

    # 尝试不同长度的密码
    for length in range(min_length, max_length + 1):
        print(f"\n尝试长度为 {length} 的密码...")

        for type_name, charset in password_types:
            print(f"\n尝试{type_name}密码...")

            # 计算总组合数
            total = len(charset) ** length
            print(f"可能的组合数: {total}")

            # 创建密码生成器
            password_generator = (''.join(p) for p in itertools.product(charset, repeat=length))

            # 将密码分成多个批次
            batch_size = 10000  # 每批处理的密码数量
            batches = chunk_generator(password_generator, batch_size)

            # 创建任务参数
            tasks = [(pdf_path, batch) for batch in batches]

            # 使用进度条跟踪总体进度
            start_time = time.time()
            total_batches = (total + batch_size - 1) // batch_size  # 向上取整

            with tqdm(total=total_batches, desc=f"尝试{type_name}") as pbar:
                # 使用imap处理任务，这样可以在处理过程中更新进度条
                for i, result in enumerate(pool.imap_unordered(try_password_batch, tasks)):
                    pbar.update(1)

                    if result:  # 找到密码
                        elapsed = time.time() - start_time
                        print(f"\n成功! 密码是: {result}")
                        print(f"密码长度: {length}")
                        print(f"密码类型: {type_name}")
                        print(f"耗时: {elapsed:.2f}秒")
                        pool.terminate()  # 立即终止所有进程
                        return result

    pool.close()
    pool.join()
    print("\n未找到密码")
    return None


def get_valid_int(prompt, min_val, max_val, default=None):
    """获取有效的整数输入"""
    default_str = f" [{default}]" if default is not None else ""
    while True:
        try:
            value = input(f"{prompt}{default_str}: ")
            if value == "" and default is not None:
                return default
            value = int(value)
            if min_val <= value <= max_val:
                return value
            print(f"请输入 {min_val} 到 {max_val} 之间的数字")
        except ValueError:
            print("请输入有效的数字")


def main():
    # 获取PDF文件路径
    while True:
        pdf_path = input("请输入PDF文件的完整路径: ").strip()
        if pdf_path.startswith('"') and pdf_path.endswith('"'):
            pdf_path = pdf_path[1:-1]  # 移除引号

        if os.path.exists(pdf_path):
            break
        print(f"错误: 找不到文件 '{pdf_path}'，请重新输入")

    # 获取密码长度范围
    min_length = get_valid_int("请输入最小密码长度,默认为", 1, 10, 4)
    max_length = get_valid_int("请输入最大密码长度,默认为", min_length, 10, 6)

    # 获取进程数
    max_processes = multiprocessing.cpu_count()
    processes = get_valid_int(f"请输入使用的进程数 (1-{max_processes})", 1, max_processes, max_processes)

    # 开始破解
    print("\n开始破解密码...")
    result = crack_pdf_password(pdf_path, min_length, max_length, processes)

    if result:
        print(f"\n破解成功! PDF密码是: {result}")
    else:
        print("\n未能破解密码。可能需要尝试更长的密码长度或不同的字符集。")


if __name__ == "__main__":
    main()