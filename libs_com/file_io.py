import os


def read_file_safe(filepath: str):
    # 原有的文件读取逻辑保持不变
    try:
        with open(filepath, 'rb') as f:
            raw_data = f.read()
            encodings = [
                'utf-8',
                'gbk',
                'gb2312',
                'gb18030',
                'big5',
                'iso-8859-1',
                'ascii',
                'latin1',
                'utf-16',
                'utf-32'
            ]
            for encoding in encodings:
                try:
                    return raw_data.decode(encoding), encoding
                except (UnicodeDecodeError, LookupError):
                    continue
    except Exception:
        return raw_data.decode('utf-8', errors='ignore'), 'utf-8-forced'


def string_encoding(data: bytes):
    # 简单的判断文件编码类型
    # 说明：UTF兼容ISO8859-1和ASCII，GB18030兼容GBK，GBK兼容GB2312，GB2312兼容ASCII
    CODES = ['UTF-8', 'GB18030', 'BIG5']
    # UTF-8 BOM前缀字节
    UTF_8_BOM = b'\xef\xbb\xbf'

    # 遍历编码类型
    for code in CODES:
        try:
            data.decode(encoding=code)
            if 'UTF-8' == code and data.startswith(UTF_8_BOM):
                return 'UTF-8-SIG'
            return code
        except UnicodeDecodeError:
            continue
    # 什么编码都没获取到 按UTF-8处理
    return 'UTF-8'


def file_encoding(file_path: str):
    # 获取文件编码类型
    if not os.path.exists(file_path):
        return "utf-8"
    with open(file_path, 'rb') as f:
        return string_encoding(f.read())


def read_by_chunks(file_object, chunk_size=1024 * 1024):
    """生成器函数，用于分块读取文件"""
    while True:
        data = file_object.read(chunk_size)
        if not data:
            break
        yield data


def copy_file(file_path, backup_path=None, cover=True) -> tuple:
    """创建文件备份 return 复制状态,错误原因 """
    import shutil
    try:
        # 检查源文件是否存在
        if not os.path.exists(file_path):
            return False, f'文件 {file_path} 不存在'

        # 如果未提供备份路径，则默认在原文件名后加上.bak扩展名
        backup_path = backup_path or f'{file_path}.bak'
        if os.path.exists(backup_path):
            if not cover:
                return False, None

        # 使用shutil.copy2进行文件复制，保留元数据（如时间戳）
        shutil.copy2(file_path, backup_path)
        return True, None
    except Exception as error:
        return False, str(error)


def write_string(file_path: str, content: str, mode: str = 'w+', encoding: str = 'utf-8') -> tuple:
    try:
        if content:
            with open(file_path, mode, encoding=encoding) as file:
                file.write(content)
        return True, None
    except IOError as e:
        print(f"写入文件时发生错误: {e}")
        return False, e


def read_file_bytes(file_path):
    with open(file_path, 'rb') as f:
        source_code = f.read()
        return source_code

