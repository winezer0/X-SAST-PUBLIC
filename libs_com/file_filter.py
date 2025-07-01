import os
from typing import List
from libs_com.file_io import read_by_chunks, file_encoding


def get_allowed_files(directory:str, allowed_ext:list, exclude_keys:list):
    """获取指定目录下的PHP文件"""

    php_files = []

    # 如果指定了单个文件
    if os.path.isfile(directory):
        return [directory]

    if not allowed_ext:
        raise ValueError("allowed_ext list is empty !!!")

    if isinstance(allowed_ext, str):
        allowed_ext = [allowed_ext]

    # 递归扫描目录
    for root, _, files in os.walk(directory):
        # 跳过特定目录
        if any(exclude_dir in root.replace('\\', '/') for exclude_dir in exclude_keys):
            continue

        for file in files:
            for suffix in allowed_ext:
                if file.endswith(suffix):
                    php_files.append(os.path.join(root, file))
    return php_files


def get_files_with_filter(directory: str, exclude_suffixes: List[str], exclude_keys: List[str] = None) -> List[str]:
    """
    获取目录下的所有文件，并根据排除后缀和关键字排除不需要的文件和目录。
    参数:
        directory (str): 要遍历的根目录。
        exclude_suffixes (List[str]): 需要排除的文件后缀列表。
        exclude_keys (List[str]): 需要排除的目录关键字列表。
    返回:
        List[str]: 符合条件的所有文件路径列表。
    """

    def _format_path(path: str):
        if path:
            path = str(path).replace("\\", "/").replace("//", "/")
        return path

    exclude_keys = [_format_path(x) for x in (exclude_keys or [])]
    files = []
    for root, dirs, filenames in os.walk(directory):
        # 检查当前目录路径是否包含任何需要排除的关键字
        if any(key in _format_path(root) for key in exclude_keys):
            # 忽略包含关键字的目录及其子目录
            continue
        # 过滤掉需要排除的目录
        dirs[:] = [d for d in dirs if not any(key in _format_path(os.path.join(root, d)) for key in exclude_keys)]
        # 进行后缀排除
        for filename in filenames:
            if not any(filename.endswith(suffix) for suffix in exclude_suffixes):
                files.append(os.path.join(root, filename))
    return files


def file_is_larger(file_path, limit=1):
    """判断指定路径的文件大小是否超过1MB。 """
    if os.path.exists(file_path):
        file_size = os.path.getsize(file_path)
        mb_in_bytes = 1024 * 1024 * limit
        return file_size > mb_in_bytes
    else:
        print(f"Error: 文件 {file_path} 不存在,返回False")
    return False


def in_allowed_suffixes(filename: str, suffixes: str) -> bool:
    """检查文件是否需要根据规则进行处理"""
    if suffixes == '*':
        return True
    if isinstance(suffixes, str):
        suffixes = suffixes.split("|")
    if any(filename.endswith(suffix) for suffix in suffixes):
        return True
    return False


def str_has_key(content: str, key_str: str) -> bool:
    """
     判断字符串 string 是否包含 关键词 black_key。

     关键词 支持逻辑运算符：
     - '||' 表示“或”，只要有一个关键词在 string 中出现即满足条件；
     - '&&' 表示“与”，所有关键词都必须出现在 string 中才满足条件。

     参数:
         string (str): 被检测的目标字符串。
         key_str (str): 黑名单关键词，可能包含 '||' 或 '&&' 逻辑表达式。

     返回:
         bool: 如果满足匹配条件返回 True，否则返回 False。
     """

    # 当 string 或 black_key 为 None 或空字符串时返回 False
    if not content or not key_str:
        return False

    if "||" in key_str:
        # 只要有一个关键词存在于 string 中，就返回 True
        keys = [key.strip() for key in key_str.split("||") if key.strip()]
        return any(key in content for key in keys)
    elif "&&" in key_str:
        # 所有关键词都必须存在于 string 中，才返回 True
        keys = [key.strip() for key in key_str.split("&&") if key.strip()]
        return all(key in content for key in keys)
    else:
        # 普通包含判断
        return key_str in content

def file_has_key(file_path: str, key_str: str):
    if not key_str:
        return False

    chunk_size = 1024 * 1024  # 每次读取1MB的数据
    with open(file_path, 'r', encoding=file_encoding(file_path), errors="ignore") as file:
        for chunk in read_by_chunks(file, chunk_size):
            if str_has_key(chunk, key_str):
                return True
        return False