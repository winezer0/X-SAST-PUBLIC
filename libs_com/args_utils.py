import sys

from libs_com.file_path import path_is_exist


def check_required_path(file_path, mode_name):
    if not file_path or not path_is_exist(file_path):
        print(f"[!] {mode_name}文件未指定或文件不存在:{file_path}")
        sys.exit(1)


def check_required_data(data, mode_name):
    if not data:
        print(f"[!] {mode_name} 数据为空或对象不存在")
        sys.exit(1)


def to_lowercase(any_strs):
    # 格式化过滤条件
    if not any_strs:
        return any_strs

    if isinstance(any_strs, str):
        return any_strs.lower()
    else:
        return [x.lower() for x in any_strs]
