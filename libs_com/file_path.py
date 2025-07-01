import os


def get_now_dir_file_path(path):
    return os.path.join(os.path.dirname(__file__), path)


def get_abspath(config_file):
    return os.path.abspath(config_file)


def get_root_dir(project_path):
    return os.path.abspath(project_path if os.path.isdir(project_path) else os.path.dirname(project_path))


def get_relative_path(absolute_path: str, project_root: str) -> str:
    """将绝对路径转换为相对于项目根目录的路径"""
    if not project_root:
        return absolute_path
    try:
        relative_path = os.path.relpath(absolute_path, project_root)
        return relative_path.replace('\\', '/')  # 统一使用正斜杠
    except ValueError:
        return absolute_path


def get_absolute_path(relative_path: str, project_root: str) -> str:
    """将相对于项目根目录的路径转换为绝对路径。 """
    if not project_root:
        raise ValueError("project_root 不能为空")

    # 拼接相对路径和项目根目录，生成绝对路径 join 支持 输入的 relative_path 是绝对路径
    absolute_path = os.path.join(project_root, relative_path)
    absolute_path = os.path.abspath(absolute_path).replace('\\', '/')  # 统一使用正斜杠
    return absolute_path


def get_base_dir():
    return os.path.dirname(os.path.abspath(__file__))


def path_is_exist(file_path):
    # 判断文件是否存在
    return os.path.exists(file_path) if file_path else False


def file_is_empty(file_path):
    # 判断一个文件是否为空
    return not path_is_exist(file_path) or not os.path.getsize(file_path)


def path_is_file(file_path):
    return os.path.exists(file_path) and os.path.isfile(file_path)
