import os

from libs_com.file_path import get_absolute_path
from libs_verifier.utils_open_ai import count_tokens
from tree_php.php_basic_define_infos import query_class_and_method_define_infos
from tree_php.php_coment import remove_php_comments
from tree_php.php_dependent_utils import get_node_infos_ranges
from tree_php.php_enums import MethodKeys, OtherKeys, FileInfoKeys
from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root


def get_global_code_by_define_ranges(absolute_path:str, define_ranges:list=None):
    """通过排除行号的方法 获取文件的全局代码信息"""
    if not define_ranges:
        # 如果没有用户输入节点信息,就需要自己解析了
        parser, language = init_php_parser()
        root_node = read_file_to_root(parser, absolute_path)
        # 解析类和方法的定义信息
        define_node_infos = query_class_and_method_define_infos(language, root_node)
        define_ranges = get_node_infos_ranges(define_node_infos)
    content = get_file_code_not_in_ranges(absolute_path, define_ranges)
    return content


def get_method_code_by_range(method_info: dict, project_path: str, define_ranges=None) -> dict:
    """通过方法信息获取方法的源代码"""
    method_content_info = {}
    method_name = method_info.get(MethodKeys.NAME.value)
    relative_path = method_info.get(MethodKeys.FILE.value)

    absolute_path= get_absolute_path(relative_path, project_path)

    if method_info[MethodKeys.NAME.value] == OtherKeys.GLOBAL_CODE.value:
        source_code = get_global_code_by_define_ranges(absolute_path, define_ranges=define_ranges)
    else:
        start_line = method_info.get(MethodKeys.START.value)
        end_line = method_info.get(MethodKeys.END.value)
        source_code = get_file_code_in_range(absolute_path, start_line, end_line)

    if not source_code or len(source_code) < 10:
        return None

    # 清理注释和空白行
    source_code = remove_php_comments(source_code, clean_line=True)
    method_content_info[MethodKeys.NAME.value] = method_name
    method_content_info[MethodKeys.FILE.value] = relative_path
    method_content_info[MethodKeys.SOURCE_CODE.value] = source_code
    return method_content_info


def find_method_info_by_code_line(code_line:int, method_infos:list[dict]):
    """根据行号信息从文件的方法解析结果中提取方法"""
    if not code_line or not isinstance(code_line, int):
        print(f"发生严重错误!!! code_line [{code_line}] type: [{type(code_line)}｝]")
        return None

    program_code_info = None
    find_method_infos = []
    for method_info in method_infos:
        # 首先排除方法名是全局代码的情况, 避免误报
        if method_info.get(MethodKeys.NAME.value) == OtherKeys.GLOBAL_CODE.value:
            program_code_info = method_info
            continue
        # 获取方法的上下行范围信息
        if method_info.get(MethodKeys.START.value) <= code_line <= method_info.get(MethodKeys.END.value):
            find_method_infos.append(method_info)

    find_method_info = None
    if len(find_method_infos) > 1:
        # 说明该方法有全局代码信息 所以才会有两个结果 已经排除全局代码了, 现在应该不会有这个情况
        find_method_info = min(find_method_infos, key=lambda ns: ns[MethodKeys.END.value] - ns[MethodKeys.START.value])
        method_file = find_method_infos[0].get(MethodKeys.FILE.value)
        print(f"发现[{method_file}] 行号[{code_line}]存在[{len(find_method_infos)}]个节点信息, 提取最小范围信息...")
    elif len(find_method_infos) == 1:
        find_method_info = find_method_infos[0]

    if find_method_info is None and program_code_info is not None:
        # 没有任何数据时, 就从全局代码中获取对应的行信息了
        if program_code_info.get(MethodKeys.START.value) <= code_line <= program_code_info.get(MethodKeys.END.value):
            find_method_info = method_info
        if not find_method_info:
            print(f"通过行号[{code_line}]在[{[x.get(MethodKeys.FILE.value) for x in method_infos]}] 没有找到任何对应方法!!!")
    return find_method_info


def find_method_info_by_method_id(method_id:str, method_infos: list[dict]):
    for method_info in method_infos:
        if method_id == method_info.get(MethodKeys.UNIQ_ID.value, None):
            return method_info
    print(f"发生严重错误!!! 通过 method_id {method_id} 反查方法信息失败!!!")
    return None


def find_method_info_by_method_id_and_file(method_id, method_file, parsed_infos):
    """通过may_source 信息反查方法节点信息"""
    # 从所有解析方法中要获取文件对应的方法信息
    parsed_info = parsed_infos.get(method_file, None)
    # 没有指定代码解析信息,返回空结果...
    if not parsed_info:
        return None
    # 获取 method_infos
    file_method_infos = parsed_info.get(FileInfoKeys.METHOD_INFOS.value)
    # 从整个文件的方法解析结果中获取行号所在的方法
    find_method_info = find_method_info_by_method_id(method_id, file_method_infos)
    # 找到方法信息后 获取方法对应的代码信息
    return find_method_info


def get_method_list_code_by_range(find_method_infos:list[dict], project_path:str):
    method_codes = []
    for method_info in find_method_infos:
        method_code = get_method_code_by_range(method_info, project_path)
        if method_code:
            method_codes.append(method_code)
    return method_codes


def find_method_info_by_may_sources(may_source:dict, parsed_infos:dict):
    # 根据may_source信息查找对应的源代码信息
    find_method_infos = []
    for method_id, method_file in may_source.items():
        find_method_info = find_method_info_by_method_id_and_file(method_id, method_file, parsed_infos)
        if find_method_info:
            find_method_infos.append(find_method_info)
    return find_method_infos


def get_called_methods_may_sources(called_method_infos:dict):
    all_may_sources = {}
    for called_method_info in called_method_infos:
        may_sources = called_method_info.get(MethodKeys.MAY_SOURCES.value, {})
        # may_sources 节点是字典格式的 "MAY_SOURCE": {"method_f97b06cb": "admin/account_log.php"}
        if may_sources:
            all_may_sources.update(may_sources)
    return all_may_sources


def get_file_code_by_lines(filepath: str, lines: list) -> str:
    """
    根据指定的行号列表，从文件中提取对应的代码内容。
    对于大文件（>5MB），逐行读取；对于小文件（<=5MB），一次性加载。
    :param filepath: 文件路径
    :param lines: 需要提取的行号列表（1-based 行号）
    :return: 一个字典，键为行号，值为对应行的代码内容
    """
    if not filepath or not isinstance(lines, list) or not all(isinstance(line, int) for line in lines):
        raise ValueError("参数错误：filepath 必须是字符串，lines 必须是整数列表")

    # 保存所有代码行
    codes = []
    # 去重并排序行号列表
    lines = sorted(set(lines))
    max_line = max(lines)

    try:
        # 获取文件大小（以字节为单位）
        file_size = os.path.getsize(filepath)
        # 判断文件是否大于 10 MB
        if file_size > 10 * 1024 * 1024:  # 1MB = 1 * 1024 * 1024 字节
            # 大文件：逐行读取
            with open(filepath, 'r', encoding='utf-8') as file:
                for line_index, line_content in enumerate(file, start=0):
                    if line_index in lines:
                        codes.append(line_content)
                    if line_index > max_line:
                        break
        else:
            # 小文件：一次性加载所有行
            with open(filepath, 'r', encoding='utf-8') as file:
                file_lines = file.readlines()
            # 遍历需要提取的行号
            for line_number in lines:
                if 1 <= line_number <= len(file_lines):  # 检查行号是否在有效范围内
                    line_content = file_lines[line_number]
                    codes.append(line_content)

    except FileNotFoundError:
        raise FileNotFoundError(f"文件未找到: {filepath}")
    except Exception as e:
        raise RuntimeError(f"读取文件时发生错误: {e}")

    return "".join(codes)


def get_file_code_in_range(filepath: str, start_line: int, end_line: int) -> str:
    """根据指定的起始行号和结束行号，从文件中提取对应的代码内容。"""
   # 生成行号范围
    lines = list(range(start_line, end_line + 1))
    return get_file_code_by_lines(filepath, lines)


def get_file_code_not_in_ranges(filepath: str, range_list:list[tuple]) -> str:
    """根据排除指定的起始行号和结束行号列表，从文件中提取对应的代码内容。"""
  # 参数校验
    if not filepath or not isinstance(range_list, list):
        raise ValueError("参数错误：filepath 必须是字符串，ranges 必须是元组列表")

    result_lines = []
    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            for line_num, line_content in enumerate(file, start=1):
                # 检查当前行是否在排除范围内
                if not any(start <= line_num <= end for start, end in range_list):
                    result_lines.append(line_content)

    except FileNotFoundError:
        raise FileNotFoundError(f"文件未找到: {filepath}")
    except Exception as e:
        raise RuntimeError(f"读取文件时发生错误: {e}")

    # 将结果拼接成字符串并返回
    return ''.join(result_lines)


def filter_called_methods_by_line(called_methods:list[dict], start_line:int, end_line:int):
    """通过代码的范围 筛选被调用的函数节点 再提取其中的 May Sources信息"""
    filtered_called_methods = []
    for called_method in called_methods:
        if start_line <= called_method.get(MethodKeys.START.value) <= end_line:
            filtered_called_methods.append(called_method)
    return filtered_called_methods



def convert_content_infos(content_infos:list, max_tokens:int=5000):
    """将函数信息转换为字符串格式"""
    if not content_infos:
        return ""

    contents = []
    tokens = 0
    for content_info in content_infos:
        method_file = content_info.get(MethodKeys.FILE.value)
        method_name = content_info.get(MethodKeys.NAME.value)
        source_code = content_info.get(MethodKeys.SOURCE_CODE.value)
        content = f"依赖方法{method_file} {method_name} 代码片段:\n{source_code}"
        # 判断Token是否超出限制
        tokens += count_tokens(content)
        if tokens > max_tokens:
            break
        else:
            contents.append(content)
    return "\n".join(contents)

def convert_content_info(content_info: dict, max_tokens:int=1000):
    if not content_info:
        return ""
    source_code = content_info.get(MethodKeys.SOURCE_CODE.value)
    # 判断Token是否超出限制
    if count_tokens(source_code) > max_tokens:
        source_code = ""
    return source_code