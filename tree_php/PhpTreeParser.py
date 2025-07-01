import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from libs_com.file_path import get_root_dir, get_relative_path, get_absolute_path, file_is_empty
from libs_com.file_filter import get_allowed_files
from libs_com.utils_hash import get_path_hash
from libs_com.utils_json import dump_json
from libs_com.utils_process import print_progress
from tree_php.php_class_info import analyze_class_infos
from tree_php.php_dependent_utils import analyse_dependent_infos
from tree_php.php_enums import FileInfoKeys
from tree_php.php_func_info import analyze_direct_method_infos
from tree_php.php_map_analyze import analyze_methods_relation
from tree_php.php_variable_info import analyze_variable_infos
from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root


def parse_php_file(abspath_path, parser, language, project_root):
    # 优化路径信息
    relative_path = get_relative_path(abspath_path, project_root) if project_root else abspath_path

    # 解析tree
    root_node = read_file_to_root(parser, abspath_path)
    # 解析出基础依赖信息用于函数调用呢
    dependent_infos = analyse_dependent_infos(language, root_node)
    # 分析函数信息
    method_infos = analyze_direct_method_infos(parser, language, root_node, dependent_infos)
    # 分析类信息（在常量分析之后添加）
    class_infos = analyze_class_infos(language, root_node, dependent_infos)
    # 分析变量和常量信息 目前没有使用
    variables_infos = analyze_variable_infos(parser, language, root_node, dependent_infos)

    # 结果信息
    parsed_info = {
        FileInfoKeys.METHOD_INFOS.value: method_infos,
        FileInfoKeys.CLASS_INFOS.value: class_infos,
        FileInfoKeys.VARIABLE_INFOS.value: variables_infos,
        FileInfoKeys.DEPEND_INFOS.value: dependent_infos,
    }

    return relative_path, parsed_info


class PhpParser:
    def __init__(self, project_name, project_path):
        # 初始化解析器
        self.parser, self.language = init_php_parser()
        self.project_path = project_path
        self.project_root = get_root_dir(project_path)
        self.parsed_cache = f"{project_name}.{get_path_hash(project_path)}.parser.php.cache"

    def parse_php_files_threads(self, php_files, workers=None):
        parse_infos = {}
        # 使用多线程解析文件
        with ThreadPoolExecutor(max_workers=workers) as executor:
            # 提交任务到线程池
            start_time = time.time()
            futures = [executor.submit(parse_php_file, file, self.parser, self.language, self.project_root) for file in php_files]

            for index, future in enumerate(as_completed(futures), start=1):
                file_path, parsed_info = future.result()
                print_progress(index, len(php_files), start_time)
                if parsed_info:
                    parse_infos[file_path] = parsed_info
        return parse_infos

    def parse_php_files_single(self, php_files):
        parse_infos = {}
        start_time = time.time()
        for index, file in enumerate(php_files, start=1):
            file_path, parsed_info = parse_php_file(file, self.parser, self.language, self.project_root)
            print_progress(index, len(php_files), start_time)
            if parsed_info:
                parse_infos[file_path] = parsed_info
        return parse_infos


    def analyse(self, save_cache=True, workers=None, import_filter=True, exclude_keys=[]):
        """运行PHP解析器"""
        #  加载已存在的解析结果
        if file_is_empty(self.parsed_cache):
            start_time = time.time()
            php_files = get_allowed_files(self.project_path, allowed_ext=[".php"], exclude_keys=exclude_keys)
            if workers == 1:
                parsed_infos = self.parse_php_files_single(php_files)
            else:
                parsed_infos = self.parse_php_files_threads(php_files, workers=workers)
            print(f"\n代码结构初步解析完成  用时:{time.time() - start_time:.1f} 秒")

            # 补充函数调用信息
            start_time = time.time()
            parsed_infos = analyze_methods_relation(parsed_infos, import_filter)
            print(f"\n补充函数调用信息完成 用时: {time.time() - start_time:.1f} 秒")

            if save_cache:
                dump_json(self.parsed_cache, parsed_infos, encoding='utf-8', indent=2, mode="w+")
        else:
            start_time = time.time()
            print(f"\n加载缓存分析结果文件:->{self.parsed_cache}")
            parsed_infos = json.load(open(self.parsed_cache, "r", encoding="utf-8"))
            print(f"\n加载缓存分析结果文件完成 用时: {time.time() - start_time:.1f} 秒")

        return parsed_infos


def get_simple_parsed_info(vuln_file, project_path):
    """简单的获取解析信息"""
    parser, language = init_php_parser()
    abspath_path = get_absolute_path(vuln_file, project_path)
    relative_path, parsed_info = parse_php_file(abspath_path, parser, language, project_path)
    return parsed_info
