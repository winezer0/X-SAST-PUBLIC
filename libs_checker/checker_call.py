import sys

from libs_checker.SASTChecker import SASTChecker
from libs_checker.checker_enum import CheckerKeys
from libs_checker.checker_filter import filter_rules, merge_similar_results
from libs_checker.checker_print import print_used_rules
from libs_com.args_utils import check_required_path
from libs_com.file_path import path_is_exist
from libs_com.utils_json import print_json, load_json
from libs_com.utils_yaml import load_yaml
from libs_rules.rules_enum import RuleKeys
from libs_rules.rules_utils import results_add_context_key
from libs_rules.rules_valid import validate_rules
from tree_php.PhpTreeParser import get_simple_parsed_info, PhpParser
from tree_php.php_enums import FileInfoKeys, MethodKeys, ClassKeys
from tree_php.php_find_code import find_method_info_by_code_line, get_method_code_by_range, \
    get_called_methods_may_sources, filter_called_methods_by_line, find_method_info_by_may_sources, \
    get_method_list_code_by_range
from tree_php.php_result_utils import split_store_parsed_infos


def find_code_by_parsed_info(vuln_info: dict, project_path: str, parsed_infos: dict):
    """从解析信息中找到源码信息 支持清除注释信息"""
    vuln_file = vuln_info.get(CheckerKeys.FILE.value)
    vuln_line = vuln_info.get(CheckerKeys.LINE.value)

    if not vuln_file or not vuln_line:
        print(f"Error!!! Please Check FileName or Vuln_line is None, vuln_info:{vuln_info}")
        sys.exit(1)

    if not parsed_infos:
        # 没有指定代码解析信息,开始简单解析代码
        parsed_info = get_simple_parsed_info(vuln_file, project_path)
    else:
        # 获取 文件的解析结果 parsed_info
        parsed_info = parsed_infos.get(vuln_file, None)

    # 没有指定代码解析信息,返回空结果...
    if not parsed_info:
        return None, None

    # 获取 方法解析结果 method_infos
    method_infos = parsed_info.get(FileInfoKeys.METHOD_INFOS.value)
    # 从整个文件的方法解析结果中获取行号所在的方法
    method_info = find_method_info_by_code_line(vuln_line, method_infos)
    if not method_info:
        # 大概率是一些导入信息或者导入信息 不应该满足这个条件的!!!
        print(f"发生严重错误: 在文件{vuln_file} 的解析结果中 没有找到对应代码行号[{vuln_line}]的信息!!!")
        return None, None

    # 获取method对应的代码
    method_content_info = get_method_code_by_range(method_info, project_path)

    # 获取method的CalledMethods包含的代码信息
    called_methods = method_info.get(MethodKeys.CALLED_METHODS.value)
    # MAY_SOURCES节点在method_info的call_methods内
    all_may_sources = get_called_methods_may_sources(called_methods)
    if not all_may_sources:
        return method_content_info, None

    method_name = method_info.get(MethodKeys.NAME.value)
    method_file = method_info.get(MethodKeys.FILE.value)
    if len(all_may_sources) > 10:
        # print(f"注意: [{method_file} {method_name}] 调用方法过多 -> {len(all_may_sources)} 开始进行排除")
        # 调用方法过多 就只获取存在漏洞代码的部分的调用函数信息 通过 called_methods里面的调用函数起始行来筛选
        find_ranges = [10, 20, 30, 40, 50]
        for pre_line in find_ranges:
            start_line = max(vuln_line - pre_line, 0)
            end_line = vuln_line + 10
            called_method_infos = filter_called_methods_by_line(called_methods, start_line, end_line)
            all_may_sources = get_called_methods_may_sources(called_method_infos)
            if all_may_sources:
                break
        if not all_may_sources:
            # print(f"[F:{vuln_file} L:{vuln_line} M:{method_name}]调用函数过多, 但({start_line}-{end_line})内未发现可解析调用")
            return method_content_info, None

    # 根据可能的方法信息进行反向查询
    find_method_infos = find_method_info_by_may_sources(all_may_sources, parsed_infos)
    if not find_method_infos:
        print(f"发生严重错误: 没有找到 [{method_file} {method_name}] {all_may_sources} 的原方法信息!!!")
        sys.exit(1)

    # 整合所有方法的代码信息
    depend_content_infos = get_method_list_code_by_range(find_method_infos, project_path)
    return method_content_info, depend_content_infos


def find_results_codes_by_parsed_info(check_results, parsed_infos, project_path):
    """根据语法解析结果 为每个结果行反查对应的代码信息 """
    for vuln_info in check_results:
        if vuln_info[RuleKeys.CONTEXT_NEED.value]:
            # 为代码补充完整函数
            method_code, called_codes = find_code_by_parsed_info(vuln_info, project_path, parsed_infos)
            vuln_info[CheckerKeys.METHOD_CODE.value] = method_code
            vuln_info[CheckerKeys.CALLED_CODES.value] = called_codes
    return check_results


def project_parser_call(project_name, project_path, workers, exclude_keys, save_cache, custom_types, import_filter):
    php_parser = PhpParser(project_name=project_name, project_path=project_path)
    parsed_infos = php_parser.analyse(save_cache=save_cache, workers=workers, import_filter=import_filter, exclude_keys=exclude_keys)

    # 为 parsed_info 中的 method_infos 键填充 class_infos中的数据
    for relative_path, parsed_info in parsed_infos.items():
        # 往方法信息中补充类方法信息
        curr_file_method_infos = parsed_info.get(FileInfoKeys.METHOD_INFOS.value)
        for class_info in parsed_info.get(FileInfoKeys.CLASS_INFOS.value):
            class_method_infos = class_info.get(ClassKeys.METHODS.value)
            curr_file_method_infos.extend(class_method_infos)

    result_info = split_store_parsed_infos(parsed_infos, project_name, project_path, custom_types=custom_types)
    del parsed_infos
    return result_info


def project_checker_call(project_name, project_path, rules_file, exclude_keys, exclude_ext, filter_lang, filter_risk,
                         filter_vuln, parsed_file, save_cache, chunk_mode, limit_size, call_parser, workers,
                         import_filter, black_key):

    # 进行规则检查和规则过滤
    check_required_path(rules_file, "扫描规则")
    rules_dict = load_yaml(rules_file)
    rules_dict = filter_rules(rules_dict,
                              lang_filter=filter_lang,
                              risk_filter=filter_risk,
                              rule_filter=filter_vuln,
                              )
    # 验证并显示本次扫描使用的规则
    if validate_rules(rules_dict):
        print_used_rules(rules_dict)
    else:
        print_json(rules_dict)
        print("规则格式验证失败,请检查当前配置文件!!!")
        sys.exit(1)

    # 进行规则扫描
    check_required_path(project_path, "扫描路径")
    # 处理排除目录路径 为绝对路径 后续调用normpath 考虑优化为key路径
    checker = SASTChecker(project_name=project_name,
                          project_path=project_path,
                          rules_dict=rules_dict,
                          exclude_ext=exclude_ext,
                          exclude_keys=exclude_keys,
                          limit_size=limit_size
                          )
    check_results = checker._check_files(max_workers=workers,
                                         save_cache=save_cache,
                                         chunk_mode=chunk_mode,
                                         black_key=black_key)

    # 合并基本相似结果
    len_results = len(check_results)
    check_results = merge_similar_results(check_results)
    print(f"通过相似度过滤结果:{len_results} -> {len(check_results)}")


    # 进行前置代码分析
    if call_parser:
        print("开始进行项目代码语法分析...")
        parsed_result = project_parser_call(
            project_name=project_name,
            project_path=project_path,
            workers=workers,
            exclude_keys=exclude_keys,
            save_cache=save_cache,
            custom_types=[FileInfoKeys.METHOD_INFOS.value],
            import_filter=import_filter
        )
        # 目前只需要获取其中的方法信息
        parsed_file = parsed_result.get(FileInfoKeys.METHOD_INFOS.value)

    # 完善分析结果正则分析结果
    if path_is_exist(parsed_file):
        print("开始尝试补充漏洞依赖代码信息...")
        # 加载代码解析信息
        parsed_infos = load_json(parsed_file)
        # 根据扫描结果的规则 判断是是否需要下文信息
        check_results = results_add_context_key(check_results, rules_dict)
        # 为每个结果行反查对应的代码信息 使用语法解析结果进行补充
        check_results = find_results_codes_by_parsed_info(check_results, parsed_infos, project_path)
    return check_results
