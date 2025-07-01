from tree_php.php_func_utils import query_global_methods_info, parse_global_code_called_methods


def analyze_direct_method_infos(parser, language, root_node, dependent_infos:dict):
    """获取所有函数信息，包括函数内部和非函数部分 """
    # 获取文件中的所有函数信息
    methods_info = query_global_methods_info(language, root_node, dependent_infos)
    # 处理文件级别的函数调用
    global_code_info = parse_global_code_called_methods(parser, language, root_node, dependent_infos)
    if global_code_info:
        methods_info.append(global_code_info)
    return methods_info


if __name__ == '__main__':
    # 解析tree
    from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root
    from libs_com.utils_json import print_json
    from tree_php.php_dependent_utils import analyse_dependent_infos
    PARSER, LANGUAGE = init_php_parser()
    php_file = r"../php_demo/class_demo/class_1.php"
    php_file = "../php_demo/full_test_demo/index.php"
    root_node = read_file_to_root(PARSER, php_file)
    # 解析出基础依赖信息用于函数调用呢
    dependent_infos = analyse_dependent_infos(LANGUAGE, root_node)
    direct_method_infos = analyze_direct_method_infos(PARSER, LANGUAGE, root_node, dependent_infos)
    print_json(direct_method_infos)
