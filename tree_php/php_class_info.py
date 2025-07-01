from tree_php.php_class_utils import parse_class_define_info


def analyze_class_infos(language, root_node, dependent_infos:dict):
    """提取所有类定义信息"""
    # 获取所有命名空间信息
    tree_sitter_class_define_query = """
        ;匹配类定义信息 含abstract类和final类
        (class_declaration) @class.def
        ;匹配接口定义
        (interface_declaration) @class.def
    """
    class_info_query = language.query(tree_sitter_class_define_query)
    class_info_matches = class_info_query.matches(root_node)

    # 函数调用解析部分
    class_infos = []
    for pattern_index, match_dict in class_info_matches:
        # 添加调试信息
        # print(f"{pattern_index}/{len(class_info_matches)} Pattern match type:", [key for key in match_dict.keys()])
        # 一次性解析类信息
        class_mark = 'class.def'  # 语法中表示类定义
        inter_mark = 'interface.def' # 语法中表示接口定义
        if class_mark in match_dict or inter_mark in match_dict:
            # 处理类信息时使用当前命名空间 # 如果命名空间栈非空，使用栈顶命名空间
            is_interface = inter_mark in match_dict
            class_node = match_dict[inter_mark][0] if is_interface else match_dict[class_mark][0]
            class_info = parse_class_define_info(language, class_node, is_interface, dependent_infos)
            class_infos.append(class_info)
    return class_infos


if __name__ == '__main__':
    # 解析tree
    from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root
    from php_dependent_utils import analyse_dependent_infos
    from libs_com.utils_json import print_json

    PARSER, LANGUAGE = init_php_parser()
    php_file = r"../php_demo/class_demo/class_3.php"
    root_node = read_file_to_root(PARSER, php_file)
    dependent_infos = analyse_dependent_infos(LANGUAGE, root_node)
    code = analyze_class_infos(LANGUAGE, root_node, dependent_infos)
    print_json(code)


