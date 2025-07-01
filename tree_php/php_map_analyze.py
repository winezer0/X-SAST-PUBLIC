from tree_php.php_enums import FileInfoKeys
from tree_php.php_basic_import_infos import analyze_import_infos
from tree_php.php_map_basic import repair_parsed_infos_basic_info
from tree_php.php_map_called import repair_parsed_infos_called_info, build_method_relation_map


def analyze_methods_relation(parsed_infos:dict, import_filter:bool):
    """整理出所有文件的函数关系"""
    # 为原始信息进行进行基本的信息补充
    parsed_infos = repair_parsed_infos_basic_info(parsed_infos)

    # 进一步补充被调用函数的信息
    method_relation_map = build_method_relation_map(parsed_infos)
    parsed_infos = repair_parsed_infos_called_info(parsed_infos, method_relation_map, import_filter)
    return parsed_infos

if __name__ == '__main__':
    # Import required modules
    from tree_php.php_class_info import analyze_class_infos
    from tree_php.php_func_info import analyze_direct_method_infos
    from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root, custom_format_path
    from libs_com.file_filter import get_allowed_files
    from tree_php.php_dependent_utils import analyse_dependent_infos
    # Initialize PHP parser
    PARSER, LANGUAGE = init_php_parser()
    
    # Set test directory
    project_path = r"../php_demo/func_call_demo"
    project_path = r"../php_demo/class_call_demo"
    php_files = get_allowed_files(project_path, allowed_ext=[".php"])
    parsed_infos = {}
    for abspath_path in php_files:
        abspath_path =  custom_format_path(abspath_path)
        root_node = read_file_to_root(PARSER, abspath_path)
        # 解析出基础依赖信息用于函数调用呢
        dependent_infos = analyse_dependent_infos(LANGUAGE, root_node)

        # 分析函数信息
        method_infos = analyze_direct_method_infos(PARSER, LANGUAGE, root_node, dependent_infos)
        # print_json(method_infos)
        # 分析类信息（在常量分析之后添加）
        class_infos = analyze_class_infos(LANGUAGE, root_node, dependent_infos)
        # print_json(class_infos)
        import_infos = analyze_import_infos(LANGUAGE, root_node)
        # print_json(import_infos)
        # 修改总结结果信息
        parsed_infos[abspath_path] = {
            FileInfoKeys.METHOD_INFOS.value: method_infos,
            FileInfoKeys.CLASS_INFOS.value: class_infos,
            FileInfoKeys.DEPEND_INFOS.value: dependent_infos,
        }

    # 修复并解析新的数据
    analyzed_infos = analyze_methods_relation(parsed_infos, import_filter=False)
