from tree_sitter._binding import Node

from tree_php.php_enums import MethodKeys
from tree_uitls.tree_sitter_uitls import find_first_child_by_field, get_node_text, get_node_filed_text


def query_class_object_infos(language: object, tree_node: Node) -> list[dict]:
    """获取节点中中所有创建的类对象和名称关系"""
    create_object_infos = query_create_object_infos(language, tree_node)
    params_named_type_infos = query_params_named_type_infos(language, tree_node)
    return create_object_infos + params_named_type_infos


def query_params_named_type_infos(language, tree_node):
    object_class_dicts = []
    # 定义查询语句
    parameters_query = language.query("""
        ; 查询参数传递 部分情况下类对象走的是参数传递
        (simple_parameter
            type: (named_type)
            name: (variable_name)
        )@parameters
    """)
    # 遍历匹配结果
    for match in parameters_query.matches(tree_node):
        match_dict = match[1]
        # {'param_type': [<Node type=named_type, start_point=(13, 26), end_point=(13, 30)>],
        # 'param_name': [<Node type=variable_name, start_point=(13, 31), end_point=(13, 36)>]}
        # 提取 assignment_expr 节点
        if 'parameters' in match_dict:
            parameters_node = match_dict['parameters'][0]
            start_line = parameters_node.start_point[0]
            end_line = parameters_node.end_point[0]
            parameter_type = get_node_filed_text(parameters_node, 'type')
            parameter_name = get_node_filed_text(parameters_node, 'name')
            if parameter_type and parameter_name:
                object_info = {
                    MethodKeys.OBJECT.value: parameter_name,
                    MethodKeys.CLASS.value: parameter_type,
                    MethodKeys.START.value: start_line,
                    MethodKeys.END.value: end_line,
                }
                object_class_dicts.append(object_info)
    return object_class_dicts


def query_create_object_infos(language, tree_node):
    # 存储结果的列表
    object_class_dicts = []
    # 定义查询语句
    new_object_query = language.query("""
        ; 查询对象方法创建 同时获取返回值
        (assignment_expression
            left: (variable_name)
            right: ((object_creation_expression))
        ) @assignment_expr
    """)
    # 遍历匹配结果
    for match in new_object_query.matches(tree_node):
        match_dict = match[1]
        # 提取 assignment_expr 节点
        if 'assignment_expr' in match_dict:
            assignment_expr_node = match_dict['assignment_expr'][0]
            start_line = assignment_expr_node.start_point[0]
            end_line = assignment_expr_node.end_point[0]

            # 初始化变量
            # 使用 child_by_field_name 提取左侧变量名
            left_node = find_first_child_by_field(assignment_expr_node, 'left')
            object_name = get_node_text(left_node)

            # 使用 child_by_field_name 提取右侧表达式
            right_expr_node = find_first_child_by_field(assignment_expr_node, 'right')
            if right_expr_node and right_expr_node.type == 'object_creation_expression':
                class_name = get_node_filed_text(right_expr_node, 'name')
                if class_name and object_name:
                    object_info = {
                        MethodKeys.OBJECT.value: object_name,
                        MethodKeys.CLASS.value: class_name,
                        MethodKeys.START.value: start_line,
                        MethodKeys.END.value: end_line,
                    }
                    object_class_dicts.append(object_info)
    return object_class_dicts


if __name__ == '__main__':
    # 解析tree
    from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root
    from libs_com.utils_json import print_json

    PARSER, LANGUAGE = init_php_parser()
    php_file = r"../php_demo/class_demo/class_1.php"
    php_file = "../php_demo/full_test_demo/index.php"
    php_file = "../php_demo/full_test_demo/src/Services/Auth.php"
    root_node = read_file_to_root(PARSER, php_file)
    object_creation_infos = query_class_object_infos(LANGUAGE, root_node)
    print_json(object_creation_infos)