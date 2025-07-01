from tree_sitter._binding import Node

from tree_php.php_enums import VariableKeys
from tree_uitls.tree_sitter_uitls import get_node_text, find_first_child_by_field, get_node_type, find_children_by_field, \
    get_node_filed_text


def create_var_info_result(name_text, name_type, value_text, value_type, start_line, end_line, full_text, function):
    var_info = {
        VariableKeys.FULL_TEXT.value: full_text,
        VariableKeys.NAME.value: name_text,
        VariableKeys.NAME_TYPE.value: name_type,
        VariableKeys.VALUE.value: value_text,
        VariableKeys.VALUE_TYPE.value: value_type,
        VariableKeys.START.value: start_line,
        VariableKeys.END.value: end_line,
        VariableKeys.FUNCTION.value: function,
    }
    return var_info


def parse_static_node(static_node: Node):
    """解析常规的变量赋值节点"""
    # (function_static_declaration (static_variable_declaration name: (variable_name (name)) value: (integer)))
    start_line = static_node.start_point[0]
    end_line = static_node.end_point[0]
    variable_text = get_node_text(static_node)

    static_node = find_first_child_by_field(static_node, "static_variable_declaration")
    variable_node = find_first_child_by_field(static_node, 'variable_name')
    name_text = get_node_text(variable_node)
    name_type = get_node_type(variable_node)

    # 获取代表 value 的内容
    if len(static_node.children) >= 3:
        value_node = static_node.children[2]
        value_text = get_node_text(value_node)
        value_type = get_node_type(value_node)
    else:
        value_text = None
        value_type = None
    var_info = create_var_info_result(name_text=name_text, name_type=name_type, value_text=value_text,
                                      value_type=value_type, start_line=start_line, end_line=end_line,
                                      full_text=variable_text, function=None)
    return var_info


def parse_variable_node(language, any_node: Node, node_name: str):
    """解析常规的函数体中的变量赋值节点"""
    def parse_assignment_node(assignment_node, function):
        """解析常规的变量赋值节点"""
        # (assignment_expression left: (variable_name (name)) right: (integer))
        start_line = assignment_node.start_point[0]
        end_line = assignment_node.end_point[0]
        variable_text = get_node_text(assignment_node)

        left_node = find_first_child_by_field(assignment_node, 'left')
        right_node = find_first_child_by_field(assignment_node, 'right')
        variable_name = get_node_text(left_node)
        variable_type = get_node_type(left_node)
        value_name = get_node_text(right_node)
        value_type = get_node_type(right_node)

        var_info = create_var_info_result(name_text=variable_name, name_type=variable_type, value_text=value_name,
                                          value_type=value_type, start_line=start_line, end_line=end_line,
                                          full_text=variable_text, function=function)
        return var_info

    query = language.query("""
        ;常规变量赋值 比如 $localVar = 42;
        (assignment_expression
            (variable_name)
            (_) @var_value
        )@variables
    """)
    matches = query.matches(any_node)
    variable_infos = []
    for match in matches:
        pattern_index, match_dict = match
        if 'variables' in match_dict:
            variable_node = match_dict['variables'][0]
            variable_info = parse_assignment_node(variable_node, node_name)
            variable_infos.append(variable_info)
    return variable_infos


def parse_global_node(global_node: Node):
    # (global_declaration (variable_name (name)))
    start_line = global_node.start_point[0]
    end_line = global_node.end_point[0]
    global_text = get_node_text(global_node)

    global_node = find_first_child_by_field(global_node, 'variable_name')
    variable_name = get_node_text(global_node)
    variable_type = get_node_type(global_node)

    var_info = create_var_info_result(name_text=variable_name, name_type=variable_type, value_text=None,
                                      value_type=None, start_line=start_line, end_line=end_line, full_text=global_text,
                                      function=None)
    return var_info


def parse_super_global_node(super_global_node: Node):
    start_line = super_global_node.start_point[0]
    end_line = super_global_node.end_point[0]

    # (subscript_expression (variable_name (name)) (string (string_content)))
    super_global_text = get_node_text(super_global_node)
    # print(f"super_global_text:{super_global_text}")  # $_SERVER[1111]

    super_var_node = find_first_child_by_field(super_global_node, 'variable_name')
    super_var_name = get_node_text(super_var_node)
    super_var_type = get_node_type(super_var_node)
    # print(super_var_name, super_var_type)  # $_COOKIE variable_name

    # 获取代表key的内容
    super_key_node = super_global_node.children[2]
    # print(super_key_node)  # (string (string_content))
    super_key_name = get_node_text(super_key_node)
    super_key_type = get_node_type(super_key_node)
    # print(super_key_name, super_key_type)  # PATH string

    var_info = create_var_info_result(name_text=super_var_name, name_type=super_var_type, value_text=super_key_name,
                                      value_type=super_key_type, start_line=start_line, end_line=end_line,
                                      full_text=super_global_text, function=None)
    return var_info


def parse_const_node(const_node):
    """ 解析 const_node 函数调用节点的信息。 """
    full_text = get_node_text(const_node)
    # (const_declaration (const_element (name) (string (string_content))))
    start_line = const_node.start_point[0]
    end_line = const_node.end_point[0]

    arguments_node = find_first_child_by_field(const_node, 'const_element')
    # (const_element (name) (string (string_content)))

    name_node = find_first_child_by_field(arguments_node, 'name')
    name_text = get_node_text(name_node)
    name_type = name_node.type
    # name_node:CLASS_INT_CONSTANT type:name

    value_node = arguments_node.children[-1]
    value_text = get_node_text(value_node)
    value_type = value_node.type

    var_info = create_var_info_result(name_text=name_text, name_type=name_type, value_text=value_text,
                                      value_type=value_type, start_line=start_line, end_line=end_line,
                                      full_text=full_text, function=None)
    return var_info


def parse_define_node(define_node):
    """ 解析 define 函数调用节点的信息。 """
    full_text = get_node_text(define_node)
    start_line = define_node.start_point[0]
    end_line = define_node.end_point[0]

    # 提取参数列表
    arguments_node = find_first_child_by_field(define_node, 'arguments')
    # (arguments (argument (string (string_content))) (argument (boolean)))
    # define 提取语法中已经限定,必须有两个参数,如果没有应该报错
    if not arguments_node or len(arguments_node.children) < 2:
        raise ValueError("Invalid arguments for 'define' function.")

    argument_nodes = find_children_by_field(arguments_node, 'argument')
    # [<Node type=argument,>, <Node type=argument, >]
    # 第一个参数：节点名称
    name_node = argument_nodes[0].child(0)  # 获取第1个节点
    name_type = name_node.type
    name_text = get_node_filed_text(name_node, 'string_content')
    # print(f"node_name: {name_text} type:{name_type}")
    # node_name: IN_ECS type:string

    # 第二个参数：节点值及其类型
    value_node = argument_nodes[1].child(0)
    value_type = value_node.type
    value_text = get_node_text(value_node)
    # print(f"node_value: {value_text} type {value_type}")
    # node_value: true type boolean

    var_info = create_var_info_result(name_text=name_text, name_type=name_type, value_text=value_text,
                                      value_type=value_type, start_line=start_line, end_line=end_line,
                                      full_text=full_text, function=None)
    return var_info


