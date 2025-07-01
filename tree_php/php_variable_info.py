from typing import List, Dict, Any

from tree_sitter._binding import Node

from libs_com.utils_json import print_json
from tree_php.php_dependent_utils import get_define_nodes_ranges
from tree_php.php_enums import VariableType, OtherKeys, VariableKeys
from tree_php.php_func_global import get_global_code_info, get_global_code_info_code
from tree_php.php_variable_utils import parse_static_node, parse_variable_node, parse_global_node, \
    parse_super_global_node, \
    parse_define_node, parse_const_node
from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root, load_string_to_root, \
    find_first_child_by_field, \
    get_node_filed_text


def analyze_variable_infos(parser, language, root_node: Node, dependent_infos:dict):
    """分析PHP文件中的所有变量"""
    # 初始化变量字典
    var_infos = {var_type.value: [] for var_type in VariableType}

    query = language.query("""
        ;匹配超全局变量访问 比如 $_SERVER['REQUEST_METHOD']
        (subscript_expression)@super_global_call

        ;全局变量声明 比如 global $globalVar;
        (global_declaration)@global_declare

        ;静态变量声明 比如 static $staticVar = 0;
        (function_static_declaration)@static_declare
    """)
    matches = query.matches(root_node)

    # SUPER_GLOBAL = 'superglobal'  超全局变量调用信息
    # PHP 中的超全局变量（Superglobals）是内置的预定义变量，在脚本的任何作用域中都可以直接访问
    # 提取文件中的 super global 信息
    super_global_infos = []
    for match in matches:
        pattern_index, match_dict = match
        if 'super_global_call' in match_dict:
            variable_node = match_dict['super_global_call'][0]
            variable_info = parse_super_global_node(variable_node)
            super_global_infos.append(variable_info)
    var_infos[VariableType.SUPER_GLOBAL.value] = super_global_infos

    # GLOBAL = 'global'  声明全局的变量信息
    # (global_declaration (variable_name (name)))
    global_infos = []
    for match in matches:
        pattern_index, match_dict = match
        if 'global_declare' in match_dict:
            variable_node = match_dict['global_declare'][0]
            variable_info = parse_global_node(variable_node)
            global_infos.append(variable_info)
    var_infos[VariableType.GLOBAL.value] = global_infos

    # STATIC = 'static' 静态变量只能在函数或方法内部声明
    # (function_static_declaration (static_variable_declaration name: (variable_name (name)) value: (encapsed_string (string_content))))
    static_variable_infos = []
    for match in matches:
        pattern_index, match_dict = match
        if 'static_declare' in match_dict:
            static_node = match_dict['static_declare'][0]
            variable_info = parse_static_node(static_node)
            static_variable_infos.append(variable_info)
    var_infos[VariableType.STATIC.value] = static_variable_infos

    # PROGRAM = 'program'  全局代码内的变量信息
    gb_methods_ranges, gb_classes_ranges = get_define_nodes_ranges(dependent_infos)
    program_code_info = get_global_code_info(root_node, gb_methods_ranges + gb_classes_ranges)
    program_code_string = get_global_code_info_code(program_code_info)
    nf_code_node = load_string_to_root(parser, program_code_string)
    program_variable_infos = parse_variable_node(language, nf_code_node, OtherKeys.GLOBAL_CODE.value)
    var_infos[VariableType.PROGRAM.value] = program_variable_infos

    # LOCAL = 'local' 函数内的变量信息
    locale_variable_infos = parse_locale_variable_infos(language, root_node)
    var_infos[VariableType.LOCAL.value] = locale_variable_infos

    # 获取常量信息
    constants_infos = parse_constants_node(language, root_node)
    var_infos[VariableType.CONSTANT.value] = constants_infos

    # TODO 进一步通过行号信息 判断变量的真实信息
    # TODO 进一步通过行号信息 判断变量所处的类和函数
    return var_infos


def parse_constants_node(language, root_node: Node) -> List[Dict[str, Any]]:
    """提取 define 和 const常量定义"""
    # 查询 可能的 define函数语法 还需要过滤
    query = language.query("""
        ;define定义信息提取
        (expression_statement
            (function_call_expression)
        )@define_call
        
        ;const定义信息提取
        (const_declaration)@const_declare
    """)
    matches = query.matches(root_node)

    constants = []
    # 提取define常量信息
    for match in matches:
        pattern_index, match_dict = match
        if 'define_call' in match_dict:
            define_call_node = match_dict['define_call'][0]
            # (expression_statement (function_call_expression function: (name) arguments: (arguments (argument (string (string_content))) (argument (boolean)))))
            function_call_node = find_first_child_by_field(define_call_node, 'function_call_expression')
            function_name = get_node_filed_text(function_call_node, 'name')

            if function_name == "define":
                define_info = parse_define_node(function_call_node)
                constants.append(define_info)

        # 提取const常量信息
        if 'const_declare' in match_dict:
            const_declare_node = match_dict['const_declare'][0]
            # (const_declaration (const_element (name) (string (string_content))))
            const_info = parse_const_node(const_declare_node)
            constants.append(const_info)

    return sorted(constants, key=lambda x: x[VariableKeys.START.value])


def parse_locale_variable_infos(language, root_node: Node):
    # 先获取所有函数节点，再分别解析其中的每个节点
    function_query = language.query("""
        ; 查询全局函数定义
        (function_definition) @function.def
        ; 查询类方法定义
        (method_declaration) @method.def
        ; 匹配闭包定义
        (anonymous_function) @anonymous.def
    """)
    matches = function_query.matches(root_node)
    locale_variable_infos = []
    for match in matches:
        pattern_index, match_dict = match
        # 处理全局函数和类函数
        if 'function.def' in match_dict or 'method.def' in match_dict:
            function_node = match_dict['function.def'][0] \
                if 'function.def' in match_dict else match_dict['method.def'][0]
            method_name = get_node_filed_text(function_node, 'name')
            body_node = find_first_child_by_field(function_node, 'body')
            if body_node:
                variable_info = parse_variable_node(language, body_node, method_name)
                locale_variable_infos.append(variable_info)

        # 处理匿名函数
        if 'anonymous.def' in match_dict:
            function_node = match_dict['anonymous.def'][0]
            body_node = find_first_child_by_field(function_node, 'body')
            if body_node:
                variable_info = parse_variable_node(language, body_node, OtherKeys.ANONYMOUS.value)
                locale_variable_infos.append(variable_info)
    return locale_variable_infos


if __name__ == '__main__':
    from tree_php.php_dependent_utils import analyse_dependent_infos
    PARSER, LANGUAGE = init_php_parser()
    # php_file = r"php_demo/var_spuer_globals.php"
    # php_file = r"php_demo/var_globals.php"
    # php_file = r"php_demo/var_static.php"
    php_file = r"../php_demo/var_demo/var_all.php"
    # php_file = r"php_demo\class_1.php"
    root_node = read_file_to_root(PARSER, php_file)
    # 分析所有变量
    dependent_infos = analyse_dependent_infos(LANGUAGE, root_node)
    variables = analyze_variable_infos(PARSER, LANGUAGE, root_node, dependent_infos)
    print_json(variables)
