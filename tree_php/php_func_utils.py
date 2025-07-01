from typing import Dict, List

from tree_sitter._binding import Node
from tree_php.php_dependent_utils import spread_dependent_infos, get_node_infos_names_ranges, \
    get_define_nodes_ranges, get_define_nodes_names
from tree_php.php_const import PHP_MAGIC_METHODS, PHP_BUILTIN_FUNCTIONS
from tree_php.php_enums import MethodKeys, GlobalCode, ParameterKeys, ReturnKeys, PHPModifier, MethodType, \
    OtherKeys, DefineKeys
from tree_php.php_func_global import has_global_code, get_global_code_info, get_global_code_info_code
from tree_uitls.tree_sitter_uitls import find_first_child_by_field, get_node_filed_text, get_node_text, get_node_type, \
    find_node_info_by_line_nearest, load_string_to_root, find_children_by_field, find_node_info_by_line_in_scope, \
    get_node_first_valid_child_node_text


def query_global_methods_info(language, root_node, dependent_infos:dict):
    """查询节点中的所有全局函数定义信息 需要优化"""
    # 查询所有函数定义
    function_query = language.query("""
        ; 全局函数定义
        (function_definition) @function.def
    """)

    functions_info = []
    # 解析所有函数信息
    query_matches = function_query.matches(root_node)
    for pattern_index, match_dict in query_matches:
        if 'function.def' in match_dict:
            function_node = match_dict['function.def'][0]
            # print(f"function_node:{function_node}")
            # function_node:(function_definition

            # 从 function_node 中直接提取子节点
            method_name = get_node_filed_text(function_node, "name")
            # print(f"f_name_text:{f_name_text}")
            start_line = function_node.start_point[0]
            end_line = function_node.end_point[0]

            # 获取方法的返回信息
            body_node = find_first_child_by_field(function_node, "body")
            # print(f"f_body_node:{f_body_node}")
            return_infos = parse_return_node(body_node)
            # print(f"f_return_infos:{f_return_infos}")

            # 获取返回参数信息
            params_node = find_first_child_by_field(function_node, "parameters")
            # print(f"f_params_node:{f_params_node}")
            params_info = parse_params_node(params_node)
            # print(f"f_params_info:{f_params_info}")

            # 查询方法对应的命名空间信息
            gb_methods_infos,gb_classes_infos,gb_namespace_infos,gb_object_class_infos, gb_import_depends_infos = spread_dependent_infos(dependent_infos)
            namespace_info = find_node_info_by_line_in_scope(start_line, gb_namespace_infos, DefineKeys.START.value, DefineKeys.END.value)
            namespace = namespace_info.get(DefineKeys.NAME.value, None)

            # 解析函数体中的调用的其他方法
            called_methods = query_method_called_methods(language, body_node, dependent_infos)
            # print(f"f_called_methods:{f_called_methods}")

            method_type = guess_method_type(method_name,True,False)
            # print(f"method_type:{method_type}")

            # 总结函数方法信息
            method_info = create_method_result(method_name=method_name, start_line=start_line, end_line=end_line,
                                               namespace=namespace, object_name=None, class_name=None,
                                               fullname=method_name, visibility=None, modifiers=None,
                                               method_type=method_type, params_info=params_info,
                                               return_infos=return_infos, is_native=None,
                                               called_methods=called_methods)
            functions_info.append(method_info)
    return functions_info


def query_method_called_methods(language, body_node, dependent_infos:dict):
    """查询方法体代码内调用的其他方法信息"""
    # 预解析依赖信息
    gb_methods_infos, gb_classes_infos, gb_namespace_infos, gb_object_class_infos, gb_import_depends_infos = spread_dependent_infos(dependent_infos)
    gb_methods_names, gb_classes_names = get_define_nodes_names(dependent_infos)

    method_called_sql = """
        ;查询常规函数调用
        (function_call_expression
                function: (name)
                arguments: (arguments)
        ) @function_call

        ;查询对象方法创建
        (object_creation_expression) @object_creation

        ;查询对象方法调用
        (member_call_expression) @member_call

        ;查询静态方法调用
        (scoped_call_expression) @scoped_call
    """

    called_method_query = language.query(method_called_sql)
    matched_info = called_method_query.matches(body_node)

    called_methods = []

    # ;查询常规函数调用 function_call_expression @ function_call
    for match in matched_info:
        match_dict = match[1]
        if 'function_call' in match_dict:
            # print("开始全局函数方法调用")
            function_call_node = match_dict['function_call'][0]
            called_info = parse_function_call_node(function_call_node, gb_methods_names)
            if called_info:
                called_methods.append(called_info)

    # ;查询对象方法创建 object_creation_expression @ object_creation
    for match in matched_info:
        match_dict = match[1]
        if 'object_creation' in match_dict:
            # print("开始对象创建方法调用")
            object_creation_node = match_dict['object_creation'][0]
            called_info = parse_object_creation_node(object_creation_node, gb_classes_names, gb_object_class_infos)
            if called_info:
                called_methods.append(called_info)

    # ;查询对象方法调用 member_call_expression @ member_call
    for match in matched_info:
        match_dict = match[1]
        if 'member_call' in match_dict:
            # print("开始解析成员方法调用")
            object_method_node = match_dict['member_call'][0]
            called_info = parse_object_member_call_node(object_method_node, gb_classes_infos, gb_object_class_infos)
            if called_info:
                called_methods.append(called_info)

    # ;查询静态方法调用 scoped_call_expression @ scoped_call
    for match in matched_info:
        match_dict = match[1]
        if 'scoped_call' in match_dict:
            # print("开始解析静态方法调用")
            static_method_node = match_dict['scoped_call'][0]
            called_info = parse_static_method_call_node(static_method_node, gb_classes_infos, gb_object_class_infos)
            if called_info:
                called_methods.append(called_info)
    return called_methods


def is_static_method(modifiers):
    if modifiers and 'static' in modifiers:
        return True
    return False


def get_class_method_fullname(class_name, method_name, is_static):
    concat = "::" if is_static or method_name in PHP_MAGIC_METHODS else "->"
    if class_name:
        fullname = f"{class_name}{concat}{method_name}"
    else:
        fullname = f"{method_name}"
    return fullname


def create_method_result(method_name, start_line, end_line, namespace, object_name, class_name, fullname, visibility,
                         modifiers, method_type, params_info, return_infos, is_native, called_methods, uniq_id=None,
                         method_file=None):
    """创建方法信息的综合返回结果"""
    return {
        MethodKeys.UNIQ_ID.value: uniq_id, # 后续等信息填充完毕再主动生成uniq_id
        MethodKeys.FILE.value: method_file, # 后续再进行文件信息补充 此处主要是占位

        MethodKeys.NAME.value: method_name,
        MethodKeys.START.value: start_line,
        MethodKeys.END.value: end_line,

        MethodKeys.NAMESPACE.value: namespace,
        MethodKeys.OBJECT.value: object_name,  # 普通函数没有对象
        MethodKeys.CLASS.value: class_name,  # 普通函数不属于类
        MethodKeys.FULLNAME.value: fullname,  # 普通函数的全名就是函数名

        MethodKeys.VISIBILITY.value: visibility,  # 普通函数默认public
        MethodKeys.MODIFIERS.value: modifiers,  # 普通函数访问属性 为空

        MethodKeys.METHOD_TYPE.value: method_type,  # 本文件定义的 普通全局
        MethodKeys.PARAMS.value: params_info,  # 动态解析 函数的参数信息
        MethodKeys.RETURNS.value: return_infos,  # 动态解析 函数的返回值类型

        MethodKeys.IS_NATIVE.value: is_native,  # 被调用的函数是否在本文件内,仅当本函数是被调用函数时有值
        MethodKeys.CALLED_METHODS.value: called_methods,  # 动态解析 函数类调用的其他方法
    }


def parse_arguments_node(arguments_node: Node):
    """分析被调用函数的参数信息"""
    def parse_argument_node_type(argument_node: Node):
        """获取argument节点的类型 """
        # 查找类型信息 argument_node:(argument (encapsed_string (string_content)))
        # 定义类型映射表
        type_mapping = {
            "string": "string",
            "encapsed_string": "string",
            "integer": "integer",
            "variable_name": "variable_name"
        }
        # 遍历类型映射表，查找第一个匹配的类型
        for field, type_name in type_mapping.items():
            if find_first_child_by_field(argument_node, field):
                return type_name
        # 如果未找到任何匹配类型，返回 UNKNOWN
        return "UNKNOWN"


    args = []
    # print(f"args_node:{arguments_node}")
    # args_node:(arguments (argument (string (string_content))))

    argument_nodes = find_children_by_field(arguments_node, 'argument')
    for arg_index, argument_node in enumerate(argument_nodes):
        argument_name = get_node_text(argument_node) #参数内容
        argument_type = parse_argument_node_type(argument_node)

        argument_info = {
                ParameterKeys.INDEX.value: arg_index,
                ParameterKeys.VALUE.value: argument_name,
                ParameterKeys.TYPE.value: argument_type,
                ParameterKeys.NAME.value: None,
                ParameterKeys.DEFAULT.value: None,
            }
        args.append(argument_info)
    return args


def parse_return_node(body_node: Node):
    """查找方法的返回信息"""

    def parse_return_node(return_node: Node):
        return_info_list = []
        variable_nodes = find_children_by_field(return_node, "variable_name")
        for variable_node in variable_nodes:
            node_text = get_node_text(variable_node)
            return_info = {
                ReturnKeys.NAME.value: None,
                ReturnKeys.VALUE.value: None,
                ReturnKeys.TYPE.value: node_text,
                ReturnKeys.START.value: variable_node.start_point[0],
                ReturnKeys.END.value: variable_node.end_point[0],
            }
            return_info_list.append(return_info)
        return return_info_list

    return_nodes = find_children_by_field(body_node, "return_statement")
    return_infos = [x for return_node in return_nodes for x in parse_return_node(return_node)]
    return return_infos


def parse_params_node(params_node: Node):
    # 获取参数列表节点
    parameters = []
    if params_node:
        for param_index, param_node in enumerate(params_node.children):
            if param_node.type == 'simple_parameter':
                # 获取默认值
                default_value_node = find_first_child_by_field(param_node, 'default_value')
                parameter_info = {
                    ParameterKeys.INDEX.value: param_index,
                    ParameterKeys.NAME.value: get_node_filed_text(param_node, 'name'),
                    ParameterKeys.TYPE.value: get_node_type(default_value_node),
                    ParameterKeys.DEFAULT.value: get_node_text(default_value_node),
                    ParameterKeys.VALUE.value: None,
                }
                parameters.append(parameter_info)
    return parameters


def parse_function_call_node(function_call_node:Node, gb_methods_names: List):
    """解析函数调用节点"""
    # print(f"function_call_node:{function_call_node}")
    # (function_call_expression function: (name) arguments: (arguments (argument (string (string_content)))))
    method_name = get_node_filed_text(function_call_node, 'name')
    start_line = function_call_node.start_point[0]
    end_line = function_call_node.end_point[0]

    # 定义是否是本文件函数
    is_native = method_name in gb_methods_names
    # 定义获取函数类型
    method_type = guess_method_type(method_name, is_native, False)
    # print(f"method_type:{method_name} is{method_type}  native:{is_native}")
    if method_type == MethodType.BUILTIN.value:
        return None

    # 解析参数信息
    arguments_node = find_first_child_by_field(function_call_node, 'arguments')
    arguments_info = parse_arguments_node(arguments_node)

    return create_method_result(method_name=method_name, start_line=start_line, end_line=end_line,
                                namespace=None, object_name=None, class_name=None, fullname=method_name,
                                visibility=None, modifiers=None, method_type=method_type, params_info=arguments_info,
                                return_infos=None, is_native=is_native, called_methods=None)


def parse_object_creation_node(object_creation_node: Node, classes_names: List, gb_object_class_infos: List[Dict]):
    """解析对象创建节点"""
    # b'new UserDemo()' # (object_creation_expression (name) (arguments)
    # object_creation_node:(object_creation_expression (name) (arguments (argument (encapsed_string (string_content)))))
    class_name = get_node_filed_text(object_creation_node, 'name')
    if not class_name:
        class_name = get_node_first_valid_child_node_text(object_creation_node)

    method_name = '__construct'
    start_line = object_creation_node.start_point[0]
    end_line = object_creation_node.end_point[0]
    # print(f"class_name:{class_name} ｛method_name｝ {start_line} {end_line}")

    # 定义是否是本文件定义的class
    is_native = class_name in classes_names # 构造方法 可以直接判断
    # print(f"is_native_class:{is_native}")

    # 定义获取函数类型
    method_type = guess_method_type(method_name, is_native, True)
    # print(f"method_type:{method_name} is {method_type}  native:{is_native} ")
    if method_type == MethodType.BUILTIN.value:
        return None

    fullname = f"{class_name}::{method_name}"
    # print("fullname:", fullname)

    # 解析参数信息
    arguments_node = find_first_child_by_field(object_creation_node, 'arguments')
    arguments_info = parse_arguments_node(arguments_node)
    # print(f"arguments_info:{arguments_info}")

    # 查找对应的对象信息 虽然没啥用
    object_name = find_object_from_object_class_infos(class_name, gb_object_class_infos, start_line, end_line)

    return create_method_result(method_name=method_name, start_line=start_line, end_line=end_line,
                                namespace=None, object_name=object_name, class_name=class_name, fullname=fullname,
                                visibility=None, modifiers=None, method_type=method_type, params_info=arguments_info,
                                return_infos=None, is_native=is_native, called_methods=None)


def find_object_from_object_class_infos(class_name, gb_object_class_infos, start_line, end_line):
    """从对象创建信息中查找类对应的对象信息"""
    object_name = None
    for object_class_info in gb_object_class_infos:
        # {'OBJECT': '$user2', 'CLASS': 'UserDemo', 'START': 16, 'END': 16}
        if object_class_info.get(MethodKeys.CLASS.value) == class_name:
            if (start_line == object_class_info.get(MethodKeys.START.value)
                    and end_line == object_class_info.get(MethodKeys.END.value)):
                object_name = object_class_info.get(MethodKeys.OBJECT.value)
                break
    return object_name


def parse_object_member_call_node(object_method_node: Node, gb_classes_infos, gb_object_class_infos: Dict):
    # print(f"object_method_node:{object_method_node}")
    # object_method_node:(member_call_expression object: (variable_name (name)) name: (name) arguments: (arguments (argument (encapsed_string (string_content)))))

    method_name = get_node_filed_text(object_method_node, 'name')
    # print(f"method_name:{method_name}") # method_name:classMethod
    start_line = object_method_node.start_point[0]
    end_line = object_method_node.end_point[0]

    # 获取对象名称
    object_name = get_node_filed_text(object_method_node, 'variable_name')
    if not object_name:
        # 对于对象是 object的函数的情况进行优化
        # (member_call_expression object: (subscript_expression (variable_name (name)) (string (string_content))) name: (name) arguments: (arguments (argument
        object_name = get_node_first_valid_child_node_text(object_method_node)

    # 定义是否是本文件函数
    is_native, class_name = guess_called_object_is_native(object_name, start_line, gb_classes_infos, gb_object_class_infos)
    if not class_name:
        # TODO 需要处理多箭头的对象方法调用问题
        # 比较复杂的情况 获取不到类名时正常的
        # TODO 需要从变量、全局变量中寻找对象的来源信息
        # print(f"没有从本文件创建对象中找到对象[{object_name}]对应的类创建信息...")
        pass

    # 定义获取函数类型
    method_type = guess_method_type(method_name, is_native, True)
    # print(f"method_type:{method_name} is {method_type}  native:{is_native}")
    if method_type == MethodType.BUILTIN.value:
        return None

    # full_name 首先判断是不是显式的魔术方法调用 静态方法和构造方法在其他函数已经实现
    concat = "::" if method_type == MethodType.MAGIC_METHOD.value else "->"
    method_fullname = f"{class_name}{concat}{method_name}" if class_name else f"{object_name}{concat}{method_name}"

    # 解析参数信息
    arguments_node = find_first_child_by_field(object_method_node, 'arguments')
    arguments_info = parse_arguments_node(arguments_node)
    # print(f"arguments_info:{arguments_info}")

    return create_method_result(method_name=method_name, start_line=start_line, end_line=end_line,
                                namespace=None, object_name=object_name, class_name=class_name,
                                fullname=method_fullname, visibility=None, modifiers=None, method_type=method_type,
                                params_info=arguments_info, return_infos=None, is_native=is_native, called_methods=None)


def parse_static_method_call_node(object_method_node: Node, gb_classes_infos, gb_object_class_infos: Dict):
    # print(f"parse_static_method_call_node:{object_method_node}")
    # parse_static_method_call_node:(scoped_call_expression scope: (name) name: (name) arguments: (arguments (argument (encapsed_string (string_content)))))

    method_name = get_node_filed_text(object_method_node, 'name')
    # print(f"method_name:{method_name}")  # method_name:classMethod
    start_line = object_method_node.start_point[0]
    end_line = object_method_node.end_point[0]

    # 获取静态方法的类名称
    class_name = get_node_filed_text(object_method_node, 'scope')
    if not class_name:
        class_name = get_node_first_valid_child_node_text(object_method_node)
    # print(f"class_name:{class_name}")  # object_name:MyClass

    # 判断静态方法是否是 对象调用 较少见
    if str(class_name).startswith("$"):
        object_name = class_name
        is_native, class_name = guess_called_object_is_native(object_name, start_line, gb_classes_infos, gb_object_class_infos)
    else:
        object_name = class_name
        gb_classes_names, gb_classes_ranges = get_node_infos_names_ranges(gb_classes_infos)
        is_native = class_name in gb_classes_names

    # 定义获取函数类型
    method_type = guess_method_type(method_name, is_native, True)
    # print(f"method_type:{method_name} is {method_type}  native:{is_native}")
    if method_type == MethodType.BUILTIN.value:
        return None

    # full_name 原则而言查找的就是静态方法 TODO 如果是本文件函数的话 后续最好需要搜索对应类信息
    method_fullname = f"{class_name}::{method_name}"

    # 解析参数信息
    arguments_node = find_first_child_by_field(object_method_node, 'arguments')
    arguments_info = parse_arguments_node(arguments_node)
    # print(f"arguments_info:{arguments_info}")

    # 补充静态方法的特殊描述符号
    modifiers = [PHPModifier.STATIC.value]
    return create_method_result(method_name=method_name, start_line=start_line, end_line=end_line,
                                namespace=None, object_name=object_name, class_name=class_name,
                                fullname=method_fullname, visibility=None, modifiers=modifiers, method_type=method_type,
                                params_info=arguments_info, return_infos=None, is_native=is_native, called_methods=None)


def parse_global_code_called_methods(parser, language, root_node, dependent_infos:dict):
    """查询全部代码调用的函数信息 并且只保留其中不属于函数和类的部分"""
    gb_methods_ranges, gb_classes_ranges = get_define_nodes_ranges(dependent_infos)

    if not has_global_code(root_node, gb_methods_ranges + gb_classes_ranges):
        # print("文件中不存在全局性代码...")
        return None

    # print("开始进行全局性代码额外处理...")
    # 方案1 获取所有代码信息 然后排除其中的 函数定义范围和类定义范围信息 再进行 代码解析
    global_code_info = get_global_code_info(root_node, gb_methods_ranges + gb_classes_ranges)
    # print(f"global_code_info:{global_code_info}")

    nf_name_txt = OtherKeys.GLOBAL_CODE.value
    nf_start_line = global_code_info[GlobalCode.START.value]
    nf_end_line = global_code_info[GlobalCode.END.value]

    # 解析全局代码数据
    nf_global_code = get_global_code_info_code(global_code_info)
    if not nf_global_code:
        return None

    nf_code_node = load_string_to_root(parser, nf_global_code)
    # 查询调用的方法信息
    nf_code_called_methods = query_method_called_methods(language, nf_code_node, dependent_infos)

    # 如果没有找到信息就直接返回None
    if not nf_code_called_methods:
        return None

    return create_method_result(method_name=nf_name_txt, start_line=nf_start_line, end_line=nf_end_line,
                                namespace=None, object_name=None, class_name=None, fullname=nf_name_txt,
                                visibility=None, modifiers=None, method_type=None, params_info=None, return_infos=None,
                                is_native=None, called_methods=nf_code_called_methods)

def guess_called_object_is_native(object_name, object_line, gb_classes_infos, gb_object_class_infos: List[Dict]):
    """从本文件中初始化类信息字典分析对象属于哪个类"""
    gb_classes_names, gb_classes_ranges = get_node_infos_names_ranges(gb_classes_infos)
    if object_name in gb_classes_names:
        # 对象名在本地类方法中, 说明对象属于全局方法调用
        return True, object_name

    if "$this" in object_name:
        # 表名就是本class的方法 TODO 目前不能查询时哪个类 可以通过 gb_classes_names 的范围进行查询
        nearest_class_info = find_node_info_by_line_nearest(object_line, gb_classes_infos, start_key=DefineKeys.START.value)
        nearest_class_name = nearest_class_info.get(DefineKeys.NAME.value) if  nearest_class_info else None
        return True, nearest_class_name

    # 通过对象名称 初次筛选获取命中的类信息
    # [{'METHOD_OBJECT': '$myClass', 'METHOD_CLASS': 'MyClass', 'METHOD_START_LINE': 5},,,]
    filtered_object_infos = []
    if object_name:
        for object_class_info in gb_object_class_infos:
            if object_name == object_class_info.get(MethodKeys.OBJECT.value, None):
                # print(f"找到对象{object_name}对应的原始类信息:{object_class_info}")
                filtered_object_infos.append(object_class_info)
                break

    if not filtered_object_infos:
        return False, None

    # 进一步筛选最近的类创建信息
    nearest_class_info = find_node_info_by_line_nearest(object_line, filtered_object_infos, start_key=MethodKeys.START.value)
    nearest_class_name = nearest_class_info.get(MethodKeys.CLASS.value)

    if nearest_class_name in gb_classes_names:
        return True, nearest_class_name
    else:
        return False, nearest_class_name


def guess_method_type(method_name, is_native_method_or_class, is_class_method):
    """根据被调用的函数完整信息猜测函数名"""
    if is_class_method:
        method_type = MethodType.CLASS_METHOD.value
        # 判断方法是否是php类的内置构造方法
        if method_name == '__construct':
            method_type = MethodType.CONSTRUCT.value
        # 判断方法是否是php类的内置魔术方法
        elif method_name in PHP_MAGIC_METHODS and is_native_method_or_class is False:
            method_type = MethodType.MAGIC_METHOD.value
    else:
        method_type = MethodType.GENERAL.value
        # 判断方法是否是php内置方法
        if method_name in PHP_BUILTIN_FUNCTIONS and is_native_method_or_class is False:
            method_type = MethodType.BUILTIN.value
        # 判断方法是否时动态调用方法
        elif method_name.startswith("$"):
            method_type = MethodType.DYNAMIC.value
    return method_type
