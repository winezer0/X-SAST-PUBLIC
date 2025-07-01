import sys

from tree_sitter._binding import Node

from tree_php.php_enums import PropertyKeys, ClassKeys, PHPModifier, DefineKeys
from tree_php.php_func_utils import query_method_called_methods, is_static_method, get_class_method_fullname, \
    create_method_result, \
    parse_return_node, parse_params_node, guess_method_type
from tree_uitls.tree_sitter_uitls import find_first_child_by_field, get_node_filed_text, find_children_by_field, \
    find_node_info_by_line_in_scope
from tree_php.php_dependent_utils import spread_dependent_infos

def parse_class_or_method_node_modifier_infos(any_none:Node):
    """获取指定节点（方法|属性|类）的特殊描述符信息"""
    modifiers = []
    if find_first_child_by_field(any_none, 'abstract_modifier'):
        modifiers.append(PHPModifier.ABSTRACT.value)
    if find_first_child_by_field(any_none, 'final_modifier'):
        modifiers.append(PHPModifier.FINAL.value)
    if find_first_child_by_field(any_none, 'readonly_modifier'):
        modifiers.append(PHPModifier.READONLY.value)
    if find_first_child_by_field(any_none, 'static_modifier'):
        modifiers.append(PHPModifier.STATIC.value)
    return modifiers

def creat_class_result(class_name, namespace, start_line, end_line, visibility, modifiers, extends,
                       interfaces, properties, is_interface, class_methods, uniq_id=None, class_file=None):
    class_info = {
        ClassKeys.UNIQ_ID.value: uniq_id,
        ClassKeys.FILE.value: class_file,
        ClassKeys.NAME.value: class_name,
        ClassKeys.NAMESPACE.value: namespace,

        ClassKeys.START.value: start_line,
        ClassKeys.END.value: end_line,

        ClassKeys.VISIBILITY.value: visibility,  # 默认可见性 Php类没有可见性
        ClassKeys.MODIFIERS.value: modifiers, # 特殊属性

        ClassKeys.EXTENDS.value: extends,
        ClassKeys.INTERFACES.value: interfaces,
        ClassKeys.PROPERTIES.value: properties,

        ClassKeys.IS_INTERFACE.value: is_interface,

        ClassKeys.METHODS.value: class_methods,
    }
    return class_info


def parse_class_properties_node(class_node):
    """获取类节内部的属性定义信息"""
    def parse_class_property_node(property_node: Node) -> dict:
        """解析单个属性声明节点的信息。 """
        # property_node:(property_declaration (visibility_modifier) (static_modifier)
        # (property_element name: (variable_name (name)) default_value: (encapsed_string (string_content))))
        # 初始化属性信息
        # 获取属性元素节点
        property_element_node = find_first_child_by_field(property_node, 'property_element')
        property_info = {
            PropertyKeys.NAME.value: get_node_filed_text(property_element_node, 'name'),
            PropertyKeys.DEFAULT.value: get_node_filed_text(property_element_node, 'default_value'),

            PropertyKeys.START.value: property_node.start_point[0],
            PropertyKeys.END.value: property_node.end_point[0],

            PropertyKeys.VISIBILITY.value: get_node_filed_text(property_node, 'visibility_modifier'),
            PropertyKeys.TYPE.value: get_node_filed_text(property_node, 'primitive_type'),
            PropertyKeys.MODIFIERS.value: parse_class_or_method_node_modifier_infos(property_node),
        }
        # 添加行属性
        return property_info

    # 获取请求体部分
    body_node = find_first_child_by_field(class_node, "body")
    props_nodes = find_children_by_field(body_node, 'property_declaration')
    properties = [parse_class_property_node(prop_node) for prop_node in props_nodes]
    return properties


def parse_class_methods_node(language, class_node: Node, namespace: str, dependent_infos: dict):
    """获取类内部定义的方法节点信息 """
    # body_node:(declaration_list
    # (declaration_list
    # (property_declaration (visibility_modifier) (readonly_modifier) type: (primitive_type) (property_element name: (variable_name (name)) default_value: (integer)))
    # (property_declaration (visibility_modifier) (readonly_modifier) type: (primitive_type) (property_element name: (variable_name (name)) default_value: (integer)))
    # (method_declaration (visibility_modifier) name: (name) parameters: (formal_parameters) body: (compound_statement (echo_statement (encapsed_string (string_content) (escape_sequence)))))
    # (method_declaration (visibility_modifier) name: (name) parameters: (formal_parameters) body: (compound_statement (echo_statement (encapsed_string (string_content) (escape_sequence))))))

    def parse_class_method_node(language, method_node, class_name, namespace, dependent_infos: dict):
        # print(f"method_node:{method_node}")
        method_name = get_node_filed_text(method_node, 'name')
        start_line = method_node.start_point[0]
        end_line = method_node.end_point[0]
        parameters_node = method_node.child_by_field_name('parameters')
        params_info = parse_params_node(parameters_node)
        called_methods = query_method_called_methods(language, method_node, dependent_infos)
        visibility = get_node_filed_text(method_node, 'visibility_modifier')
        modifiers = parse_class_or_method_node_modifier_infos(method_node)
        method_type = guess_method_type(method_name, is_native_method_or_class=True, is_class_method=True)
        fullname = get_class_method_fullname(class_name, method_name, is_static_method(modifiers))
        body_node = find_first_child_by_field(method_node, 'body')
        return_infos = parse_return_node(body_node)
        method_info = create_method_result(method_name=method_name, start_line=start_line, end_line=end_line,
                                           namespace=namespace, object_name=None, class_name=class_name,
                                           fullname=fullname, visibility=visibility, modifiers=modifiers,
                                           method_type=method_type, params_info=params_info, return_infos=return_infos,
                                           is_native=None, called_methods=called_methods)
        return method_info

    # 获取请求体部分
    class_name = get_node_filed_text(class_node, 'name')
    body_node = find_first_child_by_field(class_node, "body")

    # 获取方法属性
    method_info = []
    method_nodes = find_children_by_field(body_node, 'method_declaration')
    for method_node in method_nodes:
        property_info = parse_class_method_node(language, method_node, class_name, namespace, dependent_infos)
        method_info.append(property_info)
    return method_info


def parse_class_define_info(language, class_define_node, is_interface, dependent_infos:dict):
    """解析类定义信息，使用 child_by_field_name 提取字段。"""
    # 预解析依赖信息
    gb_methods_infos,gb_classes_infos,gb_namespace_infos,gb_object_class_infos, gb_import_depends_infos = spread_dependent_infos(dependent_infos)

    # 获取类名
    class_name = get_node_filed_text(class_define_node, 'name')
    if not class_name:
        print(f"发现未预期的情况, 获取class_define_node中的节点名称失败:{class_define_node.text}")
        sys.exit(1)

    # 获取类的起始和结束行号
    start_line = class_define_node.start_point[0]
    end_line = class_define_node.end_point[0]

    # 反向查询命名空间信息
    namespace_info = find_node_info_by_line_in_scope(start_line, gb_namespace_infos, DefineKeys.START.value, DefineKeys.END.value)
    namespace = namespace_info.get(DefineKeys.NAME.value, None)

    # 获取继承信息
    extends = parse_class_define_extends_infos(class_define_node)
    # 获取接口信息
    implements_infos = parse_class_define_implements_infos(class_define_node)

    # 获取类修饰符
    modifiers = parse_class_or_method_node_modifier_infos(class_define_node)

    # 获取类的可见性 # 在 PHP 中，类的声明本身没有可见性修饰符
    visibility = get_node_filed_text(class_define_node, 'visibility_modifier')

    # 添加类属性信息
    properties = parse_class_properties_node(class_define_node)

    # 添加类方法信息
    class_methods = parse_class_methods_node(language, class_define_node, namespace, dependent_infos)

    return creat_class_result(class_name=class_name, namespace=namespace, start_line=start_line, end_line=end_line,
                              visibility=visibility, modifiers=modifiers, extends=extends, interfaces=implements_infos,
                              properties=properties, is_interface=is_interface, class_methods=class_methods)


def parse_class_define_implements_infos(class_define_node):
    """从类定义节点中获取实现接口信息"""
    implements_infos = None
    interface_clause_node = find_first_child_by_field(class_define_node, 'class_interface_clause')
    if interface_clause_node:
        implements_infos = find_children_by_field(interface_clause_node, "name")
        implements_infos = [{node.text.decode('utf-8'): None} for node in implements_infos]
        # implements_nodes:[{'MyInterface': None}, {'MyInterfaceB': None}]
        implements_infos = implements_infos
    return implements_infos


def parse_class_define_extends_infos(class_define_node):
    """从类定义节点中获取继承信息"""
    extends_infos = None
    base_clause_node = find_first_child_by_field(class_define_node, 'base_clause')
    if base_clause_node:
        extends_infos = find_children_by_field(base_clause_node, "name")
        extends_infos = [{node.text.decode('utf-8'): None} for node in extends_infos]
        # extends_infos:[{'MyAbstractClassA': None}, {'MyAbstractClassB': None}]
    return extends_infos

