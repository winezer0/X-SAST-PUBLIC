from typing import Dict

from tree_php.php_basic_create_object import query_class_object_infos
from tree_php.php_basic_define_infos import query_methods_define_infos, query_classes_define_infos, \
    query_namespace_define_infos
from tree_php.php_basic_import_infos import analyze_import_infos
from tree_php.php_enums import DefineTypes, DefineKeys


def analyse_dependent_infos(language, root_node):
    """整合获取所有基础依赖信息 用于解析函数的调用"""
    dependent_infos = {}

    # 获取所有本地函数名称和代码范围
    gb_method_define_infos = query_methods_define_infos(language, root_node)
    dependent_infos[DefineTypes.DEFINE_METHOD.value] = gb_method_define_infos

    # 获取所有类定义的代码行范围，以排除类方法 本文件不处理类方法
    gb_class_define_infos = query_classes_define_infos(language, root_node)
    dependent_infos[DefineTypes.DEFINE_CLASS.value] = gb_class_define_infos

    # 分析命名空间信息
    gb_namespace_define_infos = query_namespace_define_infos(language, root_node)
    dependent_infos[DefineTypes.DEFINE_NAMESPACES.value] = gb_namespace_define_infos

    # 分析代码内的对象创建信息
    gb_object_class_infos = query_class_object_infos(language, root_node)
    dependent_infos[DefineTypes.CREATE_OBJECT.value] = gb_object_class_infos

    # 分析依赖信息和分析导入信息 可用于方法范围限定
    gb_import_depends_infos = analyze_import_infos(language, root_node)
    dependent_infos[DefineTypes.IMPORT_DEPENDS.value] = gb_import_depends_infos

    return dependent_infos

def get_namespace_infos(dependent_infos:dict):
    gb_namespace_infos =  dependent_infos.get(DefineTypes.DEFINE_NAMESPACES.value, [])
    return  gb_namespace_infos


def spread_dependent_infos(dependent_infos:dict):
    gb_methods_infos = dependent_infos.get(DefineTypes.DEFINE_METHOD.value, [])
    gb_classes_infos =  dependent_infos.get(DefineTypes.DEFINE_CLASS.value, [])
    gb_namespace_infos =  dependent_infos.get(DefineTypes.DEFINE_NAMESPACES.value, [])
    gb_object_class_infos =  dependent_infos.get(DefineTypes.CREATE_OBJECT.value, [])
    gb_import_depends_infos =  dependent_infos.get(DefineTypes.IMPORT_DEPENDS.value, [])
    return gb_methods_infos,gb_classes_infos,gb_namespace_infos,gb_object_class_infos, gb_import_depends_infos

def get_node_infos_ranges(node_infos: Dict):
    """从提取的节点名称|起始行信息中获取 节点名称和范围元组"""
    node_ranges = set()
    for node_info in node_infos:
        node_ranges.add((node_info.get(DefineKeys.START.value), node_info.get(DefineKeys.END.value)))
    return list(node_ranges)

def get_node_infos_names_ranges(node_infos: Dict):
    """从提取的节点名称|起始行信息中获取 节点名称和范围元组"""
    node_names = set()
    node_ranges = set()
    for node_info in node_infos:
        node_names.add(node_info.get(DefineKeys.NAME.value))
        node_ranges.add((node_info.get(DefineKeys.START.value), node_info.get(DefineKeys.END.value)))
    return list(node_names), list(node_ranges)

def get_define_nodes_ranges_names(dependent_infos):
    gb_methods_infos = dependent_infos.get(DefineTypes.DEFINE_METHOD.value, [])
    gb_methods_names, gb_methods_ranges = get_node_infos_names_ranges(gb_methods_infos)

    gb_classes_infos =  dependent_infos.get(DefineTypes.DEFINE_CLASS.value, [])
    gb_classes_names, gb_classes_ranges = get_node_infos_names_ranges(gb_classes_infos)
    return gb_methods_names, gb_methods_ranges, gb_classes_names, gb_classes_ranges


def get_define_nodes_names(dependent_infos):
    gb_methods_names, _, gb_classes_names, _ = get_define_nodes_ranges_names(dependent_infos)
    return gb_methods_names, gb_classes_names


def get_define_nodes_ranges(dependent_infos):
    _, gb_methods_ranges, _, gb_classes_ranges = get_define_nodes_ranges_names(dependent_infos)
    return gb_methods_ranges, gb_classes_ranges