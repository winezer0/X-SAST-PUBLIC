import copy
from collections import defaultdict

from tree_php.php_const import PHP_MAGIC_METHODS
from tree_php.php_enums import ClassKeys, MethodKeys, FileInfoKeys


def get_all_global_methods(parsed_infos: dict):
    """获取解析结果中的所有全局方法信息"""
    all_method_infos = []
    for file_path, parsed_info in parsed_infos.items():
        # 1.1、获取文件中的全局方法
        global_method_infos = parsed_info.get(FileInfoKeys.METHOD_INFOS.value, [])
        all_method_infos.extend(global_method_infos)
    return all_method_infos


def get_all_class_methods(parsed_infos: dict):
    """获取解析结果中的所有类方法信息"""
    all_method_infos = []
    for file_path, parsed_info in parsed_infos.items():
        for class_info in parsed_info.get(FileInfoKeys.CLASS_INFOS.value, []):
            class_method_infos = class_info.get(ClassKeys.METHODS.value, [])
            all_method_infos.extend(class_method_infos)
    return all_method_infos


def get_all_class_infos(parsed_infos: dict):
    """获取解析结果中的所有类信息"""
    all_class_infos = []
    for file_path, parsed_info in parsed_infos.items():
        class_infos = parsed_info.get(FileInfoKeys.CLASS_INFOS.value, [])
        all_class_infos.extend(class_infos)
    return all_class_infos


def build_method_name_method_ids_map(all_method_infos: list[dict]):
    """整理 method name -> method id 的映射 ｛方法名称:[函数ID,函数ID]｝"""
    method_name_method_ids_map = defaultdict(list)  # 默认值为列表 无需初始化
    for method_info in all_method_infos:
        method_name = method_info.get(MethodKeys.NAME.value)
        method_uniq_id = method_info.get(MethodKeys.UNIQ_ID.value)
        method_name_method_ids_map[method_name].append(method_uniq_id)
    return method_name_method_ids_map


def build_method_id_method_info_map(all_method_infos: dict):
    """整理 method id -> method info 的映射 ｛函数ID:方法信息｝"""
    method_id_method_info_map = {}
    for method_info in all_method_infos:
        method_uniq_id = method_info.get(MethodKeys.UNIQ_ID.value)

        # 不需要保留 CALLED_METHODS 信息
        copy_method_info = copy.deepcopy(method_info)
        copy_method_info.pop(MethodKeys.CALLED_METHODS.value)
        method_id_method_info_map[method_uniq_id] = copy_method_info
    return method_id_method_info_map


def build_class_id_class_info_map(all_class_infos: dict):
    """创建class id -> class info 的映射  ｛类ID:类信息｝"""
    class_id_class_info_map = {}
    for class_info in all_class_infos:
        class_uniq_id = class_info.get(ClassKeys.UNIQ_ID.value)

        # 不需要保留 CALLED_METHODS 信息
        copy_class_info = copy.deepcopy(class_info)
        for copy_method_info in copy_class_info.get(ClassKeys.METHODS.value, []):
            copy_method_info.pop(MethodKeys.CALLED_METHODS.value)
        class_id_class_info_map[class_uniq_id] = copy_class_info
    return class_id_class_info_map


def build_class_method_fullname_class_ids_map(all_class_infos: dict):
    """整理 class method name -> class id 的映射 ｛类方法名称:[类ID,类ID]｝"""
    method_name_class_ids_map = defaultdict(list)  # 默认值为列表 无需初始化
    for class_info in all_class_infos:
        class_uniq_id = class_info.get(ClassKeys.UNIQ_ID.value)
        for method_info in class_info.get(ClassKeys.METHODS.value, []):
            method_fullname = method_info.get(MethodKeys.FULLNAME.value)
            method_name_class_ids_map[method_fullname].append(class_uniq_id)
    return method_name_class_ids_map


def build_class_method_name_class_ids_map(all_class_infos: dict):
    """整理 class method name -> class id 的映射 ｛类方法名称:[类ID,类ID]｝"""
    method_name_class_ids_map = defaultdict(list)  # 默认值为列表 无需初始化
    for class_info in all_class_infos:
        class_uniq_id = class_info.get(ClassKeys.UNIQ_ID.value)
        for method_info in class_info.get(ClassKeys.METHODS.value, []):
            method_name = method_info.get(MethodKeys.NAME.value)
            if method_name not in PHP_MAGIC_METHODS:
                method_name_class_ids_map[method_name].append(class_uniq_id)
    return method_name_class_ids_map


def build_class_name_class_ids_map(all_class_infos: dict):
    """创建class name -> class ids 的映射 ｛类名称:[类ID,类ID]｝"""
    class_name_class_ids_map = defaultdict(list)  # 默认值为列表 无需初始化
    for class_info in all_class_infos:
        class_name = class_info.get(ClassKeys.NAME.value)
        class_uniq_id = class_info.get(ClassKeys.UNIQ_ID.value)
        class_name_class_ids_map[class_name].append(class_uniq_id)
    return class_name_class_ids_map


def build_class_namespace_class_ids_map(all_class_infos: dict):
    """创建class namespace -> class ids 的映射 ｛类命名空间:[类ID,类ID]｝"""
    class_namespace_class_ids_map = defaultdict(list)  # 默认值为列表 无需初始化
    for class_info in all_class_infos:
        class_namespace = class_info.get(ClassKeys.NAMESPACE.value)
        class_uniq_id = class_info.get(ClassKeys.UNIQ_ID.value)
        class_namespace_class_ids_map[class_namespace].append(class_uniq_id)
    return class_namespace_class_ids_map

