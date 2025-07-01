from tree_php.php_enums import ClassKeys, MethodKeys, FileInfoKeys, ImportKey, DefineKeys, DefineTypes
from tree_uitls.tree_sitter_uitls import custom_format_path
from libs_com.utils_hash import get_strs_hash


def fix_method_infos_uniq_id(method_infos: list[dict], file_path: str):
    """为方法信息填充ID数据等"""

    def calc_method_uniq_id(method_info: dict):
        m_file = method_info.get(MethodKeys.FILE.value)
        m_class = method_info.get(MethodKeys.CLASS.value)
        m_name = method_info.get(MethodKeys.NAME.value)
        m_start = method_info.get(MethodKeys.START.value)
        m_end = method_info.get(MethodKeys.END.value)
        uniq_id = get_strs_hash(f"{m_file}|{m_class}|{m_name}|{m_start}|{m_end}")
        uniq_id = f"method_{uniq_id}"
        return uniq_id

    # 循环进行信息补充
    for index, method_info in enumerate(method_infos):
        # 修复方法信息的文件路径
        method_info[MethodKeys.FILE.value] = file_path
        # 修复方法信息的唯一标识符逻辑
        method_info[MethodKeys.UNIQ_ID.value] = calc_method_uniq_id(method_info)
        # 把更新保存到原数据中
        method_infos[index] = method_info
    return method_infos


def fix_class_infos_uniq_id(class_infos: list[dict], file_path: str):
    """为生成的类信息补充数据"""

    def calc_class_uniq_id(class_info: dict):
        c_file = class_info.get(ClassKeys.FILE.value)
        c_namespace = class_info.get(ClassKeys.NAMESPACE.value)
        c_name = class_info.get(ClassKeys.NAME.value)
        c_start = class_info.get(ClassKeys.START.value)
        c_end = class_info.get(ClassKeys.END.value)
        uniq_id = get_strs_hash(f"{c_file}|{c_namespace}|{c_name}|{c_start}|{c_end}")
        uniq_id = f"class_{uniq_id}"
        return uniq_id

    for index, class_info in enumerate(class_infos):
        # 修复方法信息的文件路径
        class_info[ClassKeys.FILE.value] = file_path
        # 修复方法信息的唯一标识符逻辑
        class_info[ClassKeys.UNIQ_ID.value] = calc_class_uniq_id(class_info)
        class_infos[index] = class_info
    return class_infos


def fix_called_methods_namespace_info(called_method_infos: dict, file_path: str, namespace_infos: list[dict], import_infos: list[dict]):
    """基于native键记录和import导入信息来为被调用函数填充命名空间和文件路径信息"""
    def filter_import_files_by_line(start_line, import_infos):
        """从导入信息中获取文件信息"""
        if not import_infos:
            return []

        filtered_import_infos = [import_info
                                 for import_info in import_infos
                                 if import_info.get(ImportKey.PATH.value, None)
                                 and import_info.get(ImportKey.END.value) <= start_line]

        # 获取 filtered_import_infos 中的文件 PATH 信息路径
        import_paths = [import_info.get(ImportKey.PATH.value) for import_info in filtered_import_infos]
        return import_paths

    def filter_import_namespaces_by_line(start_line, import_infos):
        """从导入信息中获取命名空间信息"""
        if not import_infos:
            return []

        filtered_import_infos = [import_info
                                 for import_info in import_infos
                                 if import_info.get(ImportKey.NAMESPACE.value, None)
                                 and import_info.get(ImportKey.END.value) <= start_line]

        # 获取 filtered_import_infos 中的文件 PATH 信息路径
        use_namespaces = [import_info.get(ImportKey.NAMESPACE.value) for import_info in filtered_import_infos]
        return use_namespaces

    def filter_native_namespaces_by_line(start_line, namespace_infos):
        """从导入信息中获取命名空间信息"""
        if not namespace_infos:
            return []

        filtered_namespace_infos = [namespace_info
                                    for namespace_info in namespace_infos
                                    if namespace_info.get(DefineKeys.END.value) <= start_line]

        define_namespaces = [namespace_info.get(DefineKeys.NAME.value) for namespace_info in filtered_namespace_infos]
        return define_namespaces

    for called_method_info in called_method_infos:
        # 获取调用方法中的部分信息
        is_native_method = called_method_info.get(MethodKeys.IS_NATIVE.value, False)
        start_line = called_method_info.get(MethodKeys.START.value)

        if is_native_method:
            # 如果是本地方法的话 就直接设置文件路径
            called_method_info[MethodKeys.FILE.value] = file_path
            # called_method_info[MethodKeys.MAY_FILES.value] = [file_path]

            # 补充本地方法的命名空间信息 需要在找到文件对应函数的时候再进行补充 TODO 本地方法的命名空间信息应该由其他方案获取
            filter_namespaces = filter_native_namespaces_by_line(start_line, namespace_infos)
            called_method_info[MethodKeys.MAY_NAMESPACES.value] = filter_namespaces
            # if len(filter_namespaces) == 1:
            # called_method_info[MethodKeys.NAMESPACE.value] = filter_namespaces[0]
        else:
            # 否则就从导入信息中获取文件路径
            filter_files = filter_import_files_by_line(start_line, import_infos)
            called_method_info[MethodKeys.MAY_FILES.value] = filter_files
            # if len(filter_files) == 1: called_method_info[MethodKeys.FILE.value] = filter_files[0]

            filter_namespaces = filter_import_namespaces_by_line(start_line, import_infos)
            called_method_info[MethodKeys.MAY_NAMESPACES.value] = filter_namespaces
            # if len(filter_namespaces) == 1: called_method_info[MethodKeys.NAMESPACE.value] = filter_namespaces[0]
    return called_method_infos


def repair_parsed_infos_basic_info(parsed_infos:dict):
    """修复函数和类的UNIQ和FILE信息"""
    for file_path, parsed_info in parsed_infos.items():
        # 格式化路径
        file_path = custom_format_path(file_path)

        # 填充 类信息中ID和路径信息
        class_infos = parsed_info.get(FileInfoKeys.CLASS_INFOS.value, [])
        parsed_info[FileInfoKeys.CLASS_INFOS.value] = fix_class_infos_uniq_id(class_infos, file_path)

        # 填充 全局代码中的方法信息
        global_method_infos = parsed_info.get(FileInfoKeys.METHOD_INFOS.value, [])
        parsed_info[FileInfoKeys.METHOD_INFOS.value] = fix_method_infos_uniq_id(global_method_infos, file_path)

        # 填充 类信息中的方法信息
        class_infos = parsed_info.get(FileInfoKeys.CLASS_INFOS.value, [])
        for class_info in class_infos:
            class_method_infos = class_info.get(ClassKeys.METHODS.value, [])
            class_info[ClassKeys.METHODS.value] = fix_method_infos_uniq_id(class_method_infos, file_path)

        # 获取导入信息
        dependent_infos = parsed_info.get(FileInfoKeys.DEPEND_INFOS.value, {})
        import_infos = dependent_infos.get(DefineTypes.IMPORT_DEPENDS.value, [])
        # 获取命名空间的定义
        namespace_infos = dependent_infos.get(DefineTypes.DEFINE_NAMESPACES.value, [])

        # 填充 called_methods 中的部分已知信息
        global_method_infos = parsed_info.get(FileInfoKeys.METHOD_INFOS.value, [])
        for global_method_info in global_method_infos:
            # 获取调用方法信息 并逐个进行修改
            called_method_infos = global_method_info.get(MethodKeys.CALLED_METHODS.value, [])
            called_method_infos = fix_called_methods_namespace_info(called_method_infos, file_path, namespace_infos, import_infos)
            global_method_info[MethodKeys.CALLED_METHODS.value] = called_method_infos

        # 填充 class 中的 called_methods 中的部分已知信息
        class_infos = parsed_info.get(FileInfoKeys.CLASS_INFOS.value, [])
        for class_info in class_infos:
            class_method_infos = class_info.get(ClassKeys.METHODS.value, [])
            for class_method_info in class_method_infos:
                called_method_infos = class_method_info.get(MethodKeys.CALLED_METHODS.value, [])
                called_method_infos = fix_called_methods_namespace_info(called_method_infos, file_path, namespace_infos, import_infos)
                class_method_info[MethodKeys.CALLED_METHODS.value] = called_method_infos

    return parsed_infos
