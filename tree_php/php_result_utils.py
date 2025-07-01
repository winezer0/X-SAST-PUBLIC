from libs_com.utils_hash import get_path_hash
from libs_com.utils_json import dump_json
from tree_php.php_enums import FileInfoKeys, ClassKeys


def split_store_parsed_infos(parsed_infos, project_name, project_root, custom_types=None):
    """拆分并保存解析结果信息"""
    # 定义要保留的信息类型
    if custom_types:
        info_types = custom_types
    else:
        info_types = [
            FileInfoKeys.CLASS_INFOS.value,   # 暂不需要
            FileInfoKeys.VARIABLE_INFOS.value,  # 暂不需要
            FileInfoKeys.DEPEND_INFOS.value,    # 暂不需要
            FileInfoKeys.METHOD_INFOS.value,
        ]
    # 保留数据类型和文件关系
    result_info = {}
    # 按类型处理并保存，避免一次性存储所有数据
    for info_type in info_types:
        # 设置结果格式和开始相同
        a_type_infos = {}
        for relative_path, parsed_info in parsed_infos.items():
            # 初始化结果字典内容
            a_type_infos[relative_path] = {}

            # 获取当前文件的对应类型的信息
            file_type_infos = parsed_info.get(info_type, [])

            # if not file_type_infos:
            #     absolute_path = get_absolute_path(relative_path, project_root)
            #     file_size = os.path.getsize(absolute_path)
            #     print(f"文件 [{relative_path}] Size:[{file_size}] 语法解析结果中不存在 [{info_type}] 信息...")

            # 当获取方法信息时 进行额外处理
            if info_type == FileInfoKeys.METHOD_INFOS.value:
                # 当获取方法信息时，往信息中补充类方法信息
                file_class_infos = parsed_info.get(FileInfoKeys.CLASS_INFOS.value, [])
                for class_info in file_class_infos:
                    class_method_infos = class_info.get(ClassKeys.METHODS.value, [])
                    file_type_infos.extend(class_method_infos)

            if file_type_infos:
                a_type_infos[relative_path][info_type] = file_type_infos

        # 立即写入文件并释放内存
        save_file = f"{project_name}.{get_path_hash(project_root)}.parser.php.{info_type}.json"
        dump_status, dump_error = dump_json(save_file, a_type_infos)
        if dump_error:
            raise dump_error
        # 把文件名进行结果记录
        result_info[info_type] = save_file
    return result_info