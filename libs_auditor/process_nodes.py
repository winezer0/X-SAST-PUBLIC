from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox

from libs_auditor.auditor_enum import AuditStatus, AuditorKeys
from libs_com.utils_json import dump_json


def process_item_audit_status(current_item, result_hash_map, unique_key, alter_key, value):
    """递归处理所有子节点"""
    data = current_item.data(0, Qt.ItemDataRole.UserRole)
    if data:  # 如果是包含数据的节点
        # 更新数据中的人工审计状态
        data[alter_key] = AuditStatus.format(value)
        # 使用哈希映射快速找到并更新对应的结果数据
        result = result_hash_map.get(data[unique_key])
        if result is not None:
            result[alter_key] = AuditStatus.format(value)
    # 处理所有子节点
    for i in range(current_item.childCount()):
        process_item_audit_status(current_item.child(i), result_hash_map, unique_key, alter_key, value)


def batch_process_node_item_status(parent, items, value, results_data, save_file):
    """批量设置人工审计状态"""
    try:
        unique_key = AuditorKeys.AUDITOR_HASH.value
        alter_key = AuditorKeys.AUDITED.value
        # 创建一个哈希到结果数据的映射以加速查找
        hash_to_result_map = {item[unique_key]: item for item in results_data}
        # 遍历所有选中的项目（包括上级节点）
        for item in items:
            process_item_audit_status(item, hash_to_result_map, unique_key, alter_key, value)
        # 保存更改到文件
        if save_file:
            dump_status, dump_error = dump_json(save_file, results_data)
            if dump_error:
                raise dump_error

    except KeyError as e:
        QMessageBox.critical(parent, '错误', f'找不到指定的漏洞哈希值: {str(e)}')
    except Exception as e:
        QMessageBox.critical(parent, '错误', f'批量设置失败: {str(e)}')