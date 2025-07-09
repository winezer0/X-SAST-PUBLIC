from libs_auditor.auditor_enum import AuditorUIKeys, AuditorKeys
from libs_rules.rules_enum import RuleKeys
from libs_verifier.verifier_enum import VerifyKeys


def apply_filters(results_data, filters_dict: dict):
    if not results_data:
        return []

    filtered_data = results_data.copy()

    # 应用风险级别筛选
    severity_filter = filters_dict.get("severity_filter")
    if severity_filter.currentText() != AuditorUIKeys.ALL_RISKS.value:
        filtered_data = [r for r in filtered_data
                         if r[VerifyKeys.ORIGINAL.value][RuleKeys.SEVERITY.value] == severity_filter.currentText()]
    # 应用漏洞类型筛选
    vuln_type_filter = filters_dict.get("vuln_type_filter")
    if vuln_type_filter.currentText() != AuditorUIKeys.ALL_TYPES.value:
        filtered_data = [r for r in filtered_data
                         if r[VerifyKeys.ORIGINAL.value][RuleKeys.VULN_TYPE.value] == vuln_type_filter.currentText()]
    # 应用人工验证状态筛选
    audit_filter = filters_dict.get("audit_filter")
    if audit_filter.currentText() != AuditorUIKeys.ME_VERIF.value:
        filter_value = audit_filter.currentText()
        filtered_data = [r for r in filtered_data if r.get(AuditorKeys.AUDITED.value) == filter_value]
    # 应用智能验证状态筛选
    verify_filter = filters_dict.get("verify_filter")
    if verify_filter.currentText() != AuditorUIKeys.AI_VERIF.value:
        filter_value = verify_filter.currentText()
        filtered_data = [r for r in filtered_data
                         if r[VerifyKeys.PARSED.value][VerifyKeys.VERIFY.value] == filter_value]
    return filtered_data


def update_filter_text(results, vuln_filter, init_text, v_path_keys, max_size=0):
    """从结果数据获取并更新所有漏洞类型"""
    def get_nested_value(data, keys):
        for key in keys:
            if isinstance(data, dict) and key in data:
                data = data[key]
            else:
                return None
        return data

    # 更新漏洞类型筛选器的选项
    vuln_types = set()
    for result in results:
        vuln_types.add(get_nested_value(result, v_path_keys))
        # 查找最大值到以后就不找了,说明所有类型都有
        if max_size > 0 and max_size == len(vuln_types):
            break

    try:
        # 保存当前选择的值
        current_type = vuln_filter.currentText()
        # 暂时阻塞信号，防止触发不必要的事件
        vuln_filter.blockSignals(True)
        # 更新选项
        vuln_filter.clear()
        vuln_filter.addItem(init_text)
        if vuln_types:  # 只在有数据时添加选项
            vuln_filter.addItems(sorted(vuln_types))
        # 恢复之前选择的值（如果存在）
        if current_type in vuln_types or current_type == init_text:
            vuln_filter.setCurrentText(current_type)
        else:
            vuln_filter.setCurrentText(init_text)
        # 恢复信号
        vuln_filter.blockSignals(False)
    except Exception as e:
        print(f"更新[{vuln_filter}][{init_text}]类型筛选器失败: {str(e)}")
        # 确保在发生错误时恢复信号
        vuln_filter.blockSignals(False)


