from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, QWidgetAction, QTreeWidgetItem

from libs_auditor.auditor_enum import AuditorKeys
from libs_checker.checker_enum import CheckerKeys
from libs_rules.rules_enum import RuleKeys, SeverityLevel
from libs_verifier.verifier_enum import VerifyKeys


def create_vertical_box(label_name, edit_ele, max_height=-1, min_height=200, read_only=True):
    """创建垂直的容器"""
    container = QWidget()
    container.setStyleSheet("border: none;")
    if max_height > -1:
        container.setMaximumHeight(max_height)
    if min_height > -1:
        container.setMinimumHeight(min_height)

    vertical_layout = QVBoxLayout()
    vertical_layout.setSpacing(0)
    vertical_layout.setContentsMargins(0, 0, 0, 0)
    container.setLayout(vertical_layout)

    label_ele = QLabel(label_name)
    label_ele.setContentsMargins(0, 0, 0, 0)
    label_ele.setMaximumHeight(20)
    vertical_layout.addWidget(label_ele)

    edit_ele.setContentsMargins(0, 0, 0, 0)
    edit_ele.setReadOnly(read_only)
    vertical_layout.addWidget(edit_ele)

    return container


def create_horizon_box(label_name, edit_ele, max_height=20, min_height=20, read_only=True):
    """创建水平在一行的标签和规则"""
    edit_ele.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    edit_ele.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

    container = QWidget()
    container.setStyleSheet("border: none;")
    container.setContentsMargins(0, 0, 0, 0)
    if max_height > -1:
        container.setMaximumHeight(max_height)
    if min_height > -1:
        container.setMinimumHeight(min_height)

    horizontal_layout = QHBoxLayout()
    horizontal_layout.setSpacing(0)
    horizontal_layout.setContentsMargins(0, 0, 0, 0)
    container.setLayout(horizontal_layout)

    label_ele = QLabel(label_name)
    label_ele.setMaximumHeight(20)
    label_ele.setContentsMargins(0, 0, 0, 0)
    horizontal_layout.addWidget(label_ele)

    edit_ele.setContentsMargins(0, 0, 0, 0)
    edit_ele.setReadOnly(read_only)
    horizontal_layout.addWidget(edit_ele)

    return container


def create_horizon_box_with_combo(label_name, combo_ele, add_items,
                                  max_height=20, min_height=20, fixedWidth=80, enable=False):
    """创建带有下拉框的水平布局容器"""
    container = QWidget()
    container.setStyleSheet("border: none;")
    container.setContentsMargins(0, 0, 0, 0)
    if max_height > -1:
        container.setMaximumHeight(max_height)
    if min_height > -1:
        container.setMinimumHeight(min_height)

    horizontal_layout = QHBoxLayout()
    horizontal_layout.setSpacing(5)
    horizontal_layout.setContentsMargins(0, 0, 0, 0)
    container.setLayout(horizontal_layout)

    label_ele = QLabel(label_name)
    label_ele.setMaximumHeight(20)
    label_ele.setContentsMargins(0, 0, 0, 0)
    horizontal_layout.addWidget(label_ele)

    combo_ele.addItems(add_items)
    combo_ele.setContentsMargins(0, 0, 0, 0)
    combo_ele.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)

    if fixedWidth > 0:
        combo_ele.setFixedWidth(fixedWidth)
    combo_ele.setEnabled(enable)

    horizontal_layout.addWidget(combo_ele)

    horizontal_layout.addStretch()

    return container


def get_selected_infos(selected_items, tree_view_btn_is_checked):
    # 获取选择的节点下有的文件信息
    file_infos = []
    for item in selected_items:
        file_path = None
        line_number = None
        item_data = item.data(0, Qt.ItemDataRole.UserRole)
        item_text = item.text(0)
        parent = item.parent()

        if item_data and VerifyKeys.ORIGINAL.value in item_data:
            # 如果节点包含漏洞数据
            file_path = item_data[VerifyKeys.ORIGINAL.value][CheckerKeys.FILE.value]
            line_number = item_data[VerifyKeys.ORIGINAL.value].get(CheckerKeys.LINE.value, 1)
        elif parent and not item.childCount():
            # 如果是叶子节点
            if tree_view_btn_is_checked:
                # 按文件分组模式
                if '(' in item_text and parent:
                    file_path = parent.text(0).split(' (')[0]
            else:
                # 按风险分组模式
                if '(' in item_text:
                    file_path = item_text.split(' (')[0]

        if file_path:
            file_infos.append((file_path, line_number))
    return file_infos


def menu_add_combo_box(menu, combo, add_items, apply_func):
    combo.addItems(add_items)
    combo.setFixedWidth(80)  # 固定宽度为4个汉字
    combo.currentTextChanged.connect(apply_func)
    combo_widget = QWidget()
    combo_layout = QHBoxLayout(combo_widget)
    combo_layout.setContentsMargins(5, 2, 5, 2)
    combo_layout.addWidget(combo)
    combo_action = QWidgetAction(menu)
    combo_action.setDefaultWidget(combo_widget)
    menu.addAction(combo_action)
    return menu


def restore_tree_state(self_tree, node_key, node_value):
    """恢复树形视图的当前节点状态"""
    if not node_value:
        return

    def find_item(item):
        data = item.data(0, Qt.ItemDataRole.UserRole)

        if data and node_key in data and data[node_key] == node_value:
            self_tree.setCurrentItem(item)
            return True

        for x in range(item.childCount()):
            if find_item(item.child(x)):
                return True
        return False

    for i in range(self_tree.topLevelItemCount()):
        if find_item(self_tree.topLevelItem(i)):
            break


def save_tree_state(self_tree, node_key=AuditorKeys.AUDITOR_HASH.value):
    """保存树形视图的当前节点状态"""
    current_item = self_tree.currentItem()
    if not current_item:
        return None

    data = current_item.data(0, Qt.ItemDataRole.UserRole)
    if not data or node_key not in data:
        return None

    return data[node_key]


def create_file_based_tree(self_tree, filtered_data):
    """按文件路径分组的树形结构"""
    # 创建根节点
    root_item = QTreeWidgetItem(self_tree)
    total_vulns = len(filtered_data)
    root_item.setText(0, f'ROOT ({total_vulns})')
    root_item.setExpanded(True)

    # 按文件路径分组
    file_groups = {}
    for result in filtered_data:
        file_path = result[VerifyKeys.ORIGINAL.value][CheckerKeys.FILE.value]
        if file_path not in file_groups:
            file_groups[file_path] = {}

        vuln_type = result[VerifyKeys.ORIGINAL.value][RuleKeys.VULN_TYPE.value]
        if vuln_type not in file_groups[file_path]:
            file_groups[file_path][vuln_type] = []
        file_groups[file_path][vuln_type].append(result)

    # 对文件路径进行排序
    for file_path in sorted(file_groups.keys()):
        vuln_groups = file_groups[file_path]
        # 修改为在根节点下创建文件节点
        file_item = QTreeWidgetItem(root_item)
        total_vulns = sum(len(vulns) for vulns in vuln_groups.values())
        file_item.setText(0, f'{file_path} ({total_vulns})')
        file_item.setExpanded(True)

        # 对漏洞类型进行排序
        for vuln_type in sorted(vuln_groups.keys()):
            type_results = vuln_groups[vuln_type]
            type_item = QTreeWidgetItem(file_item)
            type_item.setText(0, f'{vuln_type} ({len(type_results)})')
            type_item.setExpanded(True)

            # 根据第一个漏洞的风险级别设置颜色
            if type_results:
                severity = type_results[0][VerifyKeys.ORIGINAL.value][RuleKeys.SEVERITY.value]
                if severity == SeverityLevel.HIGH.value:
                    type_item.setForeground(0, Qt.GlobalColor.red)
                elif severity == SeverityLevel.MEDIUM.value:
                    type_item.setForeground(0, Qt.GlobalColor.blue)
                elif severity == SeverityLevel.LOW.value:
                    type_item.setForeground(0, Qt.GlobalColor.darkGreen)

            # 创建具体漏洞节点
            if len(type_results) > 1:
                for i, result in enumerate(type_results, 1):
                    vuln_item = QTreeWidgetItem(type_item)
                    vuln_item.setText(0, f'漏洞 #{i}')
                    vuln_item.setData(0, Qt.ItemDataRole.UserRole, result)
            else:
                type_item.setData(0, Qt.ItemDataRole.UserRole, type_results[0])


def create_severity_based_tree(self_tree, filtered_data):
    """按风险级别分组的树形结构"""
    severity_groups = {risk: [] for risk in SeverityLevel.choices()}
    severity_colors = {
        SeverityLevel.HIGH.value: Qt.GlobalColor.red,
        SeverityLevel.MEDIUM.value: Qt.GlobalColor.blue,
        SeverityLevel.LOW.value: Qt.GlobalColor.darkGreen
    }

    for result in filtered_data:
        severity = result[VerifyKeys.ORIGINAL.value][RuleKeys.SEVERITY.value]
        severity_groups[severity].append(result)

    # 创建严重程度节点
    for severity, results in severity_groups.items():
        if not results:
            continue

        severity_item = QTreeWidgetItem(self_tree)
        severity_item.setText(0, f'{severity} ({len(results)})')
        severity_item.setForeground(0, severity_colors[severity])  # 设置颜色
        severity_item.setExpanded(True)

        # 按漏洞类型分组
        vuln_groups = {}
        for result in results:
            vuln_type = result[VerifyKeys.ORIGINAL.value][RuleKeys.VULN_TYPE.value]
            if vuln_type not in vuln_groups:
                vuln_groups[vuln_type] = []
            vuln_groups[vuln_type].append(result)

        # 对漏洞类型进行排序
        for vuln_type, type_results in vuln_groups.items():
            type_item = QTreeWidgetItem(severity_item)
            type_item.setText(0, f'{vuln_type} ({len(type_results)})')
            type_item.setExpanded(True)

            # 按文件名分组
            file_groups = {}
            for result in type_results:
                file_name = result[VerifyKeys.ORIGINAL.value][CheckerKeys.FILE.value]
                if file_name not in file_groups:
                    file_groups[file_name] = []
                file_groups[file_name].append(result)

            # 对文件名进行排序
            for file_name in sorted(file_groups.keys()):
                file_results = file_groups[file_name]
                file_item = QTreeWidgetItem(type_item)
                file_item.setText(0, f'{file_name} ({len(file_results)})')

                # 如果同一文件中有多个相同类型的漏洞，为每个漏洞创建一个子节点
                if len(file_results) > 1:
                    for i, result in enumerate(file_results, 1):
                        vuln_item = QTreeWidgetItem(file_item)
                        vuln_item.setText(0, f'漏洞 #{i}')
                        vuln_item.setData(0, Qt.ItemDataRole.UserRole, result)
                else:
                    file_item.setData(0, Qt.ItemDataRole.UserRole, file_results[0])
