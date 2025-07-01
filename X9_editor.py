import os.path
import re
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                             QHBoxLayout, QMessageBox, QInputDialog, QMenu, QTreeWidget, QSplitter)
from PyQt6.QtWidgets import QFileDialog
from PyQt6.QtWidgets import QTreeWidgetItem

from libs_com.utils_yaml import load_yaml, save_yaml_format
from libs_editor.editor_form import RulesForm
from libs_editor.editor_toolbar import RulesToolBar
from libs_rules.rules_data import fixed_rules
from libs_rules.rules_enum import RuleKeys, SeverityLevel, VulnType
from libs_rules.rules_utils import sort_lang_rules, find_lang_dup_rule
from libs_rules.rules_valid import check_all_rule_regex
from setting import DEF_CONFIG_RULES


class RulesEditor(QMainWindow):
    def __init__(self, rules_file):
        super().__init__()
        self.rules_file = rules_file
        self.rules_data = None
        self.__init_ui()

    def __init_ui(self):
        self.setWindowTitle('SAST Rules Editor')
        self.setGeometry(100, 100, 800, 600)
        # 配置tool_bar
        # self.__toolbar_setup()
        self.toolbar = RulesToolBar(self)
        self.addToolBar(self.toolbar)
        # 连接信号
        self.toolbar.save_action.triggered.connect(self.save_config)
        self.toolbar.reload_action.triggered.connect(self.quick_load_rules)
        self.toolbar.check_action.triggered.connect(self.check_all_rules)
        self.toolbar.check_dup_action.triggered.connect(self.check_duplicate_rules)  # 添加这行
        self.toolbar.disable_action.triggered.connect(lambda: self.toggle_all_rules(False))
        self.toolbar.enable_action.triggered.connect(lambda: self.toggle_all_rules(True))
        self.toolbar.open_action.triggered.connect(self.open_config_file)
        self.toolbar.sort_action.triggered.connect(self.sort_rules)  # 添加这行

        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QHBoxLayout()
        main_widget.setLayout(layout)

        # 创建分割器
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # 左侧规则树
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        left_widget.setMinimumWidth(350)   # 设置最小宽度，防止过度收缩

        # 创建规则树
        self.tree = QTreeWidget()
        self.tree.setHeaderLabel('规则列表')
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.itemClicked.connect(self.on_item_selected)
        self.tree.currentItemChanged.connect(self.on_item_selected)  # 实现按键触发更新
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        left_layout.addWidget(self.tree)

        # 右侧编辑区
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)

        # 将左右部件添加到分割器
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        
        # 设置左右比例为1:2
        splitter.setStretchFactor(0, 1)  # 左侧权重为1
        splitter.setStretchFactor(1, 2)  # 右侧权重为2

        # 将分割器添加到主布局
        layout.addWidget(splitter)

        # 创建规则编辑表单
        self.edit_form = RulesForm()
        self.edit_form.save_btn.clicked.connect(self.save_rule)
        self.edit_form.delete_btn.clicked.connect(self.delete_rule)
        right_layout.addWidget(self.edit_form)
        self.edit_form.hide()

        layout.addWidget(left_widget)
        layout.addWidget(right_widget)

    def open_config_file(self):
        """打开配置文件"""
        file_name, _ = QFileDialog.getOpenFileName(self, "选择配置文件", "", "YAML 文件 (*.yml *.yaml);;所有文件 (*.*)")
        if file_name:
            # self.edit_form.hide()  # 隐藏编辑表单
            self.load_rules(file_name)

    def load_rules(self, rules_file):
        # 备份当前的配置文件
        rules_data_copy = self.rules_data.copy() if self.rules_data else None
        try:
            rules_data = load_yaml(rules_file)
            if rules_data:
                rules_data = fixed_rules(rules_data)
                self.rules_data = rules_data
                self.update_tree()
                self.update_language_combo()
                # 加载成功后再进行配置文件更新
                self.rules_file = rules_file
                QMessageBox.information(self, '提示', f'加载规则文件 {rules_file} 成功')
            else:
                QMessageBox.critical(self, '错误', f'加载规则文件 {rules_file} 为空')
        except Exception as e:
            QMessageBox.critical(self, '错误', f'加载规则文件 {rules_file} 异常: {str(e)}')
            # 进行规则还原
            self.rules_data = rules_data_copy
            self.update_tree()
            self.update_language_combo()

    def quick_load_rules(self):
        # 检查规则文件是否存在
        if not self.rules_file or not os.path.isfile(self.rules_file):
            QMessageBox.critical(self, '错误', f'未获取到配置文件:{self.rules_file}')
            return

        # 直接进行加载
        if not self.rules_data:
            self.load_rules(self.rules_file)
            return

        # 进行重新加
        reply = QMessageBox.question(
            self,
            '确认重新加载',
            '重新加载将丢失未保存的更改，是否继续？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            # self.edit_form.hide()  # 隐藏编辑表单
            self.load_rules(self.rules_file)  # 重新加载规则

    def save_to_file(self, rules_data=None, rules_file=None):
        """保存规则到文件"""
        rules_file = rules_file if rules_file else self.rules_file
        rules_data = rules_data if rules_data else self.rules_data
        if not rules_data:
            QMessageBox.warning(self, '错误', '保存规则文件失败: 当前数据为空')
            return False
        if not rules_file:
            QMessageBox.warning(self, '错误', '保存规则文件失败: 未指定文件路径')
            return False
        # 进行文件保存
        status, error = save_yaml_format(rules_file, rules_data)
        if error:
            QMessageBox.critical(self, '错误', f'保存规则文件失败: {str(error)}')
            return False
        return True

    def save_config(self):
        """保存当前配置"""
        if self.save_to_file():
            QMessageBox.information(self, '提示', '配置已保存')

    def save_rule(self):
        current_item = self.tree.currentItem()
        if not current_item or not current_item.parent():
            QMessageBox.warning(self, '警告', '请先选择一个规则')
            return

        # 获取表单数据
        vuln_data = self.edit_form.get_form_data()

        # 检查当前规则是否有效
        matches = []
        for pattern in vuln_data[RuleKeys.PATTERNS.value]:
            # 排除空正则的情况
            if not pattern.strip():
                continue
            try:
                flags = re.MULTILINE | re.DOTALL
                if  vuln_data[RuleKeys.IGNORE_CASE.value]:
                    flags |= re.IGNORECASE

                sample_code = ' '.join(vuln_data[RuleKeys.SAMPLE_CODE.value].splitlines())
                for match in re.finditer(pattern, sample_code, flags):
                    matches.append(match.group(0))
            except re.error as e:
                QMessageBox.warning(self, '规则验证', f'正则表达式错误: {e}')
                return

        if not matches:
            reply = QMessageBox.question(
                self,
                '规则验证',
                '当前规则无法匹配示例代码，是否继续保存？',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                return

        # 更新数据
        lang_name = self.edit_form.lang_combo.currentText()
        old_name = current_item.text(0)

        for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
            if lang[RuleKeys.LANGUAGE.value] == lang_name:
                for i, vuln in enumerate(lang[RuleKeys.VULNS.value]):
                    if vuln[RuleKeys.RULE_NAME.value] == old_name:
                        lang[RuleKeys.VULNS.value][i] = vuln_data
                        break

        if self.save_to_file():
            if matches:
                QMessageBox.information(self, '保存成功', f'规则验证通过\n匹配内容: {matches}')
            
            # 保存当前规则的信息
            lang_name = self.edit_form.lang_combo.currentText()
            rule_name = vuln_data[RuleKeys.RULE_NAME.value]
            
            # 更新树并重新选择节点
            self.update_tree()
            
            # 重新查找并选择保存的规则
            for i in range(self.tree.topLevelItemCount()):
                lang_item = self.tree.topLevelItem(i)
                if lang_item.text(0) == lang_name:
                    # 遍历漏洞类型节点
                    for j in range(lang_item.childCount()):
                        class_item = lang_item.child(j)
                        # 遍历规则节点
                        for k in range(class_item.childCount()):
                            rule_item = class_item.child(k)
                            if rule_item.text(0) == rule_name:
                                self.tree.setCurrentItem(rule_item)
                                rule_item.setSelected(True)  # 确保节点被选中
                                self.on_item_selected(rule_item)  # 触发选择事件
                                return  # 找到后直接返回

    def delete_rule(self):
        current_item = self.tree.currentItem()
        if not current_item or not current_item.parent():
            return

        reply = QMessageBox.question(self, '确认删除',
                                     f'确定要删除规则 {current_item.text(0)} 吗？',
                                     QMessageBox.StandardButton.Yes |
                                     QMessageBox.StandardButton.No)

        if reply == QMessageBox.StandardButton.Yes:
            lang_name = current_item.parent().text(0)
            for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
                if lang[RuleKeys.LANGUAGE.value] == lang_name:
                    lang[RuleKeys.VULNS.value] = [v for v in lang[RuleKeys.VULNS.value]
                                                  if v[RuleKeys.RULE_NAME.value] != current_item.text(0)]
                    break

            if self.save_to_file():
                self.update_tree()
                self.edit_form.hide()

    def update_language_combo(self):
        self.edit_form.lang_combo.clear()
        if self.rules_data:
            languages = [lang[RuleKeys.LANGUAGE.value] for lang in self.rules_data.get(RuleKeys.LANGUAGES.value, [])]
            self.edit_form.lang_combo.addItems(languages)
            self.edit_form.lang_combo.setDisabled(True)  # 设置不可点击

    def on_item_selected(self, item):
        # 检查 item 是否为 None
        if item is None:
            return

        # 如果是父节点（语言节点或漏洞类型节点）
        if not item.parent() or (item.parent() and not item.parent().parent()):
            item.setExpanded(True)  # 自动展开当前节点
            self.edit_form.hide()
            return

        # 规则节点（有两层父节点：语言->漏洞类型->规则）
        self.edit_form.show()
        vuln_data = item.data(0, Qt.ItemDataRole.UserRole)
        self.edit_form.set_form_data(vuln_data)
        self.edit_form.lang_combo.setCurrentText(item.parent().parent().text(0))  # 设置语言为祖父节点的文本

    def update_tree(self):
        # 保存当前展开状态
        expanded_items = {}
        for i in range(self.tree.topLevelItemCount()):
            lang_item = self.tree.topLevelItem(i)
            if lang_item.isExpanded():
                expanded_items[lang_item.text(0)] = set()
                for j in range(lang_item.childCount()):
                    class_item = lang_item.child(j)
                    if class_item.isExpanded():
                        expanded_items[lang_item.text(0)].add(class_item.text(0))

        self.tree.clear()
        if not self.rules_data:
            return

        # 重建树并恢复展开状态
        for lang in self.rules_data.get(RuleKeys.LANGUAGES.value, []):
            # 创建语言节点
            lang_item = QTreeWidgetItem([lang[RuleKeys.LANGUAGE.value]])
            self.tree.addTopLevelItem(lang_item)

            # 按漏洞类型分组规则
            vuln_types = {}
            for vuln in lang.get(RuleKeys.VULNS.value, []):
                vuln_type = vuln.get(RuleKeys.VULN_TYPE.value, VulnType.OTHER.value)
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)

            # 添加漏洞类型节点和漏洞
            for vuln_type, vulns in sorted(vuln_types.items()):
                class_item = QTreeWidgetItem([vuln_type])
                lang_item.addChild(class_item)
                
                for vuln in sorted(vulns, key=lambda x: x[RuleKeys.RULE_NAME.value]):
                    vuln_item = QTreeWidgetItem([vuln[RuleKeys.RULE_NAME.value]])
                    vuln_item.setData(0, Qt.ItemDataRole.UserRole, vuln)
                    
                    # 根据规则状态和危险等级设置不同颜色
                    if not vuln.get(RuleKeys.LOADED.value, True):
                        # 未启用的规则显示为绿色
                        vuln_item.setForeground(0, Qt.GlobalColor.green)
                    else:
                        # 根据危险等级设置颜色
                        severity = vuln.get(RuleKeys.SEVERITY.value, SeverityLevel.HIGH.value)
                        if severity == SeverityLevel.HIGH.value:
                            # 高危显示为红色
                            vuln_item.setForeground(0, Qt.GlobalColor.red)
                        elif severity == SeverityLevel.MEDIUM.value:
                            # 中危显示为蓝色
                            vuln_item.setForeground(0, Qt.GlobalColor.blue)
                        elif severity == SeverityLevel.LOW.value:
                            # 低危显示为灰色
                            vuln_item.setForeground(0, Qt.GlobalColor.gray)
                    
                    class_item.addChild(vuln_item)

            # 恢复展开状态
            if lang[RuleKeys.LANGUAGE.value] in expanded_items:
                lang_item.setExpanded(True)
                for j in range(lang_item.childCount()):
                    class_item = lang_item.child(j)
                    if class_item.text(0) in expanded_items[lang[RuleKeys.LANGUAGE.value]]:
                        class_item.setExpanded(True)

    def check_all_rules(self):
        if not self.rules_data:
            QMessageBox.warning(self, '警告', '没有找到规则')
            return

        all_lang_rules = self.rules_data.get(RuleKeys.LANGUAGES.value, [])

        validation_results = check_all_rule_regex(all_lang_rules)

        if validation_results:
            QMessageBox.warning(self, '规则检查结果', '\n'.join(validation_results))
        else:
            QMessageBox.information(self, '规则检查结果', '所有规则验证通过！')

    def toggle_all_rules(self, enable):
        if not self.rules_data:
            QMessageBox.warning(self, '警告', '没有找到规则')
            return

        count = 0
        for lang_rule in self.rules_data.get(RuleKeys.LANGUAGES.value, []):
            for vuln in lang_rule.get(RuleKeys.VULNS.value, []):
                if vuln[RuleKeys.LOADED.value] != enable:
                    vuln[RuleKeys.LOADED.value] = enable
                    count += 1

        if self.save_to_file():
            status = '启用' if enable else '禁用'
            QMessageBox.information(self, '操作成功', f'已 {status} {count} 条规则 并保存至配置文件')
            self.update_tree()

    def show_context_menu(self, position):
        """显示右键菜单"""
        item = self.tree.itemAt(position)
        menu = QMenu()

        if not item:  # 空白处或标题处右键
            add_lang_action = menu.addAction('添加语言')
            action = menu.exec(self.tree.viewport().mapToGlobal(position))
            if action == add_lang_action:
                self.add_language()
            return

        if not item.parent():  # 语言节点
            lang_name = item.text(0)
            # 创建语言菜单项
            add_lang_action = menu.addAction('添加语言')
            menu.addSeparator()
            delete_action = menu.addAction(f'删除语言 {lang_name}')
            disable_action = menu.addAction(f'禁用语言 {lang_name} 的所有规则')
            enable_action = menu.addAction(f'启用语言 {lang_name} 的所有规则')
            add_rule_action = menu.addAction(f'为 {lang_name} 新增规则')

            action = menu.exec(self.tree.viewport().mapToGlobal(position))

            if action == add_lang_action:
                self.add_language()
            elif action == delete_action:
                self.delete_language(lang_name)
            elif action == disable_action:
                self.toggle_language_rules(lang_name, False)
            elif action == enable_action:
                self.toggle_language_rules(lang_name, True)
            elif action == add_rule_action:
                self.tree.setCurrentItem(item)
                self.add_vulnerability()
            return

        # 获取所有选中的项目
        selected_items = self.tree.selectedItems()
        
        # 规则分类节点或规则节点
        if item.parent():
            # 获取规则节点（包括规则分类下的所有规则）
            rule_items = []
            if item.parent().parent():  # 规则节点
                rule_items = [i for i in selected_items if i.parent() and i.parent().parent()]
            else:  # 规则分类节点
                # 如果点击的是分类节点，获取该分类下的所有规则
                for i in range(item.childCount()):
                    rule_items.append(item.child(i))

            if not rule_items:
                return

            rules_count = len(rule_items)
            # 创建规则菜单项
            copy_action = menu.addAction(f'复制选中的 {rules_count} 条规则')
            delete_action = menu.addAction(f'删除选中的 {rules_count} 条规则')



            # 检查是否所有规则都启用或禁用
            all_enabled = all(i.data(0, Qt.ItemDataRole.UserRole).get(RuleKeys.LOADED.value, True) for i in rule_items)
            all_disabled = all(not i.data(0, Qt.ItemDataRole.UserRole).get(RuleKeys.LOADED.value, True) for i in rule_items)

            toggle_action = None
            if all_disabled:
                toggle_action = menu.addAction(f'启用选中的 {rules_count} 条规则')
            elif all_enabled:
                toggle_action = menu.addAction(f'禁用选中的 {rules_count} 条规则')
            else:
                toggle_enable_action = menu.addAction(f'启用选中的规则')
                toggle_disable_action = menu.addAction(f'禁用选中的规则')

            # 添加漏洞类型子菜单
            vuln_type_menu = menu.addMenu(f'设置漏洞类型')
            vuln_type_actions = {}
            for vuln_type in VulnType.choices():
                action = vuln_type_menu.addAction(vuln_type)
                vuln_type_actions[action] = vuln_type

            # 显示菜单并获取选择的动作
            action = menu.exec(self.tree.viewport().mapToGlobal(position))

            if action == delete_action:
                self.delete_selected_rules(rule_items)
            elif action == copy_action:
                self.copy_rules(rule_items)
            elif all_disabled and action == toggle_action:
                self.toggle_selected_rules(rule_items, True)
            elif all_enabled and action == toggle_action:
                self.toggle_selected_rules(rule_items, False)
            elif not all_disabled and not all_enabled:
                if action == toggle_enable_action:
                    self.toggle_selected_rules(rule_items, True)
                elif action == toggle_disable_action:
                    self.toggle_selected_rules(rule_items, False)
            elif action in vuln_type_actions:  # 添加这个条件分支
                self.set_rules_vuln_type(rule_items, vuln_type_actions[action])


    def delete_selected_rules(self, items):
        """删除选中的规则"""
        reply = QMessageBox.question(
            self,
            '确认删除',
            f'确定要删除选中的 {len(items)} 条规则吗？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            changes_made = False
            for item in items:
                lang_name = item.parent().parent().text(0)  # 获取语言节点（祖父节点）
                rule_name = item.text(0)

                for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
                    if lang[RuleKeys.LANGUAGE.value] == lang_name:
                        lang[RuleKeys.VULNS.value] = [
                            v for v in lang[RuleKeys.VULNS.value]
                            if v[RuleKeys.RULE_NAME.value] != rule_name
                        ]
                        changes_made = True

            if changes_made and self.save_to_file():
                self.update_tree()
                self.edit_form.hide()

    def copy_rules(self, items):
        """复制多个规则"""
        from datetime import datetime
        import copy

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        copied_count = 0

        for item in items:
            vuln_data = item.data(0, Qt.ItemDataRole.UserRole)
            lang_name = item.parent().parent().text(0)  # 获取语言节点（祖父节点）

            # 创建新规则的副本
            new_vuln = copy.deepcopy(vuln_data)
            new_vuln[RuleKeys.RULE_NAME.value] = f"{vuln_data[RuleKeys.RULE_NAME.value]}_copy_{timestamp}"

            # 添加新规则到对应语言
            for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
                if lang[RuleKeys.LANGUAGE.value] == lang_name:
                    lang[RuleKeys.VULNS.value].append(new_vuln)
                    copied_count += 1
                    break

        # 保存并更新UI
        if copied_count > 0 and self.save_to_file():
            self.update_tree()
            QMessageBox.information(self, '提示', f'已复制 {copied_count} 条规则')

    def toggle_selected_rules(self, items, enable):
        """启用/禁用选中的规则"""
        count = 0
        for item in items:
            lang_name = item.parent().parent().text(0)  # 获取语言节点（祖父节点）
            rule_name = item.text(0)

            for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
                if lang[RuleKeys.LANGUAGE.value] == lang_name:
                    for vuln in lang[RuleKeys.VULNS.value]:
                        if vuln[RuleKeys.RULE_NAME.value] == rule_name and vuln.get(RuleKeys.LOADED.value, True) != enable:
                            vuln[RuleKeys.LOADED.value] = enable
                            count += 1

        if count > 0 and self.save_to_file():
            status = '启用' if enable else '禁用'
            QMessageBox.information(
                self,
                '操作成功',
                f'已{status} {count} 条规则'
            )
            self.update_tree()

    def add_vulnerability(self):
        if not self.rules_data or not self.rules_data.get(RuleKeys.LANGUAGES.value):
            QMessageBox.warning(self, '警告', '请先添加语言')
            return

        # 获取当前选中的树节点
        current_item = self.tree.currentItem()
        if not current_item:
            QMessageBox.warning(self, '警告', '请选择一个语言')
            return

        # 如果选中的是规则节点，获取其父节点（语言节点）
        if current_item.parent():
            lang_name = current_item.parent().text(0)
        else:
            lang_name = current_item.text(0)

        vuln_data = {
            RuleKeys.RULE_NAME.value: '新规则',
            RuleKeys.VULN_TYPE.value: VulnType.OTHER.value,
            RuleKeys.PATTERNS.value: [''],
            RuleKeys.DESCRIPTION.value: '',
            RuleKeys.SEVERITY.value: f'{SeverityLevel.HIGH.value}',
            RuleKeys.SAMPLE_CODE.value: '',
            RuleKeys.IGNORE_CASE.value: True,
            RuleKeys.LOADED.value: True,
            RuleKeys.RELATED_SUFFIXES.value: '*',
            RuleKeys.CONTEXT_BEFORE.value: 50,
            RuleKeys.CONTEXT_AFTER.value: 50,
            RuleKeys.CONTEXT_NEED.value: False
        }

        # Add vulnerability to selected language
        for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
            if lang[RuleKeys.LANGUAGE.value] == lang_name:
                lang[RuleKeys.VULNS.value].append(vuln_data)
                break

        # Save and update UI
        if self.save_to_file():
            self.update_tree()
            # Select the newly added rule
            for i in range(self.tree.topLevelItemCount()):
                lang_item = self.tree.topLevelItem(i)
                if lang_item.text(0) == lang_name:
                    vuln_item = lang_item.child(lang_item.childCount() - 1)
                    self.tree.setCurrentItem(vuln_item)
                    self.on_item_selected(vuln_item)
                    break

    def add_language(self):
        lang_name, ok = QInputDialog.getText(self, '添加语言', '请输入语言名称:')
        if ok and lang_name:
            # 初始化 rules_data 如果不存在
            if not self.rules_data:
                self.rules_data = {RuleKeys.LANGUAGES.value: []}

            # 检查语言是否已存在
            if any(lang[RuleKeys.LANGUAGE.value] == lang_name for lang in self.rules_data.get(RuleKeys.LANGUAGES.value, [])):
                QMessageBox.warning(self, '警告', f'语言 {lang_name} 已存在')
                return

            self.rules_data[RuleKeys.LANGUAGES.value].append({
                RuleKeys.LANGUAGE.value: lang_name,
                RuleKeys.VULNS.value: []
            })

            if self.save_to_file():
                self.update_tree()
                self.update_language_combo()

    def delete_language(self, lang_name):
        """删除语言"""
        reply = QMessageBox.question(
            self,
            '确认删除',
            f'确定要删除语言 {lang_name} 及其所有规则吗？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.rules_data[RuleKeys.LANGUAGES.value] = [
                lang for lang in self.rules_data[RuleKeys.LANGUAGES.value]
                if lang[RuleKeys.LANGUAGE.value] != lang_name
            ]
            if self.save_to_file():
                self.update_tree()
                self.update_language_combo()
                self.edit_form.hide()

    def toggle_language_rules(self, lang_name, enable):
        """启用/禁用语言的所有规则"""
        count = 0
        for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
            if lang[RuleKeys.LANGUAGE.value] == lang_name:
                for vuln in lang[RuleKeys.VULNS.value]:
                    if vuln[RuleKeys.LOADED.value] != enable:
                        vuln[RuleKeys.LOADED.value] = enable
                        count += 1
                break

        if count > 0 and self.save_to_file():
            status = '启用' if enable else '禁用'
            QMessageBox.information(
                self,
                '操作成功',
                f'已{status} {lang_name} 的 {count} 条规则'
            )
            self.update_tree()

    def check_duplicate_rules(self):
        """检查每个语言中是否存在重复规则"""
        if not self.rules_data:
            QMessageBox.warning(self, '警告', '没有找到规则')
            return

        all_lang_rules = self.rules_data.get(RuleKeys.LANGUAGES.value, [])

        duplicate_results = find_lang_dup_rule(all_lang_rules)

        if duplicate_results:
            QMessageBox.warning(self, '重复规则检查结果', '\n'.join(duplicate_results))
        else:
            QMessageBox.information(self, '重复规则检查结果', '未发现重复规则！')

    def sort_rules(self):
        """按字母顺序排序每个语言的规则"""
        if not self.rules_data:
            QMessageBox.warning(self, '警告', '没有找到规则')
            return

        all_lang_rules = self.rules_data[RuleKeys.LANGUAGES.value]
        changes_made = sort_lang_rules(all_lang_rules)
        if changes_made:
            if self.save_to_file():
                self.update_tree()
                QMessageBox.information(self, '排序完成', '规则已按字母顺序排序并保存')
        else:
            QMessageBox.information(self, '排序完成', '规则已经是按字母顺序排序的')

    def set_rules_vuln_type(self, items, vuln_type):
        """设置选中规则的漏洞类型"""
        count = 0
        for item in items:
            lang_name = item.parent().parent().text(0)  # 获取语言节点（祖父节点）
            rule_name = item.text(0)

            for lang in self.rules_data[RuleKeys.LANGUAGES.value]:
                if lang[RuleKeys.LANGUAGE.value] == lang_name:
                    for vuln in lang[RuleKeys.VULNS.value]:
                        if vuln[RuleKeys.RULE_NAME.value] == rule_name:
                            vuln[RuleKeys.VULN_TYPE.value] = vuln_type.value
                            count += 1

        if count > 0 and self.save_to_file():
            QMessageBox.information(
                self,
                '操作成功',
                f'已将 {count} 条规则的漏洞类型设置为 {vuln_type.value}'
            )
            self.update_tree()

            
if __name__ == '__main__':
    app = QApplication(sys.argv)
    editor = RulesEditor(DEF_CONFIG_RULES)  # 显式传入配置文件路径
    editor.show()
    sys.exit(app.exec())
