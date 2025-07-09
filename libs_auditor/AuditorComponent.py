import os
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (QWidget, QVBoxLayout,
                             QHBoxLayout, QTreeWidget, QPushButton,
                             QScrollArea, QTextEdit, QMessageBox,
                             QToolBar, QComboBox, QMenu, QWidgetAction)

from libs_auditor.auditor_enum import AuditorUIKeys, AuditStatus, AuditorKeys
from libs_auditor.process_nodes import batch_process_node_item_status
from libs_auditor.auditor_utils import open_current_file, add_editor_sub_menu, resolve_path_by_root
from libs_auditor.BuiltInEditor import BuiltInEditor
from libs_auditor.export_utils import export_report, export_selected
from libs_checker.checker_enum import CheckerKeys
from libs_com.utils_json import dump_json
from libs_auditor.auditor_ui_utils import create_vertical_box, create_horizon_box, create_horizon_box_with_combo, get_selected_infos, \
    menu_add_combo_box

from libs_com.utils_yaml import save_yaml
from libs_rules.rules_enum import RuleKeys, SeverityLevel, VulnType
from libs_verifier.verifier_enum import VerifyKeys, VerifyStatus


class AuditorComponent:
    def __init__(self, parent, ai_clients_infos, ai_model_name):
        self.ai_clients_infos = ai_clients_infos
        self.ai_model_name = ai_model_name
        self.parent = parent

        # 初始化编辑器
        print("正在初始化程序内置编辑器,请稍等...")
        self._init_built_in_editor()
        print("初始化内置编辑器已完成,程序启动完毕...")

    def _init_built_in_editor(self):
        """初始化内置编辑器"""
        parent = self.parent
        try:
            if not hasattr(parent, 'built_in_editor'):
                editor = BuiltInEditor(parent=parent, ai_clients_infos=self.ai_clients_infos,
                                       ai_model_name=self.ai_model_name)
                parent.built_in_editor = editor
        except Exception as e:
            print(f"编辑器初始化失败: {str(e)}")

    def ui_add_toolbar(self):
        parent = self.parent
        # 创建工具栏
        toolbar = QToolBar()
        toolbar.setMovable(False)  # 禁止工具栏移动
        toolbar.setFloatable(False)  # 禁止工具栏浮动
        toolbar.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)  # 使用PreventContextMenu完全禁用右键菜单
        parent.addToolBar(Qt.ToolBarArea.TopToolBarArea, toolbar)  # 明确指定工具栏位置
        parent.addToolBar(toolbar)
        # 修改快速加载示例按钮
        quick_load_btn = QPushButton('快速加载')
        quick_load_btn.clicked.connect(parent._quick_load_json)
        toolbar.addWidget(quick_load_btn)
        # 加载项目按钮
        load_btn = QPushButton('加载项目')
        load_btn.clicked.connect(parent._choice_load_json)
        toolbar.addWidget(load_btn)
        # 在筛选按钮之前添加树形视图切换按钮
        parent.tree_view_btn = QPushButton('切换视图')
        parent.tree_view_btn.setCheckable(True)
        parent.tree_view_btn.clicked.connect(parent._switch_tree_view)
        toolbar.addWidget(parent.tree_view_btn)
        toolbar.addSeparator()
        # 添加编辑模式切换按钮
        parent.edit_mode_btn = QPushButton('内容编辑')
        parent.edit_mode_btn.setCheckable(True)  # 使按钮可切换
        parent.edit_mode_btn.clicked.connect(self._switch_edit_mode)
        toolbar.addWidget(parent.edit_mode_btn)
        # 在 ResultViewer 类的 initUI 方法中，在工具栏部分添加导出按钮
        # 在工具栏添加保存按钮后面添加
        parent.save_btn = QPushButton('保存修改')
        parent.save_btn.clicked.connect(self._save_ui_changes)
        toolbar.addWidget(parent.save_btn)
        # 创建筛选菜单按钮
        filter_btn = self._init_filter_btn()
        toolbar.addWidget(filter_btn)
        # 添加分隔符
        toolbar.addSeparator()
        # 添加导出按钮
        export_btn = self._init_export_btn()
        toolbar.addWidget(export_btn)
        # 添加分隔符
        toolbar.addSeparator()

    def ui_add_right_panel(self, main_layout):
        parent = self.parent
        # 右侧详细信息（只创建一次）
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        right_widget.setLayout(right_layout)
        main_layout.addWidget(right_widget)
        # 创建上部滚动区域（原始数据）
        upper_scroll = QScrollArea()
        upper_scroll.setWidgetResizable(True)
        upper_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        right_layout.addWidget(upper_scroll)
        # 创建下部滚动区域（AI分析数据）
        lower_scroll = QScrollArea()
        lower_scroll.setWidgetResizable(True)
        lower_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        right_layout.addWidget(lower_scroll)
        # 设置上下区域比例为 7:7 setStretch的第一个参数是索引值
        right_layout.setStretch(0, 5)  # 上部区域权重为 3
        right_layout.setStretch(1, 5)  # 下部区域权重为 7
        # 上部容器（原始数据）
        upper_widget = QWidget()
        upper_layout = QVBoxLayout()
        upper_widget.setLayout(upper_layout)
        upper_scroll.setWidget(upper_widget)
        # 下部容器（AI分析数据）
        lower_widget = QWidget()
        lower_layout = QVBoxLayout()
        lower_widget.setLayout(lower_layout)
        lower_scroll.setWidget(lower_widget)
        # 将原来的self.detail_widget的内容分配到上下两个容器
        parent.detail_widget = lower_widget  # 保持兼容性
        # 创建一个水平布局来容纳两个验证组件
        # 在人工验证和智能验证的布局中添加风险级别
        verify_layout = QHBoxLayout()
        # 人工验证
        # 修改人工验证和智能验证的下拉框选项
        parent.audit_combo = QComboBox()
        manual_audit_container = create_horizon_box_with_combo("人工验证:", parent.audit_combo, AuditStatus.choices())
        verify_layout.addWidget(manual_audit_container)

        # 添加一些间距
        verify_layout.addSpacing(20)

        # 智能验证
        parent.verify_combo = QComboBox()
        verify_container = create_horizon_box_with_combo("智能验证:", parent.verify_combo, VerifyStatus.choices())
        verify_layout.addWidget(verify_container)

        # 添加一些间距
        verify_layout.addSpacing(20)

        # 风险级别
        parent.severity_combo = QComboBox()
        severity_container = create_horizon_box_with_combo("风险级别:", parent.severity_combo, SeverityLevel.choices())
        verify_layout.addWidget(severity_container)

        # 添加内置编辑器按钮
        built_in_editor_btn = QPushButton('内联AI分析')
        built_in_editor_btn.clicked.connect(self._open_with_built_in_editor)
        verify_layout.addWidget(built_in_editor_btn)

        # 添加打开文件按钮
        open_file_btn = QPushButton('打开当前文件')
        open_file_btn.clicked.connect(lambda: open_current_file(parent))
        verify_layout.addWidget(open_file_btn)

        # 将水平布局添加到上部布局
        upper_layout.addLayout(verify_layout)

        # 添加SAST相关的原始漏洞信息
        parent.file_edit = QTextEdit()
        file_container = create_horizon_box("文件路径:", parent.file_edit)
        upper_layout.addWidget(file_container)

        parent.vuln_type_edit = QTextEdit()
        vuln_type_container = create_horizon_box("漏洞类型:", parent.vuln_type_edit)
        upper_layout.addWidget(vuln_type_container)

        parent.line_number_edit = QTextEdit()
        line_number_container = create_horizon_box("代码行号:", parent.line_number_edit)
        upper_layout.addWidget(line_number_container)

        parent.context_edit = QTextEdit()
        context_container = create_vertical_box('漏洞代码:', parent.context_edit)
        upper_layout.addWidget(context_container)

        parent.match_edit = QTextEdit()
        match_container = create_vertical_box("匹配内容:", parent.match_edit, max_height=100, min_height=50, read_only=True)
        upper_layout.addWidget(match_container)

        # parsed节点的数据和AI相关数据放在下部
        parent.method_code_edit = QTextEdit()
        method_code_container = create_vertical_box('方法函数:', parent.method_code_edit)
        upper_layout.addWidget(method_code_container)

        parent.called_codes_edit = QTextEdit()
        called_codes_container = create_vertical_box('调用函数:', parent.called_codes_edit)
        upper_layout.addWidget(called_codes_container)

        parent.ai_model_name_edit = QTextEdit()
        ai_model_name_container = create_horizon_box("响应模型:", parent.ai_model_name_edit)
        lower_layout.addWidget(ai_model_name_container)

        parent.because_edit = QTextEdit()
        because_container = create_vertical_box('评分原因:', parent.because_edit)
        lower_layout.addWidget(because_container)

        parent.http_poc_edit = QTextEdit()
        poc_container = create_vertical_box('HTTP POC:', parent.http_poc_edit)
        lower_layout.addWidget(poc_container)
        parent.sensitive_edit = QTextEdit()
        sensitive_container = create_vertical_box('敏感数据:', parent.sensitive_edit)
        lower_layout.addWidget(sensitive_container)
        parent.explain_edit = QTextEdit()
        explain_container = create_vertical_box('漏洞危害:', parent.explain_edit)
        lower_layout.addWidget(explain_container)
        parent.repair_edit = QTextEdit()
        repair_container = create_vertical_box('修复建议:', parent.repair_edit)
        lower_layout.addWidget(repair_container)
        # 添加AI相关信息到下部
        parent.response_edit = QTextEdit()
        response_container = create_vertical_box('AI响应:', parent.response_edit)
        lower_layout.addWidget(response_container)

        parent.prompt_edit = QTextEdit()
        prompt_container = create_vertical_box('提示词:', parent.prompt_edit)
        lower_layout.addWidget(prompt_container)
        parent.error_edit = QTextEdit()
        error_container = create_vertical_box('错误信息:', parent.error_edit)
        lower_layout.addWidget(error_container)

    def ui_add_left_tree(self, main_layout):
        parent = self.parent
        # 左侧漏洞列表
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        left_widget.setLayout(left_layout)
        left_widget.setMinimumWidth(200)  # 最小宽度200
        left_widget.setMaximumWidth(400)  # 最大宽度400
        main_layout.addWidget(left_widget)
        # 创建滚动区域包裹树形视图
        tree_scroll = QScrollArea()
        tree_scroll.setWidgetResizable(True)
        tree_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        tree_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        left_layout.addWidget(tree_scroll)
        # 创建容器包含树形视图
        tree_container = QWidget()
        tree_layout = QVBoxLayout()
        tree_container.setLayout(tree_layout)
        # 漏洞树形视图
        parent.tree = QTreeWidget()
        parent.tree.itemClicked.connect(self._on_item_selected)
        parent.tree.setHeaderLabels(['漏洞列表'])
        parent.tree.setHeaderHidden(True)
        parent.tree.setStyleSheet("QTreeWidget { border: 0px; }")
        parent.tree.setFocusPolicy(Qt.FocusPolicy.StrongFocus)  # 允许键盘焦点
        parent.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)  # 启用多选功能
        parent.tree.currentItemChanged.connect(self._on_item_selected)  # 添加当前项改变事件
        parent.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)  # 启用自定义右键菜单
        parent.tree.customContextMenuRequested.connect(self._show_context_menu)  # 连接右键菜单信号
        tree_layout.addWidget(parent.tree)
        # 将容器设置为滚动区域的内容
        tree_scroll.setWidget(tree_container)

    def _init_filter_btn(self):
        parent = self.parent
        filter_btn = QPushButton('筛选数据')
        # 设置子菜单
        filter_menu = QMenu(parent)
        parent.severity_filter = QComboBox()
        parent.vuln_type_filter = QComboBox()
        parent.verify_filter = QComboBox()
        parent.audit_filter = QComboBox()
        parent.filters_dict = {
            'audit_filter': parent.audit_filter,
            'vuln_type_filter': parent.vuln_type_filter,
            'verify_filter': parent.verify_filter,
            'severity_filter': parent.severity_filter
        }
        apply_func = parent._update_tree_with_filter  # 按钮需要调用的过滤函数
        # 风险级别筛选
        # menu_add_combo_box(filter_menu, parent.severity_filter, [全部风险] + SeverityLevel.choices(), apply_func)
        menu_add_combo_box(filter_menu, parent.severity_filter, [AuditorUIKeys.ALL_RISKS.value], apply_func)
        # 漏洞类型筛选
        menu_add_combo_box(filter_menu, parent.vuln_type_filter, [AuditorUIKeys.ALL_TYPES.value], apply_func)
        # 智能验证状态筛选
        # menu_add_combo_box(filter_menu, parent.verify_filter, [智能验证] + VerifyStatus.choices(), apply_func)
        menu_add_combo_box(filter_menu, parent.verify_filter, [AuditorUIKeys.AI_VERIF.value], apply_func)
        # 人工验证状态筛选
        # menu_add_combo_box(filter_menu, parent.audit_filter, [人工验证] + AuditStatus.choices(), apply_func)
        menu_add_combo_box(filter_menu, parent.audit_filter, [AuditorUIKeys.ME_VERIF.value], apply_func)
        # 添加分隔线和清除筛选选项
        filter_menu.addSeparator()
        clear_filter_widget = QWidget()
        clear_filter_layout = QHBoxLayout(clear_filter_widget)
        clear_filter_layout.setContentsMargins(5, 2, 5, 2)
        clear_filter_btn = QPushButton('清除筛选^_^')
        clear_filter_btn.setFixedWidth(80)  # 与上面的下拉框保持相同宽度
        clear_filter_btn.clicked.connect(parent._clear_filters)
        clear_filter_layout.addWidget(clear_filter_btn)
        clear_filter_action = QWidgetAction(filter_menu)
        clear_filter_action.setDefaultWidget(clear_filter_widget)
        filter_menu.addAction(clear_filter_action)
        # 应用子菜单
        filter_btn.setMenu(filter_menu)
        return filter_btn

    def _init_export_btn(self):
        parent = self.parent
        # 添加导出按钮
        export_btn = QPushButton('导出报告')
        # 设计子菜单
        export_menu = QMenu(parent)
        export_json_action = export_menu.addAction('导出JSON')
        export_json_action.triggered.connect(
            lambda: export_report(parent, 'json', parent._filtered_data(), parent.current_file))
        export_md_action = export_menu.addAction('导出MD')
        export_md_action.triggered.connect(
            lambda: export_report(parent, 'md', parent._filtered_data(), parent.current_file))
        export_html_action = export_menu.addAction('导出HTML')
        export_html_action.triggered.connect(
            lambda: export_report(parent, 'html', parent._filtered_data(), parent.current_file))
        export_docx_action = export_menu.addAction('导出DOCX')
        export_docx_action.triggered.connect(
            lambda: export_report(parent, 'docx', parent._filtered_data(), parent.current_file))
        # 应用子菜单
        export_btn.setMenu(export_menu)
        return export_btn

    def _save_ui_changes(self):
        """保存当前修改的内容"""
        parent = self.parent
        try:
            results_data = parent.results_data
            current_file = parent.current_file
            unique_key = AuditorKeys.AUDITOR_HASH.value
            if not results_data or not current_file:
                QMessageBox.warning(parent, '警告', '没有可保存的数据')
                return

            current_item = parent.tree.currentItem()
            if not current_item:
                QMessageBox.warning(parent, '警告', '请先选择一个漏洞项')
                return

            # 获取当前的数据
            current_data = current_item.data(0, Qt.ItemDataRole.UserRole)
            if not current_data:
                return

            # 获取更新后的数据并验证
            updated_data = self._get_updated_data(current_data)
            if updated_data is None:
                QMessageBox.warning(parent, '警告', '数据验证失败,不进行保存')
                return

            # 查找并更新数据
            for result in results_data:
                if result[unique_key] == current_data[unique_key]:
                    result.update(updated_data)
                    break

            # 确保 current_file 不为 None
            if not current_file:
                raise ValueError("当前文件路径不能为空")
            # 保存到文件
            dump_status, dump_error = dump_json(str(current_file), results_data)
            if dump_error:
                raise dump_error
            QMessageBox.information(parent, '成功', '数据已保存')
            parent._update_tree(parent.tree, results_data, apply_filter=True)
        except Exception as e:
            QMessageBox.critical(parent, '错误', f'保存数据失败: {str(e)}')
            print(f"保存失败详细信息: {str(e)}")

    def _show_context_menu(self, position):
        parent = self.parent
        """显示右键菜单"""
        menu = QMenu()

        # 获取所有选中项
        selected_items = parent.tree.selectedItems()
        if not selected_items:
            return

        # 收集所有需要打开的文件信息
        file_infos = get_selected_infos(selected_items, parent.tree_view_btn.isChecked())

        # 添加批量审计子菜单
        audit_menu = menu.addMenu("批量审计漏洞")

        set_confirmed = audit_menu.addAction("确认存在")
        set_not_exist = audit_menu.addAction("确认误报")
        set_possible = audit_menu.addAction("可能存在")
        set_uncertain = audit_menu.addAction("条件存在")
        set_unlikely = audit_menu.addAction("可能误报")
        set_unknown = audit_menu.addAction("UNKNOWN")

        # 定义动作与审计状态之间的映射
        action_status_map = {
                set_confirmed: AuditStatus.CONFIRMED,
                set_not_exist: AuditStatus.NOT_EXIST,
                set_possible: AuditStatus.POSSIBLE,
                set_uncertain: AuditStatus.CONDITIONAL,
                set_unlikely: AuditStatus.UNLIKELY,
                set_unknown: AuditStatus.UNKNOWN,
        }
        menu.addSeparator()

        # 添加导出子菜单
        export_menu = menu.addMenu("导出所选漏洞")
        ex_json_action = export_menu.addAction("导出JSON")
        ex_md_action = export_menu.addAction("导出MD")
        ex_html_action = export_menu.addAction("导出HTML")
        ex_docx_action = export_menu.addAction("导出DOCX")
        export_type_map = {ex_json_action: 'json', ex_md_action: 'md', ex_html_action: 'html', ex_docx_action: 'docx'}
        menu.addSeparator()

        # 只在有文件可以打开编辑器已启用的状态下开始
        if file_infos:
            # 添加打开文件子菜单
            open_menu = menu.addMenu("打开所选文件")
            add_editor_sub_menu(parent, open_menu, file_infos)
            menu.addSeparator()

        # 进行动作处理
        action = menu.exec(parent.tree.viewport().mapToGlobal(position))
        if action:
            selected_items = parent.tree.selectedItems()
            if not selected_items:
                return

            # 编辑选项
            if action in action_status_map:
                # 处理数据
                batch_process_node_item_status(
                    parent, selected_items, action_status_map[action], parent.results_data, parent.current_file)
                # 更新树形视图
                parent._update_tree(parent.tree, parent.results_data, apply_filter=True)
                QMessageBox.information(parent, '成功', '批量设置完成')
            elif action in export_type_map:
                # 获取导出类型
                export_selected(parent, selected_items, export_type_map[action])

    def _on_item_selected(self, item, column):
        parent = self.parent
        try:
            # 先清空所有文本框
            parent._clear_all_fields()
            if not hasattr(item, 'data'):
                return
            data = item.data(0, Qt.ItemDataRole.UserRole)
            # 如果没有数据，说明是非叶子节点，禁用人工验证复选框
            parent.audit_combo.setEnabled(data is not None)
            if not data:
                return
            # 填充原始数据
            if AuditorKeys.AUDITED.value in data:
                parent.audit_combo.setCurrentText(str(data.get(AuditorKeys.AUDITED.value, False)))
            if VerifyKeys.ORIGINAL.value in data:
                original = data[VerifyKeys.ORIGINAL.value]
                parent.file_edit.setText(str(original.get(CheckerKeys.FILE.value, '')))

                parent.context_edit.setText(str(original.get(CheckerKeys.CONTEXT.value, '')))
                parent.match_edit.setText(str(original.get(CheckerKeys.MATCH.value, '')))
                parent.method_code_edit.setText(str(original.get(CheckerKeys.METHOD_CODE.value, '')))
                parent.called_codes_edit.setText(str(original.get(CheckerKeys.CALLED_CODES.value, '')))


                parent.vuln_type_edit.setText(str(original.get(RuleKeys.VULN_TYPE.value, VulnType.OTHER.value)))
                parent.line_number_edit.setText(str(original.get(CheckerKeys.LINE.value, '')))
                # 设置风险级别
                parent.severity_combo.setCurrentText(original.get(RuleKeys.SEVERITY.value, SeverityLevel.UNKNOWN.value))

            # 填充AI分析数据
            if VerifyKeys.PARSED.value in data:
                parsed = data[VerifyKeys.PARSED.value]
                parent.verify_combo.setCurrentText(str(parsed.get(VerifyKeys.VERIFY.value, False)))

                parent.sensitive_edit.setText(str(parsed.get(VerifyKeys.SENSITIVE.value, '')))
                parent.http_poc_edit.setText(str(parsed.get(VerifyKeys.HTTP_POC.value, '')))
                parent.explain_edit.setText(str(parsed.get(VerifyKeys.EXPLAIN.value, '')))
                parent.because_edit.setText(str(parsed.get(VerifyKeys.BECAUSE.value, '')))
                parent.repair_edit.setText(str(parsed.get(VerifyKeys.REPAIR.value, '')))
            # 填充其他AI相关数据
            if VerifyKeys.RESPONSE.value in data:
                parent.response_edit.setText(str(data.get(VerifyKeys.RESPONSE.value, '')))
            if VerifyKeys.PROMPT.value in data:
                parent.prompt_edit.setText(str(data.get(VerifyKeys.PROMPT.value, '')))
            if VerifyKeys.ERROR.value in data:
                parent.error_edit.setText(str(data.get(VerifyKeys.ERROR.value, '')))
            if VerifyKeys.MODEL.value in data:
                parent.ai_model_name_edit.setText(str(data.get(VerifyKeys.MODEL.value, '')))
        except Exception as e:
            QMessageBox.warning(parent, '警告', f'显示详细信息时发生错误: {str(e)}')

    def _switch_edit_mode(self):
        parent = self.parent
        """切换编辑模式"""
        is_editable = parent.edit_mode_btn.isChecked()
        parent.edit_mode_btn.setText('禁止编辑' if is_editable else '允许编辑')

        # 切换所有文本编辑框的只读状态
        for edit in parent._text_edits():
            edit.setReadOnly(not is_editable)

        # 切换下拉框的可编辑状态
        parent.verify_combo.setEnabled(is_editable)
        parent.severity_combo.setEnabled(is_editable)  # 允许编辑风险级别
        # 人工审计状态应该能够随时更改，所以不能禁用
        # self.manual_audit_combo.setEnabled(is_editable)

    def _get_updated_data(self, current_data):
        parent = self.parent
        """获取更新后的数据，保留原始数据中的其他属性"""
        try:
            # 校验代码行号
            # line_number = current_data.get(VerifyKeys.ORIGINAL.value).get(CheckerKeys.LINE_NUMBER.value, 0)
            line_number_text = parent.line_number_edit.toPlainText().strip()
            try:
                line_number = int(line_number_text)
                if line_number < 0: raise ValueError('代码行号必须是数字且大于等于0')
            except ValueError:
                QMessageBox.warning(parent, '警告', '代码行号必须是数字且大于等于0, 已保持原有行号')

            # 获取验证状态
            updated_data = {
                **current_data,  # 保留所有原始属性，包括 vuln_hash
                AuditorKeys.AUDITED.value: AuditStatus.format(parent.audit_combo.currentText()),  # 直接保存状态字符串
                VerifyKeys.ORIGINAL.value: {
                    **current_data[VerifyKeys.ORIGINAL.value],
                    RuleKeys.SEVERITY.value: SeverityLevel.format(parent.severity_combo.currentText())     # 允许修改风险级别
                    # FILE: parent.file_edit.toPlainText().strip(),                  #  不允许修改
                    # VULNERABILITY: parent.vuln_type_edit.toPlainText().strip(),      #  不允许修改
                    # LINE_NUMBER: line_number,                                        #  不允许修改
                    # CONTEXT: parent.context_edit.toPlainText().strip(),              #  不允许修改
                    # METHOD_CODE: parent.method_code_edit.toPlainText().strip(),      #  不允许修改
                    # CALLED_CODES: parent.called_codes_edit.toPlainText().strip(),    #  不允许修改
                },
                VerifyKeys.PARSED.value: {
                    **current_data[VerifyKeys.PARSED.value],
                    VerifyKeys.VERIFY.value: VerifyStatus.format(parent.verify_combo.currentText()),  # 保存状态字符串
                    VerifyKeys.SENSITIVE.value: parent.sensitive_edit.toPlainText().strip(),
                    VerifyKeys.HTTP_POC.value: parent.http_poc_edit.toPlainText().strip(),
                    VerifyKeys.EXPLAIN.value: parent.explain_edit.toPlainText().strip(),
                    VerifyKeys.REPAIR.value: parent.repair_edit.toPlainText().strip(),
                    VerifyKeys.BECAUSE.value: parent.because_edit.toPlainText().strip(),
                },
                # RESPONSE: parent.response_edit.toPlainText().strip(),               #  不允许修改
                # PROMPT: parent.prompt_edit.toPlainText().strip(),                   #  不允许修改
                VerifyKeys.ERROR.value: parent.error_edit.toPlainText().strip(),
                VerifyKeys.MODEL.value: parent.ai_model_name_edit.toPlainText().strip(),
            }
            return updated_data

        except Exception as e:
            QMessageBox.critical(parent, '错误', f'数据验证失败: {str(e)}')
            return None

    def _open_with_built_in_editor(self):
        parent = self.parent
        auditor_config = parent.config_dict
        config_file = parent.config_file
        try:
            current_item = parent.tree.currentItem()
            if not current_item:
                QMessageBox.warning(parent, '警告', '请先选择一个漏洞项')
                return

            data = current_item.data(0, Qt.ItemDataRole.UserRole)
            if not data or VerifyKeys.ORIGINAL.value not in data:
                QMessageBox.warning(parent, '警告', '当前选中项没有关联文件')
                return

            resolved_path = data[VerifyKeys.ORIGINAL.value].get(CheckerKeys.FILE.value, '')
            line_number = data[VerifyKeys.ORIGINAL.value].get(CheckerKeys.LINE.value, 1)
            file_path = resolve_path_by_root(parent.config_file, parent.config_dict, resolved_path, parent)
            if not file_path or not os.path.exists(file_path):
                QMessageBox.warning(parent, "失败", f"文件路径不存在:{file_path} -> {resolved_path} 已重置项目路径为None 请重新尝试!!!")
                auditor_config[AuditorKeys.PROJECT.value][AuditorKeys.SOURCE_ROOT.value] = None
                save_yaml(config_file, auditor_config)
                return

            # 如果编辑器未初始化，尝试重新初始化
            if not hasattr(parent, 'built_in_editor'):
                self._init_built_in_editor()
                if not hasattr(parent, 'built_in_editor'):
                    QMessageBox.critical(parent, '错误', '编辑器初始化失败')
                    return
            
            # 先显示窗口
            parent.built_in_editor.show()
            parent.built_in_editor.raise_()  # 将窗口提到前面
            
            # 使用 QTimer 延迟加载文件
            QTimer.singleShot(100, lambda: parent.built_in_editor.open_file(file_path, line_number, [line_number]))

        except Exception as e:
            QMessageBox.critical(parent, '错误', f'打开内置编辑器失败: {str(e)}')
