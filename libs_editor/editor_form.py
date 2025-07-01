from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QTextEdit, QComboBox,
                            QCheckBox, QPushButton, QSizePolicy)
from libs_rules.rules_enum import RuleKeys, SeverityLevel, VulnType


class RulesForm(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        form_layout = QVBoxLayout()
        self.setLayout(form_layout)

        # 在规则编辑表单中添加启用规则勾选框
        checkbox_layout = QHBoxLayout()
        self.loaded_checkbox = QCheckBox('启用规则')
        checkbox_layout.addWidget(self.loaded_checkbox)
        self.ignore_case_checkbox = QCheckBox('忽略大小写')
        checkbox_layout.addWidget(self.ignore_case_checkbox)
        self.context_need_checkbox = QCheckBox('需要上下文')
        checkbox_layout.addWidget(self.context_need_checkbox)
        form_layout.addLayout(checkbox_layout)

        # 语言选择
        self.lang_combo = QComboBox()
        form_layout.addWidget(QLabel('语言:'))
        form_layout.addWidget(self.lang_combo)

        # 规则名称
        self.rule_name_edit = QLineEdit()
        form_layout.addWidget(QLabel('规则名称:'))
        form_layout.addWidget(self.rule_name_edit)

       # 添加漏洞类型输入框
        vuln_type_layout = QHBoxLayout()
        vuln_type_layout.addWidget(QLabel("漏洞类型:"))
        self.vuln_type_combo = QComboBox()  # 改为 QComboBox
        self.vuln_type_combo.addItems(VulnType.choices())
        self.vuln_type_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        vuln_type_layout.addWidget(self.vuln_type_combo)
        form_layout.addLayout(vuln_type_layout)

        # 严重程度（放在一行）
        severity_layout = QHBoxLayout()
        severity_layout.addWidget(QLabel('严重程度:'))
        self.severity_combo = QComboBox()
        self.severity_combo.addItems(SeverityLevel.choices())
        # 修改下拉框的布局，充满剩余空间
        self.severity_combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)  # 添加这行
        severity_layout.addWidget(self.severity_combo)
        form_layout.addLayout(severity_layout)

        # 相关后缀（放在一行）
        suffix_layout = QHBoxLayout()
        suffix_layout.addWidget(QLabel('相关后缀:'))
        self.suffix_edit = QLineEdit()
        suffix_layout.addWidget(self.suffix_edit)
        form_layout.addLayout(suffix_layout)

        # 上下文行数
        context_layout = QHBoxLayout()
        self.context_before_edit = QLineEdit()
        self.context_after_edit = QLineEdit()
        context_layout.addWidget(QLabel('上文行数:'))
        context_layout.addWidget(self.context_before_edit)
        context_layout.addWidget(QLabel('下文行数:'))
        context_layout.addWidget(self.context_after_edit)
        form_layout.addLayout(context_layout)

        # 正则表达式
        self.pattern_edit = QTextEdit()
        self.pattern_edit.setMaximumHeight(100)
        form_layout.addWidget(QLabel('正则表达式:'))
        form_layout.addWidget(self.pattern_edit)

        # 描述
        self.desc_edit = QTextEdit()
        self.desc_edit.setMaximumHeight(100)
        form_layout.addWidget(QLabel('描述:'))
        form_layout.addWidget(self.desc_edit)

        # 示例代码
        self.sample_edit = QTextEdit()
        form_layout.addWidget(QLabel('示例代码:'))
        form_layout.addWidget(self.sample_edit)

        # 保存和删除按钮
        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton('保存')
        self.delete_btn = QPushButton('删除')
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.delete_btn)
        form_layout.addLayout(btn_layout)

 
    def get_form_data(self):
        """获取表单数据"""
        return {
            RuleKeys.RULE_NAME.value: self.rule_name_edit.text(),
            RuleKeys.VULN_TYPE.value: self.vuln_type_combo.currentText(),  # 修改这行
            RuleKeys.PATTERNS.value: self.pattern_edit.toPlainText().splitlines(),
            RuleKeys.DESCRIPTION.value: self.desc_edit.toPlainText(),
            RuleKeys.SEVERITY.value: self.severity_combo.currentText(),
            RuleKeys.SAMPLE_CODE.value: self.sample_edit.toPlainText(),
            RuleKeys.LOADED.value: self.loaded_checkbox.isChecked(),
            RuleKeys.IGNORE_CASE.value: self.ignore_case_checkbox.isChecked(),
            RuleKeys.RELATED_SUFFIXES.value: self.suffix_edit.text() or '*',
            RuleKeys.CONTEXT_BEFORE.value: int(self.context_before_edit.text() or 50),
            RuleKeys.CONTEXT_AFTER.value: int(self.context_after_edit.text() or 50),
            RuleKeys.CONTEXT_NEED.value: self.context_need_checkbox.isChecked()
        }

    def set_form_data(self, data):
        """设置表单数据"""
        self.rule_name_edit.setText(data[RuleKeys.RULE_NAME.value])
        self.vuln_type_combo.setCurrentText(VulnType.format(data.get(RuleKeys.VULN_TYPE.value, VulnType.OTHER.value)))
        self.pattern_edit.setPlainText('\n'.join(data[RuleKeys.PATTERNS.value]))
        self.desc_edit.setPlainText(data[RuleKeys.DESCRIPTION.value])
        self.severity_combo.setCurrentText(SeverityLevel.format(data[RuleKeys.SEVERITY.value]))
        self.sample_edit.setPlainText(data[RuleKeys.SAMPLE_CODE.value])
        self.loaded_checkbox.setChecked(data.get(RuleKeys.LOADED.value, True))
        self.ignore_case_checkbox.setChecked(data.get(RuleKeys.IGNORE_CASE.value, True))
        self.suffix_edit.setText(data.get(RuleKeys.RELATED_SUFFIXES.value, '*'))
        self.context_before_edit.setText(str(data.get(RuleKeys.CONTEXT_BEFORE.value, 50)))
        self.context_after_edit.setText(str(data.get(RuleKeys.CONTEXT_AFTER.value, 50)))
        self.context_need_checkbox.setChecked(data.get(RuleKeys.CONTEXT_NEED.value, False))