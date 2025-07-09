import os
import sys

from PyQt6.QtWidgets import QApplication, QMainWindow, QWidget, QHBoxLayout, QFileDialog, QMessageBox
from libs_auditor.AuditorComponent import AuditorComponent
from libs_auditor.auditor_data import validate_auditor_struct, trans_result_verifier_2_auditor, \
    trans_result_checker_2_verifier
from libs_auditor.auditor_enum import AuditorUIKeys, AuditorKeys, AuditStatus
from libs_auditor.auditor_filter import apply_filters, update_filter_text
from libs_auditor.auditor_ui_utils import restore_tree_state, save_tree_state, create_file_based_tree, \
    create_severity_based_tree
from libs_auditor.auditor_utils import load_auditor_config

from libs_com.file_io import copy_file
from libs_com.file_path import get_abspath
from libs_com.utils_json import load_json, dump_json
from libs_com.utils_yaml import save_yaml
from libs_rules.rules_enum import RuleKeys, SeverityLevel
from libs_verifier.utils_open_ai import simple_create_clients
from libs_verifier.verifier_enum import AIProviders, AIProvider, VerifyKeys, VerifyStatus
from setting import DEF_CONFIG_AUDITOR


class SASTAuditor(QMainWindow):
    def __init__(self, config_file):
        super().__init__()
        self.config_file = get_abspath(config_file)
        self.config_dict = load_auditor_config(self.config_file)
        # 构建多个AI客户端列表
        ai_provider = self.config_dict.get(AIProviders.PROVIDERS.value, None)
        self.ai_model_name = ai_provider.get(AIProvider.MODEL_NAME.value)
        if ai_provider is None:
            self.ai_clients_infos = None
        else:
            self.ai_clients_infos = simple_create_clients(
                ai_provider.get(AIProvider.BASE_URL.value),
                ai_provider.get(AIProvider.API_KEYS.value)
            )

        self.current_file = None
        self.results_data = None

        self.component = AuditorComponent(self, self.ai_clients_infos, self.ai_model_name)

        # 初始化定义
        self.severity_filter = None
        self.vuln_type_filter = None
        self.verify_filter = None
        self.audit_filter = None
        # 初始化UI
        self.__init_ui()

    def __init_ui(self):
        self.setWindowTitle(AuditorUIKeys.SOFTWARE.value)
        self.setGeometry(100, 100, 1000, 700)

        # 添加工具条
        self.component.ui_add_toolbar()
        # 创建主窗口部件
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout()
        main_widget.setLayout(main_layout)
        # 添加左侧树
        self.component.ui_add_left_tree(main_layout)
        # 添加右侧详情区域
        self.component.ui_add_right_panel(main_layout)
        # 设置左-右区域的比例为1:3
        main_layout.setStretch(0, 1)  # 左侧区域权重为1
        main_layout.setStretch(1, 3)  # 右侧区域权重为3

    def _text_edits(self):
        text_edits = [
            self.file_edit, self.vuln_type_edit, self.line_number_edit, self.match_edit,
            self.context_edit,self.method_code_edit, self.called_codes_edit,
            self.sensitive_edit, self.http_poc_edit, self.ai_model_name_edit,
            self.explain_edit, self.repair_edit, self.error_edit,
            self.response_edit, self.because_edit, self.prompt_edit
        ]
        return text_edits

    def _switch_tree_view(self):
        """切换树形视图的显示方式"""
        is_file_based = self.tree_view_btn.isChecked()
        self.tree_view_btn.setText(AuditorUIKeys.FILE_VIEWER.value if is_file_based else AuditorUIKeys.RISK_VIEWER.value)
        self._update_tree_with_data(self._filtered_data())

    def _filtered_data(self):
        return apply_filters(self.results_data, self.filters_dict)

    def _choice_load_json(self):
        file_name, _ = QFileDialog.getOpenFileName(self, '选择结果文件', '', 'JSON Files (*.json);;All Files (*)')
        self._load_analyse_file(file_name)
        self.config_dict[AuditorKeys.PROJECT.value][AuditorKeys.ANALYSE_FILE.value] = self.current_file
        save_yaml(self.config_file, self.config_dict)

    def _quick_load_json(self):
        """快速加载功能：如果有当前文件则重新加载，否则加载默认文件"""
        if self.current_file:
            self._load_analyse_file(self.current_file)
            self.config_dict[AuditorKeys.PROJECT.value][AuditorKeys.ANALYSE_FILE.value] = self.current_file
            save_yaml(self.config_file, self.config_dict)
        else:
            file_name = self.config_dict.get(AuditorKeys.PROJECT.value).get(AuditorKeys.ANALYSE_FILE.value, None)
            if file_name and os.path.exists(file_name):
                self._load_analyse_file(file_name)
            else:
                QMessageBox.critical(self, '错误', f'文件 {file_name} 不存在, 首次使用请手动加载据分析结果!')

    def _load_analyse_file(self, file_name):
        if file_name:
            try:
                json_load = load_json(file_name)
                if not json_load:
                    QMessageBox.critical(self, '错误', f'文件 {file_name} 内容异常, 请检查!')
                    return

                # 对分析结果进行格式转换
                self.results_data = trans_result_verifier_2_auditor(trans_result_checker_2_verifier(json_load))
                check_status, check_error, error_data = validate_auditor_struct(self.results_data)
                if check_error:
                    QMessageBox.critical(self, '错误', f'数据格式异常,请修正后再试: {check_error} -> {error_data[:200]}')
                    return

                # 进行文件备份,防止用户进行文件修改
                copy_status, copy_error = copy_file(file_name, cover=False)
                if copy_error:
                    QMessageBox.critical(self, '错误', f'创建备份文件失败: {str(copy_error)}')
                    raise copy_error

                # 把当前新格式的数据写入到文件
                self.current_file = file_name  # 保存当前文件路径
                dump_status, dump_error = dump_json(self.current_file, self.results_data)
                if dump_error:
                    QMessageBox.critical(self, '错误', f'保存结果文件失败: {str(copy_error)}')
                    raise dump_error

                # QMessageBox.information(self, '成功', f'加载结果文件成功: {str(file_name)}')
                self._update_tree(self.tree, self.results_data, apply_filter=True)
            except Exception as e:
                QMessageBox.critical(self, '错误', f'加载结果文件失败: {str(e)}')
        else:
            QMessageBox.critical(self, '错误', f'请重新选择文件!')

    def _update_tree_with_data(self, filtered_data):
        """使用筛选后的数据更新树形视图"""
        self.tree.clear()
        if not filtered_data:
            return

        # 根据按钮状态选择不同的树形结构
        if self.tree_view_btn.isChecked():
            create_file_based_tree(self.tree, filtered_data)
        else:
            create_severity_based_tree(self.tree, filtered_data)

        # 调整列宽以适应内容
        self.tree.resizeColumnToContents(0)

    def _clear_all_fields(self):
        """清空所有文本框和下拉框"""
        for edit in self._text_edits():
            edit.clear()
        for combo in [self.audit_combo, self.verify_combo, self.severity_combo]:
            combo.setCurrentText('')

    def _clear_filters(self):
        """重置所有筛选条件为默认值"""
        self.severity_filter.setCurrentText(AuditorUIKeys.ALL_RISKS.value)
        self.vuln_type_filter.setCurrentText(AuditorUIKeys.ALL_TYPES.value)
        self.verify_filter.setCurrentText(AuditorUIKeys.AI_VERIF.value)
        self.audit_filter.setCurrentText(AuditorUIKeys.ME_VERIF.value)
        # 重新应用筛选（实际上是显示所有数据）
        self._update_tree_with_data(self._filtered_data())

    def _update_tree(self, self_tree, results_data, apply_filter=True):
        """更新树形视图，保持当前节点状态"""
        # 保存当前状态
        current_vuln_hash = save_tree_state(self_tree, node_key=AuditorKeys.AUDITOR_HASH.value)
        # 清空树
        self_tree.clear()
        if not results_data:
            return
        # 更新漏洞类型筛选器的选项
        update_filter_text(results_data, self.vuln_type_filter, AuditorUIKeys.ALL_TYPES.value,
                           [VerifyKeys.ORIGINAL.value, RuleKeys.VULN_TYPE.value])
        # 更新AI验证筛选器
        update_filter_text(results_data, self.verify_filter, AuditorUIKeys.AI_VERIF.value,
                           [VerifyKeys.PARSED.value, VerifyKeys.VERIFY.value], VerifyStatus.size())
        # 更新人工验证筛选器
        update_filter_text(results_data, self.audit_filter, AuditorUIKeys.ME_VERIF.value,
                           [AuditorKeys.AUDITED.value], AuditStatus.size())
        # 更新风险级别筛选器
        update_filter_text(results_data, self.severity_filter, AuditorUIKeys.ALL_RISKS.value,
                           [VerifyKeys.ORIGINAL.value, RuleKeys.SEVERITY.value], SeverityLevel.size())
        # 更新树形视图数据
        if apply_filter:
            self._update_tree_with_data(self._filtered_data())
        else:
            self._update_tree_with_data(results_data)
        # 恢复之前的状态
        restore_tree_state(self_tree, node_key=AuditorKeys.AUDITOR_HASH.value, node_value=current_vuln_hash)

    def _update_tree_with_filter(self):
        self._update_tree_with_data(self._filtered_data())


def main():
    app = QApplication(sys.argv)
    viewer = SASTAuditor(DEF_CONFIG_AUDITOR)
    viewer.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
