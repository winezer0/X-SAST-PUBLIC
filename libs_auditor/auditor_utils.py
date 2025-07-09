import os
import subprocess
from shutil import which

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QMessageBox, QFileDialog, QMenu

from libs_auditor.auditor_enum import AuditorKeys
from libs_checker.checker_enum import CheckerKeys
from libs_com.utils_yaml import save_yaml, load_yaml
from libs_verifier.verifier_enum import AIProvider, VerifyKeys


def update_editor_path(config_file, auditor_config, editor_exe, new_path):
    """更新编辑器路径到配置文件"""
    for editor in auditor_config[AuditorKeys.EDITORS.value]:
        if editor[AuditorKeys.EXE.value] == editor_exe:
            editor[AuditorKeys.EXE.value] = os.path.basename(new_path)  # 保存文件名
            editor[AuditorKeys.FULL_PATH.value] = new_path  # 保存完整路径
            return save_yaml(config_file, auditor_config)
    return False


def get_editor_path(auditor_config, editor_exe):
    """获取编辑器的完整路径"""
    for editor in auditor_config[AuditorKeys.EDITORS.value]:
        if editor[AuditorKeys.EXE.value] == editor_exe:
            return editor.get(AuditorKeys.FULL_PATH.value)
    return None


def resolve_path_by_root(config_file, config_dict, file_path, parent=None):
    """解析文件路径，如果是相对路径则转换为绝对路径"""
    if os.path.isabs(file_path):
        if os.path.exists(file_path) and os.path.isfile(file_path):
            return file_path
    else:
        source_root = set_and_get_root_dir(config_dict, config_file, parent)
        if source_root:
            return os.path.normpath(os.path.join(source_root, file_path))
    return None


def set_and_get_root_dir(config_dict, config_file, parent=None):
    source_root = config_dict.get(AuditorKeys.PROJECT.value, {}).get(AuditorKeys.SOURCE_ROOT.value, '')
    if not source_root or not os.path.exists(source_root):
        print(f"parent:{parent}")
        try:
            # 确保 parent 是 None 或 QWidget 对象
            reply = QMessageBox.question(
                parent,  # parent 可以为 None
                '设置项目路径',
                '项目源码根目录未设置或不存在，是否现在设置？',
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No  # 设置默认按钮为 "No"
            )

            if reply == QMessageBox.StandardButton.Yes:
                # 打开文件夹选择对话框
                source_root = QFileDialog.getExistingDirectory(
                    parent,
                    "选择项目源码根目录",
                    os.path.expanduser("~")  # 默认打开用户主目录
                )

                if source_root and os.path.exists(source_root):
                    # 更新配置并保存
                    config_dict[AuditorKeys.PROJECT.value][AuditorKeys.SOURCE_ROOT.value] = source_root
                    save_yaml(config_file, config_dict)
                    QMessageBox.information(
                        parent,
                        "成功",
                        "源码目录设置成功！"
                    )
                    return source_root
                else:
                    QMessageBox.warning(
                        parent,
                        "警告",
                        "未选择有效的源码目录！"
                    )
        except Exception as error:
            QMessageBox.warning(
                parent,
                "错误",
                f"未成功设置源码目录 -> {error}"
            )
        return None
    else:
        return source_root


def load_auditor_config(config_file):
    """加载配置文件"""
    try:
        config = load_yaml(file=config_file, encoding='utf-8')
        if config and all(k in str(config)
                          for k in [AuditorKeys.PROJECT.value,
                                    AuditorKeys.EDITORS.value,
                                    AuditorKeys.SOURCE_ROOT.value,
                                    AuditorKeys.ANALYSE_FILE.value,
                                    AuditorKeys.PROVIDERS.value]):
            return config
        else:
            # 配置文件格式不正确,重新初始化
            default_config = {
                AuditorKeys.PROJECT.value: {AuditorKeys.SOURCE_ROOT.value: '',
                                            AuditorKeys.ANALYSE_FILE.value: ''},
                AuditorKeys.EDITORS.value: [
                    {AuditorKeys.EDITOR_NAME.value: 'Notepad++', AuditorKeys.EXE.value: 'notepad++.exe', AuditorKeys.ARGS.value: '-n{line} "{file}"', AuditorKeys.ENABLED.value: True},
                    {AuditorKeys.EDITOR_NAME.value: 'VSCode', AuditorKeys.EXE.value: 'code.exe', AuditorKeys.ARGS.value: '-g "{file}:{line}"', AuditorKeys.ENABLED.value: True},
                    {AuditorKeys.EDITOR_NAME.value: '记事本', AuditorKeys.EXE.value: 'notepad.exe', AuditorKeys.ARGS.value: '"{file}"', AuditorKeys.ENABLED.value: True}
                ],
                AuditorKeys.PROVIDERS.value: {
                    AIProvider.BASE_URL.value: "https://dashscope.aliyuncs.com/compatible-mode/v1",
                    AIProvider.MODEL_NAME.value: "qwen-plus",
                    AIProvider.API_KEYS.value: [],
                },
            }
            save_yaml(config_file, default_config)
            return default_config
    except Exception as e:
        print(f"加载配置文件失败: {str(e)}")
        return None


def get_enabled_editors(auditor_config):
    """获取已启用的编辑器列表"""
    return [x for x in auditor_config[AuditorKeys.EDITORS.value] if x.get(AuditorKeys.ENABLED.value, False)]


def open_current_file(parent):
    """打开当前选中项的文件"""
    try:
        current_item = parent.tree.currentItem()
        if not current_item:
            QMessageBox.warning(parent, '警告', '请先选择一个漏洞项')
            return

        data = current_item.data(0, Qt.ItemDataRole.UserRole)
        if not data or VerifyKeys.ORIGINAL.value not in data:
            QMessageBox.warning(parent, '警告', '没有获取到漏洞数据')
            return

        file_path = data[VerifyKeys.ORIGINAL.value].get(CheckerKeys.FILE.value)
        line_number = data[VerifyKeys.ORIGINAL.value].get(CheckerKeys.LINE.value, 1)
        file_infos = [(file_path, line_number)]
        if not file_path:
            return

        # 创建打开文件菜单
        menu = QMenu(parent)
        # 添加已启用的编辑器选项
        add_editor_sub_menu(parent, menu, file_infos)
        # 在按钮位置显示菜单
        button = parent.sender()
        if button:
            menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    except Exception as e:
        QMessageBox.warning(parent, '警告', f'打开文件时发生错误: {str(e)}')


def add_editor_sub_menu(parent, menu, file_infos):
    enabled_editors = get_enabled_editors(parent.config_dict)
    if not enabled_editors:
        action = menu.addAction('没有启用任何编辑器')
        action.triggered.connect(
            lambda: QMessageBox.warning(parent, '错误', f'请检查配置文件:{parent.config_file}!'))
    else:
        # 添加已启用的编辑器选项
        for editor in enabled_editors:
            action = menu.addAction(editor[AuditorKeys.EDITOR_NAME.value])
            action.triggered.connect(
                lambda checked, program=editor[AuditorKeys.EXE.value], args=editor[AuditorKeys.ARGS.value], files=file_infos:
                [open_in_editor(parent.config_file, parent.config_dict, program, args, file, line, parent)
                 for file, line in files]
            )


def open_in_editor(config_file, auditor_config, editor_exe, args_template, file_paths, line_number=1, parent=None):
    """在指定编辑器中打开一个或多个文件"""
    try:
        # 支持单个文件路径或文件路径列表
        if isinstance(file_paths, str):
            file_paths = [file_paths]

        for file_path in file_paths:
            # 解析文件路径
            resolved_path = resolve_path_by_root(config_file, auditor_config, file_path, parent)
            print(f"resolved_path:{resolved_path}")
            if resolved_path and os.path.exists(resolved_path):
                # 首先检查配置文件中保存的编辑器路径
                editor_path = get_editor_path(auditor_config, editor_exe)
                if not editor_path:
                    editor_path = which(editor_exe)
                if not editor_path or not os.path.exists(editor_path):
                    if parent:
                        reply = QMessageBox.question(
                            parent,
                            '未找到编辑器',
                            f'未找到编辑器: {editor_exe}\n是否手动指定编辑器位置？',
                            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                        )

                        if reply == QMessageBox.StandardButton.Yes:
                            editor_path, _ = QFileDialog.getOpenFileName(
                                parent,
                                "选择编辑器可执行文件",
                                os.path.expanduser("~"),
                                "可执行文件 (*.exe;*.bat;*.cmd;*.ps1;*.vbs);;所有文件 (*.*)"
                            )
                            if editor_path:
                                # 保存编辑器路径到配置文件
                                # config_file, auditor_config, editor_exe, new_path
                                update_editor_path(config_file, auditor_config, editor_exe, editor_path)
                            else:
                                continue
                        else:
                            continue
                    else:
                        continue
                # 构造命令行参数
                args = args_template.format(file=resolved_path, line=line_number)
                cmd = f'"{editor_path}" {args}'
                # 启动编辑器
                subprocess.Popen(cmd, shell=True)
            else:
                QMessageBox.warning(parent, "失败", f"文件路径不存在:{file_path} -> {resolved_path} 已重置项目路径为None 请重新尝试!!!")
                auditor_config[AuditorKeys.PROJECT.value][AuditorKeys.SOURCE_ROOT.value] = None
                save_yaml(config_file, auditor_config)
                break
    except Exception as e:
        if parent:
            QMessageBox.critical(parent, '错误', f'打开文件失败: {str(e)}')
