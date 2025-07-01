from PyQt6.QtWidgets import QToolBar, QMenu, QToolButton
from PyQt6.QtGui import QAction, QIcon

class RulesToolBar(QToolBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMovable(False)  # 设置工具栏不可移动
        self.setup_actions()

    def setup_actions(self):
        # 创建动作

        # 添加打开配置文件按钮
        self.reload_action = QAction('快速加载', self)
        self.reload_action.setStatusTip("快速加载配置文件")
        self.addAction(self.reload_action)
        self.addSeparator()  # 添加分隔符

        self.open_action = QAction('打开配置', self)
        # self.open_action.setIcon(QIcon.fromTheme('document-open'))
        self.open_action.setStatusTip("加载指定配置文件")
        self.addAction(self.open_action)
        self.addSeparator()  # 添加分隔符

        self.save_action = QAction('保存配置', self)
        self.save_action.setStatusTip("保存当前配置到文件")
        self.addAction(self.save_action)
        self.addSeparator()  # 添加分隔符

        # 创建规则管理菜单
        self.rules_menu = QMenu('规则管理', self)
        
        # 添加检查所有规则动作
        self.check_action = QAction('检查所有', self)
        self.check_action.setStatusTip("检查所有规则匹配情况")
        self.rules_menu.addAction(self.check_action)
        
        # 添加启用/禁用动作
        self.disable_action = QAction('禁用所有', self)
        self.disable_action.setStatusTip("禁用所有规则")
        self.rules_menu.addAction(self.disable_action)
        
        self.enable_action = QAction('启用所有', self)
        self.enable_action.setStatusTip("启用所有规则")
        self.rules_menu.addAction(self.enable_action)
        
        # 添加规则排序动作
        self.sort_action = QAction("规则排序", self)
        self.sort_action.setStatusTip("按字母顺序排序每个语言的规则")
        self.rules_menu.addAction(self.sort_action)
        
        # 添加检查重复规则动作
        self.check_dup_action = QAction("检查重复", self)
        self.check_dup_action.setStatusTip("检查每个语言是否存在重复规则")
        self.rules_menu.addAction(self.check_dup_action)

        # 创建规则管理按钮并设置菜单
        self.rules_button = QToolButton(self)
        self.rules_button.setText('规则管理')
        self.rules_button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.rules_button.setMenu(self.rules_menu)
        self.addWidget(self.rules_button)
        self.addSeparator()  # 添加分隔符
