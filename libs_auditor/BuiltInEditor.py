from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QTextCharFormat, QTextCursor, QColor
from PyQt6.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLineEdit, QPushButton, QApplication, \
    QMessageBox

from libs_auditor.CodeEditor import CodeEditor, LineHighlighter


class BuiltInEditor(QMainWindow):
    _last_x = None  # 类变量，记录上次的 x 坐标
    _last_y = None  # 类变量，记录上次的 y 坐标

    def __init__(self, parent=None, ai_clients_infos=None, ai_model_name=None):
        super().__init__(parent)
        self.ai_clients_infos = ai_clients_infos
        self.ai_model_name = ai_model_name

        # 创建主布局
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # 创建搜索框布局
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("输入搜索内容...")
        self.search_input.returnPressed.connect(self.find_text)
        search_btn = QPushButton("搜索")
        search_btn.clicked.connect(self.find_text)

        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)

        # 添加编辑器
        self.editor = CodeEditor(ai_clients_infos=self.ai_clients_infos, ai_model_name=self.ai_model_name)
        layout.addWidget(self.editor)

        # 创建状态栏
        self.statusBar().showMessage("就绪")

        self.resize(800, 600)

        # 设置窗口位置
        screen = QApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()

        # 等待窗口完成初始化后再设置位置
        QTimer.singleShot(100, lambda: self._set_window_position(screen_geometry))

    def _set_window_position(self, screen_geometry):
        if BuiltInEditor._last_x is not None and BuiltInEditor._last_y is not None:
            # 使用上次记录的位置
            x = min(max(BuiltInEditor._last_x, 0), screen_geometry.width() - self.width())
            y = min(max(BuiltInEditor._last_y, 0), screen_geometry.height() - self.height())
            self.move(x, y)
        else:
            # 首次打开时，放置在屏幕最右边
            x = screen_geometry.width() - self.width() - 20
            y = (screen_geometry.height() - self.height()) // 2
            self.move(x, y)

        # 初始化高亮器
        self.highlighter = LineHighlighter(self.editor.document())

    def find_text(self):
        search_text = self.search_input.text()
        if not search_text:
            self.statusBar().showMessage("请输入搜索内容")
            return

        cursor = self.editor.textCursor()
        # 保存当前位置
        current_pos = cursor.position()

        # 清除之前的高亮
        char_format = QTextCharFormat()
        cursor.select(QTextCursor.SelectionType.Document)
        cursor.mergeCharFormat(char_format)
        cursor.clearSelection()

        # 从当前位置开始搜索
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.editor.setTextCursor(cursor)

        # 设置高亮格式
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 0, 0, 100))  # 红色背景，半透明
        highlight_format.setForeground(QColor(255, 255, 255))  # 白色文字

        # 查找文本并高亮
        found = self.editor.find(search_text)
        if found:
            # 获取当前行号
            cursor = self.editor.textCursor()
            current_line = cursor.blockNumber() + 1
            self.statusBar().showMessage(f"找到匹配内容，位于第 {current_line} 行")
            cursor.mergeCharFormat(highlight_format)
        else:
            # 如果没找到，从头开始搜索
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            self.editor.setTextCursor(cursor)
            found = self.editor.find(search_text)
            if found:
                cursor = self.editor.textCursor()
                current_line = cursor.blockNumber() + 1
                self.statusBar().showMessage(f"找到匹配内容，位于第 {current_line} 行")
                cursor.mergeCharFormat(highlight_format)

        if not found:
            self.statusBar().showMessage("未找到匹配内容")
            QMessageBox.information(self, "搜索结果", "未找到匹配内容")
            # 恢复原来的位置
            cursor.setPosition(current_pos)
            self.editor.setTextCursor(cursor)

    def open_file(self, file_path, jump_line=1, highlight_lines=None):
        try:
            # QMessageBox.information(self, '提示', f'正在打开文件: {file_path}')

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 设置窗口标题和内容
            self.setWindowTitle(f'内置编辑器 - {file_path}')
            self.editor.setPlainText(content)  # 修改这里，使用 setPlainText 而不是 setText

            # 设置高亮
            if highlight_lines and self.highlighter:
                self.highlighter.set_lines(highlight_lines)

            # 延迟跳转到指定行
            QTimer.singleShot(200, lambda: self._delayed_jump(jump_line))

            self.statusBar().showMessage(f"已加载文件: {file_path}")
            # QMessageBox.information(self, '提示', '文件加载完成')
            return True

        except Exception as e:
            QMessageBox.critical(self, '错误', f"打开文件失败: {str(e)}")
            return False

    def _delayed_jump(self, line_number):
        try:
            # 获取总行数并验证行号
            total_lines = self.editor.document().blockCount()
            line_number = max(1, min(line_number, total_lines))

            cursor = self.editor.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)

            # 移动到指定行
            for _ in range(line_number - 1):
                if not cursor.movePosition(QTextCursor.MoveOperation.NextBlock):
                    break

            # 选中整行并设置光标
            cursor.movePosition(QTextCursor.MoveOperation.EndOfLine, QTextCursor.MoveMode.KeepAnchor)
            self.editor.setTextCursor(cursor)
            self.editor.ensureCursorVisible()

            self.statusBar().showMessage(f"已跳转到第 {line_number} 行")

        except Exception as e:
            QMessageBox.critical(self, '错误', f"跳转行失败: {str(e)}")

    def moveEvent(self, event):
        # 保存移动后的位置
        BuiltInEditor._last_x = self.x()
        BuiltInEditor._last_y = self.y()
        super().moveEvent(event)

    def closeEvent(self, event):
        # 关闭时也保存位置
        BuiltInEditor._last_x = self.x()
        BuiltInEditor._last_y = self.y()
        super().closeEvent(event)
