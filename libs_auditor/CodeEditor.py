from PyQt6.QtCore import Qt, QRect, QSize
from PyQt6.QtGui import (QColor, QTextCharFormat, QSyntaxHighlighter, QPainter, QTextFormat)
from PyQt6.QtWidgets import (QWidget, QVBoxLayout,
                             QApplication, QPlainTextEdit, QMessageBox,
                             QTextEdit, QMenu, QDialog)  # 添加 QLabel

from libs_auditor.ChatDialog import ChatDialog


class LineHighlighter(QSyntaxHighlighter):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.highlight_lines = set()
        self.format = QTextCharFormat()
        # 修改高亮颜色为红色，设置透明度为128
        self.format.setBackground(QColor(255, 0, 0, 128))

    def set_lines(self, lines):
        try:
            # QMessageBox.information(None, '提示', '正在设置高亮行...')
            self.highlight_lines = set(lines) if lines else set()
            self.rehighlight()
            # QMessageBox.information(None, '提示', f'高亮行设置完成: {lines}')
            return True
        except Exception as e:
            QMessageBox.critical(None, '错误', f'设置高亮行失败: {str(e)}')
            return False

    def highlightBlock(self, text):
        try:
            block_number = self.currentBlock().blockNumber() + 1
            if block_number in self.highlight_lines:
                self.setFormat(0, len(text), self.format)
        except Exception as e:
            QMessageBox.critical(None, '错误', f'高亮处理错误: {str(e)}')


class LineNumberArea(QWidget):
    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor

    def sizeHint(self):
        return QSize(self.editor.line_number_area_width(), 0)

    def paintEvent(self, event):
        self.editor.line_number_area_paint_event(event)


class SearchResultDialog(QDialog):
    _last_x = None  # 类变量，记录上次的 x 坐标
    _last_y = None  # 类变量，记录上次的 y 坐标

    def __init__(self, title, content, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(600, 400)

        # 设置窗口标志
        self.setWindowFlags(Qt.WindowType.Window)
        self.setWindowModality(Qt.WindowModality.NonModal)

        # 获取屏幕和主窗口信息
        screen = QApplication.primaryScreen()
        screen_geometry = screen.availableGeometry()

        # 设置窗口位置
        if SearchResultDialog._last_x is not None and SearchResultDialog._last_y is not None:
            # 确保位置在屏幕范围内
            x = min(max(SearchResultDialog._last_x, 0), screen_geometry.width() - self.width())
            y = min(max(SearchResultDialog._last_y, 0), screen_geometry.height() - self.height())
            self.move(x, y)
        else:
            # 首次打开时，放置在屏幕最右边
            x = screen_geometry.width() - self.width() - 20
            y = (screen_geometry.height() - self.height()) // 2
            self.move(x, y)

        layout = QVBoxLayout(self)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        text_edit.setHtml(content)
        layout.addWidget(text_edit)

    def moveEvent(self, event):
        # 保存移动后的位置
        SearchResultDialog._last_x = self.x()
        SearchResultDialog._last_y = self.y()
        super().moveEvent(event)

    def closeEvent(self, event):
        # 关闭时也保存位置
        SearchResultDialog._last_x = self.x()
        SearchResultDialog._last_y = self.y()
        super().closeEvent(event)


class CodeEditor(QPlainTextEdit):
    def __init__(self, ai_clients_infos=None, ai_model_name=None):
        super().__init__()
        self.ai_clients_infos = ai_clients_infos
        self.ai_model_name = ai_model_name
        self.line_number_area = LineNumberArea(self)
        self.search_thread = None  # 添加搜索线程属性

        self.blockCountChanged.connect(self.update_line_number_area_width)
        self.updateRequest.connect(self.update_line_number_area)
        self.cursorPositionChanged.connect(self.highlight_current_line)

        self.update_line_number_area_width(0)
        self.setReadOnly(True)

        # Add right-click menu support
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def search_by_chat_ai(self, text, ai_clients_infos, ai_model_name):
        try:
            if not ai_clients_infos or not ai_model_name:
                raise Exception(f"ai_client:[{ai_clients_infos}] or ai_model_name:[{ai_model_name}] Is None")
            dialog = ChatDialog(ai_clients_infos, ai_model_name, text, self)
            dialog.show()
        except Exception as e:
            QMessageBox.critical(self, "错误", f"创建对话框失败：{str(e)}")

    # 在 CodeEditor 类中修改对话框的显示方式
    def _handle_search_result(self, success, message, elapsed_time):
        """处理搜索结果的回调函数"""
        try:
            main_window = self.window()
            if success:
                if main_window:
                    main_window.statusBar().showMessage(f"搜索完成，用时：{elapsed_time:.2f}秒")
                dialog = SearchResultDialog(f"搜索结果（用时：{elapsed_time:.2f}秒）", message, self)
                dialog.show()
            else:
                if main_window:
                    main_window.statusBar().showMessage(f"搜索失败，用时：{elapsed_time:.2f}秒")
                QMessageBox.warning(self, "搜索失败", message)
        finally:
            if self.search_thread:
                self.search_thread.deleteLater()
                self.search_thread = None

    def line_number_area_width(self):
        digits = len(str(max(1, self.blockCount())))
        space = 3 + self.fontMetrics().horizontalAdvance('9') * digits
        return space

    def update_line_number_area_width(self, _):
        self.setViewportMargins(self.line_number_area_width(), 0, 0, 0)

    def update_line_number_area(self, rect, dy):
        if dy:
            self.line_number_area.scroll(0, dy)
        else:
            self.line_number_area.update(0, rect.y(), self.line_number_area.width(), rect.height())
        if rect.contains(self.viewport().rect()):
            self.update_line_number_area_width(0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        cr = self.contentsRect()
        self.line_number_area.setGeometry(QRect(cr.left(), cr.top(),
                                                self.line_number_area_width(), cr.height()))

    def line_number_area_paint_event(self, event):
        painter = QPainter(self.line_number_area)
        painter.fillRect(event.rect(), Qt.GlobalColor.lightGray)

        block = self.firstVisibleBlock()
        block_number = block.blockNumber()
        top = round(self.blockBoundingGeometry(block).translated(self.contentOffset()).top())
        bottom = top + round(self.blockBoundingRect(block).height())

        while block.isValid() and top <= event.rect().bottom():
            if block.isVisible() and bottom >= event.rect().top():
                number = str(block_number + 1)
                painter.setPen(Qt.GlobalColor.black)
                painter.drawText(0, top, self.line_number_area.width(), self.fontMetrics().height(),
                                 Qt.AlignmentFlag.AlignRight, number)

            block = block.next()
            top = bottom
            bottom = top + round(self.blockBoundingRect(block).height())
            block_number += 1

    def highlight_current_line(self):
        extraSelections = []

        if not self.isReadOnly():
            selection = QTextEdit.ExtraSelection()
            lineColor = QColor(Qt.GlobalColor.yellow).lighter(160)
            selection.format.setBackground(lineColor)
            selection.format.setProperty(QTextFormat.Property.FullWidthSelection, True)
            selection.cursor = self.textCursor()
            selection.cursor.clearSelection()
            extraSelections.append(selection)

        self.setExtraSelections(extraSelections)

    def show_context_menu(self, position):
        menu = QMenu(self)
        cursor = self.textCursor()
        selected_text = cursor.selectedText()

        if selected_text:
            search_action = menu.addAction("AI分析选中内容")
            search_action.triggered.connect(lambda: self.search_by_chat_ai(selected_text, self.ai_clients_infos, self.ai_model_name))

        menu.exec(self.mapToGlobal(position))


