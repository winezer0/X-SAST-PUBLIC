import time

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import QDialog, QVBoxLayout, QTextEdit, QHBoxLayout, QPushButton, QLabel, QFileDialog, QMessageBox

from libs_auditor.SearchThread import SearchThread
from libs_verifier.verifier_prompt import build_prompt_sample


class ChatDialog(QDialog):
    def __init__(self, ai_clients_infos, ai_model_name, initial_text="", parent=None):
        super().__init__(parent)
        self.ai_clients_infos = ai_clients_infos
        self.ai_model_name = ai_model_name
        self.setWindowTitle("AI 对话")
        self.resize(600, 400)
        self.setWindowFlags(Qt.WindowType.Window)

        layout = QVBoxLayout(self)

        # 对话历史显示区域
        self.chat_history = QTextEdit()
        self.chat_history.setReadOnly(True)
        # 设置滚动条策略
        self.chat_history.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.chat_history.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        # 启用自动换行
        self.chat_history.setLineWrapMode(QTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self.chat_history)

        # 输入区域
        input_layout = QVBoxLayout()  # 改为垂直布局
        self.input_edit = QTextEdit()  # 改用 QTextEdit
        self.input_edit.setMinimumHeight(60)  # 设置最小高度
        self.input_edit.setMaximumHeight(100)  # 设置最大高度

        # 按钮布局
        button_layout = QHBoxLayout()
        send_button = QPushButton("发送")
        send_button.clicked.connect(self.send_message)
        save_button = QPushButton("保存对话")
        save_button.clicked.connect(self.save_chat_history)

        button_layout.addWidget(send_button)
        button_layout.addWidget(save_button)

        input_layout.addWidget(self.input_edit)
        input_layout.addLayout(button_layout)
        layout.addLayout(input_layout)

        # 状态栏
        self.status_label = QLabel("就绪")
        layout.addWidget(self.status_label)

        self.search_thread = None

        # 如果有初始文本，直接发送
        if initial_text:
            self.input_edit.setText(initial_text)
            self.send_message()

    def send_message(self):
        text = self.input_edit.toPlainText().strip()  # 使用 toPlainText() 获取文本
        if not text:
            return

        # 添加计时器
        self.wait_timer = QTimer()
        self.wait_timer.setInterval(100)  # 每0.1秒更新一次
        self.wait_timer.timeout.connect(self.update_wait_time)
        self.start_time = None

        # 添加用户消息到历史记录
        self.chat_history.append(f"<p style='color: blue'>用户: {build_prompt_sample(text)}</p>")
        self.input_edit.clear()  # 清空输入框

        # 开始计时
        self.start_time = time.time()
        self.wait_timer.start()

        # 创建搜索线程
        if self.search_thread and self.search_thread.isRunning():
            self.search_thread.stop()
            self.search_thread.wait()

        self.search_thread = SearchThread(text, ai_clients_infos=self.ai_clients_infos, ai_model_name=self.ai_model_name)
        self.search_thread.progress.connect(self.update_status)
        self.search_thread.finished.connect(self.handle_response)
        self.search_thread.start()

    def update_wait_time(self):
        if self.start_time:
            elapsed = time.time() - self.start_time
            self.status_label.setText(f"等待响应中... {elapsed:.1f}秒")

    def handle_response(self, success, message, elapsed_time):
        # 停止计时器
        self.wait_timer.stop()
        self.start_time = None

        if success:
            self.status_label.setText(f"分析完成 ({elapsed_time:.1f}秒)")
            self.chat_history.append(f"<p style='color: green'>AI: {message}</p>")
        else:
            self.status_label.setText(f"分析失败 ({elapsed_time:.1f}秒)")
            self.chat_history.append(f"<p style='color: red'>错误: {message}</p>")

    def update_status(self, message):
        """更新状态栏消息"""
        self.status_label.setText(message)

    def save_chat_history(self):
        try:
            # 生成当前时间戳作为默认文件名
            default_filename = time.strftime("chat_%Y%m%d_%H%M%S.txt")
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "保存对话记录",
                default_filename,  # 使用时间戳作为默认文件名
                "文本文件 (*.txt);;所有文件 (*.*)"
            )
            if file_path:
                with open(file_path, 'w', encoding='utf-8') as f:
                    content = self.chat_history.toPlainText()
                    f.write(content)
                # 只显示文件名而不是完整路径
                file_name = file_path.split('\\')[-1]
                self.status_label.setText(f"已保存: {file_name}")
        except Exception as e:
            self.status_label.setText("保存失败")
            QMessageBox.critical(self, "错误", f"保存对话记录失败: {str(e)}")
