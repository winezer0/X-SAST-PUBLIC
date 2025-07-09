import time

from PyQt6.QtCore import QThread, pyqtSignal

from libs_verifier.utils_open_ai import get_random_client, query_model
from libs_verifier.verifier_prompt import build_prompt_sample


class SearchThread(QThread):
    finished = pyqtSignal(bool, str, float)  # 添加用时参数
    progress = pyqtSignal(str)
    TIMEOUT = 30

    def __init__(self, search_text, ai_clients_infos, ai_model_name, parent=None):  # 修改构造函数
        super().__init__(parent)  # 正确传递 parent 参数
        self.search_text = search_text
        self.ai_clients_infos = ai_clients_infos
        self.ai_model_name = ai_model_name
        self.is_running = False

    def run(self):
        start_time = time.time()
        try:
            self.is_running = True
            # 截断显示的文本，只显示前20个字符
            display_text = self.search_text[:20] + "..." if len(self.search_text) > 20 else self.search_text
            self.progress.emit(f"正在分析：{display_text}")

            random_client = get_random_client(self.ai_clients_infos.values())
            while self.is_running and (time.time() - start_time) < self.TIMEOUT:
                try:
                    search_text = build_prompt_sample(self.search_text)
                    response, query_time, error_msg = query_model(random_client, self.ai_model_name, search_text, stream=False)
                    elapsed_time = time.time() - start_time
                    self.finished.emit(True, response, elapsed_time)
                    return
                except Exception as e:
                    if "timeout" not in str(e).lower():
                        raise e
                    time.sleep(0.1)

            if self.is_running:
                self.finished.emit(False, f"分析超时（{self.TIMEOUT}秒），已终止", self.TIMEOUT)

        except Exception as e:
            elapsed_time = time.time() - start_time
            self.finished.emit(False, str(e), elapsed_time)
        finally:
            self.is_running = False
