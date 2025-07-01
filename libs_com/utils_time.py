import time
from datetime import timedelta, datetime


def time_to_seconds(seconds: float) -> str:
    """格式化时间显示"""
    return str(timedelta(seconds=int(seconds)))


def print_time_info(message: str):
    """打印带有时间信息的消息"""
    print(f"[{time_to_seconds(time.time())})] {message}")


def get_current_time(format_str="%Y%m%d_%H%M%S"):
    # 获取当前时间
    now = datetime.now()
    # 格式化时间
    formatted_time = now.strftime(format_str)
    return formatted_time


