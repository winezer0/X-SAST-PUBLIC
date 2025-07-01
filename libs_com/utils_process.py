import time
from datetime import timedelta


def print_progress(completed_task, total_task, start_time):
    elapsed = time.time() - start_time
    remaining = (elapsed / completed_task) * (total_task - completed_task) if completed_task > 0 else 0
    # 将秒数转换为可读的时间格式
    elapsed_delta = timedelta(seconds=int(elapsed))
    remaining_delta = timedelta(seconds=int(remaining))
    print(f"\r[*] 当前进度: {completed_task}/{total_task} ({(completed_task / total_task * 100):.2f}%) "
          f"已用时长: {str(elapsed_delta)} 预计剩余: {str(remaining_delta)}", end='')