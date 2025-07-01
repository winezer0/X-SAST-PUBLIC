from enum import Enum


class CheckerKeys(Enum):
    # RE RUle File Key
    # NAME = "name"
    # TASK_HASH = "task_hash"  # 检查前为每个规则生成一个任务HASH 用于记录已执行任务
    CHECKER_HASH = "checker_hash"  # 检查后为每个规则的解析结果生成一个HASH 用于去重

    PATTERN = "pattern"
    MATCH = "match"
    CONTEXT = "context"
    LINE = "line"
    FILE = "file"

    METHOD_CODE = "method_code"
    CALLED_CODES = "called_codes"

