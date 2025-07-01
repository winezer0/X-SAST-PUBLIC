import re
from typing import Dict

from libs_checker.checker_enum import CheckerKeys
from libs_com.file_io import file_encoding, read_by_chunks, read_file_safe
from libs_com.file_path import get_absolute_path
from libs_com.utils_hash import calc_checker_result_hash
from libs_rules.rules_enum import RuleKeys


def scan_task_rule(content: str, task_info: Dict) -> Dict:
    """使用单个规则扫描内容"""
    match_infos = []
    if not content:
        return match_infos
    # 从任务信息中获取规则
    pattern = task_info.get(RuleKeys.PATTERN.value)
    try:
        flags = re.MULTILINE | (re.IGNORECASE if task_info.get(RuleKeys.IGNORE_CASE.value, True) else 0)
        matches = re.finditer(pattern, content, flags)
        for match in matches:
            matched_text = match.group()
            context_before = task_info.get(RuleKeys.CONTEXT_BEFORE.value, 50)
            context_after = task_info.get(RuleKeys.CONTEXT_AFTER.value, 50)
            start_pos = max(0, match.start() - context_before)
            end_pos = min(len(content), match.end() + context_after)
            context = content[start_pos:end_pos]

            checker_result = {
                **task_info,
                # RuleKeys.VULN_NAME.value: rule_info.get(RuleKeys.VULN_NAME.value),
                # RuleKeys.SEVERITY.value: rule_info.get(RuleKeys.SEVERITY.value),
                # RuleKeys.DESCRIPTION.value: rule_info.get(RuleKeys.DESCRIPTION.value),
                # RuleKeys.LANGUAGE.value: rule_info.get(RuleKeys.LANGUAGE.value),
                # CheckerKeys.FILE.value: relative_path,  # 在任务信息中已经存在
                # CheckerKeys.PATTERN.value: pattern,
                CheckerKeys.LINE.value: content.count('\n', 0, match.start()),
                CheckerKeys.MATCH.value: matched_text,
                CheckerKeys.CONTEXT.value: context,
            }

            # 为查找结果计算HASH信息 不然后面无法合并和去重结果数据
            checker_result[CheckerKeys.CHECKER_HASH.value] = calc_checker_result_hash(checker_result)
            match_infos.append(checker_result)
    except re.error as e:
        print(f"正则表达式错误 in {task_info[RuleKeys.RULE_NAME.value]}: {str(e)}")
    return match_infos


def _check_file(task_hash : str, task_info:dict, project_root: str, chunk_mode: bool):
    relative_path = task_info[CheckerKeys.FILE.value]
    absolute_path = get_absolute_path(relative_path, project_root)
    # 处理需要扫描的规则
    task_matches = []
    try:
        if chunk_mode:
            chunk_size = 1024 * 1024  # 每次读取1MB的数据
            with open(absolute_path, 'r', encoding=file_encoding(absolute_path), errors="ignore") as file:
                for chunk in read_by_chunks(file, chunk_size):
                    # 返回的结果是一个列表,因为规则有多个正则
                    checked_result = scan_task_rule(chunk, task_info)
                    task_matches.extend(checked_result)
        else:
            content, encoding = read_file_safe(absolute_path)
            checked_result = scan_task_rule(content, task_info)
            task_matches.extend(checked_result)
    except Exception as error:
        print(f"规则扫描出错: {relative_path} -> Error: {str(error)}")
        raise error
    return task_hash, task_matches
