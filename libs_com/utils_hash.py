import hashlib
import json
import os
from typing import Dict

from libs_checker.checker_enum import CheckerKeys
from libs_rules.rules_enum import RuleKeys
from libs_verifier.verifier_enum import VerifyKeys


def get_path_hash(rules_path, length=8):
    abs_path = f"{os.path.abspath(rules_path)}"
    return hashlib.md5(abs_path.encode()).hexdigest()[:length]


def get_strs_hash(*args, length=8):
    """计算传入的任意个字符串的MD5哈希值，并返回指定长度的前缀"""
    if not args:
        raise ValueError("至少需要提供一个字符串参数")
    if length <= 0:
        raise ValueError("hash_length必须是正整数")
    # 将所有字符串连接成一个单一的字符串，使用'|'作为分隔符
    concatenated_string = '|'.join(str(arg) for arg in args)
    # 计算MD5哈希值
    hash_object = hashlib.md5(concatenated_string.encode('utf-8'))
    hex_digest = hash_object.hexdigest()
    # 返回指定长度的前缀
    return hex_digest[:length]


def calc_rule_info_hash(rule_info: Dict) -> str:
    # 计算扫描规则的哈希值
    patterns_list = rule_info.get(RuleKeys.PATTERNS.value, [])
    patterns_hash = get_strs_hash(
        rule_info.get(RuleKeys.LANGUAGE.value),
        rule_info.get(RuleKeys.VULN_TYPE.value),
        json.dumps(sorted(patterns_list))
    )
    return f"rule_{patterns_hash}"


def calc_checker_task_hash(task_info: Dict) -> str:
    # 计算扫描规则的哈希值
    pattern_str = (task_info.get(RuleKeys.PATTERN.value, None)
                   or json.dumps(sorted(task_info.get(RuleKeys.PATTERNS.value, []))))

    task_hash = get_strs_hash(
        task_info.get(CheckerKeys.FILE.value),
        task_info.get(RuleKeys.LANGUAGE.value),
        task_info.get(RuleKeys.VULN_TYPE.value),
        pattern_str,
    )
    return f"task_{task_hash}"


def calc_checker_result_hash(checker_result: dict) -> str:
    """为 checker 结果生成唯一键"""
    # 计算漏洞信息的哈希值 将 漏洞文件|漏洞行|语言|名称 相同的数据作为一个漏洞信息,避免重复扫描
    hash_key = get_strs_hash(
        checker_result.get(RuleKeys.LANGUAGE.value),   # 漏洞语言
        checker_result.get(RuleKeys.VULN_TYPE.value),       # 漏洞类型
        checker_result.get(CheckerKeys.FILE.value),          # 漏洞文件
        checker_result.get(CheckerKeys.LINE.value),          # 漏洞行
        # checker_result.get(CheckerKeys.CONTEXT.value),     # 漏洞内容|部分情况下 以上三种相同的情况,可以考虑合并

    )
    return f"checker_{hash_key}"


def calc_verifier_task_hash(checker_result, model_name, prompt_text):
    """为 verifier_vuln 预生成唯一键作为缓存 使用 漏洞信息|模型|提示词模板 hash"""
    # 目标是做到一个漏洞 可以通过多个模型、多个提示词 进行扫描
    # model_name = checker_result.get(VerifyKeys.MODEL.value)
    # prompt_text = checker_result.get(VerifyKeys.PROMPT.value)
    checker_hash = checker_result.get(CheckerKeys.CHECKER_HASH.value)
    hash_key = get_strs_hash(checker_hash, model_name, prompt_text)
    return f"verifier_{hash_key}"

def calc_auditor_result_hash(verifier_result):
    """为 verifier 结果生成唯一键 作为树节点 漏洞信息|分析结果"""
    # 静态提取结果部分hash
    checker_hash = verifier_result.get(VerifyKeys.ORIGINAL.value).get(CheckerKeys.CHECKER_HASH.value)
    # AI解析结果信息
    response = verifier_result.get(VerifyKeys.RESPONSE.value)
    hash_key = get_strs_hash(checker_hash, response)
    return f"auditor_{hash_key}"
