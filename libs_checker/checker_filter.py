import sys
from collections import defaultdict

from libs_checker.checker_enum import CheckerKeys
from libs_com.args_utils import to_lowercase
from libs_com.file_path import get_relative_path
from libs_com.file_filter import in_allowed_suffixes
from libs_com.utils_hash import calc_checker_task_hash
from libs_com.utils_dict import dict_pop_keys
from libs_rules.rules_enum import RuleKeys
from libs_rules.rules_print import print_rules_stats


def filter_rules(rules, lang_filter, risk_filter, rule_filter):
    """根据过滤条件筛选规则"""
    if not any([lang_filter, risk_filter, rule_filter]):
        return rules

    # 将过滤条件转换为小写以进行大小写不敏感的比较
    lang_filter = to_lowercase(lang_filter)
    risk_filter = to_lowercase(risk_filter)
    rule_filter = to_lowercase(rule_filter)

    filtered_langs = []
    for lang in rules.get(RuleKeys.LANGUAGES.value, []):
        # 检查语言过滤
        if lang_filter and lang.get(RuleKeys.LANGUAGE.value).lower() not in lang_filter:
            continue

        # 过滤漏洞规则
        filtered_vulns = []
        for vuln in lang.get(RuleKeys.VULNS.value, []):
            # 检查严重级别过滤
            if risk_filter and vuln.get(RuleKeys.SEVERITY.value).lower() not in risk_filter:
                continue

            # 模糊检查规则名称
            if (rule_filter
                    and all(x not in vuln.get(RuleKeys.RULE_NAME.value).lower() for x in rule_filter)
                    and all(x not in vuln.get(RuleKeys.VULN_TYPE.value).lower() for x in rule_filter)):
                continue

            # 确保规则已启用
            if vuln.get(RuleKeys.LOADED.value, True):
                filtered_vulns.append(vuln)

        if filtered_vulns:
            lang_copy = lang.copy()
            lang_copy[RuleKeys.VULNS.value] = filtered_vulns
            filtered_langs.append(lang_copy)

    # 检查是否有匹配的规则
    if not filtered_langs:
        print("\n错误: 未找到匹配的规则!")
        if lang_filter:
            print(f"语言过滤条件: {lang_filter}")
        if risk_filter:
            print(f"严重级别过滤条件: {risk_filter}")
        if rule_filter:
            print(f"规则名称过滤条件: {rule_filter}")
        print("\n可用的规则:")
        for lang in rules.get(RuleKeys.LANGUAGES.value, []):
            print(f"\n语言: {lang.get(RuleKeys.LANGUAGE.value)}")
            for vuln in lang.get(RuleKeys.VULNS.value, []):
                if vuln.get(RuleKeys.LOADED.value, True):
                    print(f"  - {vuln.get(RuleKeys.RULE_NAME.value)} {vuln.get(RuleKeys.VULN_TYPE.value)} (严重级别: {vuln.get(RuleKeys.SEVERITY.value)})")
        sys.exit(1)

    # 更新规则集
    rules[RuleKeys.LANGUAGES.value] = filtered_langs
    print_rules_stats(rules)
    return rules


def split_checker_tasks(checker_tasks, cache_data):
    """分离已经缓存过的规则和未缓存过的规则任务信息"""
    cache_tasks = {}
    check_tasks = {}
    for task_hash, task_info in checker_tasks.items():
        if task_hash in cache_data.keys():
            # 存在缓存数据
            cache_tasks[task_hash] = task_info
        else:
            check_tasks[task_hash] = task_info
    return cache_tasks, check_tasks


def init_checker_tasks(scan_files, rules_dict, project_root) -> dict:
    """整理每个文件应该进行的规则 """
    files_task_info = defaultdict()
    for scan_file in scan_files:
        relative_path = get_relative_path(scan_file, project_root)
        # 整理出该文件需要进行处理的漏洞规则
        lang_infos = rules_dict.get(RuleKeys.LANGUAGES.value, [])
        for lang_info in lang_infos:
            rule_infos = lang_info.get(RuleKeys.VULNS.value, [])
            language = lang_info.get(RuleKeys.LANGUAGE.value)
            for rule_info in rule_infos:
                if rule_info.get(RuleKeys.LOADED.value, True):
                    if in_allowed_suffixes(relative_path, rule_info.get(RuleKeys.RELATED_SUFFIXES.value, "*")):
                        # 为每个存在匹配正则的规则生成一个HASH
                        patterns = rule_info.get(RuleKeys.PATTERNS.value, [])
                        if patterns:
                            for pattern in patterns:
                                # 跳过空规则
                                if not str(pattern).strip():
                                    continue
                                # 为正则添加任务信息
                                task_info = {
                                    **rule_info,
                                    RuleKeys.PATTERN.value: pattern,     # 为任务补充正则信息
                                    RuleKeys.LANGUAGE.value: language,   # 为任务补充语言信息
                                    CheckerKeys.FILE.value: relative_path  # 为任务补充文件信息
                                }

                                # 移除不需要的键
                                remove_keys = [
                                    RuleKeys.PATTERNS.value,
                                    RuleKeys.SAMPLE_CODE.value,
                                    RuleKeys.RELATED_SUFFIXES.value,
                                ]
                                task_info = dict_pop_keys(task_info, remove_keys)

                                # 计算任务Hash
                                task_hash = calc_checker_task_hash(task_info)

                                # task_info[CheckerKeys.TASK_HASH.value] = task_hash
                                files_task_info[task_hash] = task_info
    return files_task_info


def merge_similar_results(check_results):
    """
    对 check_results 进行分类并去重。
    参数: check_results (list of dict): 漏洞检测结果列表
    返回: list: 去重后的最终漏洞列表
    """
    def _filter_group(group_items):
        """
        对同一组内的漏洞结果进行去重处理。
        参数: items (list): 同一类别的漏洞列表
        返回:  list: 去重后的漏洞列表
        """
        n = len(group_items)

        # 只有一个或没有元素，无需处理
        if n <= 1:
            return group_items

        # 标记哪些可以删除
        marked = [False] * n
        for i in range(n):
            if marked[i]:
                continue
            for j in range(i + 1, n):
                if abs(int(group_items[i][CheckerKeys.LINE.value]) - int(group_items[j][CheckerKeys.LINE.value])) <= 5:
                    match_i_in_j = group_items[i][CheckerKeys.MATCH.value] in group_items[j].get(CheckerKeys.CONTEXT.value)
                    match_j_in_i = group_items[j][CheckerKeys.MATCH.value] in group_items[i].get(CheckerKeys.CONTEXT.value)

                    if match_i_in_j and not match_j_in_i:
                        # i 在 j 的 context 中，但 j 不在 i 的 context 中 → 保留 j，删除 i
                        marked[i] = True
                        # print(f"match_i_in_j and not match_j_in_i 即将排除:\n{group_items[i]}")
                        break
                    elif match_j_in_i and not match_i_in_j:
                        # j 在 i 的 context 中，但 i 不在 j 的 context 中 → 保留 i，删除 j
                        marked[j] = True
                        # print(f"match_j_in_i and not match_i_in_j 即将排除:\n{group_items[j]}")
                    elif match_i_in_j and match_j_in_i:
                        # 双方都在对方 context 中 → 保留 context 更长的那个
                        if len(group_items[i].get(CheckerKeys.CONTEXT.value)) >= len(group_items[j].get(CheckerKeys.CONTEXT.value)):
                            marked[j] = True
                            # print(f"match_i_in_j and match_j_in_i 即将排除:\n{group_items[j]}")
                        else:
                            marked[i] = True
                            # print(f"match_i_in_j and match_j_in_i 即将排除:\n{group_items[i]}")
                            break  # 当前 i 被标记为删除，跳出 j 循环

        # 返回未被标记的结果
        return [group_items[index] for index, flag in enumerate(marked) if not flag]


    # 第一步：按 vuln_type、language、severity、file 分类
    groups = defaultdict(list)
    for group_items in check_results:
        key = (
            group_items.get(RuleKeys.VULN_TYPE.value),
            group_items.get(RuleKeys.LANGUAGE.value),
            group_items.get(RuleKeys.SEVERITY.value),
            group_items.get(CheckerKeys.FILE.value),
        )
        groups[key].append(group_items)

    # 第二步：对每个 group 内部做去重
    final_results = []
    for group_key, group_items in groups.items():
        filtered_results = _filter_group(group_items)
        final_results.extend(filtered_results)

    return final_results
