from libs_rules.rules_enum import RuleKeys


def reversed_find_rule_info(rules_dict, res_language, res_rule_name, res_severity):
    """根据结果字典反查原始规则信息"""
    for lang_rule in rules_dict[RuleKeys.LANGUAGES.value]:
        # 检查语言是否匹配（支持 ANY 通配符）
        if lang_rule.get(RuleKeys.LANGUAGE.value) != res_language:
            continue
        # 遍历漏洞规则
        for vuln_info in lang_rule[RuleKeys.VULNS.value]:
            # 匹配漏洞名称和严重性
            rule_name = vuln_info.get(RuleKeys.RULE_NAME.value)
            vuln_severity = vuln_info.get(RuleKeys.SEVERITY.value)
            if rule_name == res_rule_name and vuln_severity == res_severity:
                # 匹配成功，返回规则信息
                return vuln_info
    # 如果未找到匹配规则，返回 None
    return None


def results_add_context_key(static_check_results, rules_dict):
    """根据扫描规则给扫描结果添加上下文节点"""
    for vuln_info in static_check_results:
        find_vuln_rule = reversed_find_rule_info(rules_dict,
                                                 vuln_info.get(RuleKeys.LANGUAGE.value),
                                                 vuln_info.get(RuleKeys.RULE_NAME.value),
                                                 vuln_info.get(RuleKeys.SEVERITY.value))
        # 检查是否需要上下文信息
        vuln_info[RuleKeys.CONTEXT_NEED.value] = find_vuln_rule.get(RuleKeys.CONTEXT_NEED.value, False)
    return static_check_results


def sort_lang_rules(all_lang_rules):
    changes_status = False
    for lang in all_lang_rules:
        vulns = lang.get(RuleKeys.VULNS.value, [])
        if vulns:
            # 按规则名称排序
            sorted_vulns = sorted(vulns, key=lambda x: x[RuleKeys.RULE_NAME.value].lower())
            if sorted_vulns != vulns:
                lang[RuleKeys.VULNS.value] = sorted_vulns
                changes_status = True
    return changes_status


def find_lang_dup_rule(all_lang_rules):
    """检查每个语言中是否存在重复规则"""
    duplicate_results = []
    for lang_rule in all_lang_rules:
        lang_name = lang_rule[RuleKeys.LANGUAGE.value]
        rules = lang_rule.get(RuleKeys.VULNS.value, [])

        # 检查规则名称重复
        name_count = {}
        for rule in rules:
            rule_name = rule[RuleKeys.RULE_NAME.value]
            name_count[rule_name] = name_count.get(rule_name, 0) + 1

        # 检查子规则内容重复
        pattern_map = {}
        for rule in rules:
            # 获取所有非空的子规则
            valid_patterns = [p.strip() for p in rule[RuleKeys.PATTERNS.value] if p.strip()]
            if not valid_patterns:  # 跳过没有有效pattern的规则
                continue

            # 对每个子规则单独检查
            for pattern in valid_patterns:
                if pattern in pattern_map:
                    pattern_map[pattern].append(rule[RuleKeys.RULE_NAME.value])
                else:
                    pattern_map[pattern] = [rule[RuleKeys.RULE_NAME.value]]

        # 收集重复结果
        lang_duplicates = []

        # 添加名称重复的规则
        for name, count in name_count.items():
            if count > 1:
                lang_duplicates.append(f"规则名称重复 '{name}' ({count}次)")

        # 添加内容重复的规则
        for pattern, rules in pattern_map.items():
            if len(rules) > 1:  # 如果有多个规则使用相同的pattern
                rules_str = ", ".join(rules)
                lang_duplicates.append(f"子规则重复 '{pattern}' 在规则: {rules_str}")

        if lang_duplicates:
            duplicate_results.append(f"\n语言 {lang_name} 中的重复:")
            duplicate_results.extend([f"- {r}" for r in lang_duplicates])
    return duplicate_results
