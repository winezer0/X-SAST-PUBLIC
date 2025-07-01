from libs_rules.rules_enum import RuleKeys


# def print_rules(rules):
#     if rules is None:
#         print("No rules to display")
#         return
#
#     print("Rules content:")
#     for lang_rule in rules.get(RuleKeys.LANGUAGES.value, []):
#         print(f"\n语言: {lang_rule[RuleKeys.LANGUAGE.value]}")
#         for vuln in lang_rule.get(RuleKeys.VULNS.value, []):
#             print(f"  规则名称: {vuln[RuleKeys.VULN_NAME.value]}")
#             print(f"  规则类型: {vuln[RuleKeys.VULN_TYPE.value]}")
#             print(f"  严重程度: {vuln[RuleKeys.SEVERITY.value]}")
#             print(f"  规则描述: {vuln[RuleKeys.DESCRIPTION.value]}")
#             print(f"  忽略大小写: {vuln[RuleKeys.IGNORE_CASE.value]}")
#             print(f"  匹配模式: {', '.join(vuln[RuleKeys.PATTERNS.value])}")
#             print(f"  相关后缀: {vuln.get(RuleKeys.RELATED_SUFFIXES.value, '*')}")
#             print(f"  上下文行数: 前{vuln.get(RuleKeys.CONTEXT_BEFORE.value, 50)}行, 后{vuln.get(RuleKeys.CONTEXT_AFTER.value, 50)}行")
#             print(f"  上下文依赖: {vuln.get(RuleKeys.CONTEXT_NEED.value, False)}")
#             print(f"  启用状态: {vuln.get(RuleKeys.LOADED.value, True)}")
#             print(f"  示例代码:\n{vuln[RuleKeys.SAMPLE_CODE.value]}")
#             print("  " + "-" * 50)


def print_rules_stats(rules):
    """输出规则统计信息"""
    total_rules, loaded_rules, rules_by_lang = get_rules_stats(rules)

    print("\n规则统计信息:")
    print("=" * 50)
    print(f"总规则数量: {total_rules}")
    print(f"已加载规则: {loaded_rules}")
    print(f"未加载规则: {total_rules - loaded_rules}")
    print("-" * 50)
    print("各语言规则统计:")
    for lang_name, stats in rules_by_lang.items():
        print(f"[{lang_name}] 总数: {stats['total']}, 已加载: {stats[RuleKeys.LOADED.value]}, "
                f"未加载: {stats['total'] - stats[RuleKeys.LOADED.value]}")
    print("=" * 50)


def get_rules_stats(rules):
    total_rules = 0
    loaded_rules = 0
    rules_by_lang = {}
    for lang in rules.get(RuleKeys.LANGUAGES.value, []):
        lang_name = lang.get(RuleKeys.LANGUAGE.value, 'Unknown')
        vulnerabilities = lang.get(RuleKeys.VULNS.value, [])

        lang_total = len(vulnerabilities)
        lang_loaded = sum(1 for rule in vulnerabilities if rule.get(RuleKeys.LOADED.value, True))

        total_rules += lang_total
        loaded_rules += lang_loaded
        rules_by_lang[lang_name] = {
            'total': lang_total,
            RuleKeys.LOADED.value: lang_loaded
        }
    return total_rules, loaded_rules, rules_by_lang,