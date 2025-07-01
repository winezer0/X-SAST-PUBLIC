import re

from libs_rules.rules_enum import RuleKeys
from libs_rules.rules_print import print_rules_stats


def validate_rule(rule):
    """验证规则格式是否完整"""
    required_fields = [
        RuleKeys.RULE_NAME.value,  # 规则名称
        RuleKeys.VULN_TYPE.value,  # 规则名称
        RuleKeys.PATTERNS.value,  # 匹配模式
        RuleKeys.DESCRIPTION.value,  # 描述
        RuleKeys.SEVERITY.value,  # 严重程度
        RuleKeys.SAMPLE_CODE.value,  # 示例代码
        RuleKeys.IGNORE_CASE.value,  # 忽略大小写
        RuleKeys.LOADED.value,  # 启用状态
        RuleKeys.RELATED_SUFFIXES.value,  # 相关后缀
        RuleKeys.CONTEXT_BEFORE.value,  # 上文行数
        RuleKeys.CONTEXT_AFTER.value,  # 下文行数
        RuleKeys.CONTEXT_NEED.value,  # 需要上下文
    ]

    # 检查必需字段
    for field in required_fields:
        if field not in rule:
            print(f"缺少必需字段: {field}")
            return False

    # 验证字段值的类型
    if not isinstance(rule[RuleKeys.PATTERNS.value], list):
        print("patterns 必须是列表类型")
        return False
    if not isinstance(rule[RuleKeys.IGNORE_CASE.value], bool):
        print("ignore_case 必须是布尔类型")
        return False
    if not isinstance(rule[RuleKeys.LOADED.value], bool):
        print("loaded 必须是布尔类型")
        return False
    if not isinstance(rule[RuleKeys.CONTEXT_BEFORE.value], int):
        print("context_before 必须是整数类型")
        return False
    if not isinstance(rule[RuleKeys.CONTEXT_AFTER.value], int):
        print("context_after 必须是整数类型")
        return False
    if not isinstance(rule[RuleKeys.CONTEXT_NEED.value], bool):
        print("context_need 必须是布尔类型")
        return False

    # 验证正则表达式
    for pattern in rule[RuleKeys.PATTERNS.value]:
        try:
            re.compile(pattern)
        except re.error as e:
            rule_name = rule.get(RuleKeys.RULE_NAME.value)
            print(f"存在不正确的正则规则：\n{rule_name}\n {pattern}\n {str(e)}\n请修复后再运行扫描")
            return False
    return True


def validate_rules(rules):
    """验证所有规则"""
    if not rules or RuleKeys.LANGUAGES.value not in rules:
        return False

    for lang_rule in rules[RuleKeys.LANGUAGES.value]:
        if RuleKeys.LANGUAGE.value not in lang_rule or RuleKeys.VULNS.value not in lang_rule:
            return False

        for vuln in lang_rule[RuleKeys.VULNS.value]:
            if not validate_rule(vuln):
                print(f"规则验证失败: {vuln}")
                return False
    return True


def validate_pattern(pattern, sample_code, ignore_case):
    try:
        flags = re.IGNORECASE | re.MULTILINE | re.DOTALL if ignore_case else re.MULTILINE | re.DOTALL
        sample_code = ' '.join(sample_code.splitlines())
        # 使用 re.finditer 来获取完整匹配
        matches = []
        for match in re.finditer(pattern, sample_code, flags):
            matches.append(match.group(0))  # group(0) 返回完整匹配
        return matches if matches else []
    except re.error as e:
        print(f"正则表达式错误: {e}")
        return []


def validate_patterns(rules):
    print("开始验证正则匹配效果...")
    for lang_rule in rules.get(RuleKeys.LANGUAGES.value, []):
        print(f"\n语言类型: {lang_rule[RuleKeys.LANGUAGE.value]}")
        for vuln_rule in lang_rule.get(RuleKeys.VULNS.value, []):
            print(f"漏洞名称: {vuln_rule[RuleKeys.RULE_NAME.value]}")
            print(f"漏洞类型: {vuln_rule[RuleKeys.VULN_TYPE.value]}")
            for pattern in vuln_rule[RuleKeys.PATTERNS.value]:
                if not pattern.strip():
                    continue
                matches = []
                current_matches = validate_pattern(pattern,
                                                   vuln_rule[RuleKeys.SAMPLE_CODE.value],
                                                   vuln_rule[RuleKeys.IGNORE_CASE.value])
                if current_matches:
                    matches.extend(current_matches)
                is_valid = len(matches) > 0
                if is_valid:
                    print(f"验证成功: {', '.join(vuln_rule[RuleKeys.PATTERNS.value])} -> {matches}")
                else:
                    print(f"验证失败: {', '.join(vuln_rule[RuleKeys.PATTERNS.value])} -> {matches}")
                    return False
        print("验证正则匹配效果通过...")
    return True


def check_all_rule_regex(all_lang_rules):
    validation_results = []
    for lang_rule in all_lang_rules:
        invalid_rules = []
        for vuln in lang_rule.get(RuleKeys.VULNS.value, []):
            matches = []
            for pattern in vuln[RuleKeys.PATTERNS.value]:
                if not pattern.strip():
                    continue
                try:
                    flags = re.MULTILINE | re.DOTALL
                    if vuln[RuleKeys.IGNORE_CASE.value]:
                        flags |= re.IGNORECASE

                    sample_code = ' '.join(vuln[RuleKeys.SAMPLE_CODE.value].splitlines())
                    for match in re.finditer(pattern, sample_code, flags):
                        matches.append(match.group(0))
                except re.error as e:
                    invalid_rules.append(f"{vuln[RuleKeys.RULE_NAME.value]}: 正则表达式错误 - {e}")
                    continue

            if not matches:
                invalid_rules.append(f"{vuln[RuleKeys.RULE_NAME.value]}: 无法匹配示例代码")

        if invalid_rules:
            validation_results.append(f"\n语言 {lang_rule[RuleKeys.LANGUAGE.value]} 中的问题:")
            validation_results.extend([f"- {r}" for r in invalid_rules])
    return validation_results


if __name__ == "__main__":
    from libs_com.utils_yaml import load_yaml

    rules_data = load_yaml('../config_rules.yml')
    if validate_rules(rules_data):
        # print_rules(rules_data)
        print_rules_stats(rules_data)
        validate_patterns(rules_data)
    else:
        print("规则格式验证失败")
