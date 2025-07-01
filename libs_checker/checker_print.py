from libs_checker.checker_enum import CheckerKeys
from libs_rules.rules_enum import RuleKeys, SeverityLevel, VulnType


def print_scan_stats(static_check_results: list):
    """输出扫描结果统计信息"""
    # 统计数据
    unique_files = set()
    vuln_types = {}
    severity_types = {}

    for vuln in static_check_results:
        # 统计文件
        unique_files.add(vuln.get(CheckerKeys.FILE.value, ''))
        # 统计漏洞类型
        vuln_type = vuln.get(RuleKeys.VULN_TYPE.value, VulnType.OTHER.value)
        vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        # 统计严重级别
        severity = vuln.get(RuleKeys.SEVERITY.value, '')
        severity_types[severity] = severity_types.get(severity, 0) + 1

    # 输出统计信息
    print("\n扫描结果统计:")
    print("=" * 50)
    print(f"发现漏洞文件数量: {len(unique_files)}")
    print(f"发现漏洞总数: {len(static_check_results)}")

    print("\n漏洞类型分布:")
    print("-" * 50)
    for vuln_type, count in vuln_types.items():
        print(f"[{vuln_type}]: {count} 个")

    print("\n严重级别分布:")
    print("-" * 50)
    for severity, count in sorted(
        severity_types.items(), key=lambda x: {
                SeverityLevel.HIGH.value: 0,
                SeverityLevel.MEDIUM.value: 1,
                SeverityLevel.LOW.value: 2,
                SeverityLevel.UNKNOWN.value: 3,
            }.get(x[0], 4)):
        print(f"[{severity}]: {count} 个")
    print("=" * 50)


def print_check_result(relative_path, rule, finding, matched_text, context):
    print(f"\n发现潜在漏洞:"
          f"\n    严重级别: {rule[RuleKeys.SEVERITY.value]}"
          f"\n    漏洞类型: {rule[RuleKeys.VULN_TYPE.value]}"
          f"\n    文件: {relative_path}"
          f"\n    行号: {finding[CheckerKeys.LINE.value]}"
          f"\n    匹配: {matched_text}"
          f"\n    上下文: {context}")


def print_used_rules(used_rules):
    print("\n" + "=" * 50)
    print("本次扫描使用的规则:")
    for lang in used_rules.get(RuleKeys.LANGUAGES.value, []):
        lang_name = lang.get(RuleKeys.LANGUAGE.value, '')
        for vuln in lang.get(RuleKeys.VULNS.value, []):
            if not vuln.get(RuleKeys.LOADED.value, True):
                continue
            print(f"[{lang_name}] {vuln[RuleKeys.RULE_NAME.value]} (严重级别: {vuln[RuleKeys.SEVERITY.value]})")
    print("\n" + "=" * 50)