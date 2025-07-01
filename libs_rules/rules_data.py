from libs_rules.rules_enum import RuleKeys, SeverityLevel, VulnType


def fixed_rules(dic: dict) -> dict:
    for language in dic.get(RuleKeys.LANGUAGES.value):
        for rule in language[RuleKeys.VULNS.value]:
            # severity
            rule[RuleKeys.SEVERITY.value] = SeverityLevel.format(rule.get(RuleKeys.SEVERITY.value, SeverityLevel.UNKNOWN.value))
            # ignore_case: true
            rule[RuleKeys.IGNORE_CASE.value] = bool(rule.get(RuleKeys.IGNORE_CASE.value, True))
            # loaded: true
            rule[RuleKeys.LOADED.value] = bool(rule.get(RuleKeys.LOADED.value, True))
            # context_need: false
            rule[RuleKeys.CONTEXT_NEED.value] = bool(rule.get(RuleKeys.CONTEXT_NEED.value, True))
            # context_before: 300
            rule[RuleKeys.CONTEXT_BEFORE.value] = int(rule.get(RuleKeys.CONTEXT_BEFORE.value, 300))
            # context_after: 300
            rule[RuleKeys.CONTEXT_AFTER.value] = int(rule.get(RuleKeys.CONTEXT_AFTER.value, 300))
            # patterns:  - '(?:(?:access)(?:[-_])(?:key)(?:[-_])(?:id|secret))'
            rule[RuleKeys.PATTERNS.value] = list(rule.get(RuleKeys.PATTERNS.value, []))
            # 为旧规则添加规则分类默认值
            rule[RuleKeys.VULN_TYPE.value] = VulnType.format(rule.get(RuleKeys.VULN_TYPE.value, VulnType.OTHER.value))
    return dic