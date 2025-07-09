from libs_auditor.auditor_enum import AuditStatus, AuditorKeys
from libs_checker.checker_enum import CheckerKeys
from libs_com.utils_hash import calc_auditor_result_hash
from libs_com.utils_json import print_json
from libs_rules.rules_enum import RuleKeys, SeverityLevel, VulnType
from libs_verifier.verifier_enum import VerifyKeys, VerifyStatus


def validate_auditor_struct(auditor_data):
    """ 验证给定的数据结构是否符合预期的格式。"""
    # 定义期望的数据结构模式
    expected_schema = {
        VerifyKeys.ORIGINAL.value: {
            CheckerKeys.FILE.value: str,
            RuleKeys.LANGUAGE.value: str,
            RuleKeys.RULE_NAME.value: str,
            RuleKeys.VULN_TYPE.value: VulnType,  # 应该是枚举类型 漏洞类型
            RuleKeys.SEVERITY.value: SeverityLevel,  # 枚举类型 风险级别
            RuleKeys.DESCRIPTION.value: str,
            CheckerKeys.MATCH.value: str,
            CheckerKeys.CONTEXT.value: str,
            CheckerKeys.LINE.value: int,
            CheckerKeys.PATTERN.value: str,
            # 此处的 method_code called_codes 在设置 promopt 时已经改为str格式
            CheckerKeys.METHOD_CODE.value: (type(None), str, dict),
            CheckerKeys.CALLED_CODES.value: (type(None), str, list),
        },
        VerifyKeys.PARSED.value: {
            VerifyKeys.VERIFY.value: VerifyStatus,  # 枚举类型 验证状态
            VerifyKeys.SENSITIVE.value: (type(None), str),
            VerifyKeys.HTTP_POC.value: (type(None), str),
            VerifyKeys.EXPLAIN.value: (type(None), str),
            VerifyKeys.REPAIR.value: (type(None), str),
            VerifyKeys.BECAUSE.value: (type(None), str),
        },
        VerifyKeys.RESPONSE.value: (type(None), str),
        VerifyKeys.PROMPT.value: (type(None), str),
        VerifyKeys.MODEL.value: (type(None), str),
        VerifyKeys.ERROR.value: (type(None), str),
        AuditorKeys.AUDITED.value: AuditStatus,  # 枚举类型 审计状态
        AuditorKeys.AUDITOR_HASH.value: str,
    }

    return validate_data_struct(auditor_data, expected_schema)


def validate_data_struct(dicts, expected_schema):
    """ 验证给定的数据结构是否符合预期的格式。"""
    def convert_enum_value(expect, value):
        # 把枚举值转换为枚举对象 TODO 每新增一个枚举类型都需在这里修改一次
        enum_classes = [AuditStatus, SeverityLevel, VerifyStatus, VulnType]
        for enum_class in enum_classes:
            if expect == enum_class and value in enum_class.choices():
                return enum_class.toType(value)
        # 默认返回原值或其他处理
        return value

    def check_dict(data, expect, key_path=""):
        if not isinstance(data, dict):
            raise ValueError(f"Expected a dict but got {type(data)} -> [{data}] at path: {key_path}")
        for key, value_schema in expect.items():
            current_key_path = f"{key_path}.{key}" if key_path else key
            if key not in data:
                raise ValueError(f"Missing key: {key} at path: {current_key_path}")
            check_value(data[key], value_schema, current_key_path)

    def check_value(value, expect, key_path):
        if isinstance(expect, dict):
            check_dict(value, expect, key_path)
        elif isinstance(expect, list):
            if not isinstance(value, list):
                raise ValueError(
                    f"Expected a list but got {type(value)} -> [{value}] at path: {key_path}"
                )
            for i, item in enumerate(value):
                check_value(item, expect[0], f"{key_path}[{i}]")
        elif isinstance(expect, tuple):
            if not any(isinstance(value, t) for t in expect):
                raise ValueError(
                    f"Expected one of {', '.join(t.__name__ for t in expect)} "
                    f"But got {type(value)} -> [{value}] at path: {key_path}"
                )
        elif isinstance(expect, type):
            value = convert_enum_value(expect, value)
            # 放在最后处理
            if not isinstance(value, expect):
                raise ValueError(
                    f"Expected {expect.__name__} But got {type(value).__name__} -> [{value}] at path: {key_path}"
                )
        else:
            raise ValueError(f"Invalid schema type: {type(expect)} -> {value} at path: {key_path}")

    cur_dict = None
    try:
        for cur_dict in dicts:
            check_dict(cur_dict, expected_schema)
        return True, None, None
    except ValueError as e:
        print(f"Validation error: {e} -> {cur_dict}")
        return False, e, cur_dict


def convert_dict_values(data, keys, convert_func, default_value=None, sep='\n'):
    """
    将字典中指定键的值转换为指定格式。支持 list -> str 的自动 join 操作。

    参数:
        data (dict): 原始字典
        keys (list or set or tuple): 需要转换值的键列表
        convert_func (function or type): 转换函数或类型（如 int, float, str）
        default_value (any): 转换失败时使用的默认值（可选）
        sep (str): 如果值是 list 并转为 str，使用此分隔符连接，默认为空

    返回:
        dict: 新字典，含转换后的值
    """

    def tans_dict_2_values(dic):
        return list(dic.values())

    def tans_dicts_2_values(dicts):
        items = []
        for dic in dicts:
            items.extend(tans_dict_2_values(dic))
        return items

    new_data = data.copy()  # 避免修改原字典

    for key in keys:
        if key in new_data:
            value = new_data[key]
            try:
                # 特判：如果值是 list|tuple 且目标类型是 str
                if value and isinstance(value, (list, tuple)) and convert_func == str:
                    value = tans_dicts_2_values(value) if isinstance(value[0], dict) else value
                    new_data[key] = sep.join(map(str, value))
                # 特判：如果值是 dict 且目标类型是 str
                elif value and isinstance(value, dict) and convert_func == str:
                    new_data[key] = sep.join(map(str, tans_dict_2_values(value)))
                else:
                    new_data[key] = convert_func(value)
            except (ValueError, TypeError, SyntaxError) as e:
                if default_value is not None:
                    new_data[key] = default_value
                else:
                    print(f"无法转换键 '{key}' 的值 '{value}': {e}")

    return new_data




def format_parsed_data(parsed: dict) -> dict:
    """修复 AI 分析结果"""
    # "verify": "-1", # 漏洞可能性级别修改为枚举类型
    parsed[VerifyKeys.VERIFY.value] = VerifyStatus.format(parsed.get(VerifyKeys.VERIFY.value))

    # "sensitive": null,
    # "http_poc": null,
    # "explain": null,
    # "because": null,
    # "repair": null,
    # "method": "GET", "url": "/l.php?act=Function"  # TODO 发现多余的节点, parse_json 存在问题
    trans_2_str_keys = [
        VerifyKeys.SENSITIVE.value,
        VerifyKeys.HTTP_POC.value,
        VerifyKeys.EXPLAIN.value,
        VerifyKeys.BECAUSE.value,
        VerifyKeys.REPAIR.value,
    ]
    parsed = convert_dict_values(parsed, trans_2_str_keys, str, default_value="ERROR")
    return parsed


def format_checker_data(original: dict) -> dict:
    """修复静态扫描结果"""
    #   "severity": "HIGH", # 风险级别格式化
    original[RuleKeys.SEVERITY.value] = SeverityLevel.format(original[RuleKeys.SEVERITY.value])
    #   "vuln_type": "代码执行", # 漏洞类型格式化
    original[RuleKeys.VULN_TYPE.value] = VulnType.format(original[RuleKeys.VULN_TYPE.value])

    #   "line": 31,  # 修复行号为数字
    #   "context_before": 300,
    #   "context_after": 200,
    to_int_keys = [
        CheckerKeys.LINE.value,
        RuleKeys.CONTEXT_AFTER.value,
        RuleKeys.CONTEXT_BEFORE.value,
    ]
    original = convert_dict_values(original, to_int_keys, int, default_value=-1)

    #   "rule_name": "Code Execution By Backdoor (RCE)",
    #   "description": "",
    #   "pattern": "\\$_(POST|GET|REQUEST|COOKIE)\\s*\\[['\"\\w]{1,20}\\]",
    #   "language": "PHP",
    #   "file": "l.php",
    #   "match": "$_GET['act']",
    #   "context": "xxx"
    #   "checker_hash": "checker_61fe1847",
    trans_2_str_keys = [
        RuleKeys.RULE_NAME.value,
        RuleKeys.DESCRIPTION.value,
        RuleKeys.PATTERN.value,
        RuleKeys.LANGUAGE.value
        ,
        CheckerKeys.FILE.value,
        CheckerKeys.MATCH.value,
        CheckerKeys.CONTEXT.value,
        CheckerKeys.CHECKER_HASH.value,
    ]
    original = convert_dict_values(original, trans_2_str_keys, str, default_value="ERROR")

    #   "loaded": true,
    #   "ignore_case": true,
    #   "context_need": true,
    trans_2_bool_keys = [
        RuleKeys.LOADED.value,
        RuleKeys.IGNORE_CASE.value,
        RuleKeys.CONTEXT_NEED.value,
    ]
    original = convert_dict_values(original, trans_2_bool_keys, str, default_value=True)

    # 增加 METHOD_CODE　和　Called_Codes
    #   "method_code": "",
    if not original.get(CheckerKeys.METHOD_CODE.value, None):
        original[CheckerKeys.METHOD_CODE.value] = None

    #   "called_codes":  "xxx"
    if not original.get(CheckerKeys.CALLED_CODES.value, None):
        original[CheckerKeys.CALLED_CODES.value] = None
    return original


def trans_result_checker_2_verifier(dicts: list[dict]) -> list[dict]:
    """转换静态检查结果为标准格式"""
    # 判断 dict格式的键是否符合 checker结果的大部分键值对 TODO 可以考虑优化, 为每个工具结果格式进行枚举限定
    if (isinstance(dicts, list) and len(dicts) > 0 and
            CheckerKeys.CHECKER_HASH.value in dicts[0].keys() and
            VerifyKeys.VERIFIER_HASH.value not in dicts[0].keys()):
        trans_data = []
        for checker_data in dicts:
            trans_item = {
                VerifyKeys.ORIGINAL.value: checker_data,
                VerifyKeys.PARSED.value: {
                    VerifyKeys.VERIFY.value: VerifyStatus.UNKNOWN.value,
                    VerifyKeys.SENSITIVE.value: "",
                    VerifyKeys.HTTP_POC.value: "",
                    VerifyKeys.EXPLAIN.value: checker_data.get(RuleKeys.DESCRIPTION.value),
                    VerifyKeys.REPAIR.value: "",
                    VerifyKeys.BECAUSE.value: "",
                },
                VerifyKeys.MODEL.value: "",
                VerifyKeys.PROMPT.value: "",
                VerifyKeys.RESPONSE.value: "",
                VerifyKeys.ERROR.value: "未进行AI分析",
            }
            trans_data.append(trans_item)
        return trans_data
    return dicts


def trans_result_verifier_2_auditor(audit_results: list[dict]) -> list[dict]:
    """转换为人工审计结果格式"""
    new_dicts = []
    vuln_ids = set()
    for audit_result in audit_results:
        # 修复 ORIGINAL节点格式
        if VerifyKeys.ORIGINAL.value not in audit_result.keys():
            print_json(audit_result)
            raise ValueError(f"original 节点不存在:{audit_result}")
        else:
            audit_result[VerifyKeys.ORIGINAL.value] = format_checker_data(audit_result[VerifyKeys.ORIGINAL.value])

        # 修复 PARSED 格式
        if VerifyKeys.PARSED.value not in audit_result:
            print_json(audit_result)
            raise ValueError(f"parsed 节点不存在:{audit_result}")
        else:
            audit_result[VerifyKeys.PARSED.value] = format_parsed_data(audit_result[VerifyKeys.PARSED.value])

        # 增加 manual_audit 手动审计状态记录
        if AuditorKeys.AUDITED.value in audit_result.keys():
            audit_result[AuditorKeys.AUDITED.value] = AuditStatus.format(audit_result[AuditorKeys.AUDITED.value])
        else:
            audit_result[AuditorKeys.AUDITED.value] = AuditStatus.UNKNOWN.value

        # 增加 audit_result node key
        if AuditorKeys.AUDITOR_HASH.value not in audit_result.keys():
            audit_result[AuditorKeys.AUDITOR_HASH.value] = calc_auditor_result_hash(audit_result)
        # 进行去重后添加
        if audit_result[AuditorKeys.AUDITOR_HASH.value] not in vuln_ids:
            vuln_ids.add(audit_result[AuditorKeys.AUDITOR_HASH.value])
            new_dicts.append(audit_result)
    return new_dicts
