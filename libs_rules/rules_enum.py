from enum import Enum

class RuleKeys(str, Enum):
    LANGUAGES = "languages"
    VULNS = "vulnerabilities"
    LANGUAGE = "language"

    # RE RUle File Key
    RULE_NAME = "rule_name"  # 漏洞规则名称 每个漏洞大类 会 存在多个小漏洞规则
    VULN_TYPE = 'vuln_type'  # 漏洞大类型
    PATTERNS = "patterns"
    PATTERN = "pattern"
    IGNORE_CASE = "ignore_case"
    DESCRIPTION = "description"
    SEVERITY = "severity"
    SAMPLE_CODE = "sample_code"
    LOADED = "loaded"
    RELATED_SUFFIXES = "related_suffixes"

    CONTEXT_BEFORE = "context_before"
    CONTEXT_AFTER = "context_after"

    CONTEXT_NEED = "context_need"

class SeverityLevel(Enum):
    """风险级别枚举"""
    HIGH = 'HIGH'
    MEDIUM = 'MEDIUM'
    LOW = 'LOW'
    UNKNOWN = 'UNKNOWN'

    def __str__(self):
        return self.value

    @classmethod
    def choices(cls):
        """返回所有可选值"""
        return [str(member.value) for member in cls]

    @classmethod
    def choicesKnown(cls):
        """返回所有可选值"""
        return [str(member.value) for member in cls if member != cls.UNKNOWN]

    @classmethod
    def format(cls, string) -> str:
        for member in cls:
            if str(string).lower() in [str(member.value).lower(), str(member.name).lower()]:
                return member.value
        print(f"SeverityLevel 发现非预期格式:{string} 返回{cls.UNKNOWN.value} 允许格式:{cls.choices()}")
        return cls.UNKNOWN.value

    @classmethod
    def toType(cls, string):
        for member in cls:
            if str(string).lower() in [str(member.value).lower(), str(member.name).lower()]:
                return member
        return string

    @classmethod
    def size(cls):
        return len(cls.choices())

class VulnType(str, Enum):
    """漏洞类型枚举"""
    SENSITIVE_INFO = "敏感信息"
    SQL_INJECTION = "SQL注入"

    # FILE_OPERATION = "文件操作"
    FILE_UPLOAD = "文件上传"
    FILE_DELETE = "文件删除"
    FILE_INCLUDE = "文件包含"
    FILE_READ = "文件读取"
    FILE_WRITE = "文件写入"

    CODE_EXEC = "代码执行"
    CMD_EXEC = "命令注入"

    XSS = "跨站脚本"
    UNSERIALIZE = "反序列化"

    AUTH_BYPASS = "认证绕过"
    CONFIG_ERROR = "配置错误"

    LOGIC_ERROR = "逻辑缺陷"
    CRYPTO_ERROR = "加密问题"
    OTHER_TYPE = "其他问题"

    OTHER = "暂未分类"

    def __str__(self):
        return self.value

    @classmethod
    def choices(cls):
        """返回所有可选值"""
        return [str(member.value) for member in cls]

    @classmethod
    def format(cls, string) -> str:
        for member in cls:
            if str(string).lower() in [str(member.value).lower(), str(member.name).lower()]:
                return member.value
        return cls.OTHER.value

    @classmethod
    def toType(cls, string):
        for member in cls:
            if str(string).lower() in [str(member.value).lower(), str(member.name).lower()]:
                return member
        return string

if __name__ == '__main__':
    print(type(SeverityLevel.toType('MEDIUM')))  # <enum 'SeverityLevel'>
    print(isinstance(SeverityLevel.toType('MEDIUM'), Enum))  # True

    print(SeverityLevel.choicesKnown())