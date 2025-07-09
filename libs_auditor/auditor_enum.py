from enum import Enum

class AuditorUIKeys(Enum):
    # Auditor Key
    SOFTWARE = "SAST Results Viewer"

    ALL_RISKS   = "全部风险"
    ALL_TYPES   = "全部类型"
    AI_VERIF    = "智能验证"
    ME_VERIF    = "人工验证"
    FILE_VIEWER = "文件视图"
    RISK_VIEWER = "风险视图"


class AuditorKeys(Enum):
    # Editor
    AUDITOR_HASH = "auditor_hash"
    AUDITED = "audited"

    PROJECT = "project"
    SOURCE_ROOT = "source_root"
    ANALYSE_FILE = "analyse_file"

    PROVIDERS = "providers"

    EDITORS = "editors"
    EDITOR_NAME = "editor_name"
    FULL_PATH = "full_path"
    EXE = "exe"
    ARGS = "args"
    ENABLED = "enabled"


class AuditStatus(Enum):
    """验证状态枚举"""
    CONFIRMED = '确认存在'
    NOT_EXIST = '确认误报'
    POSSIBLE = '可能存在'
    CONDITIONAL = '条件存在'
    UNLIKELY = '可能误报'
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
        print(f"AuditStatus 发现非预期格式:{string} 返回 {cls.UNKNOWN.value} 允许格式:{cls.choices()}")
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
