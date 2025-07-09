from enum import Enum


class AIProviders(Enum):
    PROMPTS = "prompts"
    PROVIDERS = "providers"

class AIProvider(Enum):
    PROVIDER_NAME = "provider_name"
    BASE_URL = "base_url"
    API_KEYS = "api_keys"
    MODEL_NAME = "model_name"

    API_KEY = "api_key"
    CLIENT = "client"

class VerifyKeys(Enum):
    # AI Verify key
    VERIFIER_HASH = 'verifier_hash'

    ORIGINAL = "original"
    PROMPT = "prompt"
    MODEL = "model"

    PARSED = "parsed"
    RESPONSE = "response"
    ERROR = "error"

    VERIFY = "verify"
    BECAUSE = "because"
    HTTP_POC = "http_poc"
    SENSITIVE = "sensitive"
    EXPLAIN = "explain"
    REPAIR = "repair"

class VerifyStatus(Enum):
    """风险级别枚举"""
    # 已弃用 HIGH = 'HIGH' MEDIUM = 'MEDIUM' LOW = 'LOW'  NONE = 'NONE'  UNKNOWN = 'UNKNOWN'
    TEN = "10"
    NINE = "9"
    EIGHT = "8"
    SEVEN = "7"
    SIX = "6"
    FIVE = "5"
    FOUR = "4"
    THREE = "3"
    TWO = "2"
    ONE = "1"
    ZERO = "0"
    UNKNOWN = "-1"

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
        print(f"VerifyStatus 发现非预期格式:[{string}] 返回{cls.UNKNOWN.value} 允许格式:{cls.choices()}")
        return cls.UNKNOWN.value

    @classmethod
    def toType(cls, string):
        for member in cls:
            if str(string).lower() in [str(member.value).lower(), str(member.name).lower()]:
                return member
        return string

    @classmethod
    def choicesShort(cls):
        """返回所有可选值"""
        return f"{cls.ZERO}-{cls.NINE}"

    @classmethod
    def size(cls):
        return len(cls.choices())
