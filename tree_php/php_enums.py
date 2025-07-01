from enum import Enum


class DefineTypes(Enum):
    DEFINE_NAMESPACES = 'DEFINE_NAMESPACES'
    DEFINE_METHOD = 'DEFINE_METHOD'
    DEFINE_CLASS = 'DEFINE_CLASS'
    CREATE_OBJECT = 'CREATE_OBJECT'
    IMPORT_DEPENDS = 'IMPORT_DEPENDS'


class DefineKeys(Enum):
    UNIQ_ID = "UNIQ_ID"
    NAME = "NAME"
    START = "START"
    END = "END"

class FileInfoKeys(Enum):
    """文件信息相关的键"""
    DEPEND_INFOS = "DEPEND_INFOS"   # 组合多种基础依赖信息 会用于解析 METHOD_INFOS 和 CLASS_INFOS
    METHOD_INFOS = "METHOD_INFOS"
    CLASS_INFOS = "CLASS_INFOS"
    VARIABLE_INFOS = "VARIABLE_INFOS"

class ClassKeys(Enum):
    """类信息相关的键"""
    UNIQ_ID = "UNIQ_ID"                 # 综合属性计算出来的一个ID
    FILE = "FILE"                 # 所处的物理文件路径

    NAME = "NAME"
    START = "START"
    END = "END"

    NAMESPACE = "NAMESPACE"
    EXTENDS = "EXTENDS"
    INTERFACES = "INTERFACES"

    VISIBILITY = "VISIBILITY"
    MODIFIERS = "MODIFIERS"

    PROPERTIES = "PROPERTIES"
    METHODS = "METHODS"

    IS_INTERFACE = "IS_INTERFACE"

class PHPVisibility(Enum):
    """PHP访问修饰符枚举"""
    PUBLIC = "public"
    PRIVATE = "private"
    PROTECTED = "protected"

    @classmethod
    def from_value(cls, value):
        """根据值查找对应的枚举元素，忽略大小写。"""
        search_value = value.lower()  # 将输入值转为小写
        for item in cls:
            if item.value.lower() == search_value:  # 比较时也转为小写
                return item
        raise ValueError(f"No enum member found with value '{value}'")

class PHPModifier(Enum):
    """PHP特殊修饰符枚举"""
    STATIC = "static"
    ABSTRACT = "abstract"
    FINAL = "final"
    READONLY = "readonly"
    INTERFACE = "interface"

class PropertyKeys(Enum):
    """属性信息相关的键"""
    NAME = "PROPERTY_NAME"
    DEFAULT = "PROPERTY_DEFAULT"
    VISIBILITY = "PROPERTY_VISIBILITY"
    MODIFIERS = "PROPERTY_MODIFIERS"
    TYPE = "PROPERTY_TYPE"
    START = "START"
    END = "END"

class MethodKeys(Enum):
    """方法信息相关的键"""
    UNIQ_ID = "UNIQ_ID"           # 综合属性计算出来的一个ID
    FILE = "FILE"                 # 所处的物理文件路径
    NAMESPACE = "NAMESPACE"       # 方法所在的命名空间信息

    NAME = "NAME"                # 方法名
    FULLNAME = "FULLNAME"        # 类名+方法名
    START = "START"    # 方法开始行
    END = "END"        # 方法结束行

    VISIBILITY = "VISIBILITY"    # 方法的可访问性
    MODIFIERS = "MODIFIERS"      # 方法的特殊描述符

    RETURNS = "RETURNS"          # 方法的返回信息 存在多个返回语句
    PARAMS = "PARAMETERS"        # 方法的参数信息

    CLASS = "CLASS"             # 方法所属的类
    OBJECT = "OBJECT"             # 方法所属的对象
    IS_NATIVE = "IS_NATIVE"      # 被调用方法是否在本文件中定义 使用bool类型
    METHOD_TYPE = "METHOD_TYPE"         # 方法的类型信息

    CALLED_METHODS = "CALLED_METHODS"   # 方法内部调用的方法列表

    # 一些在后续才添加的信息
    MAY_FILES = "MAY_FILES"               # 被调用的方法源文件
    MAY_NAMESPACES = "MAY_NAMESPACES"     # 被调用的方法源命名空间
    MAY_SOURCES = "MAY_SOURCES"           # 被调用的方法源方法
    SOURCE_CODE = "SOURCE_CODE"           # 被调用的方法的源代码


class ParameterKeys(Enum):
    """参数信息相关的键"""
    NAME = "NAME"
    TYPE = "TYPE"
    DEFAULT = "DEFAULT"
    VALUE = "VALUE"
    INDEX = "INDEX"

class ReturnKeys(Enum):
    """方法类型"""
    NAME = "NAME"
    TYPE = "TYPE"
    VALUE = "VALUE"
    START = "START"
    END = "END"


class GlobalCode(Enum):
    """方法类型"""
    START = "START"
    END = "END"
    TOTAL = "TOTAL"
    BLOCKS = "BLOCKS"
    LINE = "LINE"
    CODE = "CODE"


class MethodType(Enum):
    """方法类型"""
    GENERAL = "GENERAL"      # 自定义的普通方法
    BUILTIN = "BUILTIN"      # PHP内置方法
    DYNAMIC = "DYNAMIC"      # 动态方法 （使用变量作为函数名）

    CONSTRUCT = "CONSTRUCT"  # 类的构造方法 需要额外处理
    MAGIC_METHOD = "MAGIC_METHOD"          # 类的魔术方法 直接忽略处理
    CLASS_METHOD = "CLASS_METHOD"          # 自定义的类方法


class VariableType(Enum):
    """变量类型枚举"""
    LOCAL = 'local'
    STATIC = 'static'
    GLOBAL = 'global'
    PROGRAM = 'program'
    SUPER_GLOBAL = 'superglobal'
    CONSTANT = 'constant'


class VariableKeys(Enum):
    """信息字典相关的键"""
    START = "START"
    END = "END"

    NAME = "NAME"
    NAME_TYPE = "NAME_TYPE"

    VALUE = "VALUE"
    VALUE_TYPE = "VALUE_TYPE"

    FULL_TEXT = "FULL_TEXT"
    FUNCTION = "FUNCTION"

class OtherKeys(Enum):
    GLOBAL_CODE = "GLOBAL_CODE"               # 标志函数外的代码键
    ANONYMOUS = "ANONYMOUS"


class ImportType(Enum):
    INCLUDE = 'include'
    INCLUDE_ONCE = 'include_once'
    REQUIRE = 'require'
    REQUIRE_ONCE = 'require_once'

    USE_CLASS = 'use_class'
    USE_FUNCTION = 'use_function'
    USE_CONST = 'use_const'
    USE_TRAIT = 'use_trait'
    USE_OTHER = 'use_other'
    # USE_GROUP = 'use_group'  # 新增
    # USE_ALIAS = 'use_alias'  # 新增


class ImportKey(Enum):
    START = 'START'
    END = 'END'

    TYPE = 'type'
    PATH = 'path'
    NAMESPACE = 'namespace'
    USE_FROM = 'use_from'
    ALIAS = 'alias'
    FULL_TEXT = 'full_text'
