import os

# 保持原有的函数加载内置函数列表
def load_php_builtin_functions():
    functions = set()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, 'PHP_BUILTIN_FUNCTIONS.txt')
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    functions.add(line)
        return functions
    except FileNotFoundError:
        # print(f"警告: 未找到函数列表文件 {file_path}")
        return set()

PHP_BUILTIN_FUNCTIONS = load_php_builtin_functions()
PHP_MAGIC_METHODS = [
    '__construct',   # 构造函数，在对象创建时调用
    '__destruct',    # 析构函数，在对象销毁时调用
    '__call',        # 在调用不可访问的方法时触发
    '__callStatic',  # 在调用不可访问的静态方法时触发
    '__get',         # 在尝试读取不可访问的属性时触发
    '__set',         # 在尝试设置不可访问的属性时触发
    '__isset',       # 在对不可访问的属性调用 isset() 或 empty() 时触发
    '__unset',       # 在对不可访问的属性调用 unset() 时触发
    '__toString',    # 在将对象当作字符串使用时触发
    '__invoke',      # 在尝试将对象当作函数调用时触发
    '__clone',       # 在克隆对象时触发
    '__sleep',       # 在序列化对象前触发
    '__wakeup',      # 在反序列化对象后触发
    '__serialize',   # 在序列化对象时触发（PHP 7.4+）
    '__unserialize', # 在反序列化对象时触发（PHP 7.4+）
    '__set_state',   # 在调用 var_export() 导出对象时触发
    '__debugInfo',   # 在使用 var_dump() 输出对象时触发
    '__autoload',    # 自动加载类（已弃用，推荐使用 spl_autoload_register）
]

# 常量定义
SUPER_GLOBALS = [
    '$_GET', '$_POST', '$_REQUEST', '$_SESSION',
    '$_COOKIE', '$_SERVER', '$_FILES', '$_ENV', '$GLOBALS'
]