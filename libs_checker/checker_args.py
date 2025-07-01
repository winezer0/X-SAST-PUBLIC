import argparse

from setting import *


def parse_check_args():
    parser = argparse.ArgumentParser(description='Static Application Security Testing tool')
    parser.add_argument('-r', '--rules-file', default=DEF_CONFIG_RULES, help=f'规则文件路径 (默认:{DEF_CONFIG_RULES})')
    parser.add_argument('-p', '--project-path', default=None, help='需要扫描的代码文件或目录')

    parser.add_argument('-n', '--project-name', default=DEF_PROJECT_NAME, help='项目名称')

    # 性能配置
    parser.add_argument('-w', '--workers', type=int, default=None, help='线程数 (默认：CPU数)')
    parser.add_argument('-l', '--limit-size', type=int, default=2, help='限制检查文件大小')
    parser.add_argument('-o', '--output', default=None, help='自定义输出文件路径')
    # 性能配置
    parser.add_argument('-s', '--save-cache', action='store_false', default=True,  help='缓存分析结果  (默认: True)')
    parser.add_argument('-k', '--chunk-mode', action='store_true', default=False,  help='分块读取文件 (默认: False)')
    # 过滤配置
    parser.add_argument('-E', '--exclude-keys', nargs='+', default=DEF_EXCLUDES_KEYS, help=f'扫描排除路径关键字 (默认:{DEF_EXCLUDES_KEYS})')
    parser.add_argument('-e', '--exclude-ext', nargs='+', default=DEF_EXCLUDES_EXT, help=f'扫描排除文件后缀 (默认:{DEF_EXCLUDES_EXT})')

    parser.add_argument('-b', '--black-key', default=None, help=f'扫描排除内容关键字 (默认: None) 支持简单||和&&语法')

    # 筛选配置
    parser.add_argument('-L', '--filter-lang', nargs='+', help='仅扫描指定语言的规则 (例如: ANY PHP JAVA)')
    parser.add_argument('-R', '--filter-risk', nargs='+', help='仅扫描指定风险的规则 (例如: HIGH MEDIUM LOW)')
    parser.add_argument('-N', '--filter-vuln', nargs='+', help='仅扫描指定名称的规则 (例如: "Cloud Key")')

    # 依赖解析结果
    parser.add_argument('-P', '--parsed-file', default=None, help='项目代码的语法解析结果文件')
    parser.add_argument('-C', '--call-parser', action='store_true', default=False, help='自动进行代码解析 (默认: False)')
    parser.add_argument('-f', '--import-filter', action='store_true', default=False, help='分析时被调用方法启用导入信息过滤 (默认: False)')

    args = parser.parse_args()
    return args