import argparse

from setting import DEF_EXCLUDES_KEYS, DEF_PROJECT_NAME


def parse_php_parser_args():
    parser = argparse.ArgumentParser(description='分析php项目代码语法结构 用于静态分析时补充代码信息')
    parser.add_argument('-p', '--project-path', default=None,  help='项目路径')
    parser.add_argument('-n', '--project-name', default=DEF_PROJECT_NAME, help='项目名称')
    # 性能配置 线程树为1时不启动多线程, 可用于错误调试
    parser.add_argument('-w', '--workers', type=int, default=None, help='线程数 (默认: CPU数)')

    # 性能配置
    parser.add_argument('-s', '--save-cache', action='store_false', default=True, help='缓存解析结果 (默认: True)!!!')
    parser.add_argument('-f', '--import-filter', action='store_true', default=False, help='启用导入信息过滤 (默认: False)!!!')

    # 过滤配置
    parser.add_argument('-e', '--exclude-keys', nargs='+', default=DEF_EXCLUDES_KEYS, help=f'排除路径关键字 (默认:{DEF_EXCLUDES_KEYS})')
    args = parser.parse_args()
    return args