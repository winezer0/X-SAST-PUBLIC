import yaml
import os


def save_yaml(file_path, config_data, mode='w+', encoding='utf-8', allow_unicode=True):
    # 保存配置为 YAML 文件。
    try:
        # 确保目录存在
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        with open(file_path, mode=mode, encoding=encoding) as f:
            yaml.dump(config_data, f, allow_unicode=allow_unicode)
        return True, None
    except Exception as error:
        print(f"保存 YAML 文件失败: {str(error)}")
        return False, error


def load_yaml(file, encoding='utf-8'):
    try:
        with open(file, 'r', encoding=encoding) as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        print(f"{file} -> File Not Found")
        return None
    except yaml.YAMLError:
        print(f"{file} -> Parsing YAML Error")
        return None


def save_yaml_format(file_path, rules_data) -> tuple:
    """
    保存数据到YAML文件，保留特殊字符格式
    Args:
        rules_data: 要保存的YAML数据
        file_path: 目标文件路径

    Returns:
        bool: 保存成功返回True，失败返回False
    """
    # 自定义YAML Dumper以保持特殊格式
    class MyDumper(yaml.SafeDumper):
        def increase_indent(self, flow=False, indentless=False):
            return super().increase_indent(flow, False)

    # 添加 | 字面量样式的表示器
    def str_presenter(dumper, data):
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    try:
        with open(file_path, 'w+', encoding='utf-8') as f:
            MyDumper.add_representer(str, str_presenter)
            yaml.dump(rules_data, f, allow_unicode=True, sort_keys=False, Dumper=MyDumper)
        return True, None
    except Exception as error:
        print(f'错误: 保存规则文件失败 - {str(error)}')
        return False, error
