import json
import re
from typing import Any


def parse_json_strong(text: str, need_keys: list) -> tuple:
    """
    强大的JSON解析函数，支持多种格式。

    :param text: 包含可能有 JSON 的文本。
    :param need_keys: 需要提取的键列表。
    :return: 解析后的 JSON 数据字典和错误信息。
    """

    def safe_update(original_dict, new_dict):
        for key, value in new_dict.items():
            if original_dict[key] is None and value is not None:
                original_dict[key] = value
        return original_dict

    def try_repair_sample_json(string):
        if string.startswith("{") and not string.endswith("}"):
            string += "}" if string.endswith('"') else '"}'
        return string

    def parse_json_sample(string):
        """尝试{}中的JSON"""
        parsed_json = {}

        json_pattern = r'(\{[^{^}]*\})'
        matches = re.findall(json_pattern, string, re.DOTALL)
        for match in matches:
            try:
                # 尝试解析 JSON 字符串
                parsed_json.update(json.loads(match.strip()))
            except json.JSONDecodeError as e:
                # print(f"parse_json_sample error: {e}")
                pass
        return parsed_json

    def parse_json_re_keys(string, keys):
        """根据指定的键对字符串进行切割，并将切割后的内容解析为 JSON"""
        parsed_json = {}
        # 对于每一个需要查找的键
        for key in keys:
            # 构建正则表达式模式
            pattern = r'["\']{}["\']\s*:\s*((?:["\'](.*?)["\']|(\d+)|(true|false)|(null)))'.format(re.escape(key))
            match = re.search(pattern, string, re.DOTALL)
            if match:
                # 如果找到了匹配项，则提取并保存到结果字典中
                parsed_json[key] = format_value(match.group(1))
                print(f"parse_json [{key}] by key regex -> {parsed_json[key]}")
            else:
                # 如果没有找到匹配项，则设置为None或任何你想要表示未找到的值
                parsed_json[key] = None
        return parsed_json

    def find_keys_indices(string, keys):
        indices = {}
        for key in keys:
            if key in string:
                index = string.index(key)
                indices[key] = index
        return dict(sorted(indices.items(), key=lambda item: item[1]))

    def parse_json_key_index(string, keys):
        parsed_json = {}
        # 查找每个元素在字符串中的位置
        index_dict = find_keys_indices(string, keys)
        sorted_keys = list(index_dict.keys())
        for i, key in enumerate(sorted_keys):
            index_start = index_dict[key] + len(key)
            if i < len(sorted_keys) - 1:
                next_key = sorted_keys[i + 1]
                index_end = index_dict[next_key]
                value = string[index_start:index_end]
            else:
                value = string[index_start:]
            parsed_json[key] = format_value(value)
            print(f"parse_json [{key}] by key index -> Value:[{parsed_json[key]}]")
        return parsed_json

    def format_value(value):
        return str(value).strip(r''' \'":,{}<>/*`[]''').strip()

    def format_dict(json_dict):
        new_dict = {}
        for key, value in json_dict.items():
            if isinstance(value, str):
                if value.lower() == "null":
                    value = None
                elif value.lower() == "true":
                    value = True
                elif value.lower() == "false":
                    value = False
                else:
                    pass
            new_dict[key] = value
        return new_dict

    # 初始化值
    parse_result = {key: None for key in need_keys}
    # 补充响应截断的情况
    text = try_repair_sample_json(text)
    try:
        parsed_jsons = json.loads(text)
        parse_result.update(parsed_jsons)
        return parse_result, None
    except json.JSONDecodeError:
        parsed_jsons = parse_json_sample(text)
        if parsed_jsons:
            parse_result.update(format_dict(parsed_jsons))
            return parse_result, None

        # 通过两种方式进行格式补充
        parsed_jsons_index = parse_json_key_index(text, need_keys)
        parsed_jsons_regex = parse_json_re_keys(text, need_keys)
        if parsed_jsons_index or parsed_jsons_regex:
            if parsed_jsons_index:
                parse_result = safe_update(parse_result, format_dict(parsed_jsons_index))
            if parsed_jsons_regex:
                parse_result = safe_update(parse_result, format_dict(parsed_jsons_regex))
            return parse_result, None

    return parse_result, "PARSE JSON ERROR"


def load_json(json_path: str, encoding: str = 'utf-8') -> Any:
    """加载漏洞扫描结果"""
    try:
        with open(json_path, 'r', encoding=encoding) as f:
            return json.load(f)
    except Exception as e:
        raise RuntimeError(f"加载 JSON 失败: {str(e)}")


def dump_json(file_path: str, data: Any, encoding: str = 'utf-8', indent: int = 2, mode: str = 'w+') -> tuple:
    """
    将给定的数据存储为JSON文件。
    """
    error = None
    try:
        with open(file_path, mode, encoding=encoding) as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
        return True, error
    except IOError as error:
        print(f"写入JSON发生IO异常: {file_path} -> {error}")
    except Exception as error:
        print(f"写入JSON发生未知错误: {file_path} -> {error}")
    return False, error


def dumps_json(data, indent=0, ensure_ascii=False, sort_keys=False, allow_nan=False) -> tuple:
    """
    - indent (int or str): 缩进级别 输出格式化的JSON字符串 会导致性能卡顿
    - ensure_ascii (bool): 如果为False，则允许输出非ASCII字符而不进行转义。
    - sort_keys (bool): 如果为True，则字典的键将按字母顺序排序。
    - allow_nan (bool): 如果为True，则允许 `NaN`, `Infinity`, `-Infinity` 等特殊浮点数值。
    """
    try:
        json_string = json.dumps(data, indent=indent, ensure_ascii=ensure_ascii, sort_keys=sort_keys, allow_nan=allow_nan)
        return json_string, None
    except Exception as e:
        print(f"dumps json error: {e}")
        return None, e


def print_json(data, indent=2, ensure_ascii=False, sort_keys=False, allow_nan=False):
    if not isinstance(data,str):
        json_string, _ = dumps_json(data, indent=indent, ensure_ascii=ensure_ascii, sort_keys=sort_keys, allow_nan=allow_nan)
    else:
        json_string = data
    print(json_string)


