import re

from tree_uitls.tree_sitter_uitls import init_php_parser, load_string_to_root


def remove_comment_nodes(language, root_node):
    """移除所有注释信息"""
    # 匹配所有 comment 节点
    query = language.query("""(comment) @comment_node""")
    # 执行查询，获取所有匹配的注释节点
    matches = query.matches(root_node)
    # 提取所有注释节点，并按照起始字节排序（从后往前处理，避免索引偏移）
    comment_nodes = []
    for match in matches:
        match_dict = match[1]  # 获取捕获组字典
        if 'comment_node' in match_dict:
            comment_nodes.extend(match_dict['comment_node'])

    # 按照起始字节排序注释节点
    comment_nodes = sorted(comment_nodes, key=lambda node: node.start_byte, reverse=True)

    # 替换注释为空字符串
    code_bytes = root_node.text
    for comment_node in comment_nodes:
        start_byte = comment_node.start_byte
        end_byte = comment_node.end_byte
        # 替换注释为空字符串（保留换行符以保持格式）
        replacement = b'\n' * code_bytes[start_byte:end_byte].count(b'\n')
        code_bytes = code_bytes[:start_byte] + replacement + code_bytes[end_byte:]
    # 进行编码
    code_string = code_bytes.decode("utf8")
    return code_string


def remove_blank_lines(code_string):
    """删除字符串中的所有空白行和连续空白符"""
    # 按行分割代码
    lines = code_string.splitlines()

    # 过滤掉空白行（包括仅包含空格或制表符的行）
    cleaned_lines = [line for line in lines if line.strip()]

    # 将非空白行重新组合为一个字符串
    cleaned_code = "\n".join(cleaned_lines)
    return cleaned_code


def remove_continuous_blank(lines):
    # 将字符串中的连续空白符（空格和制表符）替换为单个空格
    if not lines:
        return ""

    if isinstance(lines, list):
        lines = [re.sub(r'\s+', ' ', line) for line in lines]
    if isinstance(lines, str):
        lines = [re.sub(r'\s+', ' ', line) for line in lines.splitlines()]
    return "\n".join(lines)

def add_php_start_tag(code_string):
    """为php代码添加首行标记"""
    added_tag = False
    if not code_string.startswith("<?"):
        code_string = "<?\n" + code_string
        added_tag = True
    return code_string, added_tag


def remove_php_start_tag(code):
    """移除字符串中以换行符分隔的第一行"""
    # 只对以<?开头的格式进行第一行移除
    if not code.startswith("<?\n"):
        return code

    # 按行分割代码
    lines = code.splitlines()
    # 如果没有行或只有一行，直接返回空字符串
    if not lines or len(lines) == 1:
        return ""
    # 移除第一行并保留剩余行
    remaining_lines = lines[1:]
    # 将剩余行重新组合为一个字符串
    cleaned_code = "\n".join(remaining_lines)
    return cleaned_code


def remove_php_comments(code_string, clean_line=True):
    """分析并清理代码中的注释信息"""
    if not code_string or len(code_string) < 100:
        return code_string

    # 记录原始长度
    raw_length = len(code_string)
    # 补充php前缀 后续需要移除
    code_string, added_php_tag = add_php_start_tag(code_string)

    parser, language = init_php_parser()
    root_node = load_string_to_root(parser, code_string)
    # 解析代码并替换注释为空白字符
    modified_code = remove_comment_nodes(language, root_node)

    # 移除首行信息
    if added_php_tag:
        modified_code = remove_php_start_tag(modified_code)

    # 清理多余的空白字符行
    if clean_line:
        modified_code = remove_blank_lines(modified_code)

    # print(f"remove_comments length {raw_length} -> {len(modified_code)}")
    return modified_code


if __name__ == '__main__':
    from tree_uitls.tree_sitter_uitls import read_file_to_root
    # 解析tree
    PARSER, LANGUAGE = init_php_parser()
    php_file = r"php_demo/comment_demo/comment.php"
    root_node = read_file_to_root(PARSER, php_file)
    new_code = remove_comment_nodes(LANGUAGE, root_node)
    new_code = remove_blank_lines(new_code)
    new_code = remove_continuous_blank(new_code)
    print(new_code)
