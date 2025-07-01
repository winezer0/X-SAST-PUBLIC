from typing import List, Dict

from tree_php.php_enums import GlobalCode
from tree_uitls.tree_sitter_uitls import get_node_text


def line_in_ranges(line_num, range_list):
    """检查行号是否在函数或类范围内"""
    return any(start <= line_num <= end for start, end in range_list)


def has_global_code(root_node, define_ranges:list):
    """检查是否有(非class和非函数)全局代码的内容 一直都会有<?php的全局代码"""
    for line_num in range(root_node.start_point[0], root_node.end_point[0] + 1):
        if not line_in_ranges(line_num, define_ranges):
            return True
    return False


def get_global_code_info(root_node, define_ranges:List) -> Dict:
    """获取所有不在全局函数和类定义内的PHP代码信息"""

    # 获取源代码的每一行
    source_lines = get_node_text(root_node).split('\n')
    # 存储非函数且非类范围内的代码块
    non_function_non_class_code = []
    # 遍历每一行代码
    for line_num, line_text in enumerate(source_lines):
        # 如果当前行既不在全局函数范围内也不在类范围内，则添加到结果中
        if not line_in_ranges(line_num, define_ranges):
            code_info = {
                GlobalCode.LINE.value: line_num,
                GlobalCode.CODE.value: line_text.strip()  # 去除多余空格
            }
            non_function_non_class_code.append(code_info)

    if not non_function_non_class_code:
        return None

    # 返回结果字典
    gb_code_start_line = non_function_non_class_code[0][GlobalCode.LINE.value] if non_function_non_class_code else None
    gb_code_end_line = non_function_non_class_code[-1][GlobalCode.LINE.value] if non_function_non_class_code else None
    global_code_info = {
        GlobalCode.START.value: gb_code_start_line,
        GlobalCode.END.value: gb_code_end_line,
        GlobalCode.TOTAL.value: len(non_function_non_class_code),
        GlobalCode.BLOCKS.value: non_function_non_class_code,
    }
    return global_code_info


def get_global_code_info_code(global_code_info, retain_line=True):
    """获取文件中的全局代码, retain_line 表示使用空白行保留行号信息"""
    if not global_code_info:
        return None

    # 提取 BLOCKS 并按 LINE 排序
    code_blocks = global_code_info[GlobalCode.BLOCKS.value]
    sorted_blocks = sorted(code_blocks, key=lambda x: x[GlobalCode.LINE.value])

    if not retain_line:
        # 不保留原始行号信息 直接返回即可
        return "\n".join(sorted_blocks)

    # 提取 START 和 END 行号
    nf_start_line = global_code_info[GlobalCode.START.value]
    nf_end_line = global_code_info[GlobalCode.END.value]
    # 构建完整的行号空代码
    codes = ["" for _ in range(nf_start_line, nf_end_line + 1)]
    # 填充代码数据
    for block in sorted_blocks:
        line_num = block[GlobalCode.LINE.value]
        codes[line_num] = block[GlobalCode.CODE.value]

    # 将所有代码拼接成字符串
    return "\n".join(codes)

