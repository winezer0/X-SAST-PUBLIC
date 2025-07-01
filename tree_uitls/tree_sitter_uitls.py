from typing import List

import tree_sitter_php
from tree_sitter import Language, Parser

from tree_sitter._binding import Node

from libs_com.file_io import read_file_bytes



def init_php_parser():
    """
    初始化 tree-sitter PHP 解析器
    tree_sitter>0.21.3 （test on 0.24.0 0.23.2）
    """
    PHP_LANGUAGE = Language(tree_sitter_php.language_php())
    php_parser = Parser(PHP_LANGUAGE)
    return php_parser, PHP_LANGUAGE

def read_file_to_parse(parser, php_file: str):
    """解析PHP文件"""
    php_bytes = read_file_bytes(php_file)
    return parser.parse(php_bytes)

def read_file_to_root(parser, php_file: str):
    """解析PHP文件"""
    php_bytes = read_file_bytes(php_file)
    return parser.parse(php_bytes).root_node

def load_string_to_root(parser, php_code: str):
    """将字符串形式的 PHP 代码解析为语法树"""
    if not isinstance(php_code, str):
        return None
    # 将字符串转换为字节流（Tree-sitter 需要字节流作为输入）
    php_bytes = bytes(php_code, 'utf-8')
    # 使用解析器解析字节流
    return parser.parse(php_bytes).root_node


def find_first_child_by_field(node:Node, field_name_or_type:str) -> Node:
    """获取节点指定字段名或字段类型的 第一个值"""
    if node is None:
        return None
    find_child = node.child_by_field_name(field_name_or_type)
    if not find_child:
        find_child = next((n for n in node.children if n.type == field_name_or_type), None)
    return find_child


def find_node_info_by_line_nearest(code_line:int, infos, start_key):
    """
    根据目标行号查找最近的节点信息 可能存在误差的
    根据目标行号查找最近的类对象创建信息名称（类对象创建的开始行号必须小于等于目标行号）
    """
    find_info = {}
    if not infos:
        return find_info

    # 筛选出所有行号小于等于目标行号的命名空间
    filtered_infos = [x for x in infos if x[start_key] <= code_line]
    if len(filtered_infos) == 1:
        find_info = filtered_infos[0]
    elif len(filtered_infos) > 1:
        find_info = max(filtered_infos, key=lambda ns: ns[start_key])
    return find_info


def find_node_info_by_line_in_scope(code_line:int, infos:list[dict], start_key:str, end_key:str):
    """
    根据代码行号查找范围内的节点信息 可信的
    根据目标行号查找最近的类对象创建信息名称（类对象创建的开始行号必须小于等于目标行号）
    """
    find_info = {}

    if not infos:
        return find_info

    # 筛选出所有行号小于等于目标行号的node信息
    filtered_infos = [x for x in infos if x[start_key] <= code_line <= x[end_key]]
    if len(filtered_infos) == 1:
        find_info = filtered_infos[0]
    elif len(filtered_infos) > 1:
        # 找到行号最大的命名空间信息（即最接近目标行号的节点信息）
        print(f"Warning: 发现行号[{code_line}]处于多个节点信息中:{filtered_infos}")
        find_info = max(filtered_infos, key=lambda ns: ns[start_key])
    return find_info


def find_children_by_field(node:Node, field_name_or_type:str) -> List[Node]:
    """获取节点指定字段名或字段类型的 所有值"""
    if node is None:
        return []
    children = node.children_by_field_name(field_name_or_type)
    if not children:
        children = [child for child in node.children if child.type == field_name_or_type]
    return children


def get_node_filed_text(node, field_name_or_type):
    """获取节点的指定子节点的指定名称or类型对应的文本值"""
    find_node = find_first_child_by_field(node, field_name_or_type)
    if not find_node:
        return None

    try:
        find_text = find_node.text.decode('utf-8')
    except Exception:
        find_text = str(find_node.text)
    return find_text


def get_node_first_valid_child_node(node):
    """获取节点的指定子节点的指定名称or类型对应的文本值"""
    for child in node.children:
        if len(child.type)>1:
            return child
    return None


def get_node_first_valid_child_node_text(node):
    """获取节点的指定子节点的指定名称or类型对应的文本值"""
    find_node = get_node_first_valid_child_node(node)
    if not find_node:
        return None
    try:
        find_text = find_node.text.decode('utf-8')
    except Exception:
        find_text = str(find_node.text)
    return find_text


def get_node_text(node):
    """获取节点的文本值"""
    if not node:
        return None
    if node.type in ['string','encapsed_string']:
        find_text = get_node_filed_text(node, "string_content")
    elif node.type == 'array_creation_expression':
        # 解析数组内容
        array_elements = []
        for element in node.children:
            if element.type == 'array_element_initializer':
                element_value = get_node_text(element.child(0))
                array_elements.append(element_value)
        find_text = array_elements
    else:
        try:
            find_text = node.text.decode('utf-8')
        except Exception as e:
            # print(f"node.text.decode error:{e}")
            find_text = str(node.text)
    return find_text


def get_node_type(node):
    """获取节点的文本值"""
    find_type = node.type if node else None
    return find_type



def custom_format_path(path:str):
    """转换代码中解析出来的的path路径"""
    if not path:
        return path

    replace_map = {
        "\\": "/",
        "//": "/",
        "'": "",
        "\"": "",
    }
    for key, value in replace_map.items():
        path = path.replace(key, value)
    path = path.strip("\\/ .")
    return path
