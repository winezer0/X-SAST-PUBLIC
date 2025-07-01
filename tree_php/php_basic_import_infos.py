import sys

from tree_php.php_enums import ImportType, ImportKey
from tree_uitls.tree_sitter_uitls import get_node_text, find_first_child_by_field, custom_format_path, \
    get_node_first_valid_child_node_text, get_node_first_valid_child_node


def create_import_result(import_type, start_line, end_line, namespace, file_path, use_from, alias, full_text):
    import_info = {
        ImportKey.TYPE.value: import_type,
        ImportKey.START.value: start_line,
        ImportKey.END.value: end_line,
        ImportKey.NAMESPACE.value: namespace,
        ImportKey.PATH.value: file_path,
        ImportKey.USE_FROM.value: use_from,
        ImportKey.ALIAS.value: alias,
        ImportKey.FULL_TEXT.value: full_text
    }
    return import_info


def get_use_declarations(root_node, language):
    """解析 use格式的导入信息"""
    def determine_use_type(item_text):
        """Helper function to determine the import type and clean the text."""
        if item_text.startswith('function '):
            return ImportType.USE_FUNCTION.value, item_text.replace('function ', '').strip()
        elif item_text.startswith('const '):
            return ImportType.USE_CONST.value, item_text.replace('const ', '').strip()
        elif 'SomeTrait' in item_text:
            return ImportType.USE_TRAIT.value, item_text.strip()
        else:
            return ImportType.USE_CLASS.value, item_text.strip()

    use_infos = []
    use_query = language.query("(namespace_use_declaration) @use_declaration")
    for match, match_dict in use_query.matches(root_node):
        use_node = match_dict['use_declaration'][0]
        full_text = get_node_text(use_node)
        start_line, end_line = use_node.start_point[0], use_node.end_point[0]

        if '{' in full_text and '}' in full_text:  # Group use statement
            group_prefix, group_content = full_text.split('{')
            group_prefix = group_prefix.replace('use', '').strip()
            items = [item.strip() for item in group_content.split('}')[0].split(',')]

            for item in items:
                import_type, item = determine_use_type(item)
                use_from = f"{group_prefix}\\{item}"
                use_info = create_import_result(
                    import_type=import_type, start_line=start_line, end_line=end_line, namespace=group_prefix,
                    file_path=None, use_from=use_from, alias=None, full_text=get_node_text(use_node)
                )
                use_infos.append(use_info)

        else:  # Regular use statement
            import_type, full_text = determine_use_type(full_text.replace('use ', '').strip())
            use_content = full_text.rstrip(';')
            use_from, alias = (use_content.split(' as ') + [None])[:2]  # Handle optional alias

            namespace = '\\'.join(use_from.split('\\')[:-1]) if '\\' in use_from else None
            use_info = create_import_result(
                import_type=import_type, start_line=start_line, end_line=end_line,
                namespace=namespace, file_path=None, use_from=use_from, alias=alias, full_text=get_node_text(use_node)
            )
            use_infos.append(use_info)

    return use_infos



def get_include_require_info(root_node, language):
    """获取 include/require 信息"""
    def guess_import_type(full_text):
        import_type = None
        import_types_mapping = {
            "require_once": ImportType.REQUIRE_ONCE.value,
            "include_once": ImportType.INCLUDE_ONCE.value,
            "require": ImportType.REQUIRE.value,
            "include": ImportType.INCLUDE.value
        }
        for keyword, value in import_types_mapping.items():
            if keyword in full_text:
                import_type = value
                break
        return import_type

    include_query = language.query("""
        (include_expression) @import_expression
        
        (include_once_expression) @import_expression
        
        (require_expression) @import_expression
        
        (require_once_expression) @import_expression
    """)
    
    import_infos = []
    matches = include_query.matches(root_node)
    
    for _, match_dict in matches:
        # 处理 include 语句
        if 'import_expression' in match_dict:
            import_expression_node = match_dict['import_expression'][0]
            full_text = get_node_text(import_expression_node)
            import_type = guess_import_type(full_text)

            # require(dirname(__FILE__) . '/includes/init.php')
            start_line,end_line = import_expression_node.start_point[0],import_expression_node.end_point[0]

            # include_node:(include_expression (parenthesized_expression (binary_expression left: (name) right: (string (string_content)))))
            parenthesized_node = find_first_child_by_field(import_expression_node, 'parenthesized_expression')
            if parenthesized_node:
                binary_expression_node = find_first_child_by_field(parenthesized_node, 'binary_expression')
                if binary_expression_node:
                    file_path = get_node_text(binary_expression_node)
                else:
                    # parenthesized_node:(parenthesized_expression (string (string_content)))
                    first_valid_child_node = get_node_first_valid_child_node(parenthesized_node)
                    file_path = get_node_text(first_valid_child_node)
            else:
                # (require_once_expression (string (string_content))))
                string_node = find_first_child_by_field(import_expression_node, 'string')
                if string_node:
                    file_path = get_node_text(string_node)
                else:
                    file_path = get_node_first_valid_child_node_text(import_expression_node)

            if file_path is None:
                print(f"解析导入信息出错:{full_text} -> {import_expression_node}")
                sys.exit(1)
            import_info= create_import_result(import_type=import_type, start_line=start_line, end_line=end_line,
                                              namespace=None, file_path=file_path, use_from=None, alias=None,
                                              full_text=full_text)
            import_infos.append(import_info)

    return import_infos


def format_import_paths(import_info):
    """格式化导入路径中的反斜杠"""
    for item in import_info:
        # 格式化 NAMESPACE 值
        if item.get(ImportKey.NAMESPACE.value):
            item[ImportKey.NAMESPACE.value] = custom_format_path(item[ImportKey.NAMESPACE.value])
        # 格式化 USE_FROM 值
        if item.get(ImportKey.USE_FROM.value):
            item[ImportKey.USE_FROM.value] = custom_format_path(item[ImportKey.USE_FROM.value])
        # 格式化 PATH 值
        if item.get(ImportKey.PATH.value):
            item[ImportKey.PATH.value] = custom_format_path(item[ImportKey.PATH.value])
    return import_info

def analyze_import_infos(language, root_node):
    """获取PHP文件中的所有导入信息"""
    import_infos = []
    import_infos.extend(format_import_paths(get_use_declarations(root_node, language)))
    import_infos.extend(format_import_paths(get_include_require_info(root_node, language)))
    return import_infos


if __name__ == '__main__':
    # 解析tree
    from tree_uitls.tree_sitter_uitls import init_php_parser, read_file_to_root
    from libs_com.utils_json import print_json

    PARSER, LANGUAGE = init_php_parser()
    # php_file = r"php_demo\depends.php"
    php_file = r"../php_demo/full_test_demo/index.php"
    root_node = read_file_to_root(PARSER, php_file)
    # print(f"read_file_bytes:->{php_file}")
    import_infos = analyze_import_infos(LANGUAGE, root_node)
    print_json(import_infos)
