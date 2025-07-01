from libs_checker.checker_args import parse_check_args
from libs_checker.checker_call import project_checker_call
from libs_checker.checker_enum import CheckerKeys
from libs_com.file_path import path_is_exist
from libs_com.utils_dict import merge_dicts_by_key
from libs_com.utils_hash import get_path_hash
from libs_com.utils_json import load_json, dump_json


def main():
    args = parse_check_args()

    project_path = args.project_path
    project_name = args.project_name
    rules_file = args.rules_file
    workers = args.workers
    exclude_keys = args.exclude_keys
    save_cache = args.save_cache

    filter_lang = args.filter_lang
    filter_risk = args.filter_risk
    filter_vuln = args.filter_vuln

    exclude_ext = args.exclude_ext
    limit_size = args.limit_size

    chunk_mode = args.chunk_mode

    parsed_file = args.parsed_file
    call_parser = args.call_parser

    import_filter = args.import_filter
    black_key = args.black_key


    check_results = project_checker_call(project_name, project_path, rules_file, exclude_keys, exclude_ext, filter_lang,
                                         filter_risk, filter_vuln, parsed_file, save_cache, chunk_mode, limit_size,
                                         call_parser, workers, import_filter, black_key)

    # 保存分析结果
    if check_results:
        save_file = args.output or f"{project_name}.{get_path_hash(project_path)}.checker.json"
        if path_is_exist(save_file):
            print("历史分析结果已存在, 开始进行合并更新...")
            check_results = merge_dicts_by_key(check_results, load_json(save_file), unique_key=CheckerKeys.CHECKER_HASH.value)
            print(f"历史分析结果已合并, 最终结果数量:{len(check_results)}...")

        dump_status, dump_error = dump_json(save_file, check_results)
        if dump_error:
            raise dump_error
        print(f"分析结果已保存至: {save_file}")


if __name__ == '__main__':
    main()
