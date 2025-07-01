import copy
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict

from libs_checker.checker_core import _check_file
from libs_checker.checker_enum import CheckerKeys
from libs_checker.checker_filter import split_checker_tasks, init_checker_tasks
from libs_com.file_path import get_root_dir
from libs_com.file_filter import get_files_with_filter, file_is_larger, file_has_key
from libs_com.utils_cache import save_cache_if_needed, init_cacha_dict, CacheKeys, get_cached_results
from libs_com.utils_dict import dedup_dicts_by_key
from libs_com.utils_hash import get_path_hash
from libs_com.utils_json import load_json
from libs_com.utils_process import print_progress
from libs_com.utils_time import time_to_seconds



class SASTChecker:
    def __init__(self, project_name: str, project_path: str, rules_dict: dict, exclude_ext: List[str],
                 exclude_keys: List[str] = None, limit_size: int = 2):

        self.start_time = time.time()
        # 添加项目根路径属性
        self.project_path = project_path
        self.project_root = get_root_dir(project_path)
        # 进行规则赋值
        self.rules_dict = rules_dict

        # 排除路径
        self.exclude_suffixes = exclude_ext  # 需要排除的后缀
        self.exclude_keys = exclude_keys or []  # 添加排除目录属性，如果为None则使用空列表
        self.limit_size = limit_size  # 排除超过超过大小的文件

        # 添加缓存相关属性
        self.cache_file = f"{project_name}.{get_path_hash(self.project_root)}.checker.cache"
        self.cache_data = self._load_checker_cache()
        self.cache_interval = 30
        self.last_cache_time = datetime.now()
        self.cache_lock = threading.Lock()  # 添加线程锁

    def _load_checker_cache(self) -> Dict:
        """加载验证缓存"""
        cache = init_cacha_dict()
        try:
            if os.path.exists(self.cache_file):
                cache = load_json(self.cache_file)
                print(f"已缓存结果数: {len(cache.get(CacheKeys.RESULT.value, {}).keys())}"
                      f"\n缓存更新时间: {cache.get(CacheKeys.LAST_UPDATE.value, '未知')}")
        except Exception as e:
            print(f"加载缓存失败: {e}")
        return cache

    def _check_files(self, max_workers: int = None, save_cache=True, chunk_mode=False, black_key=None):
        # 从目录过滤文件
        scan_files = get_files_with_filter(self.project_path, self.exclude_suffixes, self.exclude_keys)
        print(f"路径信息过滤 剩余文件: {len(scan_files)}")
        # 过滤较大文件
        scan_files = [file for file in scan_files if not file_is_larger(file, self.limit_size)]
        print(f"大文件过滤 剩余文件: {len(scan_files)}")
        # 过滤包含黑名单关键字的文件
        scan_files = [file for file in scan_files if not file_has_key(file, black_key)]
        print(f"关键字过滤 剩余文件: {len(scan_files)}")

        # 整理每个文件需要进行的扫描规则  {task_hash : task_info,...}
        check_tasks = init_checker_tasks(scan_files, self.rules_dict, self.project_root)
        cache_result = self.cache_data.get(CacheKeys.RESULT.value)
        cache_tasks, check_tasks = split_checker_tasks(check_tasks, cache_result)
        checker_results = get_cached_results(cache_tasks, cache_result)
        print(f"匹配缓存结果: {len(checker_results)}")

        # 进行多线程验证
        print(f"扫描线程数量: {max_workers if max_workers else f'{os.cpu_count()}'}")
        check_results = self._check_files_threads(check_tasks, chunk_mode, max_workers, save_cache)
        checker_results.extend(check_results)

        # 去重分析结果数据
        checker_results = dedup_dicts_by_key(checker_results, unique_key=CheckerKeys.CHECKER_HASH.value)

        total_time = time.time() - self.start_time
        print(f"\n扫描完成！总用时: {time_to_seconds(total_time)} 匹配漏洞规则[去重]: {len(checker_results)} 个")
        return checker_results

    def _check_files_threads(self, check_tasks, chunk_mode, max_workers, save_cache):
        checker_results = []
        start_time = time.time()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for task_hash, task_info in check_tasks.items():
                task = executor.submit(_check_file, task_hash, task_info, self.project_root, chunk_mode)
                futures.append(task)

            # 存储结果文件
            for completed, future in enumerate(as_completed(futures), start=1):
                task_hash, task_matches = future.result()
                print_progress(completed, len(futures), start_time)
                # 保存扫描结果、提取所有 match_infos 内容到一个列表
                if task_matches:
                    checker_results.extend(task_matches)

                # 保存缓存数据 不管有没有有效结果都进行缓存
                if save_cache:
                    try:
                        # 记录缓存
                        with self.cache_lock:
                            now_cache_time = datetime.now()
                            is_completed = len(futures) == completed
                            cache_result = self.cache_data[CacheKeys.RESULT.value]
                            cache_result[task_hash] = task_matches
                            self.cache_data[CacheKeys.LAST_UPDATE.value] = now_cache_time.isoformat()

                            cache_data_copy = copy.deepcopy(self.cache_data)
                            cache_status, cache_error = save_cache_if_needed(
                                cache_file=self.cache_file,
                                cache_data=cache_data_copy,
                                cache_time=now_cache_time,
                                last_cache_time=self.last_cache_time,
                                save_interval=self.cache_interval,
                                force_store=is_completed)
                            if cache_status:
                                self.last_cache_time = now_cache_time
                                print("\nSuccess save scan cache by cache_save_interval...")
                    except Exception as e:
                        print(f"\nFailure save scan cache by cache_save_interval:{e}")

        return checker_results
