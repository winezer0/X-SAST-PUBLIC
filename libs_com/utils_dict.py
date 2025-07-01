import copy


def dedup_dicts_by_key(data_dicts, unique_key):
    """
    合并新旧数据，基于 node_key 作为唯一标识符进行合并。
    如果新数据中的 node_key 已存在于旧数据中，则用新数据覆盖；否则追加新数据。
    """
    # 将旧数据转换为字典格式，从而实现自动去重
    data_dict = {item[unique_key]: item for item in data_dicts}
    # 返回最终的数据列表
    return list(data_dict.values())

def merge_dicts_by_key(new_dicts, old_dicts, unique_key):
    """
    合并新旧数据，基于 node_key 作为唯一标识符进行合并。
    如果新数据中的 node_key 已存在于旧数据中，则用新数据覆盖；否则追加新数据。
    """

    # 将旧数据转换为字典格式，便于快速查找和更新 # 首先判断旧的数据是否含有 unique_key
    final_dict = {item[unique_key]: item for item in old_dicts if item.get(unique_key, None)}
    if not final_dict:
        print("old_dicts not has unique_key or no data ...")
        return new_dicts

    # 遍历新数据，进行更新或添加
    for new_data_dict in new_dicts:
        new_data_key = new_data_dict[unique_key]
        final_dict[new_data_key] = new_data_dict

    # 返回最终的数据列表
    return list(final_dict.values())


def dict_pop_keys(my_dict:dict, keys:list):
    """移除字典中不需要的键"""
    for key in keys:
        my_dict.pop(key, None)
    return my_dict


def dict_deep_update(old_dict, new_dict):
    """
    递归地将 dict2 的内容更新到 dict1 中。

    :param old_dict: 被更新的字典
    :param new_dict: 更新来源的字典
    :return: 更新后的 dict1
    """
    for key, value in new_dict.items():
        if key in old_dict:
            if isinstance(old_dict[key], dict) and isinstance(value, dict):
                # 如果当前值是字典，则递归更新
                dict_deep_update(old_dict[key], value)
            else:
                # 否则直接更新
                old_dict[key] = value
        else:
            # 如果键不存在于 dict1 中，则添加
            old_dict[key] = value
    return old_dict


def filter_expect_keys(raw_dict, need_keys):
    try:
        dic_copy = copy.deepcopy(raw_dict)
        # 检查是否有超出格式的json
        for k, v in raw_dict.items():
            if k not in need_keys:
                dic_copy.pop(k)
                print(f"not expect dict Key:[{k}] -> value:[{v}]")
        return dic_copy
    except Exception as error:
        print(f"filter_expect_keys occur error: {error}")
        return raw_dict


def spread_dict(data, parent_key='', sep='.', ignore_list_indices=True):
    """
    将嵌套的 dict 或 list 扁平化为单层 dict。

    :param data: 要展开的数据，可以是 dict 或 list
    :param parent_key: 父级键名（递归用）
    :param sep: 键名分隔符
    :param ignore_list_indices: 是否忽略列表索引（True 表示不显示 [0], [1] 等）
    :return: 扁平化后的 dict 或 list（根据输入类型）
    """
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            value = spread_dict(v, new_key, sep=sep, ignore_list_indices=ignore_list_indices)
            if isinstance(value, dict):
                result.update(value)
            else:
                result[new_key] = value
        return result

    elif isinstance(data, list):
        if ignore_list_indices:
            # 忽略索引，仅处理每个 item（如果是 dict，则展开）
            results = []
            for item in data:
                processed = spread_dict(item, '', sep=sep, ignore_list_indices=ignore_list_indices)
                if isinstance(processed, dict):
                    results.append(processed)
                else:
                    results.append(processed)
            return results
        else:
            # 保留索引
            return [
                spread_dict(item, f"{parent_key}[{i}]", sep=sep, ignore_list_indices=ignore_list_indices)
                if isinstance(item, dict) else item
                for i, item in enumerate(data)
            ]
    else:
        return data