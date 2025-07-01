import copy
import random
import time
from collections import defaultdict
from datetime import datetime
from typing import Any

import tiktoken

from libs_com.file_path import path_is_file
from libs_com.utils_dict import dict_deep_update, filter_expect_keys
from libs_com.utils_json import parse_json_strong, print_json
from libs_com.utils_yaml import load_yaml, save_yaml
from libs_verifier.verifier_enum import VerifyKeys, VerifyStatus, AIProvider, AIModelKeys


def get_providers_model_info(providers_info):
    providers_model_info = defaultdict(dict)
    for provider_name, provider_content in providers_info.items():
        provider_infos = get_provider_infos(providers_info, provider_name)
        # 更新模型信息
        for provider_info in provider_infos:
            # {'provider_name': 'qwen', 'base_url': '', 'api_key': '', 'model_name': ''}
            print(f"开始查询[{provider_name}]模型列表信息:{provider_info}")
            client_info = provider_creat_client(provider_info)
            model_info = get_client_model_info(client_info)
            if not model_info:
                continue
            # 把获取的模型信息保存起来
            providers_model_info[provider_name].update(model_info)
    return providers_model_info

def get_client_model_info(client_info:dict):
    # 获取所有模型
    provider_name = client_info[AIProvider.PROVIDER_NAME.value]
    ai_client = client_info[AIProvider.CLIENT.value]
    models_info = get_models_info(ai_client)
    if models_info:
        print(f"[{provider_name}]模型列表获取成功 -> 模型数量:[{len(models_info.keys())}]")
        return models_info
    else:
        api_key = client_info[AIProvider.API_KEY.value]
        print(f"[{provider_name}]模型列表获取失败 -> api_key:[{api_key}] ")
        return None


def get_models_info(ai_client) -> dict:
    """获取可用模型列表"""
    models_info = {}
    try:
        response = ai_client.models.list()
        models = response.data
        # 转换为字典列表
        for model in models:
            model_name = model.id
            created_time = datetime.fromtimestamp(model.created).strftime("%Y-%m-%d %H:%M:%S")
            models_info[model_name] = {
                AIModelKeys.NAME.value: model_name,
                AIModelKeys.CREATED.value: created_time,
                AIModelKeys.OBJECT.value: model.object,
                AIModelKeys.OWNED_BY.value: model.owned_by,
                AIModelKeys.USABLE.value: None, # 记录模型是否可用
                AIModelKeys.STREAM.value: None, # 记录模型是否必须用流模式
                AIModelKeys.DELAY.value: None,  # 记录模型延时
            }
    except Exception as e:
        print(f"获取模型列表失败: {str(e)}")
    return models_info



def provider_creat_client(provider_info: dict):
    """基于provider_info dict 创建ai client"""
    from openai import OpenAI
    provider_name = provider_info.get(AIProvider.PROVIDER_NAME.value)
    base_url = provider_info.get(AIProvider.BASE_URL.value)
    api_key = provider_info.get(AIProvider.API_KEY.value)

    if not api_key:
        print(f"[{provider_name}] api_key 密钥为空!!!")
        return None

    provider_info[AIProvider.CLIENT.value] = OpenAI(base_url=base_url, api_key=api_key)
    return provider_info


def simple_create_clients(base_url: str, api_keys: list):
    """根据 base_url 和 api_keys 构建多个 OpenAI 客户端实例。 """
    from openai import OpenAI
    if not api_keys:
        print("api_keys 密钥列表为空!!!")
        return None

    client_info = {}
    for api_key in api_keys:
        ai_client = OpenAI(base_url=base_url, api_key=api_key)
        client_info[api_key] = ai_client
    return client_info


def get_random_client(ai_clients:list):
    """从客户端列表中随机选择一个客户端。 """
    if not ai_clients:
        raise ValueError("客户端列表不能为空")

    return random.choice(list(ai_clients))


def query_model_common(ai_client: Any, model_name: str, content: str):
    """ 发送查询到模型，并返回模型的响应内容以及查询耗时。"""
    try:
        # 记录查询开始时间
        start_time = time.time()
        # 发送请求到模型
        response = ai_client.chat.completions.create(
            model=model_name,
            messages=[{'role': 'user', 'content': content}]
        )
        # 记录查询结束时间
        query_time = time.time() - start_time
        # 返回模型的响应内容和查询耗时
        message = response.choices[0].message.content
        return message, query_time
    except Exception as error:
        print(f"模型查询异常: {str(error)}")
        if "You exceeded your current requests list" in str(error):
            print("模型查询线程数量超出限制, 请修改线程数!!!")
        return None, None


def query_model_stream(ai_client: Any, model_name: str, content: str):
    """ 调用思考模型并返回思考过程、回复内容及分阶段耗时"""
    # 时间记录初始化
    start_time = time.time()
    thinking_start_time = start_time
    answering_start_time = None

    # 创建流式请求
    completion = ai_client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": content}],
        stream=True
    )

    # 初始化变量
    reasoning_content = ""
    answer_content = ""
    is_answering = False

    for chunk in completion:
        if not chunk.choices:
            continue  # 忽略空choices
        delta = chunk.choices[0].delta
        # 处理思考过程
        if hasattr(delta, 'reasoning_content') and delta.reasoning_content is not None:
            reasoning_content += delta.reasoning_content
        else:
            # 处理回复内容
            content = delta.content
            if content is not None:
                # 记录回复阶段开始时间
                if not is_answering and content.strip() != "":
                    is_answering = True
                    answering_start_time = time.time()

                answer_content += content

    # 计算时间
    end_time = time.time()
    total_time = end_time - start_time
    thinking_time = answering_start_time - thinking_start_time if answering_start_time else 0
    answering_time = end_time - answering_start_time if answering_start_time else (end_time - start_time)
    return reasoning_content, answer_content, total_time, thinking_time, answering_time


def query_model(ai_client: Any, model_name: str, content: str, stream: bool = False):
    """ 发送查询到模型（支持普通/流式模式）"""
    try:
        start_time = time.time()
        message = ""
        response = ai_client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": content}],
            stream=stream
        )
        if stream:
            # 流式模式
            for chunk in response:
                if chunk.choices and chunk.choices[0].delta.content:
                    message += chunk.choices[0].delta.content
        else:
            # 非流式模式
            message = response.choices[0].message.content

        query_time = round(time.time() - start_time, 2)
        return message, query_time, None
    except Exception as error:
        print(f"模型查询异常: {str(error)}")
        if "exceeded your" in str(error):
            print("模型查询线程数量超出限制, 请修改线程数!!!")
        if "stream mode" in str(error):
            print("当前模型仅支持流模式, 请使用流模式调用!!!")
        return None, None, error


def query_test(ai_client, model_name, stream:bool = False) -> bool:
    """测试模型连接是否正常"""
    content = '请求测试 (回复限定格式 回复消息:{消息})'
    return query_model(ai_client, model_name, content, stream=stream)


def clients_test_query(client_infos:list[dict], model_name:str):
    """批量验证client的可用性, 并返回测试结果"""
    usable_client_infos = []
    provider_model_infos = []
    for client_info in client_infos:
        client_usable, provider_model_info = client_test_query(client_info, model_name)
        if client_usable:
            usable_client_infos.append(client_info)
            provider_model_infos.append(provider_model_info)
    return usable_client_infos, provider_model_infos


def client_test_query(client_info:dict, model_name:str):
    """调用ai客户端进行运行尝试"""
    ai_client = client_info.get(AIProvider.CLIENT.value)
    provider_name = client_info.get(AIProvider.PROVIDER_NAME.value)
    api_key = client_info.get(AIProvider.API_KEY.value)

    curr_model_info = {
        AIModelKeys.NAME.value: model_name,
        # AIModelKeys.USABLE.value: None,  # 记录模型是否可用
        # AIModelKeys.STREAM.value: None,  # 记录模型是否必须用流模式
        # AIModelKeys.DELAY.value: None,  # 记录模型延时
    }

    # 两种模式均不可用
    usable = False
    stream = None
    delay = None

    message, common_time, error_msg =  query_test(ai_client, model_name, stream=False)
    is_common = "回复消息" in str(message)
    is_stream = "enable the stream" in str(error_msg)

    if is_common:
        # 先进行常规格式,常规则是完毕后
        usable = True
        stream = False
        delay = common_time

    if is_stream:
        usable = True
        stream = True
        message, stream_time, error_msg = query_test(ai_client, model_name, stream=True)
        delay = stream_time

    # 更新 model_info
    curr_model_info[AIModelKeys.USABLE.value] = usable
    curr_model_info[AIModelKeys.STREAM.value] = stream
    curr_model_info[AIModelKeys.DELAY.value] = delay
    print(f"模型[{model_name}] 是否可用:[{usable}] 流模式:[{stream}] 延时:[{delay}]")

    # 保存为可以更新到model配置的格式
    rovider_model_info = {provider_name:{model_name:curr_model_info}}

    if usable:
        print(f"[{provider_name}] 模型 [{model_name}] 连接测试通过...")
    else:
        print(f"[{provider_name}] 模型 [{model_name}] 连接测试失败, 密钥[{api_key}] ...")
    return usable, rovider_model_info


def parse_response(response: str) -> tuple:
    """解析模型响应"""
    analysis_base = {
        VerifyKeys.VERIFY.value: VerifyStatus.UNKNOWN.value,
        VerifyKeys.SENSITIVE.value: None,
        VerifyKeys.HTTP_POC.value: None,
        VerifyKeys.EXPLAIN.value: None,
        VerifyKeys.BECAUSE.value: None,
        VerifyKeys.REPAIR.value: None
    }

    if not response:
        error_msg = "模型返回为空"
    else:
        need_keys = list(analysis_base.keys())
        response = response.strip("json`\n, ")
        analysis_resp, error_msg = parse_json_strong(response, need_keys)
        analysis_resp = filter_expect_keys(analysis_resp, need_keys)
        # 将 verify 转换为 VerifyStatus 格式
        analysis_resp[VerifyKeys.VERIFY.value] = VerifyStatus.format(analysis_resp.get(VerifyKeys.VERIFY.value))
        analysis_base.update(analysis_resp)
    return analysis_base, error_msg



def count_tokens(text: str, model_name: str = 'gpt-3.5-turbo') -> int:
    """
    根据指定的模型名称计算文本中的 tokens 数量。

    :param text: 要计算 tokens 数量的文本
    :param model_name: 使用的模型名称，默认是 'gpt-3.5-turbo'
    :return: 文本中的 tokens 数量
    """
    try:
        # 获取对应模型的编码器
        encoding = tiktoken.encoding_for_model(model_name)
        # 将文本转换为 tokens 并计算数量
        num_tokens = len(encoding.encode(text))
        return num_tokens
    except Exception as error:
        print(f"count_tokens error:{error}")
        return -1


def res_money(res_tokens, price=0.002):
    """计算响应tokens的总价"""
    return round(res_tokens / 1000.0 * price, 3)


def req_money(req_tokens, price=0.0008):
    """计算请求tokens的总价"""
    return round(req_tokens / 1000.0 * price, 3)


def get_provider_infos(providers: dict, provider_name: str):
    """生成AI接口信息"""
    provider_content = providers.get(provider_name, {})
    if not provider_content:
        print(f"配置信息中没有找到[{provider_name}]对应的AI接口!!! -> 允许接口为: {list(providers.keys())}")
        return None

    base_url = provider_content.get(AIProvider.BASE_URL.value, [])
    if not base_url:
        print(f"配置信息中没有找到[{provider_name}]对应的AI接口URL!!! -> 请手动填充配置文件Base_URL")
        return None

    api_keys = provider_content.get(AIProvider.API_KEYS.value, [])
    if not api_keys:
        print(f"配置信息中没有找到[{provider_name}]对应的密钥信息!!! -> 请手动填充配置文件API_KEYS")
        return None

    provider_infos = []
    for api_key in api_keys:
        provider_info = {
            AIProvider.PROVIDER_NAME.value: provider_name,
            AIProvider.BASE_URL.value: base_url,
            AIProvider.API_KEY.value: api_key,
            AIProvider.MODEL_NAME.value: None,
        }
        provider_infos.append(provider_info)
    return provider_infos


if __name__ == '__main__':
    from openai import OpenAI

    # 阿里云百炼 需要密钥
    # base_url = "https://dashscope.aliyuncs.com/compatible-mode/v1"
    # Ollama 接口 不需要密钥
    base_url = "http://192.168.210.5/v1"
    api_key = "xxxxxxxxxxxxxx"
    ai_client = OpenAI(base_url=base_url, api_key=api_key)
    models_info = get_models_info(ai_client)
    print(models_info.keys())

    message, query_time, error = query_model(ai_client, model_name="qwen3:32b", content="1+1等于几", stream=True)
    print(f"完整回复：{message}")
    print(f"回复阶段耗时：{query_time:.2f}秒")

    query_test(ai_client, model_name="qwen3:32b", stream=True)


def update_providers_models_info(config_models, providers_info):
    """下载所有api接口的模型信息"""
    providers_model_info = get_providers_model_info(providers_info)
    if providers_model_info:
        providers_model_info = dict(providers_model_info)
        if path_is_file(config_models):
            # 更新合并新旧数据
            old_providers_model_info = load_yaml(config_models)
            providers_model_info = dict_deep_update(providers_model_info, old_providers_model_info)
        save_yaml(config_models, providers_model_info)
    print("所有接口模型列表更新完毕...")


def update_models_info(config_models, usable_provider_model_infos):
    """更新单个模型信息"""
    # 把当前模型的可用测试结果写入到模型记录配置文件中
    if usable_provider_model_infos:
        print_json(f"成功获取到模型状态:{usable_provider_model_infos}")
        cur_providers_model_info = load_yaml(config_models)
        for usable_provider_model_info in usable_provider_model_infos:
            cur_providers_model_info = dict_deep_update(cur_providers_model_info, usable_provider_model_info)
        save_yaml(config_models, cur_providers_model_info)

def get_cached_model_infos(config_models, provider_name, model_names):
    """从缓存的配置文件中获取模型的信息"""
    model_infos = []
    for model_name in model_names:
        model_info = get_cached_model_info(config_models, provider_name, model_name)
        if model_info:
            model_infos.append(model_info)
    return model_infos

def get_cached_model_info(config_models, provider_name, model_name):
    """从缓存的配置文件中获取模型的信息"""
    providers_model_info = load_yaml(config_models)
    if not providers_model_info or provider_name not in providers_model_info.keys():
        print(f"[{provider_name}] -> [所有模型] 信息不存在 请执行[--load-models] ")
        return None

    if model_name not in providers_model_info.get(provider_name).keys():
        print(f"[{provider_name}] -> [{model_name}] 信息不存在 请执行[-m {model_name} --check-model] ")
        return None

    model_info = providers_model_info.get(provider_name).get(model_name)
    print(f"[{provider_name}] -> [{model_name}]存在模型缓存信息:")
    print_json(model_info)
    return model_info
