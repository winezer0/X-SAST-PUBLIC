import random
import time
from typing import Any

import tiktoken


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


def query_model(ai_client: Any, model_name: str, content: str, time_out:int, stream: bool = False):
    """ 发送查询到模型（支持普通/流式模式）"""
    try:
        start_time = time.time()
        message = ""
        response = ai_client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": content}],
            stream=stream,
            timeout=time_out
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


