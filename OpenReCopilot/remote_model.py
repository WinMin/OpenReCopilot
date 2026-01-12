import openai # pip install openai
import anthropic # pip install anthropic
import time
import asyncio
import traceback # 用于打印异常堆栈

# 假设这些自定义模块存在于项目中
from config import settings_manager, PROMPT_TEMPLATE # PROMPT_TEMPLATE 可能是字典
from task_guides import TASK_GUIDES, TASK_OUTPUT_FORMATS, get_mock_response

# PyArmor 相关的 __assert_armored__, __pyarmor_enter_XXXX__, __pyarmor_exit_XXXX__ 调用已省略

class OpenAIModel:
    def __init__(self):
        # PyArmor 保护代码已省略
        super().__init__() # 虽然字节码中没有明确的父类，但 super() 调用通常存在
        self._current_completion = None # 用于存储活动的流式 API 调用对象
        self._cancelled = False         # 取消标志

    def _is_anthropic_api(self, base_url: str) -> bool:
        """检测是否为 Anthropic API。"""
        return 'anthropic' in base_url.lower() if base_url else False

    def cancel(self):
        """取消当前正在进行的模型调用。"""
        # PyArmor 保护代码已省略
        self._cancelled = True

    async def call_model(self, prompt: str, task_tag: str, timeout: int = 600):
        """
        异步调用 OpenAI 模型。

        Args:
            prompt: 用户提供的核心提示内容。
            task_tag: 任务的唯一标识符，用于选择任务指南和输出格式。
            timeout: API 调用的超时时间（秒）。

        Returns:
            一个元组 (model_response_text, original_prompt_for_feedback)。
            如果发生错误或取消，model_response_text 会包含错误或取消信息。
        """
        # PyArmor 保护代码已省略
        self._cancelled = False # 重置取消标志
        
        # 1. 获取并格式化提示模板
        template_name = settings_manager.settings.get('prompt_template', 'default_template_name') # 从配置获取模板名称
        # 假设 PROMPT_TEMPLATE 是一个字典，例如:
        # PROMPT_TEMPLATE = {
        #     "default_template_name": "Format: {format}\nGuide: {guide}\nInput: {input}",
        #     "default_template_name_wo_guide": "Format: {format}\nInput: {input}"
        # }
        
        current_template_str = PROMPT_TEMPLATE.get(template_name, "{input}") # 获取模板字符串，提供默认值

        if template_name.endswith("_wo_guide"): # 如果模板名称指示不使用指南
            formatted_prompt = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(task_tag, "")) \
                                                 .replace("{input}", prompt)
        else:
            formatted_prompt = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(task_tag, "")) \
                                                 .replace("{guide}", TASK_GUIDES.get(task_tag, "")) \
                                                 .replace("{input}", prompt)
        
        # 为反馈准备的原始提示（可能就是格式化后的提示）
        prompt_for_feedback = formatted_prompt 

        # 2. 打印调试信息 (如果启用了调试模式)
        if settings_manager.settings.get('debug_mode', False):
            # 字节码中对 prompt 进行了 .split('\n') 和 .join('\n[DEBUG🐛] ') 操作
            debug_prompt_lines = [f"\n[DEBUG🐛] {line}" for line in formatted_prompt.split('\n')]
            print("".join(debug_prompt_lines))

            model_name_setting = settings_manager.settings.get('model_name', 'unknown_model')
            print(f"[🔗] OpenAIModel.call_model: model_name={model_name_setting}, timeout={timeout}s")
            print(f"[🔗] OpenAIModel.call_model: send {len(formatted_prompt)} chars prompt")

        # 3. 初始化 API 客户端（支持 OpenAI 兼容和 Anthropic）
        try:
            base_url = settings_manager.settings.get('base_url', '')
            api_key = settings_manager.settings.get('api_key', 'sk-none')
            model_name = settings_manager.settings.get('model_name', 'gpt-3.5-turbo')

            print(f"[🔗] Calling model: {model_name} at {base_url or 'OpenAI default'}")

            # 检测是否为 Anthropic API
            if self._is_anthropic_api(base_url):
                # 使用 Anthropic 客户端
                return await self._call_anthropic_model(
                    formatted_prompt, model_name, api_key, base_url, timeout, prompt_for_feedback
                )
            
            # 使用 OpenAI 兼容客户端
            # 构建客户端参数
            client_args = {'api_key': api_key}
            if base_url:
                # 确保 base_url 格式正确
                if not base_url.endswith('/v1') and not base_url.endswith('/v1/'):
                    if not base_url.endswith('/'):
                        base_url += '/v1'
                    else:
                        base_url += 'v1'
                client_args['base_url'] = base_url

            # 使用异步客户端
            client = openai.AsyncOpenAI(**client_args)

            # 4. 构建消息并发送请求
            messages = [{"role": "user", "content": formatted_prompt}]

            self._current_completion = await client.chat.completions.create(
                model=model_name,
                temperature=0.6,
                stream=True,
                max_tokens=settings_manager.settings.get('max_output_tokens', 2048),
                messages=messages,
                timeout=float(timeout)
            )

            # 5. 处理流式响应
            reasoning_content_parts = []
            async for chunk in self._current_completion:
                if self._cancelled:
                    print("\n[!💥] Analysis cancelled by user (during streaming)")
                    await self._current_completion.close() # 确保关闭流
                    self._current_completion = None
                    return "<Cancelled>Analysis cancelled by user", prompt_for_feedback
                
                # 检查 chunk.choices[0].delta.content
                # 字节码中检查了 hasattr(chunk.choices[0].delta, 'reasoning_content')
                # 和 hasattr(chunk.choices[0].delta, 'content')
                # 这表明模型可能返回带有 'reasoning_content' 或 'content' 的 delta
                
                chunk_content = None
                if chunk.choices and chunk.choices[0].delta:
                    delta = chunk.choices[0].delta
                    if hasattr(delta, 'reasoning_content') and delta.reasoning_content:
                        chunk_content = delta.reasoning_content
                    elif hasattr(delta, 'content') and delta.content:
                         chunk_content = delta.content
                
                if chunk_content:
                    print(chunk_content, end="") # 实时打印，不换行
                    reasoning_content_parts.append(chunk_content)
            
            print() # 在流结束后换行
            self._current_completion = None
            final_response_text = "".join(reasoning_content_parts)
            return final_response_text, prompt_for_feedback

        except openai.APITimeoutError as e:
            print(f"[!💥] Error: OpenAI API request timed out: {e}")
            self._current_completion = None
            return f"<RequestException>Request timed out: {e}", prompt_for_feedback
        except openai.APIConnectionError as e:
            print(f"[!💥] Error: Failed to connect to API: {e}")
            self._current_completion = None
            return f"<RequestException>Connection failed: {e}", prompt_for_feedback
        except openai.AuthenticationError as e:
            print(f"[!💥] Error: API authentication failed: {e}")
            self._current_completion = None
            return f"<RequestException>Authentication failed - check your API key: {e}", prompt_for_feedback
        except Exception as e:
            print(f"[!💥] Error in OpenAIModel.call_model: {e}")
            traceback.print_exc()
            self._current_completion = None # 清理
            return f"<RequestException>{str(e)}", prompt_for_feedback

    async def _call_anthropic_model(self, formatted_prompt: str, model_name: str, 
                                     api_key: str, base_url: str, timeout: int, prompt_for_feedback: str):
        """
        使用 Anthropic API 调用 Claude 模型。
        
        Args:
            formatted_prompt: 格式化后的提示词
            model_name: 模型名称 (如 claude-sonnet-4-20250514)
            api_key: Anthropic API 密钥
            base_url: API 基础 URL (如 https://open.bigmodel.cn/api/anthropic)
            timeout: 超时时间（秒）
            prompt_for_feedback: 用于反馈的原始提示词
            
        Returns:
            元组 (响应文本, 原始提示词)
        """
        try:
            # 构建客户端参数
            client_args = {'api_key': api_key}
            if base_url:
                client_args['base_url'] = base_url
            
            client = anthropic.AsyncAnthropic(**client_args)
            
            # 构建消息
            messages = [{"role": "user", "content": formatted_prompt}]
            
            # 创建流式请求
            reasoning_content_parts = []
            
            async with client.messages.stream(
                model=model_name,
                max_tokens=settings_manager.settings.get('max_output_tokens', 2048),
                messages=messages,
            ) as stream:
                self._current_completion = stream
                async for text in stream.text_stream:
                    if self._cancelled:
                        print("\n[!💥] Analysis cancelled by user (during Anthropic streaming)")
                        self._current_completion = None
                        return "<Cancelled>Analysis cancelled by user", prompt_for_feedback
                    
                    print(text, end="")
                    reasoning_content_parts.append(text)
            
            print()  # 在流结束后换行
            self._current_completion = None
            final_response_text = "".join(reasoning_content_parts)
            return final_response_text, prompt_for_feedback
            
        except anthropic.APIConnectionError as e:
            print(f"[!💥] Error: Failed to connect to Anthropic API: {e}")
            self._current_completion = None
            return f"<RequestException>Connection failed: {e}", prompt_for_feedback
        except anthropic.AuthenticationError as e:
            print(f"[!💥] Error: Anthropic API authentication failed: {e}")
            self._current_completion = None
            return f"<RequestException>Authentication failed - check your API key: {e}", prompt_for_feedback
        except anthropic.RateLimitError as e:
            print(f"[!💥] Error: Anthropic API rate limit exceeded: {e}")
            self._current_completion = None
            return f"<RequestException>Rate limit exceeded: {e}", prompt_for_feedback
        except Exception as e:
            print(f"[!💥] Error in Anthropic API call: {e}")
            traceback.print_exc()
            self._current_completion = None
            return f"<RequestException>{str(e)}", prompt_for_feedback

    async def call_model_mock(self, prompt: str, task_tag: str, timeout: int = 600):
        """
        异步模拟调用AI模型，用于调试。
        """
        # PyArmor 保护代码已省略
        self._cancelled = False
        
        template_name = settings_manager.settings.get('prompt_template', 'default_template_name')
        current_template_str = PROMPT_TEMPLATE.get(template_name, "{input}")

        if template_name.endswith("_wo_guide"):
            formatted_prompt = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(task_tag, "")) \
                                                 .replace("{input}", prompt)
        else:
            formatted_prompt = current_template_str.replace("{format}", TASK_OUTPUT_FORMATS.get(task_tag, "")) \
                                                 .replace("{guide}", TASK_GUIDES.get(task_tag, "")) \
                                                 .replace("{input}", prompt)
        
        prompt_for_feedback = formatted_prompt

        # 打印调试信息
        if settings_manager.settings.get('debug_mode', False):
            debug_prompt_lines = [f"\n[DEBUG🐛] {line}" for line in formatted_prompt.split('\n')]
            print("".join(debug_prompt_lines))
            
            base_url_setting = settings_manager.settings.get('base_url', 'N/A')
            api_key_setting = settings_manager.settings.get('api_key', 'N/A')[:5] + "..." # 仅显示部分API密钥
            model_name_setting = settings_manager.settings.get('model_name', 'mock_model')
            print(f"[DEBUG🐛] OpenAIModel.call_model_mock: base_url={base_url_setting}, api_key={api_key_setting}, model_name={model_name_setting}, timeout={timeout}s")
            print(f"[DEBUG🐛] OpenAIModel.call_model_mock: recv {len(formatted_prompt)} chars prompt")

        mock_response_full = get_mock_response(task_tag)
        
        print(f"[DEBUG🐛] Mock response for {task_tag}:")
        response_parts = []
        for line in mock_response_full.split('\n'): # 模拟流式输出
            if self._cancelled:
                print("\n[!💥] Analysis cancelled by user (during mock streaming)")
                return "<Cancelled>Analysis cancelled by user", prompt_for_feedback
            
            print(f"[DEBUG🐛] {line}") # 逐行打印模拟响应
            response_parts.append(line)
            await asyncio.sleep(0.1) # 模拟网络延迟

        return "\n".join(response_parts), prompt_for_feedback