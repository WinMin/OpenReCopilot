import os
import json

RECOPILOT_MODEL_PROMPT_TEPLATE = "{input}<Thought>"
RECOPILOT_MODEL_SUPERT_THOUGHT_PROMPT_TEPLATE = "{input}<Super-Thought>"

# 加载 prompts.json
prompt_json_path = os.path.join(os.path.dirname(__file__), 'prompts.json')

if not os.path.exists(prompt_json_path):
    raise Exception(f"[!💥] not found {prompt_json_path}")

PROMPT_TEMPLATE = {}
try:
    with open(prompt_json_path, 'r', encoding='utf-8') as f:
        PROMPT_TEMPLATE = json.load(f)
    print(f"[👏] load {len(PROMPT_TEMPLATE)} prompt templates:\n{list(PROMPT_TEMPLATE.keys())}")
except Exception as e:
    # 原始字节码中没有明确的此处的异常处理，但通常会有
    print(f"Error loading prompts.json: {e}")
    # PROMPT_TEMPLATE 将保持为空字典或根据具体错误处理逻辑

class ReCopilotSettingsManager:
    """
    Manages persistent storage and retrieval of ReCopilot settings.
    """
    def __init__(self):
        # PyArmor 相关的 __assert_armored__ 和 __pyarmor_enter/exit__ 调用被忽略
        self.settings_dir = os.path.dirname(os.path.abspath(__file__))
        self.settings_file = os.path.join(self.settings_dir, 'settings.json')
        os.makedirs(self.settings_dir, exist_ok=True)
        print(f"[DEBUG🐛] Settings file: {self.settings_file}")
        self.settings = self.load_settings()

    def get_default_settings(self):
        """Get default settings dictionary."""
        # 支持第三方API配置:
        # - OpenAI: base_url留空, api_key填写sk-xxx, model_name如gpt-4o
        # - Claude (via OpenAI兼容): base_url=https://api.anthropic.com, model_name=claude-3-opus-20240229
        # - DeepSeek: base_url=https://api.deepseek.com, model_name=deepseek-chat
        # - 本地Ollama: base_url=http://localhost:11434, model_name=llama3
        return {
            'model_name': 'gpt-4o',  # 默认使用OpenAI GPT-4o
            'base_url': '',  # 留空使用OpenAI官方API
            'api_key': '',  # 需要用户填写
            'prompt_template': 'general', # 默认使用通用提示模板
            'max_output_tokens': 8000,
            'max_trace_caller_depth': 1,
            'max_trace_callee_depth': 1,
            'max_context_func_num': 10,
            'data_flow_analysis': True,
            'measure_info_score': True,
            'need_confirm': True,
            'debug_mode': False,
            'feedback': False # 原始字节码中有13个值，这里推测为 False
        }

    def load_settings(self):
        """Load settings from file or return defaults."""
        # PyArmor 相关的 __assert_armored__ 和 __pyarmor_enter/exit__ 调用被忽略
        if not os.path.exists(self.settings_file):
            return self.get_default_settings()
        try:
            with open(self.settings_file, 'r') as f:
                loaded_settings = json.load(f)
            
            # 合并默认设置，确保所有键都存在
            default_settings = self.get_default_settings()
            for key in default_settings:
                if key not in loaded_settings:
                    loaded_settings[key] = default_settings[key]
            return loaded_settings
        except Exception as e:
            print(f"Error loading settings: {str(e)}")
            return self.get_default_settings()

    def save_settings(self, settings_data): # 字节码中的参数名是 settings，避免与 self.settings 混淆
        """Save settings to file."""
        # PyArmor 相关的 __assert_armored__ 和 __pyarmor_enter/exit__ 调用被忽略
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings_data, f, indent=4)
            self.settings = settings_data # 更新实例的 settings
        except Exception as e:
            print(f"Error saving settings: {str(e)}")

    def get_setting(self, key):
        """Get current settings.""" # 文档字符串可能不准确，实际是获取特定键的值
        # PyArmor 相关的 __assert_armored__ 和 __pyarmor_enter/exit__ 调用被忽略
        return self.settings.get(key, None)

    def set_setting(self, key, value):
        """Change setting and save to file."""
        # PyArmor 相关的 __assert_armored__ 和 __pyarmor_enter/exit__ 调用被忽略
        if key in self.settings: # 确保键存在才更新，原始字节码逻辑
            self.settings[key] = value
            self.save_settings(self.settings)
        # else: # 如果键不存在，原始代码似乎不处理，也可以选择添加或抛出错误
            # print(f"Warning: Setting key '{key}' not found in default settings.")
            # self.settings[key] = value # 如果希望即使键不存在也添加
            # self.save_settings(self.settings)


# 实例化设置管理器
settings_manager = ReCopilotSettingsManager()

# 模块加载完成的 __pyarmor_exit_... 调用被忽略