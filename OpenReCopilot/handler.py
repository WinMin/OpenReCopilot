import ida_kernwin
import idc
import idaapi
import threading
import time
import re # 虽然导入了，但在顶层代码中未直接使用
import json
import asyncio
import functools
from functools import partial

# 假设这些模块存在于项目中
from remote_model import OpenAIModel
from ext_info import build_prompt, apply_prediction # apply_prediction 导入但未在此文件顶层使用
from recopilot_qt import (
    ReCopilotSettingsDialog, create_decompilation_view,
    create_user_confirm_view, create_variable_selection_view,
    create_user_confirm_view_for_funcname, add_cancel_button,
    remove_cancel_button
)
from config import settings_manager
from checker import (
    response_check_and_refine, split_pred_to_var_arg,
    parse_model_response_json, parse_model_response_str,
    get_func_args, get_func_args_vars
)

# 全局AI模型实例
model = OpenAIModel()

# IDA 主线程执行辅助函数
def ida_execute(func_to_exec, exec_args=(), sync_type=ida_kernwin.MFF_WRITE):
    """
    在IDA主线程中执行函数。
    """
    # PyArmor 相关的保护代码在此处被忽略
    result_container = {'result': None}

    def wrapper_func():
        # PyArmor 相关的保护代码在此处被忽略
        try:
            if exec_args is None: # 处理无参数调用的情况
                 result_container['result'] = func_to_exec()
            else:
                 result_container['result'] = func_to_exec(*exec_args)
        except Exception as e:
            # 考虑在调试模式下打印更详细的错误
            print(f"[!] 在 ida_execute 的 wrapper 中发生错误: {e}")
            if settings_manager.settings.get('debug_mode', False):
                import traceback
                traceback.print_exc()
            result_container['result'] = None
        return 1 # execute_sync 要求返回非0值

    # 字节码显示使用了 partial，即使 wrapper_func 内部通过闭包访问 func_to_exec 和 exec_args
    # MAKE_CELL指令为 func, args, _var_var_0 (result_container) 创建了cell对象
    # 然后在创建 wrapper 时使用 LOAD_CLOSURE 加载它们
    prepared_task = partial(wrapper_func)
    
    ida_kernwin.execute_sync(prepared_task, sync_type)
    return result_container['result']

# --- 分析功能函数 ---

def common_analysis_logic(ea, task_tag, selected_items=(), response_parser=parse_model_response_json, view_creator=create_user_confirm_view, check_refine_parser_args_count=4):
    """
    通用的分析逻辑骨架。
    check_refine_parser_args_count: response_check_and_refine 需要的参数数量 (除了response和task_tag)
    """
    prompt_str = ida_execute(build_prompt, (ea, task_tag, selected_items))
    if not prompt_str:
        print(f"[{task_tag}] 未能构建 prompt 或用户取消。")
        return

    if settings_manager.settings.get('need_confirm', True):
        func_name_str = ida_execute(idc.get_func_name, (ea,))
        prompt_len = len(prompt_str)
        confirm_msg = (f"对地址 {hex(ea)} ({func_name_str}) 执行 {task_tag} 分析，"
                       f"查询长度 {prompt_len} 字符?\n\n"
                       "(可在设置中禁用用户确认)")
        if ida_execute(ida_kernwin.ask_yn, (1, confirm_msg)) != 1:
            print(f"[{task_tag}] 用户取消操作。")
            return

    cancel_button_widget = ida_execute(add_cancel_button, (model,))
    
    model_response_text, prompt_for_feedback = "", ""
    try:
        if settings_manager.settings.get('debug_mode', False):
            # 模拟函数也应返回 (response, prompt)
            if task_tag == '<func-analysis>': model_response_text, prompt_for_feedback = func_analysis_mock(ea)
            elif task_tag == '<decompilation>': model_response_text, prompt_for_feedback = decompilation_mock(ea)
            elif task_tag == '<specific-vars>': model_response_text, prompt_for_feedback = specific_vars_analysis_mock(ea, selected_items) # 假设 mock 也能处理
            elif task_tag == '<vars>': model_response_text, prompt_for_feedback = all_vars_analysis_mock(ea)
            elif task_tag == '<args>': model_response_text, prompt_for_feedback = all_args_analysis_mock(ea)
            # 为 func_name_analysis_mock 和 summary_analysis_mock 添加类似分支
            else: # 默认 mock
                 model_response_text, prompt_for_feedback = f'{{"mock_response": "mock for {task_tag}"}}', f"mock_prompt_for_{task_tag}"

        else:
            model_response_text, prompt_for_feedback = asyncio.run(model.call_model(prompt_str, task_tag))
    finally:
        if cancel_button_widget:
            ida_execute(remove_cancel_button, (cancel_button_widget,))

    if model_response_text is not None and model_response_text.startswith("<Cancelled>"):
        print(f"[{task_tag}] 操作被用户通过取消按钮中断。")
        return

    if not model_response_text:
        print(f"[{task_tag}] AI模型未返回响应。")
        return
        
    parsed_response = response_parser(model_response_text) # parse_model_response_json 或 parse_model_response_str
    if not parsed_response:
        print(f"[{task_tag}] 解析模型响应失败: {model_response_text[:200]}")
        return

    checked_response = parsed_response # 默认值
    if response_parser == parse_model_response_json: # 通常 JSON 响应需要进一步检查和提炼
        func_args, func_vars = (), () # 默认值
        if check_refine_parser_args_count == 4: # 需要 args 和 vars
            func_args, func_vars = ida_execute(get_func_args_vars, (ea,))
        elif check_refine_parser_args_count == 2: # 可能只需要 args (例如 all_args_analysis)
            func_args = ida_execute(get_func_args, (ea,)) # 假设有这个函数
            
        # 动态构建参数列表
        refine_args = [parsed_response, task_tag]
        if func_args is not None: refine_args.append(func_args)
        if func_vars is not None and check_refine_parser_args_count == 4 : refine_args.append(func_vars)

        checked_response = response_check_and_refine(*refine_args)

    ida_execute(view_creator, (ea, task_tag, prompt_for_feedback, model_response_text, checked_response))


def func_analysis(ea):
    common_analysis_logic(ea, '<func-analysis>')

def decompilation(ea):
    common_analysis_logic(ea, '<decompilation>', response_parser=parse_model_response_str, view_creator=create_decompilation_view, check_refine_parser_args_count=0)

def specific_vars_analysis(ea):
    var_selection_form = ida_execute(create_variable_selection_view, (ea,))
    if not var_selection_form:
        print("[!] 创建变量选择视图失败。")
        return

    # 检查表单是否有选择
    def check_form_has_selection():
        if hasattr(var_selection_form, 'selected_args') and hasattr(var_selection_form, 'selected_vars'):
             return bool(var_selection_form.selected_args or var_selection_form.selected_vars)
        return False

    # 检查表单窗口是否仍然存在
    def is_form_visible():
        if hasattr(var_selection_form, 'title'):
            widget = ida_execute(ida_kernwin.find_widget, (var_selection_form.title,))
            return widget is not None
        return False

    # 等待用户选择（最多等待60秒）
    max_wait = 600  # 60秒
    wait_count = 0
    while wait_count < max_wait:
        if check_form_has_selection():
            break
        if not is_form_visible():
            break
        time.sleep(0.1)
        wait_count += 1

    if not check_form_has_selection():
        print("[!] 变量选择视图已关闭或未选择任何内容。")
        return

    selected_args_list = getattr(var_selection_form, 'selected_args', [])
    selected_vars_list = getattr(var_selection_form, 'selected_vars', [])

    if not selected_args_list and not selected_vars_list:
        print('[!] 未选择任何变量或参数。')
        return

    print(f"[*] 已选参数: {selected_args_list}")
    print(f"[*] 已选变量: {selected_vars_list}")

    all_selected_items = selected_args_list + selected_vars_list
    common_analysis_logic(ea, '<specific-vars>', selected_items=all_selected_items, check_refine_parser_args_count=4)


def all_vars_analysis(ea):
    common_analysis_logic(ea, '<vars>') # 假设 build_prompt 会处理获取所有变量

def all_args_analysis(ea):
    # 对于 <args>, response_check_and_refine 可能只需要 func_args
    common_analysis_logic(ea, '<args>', check_refine_parser_args_count=2)


def func_name_analysis(ea):
    common_analysis_logic(ea, '<funcname>', response_parser=parse_model_response_str, view_creator=create_user_confirm_view_for_funcname, check_refine_parser_args_count=0)

def summary_analysis(ea):
    common_analysis_logic(ea, '<summary>', response_parser=parse_model_response_json, view_creator=create_user_confirm_view) # 假设 summary 用 JSON 格式

# --- Mock Analysis Functions ---
# (这些函数模拟AI模型的行为，用于调试)
def func_analysis_mock(ea):
    print(f"func_analysis_mock: EA {hex(ea)}")
    for _ in range(3): print("."); time.sleep(0.5)
    return '{"analysis_type": "function", "summary": "Mock function analysis done."}', "Mock prompt for func analysis"

def decompilation_mock(ea):
    print(f"decompilation_mock: EA {hex(ea)}")
    for _ in range(3): print("."); time.sleep(1.5)
    return "// Mock decompiled code for " + hex(ea), "Mock prompt for decompilation"

def specific_vars_analysis_mock(ea, selected_items):
    print(f"specific_vars_analysis_mock: EA {hex(ea)}, items: {selected_items}")
    for _ in range(3): print("."); time.sleep(1.5)
    return '{"analysis_type": "specific_vars", "details": "Mock analysis for specific vars done."}', "Mock prompt for specific vars"

def all_vars_analysis_mock(ea):
    print(f"all_vars_analysis_mock: EA {hex(ea)}")
    for _ in range(3): print("."); time.sleep(1.5)
    return '{"analysis_type": "all_vars", "variables": ["var_a", "var_b"]}', "Mock prompt for all vars"

def all_args_analysis_mock(ea):
    print(f"all_args_analysis_mock: EA {hex(ea)}")
    for _ in range(3): print("."); time.sleep(1.5)
    return '{"analysis_type": "all_args", "arguments": ["arg_1", "arg_2"]}', "Mock prompt for all args"


# --- IDA Action Handlers ---
class BaseAnalysisHandler(ida_kernwin.action_handler_t):
    analysis_function = None
    action_description = "N/A"

    def __init__(self):
        super(BaseAnalysisHandler, self).__init__()

    def activate(self, ctx):
        current_ea = ida_execute(idc.get_screen_ea)
        if current_ea == idaapi.BADADDR:
            print(f"{self.action_description}: 无效地址。")
            return 1
        
        func_obj = ida_execute(idaapi.get_func, (current_ea,))
        
        if func_obj:
            func_name_str = ida_execute(idc.get_func_name, (func_obj.start_ea,))
            print(f"{self.action_description} 在地址: {hex(func_obj.start_ea)}, 函数名: {func_name_str}")
            
            if self.analysis_function:
                # 在新线程中运行分析以避免阻塞UI
                thread = threading.Thread(target=self.analysis_function, args=(func_obj.start_ea,))
                thread.start()
        else:
            print(f"{self.action_description}: 当前地址 {hex(current_ea)} 不在函数内。")
        return 1

    def update(self, ctx):
        # 仅在反编译伪代码窗口启用
        if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class FuncAnalysisHandler(BaseAnalysisHandler):
    analysis_function = staticmethod(func_analysis)
    action_description = "函数整体分析"

class DecompilationHandler(BaseAnalysisHandler):
    analysis_function = staticmethod(decompilation)
    action_description = "反编译"

class SpecificVariableAnalysisHandler(BaseAnalysisHandler):
    analysis_function = staticmethod(specific_vars_analysis)
    action_description = "特定变量分析"

class AllVariableAnalysisHandler(BaseAnalysisHandler):
    analysis_function = staticmethod(all_vars_analysis)
    action_description = "所有变量分析"

class AllArgumentAnalysisHandler(BaseAnalysisHandler):
    analysis_function = staticmethod(all_args_analysis)
    action_description = "所有参数分析"

class FuncNameAnalysisHandler(BaseAnalysisHandler):
    analysis_function = staticmethod(func_name_analysis)
    action_description = "函数名称分析"

class SummaryAnalysisHandler(BaseAnalysisHandler):
    analysis_function = staticmethod(summary_analysis)
    action_description = "总结分析"


class ReCopilotSettingsHandler(ida_kernwin.action_handler_t):
    """处理显示 ReCopilot 设置对话框的处理器。"""
    def __init__(self):
        super(ReCopilotSettingsHandler, self).__init__()

    def activate(self, ctx):
        dialog = ReCopilotSettingsDialog() # 来自 recopilot_qt
        dialog.exec_() # 显示 Qt 对话框
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS # 设置应始终可访问