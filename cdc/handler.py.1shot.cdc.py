# Source Generated with Decompyle++
# File: handler.py.1shot.seq (Python 3.12)

'__pyarmor_enter_54986__(...)'
import ida_kernwin
import idc
import idaapi
import threading
import time
import re
import json
import asyncio
from functools import partial
from remote_model import OpenAIModel
from ext_info import build_prompt, apply_prediction
from recopilot_qt import ReCopilotSettingsDialog, create_decompilation_view, create_user_confirm_view, create_variable_selection_view, create_user_confirm_view_for_funcname, add_cancel_button, remove_cancel_button
from config import settings_manager
from checker import response_check_and_refine, split_pred_to_var_arg, parse_model_response_json, parse_model_response_str, get_func_args, get_func_args_vars
from feedback import send_feedback
model = OpenAIModel()

def ida_execute(func, args, sync_type):
    '''
    exec func in ida main thread
    
    Args:
        func: exec func
        args: args for func
        sync_type: default MFF_WRITE
        
    Returns:
        func return value
    '''
    '__pyarmor_enter_54989__(...)'
    _var_var_0 = {
        'result': None }
    
    def _var_var_1():
        '__pyarmor_enter_54992__(...)'
        _var_var_0['result'] = func(*args)
        '__pyarmor_exit_54993__(...)'
        return 1

    _var_var_2 = partial(_var_var_1)
    ida_kernwin.execute_sync(_var_var_2, sync_type)
    '__pyarmor_exit_54990__(...)'
    return _var_var_0['result']


def func_analysis(ea):
    '__pyarmor_enter_54995__(...)'
    _var_var_3 = '<func-analysis>'
    _var_var_4 = ida_execute(build_prompt, (ea, _var_var_3, ()))
    '__pyarmor_exit_54996__(...)'
    return None if not _var_var_4 else None


def decompilation(ea):
    '__pyarmor_enter_54998__(...)'
    _var_var_3 = '<decompilation>'
    _var_var_4 = ida_execute(build_prompt, (ea, _var_var_3, ()))
    '__pyarmor_exit_54999__(...)'
    return None if not _var_var_4 else None


def specific_vars_analysis(ea):
    '__pyarmor_enter_55001__(...)'
    _var_var_13 = ida_execute(create_variable_selection_view, (ea,))
    _var_var_14 = []
    _var_var_15 = []
    
    def _var_var_16():
        '__pyarmor_enter_55004__(...)'
        if _var_var_13.selected_args or _var_var_13.selected_vars:
            pass
        else:
            True
            return True
        False
        return False
        '__pyarmor_exit_55005__(...)'
        '__pyarmor_exit_55005__(...)'

# WARNING: Decompyle incomplete


def all_vars_analysis(ea):
    '__pyarmor_enter_55007__(...)'
    _var_var_3 = '<vars>'
    _var_var_4 = ida_execute(build_prompt, (ea, _var_var_3, ()))
    '__pyarmor_exit_55008__(...)'
    return None if not _var_var_4 else None


def all_args_analysis(ea):
    '__pyarmor_enter_55010__(...)'
    _var_var_3 = '<args>'
    _var_var_4 = ida_execute(build_prompt, (ea, _var_var_3, ()))
    '__pyarmor_exit_55011__(...)'
    return None if not _var_var_4 else None


def func_name_analysis(ea):
    '__pyarmor_enter_55013__(...)'
    _var_var_3 = '<funcname>'
    _var_var_4 = ida_execute(build_prompt, (ea, _var_var_3, ()))
    '__pyarmor_exit_55014__(...)'
    return None if not _var_var_4 else None if _var_var_7 != 1 else None if _var_var_9.startswith('<Cancelled>') else None


def summary_analysis(ea):
    '__pyarmor_enter_55016__(...)'
    _var_var_3 = '<summary>'
    _var_var_4 = ida_execute(build_prompt, (ea, _var_var_3, ()))
    '__pyarmor_exit_55017__(...)'
    return None if not _var_var_4 else None


def func_analysis_mock(ea):
    '__pyarmor_enter_55019__(...)'
    print(f'''func_analysis: Function Analysis on ea: {hex(ea)}''')
# WARNING: Decompyle incomplete


def decompilation_mock(ea):
    '__pyarmor_enter_55022__(...)'
    print(f'''decompilation: Decompilation on ea: {hex(ea)}''')
# WARNING: Decompyle incomplete


def specific_vars_analysis_mock(ea):
    '__pyarmor_enter_55025__(...)'
    print(f'''specific_vars_analysis: Variable Analysis on ea: {hex(ea)}''')
# WARNING: Decompyle incomplete


def all_vars_analysis_mock(ea):
    '__pyarmor_enter_55028__(...)'
    print(f'''all_vars_analysis: Variable Analysis on ea: {hex(ea)}''')
# WARNING: Decompyle incomplete


def all_args_analysis_mock(ea):
    '__pyarmor_enter_55031__(...)'
    print(f'''all_args_analysis: Variable Analysis on ea: {hex(ea)}''')
# WARNING: Decompyle incomplete


class FuncAnalysisHandler(ida_kernwin.action_handler_t):
    '__pyarmor_enter_55034__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55037__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55038__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55040__(...)'
        _var_var_18 = idc.get_screen_ea()
        _var_var_19 = idaapi.get_func(_var_var_18)
        _var_var_6 = idc.get_func_name(_var_var_18)
        print(f'''Function Analysis on ea: {hex(_var_var_18)}, func name: {_var_var_6}''')
        _var_var_20 = threading.Thread(target = func_analysis, args = (_var_var_19.start_ea,))
        _var_var_20.start()
        '__pyarmor_exit_55041__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55043__(...)'
        '__pyarmor_exit_55044__(...)'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

    '__pyarmor_exit_55035__(...)'


class DecompilationHandler(ida_kernwin.action_handler_t):
    '__pyarmor_enter_55046__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55049__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55050__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55052__(...)'
        _var_var_18 = idc.get_screen_ea()
        _var_var_19 = idaapi.get_func(_var_var_18)
        _var_var_6 = idc.get_func_name(_var_var_18)
        print(f'''Decompilation on ea: {hex(_var_var_18)}, func name: {_var_var_6}''')
        _var_var_20 = threading.Thread(target = decompilation, args = (_var_var_19.start_ea,))
        _var_var_20.start()
        '__pyarmor_exit_55053__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55055__(...)'
        '__pyarmor_exit_55056__(...)'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

    '__pyarmor_exit_55047__(...)'


class SpecificVariableAnalysisHandler(ida_kernwin.action_handler_t):
    '__pyarmor_enter_55058__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55061__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55062__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55064__(...)'
        _var_var_18 = idc.get_screen_ea()
        _var_var_19 = idaapi.get_func(_var_var_18)
        _var_var_6 = idc.get_func_name(_var_var_18)
        print(f'''Variable Analysis on ea: {hex(_var_var_18)}, func name: {_var_var_6}''')
        _var_var_20 = threading.Thread(target = specific_vars_analysis, args = (_var_var_19.start_ea,))
        _var_var_20.start()
        '__pyarmor_exit_55065__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55067__(...)'
        '__pyarmor_exit_55068__(...)'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

    '__pyarmor_exit_55059__(...)'


class AllVariableAnalysisHandler(ida_kernwin.action_handler_t):
    '__pyarmor_enter_55070__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55073__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55074__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55076__(...)'
        _var_var_18 = idc.get_screen_ea()
        _var_var_19 = idaapi.get_func(_var_var_18)
        _var_var_6 = idc.get_func_name(_var_var_18)
        print(f'''Variable Analysis on ea: {hex(_var_var_18)}, func name: {_var_var_6}''')
        _var_var_20 = threading.Thread(target = all_vars_analysis, args = (_var_var_19.start_ea,))
        _var_var_20.start()
        '__pyarmor_exit_55077__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55079__(...)'
        '__pyarmor_exit_55080__(...)'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

    '__pyarmor_exit_55071__(...)'


class AllArgumentAnalysisHandler(ida_kernwin.action_handler_t):
    '__pyarmor_enter_55082__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55085__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55086__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55088__(...)'
        _var_var_18 = idc.get_screen_ea()
        _var_var_19 = idaapi.get_func(_var_var_18)
        _var_var_6 = idc.get_func_name(_var_var_18)
        print(f'''All Argument Analysis on ea: {hex(_var_var_18)}, func name: {_var_var_6}''')
        _var_var_20 = threading.Thread(target = all_args_analysis, args = (_var_var_19.start_ea,))
        _var_var_20.start()
        '__pyarmor_exit_55089__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55091__(...)'
        '__pyarmor_exit_55092__(...)'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

    '__pyarmor_exit_55083__(...)'


class FuncNameAnalysisHandler(ida_kernwin.action_handler_t):
    '__pyarmor_enter_55094__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55097__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55098__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55100__(...)'
        _var_var_18 = idc.get_screen_ea()
        _var_var_19 = idaapi.get_func(_var_var_18)
        _var_var_6 = idc.get_func_name(_var_var_18)
        print(f'''Function Name Analysis on ea: {hex(_var_var_18)}, func name: {_var_var_6}''')
        _var_var_20 = threading.Thread(target = func_name_analysis, args = (_var_var_19.start_ea,))
        _var_var_20.start()
        '__pyarmor_exit_55101__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55103__(...)'
        '__pyarmor_exit_55104__(...)'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

    '__pyarmor_exit_55095__(...)'


class SummaryAnalysisHandler(ida_kernwin.action_handler_t):
    '__pyarmor_enter_55106__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55109__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55110__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55112__(...)'
        _var_var_18 = idc.get_screen_ea()
        _var_var_19 = idaapi.get_func(_var_var_18)
        _var_var_6 = idc.get_func_name(_var_var_18)
        print(f'''Summary Analysis on ea: {hex(_var_var_18)}, func name: {_var_var_6}''')
        _var_var_20 = threading.Thread(target = summary_analysis, args = (_var_var_19.start_ea,))
        _var_var_20.start()
        '__pyarmor_exit_55113__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55115__(...)'
        '__pyarmor_exit_55116__(...)'
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

    '__pyarmor_exit_55107__(...)'


class ReCopilotSettingsHandler(ida_kernwin.action_handler_t):
    '''
    Handler for showing ReCopilot settings dialog.
    '''
    '__pyarmor_enter_55118__(...)'
    
    def __init__(self):
        '__pyarmor_enter_55121__(...)'
        ida_kernwin.action_handler_t.__init__(self)
        '__pyarmor_exit_55122__(...)'

    
    def activate(self, ctx):
        '__pyarmor_enter_55124__(...)'
        _var_var_21 = ReCopilotSettingsDialog()
        _var_var_21.exec_()
        '__pyarmor_exit_55125__(...)'
        return 1

    
    def update(self, ctx):
        '__pyarmor_enter_55127__(...)'
        '__pyarmor_exit_55128__(...)'
        return ida_kernwin.AST_ENABLE_ALWAYS

    '__pyarmor_exit_55119__(...)'

'__pyarmor_exit_54987__(...)'
