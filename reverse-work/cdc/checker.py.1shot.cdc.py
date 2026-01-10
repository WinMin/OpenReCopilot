# Source Generated with Decompyle++
# File: checker.py.1shot.seq (Python 3.12)

'__pyarmor_enter_54914__(...)'
import re
import os
import json
import textwrap
from collections import defaultdict
from ida_hexrays import DecompilationFailure, decompile

def drop_task_tag_in_output(output):
    '__pyarmor_enter_54917__(...)'
    _var_var_0 = output.split('\n')[-1]
# WARNING: Decompyle incomplete


def find_json_by_re(output):
    '__pyarmor_enter_54920__(...)'
    _var_var_1 = '```(json|JSON)?(.*?)```'
    _var_var_2 = re.findall(_var_var_1, output, re.DOTALL)
    if _var_var_2:
        pass
    else:
        None(_var_var_2[-1][1])
        return None
    '__pyarmor_exit_54921__(...)'
    return _var_var_2[-1][1]


def find_output_by_re(output):
    '__pyarmor_enter_54923__(...)'
    _var_var_1 = '<Output>(.*?)</Output>'
    _var_var_2 = re.findall(_var_var_1, output, re.DOTALL)
    if _var_var_2:
        pass
    else:
        None(_var_var_2[-1])
        return None
    '__pyarmor_exit_54924__(...)'
    return _var_var_2[-1]


def parse_model_response_json(json_str):
    '__pyarmor_enter_54926__(...)'
    if not json_str:
        print('[!] Empty model response')
# WARNING: Decompyle incomplete


def parse_model_response_str(response):
    '__pyarmor_enter_54929__(...)'
    if not response:
        print('[!] Empty model response')
# WARNING: Decompyle incomplete


def parse_var_pred(var_pred):
    '__pyarmor_enter_54932__(...)'
    if not isinstance(var_pred, list):
        pass
# WARNING: Decompyle incomplete


def vars_check_and_refine(var_pred_items, return_type):
    """
    var_pred_items: [ 
        {'original':[type, name], 'prediction':[type, name, is_complex_type, typedetails]}, 
        ... 
    ]
    """
    '__pyarmor_enter_54935__(...)'
    if not var_pred_items:
        pass
    else:
        None([] if return_type == 'list' else { })
        return None
    if [] if return_type == 'list' else { }(var_pred_items, dict):
        var_pred_items = [
            var_pred_items]
    if not isinstance(var_pred_items, list):
        pass
    else:
        None([] if return_type == 'list' else { })
        return None
    _var_var_17 = [] if return_type == 'list' else { }
# WARNING: Decompyle incomplete


def funcname_check_and_refine(funcname_preds):
    '__pyarmor_enter_54938__(...)'
# WARNING: Decompyle incomplete


def summary_check_and_refine(summary):
    '__pyarmor_enter_54941__(...)'
    if not summary:
        pass
    else:
        None(dict())
        return None
    if dict()(summary, str):
        pass
    else:
        None(summary)
        return None
    _var_var_25 = summary
    _var_var_25['brief'] = summary.get('brief', '')
    _var_var_25['details'] = summary.get('details', '')
    _var_var_25['params'] = summary.get('params', { })
    _var_var_25['return'] = summary.get('return', '')
    _var_var_25['category'] = summary.get('category', 'none')
    _var_var_25['algorithm'] = summary.get('algorithm', 'none')
    _var_var_26 = summary.get('inline_comment', { })
# WARNING: Decompyle incomplete


def is_no_original_list(items):
    '''
    items: [pred_list_1, pred_list_2, ...]
    pred_list_x: [type, name, is_complex_type, typedetails]
    '''
    '__pyarmor_enter_54944__(...)'
# WARNING: Decompyle incomplete


def get_func_args(func_ea):
    '__pyarmor_enter_54947__(...)'
    _var_var_31 = decompile(func_ea)
    if not _var_var_31:
        raise DecompilationFailure
# WARNING: Decompyle incomplete


def get_func_args_vars(func_ea):
    '__pyarmor_enter_54950__(...)'
    _var_var_31 = decompile(func_ea)
    if not _var_var_31:
        raise DecompilationFailure
# WARNING: Decompyle incomplete


def func_analysis_check_and_refine(func_analysis, arg_names, var_names):
    '__pyarmor_enter_54953__(...)'
    if arg_names == None:
        arg_names = []
    if var_names == None:
        var_names = []
    if not func_analysis:
        pass
    else:
        None(dict())
        return None
    _var_var_34 = dict()
    _var_var_35 = summary_check_and_refine(func_analysis)
    _var_var_34['funcname'] = funcname_check_and_refine(func_analysis.get('funcname', ''))
    _var_var_34['ret_type'] = func_analysis.get('ret_type', '')
    _var_var_36 = []
    _var_var_37 = func_analysis.get('vars', { })
    if not isinstance(_var_var_37, dict) and isinstance(_var_var_37, list):
        print(f'''[!] found bad vars in prediction: {str(_var_var_37)}''')
        _var_var_37 = { }
    if isinstance(_var_var_37, list):
        _var_var_36 = _var_var_37
# WARNING: Decompyle incomplete


def response_check_and_refine(response, task_tag, arg_names, var_names):
    '__pyarmor_enter_54956__(...)'
    if not response:
        print('[!] Empty model response')
# WARNING: Decompyle incomplete


def split_pred_to_var_arg(func_ea, response):
    '''
    Split the response to vars and args
    need run with ida_execute
    '''
    '__pyarmor_enter_54959__(...)'
    _var_var_50 = {
        'vars': { },
        'args': { } }
    if not response:
        pass
    else:
        None(_var_var_50)
        return None
    _var_var_31 = decompile(func_ea)
    if not _var_var_31:
        raise DecompilationFailure
# WARNING: Decompyle incomplete

'__pyarmor_exit_54915__(...)'
