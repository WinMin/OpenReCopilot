# Source Generated with Decompyle++
# File: ext_info.py.1shot.seq (Python 3.12)

'__pyarmor_enter_55130__(...)'
import os
import re
import idc
import json
import hashlib
import idaapi
import ida_ua
import ida_idp
import ida_name
import idautils
import ida_nalt
import ida_auto
import ida_funcs
import ida_xref
import ida_kernwin
import ida_typeinf
import ida_segment
import ida_hexrays
from collections import defaultdict
from ida_hexrays import decompile, DecompilationFailure
from data_flow import DataFlowAnalyzer
from config import settings_manager
from checker import parse_var_pred
from task_guides import TASK_GUIDES
MAX_TRACE_CALLER_DEPTH = settings_manager.settings['max_trace_caller_depth']
MAX_TRACE_CALLEE_DEPTH = settings_manager.settings['max_trace_callee_depth']
MAX_CONTEXT_FUNC_NUM = settings_manager.settings['max_context_func_num']
MEASURE_INFO_SCORE = settings_manager.settings['measure_info_score']
SUPPORT_FUNC_TYPES = set(TASK_GUIDES.keys())
DATA_FLOW_TEMPLATE = '<Data-Flow>\nTips: the alias expressions below are used to present the relationship between the local variable and the variable in target function. And the left value of `==` is the local variable and type, the right value is the usage pattern of the variable in target function.\n{}\n</Data-Flow>'
INPUT_TEMPLATE = '<context-pseudocode>\n{context}\n</context-pseudocode>\n<pseudocode>\n{target_func}\n</pseudocode>\n<Call-Chains>\n{call_chains}\n</Call-Chains>\n{data_flow}\nAnalysis Task Tag:\n{task_tag}'
IMPORT_FUNCS = dict()

def collect_import_funcs():
    '__pyarmor_enter_55133__(...)'
    _var_var_2 = idaapi.get_import_module_qty()
# WARNING: Decompyle incomplete

collect_import_funcs()

def is_thunk(ea):
    '__pyarmor_enter_55139__(...)'
    _var_var_5 = idc.get_func_flags(ea)
    if 0 < _var_var_5:
        0 < _var_var_5
    '__pyarmor_exit_55140__(...)'
    return 0 != _var_var_5 & ida_funcs.FUNC_THUNK


def is_thunk_func(func):
    '__pyarmor_enter_55142__(...)'
    if 0 < func.flags:
        0 < func.flags
    '__pyarmor_exit_55143__(...)'
    return 0 != func.flags & ida_funcs.FUNC_THUNK


def is_import_name(ea):
    '__pyarmor_enter_55145__(...)'
    _var_var_6 = ea
    if is_thunk(ea):
        _var_var_6 = ida_funcs.calc_thunk_func_target(ea)[0]
        if _var_var_6 == idaapi.BADADDR:
            _var_var_6 = ea
    if _var_var_6 in IMPORT_FUNCS:
        pass
    else:
        True
        return True
    False
    return False
    '__pyarmor_exit_55146__(...)'
    '__pyarmor_exit_55146__(...)'


def get_import_name_info(ea):
    '__pyarmor_enter_55148__(...)'
    _var_var_6 = ea
    if is_thunk(ea):
        _var_var_6 = ida_funcs.calc_thunk_func_target(ea)[0]
        if _var_var_6 == idaapi.BADADDR:
            _var_var_6 = ea
    if _var_var_6 in IMPORT_FUNCS:
        pass
    else:
        None(IMPORT_FUNCS[_var_var_6])
        return None
    '__pyarmor_exit_55149__(...)'
    return IMPORT_FUNCS[_var_var_6]


def demangle(name, disable_mask):
    '__pyarmor_enter_55151__(...)'
    _var_var_7 = idaapi.demangle_name(name, disable_mask, idaapi.DQT_FULL)
    if _var_var_7:
        pass
    else:
        None(_var_var_7)
        return None
    '__pyarmor_exit_55152__(...)'
    return _var_var_7


def get_pcode_md5(s):
    '__pyarmor_enter_55154__(...)'
    '__pyarmor_exit_55155__(...)'
    return hashlib.md5(s.encode('utf-8')).hexdigest()


def get_struc(struct_tid):
    '__pyarmor_enter_55157__(...)'
    _var_var_8 = ida_typeinf.tinfo_t()
    if _var_var_8.get_type_by_tid(struct_tid) and _var_var_8.is_struct():
        pass
    else:
        None(_var_var_8)
        return None
    '__pyarmor_exit_55158__(...)'
    return _var_var_8.BADADDR


def get_enum(enum_tid):
    '__pyarmor_enter_55160__(...)'
    _var_var_8 = ida_typeinf.tinfo_t()
    if _var_var_8.get_type_by_tid(enum_tid) and _var_var_8.is_enum():
        pass
    else:
        None(_var_var_8)
        return None
    '__pyarmor_exit_55161__(...)'
    return _var_var_8.BADADDR


def list_enum_members(name):
    '__pyarmor_enter_55163__(...)'
    _var_var_9 = f'''enum {name} {{\n'''
    _var_var_10 = ida_typeinf.get_idati()
    _var_var_8 = ida_typeinf.tinfo_t()
    if not _var_var_8.get_named_type(_var_var_10, name, ida_typeinf.BTF_ENUM, True, False):
        _var_var_9 += '??\n}'
# WARNING: Decompyle incomplete


class StructUnroller:
    '__pyarmor_enter_55166__(...)'
    
    def __init__(self, max_depth):
        '__pyarmor_enter_55169__(...)'
        self.structs = { }
        self.structs_size = { }
        self.MAX_DEPTH = max_depth
        '__pyarmor_exit_55170__(...)'

    
    def get_member(self, tif, offset):
        '__pyarmor_enter_55172__(...)'
        if not tif.is_struct():
            pass
        else:
            return None
            _var_var_18 = ida_typeinf.udm_t()
            _var_var_18.offset = offset * 8
            _var_var_14 = tif.find_udm(_var_var_18, ida_typeinf.STRMEM_OFFSET)
            if _var_var_14 != -1:
                pass
            else:
                None(_var_var_18)
                return None
        _var_var_18
        return None
        '__pyarmor_exit_55173__(...)'
        '__pyarmor_exit_55173__(...)'

    
    def unroll_struct_type(self, struct_type, cur_depth):
        '__pyarmor_enter_55175__(...)'
        if cur_depth > self.MAX_DEPTH:
            pass
        else:
            None(str(struct_type))
            return None
        _var_var_19 = str(struct_type).get_struc_id(str(struct_type))
        if _var_var_19 == idaapi.BADADDR:
            if cur_depth == 0 and struct_type.is_struct():
                self.structs[str(struct_type)] = []
        else:
            None(str(struct_type))
            return None
        _var_var_20 = str(struct_type)(struct_type)
        _var_var_21 = struct_type.get_size()
        self.structs[_var_var_20] = []
        self.structs_size[_var_var_20] = _var_var_21
        _var_var_22 = f'''struct {_var_var_20} // sizeof={hex(_var_var_21)}\n{{\n'''
    # WARNING: Decompyle incomplete

    '__pyarmor_exit_55167__(...)'


def get_structs_enums(var_list):
    '__pyarmor_enter_55178__(...)'
    _var_var_32 = dict()
# WARNING: Decompyle incomplete


def get_callee_name(inst_head_ea):
    '__pyarmor_enter_55181__(...)'
    _var_var_39 = []
# WARNING: Decompyle incomplete


def get_var_info(var_list):
    '__pyarmor_enter_55184__(...)'
    _var_var_44 = []
# WARNING: Decompyle incomplete


def get_local_vars(func_ea):
    '__pyarmor_enter_55187__(...)'
    _var_var_50 = decompile(func_ea)
    if _var_var_50 == None:
        raise DecompilationFailure
    _var_var_44 = []
# WARNING: Decompyle incomplete


def get_args(func_ea):
    '__pyarmor_enter_55190__(...)'
    _var_var_50 = decompile(func_ea)
    if _var_var_50 == None:
        raise DecompilationFailure
    _var_var_52 = []
# WARNING: Decompyle incomplete


def omit_too_long_pcode(pcode_lines):
    '__pyarmor_enter_55193__(...)'
# WARNING: Decompyle incomplete


def build_pcode_with_struct_and_enum(func_ea):
    '__pyarmor_enter_55196__(...)'
    if is_import_name(func_ea):
        (_var_var_54, _var_var_55) = get_import_name_info(func_ea)
    else:
        None({
            'pcode': f'''An imported function with name: {_var_var_54} in library: {_var_var_55}''',
            'struct_enum_dict': dict() })
        return None
    _var_var_50 = decompile(func_ea)
    if _var_var_50 == None:
        raise DecompilationFailure
    _var_var_56 = str(_var_var_50)
# WARNING: Decompyle incomplete


def measure_informative_score_strings(func, pcode_line_cnt):
    '__pyarmor_enter_55199__(...)'
    _var_var_59 = 0
# WARNING: Decompyle incomplete


def measure_informative_score_callees(func):
    '__pyarmor_enter_55202__(...)'
    _var_var_39 = []
# WARNING: Decompyle incomplete


def _real_measure_informative_score(func_ea):
    '__pyarmor_enter_55205__(...)'
    _var_var_65 = 0
    _var_var_66 = ida_funcs.get_func(func_ea)
    if not _var_var_66:
        pass
    else:
        -999
        return -999
        _var_var_64 = idaapi.has_name(idaapi.get_full_flags(_var_var_66.start_ea))
        if _var_var_64:
            _var_var_65 += 2
        _var_var_58 = 1
        _var_var_50 = decompile(func_ea)
        if _var_var_50:
            _var_var_58 = len(_var_var_50.get_pseudocode())
        else:
            raise DecompilationFailure
        _var_var_65 += measure_informative_score_strings(_var_var_66, _var_var_58)
        _var_var_65 += measure_informative_score_callees(_var_var_66)
        _var_var_65 += max(_var_var_58 // 100 - 1, 0) * -1
    None(_var_var_65)
    return None
# WARNING: Decompyle incomplete


def measure_informative_score(func_ea):
    '__pyarmor_enter_55208__(...)'
    if MEASURE_INFO_SCORE:
        pass
    else:
        None(_real_measure_informative_score(func_ea))
        return None
    '__pyarmor_exit_55209__(...)'
    return 1


class ContextBuilder:
    '''
    build pseudo-code context and call-chains for the target function
    '''
    '__pyarmor_enter_55211__(...)'
    
    def __init__(self, max_trace_callee_depth, max_trace_caller_depth, max_context_func_num, limit_funcs):
        '__pyarmor_enter_55214__(...)'
        self.context_callee_funcs = dict()
        self.context_caller_funcs = defaultdict(int)
        self.call_chains = set()
        self.limited_funcs = limit_funcs
        self.MAX_TRACE_CALLEE_DEPTH = max_trace_callee_depth
        self.MAX_TRACE_CALLER_DEPTH = max_trace_caller_depth
        self.MAX_CONTEXT_FUNC_NUM = max_context_func_num
        '__pyarmor_exit_55215__(...)'

    
    def build_context_forward(self, func_ea, temp_call_chain, depth):
        '__pyarmor_enter_55217__(...)'
        if self.limited_funcs and func_ea not in self.limited_funcs:
            pass
    # WARNING: Decompyle incomplete

    
    def build_context_backward(self, func_ea, temp_call_chain, depth):
        '__pyarmor_enter_55220__(...)'
        if self.limited_funcs and func_ea not in self.limited_funcs:
            pass
    # WARNING: Decompyle incomplete

    
    def build_context(self, func_ea):
        '__pyarmor_enter_55223__(...)'
        self.context_callee_funcs = dict()
        self.context_caller_funcs = defaultdict(int)
        self.call_chains = set()
        _var_var_74 = demangle(idc.get_func_name(func_ea))
        self.build_context_forward(func_ea, _var_var_74, 0)
        self.build_context_backward(func_ea, _var_var_74, 0)
        '__pyarmor_exit_55224__(...)'
        return True

    
    def get_context_pcode(self, target_func_ea, analyzed_funcs_in_dataflow):
        '__pyarmor_enter_55226__(...)'
        _var_var_66 = ida_funcs.get_func(target_func_ea)
        if not _var_var_66:
            pass
    # WARNING: Decompyle incomplete

    
    def get_call_chains(self):
        '__pyarmor_enter_55229__(...)'
        '__pyarmor_exit_55230__(...)'
        return '\n'.join(self.call_chains)

    
    def get_incontext_funcs(self):
        '''
        按keys(ea)去重，按values(depth)排序，value的绝对值大的在前
        '''
        '__pyarmor_enter_55232__(...)'
        _var_var_86 = set(self.context_callee_funcs.keys()) | set(self.context_caller_funcs.keys())
        _var_var_86 = None(sorted, key = (lambda x: max(self.context_callee_funcs.get(x, 0), abs(self.context_caller_funcs.get(x, 0)))), reverse = True)
        '__pyarmor_exit_55233__(...)'
        return _var_var_86

    '__pyarmor_exit_55212__(...)'


def get_numbers_from_pcode(pcode):
    '__pyarmor_enter_55235__(...)'
    _var_var_87 = '(?<!\\w)[+-]?0[xX][0-9a-fA-F]+(?:uLL|LL)?|(?<!\\w)[+-]?\\d+(?:uLL|LL)?(?!\\w)'
    _var_var_88 = []
# WARNING: Decompyle incomplete


def get_functions_in_text_like_seg():
    '__pyarmor_enter_55238__(...)'
    _var_var_92 = ida_segment.get_first_seg()
    _var_var_93 = []
# WARNING: Decompyle incomplete

MEANINGLESS_NAME_LIST = {
    'frame_dummy',
    'call_weak_fn',
    '__libc_csu_fini',
    '__libc_csu_init',
    'register_tm_clones',
    'deregister_tm_clones',
    '__do_global_ctors_aux',
    '__do_global_dtors_aux',
    '__x86.get_pc_thunk.ax',
    '__x86.get_pc_thunk.bp',
    '__x86.get_pc_thunk.bx',
    '__x86.get_pc_thunk.cx',
    '__x86.get_pc_thunk.di',
    '__x86.get_pc_thunk.dx',
    '__x86.get_pc_thunk.si'}

def is_good_func_for_build_input(func_ea, demangled_name, pcode_line_cnt, pcode_var_cnt):
    '__pyarmor_enter_55241__(...)'
    if demangled_name in MEANINGLESS_NAME_LIST:
        pass
    else:
        False
        return False
        if pcode_line_cnt > 100:
            pass
        else:
            False
            return False
            if pcode_var_cnt > 30:
                pass
            else:
                False
                return False
    False
    return True
    '__pyarmor_exit_55242__(...)'
    '__pyarmor_exit_55242__(...)'


def build_prompt(func_ea, task_tag, args):
    global MAX_TRACE_CALLEE_DEPTH, MAX_TRACE_CALLER_DEPTH, MAX_CONTEXT_FUNC_NUM, MEASURE_INFO_SCORE
    '__pyarmor_enter_55244__(...)'
    MAX_TRACE_CALLEE_DEPTH = settings_manager.settings['max_trace_callee_depth']
    MAX_TRACE_CALLER_DEPTH = settings_manager.settings['max_trace_caller_depth']
    MAX_CONTEXT_FUNC_NUM = settings_manager.settings['max_context_func_num']
    MEASURE_INFO_SCORE = settings_manager.settings['measure_info_score']
    _var_var_96 = settings_manager.settings['data_flow_analysis']
    print(f'''[DEBUG🐛] MAX_TRACE_CALLEE_DEPTH={MAX_TRACE_CALLEE_DEPTH}, MAX_TRACE_CALLER_DEPTH={MAX_TRACE_CALLER_DEPTH}, MAX_CONTEXT_FUNC_NUM={MAX_CONTEXT_FUNC_NUM}, MEASURE_INFO_SCORE={MEASURE_INFO_SCORE}, DATA_FLOW_ANALYSIS={_var_var_96}''')
    if task_tag not in SUPPORT_FUNC_TYPES:
        print(f'''[!] Unsupported task tag: {task_tag}''')
# WARNING: Decompyle incomplete


def apply_prediction_ret_type(func_ea, prediction):
    '__pyarmor_enter_55247__(...)'
    _var_var_110 = prediction.get('ret_type', None)
    if not _var_var_110 or isinstance(_var_var_110, str):
        print(f'''[!] found bad ret_type in prediction: {_var_var_110}''')
# WARNING: Decompyle incomplete


def apply_prediction_func_name(func_ea, prediction):
    '__pyarmor_enter_55250__(...)'
# WARNING: Decompyle incomplete


def add_array_type(type_name, array_dims):
    '''添加数组类型定义
    Args:
        type_name: 类型名称，如 "char"
        array_dims: 数组维度列表，如 [32] 表示一维数组，[4,4] 表示二维数组
    Returns:
        tinfo_t: 添加成功的类型
    '''
    '__pyarmor_enter_55253__(...)'
    print(f'''[+] Adding typedef for array type {type_name}''')
    _var_var_120 = ida_typeinf.tinfo_t()
    if not type_name.endswith(';'):
        type_name = f'''{type_name};'''
    if ida_typeinf.parse_decl(_var_var_120, idaapi.get_idati(), type_name, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL) == None:
        print(f'''[!] Failed to parse base type {type_name}''')
# WARNING: Decompyle incomplete


def add_enum_type(enum_name, enum_details):
    '''添加枚举类型
    Args:
        enum_name: 枚举名称
        enum_details: 枚举成员列表，每项格式为 [name, value]
    Returns:
        tinfo_t: 添加成功的枚举类型
    '''
    '__pyarmor_enter_55256__(...)'
    enum_name = list(enum_details.keys())[0]
    enum_details = enum_details[enum_name]
    print(f'''[+] Adding enum {enum_name}''')
    _var_var_123 = idc.get_enum(enum_name)
    if _var_var_123 != idaapi.BADADDR:
        print(f'''[*] Removing existing enum {enum_name}''')
        idc.del_enum(_var_var_123)
    _var_var_124 = idc.add_enum(-1, enum_name, 0)
    if _var_var_124 == -1 or _var_var_124 == idaapi.BADADDR:
        print(f'''[!] Failed to create enum {enum_name}''')
# WARNING: Decompyle incomplete


def add_empty_struct_type(struct_name, struct_size):
    '__pyarmor_enter_55259__(...)'
    struct_name = struct_name.replace('*', '').replace('struct ', '').strip()
    _var_var_84 = get_struc(idc.add_struc(-1, struct_name, 0))
    if _var_var_84 == idaapi.BADADDR:
        print(f'''[!] Failed to create struct {struct_name}''')
    else:
        return None
        _var_var_84.set_fixed_struct(True)
        _var_var_84.set_struct_size(struct_size)
    None(_var_var_84)
    return None
    '__pyarmor_exit_55260__(...)'
    '__pyarmor_exit_55260__(...)'


def add_struct_type(struct_name, struct_details):
    '''添加结构体类型
    Args:
        struct_name: 结构体名称
        struct_details: 结构体定义细节 {struct_name: [type_str, name, size]}
    Returns:
        tinfo_t: 添加成功的结构体类型
    '''
    '__pyarmor_enter_55262__(...)'
    struct_name = list(struct_details.keys())[0]
    struct_details = struct_details[struct_name]
    print(f'''[+] Adding struct {struct_name}''')
    _var_var_127 = idc.get_struc_id(struct_name)
    if _var_var_127 != idaapi.BADADDR:
        print(f'''[*] Removing existing struct {struct_name}''')
        idc.del_struc(_var_var_127)
    _var_var_128 = idc.add_struc(-1, struct_name, 0)
    if _var_var_128 == -1 or _var_var_128 == idaapi.BADADDR:
        print(f'''[!] Failed to create struct {struct_name}''')
# WARNING: Decompyle incomplete


def apply_prediction_arg(arg, arg_pred):
    '__pyarmor_enter_55265__(...)'
    (_var_var_136, _var_var_137, _var_var_138, _var_var_139) = arg_pred
    if not _var_var_136 and _var_var_137:
        print(f'''[!] found bad arg prediction for {arg.name}: {arg_pred}''')
# WARNING: Decompyle incomplete


def apply_prediction_args_old(func_ea, prediction):
    '__pyarmor_enter_55268__(...)'
    _var_var_143 = prediction.get('args', dict())
    if not _var_var_143:
        print(f'''[-] found empty args in prediction: {_var_var_143}''')
# WARNING: Decompyle incomplete


def apply_prediction_vars(func_ea, prediction):
    '__pyarmor_enter_55271__(...)'
    _var_var_146 = prediction.get('vars', dict())
    if not _var_var_146:
        print(f'''[-] found empty vars in prediction: {_var_var_146}''')
# WARNING: Decompyle incomplete


def build_doxygen_comment(prediction):
    '__pyarmor_enter_55274__(...)'
    _var_var_152 = prediction.get('brief', '')
    _var_var_153 = prediction.get('details', '')
    _var_var_154 = prediction.get('params', dict())
    _var_var_155 = prediction.get('return', '')
    _var_var_156 = prediction.get('category', '')
    _var_var_157 = prediction.get('algorithm', '')
    _var_var_158 = {
        'brief': _var_var_152,
        'details': _var_var_153,
        'params': _var_var_154,
        'return': _var_var_155,
        'category': _var_var_156,
        'algorithm': _var_var_157 }
    _var_var_159 = '/**\n'
# WARNING: Decompyle incomplete


def apply_prediction_func_comment(func_ea, comment):
    '__pyarmor_enter_55277__(...)'
    _var_var_66 = ida_funcs.get_func(func_ea)
    if not _var_var_66:
        print(f'''[!] Fail to get function at {hex(func_ea)}''')
    else:
        False
        return False
        if not comment:
            print(f'''[!] Apply empty comment to {hex(func_ea)}''')
        else:
            True
            return True
            if idc.set_func_cmt(_var_var_66.start_ea, comment, 0):
                print(f'''[+] Successfully set comment for function {hex(func_ea)}''')
                _var_var_116 = idaapi.open_pseudocode(_var_var_66.start_ea, 0)
                if _var_var_116:
                    _var_var_116.cfunc.refresh_func_ctext()
            else:
                True
                return True
                print(f'''[!] Fail to set comment for function {hex(func_ea)}''')
    False
    return False
    '__pyarmor_exit_55278__(...)'
    '__pyarmor_exit_55278__(...)'


def apply_prediction_inline_comment(func_ea, prediction):
    '__pyarmor_enter_55280__(...)'
    _var_var_164 = prediction.get('inline_comment', dict())
    if not _var_var_164 or isinstance(_var_var_164, dict):
        print(f'''[!] found bad inline_comment in prediction: {_var_var_164}''')
# WARNING: Decompyle incomplete


def apply_prediction(func_ea, task_tag, prediction):
    '__pyarmor_enter_55283__(...)'
    print('[🐛DEBUG] invoke apply_prediction')
    print(f'''[🐛DEBUG] task_tag: {task_tag}''')
    print(f'''[🐛DEBUG] prediction: {prediction}''')
    if task_tag not in SUPPORT_FUNC_TYPES:
        print(f'''[!] Unsupported task tag: {task_tag}''')
# WARNING: Decompyle incomplete

'__pyarmor_exit_55131__(...)'
