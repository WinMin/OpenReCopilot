# Source Generated with Decompyle++
# File: data_flow.py.1shot.seq (Python 3.12)

'__pyarmor_enter_54740__(...)'
import re
import idc
import json
import ida_hexrays
import ida_funcs
import ida_auto
import ida_name
import ida_lines
import ida_idaapi
import ida_xref
import idaapi
import idautils
import ida_segment
from collections import defaultdict
from termcolor import colored
IMPORT_FUNCS = dict()

def collect_import_funcs():
    '__pyarmor_enter_54743__(...)'
    _var_var_2 = idaapi.get_import_module_qty()
# WARNING: Decompyle incomplete

collect_import_funcs()

def is_thunk(ea):
    '__pyarmor_enter_54749__(...)'
    _var_var_5 = idc.get_func_flags(ea)
    if 0 < _var_var_5:
        0 < _var_var_5
    '__pyarmor_exit_54750__(...)'
    return 0 != _var_var_5 & ida_funcs.FUNC_THUNK


def is_thunk_func(func):
    '__pyarmor_enter_54752__(...)'
    if 0 < func.flags:
        0 < func.flags
    '__pyarmor_exit_54753__(...)'
    return 0 != func.flags & ida_funcs.FUNC_THUNK


def is_import_name(ea):
    '__pyarmor_enter_54755__(...)'
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
    '__pyarmor_exit_54756__(...)'
    '__pyarmor_exit_54756__(...)'


def get_import_name_info(ea):
    '__pyarmor_enter_54758__(...)'
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
    '__pyarmor_exit_54759__(...)'
    return IMPORT_FUNCS[_var_var_6]


def find_var_declaration(cfunc, type_name, var_name, is_arg):
    '__pyarmor_enter_54761__(...)'
    if is_arg:
        _var_var_7 = '.*' + re.escape(type_name) + '\\s*' + re.escape(var_name) + '.*'
    else:
        _var_var_7 = '\\s*' + re.escape(type_name) + '\\s*' + re.escape(var_name) + '[\\[\\]0-9xA-Fa-f]*;.*'
# WARNING: Decompyle incomplete


def demangle(name, disable_mask):
    '__pyarmor_enter_54764__(...)'
    _var_var_12 = ida_name.demangle_name(name, disable_mask, ida_name.DQT_FULL)
    if _var_var_12:
        pass
    else:
        None(_var_var_12)
        return None
    '__pyarmor_exit_54765__(...)'
    return _var_var_12


def get_final_x(cexpr):
    '__pyarmor_enter_54767__(...)'
    if cexpr.x:
        pass
    else:
        None(get_final_x(cexpr.x))
        return None
    '__pyarmor_exit_54768__(...)'
    return get_final_x(cexpr.x)


def clear_cast(cexpr):
    '__pyarmor_enter_54770__(...)'
    if cexpr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_ptr):
        pass
    else:
        None(clear_cast(cexpr.x))
        return None
    '__pyarmor_exit_54771__(...)'
    return clear_cast(cexpr.x)


class VarUsage:
    '__pyarmor_enter_54773__(...)'
    
    def __init__(self, var_name, var_type, pcode_line, ori_var_name, ori_var_type, alias_name, usage_type, access_type, offset, line_addr, func_name, context_depth):
        '__pyarmor_enter_54776__(...)'
        self.var_name = var_name
        self.var_type = var_type
        self.ori_var_name = ori_var_name
        self.ori_var_type = ori_var_type
        self.alias_name = alias_name
        self.pcode_line = pcode_line
        self.access_type = access_type
        self.usage_type = usage_type
        self.offset = offset
        self.line_addr = line_addr
        self.func_name = func_name
        self.context_depth = context_depth
        '__pyarmor_exit_54777__(...)'

    
    def __str__(self):
        '__pyarmor_enter_54779__(...)'
        if self.pcode_line:
            _var_var_13 = self.pcode_line.strip()
        else:
            _var_var_13 = 'Get pseudocode line error'
        _var_var_14 = f'''// alias: {self.var_type} {self.var_name} == {self.alias_name}'''
        '__pyarmor_exit_54780__(...)'
        return '\t' * abs(self.context_depth) + f'''{self.func_name}@L{self.line_addr}||{_var_var_13} {_var_var_14}'''

    
    def colored_print(self):
        '__pyarmor_enter_54782__(...)'
        if self.pcode_line == 'VARIABLE DECLARATION STATEMENT':
            _var_var_13 = colored('VARIABLE DECLARATION STATEMENT', 'red')
        elif self.pcode_line:
            _var_var_13 = self.pcode_line.strip()
        else:
            _var_var_13 = colored('Get pseudocode line error', 'red')
        _var_var_14 = f'''// alias: {self.var_type} {self.var_name} == {self.alias_name}'''
        '__pyarmor_exit_54783__(...)'
        return '\t' * abs(self.context_depth) + f'''{colored(self.func_name, 'blue')}@L{colored(self.line_addr, 'blue')}||{_var_var_13} {colored(_var_var_14, 'green')}'''

    '__pyarmor_exit_54774__(...)'


class FunctionContext:
    '__pyarmor_enter_54785__(...)'
    
    def __init__(self, func_ea, caller_ea):
        '__pyarmor_enter_54788__(...)'
        self.func_ea = func_ea
        self.caller_ea = caller_ea
        self.var_mappings = dict()
        self.depth = 0
        '__pyarmor_exit_54789__(...)'

    
    def __str__(self):
        '__pyarmor_enter_54791__(...)'
        '__pyarmor_exit_54792__(...)'
        return f'''Function at {hex(self.func_ea)} called from {hex(self.caller_ea) if self.caller_ea else 'None'}'''

    '__pyarmor_exit_54786__(...)'


class DataFlowAnalyzer:
    '__pyarmor_enter_54794__(...)'
    
    def __init__(self, max_trace_callee_depth, max_trace_caller_depth, limit_funcs):
        '__pyarmor_enter_54797__(...)'
        self.analyzed_funcs = set()
        self.current_cfunc = None
        self.usage_lines = []
        self.limited_funcs = limit_funcs
        self.MAX_TRACE_CALLEE_DEPTH = max_trace_callee_depth
        self.MAX_TRACE_CALLER_DEPTH = max_trace_caller_depth
        '__pyarmor_exit_54798__(...)'

    
    def _get_func_args(self, cfunc):
        """Get function's arguments"""
        '__pyarmor_enter_54800__(...)'
        _var_var_15 = []
    # WARNING: Decompyle incomplete

    
    def _get_pcode_line(self, line_no):
        '__pyarmor_enter_54803__(...)'
        if not self.current_cfunc:
            pass
        else:
            return None
            _var_var_13 = ida_lines.tag_remove(self.current_cfunc.get_pseudocode()[line_no].line)
        None(_var_var_13)
        return None
        '__pyarmor_exit_54804__(...)'
        '__pyarmor_exit_54804__(...)'

    
    def analyze_function_dataflow_forward(self, func_ea, context):
        '''trace data flow, forward on call stack (callee only)
        
        Args:
            func_ea: func addr
            context: func calling context for cross-function analysis
        '''
        '__pyarmor_enter_54806__(...)'
        if not context:
            context = FunctionContext(func_ea, caller_ea = None)
        if abs(context.depth) > self.MAX_TRACE_CALLEE_DEPTH:
            pass
    # WARNING: Decompyle incomplete

    
    def analyze_function_dataflow_backward(self, func_ea, context):
        '''trace data flow, backward on call stack (caller only)
        从 context.var_mappings 中的获取要追踪的变量，找到其在当前函数中的使用情况，分析时调用 DataFlowVisitor 注意此时不对 callee expr 进行分析，
        当前函数分析完成后，获取当前函数的所有arguments 判断每个参数是否在 context.var_mappings 中，如果一个arg存在于 context.var_mappings 中，
        则构建这个参数在caller中的var与arg alias的映射关系，存储到new_context.var_mappings 中，然后递归调用 analyze_function_dataflow_backward 

        Args:
            func_ea: func addr
            context: func calling context for cross-function analysis
        '''
        '__pyarmor_enter_54809__(...)'
        if not context:
            context = FunctionContext(func_ea, caller_ea = None)
        if abs(context.depth) > self.MAX_TRACE_CALLER_DEPTH:
            pass
    # WARNING: Decompyle incomplete

    
    def get_var_dataflow(self, func_ea, var_name, verbose):
        '''get specific variable data flow in the target function
        
        Args:
            func_ea: func addr
            var_name: specific variable, str or List[str]
            
        Returns:
            formatted data flow string
        '''
        '__pyarmor_enter_54821__(...)'
        self.analyzed_funcs.clear()
        self.usage_lines.clear()
        _var_var_33 = FunctionContext(func_ea)
        if isinstance(var_name, str):
            _var_var_33.var_mappings = {
                var_name: var_name }
    # WARNING: Decompyle incomplete

    
    def filter_data_flow_by_context_func(self, original_data_flow_str, context_funcs):
        '''filter data flow, keep the ones within context_funcs'''
        '__pyarmor_enter_54824__(...)'
    # WARNING: Decompyle incomplete

    '__pyarmor_exit_54795__(...)'


class DataFlowVisitor(ida_hexrays.ctree_visitor_t):
    '__pyarmor_enter_54827__(...)'
    
    def __init__(self, analyzer, context, tracked_vars, alias_mapping, not_trace_callee):
        '__pyarmor_enter_54830__(...)'
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS | ida_hexrays.CV_FAST | ida_hexrays.CV_PRUNE)
        self.analyzer = analyzer
        self.context = context
        self.tracked_vars = tracked_vars
        self.usage_lines = defaultdict(list)
        self.alias_mapping = alias_mapping if alias_mapping else dict()
        self.current_func_ea = self.analyzer.current_cfunc.entry_ea
        self.current_func_name = demangle(ida_funcs.get_func_name(self.current_func_ea))
        self.not_trace_callee = not_trace_callee
    # WARNING: Decompyle incomplete

    
    def _find_final_alias(self, var_name):
        '__pyarmor_enter_54833__(...)'
        _var_var_48 = set()
        _var_var_31 = self.alias_mapping.get(var_name, None)
    # WARNING: Decompyle incomplete

    
    def _track_var_in_expr(self, expr):
        '__pyarmor_enter_54836__(...)'
    # WARNING: Decompyle incomplete

    
    def _track_var_in_callee(self, expr):
        '__pyarmor_enter_54839__(...)'
        _var_var_55 = expr.x.obj_ea
        if _var_var_55 == ida_idaapi.BADADDR:
            pass
    # WARNING: Decompyle incomplete

    
    def _track_var_in_asg(self, expr):
        '__pyarmor_enter_54842__(...)'
        if expr.op != ida_hexrays.cot_asg:
            pass
        else:
            0
            return 0
            if expr.y.op in (ida_hexrays.cot_var, ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_idx, ida_hexrays.cot_memptr, ida_hexrays.cot_memref) and get_final_x(expr.y).op in (ida_hexrays.cot_var, ida_hexrays.cot_obj):
                _var_var_60 = get_final_x(expr.y)
                _var_var_62 = _var_var_60.dstr()
                if _var_var_60.op == ida_hexrays.cot_var and _var_var_62 in self.tracked_vars:
                    _var_var_63 = expr.y.dstr()
                    _var_var_31 = self._find_final_alias(_var_var_62)
                    if _var_var_31 and _var_var_31 != _var_var_62:
                        _var_var_60.v.getv().name = _var_var_31
                        _var_var_63 = expr.y.dstr()
                        _var_var_60.v.getv().name = _var_var_62
                    _var_var_64 = None
                    if expr.x.op in (ida_hexrays.cot_var, ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_idx, ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                        _var_var_64 = expr.x.dstr()
                    if _var_var_64:
                        self.alias_mapping[_var_var_64] = _var_var_63
                        self.tracked_vars.add(_var_var_64)
            if expr.x.op in (ida_hexrays.cot_var, ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_idx, ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                _var_var_60 = get_final_x(expr.x)
                if _var_var_60.op == ida_hexrays.cot_var and _var_var_60.dstr() in self.tracked_vars:
                    _var_var_62 = _var_var_60.dstr()
                    _var_var_64 = expr.x.dstr()
                    _var_var_31 = self._find_final_alias(_var_var_62)
                    if _var_var_31:
                        _var_var_60.v.getv().name = _var_var_31
                        _var_var_64 = expr.x.dstr()
                        _var_var_60.v.getv().name = _var_var_62
                    _var_var_63 = None
                    if expr.y.op in (ida_hexrays.cot_var, ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_idx, ida_hexrays.cot_memptr, ida_hexrays.cot_memref):
                        _var_var_63 = expr.y.dstr()
                    if _var_var_63:
                        self.alias_mapping[_var_var_63] = _var_var_64
                        self.tracked_vars.add(_var_var_63)
        0
        return 0
        '__pyarmor_exit_54843__(...)'
        '__pyarmor_exit_54843__(...)'

    
    def visit_expr(self, expr):
        '__pyarmor_enter_54845__(...)'
        if self.not_trace_callee == False and expr.op == ida_hexrays.cot_call and expr.x.op == ida_hexrays.cot_obj:
            self._track_var_in_callee(expr)
        if expr.op == ida_hexrays.cot_asg:
            self._track_var_in_asg(expr)
        if expr.op in (ida_hexrays.cot_var, ida_hexrays.cot_memptr, ida_hexrays.cot_memref, ida_hexrays.cot_idx, ida_hexrays.cot_ref, ida_hexrays.cot_ptr):
            self._track_var_in_expr(expr)
        '__pyarmor_exit_54846__(...)'
        return 0

    
    def visit_insn(self, insn):
        '__pyarmor_enter_54848__(...)'
        '__pyarmor_exit_54849__(...)'
        return 0

    '__pyarmor_exit_54828__(...)'

'__pyarmor_exit_54741__(...)'
