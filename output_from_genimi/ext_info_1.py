# 文件名: <frozen ..ext_info>
# 模块: <module>

# 假设这些模块已导入或在环境中可用
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
import ida_hexrays # 从 ida_hexrays 导入 decompile, DecompilationFailure
from collections import defaultdict

# 模拟来自其他自定义模块的导入
# from .data_flow import DataFlowAnalyzer # 假设是相对导入
# from .config import settings_manager
# from .checker import parse_var_pred
# from .task_guides import TASK_GUIDES

# 模拟这些不存在的导入，以便代码结构完整
class DataFlowAnalyzer:
    def __init__(self, max_callee_depth, max_caller_depth):
        self.max_callee_depth = max_callee_depth
        self.max_caller_depth = max_caller_depth
        self.analyzed_funcs = set()

    def get_var_dataflow(self, func_ea, var_name=None):
        print(f"[SIMULATED] Getting data flow for {var_name or 'all vars'} in {hex(func_ea)}")
        return "Simulated data flow content."
    
    def filter_data_flow_by_context_func(self, data_flow_str, context_funcs_set):
        print(f"[SIMULATED] Filtering data flow with context funcs: {context_funcs_set}")
        return data_flow_str # 简单返回

class DecompilationFailure(Exception):
    pass

def decompile(ea):
    print(f"[SIMULATED] Decompiling {hex(ea)}")
    if ea == 0xBADBAD: # 模拟无法反编译的情况
        return None
    
    class MockLvar:
        def __init__(self, name, type_str, is_arg):
            self.name = name
            self._type = type_str # 模拟私有属性存储类型字符串
            self._is_arg = is_arg

        def type(self): # 模拟 type() 方法返回 tinfo_t 对象
            ti = ida_typeinf.tinfo_t()
            # 尝试解析类型字符串，这只是一个非常简化的模拟
            if self._type:
                # 移除可能的 ';'
                clean_type = self._type.rstrip(';')
                # 尝试使用 ida_typeinf.parse_decl 来模拟设置类型，如果失败则保持默认
                # 这只是一个示意，实际的类型解析和设置会更复杂
                ida_typeinf.parse_decl(ti, None, f"{clean_type} {self.name};", ida_typeinf.PT_VAR)
            return ti

        def is_arg_var(self):
            return self._is_arg
        
        def set_lvar_type(self, tinfo):
            print(f"[SIMULATED] Setting type for lvar {self.name} to {tinfo.dstr()}")
            self._type = tinfo.dstr() # 更新模拟的类型字符串
            return True

        def rename_lvar(self, new_name, allow_rename):
            print(f"[SIMULATED] Renaming lvar {self.name} to {new_name}")
            self.name = new_name
            return True


    class MockCfunc:
        def __init__(self, ea):
            self.entry_ea = ea
            self.lvars = [MockLvar("arg1", "int", True), MockLvar("var_local", "char *", False)] if ea != 0xBADBAD else []
            self.arguments = [lv for lv in self.lvars if lv.is_arg_var()]

        def get_pseudocode(self):
            return [ida_lines.tag_remove(f"// Pseudocode for {hex(self.entry_ea)}\nvoid func_{hex(self.entry_ea)}(int arg1) {{\n  char* var_local;\n  return;\n}}")]
        
        def refresh_func_ctext(self):
            print(f"[SIMULATED] Refreshing func ctext for {hex(self.entry_ea)}")
            return True
        
        def save_user_cmts(self):
            print(f"[SIMULATED] Saving user comments for {hex(self.entry_ea)}")
            return True

        def set_user_cmt(self, treeloc, comment):
            print(f"[SIMULATED] Setting user comment at {treeloc.ea if treeloc else 'unknown_ea'}:{treeloc.itp if treeloc else 'unknown_itp'} to '{comment}'")
            return True
        
        def get_line_item(self, line_text, a, b, c, d): # 模拟参数
            print(f"[SIMULATED] Getting line item for line: '{line_text}'")
            if "return" in line_text:
                item = ida_hexrays.ctree_item_t()
                item.ea = self.entry_ea + 0x10 # 假设 return 语句的地址
                item.itp = ida_hexrays.ITP_SEMI # 假设是分号后的注释
                return True, item, item, item # 模拟返回
            return False, None, None, None


    return MockCfunc(ea)


# 全局变量/配置 (基于字节码中的常量和名称推断)
MAX_TRACE_CALLER_DEPTH = settings_manager.settings.get('max_trace_caller_depth', 3) # 默认值从类似代码推断
MAX_TRACE_CALLEE_DEPTH = settings_manager.settings.get('max_trace_callee_depth', 3) # 默认值从类似代码推断
MAX_CONTEXT_FUNC_NUM = settings_manager.settings.get('max_context_func_num', 10) # 默认值从类似代码推断
MEASURE_INFO_SCORE = settings_manager.settings.get('measure_info_score', True)    # 默认值从类似代码推断
DATA_FLOW_ANALYSIS_ENABLED = settings_manager.settings.get('data_flow_analysis', True) # 假设的设置

SUPPORT_FUNC_TYPES = set(TASK_GUIDES.keys()) # 任务指南支持的函数类型
DATA_FLOW_TEMPLATE = "<Data-Flow>\nTips: the alias expressions below are used to present the relationship between the local variable and the variable in target function. And the left value of `==` is the local variable and type, the right value is the usage pattern of the variable in target function.\n{}\n</Data-Flow>"
INPUT_TEMPLATE = "<context-pseudocode>\n{context}\n</context-pseudocode>\n<pseudocode>\n{target_func}\n</pseudocode>\n<Call-Chains>\n{call_chains}\n</Call-Chains>\n{data_flow}\nAnalysis Task Tag:\n{task_tag}"

IMPORT_FUNCS = {} # 全局字典，用于存储导入函数信息

MEANINGLESS_NAME_LIST = frozenset({
    'frame_dummy', 'call_weak_fn', '__libc_csu_fini', '__libc_csu_init',
    'register_tm_clones', 'deregister_tm_clones', '__do_global_ctors_aux',
    '__do_global_dtors_aux', '__x86.get_pc_thunk.ax', '__x86.get_pc_thunk.bp',
    '__x86.get_pc_thunk.bx', '__x86.get_pc_thunk.cx', '__x86.get_pc_thunk.di',
    '__x86.get_pc_thunk.dx', '__x86.get_pc_thunk.si'
})

# --- 函数定义 ---

def collect_import_funcs():
    """
    收集所有导入函数的信息并存储到全局 IMPORT_FUNCS 字典中。
    """
    num_modules = idaapi.get_import_module_qty()
    for i in range(num_modules):
        module_name = idaapi.get_import_module_name(i)
        if not module_name:
            print(f"[!] Err: fail to get import module {i} name")
            continue
        
        module_imports = {}
        def imp_cb(ea, name, _ord): # ord 参数在字节码中未使用，但回调通常需要它
            if name: # 确保 name 不是 None 或空字符串
                module_imports.update({ea: [name, module_name]}) # 使用 update 更新字典
            return True # 继续枚举
        
        idaapi.enum_import_names(i, imp_cb)
        IMPORT_FUNCS.update(module_imports)
    return True

collect_import_funcs() # 模块加载时执行

def is_thunk(ea: int) -> bool:
    """
    检查给定地址处的函数是否为 thunk 函数。
    """
    flags = idc.get_func_flags(ea)
    if flags < 0: # 无效函数标志
        return False
    return (flags & ida_funcs.FUNC_THUNK) != 0

def is_thunk_func(func: ida_funcs.func_t) -> bool:
    """
    检查给定的 func_t 对象是否为 thunk 函数。
    """
    if not func: # 确保 func 不是 None
        return False
    flags = func.flags
    if flags < 0: # 无效函数标志 (虽然 func_t.flags 通常不会是 -1，但以防万一)
        return False
    return (flags & ida_funcs.FUNC_THUNK) != 0

def is_import_name(ea: int) -> bool:
    """
    检查给定地址是否为导入函数的名称。
    如果它是 thunk，则解析其目标。
    """
    target_ea = ea
    if is_thunk(ea):
        # calc_thunk_func_target 返回一个元组 (bool success, target_ea)
        # 但字节码直接取了第一个元素作为目标地址
        thunk_target_info = ida_funcs.calc_thunk_func_target(ea)
        if thunk_target_info and len(thunk_target_info) > 0: # 确保元组非空
            potential_target = thunk_target_info[0]
            if potential_target != idaapi.BADADDR:
                target_ea = potential_target
            # else: 如果解析失败，target_ea 保持为原始 ea

    return target_ea in IMPORT_FUNCS

def get_import_name_info(ea: int):
    """
    获取导入函数的名称和库信息。
    如果它是 thunk，则解析其目标。
    """
    target_ea = ea
    if is_thunk(ea):
        thunk_target_info = ida_funcs.calc_thunk_func_target(ea)
        if thunk_target_info and len(thunk_target_info) > 0:
            potential_target = thunk_target_info[0]
            if potential_target != idaapi.BADADDR:
                target_ea = potential_target
    
    if target_ea in IMPORT_FUNCS:
        return IMPORT_FUNCS[target_ea] # 返回 [name, library_name]
    return None

def demangle(name: str, disable_mask = 0) -> str: # disable_mask 默认值从常见用法推断
    """
    对名称进行 demangle 操作。
    """
    demangled_name = idaapi.demangle_name(name, disable_mask, idaapi.DQT_FULL)
    return demangled_name if demangled_name else name

def get_pcode_md5(s: str) -> str:
    """
    计算给定字符串（伪代码）的 MD5 哈希值。
    """
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def get_struc(struct_tid: int) -> ida_typeinf.tinfo_t or idaapi.BADADDR:
    """
    根据结构体类型 ID 获取 tinfo_t 对象。
    """
    ti = ida_typeinf.tinfo_t()
    if ti.get_type_by_tid(struct_tid) and ti.is_struct():
        return ti
    return idaapi.BADADDR # 或者 None，根据后续使用情况，但字节码模式与 get_enum 类似

def get_enum(enum_tid: int) -> ida_typeinf.tinfo_t or idaapi.BADADDR:
    """
    根据枚举类型 ID 获取 tinfo_t 对象。
    """
    ti = ida_typeinf.tinfo_t()
    if ti.get_type_by_tid(enum_tid) and ti.is_enum():
        return ti
    return idaapi.BADADDR

def list_enum_members(name: str) -> str:
    """
    将枚举类型格式化为字符串表示形式。
    """
    result_str = f"enum {name} {{\n"
    idati = ida_typeinf.get_idati()
    enum_tinfo = ida_typeinf.tinfo_t()

    if not enum_tinfo.get_named_type(idati, name, ida_typeinf.BTF_ENUM, True, False):
        result_str += "??\n}" # 如果找不到枚举，返回一个标记
        return result_str

    enum_size = enum_tinfo.get_size()
    header_str = f"enum {name} // sizeof={hex(enum_size)}\n{{\n" # 字节码显示 size 在名称后
    result_str = header_str # 修正：直接使用 header_str 初始化

    etd = ida_typeinf.enum_type_data_t()
    if not enum_tinfo.get_enum_details(etd):
        result_str += "??\n}" # 如果无法获取详情
        return result_str
    
    member_details = ""
    is_bitfield = etd.is_bf()
    
    for i, member_tinfo_ptr in enumerate(etd): # etd 本身是可迭代的
        member_name = member_tinfo_ptr.name if member_tinfo_ptr.name else "?"
        member_value = member_tinfo_ptr.value
        
        # 字节码中有一个复杂的获取成员大小的逻辑，这里简化
        # member_type_info = ida_typeinf.tinfo_t()
        # member_type_size_str = "?"
        # if member_type_info.get_type_by_tid(member_tinfo_ptr.get_tid()):
        #     member_type_size_str = hex(member_type_info.get_size())

        member_details += f"    {member_name} = {hex(member_value)}"
        if is_bitfield: # 字节码中有类似 (bitfield) 的添加逻辑
             member_details += " (bitfield)" # 这只是一个猜测，实际可能更复杂
        member_details += ",\n"
        
    result_str += member_details
    result_str += "}"
    return result_str

class StructUnroller:
    """
    展开结构体类型以供显示或分析。
    """
    def __init__(self, max_depth: int = 3): # 默认 max_depth 从常量推断
        self.structs = {} # 存储已展开的结构体定义
        self.structs_size = {} # 存储结构体大小
        self.MAX_DEPTH = max_depth

    def get_member(self, tif: ida_typeinf.tinfo_t, offset: int) -> ida_typeinf.udm_t or None:
        """
        获取结构体在指定偏移处的成员。
        偏移量是以位（bits）为单位。
        """
        if not tif.is_struct():
            return None
        
        udm = ida_typeinf.udm_t()
        udm.offset = offset * 8 # 字节码显示乘以8，IDA通常以位为单位处理偏移
        
        # STRMEM_OFFSET 似乎是 ida_typeinf.STRMEM_OFFSET
        found_idx = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET) 
        if found_idx != -1:
            return udm
        return None

    def unroll_struct_type(self, struct_type: ida_typeinf.tinfo_t, cur_depth: int = 0) -> str:
        """
        递归地展开结构体类型定义。
        """
        if cur_depth > self.MAX_DEPTH:
            return str(struct_type) # 达到最大深度，直接返回类型字符串

        struct_name_str = str(struct_type)
        struct_id = idc.get_struc_id(struct_name_str)

        if struct_id == idaapi.BADADDR:
            if cur_depth == 0 and struct_type.is_struct(): # 仅在顶层且确实是结构体时尝试创建
                 self.structs[struct_name_str] = [] # 初始化为空列表，表示尚未有成员
            return str(struct_type) # 如果不是已知结构体，返回其字符串表示

        if struct_name_str in self.structs and self.structs[struct_name_str]: # 如果已展开且非空
            return struct_name_str

        struct_size = struct_type.get_size()
        self.structs[struct_name_str] = [] # 标记为正在处理
        self.structs_size[struct_name_str] = struct_size

        declaration = f"struct {struct_name_str} // sizeof={hex(struct_size)}\n{{\n"
        
        members_str_list = []
        for offset, name, size in idautils.StructMembers(struct_id):
            member_udt = self.get_member(struct_type, offset)
            if not member_udt:
                continue

            member_type_tinfo = member_udt.type
            member_type_copy = member_type_tinfo.copy() # 创建副本以进行修改

            type_prefix = ""
            type_suffix = "" # 用于指针
            
            # 处理指针和 const
            while member_type_copy.is_ptr() or member_type_copy.is_const():
                if member_type_copy.is_ptr():
                    type_suffix += " *"
                    member_type_copy.remove_ptr_or_array()
                if member_type_copy.is_const(): # 确保在移除指针后检查
                    type_prefix += "const "
                    member_type_copy.clr_const()
            
            final_type_str = ""
            if member_type_copy.is_struct():
                final_type_str = self.unroll_struct_type(member_type_copy, cur_depth + 1)
            elif member_type_copy.is_enum():
                final_type_str = list_enum_members(member_type_copy.dstr())
            else:
                final_type_str = member_type_copy.dstr() if member_type_copy.dstr() else "?"
            
            full_member_type = type_prefix + final_type_str + type_suffix
            
            # 格式化成员行 (字节码中包含复杂的字符串拼接)
            # 假设每行缩进4个空格，这里用 "    " 模拟
            member_line_parts = ["    "]
            member_line_parts.append(full_member_type)
            member_line_parts.append(" ") # 类型和名称之间的空格
            member_line_parts.append(name if name else f"field_{hex(offset)}")
            member_line_parts.append(f"; // sizeof={hex(size)}")
            members_str_list.append("".join(member_line_parts))

        declaration += "\n".join(members_str_list)
        declaration += "\n}"
        self.structs[struct_name_str] = declaration.split('\n') # 存储为行列表

        return struct_name_str # 返回结构体名称作为引用

def get_structs_enums(var_list) -> dict:
    """
    从变量列表中提取结构体和枚举定义。
    """
    collected_types = {}
    struct_unroller = StructUnroller(max_depth=0) # 字节码中似乎为 get_structs_enums 硬编码了 max_depth=0

    for lvar_details in var_list: # 假设 var_list 是包含变量信息的列表
        # 字节码中，lvar_details 似乎是一个有 'type' 属性的对象
        # 其 'type' 属性又是一个可以调用 .copy() 的对象 (tinfo_t)
        
        current_type_tinfo = lvar_details.type().copy() # 获取类型信息并复制
        original_type_str = str(current_type_tinfo) # 用于字典键

        # 移除指针和 const 以获取基础类型
        # 注意：字节码中的循环条件是 is_ptr OR is_const
        # 但通常处理顺序是先处理指针，再处理 const
        # 并且多次移除指针是可能的，例如 int**
        temp_tinfo_for_base = current_type_tinfo.copy()
        while temp_tinfo_for_base.is_ptr():
            temp_tinfo_for_base.remove_ptr_or_array()
        if temp_tinfo_for_base.is_const(): # 在移除所有指针后再移除 const
            temp_tinfo_for_base.clr_const()
        
        base_type_str = str(temp_tinfo_for_base)

        if temp_tinfo_for_base.is_struct():
            # 字节码似乎在这里调用 struct_unroller.unroll_struct_type
            # unroll_struct_type 内部会填充 struct_unroller.structs
            struct_unroller.unroll_struct_type(temp_tinfo_for_base) # depth 默认为 0
            # 然后将 struct_unroller.structs 的内容（可能是格式化后的字符串）
            # 添加到 collected_types[original_type_str]
            # 字节码显示 _var_var_32[str(_var_var_34)] = _var_var_38.structs
            # _var_var_34