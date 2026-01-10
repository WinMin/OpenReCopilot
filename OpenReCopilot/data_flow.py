import re
import idc
import json # Not explicitly used in visible logic but imported
import ida_hexrays
import ida_funcs
import ida_auto # Not explicitly used
import ida_name
import ida_lines
import ida_idaapi
import ida_xref # Not explicitly used
import idaapi
import idautils
import ida_segment # Not explicitly used
from collections import defaultdict
from termcolor import colored

# --- Global variable for imported functions ---
IMPORT_FUNCS = {}

def collect_import_funcs():
    """
    Populates the global IMPORT_FUNCS dictionary with information about imported functions.
    IMPORT_FUNCS format: {ea: [name, module_name]}
    """
    global IMPORT_FUNCS
    num_modules = idaapi.get_import_module_qty()
    for i in range(num_modules):
        module_name = idaapi.get_import_module_name(i)
        if not module_name:
            print(f"[!] Err: fail to get import module {i} name")
            continue

        current_module_imports = {}
        def imp_cb(ea, name, _ord):
            if name: # Ensure name is not None
                current_module_imports[ea] = [name, module_name]
            return True

        idaapi.enum_import_names(i, imp_cb)
        IMPORT_FUNCS.update(current_module_imports)
    return True

collect_import_funcs() # Initialize on module load

def is_thunk(ea):
    """Checks if the function at ea is a thunk function."""
    flags = idc.get_func_flags(ea)
    return (flags != -1) and (flags & ida_funcs.FUNC_THUNK) != 0

def is_thunk_func(func_t_obj):
    """Checks if the given func_t object is a thunk function."""
    if func_t_obj:
        return (func_t_obj.flags & ida_funcs.FUNC_THUNK) != 0
    return False

def is_import_name(ea):
    """Checks if the name at ea (possibly after resolving thunks) is an import."""
    target_ea = ea
    if is_thunk(ea):
        # calc_thunk_func_target returns a tuple (target_ea, func_t) or None
        thunk_info = ida_funcs.calc_thunk_func_target(ea)
        if thunk_info and thunk_info[0] != idaapi.BADADDR:
            target_ea = thunk_info[0]
        # If thunk target is BADADDR, it might be an unresolved thunk,
        # or the original ea itself is what's in IMPORT_FUNCS for some obscure cases.
        # The original bytecode logic implies falling back to original ea if thunk target is BADADDR.
        # else: target_ea = ea; (implicitly handled by initial assignment)

    return target_ea in IMPORT_FUNCS

def get_import_name_info(ea):
    """Gets import information for ea, resolving thunks."""
    target_ea = ea
    if is_thunk(ea):
        thunk_info = ida_funcs.calc_thunk_func_target(ea)
        if thunk_info and thunk_info[0] != idaapi.BADADDR:
            target_ea = thunk_info[0]

    return IMPORT_FUNCS.get(target_ea)

def find_var_declaration(cfunc, type_name, var_name, is_arg=False):
    """
    Finds the line number and text of a variable declaration in pseudocode.
    """
    if not cfunc:
        return ("??", "VARIABLE DECLARATION STATEMENT")

    escaped_type = re.escape(type_name)
    escaped_var = re.escape(var_name)

    if is_arg:
        # Pattern for arguments in function signature (less strict)
        pattern_str = f".*{escaped_type}\\s+{escaped_var}.*" # Simplified
    else:
        # Pattern for local variable declarations
        pattern_str = f"\\s*{escaped_type}\\s+{escaped_var}(?:\\[[^\\]]*\\])?\\s*;" # Matches type var_name[size];
        # The original bytecode used '[\\[\\]0-9xA-Fa-f]*;.*' which is more complex than needed for typical array decls

    for i, pc_line in enumerate(cfunc.get_pseudocode()):
        line_text = ida_lines.tag_remove(pc_line.line).strip()
        if re.search(pattern_str, line_text): # re.DOTALL might not be necessary for single lines
            return (i, line_text)
    return ("??", "VARIABLE DECLARATION STATEMENT")


def demangle(name, disable_mask=0):
    """Demangles a C++ name."""
    demangled = ida_name.demangle_name(name, disable_mask, ida_name.DQT_FULL)
    return demangled if demangled else name

def get_final_x(cexpr):
    """Recursively gets the base expression by stripping away .x attributes."""
    while hasattr(cexpr, 'x') and cexpr.x:
        cexpr = cexpr.x
    return cexpr

def clear_cast(cexpr):
    """Recursively removes casts, refs, and ptrs from an expression."""
    while cexpr and cexpr.op in (ida_hexrays.cot_cast, ida_hexrays.cot_ref, ida_hexrays.cot_ptr):
        cexpr = cexpr.x
    return cexpr

class VarUsage:
    def __init__(self, var_name, var_type, pcode_line,
                 ori_var_name=None, ori_var_type=None, alias_name=None,
                 usage_type=None, access_type=None, offset=None, # offset wasn't in __init__ args in bytecode for VarUsage but was an attr
                 line_addr=0, func_name=None, context_depth=0): # context_depth default from constants
        self.var_name = var_name
        self.var_type = var_type
        self.pcode_line = pcode_line
        self.ori_var_name = ori_var_name if ori_var_name is not None else var_name
        self.ori_var_type = ori_var_type if ori_var_type is not None else var_type
        self.alias_name = alias_name
        self.usage_type = usage_type # e.g., 'param', 'lvar', 'gvar' - not explicitly set here
        self.access_type = access_type # e.g., 'r', 'w', 'call'
        self.offset = offset
        self.line_addr = line_addr
        self.func_name = func_name
        self.context_depth = context_depth

    def __str__(self):
        pcode_line_str = self.pcode_line.strip() if self.pcode_line else "Get pseudocode line error"
        alias_info = f"// alias: {self.var_type} {self.var_name} == {self.alias_name}" if self.alias_name else ""

        indent = '\t' * abs(self.context_depth if self.context_depth is not None else 0)
        # 处理 line_addr 可能是字符串或整数的情况
        if isinstance(self.line_addr, int) and self.line_addr:
            line_addr_str = hex(self.line_addr)
        elif self.line_addr:
            line_addr_str = str(self.line_addr)
        else:
            line_addr_str = '?'
        return f"{indent}{self.func_name}@L{line_addr_str}| |{pcode_line_str} {alias_info}".strip()

    def colored_print(self):
        pcode_line_str = ""
        if self.pcode_line == "VARIABLE DECLARATION STATEMENT":
            pcode_line_str = colored("VARIABLE DECLARATION STATEMENT", 'red')
        elif self.pcode_line:
            pcode_line_str = self.pcode_line.strip()
        else:
            pcode_line_str = colored("Get pseudocode line error", 'red')

        alias_info = colored(f"// alias: {self.var_type} {self.var_name} == {self.alias_name}", 'green') if self.alias_name else ""
        
        indent = '\t' * abs(self.context_depth if self.context_depth is not None else 0)
        func_part = colored(self.func_name if self.func_name else "?", 'blue')
        # 处理 line_addr 可能是字符串或整数的情况
        if isinstance(self.line_addr, int) and self.line_addr:
            addr_str = hex(self.line_addr)
        elif self.line_addr:
            addr_str = str(self.line_addr)
        else:
            addr_str = '?'
        addr_part = colored(addr_str, 'blue')

        return f"{indent}{func_part}@L{addr_part}| |{pcode_line_str} {alias_info}".strip()

class FunctionContext:
    def __init__(self, func_ea, caller_ea=None):
        self.func_ea = func_ea
        self.caller_ea = caller_ea
        self.var_mappings = {}  # var_in_callee: var_in_caller (or more complex alias)
        self.depth = 0

    def __str__(self):
        return f"Function at {hex(self.func_ea)} called from {hex(self.caller_ea) if self.caller_ea else 'None'}"

class DataFlowAnalyzer:
    def __init__(self, max_trace_callee_depth=None, max_trace_caller_depth=None, limit_funcs=None):
        self.analyzed_funcs = set() # Tracks EAs of analyzed functions to avoid re-analysis / loops
        self.current_cfunc = None   # Current decompiled function (cfunc_t)
        self.usage_lines = []       # List of VarUsage objects
        self.limited_funcs = set(limit_funcs) if limit_funcs else None # Set of EAs to limit analysis to
        self.MAX_TRACE_CALLEE_DEPTH = max_trace_callee_depth if max_trace_callee_depth is not None else 3 # Default
        self.MAX_TRACE_CALLER_DEPTH = max_trace_caller_depth if max_trace_caller_depth is not None else 3 # Default

    def _get_func_args(self, cfunc):
        if cfunc and cfunc.arguments:
            return [arg.name for arg in cfunc.arguments]
        return []

    def _get_pcode_line(self, line_no):
        if self.current_cfunc and 0 <= line_no < len(self.current_cfunc.get_pseudocode()):
            return ida_lines.tag_remove(self.current_cfunc.get_pseudocode()[line_no].line)
        return "Error: Pseudocode line out of bounds or cfunc not set"

    def analyze_function_dataflow_forward(self, func_ea, context=None):
        if context is None:
            context = FunctionContext(func_ea)

        if abs(context.depth) > self.MAX_TRACE_CALLEE_DEPTH:
            return
        if func_ea in self.analyzed_funcs and context.depth !=0: # Avoid re-analyzing non-entry funcs in same path
             return # Simplified loop/recursion break
        if self.limited_funcs and context.depth != 0 and func_ea not in self.limited_funcs:
            return

        func_t = ida_funcs.get_func(func_ea)
        if not func_t: return
        try:
            cfunc = ida_hexrays.decompile(func_t)
        except ida_hexrays.DecompilationFailure:
            return
        if not cfunc: return

        prev_cfunc = self.current_cfunc
        self.current_cfunc = cfunc
        self.analyzed_funcs.add(func_ea)

        tracked_vars_in_callee = set()
        if context.var_mappings:
            tracked_vars_in_callee.update(context.var_mappings.keys())
        else: # If no specific mappings, track all lvars (entry point)
            if cfunc.get_lvars():
                for lvar in cfunc.get_lvars():
                    if lvar.name: tracked_vars_in_callee.add(lvar.name)
        
        alias_map_for_visitor = context.var_mappings if context.var_mappings else {}

        visitor = DataFlowVisitor(self, context, tracked_vars_in_callee, 
                                  alias_mapping=alias_map_for_visitor, not_trace_callee=False)
        visitor.apply_to(cfunc.body, None)
        # Update alias_mapping in context if visitor modified it, for deeper calls
        # context.var_mappings.update(visitor.alias_mapping) # If visitor is allowed to modify

        self.current_cfunc = prev_cfunc


    def analyze_function_dataflow_backward(self, func_ea, context=None):
        if context is None:
            context = FunctionContext(func_ea) # Initial call

        if abs(context.depth) > self.MAX_TRACE_CALLER_DEPTH : # Note: depth becomes negative
            return
        if self.limited_funcs and context.depth != 0 and func_ea not in self.limited_funcs:
            return
        
        func_t = ida_funcs.get_func(func_ea)
        if not func_t: return
        try:
            cfunc = ida_hexrays.decompile(func_t)
        except ida_hexrays.DecompilationFailure:
            return
        if not cfunc: return

        prev_cfunc = self.current_cfunc
        self.current_cfunc = cfunc
        self.analyzed_funcs.add(func_ea) # Mark as analyzed in this path

        tracked_vars_in_current = set()
        # If context has mappings, those are the vars we care about from the callee's perspective
        if context.var_mappings:
            tracked_vars_in_current.update(context.var_mappings.keys())
        else: # Initial call, track all lvars and args
             if cfunc.get_lvars():
                for lvar in cfunc.get_lvars():
                     if lvar.name: tracked_vars_in_current.add(lvar.name)
        
        current_alias_mapping = dict(context.var_mappings) if context.var_mappings else {}

        # Visitor for current function, not tracing into further callees from here
        visitor = DataFlowVisitor(self, context, tracked_vars_in_current,
                                  alias_mapping=current_alias_mapping, not_trace_callee=True)
        visitor.apply_to(cfunc.body, None)
        current_alias_mapping.update(visitor.alias_mapping) # Get any new aliases found

        # Now, find callers and propagate context
        for caller_ref_ea in idautils.CodeRefsTo(func_ea, 1):
            actual_caller_ea = caller_ref_ea
            if is_thunk(caller_ref_ea):
                thunk_info = ida_funcs.calc_thunk_func_target(caller_ref_ea)
                if thunk_info and thunk_info[0] != idaapi.BADADDR:
                    actual_caller_ea = thunk_info[0]
                # else: stay with caller_ref_ea if thunk not resolved well

            if actual_caller_ea == idaapi.BADADDR: continue

            caller_func_t = ida_funcs.get_func(actual_caller_ea)
            if not caller_func_t: continue
            
            try:
                caller_cfunc = ida_hexrays.decompile(caller_func_t)
            except ida_hexrays.DecompilationFailure:
                continue
            if not caller_cfunc: continue

            # Find the specific call expression in caller_cfunc that calls func_ea
            call_site_visitor = self.CallSiteVisitor(func_ea) # Nested class defined below or similar
            call_site_visitor.apply_to(caller_cfunc.body, None)
            call_expr_in_caller = call_site_visitor.call_expr

            if call_expr_in_caller:
                new_context_for_caller = FunctionContext(actual_caller_ea, func_ea) # func_ea is the callee
                new_context_for_caller.depth = context.depth - 1 # Going up the call stack

                # Map arguments from current function (callee) back to caller's expressions
                for arg_idx_in_current, arg_obj_in_current in enumerate(cfunc.arguments):
                    if arg_obj_in_current.name in current_alias_mapping: # If this arg was tracked
                        aliased_var_name_for_caller = current_alias_mapping[arg_obj_in_current.name]
                        
                        if arg_idx_in_current < len(call_expr_in_caller.a):
                            corresponding_arg_expr_in_caller = call_expr_in_caller.a[arg_idx_in_current]
                            
                            # Try to get a variable name or a stable string representation from caller's arg
                            key_for_mapping = ""
                            temp_arg_expr = clear_cast(corresponding_arg_expr_in_caller) # was get_final_x
                            
                            if temp_arg_expr.op == ida_hexrays.cot_var and temp_arg_expr.v:
                                key_for_mapping = temp_arg_expr.v.getv().name
                            elif temp_arg_expr.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref,
                                                   ida_hexrays.cot_ptr, ida_hexrays.cot_ref, ida_hexrays.cot_idx,
                                                   ida_hexrays.cot_add, ida_hexrays.cot_sub): # Heuristic
                                key_for_mapping = temp_arg_expr.dstr()
                                # The original bytecode had a complex string manipulation for cot_cast args.
                                # This part is tricky to get perfectly right without exact original logic.
                                if corresponding_arg_expr_in_caller.op == ida_hexrays.cot_cast:
                                     full_str = corresponding_arg_expr_in_caller.dstr()
                                     inner_str = temp_arg_expr.dstr()
                                     if full_str.endswith(f"({inner_str})"): # Simplified
                                         key_for_mapping = full_str[:-len(f"({inner_str})")-1] + key_for_mapping
                                     elif full_str.startswith(f"({inner_str})"):
                                         key_for_mapping += full_str[len(f"({inner_str})"):]


                            if key_for_mapping:
                                new_context_for_caller.var_mappings[key_for_mapping] = aliased_var_name_for_caller
                
                if new_context_for_caller.var_mappings:
                    self.analyze_function_dataflow_backward(caller_func_t.start_ea, new_context_for_caller)
        
        self.current_cfunc = prev_cfunc

    class CallSiteVisitor(ida_hexrays.ctree_visitor_t): # Nested for brevity
        def __init__(self, target_ea):
            super().__init__(ida_hexrays.CV_FAST) # Original used CV_FAST
            self.target_ea = target_ea
            self.call_expr = None

        def visit_expr(self, expr):
            if self.call_expr: return 0 # Found, stop
            if expr.op == ida_hexrays.cot_call:
                # Check if expr.x (the function being called) resolves to target_ea
                obj = expr.x
                if obj.op == ida_hexrays.cot_obj and obj.obj_ea == self.target_ea:
                    self.call_expr = expr
                    return 1 # Stop visiting
            return 0


    def get_var_dataflow(self, func_ea, var_name_or_list, verbose=False): # verbose default based on bytecode
        self.analyzed_funcs.clear()
        self.usage_lines.clear()

        initial_context = FunctionContext(func_ea)
        
        if isinstance(var_name_or_list, str):
            initial_context.var_mappings = {var_name_or_list: var_name_or_list}
        elif isinstance(var_name_or_list, list):
            initial_context.var_mappings = {v: v for v in var_name_or_list}
        elif var_name_or_list is None:
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if not cfunc: return "Error: Could not decompile function."
                lvars = cfunc.get_lvars()
                if not lvars: return f"No local variables or arguments found in the func_ea: {hex(func_ea)}"
                initial_context.var_mappings = {lv.name: lv.name for lv in lvars if lv.name}
            except ida_hexrays.DecompilationFailure:
                 return f"Decompilation failed for {hex(func_ea)}"
        else:
            raise ValueError(f"Invalid var_name_or_list: {var_name_or_list}")

        if not initial_context.var_mappings:
             return f"No variables to track for {hex(func_ea)}"

        self.analyze_function_dataflow_forward(func_ea, initial_context)
        # Reset for backward pass, or use a new context if needed
        # For simplicity, reusing context means backward pass starts with original var_mappings
        self.analyzed_funcs.clear() # Allow re-analysis for backward pass starting from same func
        self.analyze_function_dataflow_backward(func_ea, initial_context)

        # --- Formatting output (simplified) ---
        # The original code has complex grouping and sorting logic for presentation
        unique_usages_dict = {} # Key: (func_name, line_addr, pcode_line, alias_name, var_name) Value: VarUsage
        for usage in self.usage_lines:
            key = (usage.func_name, usage.line_addr, usage.pcode_line, usage.alias_name, usage.var_name)
            if key not in unique_usages_dict: # Keep first encountered, or based on some logic
                unique_usages_dict[key] = usage
        
        # 排序时确保 line_addr 是整数类型
        def get_sort_key(u):
            func_name = u.func_name or ""
            line_addr = u.line_addr
            # 确保 line_addr 是整数用于排序
            if isinstance(line_addr, str):
                line_addr = 0
            elif line_addr is None:
                line_addr = 0
            return (func_name, line_addr)

        sorted_unique_usages = sorted(list(unique_usages_dict.values()), key=get_sort_key)

        # Store results for callee and caller trace based on context_depth
        callee_results = [] # context_depth >= 0
        caller_results = [] # context_depth < 0

        for usage in sorted_unique_usages:
            depth = usage.context_depth if usage.context_depth is not None else 0
            if verbose:
                # The original groups by (func_name, line_addr, pcode_line) and appends alias info
                # This is a simplified representation
                formatted_str = usage.colored_print() # if verbose
                if depth >= 0: callee_results.append(formatted_str)
                else: caller_results.append(formatted_str)
            else:
                formatted_str = str(usage)
                if depth >= 0: callee_results.append(formatted_str)
                else: caller_results.append(formatted_str)
        
        target_func_name = demangle(idc.get_func_name(func_ea))
        tracked_vars_str = ", ".join(initial_context.var_mappings.keys())

        final_str = f"==== final usages for traced variable: `{tracked_vars_str}` in `{target_func_name}` ====\n"
        final_str += "---- trace callee usages ----\n"
        final_str += "\n".join(callee_results)
        final_str += "\n\n---- trace caller usages ----\n"
        final_str += "\n".join(caller_results)
        final_str += "\n" + ("=" * 40) + "\n"
        
        if verbose:
            print(final_str) # In verbose mode, the original prints detailed lines as they are processed too.
        
        return final_str

    def filter_data_flow_by_context_func(self, original_data_flow_str, context_funcs_eas):
        # This function in the original seems to re-filter `self.usage_lines`
        # based on `context_funcs_eas` and then re-generates the string output.
        # It does not directly parse `original_data_flow_str`.

        demangled_context_func_names = set()
        if context_funcs_eas:
            for ea in context_funcs_eas:
                name = ida_funcs.get_func_name(ea)
                if name:
                    demangled_context_func_names.add(demangle(name))
        
        filtered_usages = []
        for usage in self.usage_lines: # Assuming usage_lines is still populated
            if usage.func_name in demangled_context_func_names:
                filtered_usages.append(usage)
        
        # Re-format output based on filtered_usages (similar to get_var_dataflow's formatting part)
        # ... (omitting repetitive formatting logic for brevity) ...
        # For simplicity, let's just return a placeholder for the re-formatted string
        if not filtered_usages:
            return "No data flow found within the specified context functions."

        # Re-use parts of get_var_dataflow's string building
        callee_results = []
        caller_results = []
        # Group and sort filtered_usages
        unique_filtered_usages = {}
        for usage in filtered_usages:
            key = (usage.func_name, usage.line_addr, usage.pcode_line, usage.alias_name, usage.var_name)
            if key not in unique_filtered_usages:
                 unique_filtered_usages[key] = usage
        
        # 排序时确保 line_addr 是整数类型
        def get_filter_sort_key(u):
            func_name = u.func_name or ""
            line_addr = u.line_addr
            if isinstance(line_addr, str):
                line_addr = 0
            elif line_addr is None:
                line_addr = 0
            return (func_name, line_addr)

        sorted_filtered_usages = sorted(list(unique_filtered_usages.values()), key=get_filter_sort_key)

        for usage in sorted_filtered_usages:
            depth = usage.context_depth if usage.context_depth is not None else 0
            formatted_str = str(usage) # Non-verbose for simplicity here
            if depth >= 0: callee_results.append(formatted_str)
            else: caller_results.append(formatted_str)

        # Assuming original_data_flow_str's header is somewhat generic
        header = original_data_flow_str.split("====")[0] + "==== (Filtered) ===="
        
        final_str = header + "\n"
        final_str += "---- trace callee usages ----\n"
        final_str += "\n".join(callee_results)
        final_str += "\n\n---- trace caller usages ----\n"
        final_str += "\n".join(caller_results)
        final_str += "\n" + ("=" * 40) + "\n"
        return final_str


class DataFlowVisitor(ida_hexrays.ctree_visitor_t):
    def __init__(self, analyzer: DataFlowAnalyzer, context: FunctionContext,
                 tracked_vars: set, alias_mapping: dict = None, not_trace_callee: bool = False):
        super().__init__(ida_hexrays.CV_PARENTS | ida_hexrays.CV_FAST | ida_hexrays.CV_PRUNE)
        self.analyzer = analyzer
        self.context = context
        self.tracked_vars = set(tracked_vars) # Ensure it's a mutable set
        self.alias_mapping = dict(alias_mapping) if alias_mapping is not None else {}
        self.usage_lines = defaultdict(list) # Stores VarUsage objects, keyed by original var name
        
        self.current_func_ea = analyzer.current_cfunc.entry_ea
        self.current_func_name = demangle(ida_funcs.get_func_name(self.current_func_ea))
        self.not_trace_callee = not_trace_callee # If true, don't trace into callees

        # Initial variable declarations
        if analyzer.current_cfunc and analyzer.current_cfunc.get_lvars():
            for lvar in analyzer.current_cfunc.get_lvars():
                if lvar.name and lvar.name in self.tracked_vars:
                    var_type_str = lvar.type().dstr()
                    
                    # Handle array types correctly for declaration pattern
                    # temp_type_for_decl = lvar.type().copy() # Avoid modifying original
                    # if temp_type_for_decl.is_array():
                    #     while temp_type_for_decl.is_array() and temp_type_for_decl.remove_ptr_or_array():
                    #         pass # Strip array dimensions for base type string
                    #     var_type_str_for_decl = temp_type_for_decl.dstr()
                    # else:
                    var_type_str_for_decl = var_type_str

                    line_no, pcode_decl_str = find_var_declaration(
                        analyzer.current_cfunc,
                        var_type_str_for_decl, # Use potentially stripped type for regex
                        lvar.name,
                        is_arg=lvar.is_arg_var
                    )
                    alias = self.alias_mapping.get(lvar.name) # Check if it's already an alias from context

                    usage = VarUsage(var_name=lvar.name, var_type=var_type_str,
                                     pcode_line=pcode_decl_str,
                                     access_type="decl", alias_name=alias,
                                     line_addr=line_no, # This should be actual EA if possible
                                     func_name=self.current_func_name,
                                     context_depth=self.context.depth)
                    self.usage_lines[lvar.name].append(usage)
                    self.analyzer.usage_lines.append(usage)


    def _find_final_alias(self, var_name):
        """ Follows the alias chain to find the original variable name."""
        seen = {var_name}
        current_alias = self.alias_mapping.get(var_name)
        while current_alias and current_alias != var_name and current_alias not in seen:
            seen.add(current_alias)
            var_name = current_alias
            current_alias = self.alias_mapping.get(var_name)
        return var_name

    def _track_var_in_expr(self, expr: ida_hexrays.cexpr_t):
        """Tracks a variable usage in a non-assignment, non-call context."""
        var_name_str = None
        var_type_str = ""
        is_complex_expr = False

        temp_expr = expr
        if temp_expr.op == ida_hexrays.cot_var and temp_expr.v:
            var_name_str = temp_expr.v.getv().name
            var_type_str = temp_expr.v.getv().type().dstr()
        elif temp_expr.op in (ida_hexrays.cot_memptr, ida_hexrays.cot_memref,
                              ida_hexrays.cot_idx, ida_hexrays.cot_ref, ida_hexrays.cot_ptr):
            var_name_str = temp_expr.dstr() # Track the complex expression string as a "name"
            var_type_str = temp_expr.type.dstr() if hasattr(temp_expr, 'type') else "" # type of the expression
            is_complex_expr = True
        
        if not var_name_str or var_name_str not in self.tracked_vars:
            return 0

        # Determine access type (r, w, call)
        access = 'r' # Default for simple usage
        parent_idx = 0
        while parent_idx < len(self.parents) and self.parents.at(parent_idx):
            parent_expr = self.parents.at(parent_idx).cexpr
            if parent_expr.op == ida_hexrays.cot_asg:
                # If current expr is on the LHS of assignment (final target)
                # Note: clear_cast might be needed for robust LHS check
                final_lhs_target = get_final_x(parent_expr.x) # simplify LHS
                if final_lhs_target == expr or (hasattr(final_lhs_target, 'dstr') and final_lhs_target.dstr() == var_name_str):
                     access = 'w'
                break 
            if parent_expr.op == ida_hexrays.cot_call:
                access = '(call)' # Variable is part of a call (either as arg or func pointer)
                break
            parent_idx += 1

        # find_item_coords returns bool, coords are returned via pointer parameters
        y_holder = idaapi.int_pointer()
        x_holder = idaapi.int_pointer()
        coords_found = self.analyzer.current_cfunc.find_item_coords(expr, x_holder, y_holder)
        if coords_found:
            line_no = y_holder.value()
            pcode_line = self.analyzer._get_pcode_line(line_no)
            # Use line number as item_ea since we don't have direct EA access
            item_ea = line_no

            final_alias = self._find_final_alias(var_name_str)

            usage = VarUsage(var_name=var_name_str, var_type=var_type_str,
                             pcode_line=pcode_line,
                             access_type=access,
                             alias_name=final_alias if final_alias != var_name_str else None,
                             line_addr=item_ea, # or coords.ea
                             func_name=self.current_func_name,
                             context_depth=self.context.depth)
            self.usage_lines[var_name_str].append(usage)
            self.analyzer.usage_lines.append(usage)
        return 0

    def _track_var_in_callee(self, call_expr: ida_hexrays.cexpr_t):
        if not call_expr.x or call_expr.x.op != ida_hexrays.cot_obj:
            return 0
        
        callee_ea = call_expr.x.obj_ea
        if callee_ea == idaapi.BADADDR or is_thunk(callee_ea) or is_import_name(callee_ea):
            return 0

        callee_func_t = ida_funcs.get_func(callee_ea)
        if not callee_func_t: return 0
        try:
            callee_cfunc = ida_hexrays.decompile(callee_func_t)
        except ida_hexrays.DecompilationFailure:
            return 0
        if not callee_cfunc: return 0

        new_context_for_callee = FunctionContext(callee_ea, self.current_func_ea)
        new_context_for_callee.depth = self.context.depth + 1
        
        made_a_mapping = False
        for arg_idx, arg_expr_in_caller in enumerate(call_expr.a):
            if arg_idx >= len(callee_cfunc.arguments): continue

            # Determine the key for mapping: either a var name or a string repr of complex arg
            arg_key_in_caller = ""
            temp_arg_expr = clear_cast(arg_expr_in_caller)
            
            if temp_arg_expr.op == ida_hexrays.cot_var and temp_arg_expr.v:
                arg_key_in_caller = temp_arg_expr.v.getv().name
                if arg_key_in_caller in self.tracked_vars:
                    final_alias = self._find_final_alias(arg_key_in_caller)
                    # Map callee_param_name to (caller_arg_name or its alias)
                    callee_param_name = callee_cfunc.arguments[arg_idx].name
                    
                    # Heuristic for representing the source in caller
                    caller_source_repr = arg_key_in_caller
                    if final_alias and final_alias != arg_key_in_caller:
                        caller_source_repr = f"{arg_key_in_caller}({final_alias})"
                    
                    # If the argument expression itself was more complex than just a var
                    arg_expr_str = arg_expr_in_caller.dstr() # Full expression as passed
                    if arg_expr_str != arg_key_in_caller : # It was casted or part of something
                         # The original bytecode had a complex string reconstruction here.
                         # This is a simplification.
                         cleaned_arg_expr_str = arg_expr_str
                         if arg_expr_in_caller.op == ida_hexrays.cot_cast:
                             cleaned_arg_expr_str = arg_expr_str[1:arg_expr_str.rfind(')')] # strip outer cast like
                         
                         if cleaned_arg_expr_str != arg_key_in_caller:
                              caller_source_repr = f"{cleaned_arg_expr_str} -> {caller_source_repr}"


                    new_context_for_callee.var_mappings[callee_param_name] = caller_source_repr
                    made_a_mapping = True
                    self._track_var_in_expr(temp_arg_expr) # Track usage of the var in the call itself

            # Simplified: if it's a complex expr that we are tracking as an alias directly
            elif arg_expr_in_caller.dstr() in self.tracked_vars:
                complex_arg_str = arg_expr_in_caller.dstr()
                final_alias = self._find_final_alias(complex_arg_str)
                callee_param_name = callee_cfunc.arguments[arg_idx].name
                new_context_for_callee.var_mappings[callee_param_name] = final_alias if final_alias else complex_arg_str
                made_a_mapping = True
                self._track_var_in_expr(arg_expr_in_caller)


        if made_a_mapping or not self.tracked_vars : # if no specific tracked vars, explore all paths initially
            self.analyzer.analyze_function_dataflow_forward(callee_ea, new_context_for_callee)
        return 0

    def _track_var_in_asg(self, expr: ida_hexrays.cexpr_t):
        lhs_expr = expr.x
        rhs_expr = expr.y

        # RHS processing: if RHS is a tracked var, LHS becomes an alias
        final_rhs_var = get_final_x(rhs_expr)
        rhs_is_tracked_var = False
        rhs_var_name_str = ""
        original_rhs_name_for_alias = ""

        if final_rhs_var.op == ida_hexrays.cot_var and final_rhs_var.v:
            rhs_var_name_str = final_rhs_var.v.getv().name
            if rhs_var_name_str in self.tracked_vars:
                rhs_is_tracked_var = True
                original_rhs_name_for_alias = self._find_final_alias(rhs_var_name_str)
        elif final_rhs_var.dstr() in self.tracked_vars: # RHS is a complex expr string we track
            rhs_var_name_str = final_rhs_var.dstr()
            rhs_is_tracked_var = True
            original_rhs_name_for_alias = self._find_final_alias(rhs_var_name_str)


        if rhs_is_tracked_var:
            final_lhs_target = get_final_x(lhs_expr)
            if final_lhs_target.op == ida_hexrays.cot_var and final_lhs_target.v:
                lhs_var_name_str = final_lhs_target.v.getv().name
                if lhs_var_name_str != original_rhs_name_for_alias: # Avoid self-alias if already final
                    self.alias_mapping[lhs_var_name_str] = original_rhs_name_for_alias
                    self.tracked_vars.add(lhs_var_name_str) # Start tracking the new alias
            elif final_lhs_target.dstr(): # LHS is complex
                lhs_expr_str = final_lhs_target.dstr()
                if lhs_expr_str != original_rhs_name_for_alias:
                    self.alias_mapping[lhs_expr_str] = original_rhs_name_for_alias
                    self.tracked_vars.add(lhs_expr_str)


        # LHS processing: if LHS is a tracked var, RHS might become an alias (less common for data flow)
        # Or, more importantly, RHS's components are now associated with LHS's data flow.
        final_lhs_var = get_final_x(lhs_expr)
        lhs_is_tracked_var = False
        lhs_var_name_str = ""
        original_lhs_name_for_alias = ""

        if final_lhs_var.op == ida_hexrays.cot_var and final_lhs_var.v:
            lhs_var_name_str = final_lhs_var.v.getv().name
            if lhs_var_name_str in self.tracked_vars:
                lhs_is_tracked_var = True
                original_lhs_name_for_alias = self._find_final_alias(lhs_var_name_str)
        elif final_lhs_var.dstr() in self.tracked_vars:
            lhs_var_name_str = final_lhs_var.dstr()
            lhs_is_tracked_var = True
            original_lhs_name_for_alias = self._find_final_alias(lhs_var_name_str)

        if lhs_is_tracked_var:
            # If RHS is a simple var, it becomes an alias for LHS's original flow
            if final_rhs_var.op == ida_hexrays.cot_var and final_rhs_var.v:
                rhs_simple_var_name = final_rhs_var.v.getv().name
                if rhs_simple_var_name != original_lhs_name_for_alias:
                    self.alias_mapping[rhs_simple_var_name] = original_lhs_name_for_alias
                    self.tracked_vars.add(rhs_simple_var_name)
            elif final_rhs_var.dstr(): # RHS is complex
                rhs_expr_str = final_rhs_var.dstr()
                if rhs_expr_str != original_lhs_name_for_alias:
                     self.alias_mapping[rhs_expr_str] = original_lhs_name_for_alias
                     self.tracked_vars.add(rhs_expr_str)
            
            # Track components of RHS as reads contributing to LHS
            # This requires recursively visiting parts of rhs_expr
            # For simplicity, we call _track_var_in_expr on rhs_expr as a whole.
            # A more granular approach would be to create a new visitor for rhs_expr.
            self._track_var_in_expr(rhs_expr)


        # Also track the LHS and RHS themselves as usages if they are vars
        self._track_var_in_expr(lhs_expr) # as a 'w' (write) usage (handled by _track_var_in_expr logic)
        # self._track_var_in_expr(rhs_expr) # as an 'r' (read) usage (handled by _track_var_in_expr logic)
        return 0


    def visit_expr(self, expr: ida_hexrays.cexpr_t):
        if self.not_trace_callee is False and \
           expr.op == ida_hexrays.cot_call and \
           expr.x and expr.x.op == ida_hexrays.cot_obj:
            self._track_var_in_callee(expr)

        elif expr.op == ida_hexrays.cot_asg:
            self._track_var_in_asg(expr)
            
        elif expr.op in (ida_hexrays.cot_var, ida_hexrays.cot_memptr,
                         ida_hexrays.cot_memref, ida_hexrays.cot_idx,
                         ida_hexrays.cot_ref, ida_hexrays.cot_ptr):
            self._track_var_in_expr(expr)
            
        return 0 # Continue traversal

    def visit_insn(self, insn: ida_hexrays.cinsn_t):
        return 0 # Continue traversal, expressions are primary focus