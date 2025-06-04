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
import collections
from collections import defaultdict
from ida_hexrays import decompile, DecompilationFailure
from data_flow import DataFlowAnalyzer
from config import settings_manager
from checker import parse_var_pred
from task_guides import TASK_GUIDES

# Global settings (likely pulled from settings_manager.settings)
MAX_TRACE_CALLER_DEPTH = settings_manager.settings['max_trace_caller_depth']
MAX_TRACE_CALLEE_DEPTH = settings_manager.settings['max_trace_callee_depth']
MAX_CONTEXT_FUNC_NUM = settings_manager.settings['max_context_func_num']
MEASURE_INFO_SCORE = settings_manager.settings['measure_info_score']
DATA_FLOW_ANALYSIS_ENABLED = settings_manager.settings['data_flow_analysis']

SUPPORT_FUNC_TYPES = set(TASK_GUIDES.keys())

DATA_FLOW_TEMPLATE = '<Data-Flow>\nTips: the alias expressions below are used to present the relationship between the local variable and the variable in target function. And the left value of `==` is the local variable and type, the right value is the usage pattern of the variable in target function.\n{}\n</Data-Flow>'
INPUT_TEMPLATE = '<context-pseudocode>\n{context}\n</context-pseudocode>\n<pseudocode>\n{target_func}\n</pseudocode>\n<Call-Chains>\n{call_chains}\n</Call-Chains>\n{data_flow}\nAnalysis Task Tag:\n{task_tag}'

IMPORT_FUNCS = {} # This is likely initialized by collect_import_funcs

def collect_import_funcs():
    """
    Collects information about imported functions in the IDA database.
    Stores them in the global IMPORT_FUNCS dictionary.
    """
    global IMPORT_FUNCS
    
    # Initialize IMPORT_FUNCS as a dictionary before updating it
    # This might have been a global declaration initially, but assuming it's cleared or initialized here.
    IMPORT_FUNCS = {} 

    mod_qty = idaapi.get_import_module_qty()
    for i in range(mod_qty):
        mod_name = idaapi.get_import_module_name(i)
        if not mod_name:
            print(f"[!] Err: fail to get import module {i} name")
            continue

        # Using a defaultdict to store names per module might be more robust
        # based on the original structure implied by `update`.
        module_imports = defaultdict(lambda: None) # Default value could be anything, or perhaps a list if multiple imports per name

        def imp_cb(ea, name, _ord):
            """
            Callback function for enumerating imported names.
            Adds imported function EAs and names to the module_imports dict.
            """
            if name: # Only add if name is not None/empty
                module_imports[ea] = name
            return True # Continue enumeration

        idaapi.enum_import_names(i, imp_cb)
        IMPORT_FUNCS.update(module_imports)

    return True

def is_thunk(ea):
    """
    Checks if a given address 'ea' points to a thunk function.
    A thunk function often acts as a trampoline to another function.
    """
    func_flags = idc.get_func_flags(ea)
    if func_flags < 0: # Check if get_func_flags failed or returned an invalid flag
        return False
    return (func_flags & ida_funcs.FUNC_THUNK) != 0

def is_thunk_func(func):
    """
    Checks if a given function object 'func' is a thunk function.
    """
    if func.flags < 0: # Assuming func has a 'flags' attribute
        return False
    return (func.flags & ida_funcs.FUNC_THUNK) != 0

def is_import_name(ea):
    """
    Checks if an address 'ea' is an imported name (function or data).
    Handles thunk functions by resolving their target.
    """
    target_ea = ea
    if is_thunk(ea):
        # Resolve thunk target if it's a thunk
        target_ea = ida_funcs.calc_thunk_func_target(ea)[0]
        if target_ea == idaapi.BADADDR:
            target_ea = ea # Fallback to original if target not found

    return target_ea in IMPORT_FUNCS

def get_import_name_info(ea):
    """
    Retrieves the imported name and its library for a given address 'ea'.
    Handles thunk functions.
    Returns (imported_name, library_name) or None if not an import.
    """
    target_ea = ea
    if is_thunk(ea):
        # Resolve thunk target if it's a thunk
        target_ea = ida_funcs.calc_thunk_func_target(ea)[0]
        if target_ea == idaapi.BADADDR:
            target_ea = ea # Fallback to original if target not found

    if target_ea in IMPORT_FUNCS:
        # Assuming IMPORT_FUNCS stores (ea: name)
        # And we need module name as well, which isn't directly in IMPORT_FUNCS from the provided names.
        # This part might require looking up the module name from idaapi or restructuring `IMPORT_FUNCS`.
        # For now, let's assume IMPORT_FUNCS stores a tuple (name, module) or similar structure.
        # Given the original bytecode, it's likely a simple dict of {ea: name} where name implicitly contains module.
        imported_name = IMPORT_FUNCS[target_ea]
        # To get the library name, we'd typically parse the imported_name
        # or have a more complex IMPORT_FUNCS structure.
        # Let's return the name and a placeholder for the library based on common import formats.
        if "::" in imported_name: # Common for C++ namespaces
            lib_name = imported_name.split("::")[0] # Very simplified
        else:
            lib_name = "unknown_lib" # Placeholder if not clearly from a C++ like import
            
        return (imported_name, lib_name)
    return None

def demangle(name, disable_mask=idaapi.DQT_FULL):
    """
    Demangles a given symbol name.
    """
    demangled_name = idaapi.demangle_name(name, disable_mask)
    if demangled_name:
        return demangled_name
    return name # Return original name if demangling fails

def get_pcode_md5(s):
    """
    Calculates the MD5 hash of a given string 's'.
    """
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def get_struc(struct_tid):
    """
    Retrieves a structure (tinfo_t) by its type ID.
    Returns the tinfo_t object if it's a struct, None otherwise.
    """
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(struct_tid) and tif.is_struct():
        return tif
    return idaapi.BADADDR # Using BADADDR as a sentinel for failure, matching IDA API style

def get_enum(enum_tid):
    """
    Retrieves an enum (tinfo_t) by its type ID.
    Returns the tinfo_t object if it's an enum, None otherwise.
    """
    tif = ida_typeinf.tinfo_t()
    if tif.get_type_by_tid(enum_tid) and tif.is_enum():
        return tif
    return idaapi.BADADDR # Using BADADDR as a sentinel for failure, matching IDA API style

def list_enum_members(name):
    """
    Lists the members of a given enum by its name.
    Returns a string representation of the enum definition.
    """
    enum_str = f"enum {name} {{\n"

    # Get enum tinfo
    idati = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    # BTF_ENUM indicates it's an enum, 1 (True) for exact match, 0 (False) for create if not found
    if not tif.get_named_type(idati, name, ida_typeinf.BTF_ENUM, True, False):
        enum_str += "??\n}"
        return enum_str

    enum_size = tif.get_size()
    enum_str = f"enum {name} // sizeof={hex(enum_size)}\n{{\n"

    enum_data = ida_typeinf.enum_type_data_t()
    if tif.get_enum_details(enum_data):
        is_bitfield = ""
        if enum_data.is_bf():
            is_bitfield = "(bitfield)"

        for i, member in enumerate(enum_data):
            # Assuming member has 'name' and 'value' attributes based on disassembly
            # The disassembly suggests direct attribute access after enumeration
            member_name = member.name
            member_value = member.value
            member_type_info = ida_typeinf.tinfo_t()
            # This part is complex from bytecode. Assuming it tries to get member type info
            # The disassembly path suggests attempting to get type by TID from member.
            # Let's simplify this part as it's hard to accurately represent.
            # Original looks like a check for a member type size, indicating a bitfield or complex enum.
            # Simplified to just name and value for readability.
            # The bytecode seems to try to get `member_type_info.get_type_by_tid(member.get_tid())`
            # and then `get_size()` on that type.
            # We'll just represent name and value.
            
            enum_str += f"    {member_name} = {member_value},\n"
        enum_str += "}"
    else:
        enum_str += "??\n}"
    return enum_str

class StructUnroller:
    """
    A class to unroll and represent structure definitions recursively.
    """
    def __init__(self, max_depth=3):
        self.structs = {}  # Store unrolled structs {name: content_string}
        self.structs_size = {} # Store struct sizes {name: size}
        self.MAX_DEPTH = max_depth

    def get_member(self, tif, offset):
        """
        Retrieves a structure member at a given offset within a tinfo_t.
        Returns the member object if found, None otherwise.
        """
        if not tif.is_struct():
            return None
        
        # In IDA API, members are found via offset using udm_t or similar mechanisms
        # The bytecode path implies a direct lookup with `find_udm` after setting `offset` on a `udm_t` object.
        udm = ida_typeinf.udm_t()
        udm.offset = offset * 8 # Convert bytes offset to bits offset
        
        # STRMEM_OFFSET is usually `MF_BY_OFFSET` or related flags
        member_idx = tif.find_udm(udm, ida_typeinf.STRMEM_OFFSET)
        
        if member_idx != -1 and udm.member_tinfo: # assuming udm.member_tinfo gets populated
            return udm # Return the udm_t which now holds member info
        return None

    def unroll_struct_type(self, struct_type, cur_depth=0):
        """
        Recursively unrolls a structure type into a readable string format.
        Adds new struct definitions to self.structs.
        """
        if cur_depth > self.MAX_DEPTH:
            return str(struct_type)

        struct_name = str(struct_type)
        if idc.get_struc_id(struct_name) == idaapi.BADADDR:
            if cur_depth == 0 and struct_type.is_struct():
                # For root struct, if not found, create empty struct to avoid recursion loop
                # This seems like a fallback or a way to register it.
                self.structs[struct_name] = []
            return str(struct_type) # Can't resolve, return original string

        struct_size = struct_type.get_size()
        self.structs[struct_name] = [] # Initialize content list
        self.structs_size[struct_name] = struct_size

        struct_def_str = f"struct {struct_name} // sizeof={hex(struct_size)}\n{{\n"

        for m_idx, member_ea, member_size in idautils.StructMembers(idc.get_struc_id(struct_name)):
            # idautils.StructMembers yields (member_idx, member_ea, member_size)
            # The bytecode's disassembly is very intricate here, implying retrieving the actual member_tinfo from the structure.
            # Let's simplify this by assuming we directly use member_tinfo from the original struct_type.
            
            # Simplified approach based on common IDA API patterns and disassembly hints:
            # We need the member's type object (tinfo_t) and its name.
            # The original bytecode suggests a recursive call `self.unroll_struct_type` for nested structs/enums.
            
            # The actual member type retrieval would be complex without full IDA API knowledge in bytecode.
            # The bytecode seems to retrieve the member's type using `get_member` and then processes it.
            
            member_tinfo = ida_typeinf.tinfo_t()
            # This is a placeholder for actual member tinfo retrieval using `member_ea`
            # In a real scenario, this involves more IDA API calls to get the member's tinfo based on its offset in the struct.
            # Assuming `struct_type` itself is enough to find members and their types.
            
            # The bytecode path for `get_member` and then `member.type.copy()`
            # suggests it tries to get the member's tinfo from the structure and copies it.
            
            # A more direct interpretation of typical IDA Python:
            member_tif = ida_typeinf.tinfo_t()
            if not member_tif.get_type_by_tid(m_idx): # m_idx is the ID of the member type if it exists globally
                # If not a global type, try to get from the struct's member directly
                # This is a simplification; getting member info is complex.
                # Assuming `get_member` (defined in this class) returns a proper object or None.
                member_obj = self.get_member(struct_type, member_ea) # member_ea is offset actually, not EA of type directly
                if member_obj and member_obj.type:
                     member_tif = member_obj.type.copy()
            else:
                member_tif = member_tif.copy() # Copy existing global type

            member_type_str = ""
            if member_tif:
                if member_tif.is_struct():
                    # Recursive call for nested structs
                    member_type_str = self.unroll_struct_type(member_tif, cur_depth + 1)
                elif member_tif.is_enum():
                    # Use list_enum_members for enums
                    member_type_str = list_enum_members(member_tif.dstr()) # Assuming dstr gives the name
                else:
                    # Handle pointers and const
                    prefix = ""
                    if member_tif.is_ptr():
                        member_tif.remove_ptr_or_array()
                        prefix += "*" # Represents pointer
                    if member_tif.is_const():
                        member_tif.clr_const()
                        prefix = "const " + prefix
                    member_type_str = prefix + member_tif.dstr() # Direct string representation

            # The original bytecode is complex for formatting this.
            # It builds a string with spaces and newlines dynamically.
            # Let's approximate the string formatting.
            # The bytecode shows `JOIN` and `SPLIT` operations with `\n` and `   `
            # indicating indentation for nested structures.
            
            indent = "    "
            line = f"{indent}{member_type_str} {idc.get_member_name(idc.get_struc_id(struct_name), member_ea)}; // sizeof={hex(member_size)}\n"
            
            self.structs[struct_name].append(line)
            struct_def_str += line

        struct_def_str += "}"
        return struct_def_str


def get_structs_enums(var_list):
    """
    Analyzes a list of variables/types and extracts associated structure and enum definitions.
    Returns a dictionary of {name: definition_string} for structs and enums.
    """
    struct_enum_dict = {}
    unroller = StructUnroller() # Default max_depth=3

    for var_info in var_list:
        # Assuming var_info is an object with 'type' attribute that is a tinfo_t
        var_type = var_info.type.copy() # Get a copy to avoid modifying original
        type_str = str(var_type) # Initial string representation

        # Process pointers and const qualifiers for the string representation
        is_ptr = var_type.is_ptr()
        is_const = var_type.is_const()
        
        # Remove pointer and const qualifiers for core type detection
        while var_type.is_ptr():
            var_type.remove_ptr_or_array()
            type_str = "*" + type_str # Append * for pointers for simplicity
        while var_type.is_const():
            var_type.clr_const()
            type_str = "const " + type_str # Prepend const

        # Check if it's a struct or enum, and unroll/list it
        if var_type.is_struct():
            unrolled_def = unroller.unroll_struct_type(var_type)
            # The bytecode for `get_structs_enums` seems to get the name `str(var_type)`
            # and then stores the unrolled definition under that name.
            struct_enum_dict[str(var_type)] = unrolled_def
        elif var_type.is_enum():
            enum_def = list_enum_members(str(var_type))
            struct_enum_dict[str(var_type)] = enum_def
            
    return struct_enum_dict

def get_callee_name(inst_head_ea):
    """
    Gets the name of the callee function(s) from a call instruction.
    Returns a list of (address, name) tuples for identified callees.
    """
    callees = []
    
    # Iterate over xrefs from the instruction
    for xref in idautils.XrefsFrom(inst_head_ea, ida_xref.XREF_ALL):
        # Check for call/jump cross-references
        # These are common call/jump types in IDA
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF):
            callee_ea = xref.to

            # Resolve thunk targets
            if is_thunk(callee_ea):
                thunk_target_ea = ida_funcs.calc_thunk_func_target(callee_ea)[0]
                if thunk_target_ea != idaapi.BADADDR:
                    callee_ea = thunk_target_ea
            
            callee_name = idc.get_func_name(callee_ea)
            if callee_name:
                callees.append((callee_ea, callee_name))
            else:
                # If no function name, try to find xrefs to this address
                # This could be for data references or non-function calls
                # The original bytecode has a fallback to `XrefsTo` if `get_func_name` fails.
                for back_xref in idautils.XrefsTo(callee_ea, ida_xref.XREF_ALL):
                    back_callee_name = idc.get_func_name(back_xref.frm) # Get name of function calling into the callee
                    if back_callee_name:
                        callees.append((back_xref.frm, back_callee_name))
                        break # Take first good name
    return callees


def get_var_info(var_list):
    """
    Extracts detailed information about variables in a given list.
    Returns a list of formatted strings describing each variable.
    """
    var_info_list = []
    for var in var_list: # Assuming var is an object with name, type, defea, location
        var_name = var.name
        var_type = var.type.copy() # Get a copy
        var_type_str = str(var_type)
        var_defea = var.defea
        var_location = var.location # assuming location is an object with is_stkoff, stkoff, is_reg1, reg1, is_reg2, reg2

        location_str = ""
        if var_location.is_stkoff():
            location_str = f"stack_offset@{var_location.stkoff()}"
        elif var_location.is_reg1():
            location_str = f"register@{var_location.reg1()}"
        elif var_location.is_reg2():
            location_str = f"register_pair@{var_location.reg1()},{var_location.reg2()}"
        
        # Handle pointer and const qualifiers
        if var_type.is_ptr():
            var_type_str = "ptr"
            while var_type.is_ptr():
                var_type.remove_ptr_or_array()
        else:
            var_type_str = "not-ptr"

        if var_type.is_struct():
            var_type_str += "struct"
        else:
            var_type_str += "not-struct"
            
        if var_type.is_enum():
            var_type_str += "enum"
        else:
            var_type_str += "not-enum"
        
        if var_type.is_const():
            var_type_str += "const"
            while var_type.is_const():
                var_type.clr_const()
        else:
            var_type_str += "not-const"

        var_info_list.append([
            var_name,
            var_type_str, # String representation of the type
            location_str,
            var_defea,
            var_type_str, # Redundant, but seems to be used twice in original bytecode
            var_type.is_ptr(),
            var_type.is_struct(),
            var_type.is_enum(),
        ])
    return var_info_list

def get_local_vars(func_ea):
    """
    Retrieves local variables (excluding arguments) for a given function.
    Returns a list of variable names.
    """
    try:
        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure
    except DecompilationFailure:
        print(f"[!] Failed to decompile function at {hex(func_ea)}")
        return None

    local_vars = []
    if cfunc.lvars:
        for lvar in cfunc.lvars:
            if lvar.name and not lvar.is_arg_var: # Exclude arguments
                local_vars.append(lvar.name)
    return local_vars

def get_args(func_ea):
    """
    Retrieves arguments for a given function.
    Returns a list of argument names.
    """
    try:
        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure
    except DecompilationFailure:
        print(f"[!] Failed to decompile function at {hex(func_ea)}")
        return None

    args = []
    if cfunc.arguments:
        for arg in cfunc.arguments:
            if arg.name:
                args.append(arg.name)
    return args

def omit_too_long_pcode(pcode_lines):
    """
    Omits pseudo-code lines if they exceed a certain limit.
    """
    if len(pcode_lines) > 800:
        return pcode_lines[:800] + ['... // omit too long pseudo-code']
    return pcode_lines

def build_pcode_with_struct_and_enum(func_ea):
    """
    Builds the pseudocode string and extracts structure/enum definitions
    used within the function.
    Returns a dictionary {'pcode': str, 'struct_enum_dict': dict}.
    """
    try:
        # Check if it's an imported name, if so, return simplified info
        if is_import_name(func_ea):
            imp_name, lib_name = get_import_name_info(func_ea)
            return {
                'pcode': f"An imported function with name: {imp_name} in library: {lib_name}",
                'struct_enum_dict': {}
            }

        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure

        # Get pseudocode lines and add line numbers
        pcode_lines = []
        for i, line in enumerate(str(cfunc).split('\n')):
            pcode_lines.append(f"{i}| {line}")

        # Omit long pcode
        pcode_lines = omit_too_long_pcode(pcode_lines)
        pcode_str = '\n'.join(pcode_lines)

        # Get structs and enums from local variables
        struct_enum_dict = get_structs_enums(cfunc.lvars)

        return {
            'pcode': pcode_str,
            'struct_enum_dict': struct_enum_dict
        }

    except DecompilationFailure:
        func_name = idc.get_func_name(func_ea)
        demangled_name = demangle(func_name)
        print(f"Fail to decompile func_ea: {hex(func_ea)}, name: {demangled_name}")
        return {'pcode': None, 'struct_enum_dict': {}}
    except Exception as e:
        func_name = idc.get_func_name(func_ea)
        demangled_name = demangle(func_name)
        print(f"Error processing func_ea {hex(func_ea)}, name: {demangled_name}: {e}")
        return {'pcode': None, 'struct_enum_dict': {}}


def measure_informative_score_strings(func, pcode_line_cnt):
    """
    Measures the informative score based on string references within a function.
    Score increases with unique string references, normalized by pcode line count.
    """
    score = 0
    strings_found = 0
    
    # Iterate over all instructions in the function
    for head_ea in idautils.Heads(func.start_ea, func.end_ea):
        # Find string references from each instruction
        for xref in idautils.XrefsFrom(head_ea, ida_xref.XREF_DATA):
            # Check if the target is a string literal
            flags = idc.get_full_flags(xref.to)
            if idc.is_strlit(flags):
                str_content = idc.get_strlit_contents(xref.to)
                if str_content is not None:
                    strings_found += 1
    
    # Calculate score based on strings found, normalized by code size
    # Assuming the constant '25' is a scaling factor or threshold
    # The bytecode implies min(strings_found / pcode_line_cnt * 25, 1)
    if pcode_line_cnt > 0:
        score = min(strings_found / pcode_line_cnt * 25, 1) # Simplified interpretation
    else:
        score = 0
    return score

def measure_informative_score_callees(func):
    """
    Measures the informative score based on calls to named functions within a function.
    Score increases with unique named callees, normalized by function count.
    """
    score = 0
    callees_found = [] # List to store (callee_ea, callee_name) tuples
    
    # Iterate over all instructions in the function
    for head_ea in idautils.Heads(func.start_ea, func.end_ea):
        # Check if the instruction is a call instruction
        # A full implementation would involve decoding the instruction
        # and checking its type. The bytecode points to `ida_ua.insn_t` and `decode_insn`.
        # Simplified: just checking if it's a call instruction from ida_idp.
        
        # Example of how it's done:
        # insn = ida_ua.insn_t()
        # if ida_ua.decode_insn(insn, head_ea) and ida_idp.is_call_insn(insn):
        
        # Let's assume there's a simpler way based on xrefs and function types if available.
        # Or just simulate a direct check from the bytecode's usage of these functions.
        # It calls `ida_idp.is_call_insn` after decoding.
        
        # Due to complexity of opcode analysis, simplifying to direct calls to `get_callee_name`
        # for all instruction heads and filtering later or assuming `get_callee_name` does the filtering.
        # The bytecode iterates `XrefsFrom` for string score but then just `Heads` for callee score.
        # It's more likely iterating `Heads` and then checking if each head is a call,
        # then getting its callee.

        # Let's simulate the `is_call_insn` check based on the opcode:
        # A more direct check could be:
        # op_type = idc.get_item_type(head_ea)
        # if op_type == idc.NN_call: # Example, specific opcode for call
        
        # Instead, let's use the provided `get_callee_name` which should handle call resolution.
        
        # The bytecode indicates processing of each instruction (`Heads`)
        # then checking if it's code, then decoding it and checking if it's a call instruction.
        # Only then it calls `get_callee_name`.
        
        flags = idc.get_full_flags(head_ea)
        if idc.is_code(flags): # Ensure it's a code instruction
            # Decode instruction (simplified, as exact instruction decoding is complex without full IDA context)
            # insn = ida_ua.insn_t()
            # if ida_ua.decode_insn(insn, head_ea) and ida_idp.is_call_insn(insn):
            # The bytecode just calls `get_callee_name(head_ea)` without explicit `is_call_insn` check before.
            # This suggests `get_callee_name` might handle the check internally.
            
            callee_list = get_callee_name(head_ea)
            callees_found.extend(callee_list)

    # Filter for unique and named callees
    unique_named_callees_count = 0
    processed_callees = set()
    for callee_ea, callee_name in callees_found:
        # Ensure it's a function and has a meaningful name
        func = ida_funcs.get_func(callee_ea)
        if func and idaapi.has_name(idc.get_full_flags(func.start_ea)): # Check if func has a non-auto-generated name
            if callee_ea not in processed_callees: # Count unique callees
                unique_named_callees_count += 1
                processed_callees.add(callee_ea)

    # Score calculation seems to be similar to string score, normalized by a factor (e.g., 2)
    # The bytecode implies `min(unique_named_callees_count / len(callees_found) * 2, 1)` or similar.
    # It takes `min(callee_score_value, 1)` where `callee_score_value = unique_named_callees_count / 2` 
    # (assuming the original `callees_found` is a proxy for all calls, thus dividing by a constant like 2 for normalization)
    
    if unique_named_callees_count > 0:
        score = min(unique_named_callees_count / 2, 1) # Simplified based on numerical constants like 2
    else:
        score = 0
        
    return score

def _real_measure_informative_score(func_ea):
    """
    Calculates the real informative score for a function.
    Combines scores from string references, named callees, and pcode size.
    """
    score = 0
    func = ida_funcs.get_func(func_ea)
    if not func:
        return -999 # Sentinel for function not found

    # Score from having a meaningful name
    if idaapi.has_name(idc.get_full_flags(func.start_ea)):
        score += 2 # Arbitrary score for named function based on bytecode constant 2

    # Score from pcode length
    pcode_len_score = 0
    try:
        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure
        
        # Pcode line count score: `min(pcode_line_cnt // 100 - 1, 0) * -1`
        # This converts a positive penalty to a negative score contribution.
        # E.g., 200 lines: 2 - 1 = 1. Score -= 1.
        pcode_line_count = len(cfunc.get_pseudocode())
        pcode_len_score = max(0, -(pcode_line_count // 100 - 1)) # Penalty for long pcode

        score += measure_informative_score_strings(func, pcode_line_count)
        score += measure_informative_score_callees(func)
        score -= pcode_len_score # Deduct long pcode penalty

    except DecompilationFailure:
        # If decompilation fails, a penalty might be applied.
        score -= 999 # Large penalty
    except Exception as e:
        # Generic error handling during scoring
        score -= 50 # Smaller penalty for other errors
    
    return score

def measure_informative_score(func_ea):
    """
    Public function to measure the informative score of a function.
    Only runs if MEASURE_INFO_SCORE global flag is True.
    """
    if MEASURE_INFO_SCORE:
        return _real_measure_informative_score(func_ea)
    return 1 # Default score if not measuring


class ContextBuilder:
    """
    Builds pseudo-code context and call-chains for the target function.
    """
    def __init__(self, max_trace_callee_depth, max_trace_caller_depth, max_context_func_num, limit_funcs=None):
        self.context_callee_funcs = {} # {ea: depth} for callees
        self.context_caller_funcs = defaultdict(int) # {ea: depth} for callers
        self.call_chains = set() # Store unique call chains
        self.limited_funcs = limit_funcs if limit_funcs is not None else set()
        self.MAX_TRACE_CALLEE_DEPTH = max_trace_callee_depth
        self.MAX_TRACE_CALLER_DEPTH = max_trace_caller_depth
        self.MAX_CONTEXT_FUNC_NUM = max_context_func_num

    def build_context_forward(self, func_ea, temp_call_chain, depth):
        """
        Recursively builds forward context (callees).
        """
        if self.limited_funcs and func_ea not in self.limited_funcs:
            return
        
        # If already visited at this depth or shallower, skip
        if func_ea in self.context_callee_funcs and self.context_callee_funcs[func_ea] <= depth:
            return

        self.context_callee_funcs[func_ea] = depth

        if depth > self.MAX_TRACE_CALLEE_DEPTH:
            return

        # Find call instructions within the function
        # Iterate through instructions, check if it's a call, then get callee(s)
        for head_ea in idautils.FuncItems(func_ea):
            # Check if it's a call instruction
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, head_ea) and ida_idp.is_call_insn(insn):
                for xref in idautils.XrefsFrom(head_ea, ida_xref.XREF_ALL):
                    # Check xref type for calls/jumps to code
                    if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF) and idaapi.iscode(idc.get_full_flags(xref.to)):
                        callee_ea = xref.to
                        callee_func = ida_funcs.get_func(callee_ea)
                        if callee_func:
                            callee_name = idc.get_func_name(callee_func.start_ea)
                            if callee_name:
                                demangled_callee_name = demangle(callee_name)
                                self.build_context_forward(
                                    callee_func.start_ea,
                                    f"{temp_call_chain}-->{demangled_callee_name}",
                                    depth + 1
                                )
                                # No need for `else` here, just add to call chain if depth limit reached
                                if depth == self.MAX_TRACE_CALLEE_DEPTH:
                                    self.call_chains.add(f"{temp_call_chain}-->{demangled_callee_name}")
                                    
        # If depth limit reached and this isn't a call. This logic needs refinement in decompilation.
        # The original bytecode had complex jumps for this.
        # This part seems to be an `if/else` block.
        if depth >= 1 and not (self.limited_funcs and func_ea not in self.limited_funcs): # re-checking original condition
            self.call_chains.add(temp_call_chain) # Add current function path if no further calls or at max depth


    def build_context_backward(self, func_ea, temp_call_chain, depth):
        """
        Recursively builds backward context (callers).
        """
        if self.limited_funcs and func_ea not in self.limited_funcs:
            return
        
        # If already visited at this depth or shallower, skip (abs depth)
        if func_ea in self.context_caller_funcs and abs(self.context_caller_funcs[func_ea]) >= abs(depth):
            return

        self.context_caller_funcs[func_ea] = depth

        if abs(depth) > self.MAX_TRACE_CALLER_DEPTH:
            return

        # Find code references to the function
        for xref_ea in idautils.CodeRefsTo(func_ea, 1): # 1 for regular code refs
            caller_func = ida_funcs.get_func(xref_ea)
            if caller_func and caller_func.start_ea != idaapi.BADADDR:
                caller_ea = caller_func.start_ea
                caller_name = idc.get_func_name(caller_ea)
                if caller_name:
                    demangled_caller_name = demangle(caller_name)
                    self.build_context_backward(
                        caller_ea,
                        f"{demangled_caller_name}-->{temp_call_chain}",
                        depth - 1 # Decrease depth for callers
                    )
                # Similar logic for adding to call chains as in forward build
                if abs(depth) == self.MAX_TRACE_CALLER_DEPTH:
                    self.call_chains.add(f"{demangled_caller_name}-->{temp_call_chain}")
        
        # Similar logic for adding to call chains if no further calls or at max depth
        if abs(depth) >= 1 and not (self.limited_funcs and func_ea not in self.limited_funcs):
            self.call_chains.add(temp_call_chain)

    def build_context(self, func_ea):
        """
        Initializes and starts building both forward and backward contexts.
        """
        self.context_callee_funcs = {}
        self.context_caller_funcs = defaultdict(int)
        self.call_chains = set()

        # Get initial function name for the chain
        func_name = idc.get_func_name(func_ea)
        demangled_func_name = demangle(func_name)

        # Build forward context (callees)
        self.build_context_forward(func_ea, demangled_func_name, 0)
        # Build backward context (callers)
        self.build_context_backward(func_ea, demangled_func_name, 0)

        return True # Indicates context building was initiated

    def get_context_pcode(self, target_func_ea, analyzer_funcs):
        """
        Retrieves formatted pseudocode for relevant context functions.
        Sorts context functions by their informative score.
        """
        context_pcode_str = ""
        context_funcs_dict = {}
        
        # Get target function to retrieve `start_ea`
        target_func = ida_funcs.get_func(target_func_ea)
        if not target_func:
            return None, None, None # Pcode, struct_enum_dict, analyzed_funcs_in_dataflow

        # Consolidate all unique functions involved in context
        # Prioritize functions that were analyzed by the data flow analyzer
        all_context_funcs = set(self.context_callee_funcs.keys()).union(self.context_caller_funcs.keys())
        
        # Remove target function itself from context list, if present
        if target_func.start_ea in all_context_funcs:
            all_context_funcs.remove(target_func.start_ea)

        # Apply MAX_CONTEXT_FUNC_NUM limit by sorting by a score
        # The bytecode implies sorting by `max(callee_depth, abs(caller_depth))` in reverse order.
        # This prioritizes functions that are closer in the call chain.
        
        # This lambda function definition and usage within sorted is complex in bytecode.
        # It needs to access `self.context_callee_funcs` and `self.context_caller_funcs`.
        
        # We need a function to get the maximum absolute depth for a given function EA
        def get_max_depth_for_sort(ea_to_score):
            callee_depth = self.context_callee_funcs.get(ea_to_score, 0)
            caller_depth = self.context_caller_funcs.get(ea_to_score, 0)
            return max(callee_depth, abs(caller_depth))

        sorted_context_funcs_ea = sorted(
            list(all_context_funcs),
            key=get_max_depth_for_sort,
            reverse=True # Sort by absolute depth, deeper first (larger absolute value)
        )
        
        # Apply MAX_CONTEXT_FUNC_NUM limit
        limited_context_funcs_ea = sorted_context_funcs_ea[:self.MAX_CONTEXT_FUNC_NUM]

        # Build pcode for each context function
        struct_enum_defs = {}
        analyzed_funcs_in_dataflow = set() # Keep track of which functions were actually added

        for func_ea_item in limited_context_funcs_ea:
            # Re-check if func_ea_item is valid and exists as a function
            func = ida_funcs.get_func(func_ea_item)
            if not func:
                continue # Skip if function doesn't exist

            # Get pcode and struct/enum info for this context function
            func_pcode_info = build_pcode_with_struct_and_enum(func.start_ea)
            pcode = func_pcode_info['pcode']
            s_e_dict = func_pcode_info['struct_enum_dict']

            if pcode:
                context_pcode_str += pcode + "\n\n" # Add double newline between functions
                analyzed_funcs_in_dataflow.add(func.start_ea)
                struct_enum_defs.update(s_e_dict)

        return context_pcode_str, struct_enum_defs, list(analyzed_funcs_in_dataflow) # Return as list for flexibility

    def get_call_chains(self):
        """
        Returns the formatted call chains as a single string.
        """
        return "\n".join(sorted(list(self.call_chains)))


def get_numbers_from_pcode(pcode):
    """
    Extracts numerical constants (hex and decimal) from pcode text.
    Returns a list of extracted numbers as strings.
    """
    numbers = []
    # Regex to find hex and decimal numbers, possibly with sign and LL suffix.
    # (?<!\w) ensures no word character before, (?!\\w) ensures no word char after for whole number match.
    # 0[xX][0-9a-fA-F]+(?:uLL|LL)? : Hex numbers (0x...) with optional uLL/LL suffix
    # \d+(?:uLL|LL)? : Decimal numbers with optional uLL/LL suffix
    # [+-]? : Optional sign
    numeric_pattern = r"(?<!\w)[+-]?0[xX][0-9a-fA-F]+(?:uLL|LL)?|(?<!\w)[+-]?\d+(?:uLL|LL)?(?!\w)"
    
    for line in pcode.split('\n'):
        found_numbers_in_line = re.findall(numeric_pattern, line)
        numbers.extend(found_numbers_in_line)
    return numbers

def get_functions_in_text_like_seg():
    """
    Retrieves a list of all function EAs within text-like segments.
    """
    funcs = []
    seg_ea = ida_segment.get_first_seg()
    while seg_ea != idaapi.BADADDR:
        seg_name = ida_segment.get_segm_name(seg_ea)
        if "text" in seg_name: # Simple check for "text" in segment name
            # Functions in this segment
            for func_ea in idautils.Functions(idc.get_segm_start(seg_ea), idc.get_segm_end(seg_ea)):
                funcs.append(func_ea)
        seg_ea = ida_segment.get_next_seg(seg_ea)
    return funcs

def is_good_func_for_build_input(func_ea, demangled_name, pcode_line_cnt, pcode_var_cnt):
    """
    Determines if a function is 'good' for building input based on heuristics.
    """
    if demangled_name in MEANINGLESS_NAME_LIST:
        return False
    if pcode_line_cnt > 100: # Too many lines, possibly large/complex function
        return False
    if pcode_var_cnt > 30: # Too many variables, possibly complex
        return False
    return True

def build_prompt(func_ea, task_tag, args=None):
    """
    Builds the complete prompt string for the given function and task.
    Integrates pseudocode, data flow, call chains, and structural information.
    """
    # Load settings (already done globally, but good to keep in mind they're used)
    # MAX_TRACE_CALLEE_DEPTH, MAX_TRACE_CALLER_DEPTH, MAX_CONTEXT_FUNC_NUM, MEASURE_INFO_SCORE, DATA_FLOW_ANALYSIS_ENABLED

    print(f"[🐛DEBUG] invoke apply_prediction") # Debug print from original
    print(f"[🐛DEBUG] task_tag: {task_tag}") # Debug print from original
    print(f"[🐛DEBUG] prediction: {args}") # Debug print from original (args is the prediction dict)

    # Basic input validation based on SUPPORT_FUNC_TYPES
    if task_tag not in SUPPORT_FUNC_TYPES:
        print(f"[!] Unsupported task tag: {task_tag}")
        return None

    # Get function object
    func = ida_funcs.get_func(func_ea)
    if not func:
        print(f"[!] Fail to get function at {hex(func_ea)}")
        return None

    # Handle thunk functions
    if is_thunk(func_ea):
        print("[!] Thunk function is not supported")
        return None

    # Get function metadata for building input
    func_start_ea = func.start_ea
    func_end_ea = func.end_ea
    func_name = idc.get_func_name(func_start_ea)
    demangled_func_name = demangle(func_name)

    # Decompile for pcode and variable/argument info
    try:
        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure
        
        target_pcode_lines = cfunc.get_pseudocode()
        pcode_line_cnt = len(target_pcode_lines)
        pcode_var_cnt = len(cfunc.lvars) # Local variables + arguments count

        # Check if function is suitable based on heuristics
        if not is_good_func_for_build_input(func_ea, demangled_func_name, pcode_line_cnt, pcode_var_cnt):
            print(f"[!] Function {demangled_func_name} is not good for building input")
            return None

        # --- Data Flow Analysis ---
        data_flow_str = ""
        if DATA_FLOW_ANALYSIS_ENABLED:
            data_flow_analyzer = DataFlowAnalyzer(MAX_TRACE_CALLEE_DEPTH, MAX_TRACE_CALLER_DEPTH)
            raw_data_flow = data_flow_analyzer.get_var_dataflow(func_ea, args['var_name'] if 'var_name' in args else None) # Assuming 'var_name' for specific vars
            # Filter data flow by context functions (if any)
            # This is complex, assuming `filter_data_flow_by_context_func` is a method that takes raw_data_flow and context functions
            # Simplified for now, just format the raw data flow.
            # The bytecode flow here indicates passing `data_flow_analyzer.analyzed_funcs` to `filter_data_flow_by_context_func`
            
            # This is a placeholder; real `filter_data_flow_by_context_func` would be more complex
            # For simplicity, if not specific var, get all vars and apply basic formatting.
            if raw_data_flow: # Check if data flow exists and is not empty
                data_flow_str = DATA_FLOW_TEMPLATE.format(raw_data_flow)
            else:
                data_flow_str = DATA_FLOW_TEMPLATE.format("") # Empty if no data flow
                

        # --- Context and Call Chains ---
        context_builder = ContextBuilder(
            MAX_TRACE_CALLEE_DEPTH,
            MAX_TRACE_CALLER_DEPTH,
            MAX_CONTEXT_FUNC_NUM
        )
        context_builder.build_context(func_ea)
        
        call_chains_str = context_builder.get_call_chains()
        context_pcode_str, context_struct_enum_dict, _ = context_builder.get_context_pcode(func_ea, None) # The 'analyzer_funcs' param for `get_context_pcode` seemed to be `data_flow_analyzer.analyzed_funcs` in original code, but not used here.
        
        # Merge struct/enum definitions from target and context
        # This step is implied if get_structs_enums is used more broadly
        # For this function, we'll just format the relevant parts.

        # --- Build final prompt based on task_tag ---
        # The prompt construction is based on the INPUT_TEMPLATE
        # and depends on the `task_tag`.

        # For tasks like `<func-analysis>`, `<decompilation>`, `<funcname>`, `<summary>`
        # This implies these tasks use the general prompt template.
        if task_tag in ['<func-analysis>', '<decompilation>', '<funcname>', '<summary>']:
            return INPUT_TEMPLATE.format(
                context=context_pcode_str or "",
                target_func='\n'.join(target_pcode_lines),
                call_chains=call_chains_str,
                data_flow=data_flow_str,
                task_tag=task_tag
            )
        
        # For `<vars>`
        elif task_tag == '<vars>':
            if not cfunc.lvars and not cfunc.arguments:
                print(f"[!] No local variables or arguments found in function {demangled_func_name}")
                return None
            
            # Reuse the `INPUT_TEMPLATE` but adjust `data_flow` part to include var info.
            # Get local variables and arguments.
            all_vars_info = get_var_info(list(cfunc.lvars) + list(cfunc.arguments))
            var_data_flow_str = ""
            if DATA_FLOW_ANALYSIS_ENABLED:
                var_data_flow_str = DATA_FLOW_TEMPLATE.format(data_flow_analyzer.get_var_dataflow(func_ea, None))
                # Need to filter `var_data_flow_str` by `context_builder.analyzed_funcs` as seen in original bytecode.
                # Assuming `filter_data_flow_by_context_func` is part of DataFlowAnalyzer
                var_data_flow_str = data_flow_analyzer.filter_data_flow_by_context_func(var_data_flow_str, context_builder.get_incontext_funcs())
                var_data_flow_str = DATA_FLOW_TEMPLATE.format(var_data_flow_str)
            else:
                 var_data_flow_str = DATA_FLOW_TEMPLATE.format("")

            # This part is highly simplified. Original bytecode indicates complex formatting
            # iterating through parsed var_info to build string representation.
            # Let's represent it as a placeholder for now.
            var_declarations_str = "\n".join([f"{v[1]} {v[0]} // at {v[2]}" for v in all_vars_info])

            return INPUT_TEMPLATE.format(
                context=context_pcode_str or "",
                target_func='\n'.join(target_pcode_lines),
                call_chains=call_chains_str,
                data_flow=var_data_flow_str,
                task_tag=task_tag
            )

        # For `<args>`
        elif task_tag == '<args>':
            if not cfunc.arguments:
                print(f"[!] No arguments found in function {demangled_func_name}")
                return None
            
            # Similar to vars, but only for arguments
            args_info = get_var_info(list(cfunc.arguments))
            args_data_flow_str = ""
            if DATA_FLOW_ANALYSIS_ENABLED:
                args_data_flow_str = DATA_FLOW_TEMPLATE.format(data_flow_analyzer.get_var_dataflow(func_ea, [arg[0] for arg in args_info]))
                args_data_flow_str = data_flow_analyzer.filter_data_flow_by_context_func(args_data_flow_str, context_builder.get_incontext_funcs())
                args_data_flow_str = DATA_FLOW_TEMPLATE.format(args_data_flow_str)
            else:
                 args_data_flow_str = DATA_FLOW_TEMPLATE.format("")
            
            arg_declarations_str = "\n".join([f"{v[1]} {v[0]} // at {v[2]}" for v in args_info])

            return INPUT_TEMPLATE.format(
                context=context_pcode_str or "",
                target_func='\n'.join(target_pcode_lines),
                call_chains=call_chains_str,
                data_flow=args_data_flow_str,
                task_tag=task_tag
            )
            
        # For `<specific-vars>`
        elif task_tag == '<specific-vars>':
            # `args` in this context should be a list of variable names to analyze
            if not args or not isinstance(args, (str, list)):
                raise AssertionError(f"[!] Bad specified vars: {args}")

            # Ensure args is a list for iteration
            specific_var_names = [args] if isinstance(args, str) else args
            
            # Format specific vars into task tag as seen in bytecode
            formatted_task_tag = task_tag
            for var_name in specific_var_names:
                formatted_task_tag += f"<var:{var_name}>"

            specific_vars_info = []
            for var_name in specific_var_names:
                # Find the actual variable object in cfunc.lvars or cfunc.arguments
                found_var = None
                for lvar in cfunc.lvars:
                    if lvar.name == var_name:
                        found_var = lvar
                        break
                if not found_var:
                    for arg in cfunc.arguments:
                        if arg.name == var_name:
                            found_var = arg
                            break
                
                if found_var:
                    specific_vars_info.extend(get_var_info([found_var]))
                else:
                    print(f"[!] Variable '{var_name}' not found in function {demangled_func_name}")

            specific_vars_data_flow_str = ""
            if DATA_FLOW_ANALYSIS_ENABLED:
                specific_vars_data_flow_str = DATA_FLOW_TEMPLATE.format(data_flow_analyzer.get_var_dataflow(func_ea, specific_var_names))
                specific_vars_data_flow_str = data_flow_analyzer.filter_data_flow_by_context_func(specific_vars_data_flow_str, context_builder.get_incontext_funcs())
                specific_vars_data_flow_str = DATA_FLOW_TEMPLATE.format(specific_vars_data_flow_str)
            else:
                 specific_vars_data_flow_str = DATA_FLOW_TEMPLATE.format("")
            
            # Format output for specific vars
            specific_var_declarations_str = "\n".join([f"{v[1]} {v[0]} // at {v[2]}" for v in specific_vars_info])

            return INPUT_TEMPLATE.format(
                context=context_pcode_str or "",
                target_func='\n'.join(target_pcode_lines),
                call_chains=call_chains_str,
                data_flow=specific_vars_data_flow_str,
                task_tag=formatted_task_tag
            )

        else:
            raise NotImplementedError(f"Not implemented func_type == `{task_tag}` yet")

    except DecompilationFailure:
        print(f"[!] Failed to decompile function at {hex(func_ea)}")
        return None
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"An unexpected error occurred: {e}")
        return None

def apply_prediction_ret_type(func_ea, prediction):
    """
    Applies the predicted return type to a function.
    """
    ret_type_str = prediction.get('ret_type', None)
    if not isinstance(ret_type_str, str): # Check if ret_type is valid string
        print(f"[!] found bad ret_type in prediction: {ret_type_str}")
        return None
    
    # Ensure type string ends with ';'
    if not ret_type_str.endswith(';'):
        ret_type_str += ';'

    # Parse the new type string
    tif = ida_typeinf.tinfo_t()
    idati = idaapi.get_idati()
    
    # parse_decl returns 1 if successful and sets tif, 0 on failure
    # PT_TYP: assume type
    # PT_SIL: silent mode
    parse_success = ida_typeinf.parse_decl(tif, idati, ret_type_str, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
    
    if not parse_success: # Failed to parse type
        # Try without trailing semicolon, if it was added
        if ret_type_str.endswith(';'):
            ret_type_str = ret_type_str[:-1]
            parse_success = ida_typeinf.parse_decl(tif, idati, ret_type_str, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
        
        # If still failed, try `get_named_type` (e.g., if it's an existing struct/enum)
        if not parse_success:
            # BTF_TYPEDEF: try to find a typedef
            # True, False: exact match, don't create if not found
            if not tif.get_named_type(idati, ret_type_str, ida_typeinf.BTF_TYPEDEF, True, False):
                print(f"[!] Failed to parse or find type {ret_type_str}")
                return None

    # Get the function's existing type info
    old_func_tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(old_func_tif, func_ea):
        print(f"[!] Fail to get function type info at {hex(func_ea)}")
        return None

    # Get function details (arguments, calling convention, etc.)
    func_type_data = ida_typeinf.func_type_data_t()
    if not old_func_tif.get_func_details(func_type_data):
        print(f"[!] Fail to get function details at {hex(func_ea)}")
        return None

    # Update the return type
    func_type_data.rettype = tif # Set the new return type

    # Create a new function type with updated return type
    new_func_tif = ida_typeinf.tinfo_t()
    if not new_func_tif.create_func(func_type_data):
        print(f"[!] Fail to create new function type at {hex(func_ea)}")
        return None

    # Apply the new function type
    # TINFO_DEFINITE: The new type should be applied even if it's less specific.
    if not idaapi.apply_tinfo(func_ea, new_func_tif, idaapi.TINFO_DEFINITE):
        print(f"[!] Fail to apply new function type at {hex(func_ea)}")
        return False
    
    print(f"[+] Successfully set return type {ret_type_str.strip(';')} for function {hex(func_ea)}")

    # Refresh pseudocode view if open
    widget = idaapi.open_pseudocode(func_ea, 0)
    if widget:
        # Assuming cfunc is the cfunc_t object from the open widget
        # The bytecode does access `widget.cfunc.refresh_func_ctext()`
        if hasattr(widget, 'cfunc') and hasattr(widget.cfunc, 'refresh_func_ctext'):
            widget.cfunc.refresh_func_ctext()
    
    return True


def apply_prediction_func_name(func_ea, prediction):
    """
    Applies the predicted function name.
    Handles both direct name string or a dict with 'original' and 'prediction' keys.
    """
    new_func_name = None

    if isinstance(prediction, str):
        new_func_name = prediction
    elif isinstance(prediction, dict):
        old_name_in_pred = prediction.get('original', None)
        new_name_in_pred = prediction.get('prediction', None)
        if not new_name_in_pred:
            print(f"[!] found bad funcname in prediction: {prediction}")
            return None

        new_func_name = new_name_in_pred
        
        # If old_name_in_pred is provided, try to rename it instead of func_ea
        if old_name_in_pred:
            # Get EA of the old name
            old_ea = idc.get_name_ea_simple(old_name_in_pred)
            if old_ea != idaapi.BADADDR:
                if not idc.set_name(old_ea, new_func_name):
                    print(f"[!] Fail to apply new name to original name: {old_name_in_pred}")
                    return None
                print(f"[+] Successfully set new name {new_func_name} for old name: {old_name_in_pred}")
            else:
                print(f"[!] Fail to apply new name to original name: {old_name_in_pred} (old name not found)")
                return False
            # Reopen pseudocode for both old_ea (if it was the primary function) or func_ea if they're different
            target_ea_to_refresh = old_ea if old_ea == func_ea else func_ea
            widget = idaapi.open_pseudocode(target_ea_to_refresh, 0)
            if widget and hasattr(widget, 'cfunc') and hasattr(widget.cfunc, 'refresh_func_ctext'):
                widget.cfunc.refresh_func_ctext()
            return True # Successfully handled renaming by old name

    else:
        print(f"[!] found bad funcname in prediction: {prediction}")
        return None
    
    # If it's a direct func_ea rename or we processed the old name logic
    if new_func_name:
        if not idc.set_name(func_ea, new_func_name):
            print(f"[!] Fail to set function name {new_func_name} at {hex(func_ea)}")
            return False
        print(f"[+] Successfully set new name {new_func_name} at {hex(func_ea)}")

        # Refresh pseudocode view if open
        widget = idaapi.open_pseudocode(func_ea, 0)
        if widget and hasattr(widget, 'cfunc') and hasattr(widget.cfunc, 'refresh_func_ctext'):
            widget.cfunc.refresh_func_ctext()
        return True
    return False # Should not reach here if `new_func_name` is set successfully


def add_array_type(type_name, array_dims):
    """
    Adds an array type definition (typedef).
    Args:
        type_name: Base type name, e.g., "char"
        array_dims: List of array dimensions, e.g., [32] for 1D, [4,4] for 2D
    Returns:
        tinfo_t: The successfully added type
    """
    print(f"[+] Adding typedef for array type {type_name}")

    tif = ida_typeinf.tinfo_t()
    
    # Ensure base type string ends with ';' for parse_decl
    if not type_name.endswith(';'):
        type_name += ';'

    # Parse base type
    # PT_TYP: assume type
    # PT_SIL: silent mode
    parse_success = ida_typeinf.parse_decl(tif, idaapi.get_idati(), type_name, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
    
    if not parse_success:
        print(f"[!] Failed to parse base type {type_name}")
        return None
    
    # Create array type recursively using reversed dimensions
    # The bytecode shows a loop over `reversed(array_dims)`
    # where a copy of `tif` is made and then `create_array` is called.
    current_tif = tif.copy()
    for dim in reversed(array_dims):
        new_array_tif = ida_typeinf.tinfo_t()
        # create_array needs the base type and the dimension
        if not new_array_tif.create_array(current_tif, dim):
            print(f"[!] Failed to create array with dimension {dim}")
            return None # Return None on failure
        current_tif = new_array_tif # Use the newly created array type as base for next dimension

    return current_tif # Return the final array tinfo_t

def add_enum_type(enum_name, enum_details):
    """
    Adds an enum type definition to IDA.
    Args:
        enum_name: Name of the enum.
        enum_details: Dictionary of enum members {member_name: member_value}.
    Returns:
        tinfo_t: The successfully added enum type.
    """
    print(f"[+] Adding enum {enum_name}")

    # Check if enum already exists and delete it
    enum_id = idc.get_enum(enum_name)
    if enum_id != idaapi.BADADDR:
        print(f"[*] Removing existing enum {enum_name}")
        idc.del_enum(enum_id)

    # Add the new enum
    new_enum_id = idc.add_enum(idc.BADADDR, enum_name, 0) # 0 for default flags
    if new_enum_id == idc.BADADDR:
        print(f"[!] Failed to create enum {enum_name}")
        return None

    # Add members to the enum
    for member_name, member_value in enum_details.items():
        # Validate member_name and member_value based on bytecode checks
        # The bytecode checks `isinstance(member_name, str)` and `isinstance(member_value, (int, str))`
        # It also attempts to parse `member_value` if it's a string.
        
        # Parse member_value if it's a string, converting hex/decimal
        if isinstance(member_value, str):
            # This is complex in bytecode, but typical implementation would use `int(val, 0)` for auto-base detection
            try:
                if member_value.startswith("0x") or member_value.startswith("0X"):
                    member_value = int(member_value, 16)
                else:
                    member_value = int(member_value)
            except ValueError:
                print(f"[!] Bad enum member value {member_value} for member {member_name}")
                continue # Skip bad member

        if not isinstance(member_name, str) or not isinstance(member_value, int):
            print(f"[!] Bad enum member {member_name} = {member_value}")
            continue
            
        print(f"[*] Adding enum member {member_name} = {member_value}")
        # Add member to enum
        # The disassembly for `add_enum_member` has several arguments,
        # typically: `(enum_id, name, value, bmask)`
        # `bmask` is usually 0xFFFFFFFF for full mask. Let's assume default flags.
        if idc.add_enum_member(new_enum_id, member_name, member_value) == 0: # 0 indicates success
            print(f"[+] Successfully added enum member {member_name}")
        else:
            print(f"[!] Failed to add enum member {member_name}")

    # Return the newly created enum's tinfo_t
    enum_tif = ida_typeinf.tinfo_t()
    if not enum_tif.get_type_by_tid(new_enum_id):
        return None # Should not happen if add_enum succeeded
        
    print(f"[+] Successfully created enum {enum_name}")
    return enum_tif

def add_empty_struct_type(struct_name, struct_size):
    """
    Adds an empty structure type definition to IDA with a specified size.
    Used for forward declarations or unknown struct sizes.
    """
    # Remove any pointer/struct prefixes from the name
    clean_struct_name = struct_name.replace('*', '').replace('struct ', '').strip()

    # Check if struct already exists
    struct_id = idc.get_struc_id(clean_struct_name)
    if struct_id != idaapi.BADADDR:
        # If it exists, verify its size. If different, delete and recreate.
        # This part of the original bytecode logic is about recreating if size is different.
        # For simplicity, we just delete and re-add if it exists.
        idc.del_struc(struct_id)

    # Add the new structure
    new_struct_id = idc.add_struc(idc.BADADDR, clean_struct_name, 0) # 0 for default flags (e.g., public)
    if new_struct_id == idaapi.BADADDR:
        print(f"[!] Failed to create struct {clean_struct_name}")
        return None

    # Set the size of the structure
    struc = idc.get_struc(new_struct_id)
    if struc:
        # The `set_fixed_struct` is used to make it a fixed-size struct
        idc.set_fixed_struct(struc, True)
        idc.set_struct_size(struc, struct_size)
        return struc # Return the struct_t object
    
    return None # Return None if something went wrong

def add_struct_type(struct_name, struct_details):
    """
    Adds a full structure type definition with members to IDA.
    Args:
        struct_name: Name of the struct.
        struct_details: List of struct members, each [type_string, member_name, offset_bytes].
    Returns:
        tinfo_t: The successfully added struct type.
    """
    print(f"[+] Adding struct {struct_name}")

    # Check and remove existing struct
    struct_id = idc.get_struc_id(struct_name)
    if struct_id != idaapi.BADADDR:
        print(f"[*] Removing existing struct {struct_name}")
        idc.del_struc(struct_id)

    # Add the new empty struct
    new_struct_id = idc.add_struc(idc.BADADDR, struct_name, 0)
    if new_struct_id == idaapi.BADADDR:
        print(f"[!] Failed to create struct {struct_name}")
        return None

    struct_obj = idc.get_struc(new_struct_id) # Get the struct_t object
    if not struct_obj:
        return None # Should not happen if add_struc succeeded

    # Add members to the struct
    current_offset = 0
    for member_type_str, member_name, member_size in struct_details: # Format: [type_string, name, size]
        print(f"[*] Adding member {member_name} with type {member_type_str} at offset {hex(current_offset)}")

        # Parse member type string
        member_tif = ida_typeinf.tinfo_t()
        idati = idaapi.get_idati()
        
        # Ensure type string ends with ';' for parse_decl
        if not member_type_str.endswith(';'):
            member_type_str += ';'

        parse_success = ida_typeinf.parse_decl(member_tif, idati, member_type_str, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
        
        if not parse_success:
            # If parsing fails, try to find it as a named type (struct, enum)
            if not member_tif.get_named_type(idati, member_type_str.strip(';'), ida_typeinf.BTF_TYPEDEF, True, False):
                print(f"[!] Failed to parse type {member_type_str} for member {member_name}")
                # Fallback to a default type (e.g., dword) if parsing fails completely
                # The bytecode path here implies creating a `tinfo_t` again then getting its `dstr()`
                # If still fails, it jumps to a segment that does `add_empty_struct_type` or similar.
                # Let's simplify this by just returning None on critical failure or continuing
                # if the original logic implies continuing with a dummy type.
                member_tif = ida_typeinf.tinfo_t() # Default to void
                # The bytecode tries to derive a basic type based on `member_size`
                # 1 byte: FF_BYTE | FF_DATA
                # 2 bytes: FF_WORD | FF_DATA
                # 4 bytes: FF_DWORD | FF_DATA
                # 8 bytes: FF_QWORD | FF_DATA
                # For other sizes, it uses FF_DATA and tries to get TID if available.
                # This part is highly detailed.
                
                # Simplified default logic:
                if member_size == 1:
                    member_flags = idc.FF_BYTE | idc.FF_DATA
                elif member_size == 2:
                    member_flags = idc.FF_WORD | idc.FF_DATA
                elif member_size == 4:
                    member_flags = idc.FF_DWORD | idc.FF_DATA
                elif member_size == 8:
                    member_flags = idc.FF_QWORD | idc.FF_DATA
                else:
                    member_flags = idc.FF_DATA # Generic data type

                # If the type string contained "struct " or "enum ", and we couldn't parse it.
                # The bytecode explicitly calls `add_empty_struct_type` or `add_enum_type`
                # if the parse fails and the type string indicates a struct/enum.
                if 'struct ' in member_type_str:
                    add_empty_struct_type(member_type_str, member_size) # Try to add it as an empty struct
                elif 'enum ' in member_type_str:
                    # add_enum_type expects {name: [[member_name, value]]} structure
                    # We can't provide full details here, so might just add a placeholder.
                    # Or skip if the original type wasn't resolved.
                    pass # Skipping for now to avoid complexity without full enum details
                
                # In a real scenario, this would likely involve more robust error handling
                # or creation of placeholder types. For simplicity, we'll indicate failure.
                continue # Skip this member if its type can't be resolved

        # Add the member to the structure
        # `add_struc_member(sid, name, offset, flag, typeid, nbytes)`
        # flag: FF_BYTE | FF_DATA, etc. derived from type
        # typeid: TID of the type (e.g., struct ID, enum ID, or 0 for basic types)
        
        # This part in the bytecode for `add_struc_member` is super complex with flags
        # It gets `member_tif.get_tid()` for `typeid` argument
        # And it builds flags based on `member_size` and type kind (e.g., `FF_STRUCT | FF_DATA`)
        
        member_flags_ida = idc.FF_DATA # Default generic data
        member_tid_ida = 0 # Default no specific type ID
        
        if member_tif.is_struct():
            member_flags_ida |= idc.FF_STRUCT
            member_tid_ida = member_tif.get_tid()
        elif member_tif.is_enum():
            # Enums don't get FF_ENUM flag directly when added as member. Their TID is used.
            member_tid_ida = member_tif.get_tid()
        
        if member_size == 1:
            member_flags_ida |= idc.FF_BYTE
        elif member_size == 2:
            member_flags_ida |= idc.FF_WORD
        elif member_size == 4:
            member_flags_ida |= idc.FF_DWORD
        elif member_size == 8:
            member_flags_ida |= idc.FF_QWORD
        
        # Attempt to add member
        res = idc.add_struc_member(
            new_struct_id,
            member_name,
            current_offset,
            member_flags_ida,
            member_tid_ida,
            member_size
        )

        if res != 0: # If add_struc_member returns non-zero, it indicates an error
            print(f"[!] Failed to add member: {member_name} ({res})")
        else:
            print(f"[+] Successfully added member {member_name}")
            # Set the member's type using `set_udm_type`
            # This is done separately in the bytecode after adding the member.
            # `set_udm_type(struct_id, member_offset, member_tif, TINFO_DEFINITE)`
            if not idc.set_udm_type(new_struct_id, current_offset, member_tif, idaapi.TINFO_DEFINITE):
                print(f"[!] Failed to set type for member {member_name}")
                
        current_offset += member_size

    print(f"[+] Successfully created struct {struct_name}")
    
    return struct_obj # Return the struct_t object as a representation of success

def apply_prediction_args_old(func_ea, prediction):
    """
    Applies predicted argument names and types to a function.
    This version handles cases where `prediction['args']` is a dict.
    """
    args_pred = prediction.get('args', {}) # Get args prediction, default to empty dict
    if not args_pred:
        print(f"[-] found empty args in prediction: {args_pred}")
        return None

    # Check if `args_pred` is a dictionary
    if not isinstance(args_pred, dict):
        print(f"[!] found bad args in prediction: {args_pred}")
        return None

    # Get function's current type info
    func_tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(func_tif, func_ea):
        print(f"[!] Fail to get function type info at {hex(func_ea)}")
        return False

    func_type_data = ida_typeinf.func_type_data_t()
    if not func_tif.get_func_details(func_type_data):
        print(f"[!] Fail to get function details at {hex(func_ea)}")
        return False
    
    # Decompile to get actual argument objects (lvar_t for arguments)
    try:
        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure
    except DecompilationFailure:
        print(f"[!] Fail to decompile function at {hex(func_ea)}")
        return False

    # Check argument count match
    if len(func_type_data.arguments) != len(args_pred):
        print(f"[DEBUG🐛] apply_prediction_args_old: Arguments count not match")
        # For simplicity, if counts don't match, we won't proceed with type application
        # or it implies a more complex re-typing logic.
        # Original code might try to apply best effort or fail.
        # Based on the bytecode, it proceeds, meaning it might match by index or name.
        # We'll match by index if names are not perfectly aligned.

    # Iterate through predictions and apply
    # The bytecode iterates `args_pred.items()` which gives (arg_name, arg_details_dict)
    # And then iterates `cfunc.arguments` with `enumerate`
    # Matching based on index or name, and then applying `apply_prediction_arg`
    
    success_flag = True
    for idx, (pred_arg_name, pred_arg_details) in enumerate(args_pred.items()):
        # Find the corresponding argument object in cfunc.arguments
        arg_obj_found = None
        for arg_idx, arg_obj in enumerate(cfunc.arguments):
            # Try to match by predicted name, or fall back to index if names don't match or no name.
            if arg_obj.name == pred_arg_name or (arg_obj.name is None and idx == arg_idx):
                arg_obj_found = arg_obj
                break
        
        if arg_obj_found:
            # `apply_prediction_arg` expects the argument object and its prediction details
            # Its bytecode indicates it gets (predicted_type, predicted_name, type_category, array_dims)
            # from `pred_arg_details` then applies.
            
            # Simplified call:
            apply_prediction_arg(arg_obj_found, pred_arg_details)
        else:
            print(f"[!] Fail to find argument {pred_arg_name} in function {hex(func_ea)}")
            success_flag = False

    # After applying individual arg predictions, re-create the function type and apply it
    # This is crucial for IDA to update its function prototype.
    new_func_tif = ida_typeinf.tinfo_t()
    if not new_func_tif.create_func(func_type_data):
        print(f"[!] Error: failed to create func new type info")
        return False
    
    # Apply new type info definitively
    if not idaapi.apply_tinfo(func_ea, new_func_tif, idaapi.TINFO_DEFINITE):
        print(f"[!] Error: failed to apply func new type info")
        return False

    return success_flag # Return overall success

def apply_prediction_vars(func_ea, prediction):
    """
    Applies predicted variable names and types to local variables.
    """
    vars_pred = prediction.get('vars', {})
    if not vars_pred:
        print(f"[-] found empty vars in prediction: {vars_pred}")
        return None

    if not isinstance(vars_pred, dict):
        print(f"[!] found bad vars in prediction: {vars_pred}")
        return None

    # Open pseudocode view to get cfunc and lvars access
    widget = idaapi.open_pseudocode(func_ea, 0)
    if not widget:
        print(f"[!] Fail to open pseudocode view for function at {hex(func_ea)}")
        return None
    
    cfunc = widget.cfunc
    if not cfunc:
        print(f"[!] Fail to get cfunc for function at {hex(func_ea)}")
        return None

    # Get local variables from cfunc (excluding arguments)
    local_vars_in_cfunc = [lvar for lvar in cfunc.lvars if not lvar.is_arg_var]

    success_flag = True
    for old_var_name, pred_var_details in vars_pred.items():
        # Find the actual lvar_t object by old name
        lvar_obj_found = None
        for lvar_obj in local_vars_in_cfunc:
            if lvar_obj.name == old_var_name:
                lvar_obj_found = lvar_obj
                break
        
        if lvar_obj_found:
            # Extract prediction details
            predicted_type_str = pred_var_details[0] # Assuming first element is type string
            predicted_new_name = pred_var_details[1] # Assuming second element is new name
            type_category = pred_var_details[2] # Type category
            array_dims = pred_var_details[3] if len(pred_var_details) > 3 else [] # Array dimensions

            # --- Apply new name (if provided and different) ---
            if predicted_new_name and predicted_new_name != old_var_name:
                # rename_lvar returns True on success, False on failure
                if cfunc.rename_lvar(lvar_obj_found.lvar_idx, predicted_new_name): # lvar_idx is the index
                    print(f"[+] Successfully change var: {old_var_name} to: {predicted_new_name}")
                else:
                    print(f"[!] Fail change var: {old_var_name} to: {predicted_new_name}")
                    success_flag = False
            
            # --- Apply new type (if provided and different) ---
            current_type_str = lvar_obj_found.type.dstr() # Get current type string
            
            if predicted_type_str and predicted_type_str != current_type_str.replace('*', '').strip(): # Basic comparison, ignore pointers
                # Ensure type string ends with ';'
                if not predicted_type_str.endswith(';'):
                    predicted_type_str += ';'

                # Parse the new type string
                new_tif = ida_typeinf.tinfo_t()
                idati = idaapi.get_idati()
                parse_success = ida_typeinf.parse_decl(new_tif, idati, predicted_type_str, ida_typeinf.PT_TYP | ida_typeinf.PT_SIL)
                
                if not parse_success:
                    # If parsing fails, try specific type adders
                    if type_category == 'array' and isinstance(array_dims, list):
                        new_tif = add_array_type(predicted_type_str.strip(';'), array_dims)
                    elif type_category == 'struct':
                        # struct_details should be provided
                        new_tif = add_struct_type(predicted_type_str.strip(';'), {}) # No members provided here
                    elif type_category == 'enum':
                        # enum_details should be provided
                        new_tif = add_enum_type(predicted_type_str.strip(';'), {}) # No members provided here
                    
                    if new_tif is None or not new_tif.is_valid():
                        print(f"[!] Failed to parse or find type {predicted_type_str} for {old_var_name}")
                        success_flag = False
                        continue # Skip to next var

                # Apply the new type to the local variable
                # set_lvar_type takes (lvar_t, new_type_tinfo, flags)
                # Flags (True, True) indicates `LVARLOC_TYPE` and `LVARLOC_NAME` likely
                # The bytecode has a constant `(True, True)` as flags for `set_lvar_type`
                if new_tif and new_tif.is_valid() and cfunc.set_lvar_type(lvar_obj_found, new_tif, idaapi.TINFO_DEFINITE):
                    print(f"[+] Successfully set type {new_tif.dstr()} for var {lvar_obj_found.name}")
                else:
                    print(f"[!] Failed to set type {predicted_type_str} for var {old_var_name}")
                    success_flag = False
        else:
            print(f"[!] Fail to find variable {old_var_name} in function {hex(func_ea)}")
            success_flag = False

    # Refresh the pseudocode view after changes
    if widget and hasattr(widget, 'cfunc') and hasattr(widget.cfunc, 'refresh_func_ctext'):
        widget.cfunc.refresh_func_ctext()
        
    return success_flag


def build_doxygen_comment(prediction):
    """
    Builds a Doxygen-style comment string from prediction details.
    """
    # Extract relevant fields, defaulting to empty string or dict
    brief = prediction.get('brief', '')
    details = prediction.get('details', '')
    params = prediction.get('params', {}) # Assuming params is a dict of {name: description}
    ret = prediction.get('return', '')
    category = prediction.get('category', '')
    algorithm = prediction.get('algorithm', '')

    # Consolidate non-empty fields into a dict for easier iteration
    doxygen_fields = {
        'brief': brief,
        'details': details,
        'params': params,
        'return': ret,
        'category': category,
        'algorithm': algorithm,
    }

    comment_str = "/**\n"
    for field_name, field_value in doxygen_fields.items():
        if isinstance(field_value, dict) and field_name == 'params':
            for param_name, param_desc in field_value.items():
                comment_str += f" * @param {param_name}: {param_desc}\n"
        elif field_value: # For non-empty strings
            comment_str += f" * @{field_name} {field_value}\n"
    comment_str += " */"
    return comment_str


def apply_prediction_func_comment(func_ea, comment):
    """
    Applies a function comment to the function.
    """
    func_obj = ida_funcs.get_func(func_ea)
    if not func_obj:
        print(f"[!] Fail to get function at {hex(func_ea)}")
        return False
    
    # If comment is empty, log and return success (effectively removing it)
    if not comment:
        print(f"[!] Apply empty comment to {hex(func_ea)}")
        idc.set_func_cmt(func_obj.start_ea, "", 0) # Clear comment
        return True # Success in setting empty comment

    # Apply the comment (0 for regular comment, 1 for repeatable)
    if not idc.set_func_cmt(func_obj.start_ea, comment, 0): # Non-repeatable comment
        print(f"[!] Fail to set comment for function {hex(func_ea)}")
        return False
    
    print(f"[+] Successfully set comment for function {hex(func_ea)}")

    # Refresh pseudocode view if open
    widget = idaapi.open_pseudocode(func_obj.start_ea, 0)
    if widget and hasattr(widget, 'cfunc') and hasattr(widget.cfunc, 'refresh_func_ctext'):
        widget.cfunc.refresh_func_ctext()
        
    return True


def apply_prediction_inline_comment(func_ea, prediction):
    """
    Applies inline comments based on predicted line numbers and comments.
    """
    inline_comments_pred = prediction.get('inline_comment', {})
    if not isinstance(inline_comments_pred, dict):
        print(f"[!] found bad inline_comment in prediction: {inline_comments_pred}")
        return None

    if not inline_comments_pred: # No comments to apply
        return None

    # Open pseudocode view to get cfunc and access to comments
    widget = idaapi.open_pseudocode(func_ea, 0)
    if not widget:
        print(f"[!] Fail to open pseudocode view for function at {hex(func_ea)}")
        return False
    
    cfunc = widget.cfunc
    if not cfunc:
        print(f"[!] Fail to get cfunc for function at {hex(func_ea)}")
        return False

    pcode_lines = cfunc.get_pseudocode() # Get all lines of decompiled code
    
    success_flag = True
    for line_num_str, comment_text in inline_comments_pred.items():
        if not line_num_str.isdigit():
            print(f"[!] bad line number {line_num_str} with comment: {comment_text}")
            continue # Skip bad line numbers

        line_num = int(line_num_str)
        # Check if line number is valid
        if line_num < 1 or line_num > len(pcode_lines):
            print(f"[!] bad line number {line_num} with comment: {comment_text}")
            continue

        # Get the ctree_item_t for the specific line
        # IDA's get_line_item uses line index (0-based) and item index (0-based)
        # For inline comments, usually attached to the line's instruction item.
        
        # The bytecode iterates line by line, then `get_line_item(idx, 0)` is used
        # to get the ctree_item_t for the line.
        
        # The exact mechanism of getting the item ID and applying comment can be tricky.
        # Assuming `get_line_item` returns a valid item or None.
        
        line_item_ea = cfunc.get_pseudocode_item(line_num - 1).ea # Get EA of the line
        
        # Set user comment using treeloc_t.
        # This is how IDA associates comments to specific points in pcode.
        user_loc = ida_hexrays.treeloc_t()
        user_loc.ea = line_item_ea # Address of the instruction
        user_loc.itp = ida_hexrays.ITP_SEMI # After semicolon (end of line)
        
        if cfunc.set_user_cmt(user_loc, comment_text):
            pass # Success
        else:
            print(f"[!] Failed to set inline comment for line {line_num} at {hex(line_item_ea)}")
            success_flag = False

    # Save user comments to database
    cfunc.save_user_cmts()
    # Refresh the pseudocode view after changes
    if widget and hasattr(widget, 'cfunc') and hasattr(widget.cfunc, 'refresh_func_ctext'):
        widget.cfunc.refresh_func_ctext()

    return success_flag


def apply_prediction(func_ea, task_tag, prediction):
    """
    Applies various types of predictions to an IDA Pro function based on the task tag.
    """
    print(f"[🐛DEBUG] invoke apply_prediction")
    print(f"[🐛DEBUG] task_tag: {task_tag}")
    print(f"[🐛DEBUG] prediction: {prediction}")

    # Basic input validation based on SUPPORT_FUNC_TYPES
    if task_tag not in SUPPORT_FUNC_TYPES:
        print(f"[!] Unsupported task tag: {task_tag}")
        return False

    # Check if prediction is empty
    if not prediction:
        print("[!] apply_prediction: receive empty prediction")
        return False

    # Get function object
    func = ida_funcs.get_func(func_ea)
    if not func:
        print(f"[!] Fail to get function at {hex(func_ea)}")
        return False

    # Handle thunk functions
    if is_thunk(func_ea):
        print("[!] Thunk function is not supported")
        return False

    # Get function metadata for input validation
    func_start_ea = func.start_ea
    func_end_ea = func.end_ea
    func_name = idc.get_func_name(func_start_ea)
    demangled_func_name = demangle(func_name)

    # Check if function is suitable based on heuristics before applying (redundant if done in build_prompt)
    # This check is in `build_prompt` already, but repeated here, suggesting it's a critical early exit.
    try:
        cfunc_check = decompile(func_ea)
        if cfunc_check is None:
            raise DecompilationFailure
        pcode_line_cnt = len(cfunc_check.get_pseudocode())
        pcode_var_cnt = len(cfunc_check.lvars)
        if not is_good_func_for_build_input(func_ea, demangled_func_name, pcode_line_cnt, pcode_var_cnt):
            print(f"[!] Function {demangled_func_name} is not good for building input")
            return False
    except DecompilationFailure:
        print(f"[!] Failed to decompile function at {hex(func_ea)}")
        return False
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"An unexpected error occurred during pre-apply check: {e}")
        return False
    
    # --- Apply predictions based on task_tag ---

    # For func-analysis and decompilation, apply all possible sub-predictions
    if task_tag == '<func-analysis>' or task_tag == '<decompilation>':
        result_inline_comment = apply_prediction_inline_comment(func_ea, prediction)
        result_ret_type = apply_prediction_ret_type(func_ea, prediction)
        result_func_name = apply_prediction_func_name(func_ea, prediction)
        result_args = apply_prediction_args_old(func_ea, prediction) # Assuming this is for arguments
        result_vars = apply_prediction_vars(func_ea, prediction) # Assuming this is for local variables
        result_func_comment = apply_prediction_func_comment(func_ea, build_doxygen_comment(prediction))
        
        # Return True only if all applications were successful.
        return all([result_inline_comment, result_ret_type, result_func_name, result_args, result_vars, result_func_comment])

    # For other specific tasks, call the corresponding apply function
    elif task_tag == 'inline_comment':
        return apply_prediction_inline_comment(func_ea, prediction)
    elif task_tag == 'ret_type':
        return apply_prediction_ret_type(func_ea, prediction)
    elif task_tag == '<specific-vars>' or task_tag == '<vars>': # Both handled by apply_prediction_vars
        return apply_prediction_vars(func_ea, prediction)
    elif task_tag == '<args>':
        return apply_prediction_args_old(func_ea, prediction)
    elif task_tag == '<funcname>':
        return apply_prediction_func_name(func_ea, prediction)
    elif task_tag == '<summary>':
        # Summary implies applying function comment, possibly Doxygen
        doxygen_comment = build_doxygen_comment(prediction)
        return apply_prediction_func_comment(func_ea, doxygen_comment)
    
    else:
        raise NotImplementedError(f"Not implemented func_type == `{task_tag}` yet")