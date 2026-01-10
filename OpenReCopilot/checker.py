# 文件名: checker.py
# ReCopilot响应解析和检查模块

import re
import os
import json
import textwrap
from collections import defaultdict

# IDA Pro API导入
try:
    import ida_hexrays
    import ida_typeinf
    from ida_hexrays import decompile, DecompilationFailure
except ImportError:
    # 如果不在IDA环境中运行，提供模拟
    class DecompilationFailure(Exception):
        pass

    def decompile(ea):
        """模拟反编译函数，仅用于测试"""
        return None

# --- Helper Functions for Parsing Model Output ---

def drop_task_tag_in_output(output: str) -> str:
    """
    Removes a potential closing XML-like tag from the last line of the output.
    This is likely to clean up model responses that might include task tags.
    """
    if not output:
        return ""
    lines = output.split('\n')
    last_line = lines[-1]
    
    # _var_var_0 = last_line
    # if '</' in _var_var_0:
    #     _var_var_0 = _var_var_0[:_var_var_0.index('</')]
    #     return '\n'.join(lines[:-1]) + '\n' + _var_var_0 # Bytecode implies this reconstruction
    
    # Simplified and more robust:
    # Find the last occurrence of '</' and take everything before it on that line
    # Then join with previous lines.
    # The original bytecode logic was a bit more convoluted if the tag wasn't there.
    # A direct translation of the bytecode's effect if the tag is found:
    if '</' in last_line:
        stripped_last_line = last_line[:last_line.index('</')]
        if len(lines) > 1:
            return '\n'.join(lines[:-1]) + '\n' + stripped_last_line
        else:
            return stripped_last_line
    return output

def find_json_by_re(output: str) -> str:
    """
    Finds JSON content within triple backticks (```json ... ```) using regex.
    Returns the last found JSON string, or an empty string if not found.
    """
    # Regex from bytecode: '```(json|JSON)?(.*?)```'
    pattern = r"```(?:json|JSON)?\s*\n?(.*?)```" # Adjusted for optional newline after language specifier
    matches = re.findall(pattern, output, re.DOTALL)
    if matches:
        # Bytecode logic: _var_var_2[-1][1]
        # re.findall with multiple groups returns a list of tuples.
        # If (json|JSON)? is group 1 and (.*?) is group 2, it takes the second element of the last tuple.
        # The provided regex ````(json|JSON)?(.*?)``` ` when used with findall,
        # will return tuples like ('json', 'content') or ('', 'content').
        # So matches[-1][1] should be correct.
        return matches[-1] # findall with one capturing group returns a list of strings
    return ""

def find_output_by_re(output: str) -> str:
    """
    Finds content within <Output>...</Output> tags using regex.
    Returns the last found content, or an empty string if not found.
    """
    # Regex from bytecode: '<Output>(.*?)</Output>'
    pattern = r"<Output>(.*?)</Output>"
    matches = re.findall(pattern, output, re.DOTALL)
    if matches:
        return matches[-1] # Returns the content of the last <Output> tag
    return ""

def parse_model_response_json(json_str_input: str):
    """
    Parses a string potentially containing JSON, possibly wrapped in tags or markdown.
    """
    if not json_str_input:
        print("[!] Empty model response")
        return None

    # First, try to extract content from <Output> tags
    processed_str = find_output_by_re(json_str_input)
    if not processed_str: # If no <Output> tag, use the original input
        processed_str = json_str_input
    
    processed_str = processed_str.strip()
    processed_str = drop_task_tag_in_output(processed_str) # Remove potential closing task tags
    processed_str = processed_str.strip()

    # Try to find JSON within ```json ... ```
    json_from_re = find_json_by_re(processed_str)
    if json_from_re:
        processed_str = json_from_re.strip()
    else: # If no ```json``` block, check for raw ``` ```
        if processed_str.startswith("```") and processed_str.endswith("```"):
            processed_str = processed_str[3:-3].strip()
            # Further strip an optional newline immediately after ``` and before ```
            if processed_str.startswith("\n"):
                processed_str = processed_str[1:]
            if processed_str.endswith("\n"):
                processed_str = processed_str[:-1]
            processed_str = processed_str.strip()


    # Final check for common markdown code block start/end
    if processed_str.startswith("```json"):
        processed_str = processed_str[len("```json"):].strip() # remove ```json
    if processed_str.startswith("```"): # In case it was just ``` without language
        processed_str = processed_str[3:].strip()
    if processed_str.endswith("```"):
        processed_str = processed_str[:-3].strip()

    if not processed_str:
        print("[!] Empty content after stripping tags.")
        return None
        
    try:
        return json.loads(processed_str)
    except Exception as e: # Bytecode catches generic Exception
        print(f"[!💥] parser json error: {e} for string: '{processed_str[:100]}...'")
        return None

def parse_model_response_str(response: str):
    """
    Parses a string potentially containing a plain string output, 
    possibly wrapped in tags or markdown.
    """
    if not response:
        print("[!] Empty model response")
        return None

    # First, try to extract content from <Output> tags
    processed_str = find_output_by_re(response)
    if not processed_str: # If no <Output> tag, use the original input
        processed_str = response
        
    processed_str = processed_str.strip()
    processed_str = drop_task_tag_in_output(processed_str) # Remove potential closing task tags
    processed_str = processed_str.strip()

    # Check for triple backticks
    if processed_str.startswith("```"):
        # Try to find the first newline after ```
        newline_idx = processed_str.find('\n')
        if newline_idx != -1:
            processed_str = processed_str[newline_idx + 1:] # Content after the first newline
        else: # No newline, maybe just ```content```
            processed_str = processed_str[3:] 
            
    if processed_str.endswith("```"):
        processed_str = processed_str[:-3]
        
    processed_str = processed_str.strip()

    if not processed_str: # If after all stripping, it's empty
        print("[!💥] not found <Output>...</Output> or content within ```") # Bytecode message
        return None
        
    return processed_str

# ... (parse_var_pred, vars_check_and_refine, etc. would be very complex to fully decompile accurately
# without more context on their exact input/output formats and IDA interactions.
# The stubs below reflect the names and argument counts.)

def parse_var_pred(var_pred_item):
    """
    Parses a single variable prediction item.
    Expected input format is complex and can be a list or dict.
    Aims to return a tuple: (type_str, name_str, complex_type_indicator, type_details)
    """
    # This function is highly complex in bytecode due to handling many input variations.
    # A simplified conceptual version:
    print(f"[SIMULATED] parse_var_pred for: {var_pred_item}")
    if isinstance(var_pred_item, list) and len(var_pred_item) >= 2:
        type_str = str(var_pred_item[0] or "")
        name_str = str(var_pred_item[1] or "")
        is_complex_type = ""
        type_details = {}
        if len(var_pred_item) > 2 and var_pred_item[2]:
            is_complex_type = str(var_pred_item[2]).lower()
        if len(var_pred_item) > 3 and var_pred_item[3]:
            type_details = var_pred_item[3]

        # Basic cleanup based on observed patterns
        if type_str.startswith("struct "):
            type_str = type_str[len("struct "):].strip()
            if not is_complex_type: is_complex_type = "struct"
        elif type_str.startswith("enum "):
            type_str = type_str[len("enum "):].strip()
            if not is_complex_type: is_complex_type = "enum"
        
        type_str = type_str.replace('*', '').strip() # Remove pointers for base type name

        return type_str, name_str, is_complex_type, type_details
    elif isinstance(var_pred_item, dict):
        # Handle dictionary case if necessary based on actual usage
        pass
    return None, None, None, None # Default error return

def vars_check_and_refine(var_pred_items, return_type='list'):
    """
    var_pred_items: [{'original':[type, name], 'prediction':[type, name, is_complex_type, typedetails]}, ...]
                   or a list of prediction lists if is_no_original_list is true.
    return_type: 'list' or 'dict'
    """
    # Docstring from bytecode:
    # var_pred_items: [
    #     {'original':[type, name], 'prediction':[type, name, is_complex_type, typedetails]},
    #     ...
    # ]
    print(f"[SIMULATED] vars_check_and_refine, return_type: {return_type}")
    refined_list = []
    refined_dict = {}

    if not isinstance(var_pred_items, (list, dict)): # Bytecode implies it handles dict input too for 'vars'
        return [] if return_type == 'list' else {}

    items_to_process = []
    if isinstance(var_pred_items, dict): # Convert dict to list of dicts
        items_to_process = [{"original": [None, k], "prediction": v} for k, v in var_pred_items.items()] # Assuming key is original name
    else: # Is a list
        if is_no_original_list(var_pred_items): # List of prediction_lists
            items_to_process = [{"original": [None, None], "prediction": pred} for pred in var_pred_items]
        else: # List of dicts {'original': ..., 'prediction': ...}
            items_to_process = var_pred_items

    for item_dict in items_to_process:
        if not isinstance(item_dict, dict): continue

        original_info = item_dict.get('original', [None, None])
        prediction_info = item_dict.get('prediction')

        if not isinstance(original_info, list) or len(original_info) < 2:
            original_name = None
        else:
            original_name = original_info[1] # Second element is name

        parsed_pred = parse_var_pred(prediction_info) # Returns (type, name, complex_indicator, details)
        
        if parsed_pred[0] is not None: # If type is not None (parsing was somewhat successful)
            if return_type == 'list':
                refined_list.append([original_name, parsed_pred])
            else: # dict
                # Bytecode uses the *predicted* name as key if original_name is missing
                # This part is complex in bytecode with multiple fallbacks
                key_name = parsed_pred[1] if parsed_pred[1] else original_name
                if key_name: # Only add if we have a valid key
                     refined_dict[key_name] = parsed_pred
    
    return refined_list if return_type == 'list' else refined_dict


def funcname_check_and_refine(funcname_preds):
    """
    Refines function name predictions.
    Can be a string or a list of dicts: [{'original': 'old_name', 'prediction': 'new_name'}, ...]
    """
    print(f"[SIMULATED] funcname_check_and_refine for: {funcname_preds}")
    if isinstance(funcname_preds, str):
        name = funcname_preds.strip()
        if name.endswith("<funcname>"): # Based on a constant in disassembly
            name = name[:-len("<funcname>")].strip()
        return name # Returns a single refined name string
    elif isinstance(funcname_preds, list):
        refined_list = []
        for item in funcname_preds:
            if isinstance(item, dict):
                original = item.get('original', '')
                prediction = item.get('prediction', '')
                if prediction: # Only add if there's a prediction
                     refined_list.append([original, prediction])
            # Bytecode does not seem to handle other list item types for funcname
        return refined_list
    return [] # Default for list if input is not str or list, or list is malformed


def summary_check_and_refine(summary_pred):
    """
    Refines the summary prediction dictionary.
    Fills missing fields and formats text.
    """
    if not summary_pred or not isinstance(summary_pred, dict):
        return {}

    # Keys from constants: 'brief', 'details', 'params', 'return', 'category', 'algorithm', 'inline_comment'
    # Default values also from constants.
    refined = {
        'brief': summary_pred.get('brief', ''),
        'details': summary_pred.get('details', ''),
        'params': summary_pred.get('params', {}), # Default to empty dict
        'return': summary_pred.get('return', ''),
        'category': summary_pred.get('category', 'none'),
        'algorithm': summary_pred.get('algorithm', 'none'),
        'inline_comment': summary_pred.get('inline_comment', {}) # Default to empty dict
    }

    # Text wrapping (from bytecode constants: width=70, replace_whitespace=False)
    for key in ['brief', 'details', 'return']:
        if isinstance(refined[key], str):
            refined[key] = textwrap.fill(refined[key], width=70, replace_whitespace=False)
            
    if isinstance(refined['params'], dict):
        for param_name, param_desc in refined['params'].items():
            if isinstance(param_desc, str):
                refined['params'][param_name] = textwrap.fill(param_desc, width=70, replace_whitespace=False)
    
    # Inline comments seem to be a dict of {line_num_str: comment_str}
    # Bytecode iterates through it, no specific refinement shown other than ensuring keys are strings
    if isinstance(refined['inline_comment'], dict):
        cleaned_inline_comments = {}
        for key, val in refined['inline_comment'].items():
            # Bytecode checks if key.isdigit()
            if isinstance(key, str) and key.isdigit() and isinstance(val, str):
                cleaned_inline_comments[key] = val
            elif isinstance(key, int) and isinstance(val, str): # Allow int keys too
                cleaned_inline_comments[str(key)] = val

        refined['inline_comment'] = cleaned_inline_comments

    return refined

def is_no_original_list(items: list) -> bool:
    """
    Checks if a list of items (predictions) does not contain 'original' information.
    Each item in 'items' is expected to be a list. If all these inner lists
    have length <= 2, it's considered to be "no original" (i.e., just prediction).
    Prediction format: [type, name, is_complex_type, typedetails] (len 4)
    If only [type, name] is present for all, it means no original info was paired.
    """
    # Docstring from bytecode:
    # items: [pred_list_1, pred_list_2, ...]
    # pred_list_x: [type, name, is_complex_type, typedetails]
    if not isinstance(items, list):
        return False # Or raise error, bytecode implies it continues
    for item in items:
        if not isinstance(item, list) or len(item) > 2: # If any item has more than 2 elements, it might have original info
            return False
    return True


def get_func_args(func_ea: int):
    """
    Gets a list of argument names for the given function.
    """
    try:
        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure
        
        arg_names = []
        if hasattr(cfunc, 'arguments'): # arguments is a list of lvar_t
            for arg_lvar in cfunc.arguments:
                if arg_lvar and hasattr(arg_lvar, 'name') and arg_lvar.name:
                    arg_names.append(arg_lvar.name)
        return arg_names
    except DecompilationFailure:
        print(f"[!] Fail to decompile function at: {hex(func_ea)}")
        return None


def get_func_args_vars(func_ea: int):
    """
    Gets lists of argument names and local variable names for the given function.
    Returns (arg_names_list, local_vars_names_list) or (None, None).
    """
    try:
        cfunc = decompile(func_ea)
        if cfunc is None:
            raise DecompilationFailure

        arg_names = []
        if hasattr(cfunc, 'arguments'):
            for arg_lvar in cfunc.arguments:
                if arg_lvar and hasattr(arg_lvar, 'name') and arg_lvar.name:
                    arg_names.append(arg_lvar.name)
        
        local_vars_names = []
        if hasattr(cfunc, 'lvars'): # lvars is a list of lvar_t
            for lvar in cfunc.lvars:
                if lvar and hasattr(lvar, 'name') and lvar.name and \
                   hasattr(lvar, 'is_arg_var') and not lvar.is_arg_var:
                    local_vars_names.append(lvar.name)
        
        return arg_names, local_vars_names
        
    except DecompilationFailure:
        print(f"[!] Fail to decompile function at: {hex(func_ea)}")
        return None, None


def func_analysis_check_and_refine(func_analysis_pred: dict, arg_names: list = None, var_names: list = None) -> dict:
    """
    Checks and refines the 'func-analysis' prediction.
    It processes 'funcname', 'ret_type', 'args', 'vars', and 'summary'.
    """
    refined_response = {}
    if not func_analysis_pred or not isinstance(func_analysis_pred, dict):
        return refined_response # Return empty dict if input is bad

    # Refine summary
    refined_response.update(summary_check_and_refine(func_analysis_pred)) # summary_check_and_refine returns a dict

    # Refine funcname
    funcname_pred = func_analysis_pred.get('funcname', '')
    refined_response['funcname'] = funcname_check_and_refine(funcname_pred)
    
    # Refine ret_type (assuming it's a string)
    ret_type_pred = func_analysis_pred.get('ret_type', '')
    if isinstance(ret_type_pred, str):
        refined_response['ret_type'] = ret_type_pred.strip() # Simple strip for now
    else:
        refined_response['ret_type'] = ''


    # Refine args
    args_pred_raw = func_analysis_pred.get('args', []) # Default to empty list
    if arg_names is None: arg_names = [] # Ensure arg_names is a list

    refined_args_list = []
    if isinstance(args_pred_raw, list):
        if is_no_original_list(args_pred_raw): # List of just predictions
            for i, pred_val in enumerate(args_pred_raw):
                original_name = arg_names[i] if i < len(arg_names) else f"a{i+1}" # Fallback original name
                # parse_var_pred expects a list [type, name, complex_type_indicator, details]
                # If pred_val is just a string, it needs to be a type for an unnamed arg
                # This part is tricky to perfectly match bytecode without seeing more usage
                if isinstance(pred_val, str): # Assume it's a type string
                    parsed_val = parse_var_pred([pred_val, original_name])
                elif isinstance(pred_val, list):
                    parsed_val = parse_var_pred(pred_val)
                else:
                    parsed_val = (None,None,None,None)

                if parsed_val[0]: # If type is valid
                    refined_args_list.append({'original': [None, original_name], 'prediction': parsed_val})
        elif all(isinstance(item, dict) for item in args_pred_raw): # List of dicts
             refined_args_list = vars_check_and_refine(args_pred_raw, return_type='list') # Bytecode indicates list
    elif isinstance(args_pred_raw, dict): # Dict of {original_name: prediction_list}
        temp_list_of_dicts = [{'original': [None, k], 'prediction': v} for k,v in args_pred_raw.items()]
        refined_args_list = vars_check_and_refine(temp_list_of_dicts, return_type='list')
    
    refined_response['args'] = refined_args_list


    # Refine vars (similar logic to args)
    vars_pred_raw = func_analysis_pred.get('vars', [])
    if var_names is None: var_names = []

    refined_vars_list = []
    if isinstance(vars_pred_raw, list):
        if is_no_original_list(vars_pred_raw):
            for i, pred_val in enumerate(vars_pred_raw):
                original_name = var_names[i] if i < len(var_names) else f"v{i+1}"
                if isinstance(pred_val, str):
                    parsed_val = parse_var_pred([pred_val, original_name])
                elif isinstance(pred_val, list):
                    parsed_val = parse_var_pred(pred_val)
                else:
                    parsed_val = (None,None,None,None)
                if parsed_val[0]:
                    refined_vars_list.append({'original': [None, original_name], 'prediction': parsed_val})
        elif all(isinstance(item, dict) for item in vars_pred_raw):
            refined_vars_list = vars_check_and_refine(vars_pred_raw, return_type='list')
    elif isinstance(vars_pred_raw, dict):
        temp_list_of_dicts = [{'original': [None, k], 'prediction': v} for k,v in vars_pred_raw.items()]
        refined_vars_list = vars_check_and_refine(temp_list_of_dicts, return_type='list')

    refined_response['vars'] = refined_vars_list
    
    return refined_response


def response_check_and_refine(response, task_tag: str, arg_names=None, var_names=None):
    """
    Main function to check and refine the model's response based on the task tag.
    """
    if not response:
        print("[!] Empty model response")
        return None

    if task_tag == '<func-analysis>':
        if arg_names is None or var_names is None: # Bytecode asserts this
            print("[!] Error: need pass arg_names and var_names for checking response of func-analysis task")
            # The bytecode would raise an AssertionError. Here, we might return None or raise error.
            return None 
        if not isinstance(response, dict): # func-analysis expects a dict
            return func_analysis_check_and_refine({}, arg_names, var_names) # Pass empty dict
        return func_analysis_check_and_refine(response, arg_names, var_names)
    
    elif task_tag == '<vars>':
        # vars_check_and_refine expects a list of items or a dict
        # The bytecode defaults return_type to 'dict' for this task_tag
        return vars_check_and_refine(response, return_type='dict') 
    
    elif task_tag == '<args>':
        return vars_check_and_refine(response, return_type='dict')

    elif task_tag == '<specific-vars>':
        return vars_check_and_refine(response, return_type='dict')
        
    elif task_tag == '<funcname>':
        return funcname_check_and_refine(response)
        
    elif task_tag == '<summary>':
        if not isinstance(response, dict): # summary_check_and_refine expects a dict
            return summary_check_and_refine({})
        return summary_check_and_refine(response)
        
    else:
        raise NotImplementedError(f"Not implemented task tag: {task_tag}")


def split_pred_to_var_arg(func_ea: int, response):
    """
    Splits the 'vars' predictions in the response into 'args' and 'vars'
    based on whether they are actual function arguments.
    Needs to run with ida_execute.
    """
    result = {'vars': {}, 'args': {}}
    if not response or 'vars' not in response:
        return result

    try:
        cfunc = decompile(func_ea)
        if not cfunc:
            raise DecompilationFailure
        
        actual_arg_names = set()
        if hasattr(cfunc, 'arguments'):
            for lvar in cfunc.arguments:
                if lvar and lvar.name:
                    actual_arg_names.add(lvar.name)
        
        # Iterate through the 'vars' in the response
        # The response['vars'] can be a list of dicts or a dict
        vars_to_process = response['vars']
        if isinstance(vars_to_process, list) and all(isinstance(item, dict) for item in vars_to_process):
            # Convert list of dicts to a single dict for easier processing here
            # Assuming 'original' name is the key we care about, or predicted name if original is missing
            temp_dict = {}
            for item in vars_to_process:
                # Original: [type, name], Prediction: [type, name, complex_type, details]
                original_name = item.get('original', [None, None])[1]
                predicted_name = item.get('prediction', [None, None, None, None])[1]
                key_name = original_name if original_name else predicted_name
                if key_name:
                    temp_dict[key_name] = item['prediction'] # Store the prediction part
            vars_to_process = temp_dict


        if isinstance(vars_to_process, dict):
            for var_name, pred_details in vars_to_process.items():
                # Check if var_name (from prediction key or original name) is an actual argument
                is_an_arg = False
                for lvar in cfunc.lvars: # Iterate actual lvars to find a match
                    if lvar.name == var_name and lvar.is_arg_var:
                        is_an_arg = True
                        break
                
                if is_an_arg:
                    result['args'][var_name] = pred_details
                else:
                    result['vars'][var_name] = pred_details
        else:
            # If response['vars'] is not a dict or list of dicts as expected, return default
            pass 
            
    except DecompilationFailure:
        print(f"[!] Fail to decompile function at: {hex(func_ea)}")
        # Returns the empty initialized result
        
    return result