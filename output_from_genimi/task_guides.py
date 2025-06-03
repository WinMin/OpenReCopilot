import json
import os
import random
# PyArmor 相关的 __assert_armored__, __pyarmor_enter_XXXX__, __pyarmor_exit_XXXX__ 调用已省略

# --- 任务指南字符串 ---
# (这些是直接从字节码的常量池中提取的超长字符串)

func_analysis_guide = """1. Understand the Task 
What should be analyzed in the task.
List the objects within the target function should be analyzed base on the specific task, such as args, vars, func name, etc.

2. Inspect the Calling Context
Describe the calling relationship of the functions.
If a function in context is a library function, describe its functionality and definition (including arguments and return type).

3. Callsites Analysis
Analyze each caller of the target function, describing each argument passed into the target function.
Analyze each callsite within the target function, describing the arguments passed into each callee function.

4. Analyze Function Semantics
Analyze the behavior of each function, end with detailed analysis of the target function.

5. Data Flow Analysis
Inferring the propagation path of each target variable and argument (cross-function and inter-procedural analysis).

6. Usage Patterns
Summarize the usage patterns of each variable and argument in target function.
Based on the usage patterns, judge if the argument and variable is a complex type, such as struct, enum, array, etc.

7. Type Inference
Infer the type of each argument and variable within target function base on the data flow analysis and usage patterns.
If the type is structure, enum, or array, infer the detailed type information: structure fields, enum list, array length.

8. Name Recovery
Recover the name of each argument and variable within target function base on the analysis above.

9. Return Type Inference
Infer the return type of the target function based on the analysis above.

10. Function Name Recovery
If one context function's name is stripped (e.g., sub_0xFuncAddr), infer the possible function name based on the analysis above.
Infer the possible name for target function based on the analysis above, only when the function name is stripped.

11. Comment Generation
- a. Generate doxygen comments for the whole target function based on the analysis above, including brief, detailed, parameters, return.
- b. Generate inline comments (end of the line) only for the target function to help user understand the code. Only comment on the key lines, such as some callsites, some important variables and usages, beginning of some loops, etc. LESS IS BETTER!

12. Algorithm and Category Analysis
Analyze whether the target function implements a specific algorithm, or is a part of a specific algorithm.
Analyze what category the target function belongs to, such as logging, network, crypto, data processing, etc.
If it is not one of the well-defined ones, or if you are not sure, use "none".

13. Review and Summary
Review the analysis check reasoning process.
Describe the key basis for inferring each result above.
Summarize the final results wrapped with <Output>...</Output> in JSON format, such as:
<Output>
{
    "ret_type": "int",
    "funcname": "foo", // recovered meaningful function name for meaningless original name
    "args": {
        "a1": ["int","name1","",{}], // type, name, is_complex_type?, and struct or enum details
        "a2": ["struct_type_a *","name2","struct",{"struct_type_a": [
                ["int","field1",4], // field type, field name, field size
                ["char","field2",1],
                ...
                ]}
            ],
        "a3": ["enum_type_b","name3","enum",{"enum_type_b": [
                ["field1","value1",4], // item name, value, and size
                ["field2","value2",4],
                ...
                ]}
            ],
        "a4": ["char","name4","array","4,4"], // array type, name, array size
        "a5@del_arg": [], // delete the argument erroneously recovered by decompiler
        "a6@add_arg": [], // add the argument erroneously omitted by decompiler
        ...
    },
    "vars": {
        "var1": ["int","name5","",{}],
        "var2": ["struct_type_b","name6","struct",{"struct_type_b": [
                ["int","field3",4],
                ["char","field4",1],
                ...
                ]}
            ],
        ...
    },
    "brief": "brief description",
    "details": "detailed description",
    "params": {
        "a1": "comment for a1",
        "a2": "comment for a2",
        ...
    },
    "return": "return description",
    "inline_comment": {
        "3": "comment for L3",
        "5": "comment for L5",
        ...
    },
    "category": "functional category or none",
    "algorithm": "algorithm name or none"
}
</Output>
The prediction of the variable/argument is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable/argument is a complex type, such as struct, enum, and array, keep "" if not.
The <Output>...</Output> shoud be the end of the reasoning process, and do not append more explain after it.
"""

decompilation_guide = """1. Understand the Task 
What should be analyzed in the task.
<decompilation>: Given a function in decompiled pseudocode, improve the pseudocode, make it closer to source code and more understandable, including doxygen comment, new complex type define (recovery by your analysis), and the source code function.

2. Inspect the Calling Context
Describe the calling relationship of the functions.
If a function in context is a library function, describe its functionality and definition (including arguments and return type).

3. Callsites Analysis
Analyze each caller of the target function, describing each argument passed into the target function.
Analyze each callsite within the target function, describing the arguments passed into each callee function.

4. Analyze Function Semantics
- a. Analyze the behavior of each function, end with detailed analysis of the target function. Start from the calling context, and then analyze the target function based on the calling context.
- b. List each functionality implementation within the target function in detail.

5. Algorithm and Category Analysis
Analyze whether the target function implements a specific algorithm, or is a part of a specific algorithm.
Analyze what category the target function belongs to, such as logging, network, data processing, etc.

6. Data Flow Analysis
Inferring the propagation path of each key variable and argument within target function (cross-function and inter-procedural analysis).

7. Usage Patterns
Summarize the usage patterns of each key variable and argument in target function.
Based on the usage patterns, judge if the argument and variable is a complex type, such as struct, enum, array, etc.

8. Variable Name and Type Inference
- a. Infer the type of key argument and variable within target function base on the data flow analysis and usage patterns.
If the type is structure, enum, or array, infer the detailed type information: structure fields, enum list, array length.
- b. Recover the name of each argument and variable within target function base on the analysis above.

9. Code Structure Analysis
Analyze the code structure and patterns of the target function, and present possible original code structure in its source code.

10. Review and Summary
Review the analysis check reasoning process.
Output the final source code with Doxygen comment wrapped with <Output>...</Output>, such as:
<Output>
```C
/**
 * @brief brief description
 * @details detailed description
 * @param arg1 comment for arg1
 * @param arg2 comment for arg2
 * ...
 * @return return description
 * @category category
 * @algorithm algorithm
 */
struct struct_type_a { // present the complex types recovered in the analysis
    ...
}
void foo(int arg1, struct_type_a arg2, ...) {
    ...
}
&lt;/Output>
The &lt;Output>...&lt;/Output> shoud be the end of the reasoning process, and do not append more explain after it."""

specific_vars_guide = """

Understand the Task
What should be analyzed in the task.
List the objects within the target function should be analyzed base on the specific task, such as args, vars, func name, etc.

Inspect the Calling Context
Describe the calling relationship of the functions.
If a function in context is a library function, describe its functionality and definition (including arguments and return type).

Callsites Analysis
Analyze each caller of the target function, describing each argument passed into the target function.
Analyze each callsite within the target function, describing the arguments passed into each callee function.

Analyze Function Semantics
Analyze the behavior of each function, end with detailed analysis of the target function.

Data Flow Analysis
Inferring the propagation path of the target variable specified by task tag (cross-function and inter-procedural analysis).

Usage Patterns
Summarize the usage pattern of the target variable specified by task tag.
Based on the usage pattern, judge if the target variable is a structure, enum, array.

Type Inference
Infer the type of the target variable base on the data flow analysis and usage pattern.
If the type is structure, enum, or array, infer the detailed type information: structure fields, enum list, array length.

Name Recovery
Recover the name of the target variable, specified by task tag, base on the analysis above.

Review and Summary
Review the analysis check reasoning process.
Describe the key basis for inferring the result for the target variable.
Summarize the final results wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:

&lt;Output>
{
"original": ["__int64", "v1"],
"prediction": ["char", "name1", "", {}] // type, name, is_complex_type?, and struct or enum details
}
&lt;/Output>
or
&lt;Output>
{
"original": ["__int64", "v1"],
"prediction": ["struct_type_a *", "name1", "struct", {"struct_type_a": [
["int","field1",4], // field type, field name, field size
["char","field2",1],
...
]}
]
}
&lt;/Output>
or
&lt;Output>
{
"original": ["__uint8","v1"],
"prediction": ["enum_type_a","name1","enum",{"enum_type_a": [
["field1","value1",4], // item name, value, and size
["field2","value2",4],
...
]}
]
}
&lt;/Output>
or
&lt;Output>
{
"original": ["__int64 *","v1"],
"prediction": ["int","name1","array","4,4"] // array type, name, array size
}
&lt;/Output>
The prediction of the variable is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable is a complex type, such as struct, enum, and array, keep "" if not.
If multiple variables are analyzed, the output should be a list of the above format wrapped with one &lt;Output>...&lt;/Output>.
The &lt;Output>...&lt;/Output> shoud be the end of the reasoning process, and do not append more explain after it.
"""

ars_guide = """1. Understand the Task
What should be analyzed in the task.
List the objects within the target function should be analyzed base on the specific task, such as args, vars, func name, etc.

Inspect the Calling Context
Describe the calling relationship of the functions.
If a function in context is a library function, describe its functionality and definition (including arguments and return type).

Callsites Analysis
Analyze each caller of the target function, describing each argument passed into the target function.
Analyze each callsite within the target function, describing the arguments passed into each callee function.

Analyze Function Semantics
Analyze the behavior of each function, end with detailed analysis of the target function.

Data Flow Analysis
Inferring the propagation path of each target variable (cross-function and inter-procedural analysis).

Usage Patterns
Summarize the usage patterns of each variable in target function.
Based on the usage patterns, judge if the variable is a complex type, such as struct, enum, array, etc.

Type Inference
Infer the type of each variable within target function base on the data flow analysis and usage patterns.
If the type is structure, enum, or array, infer the detailed type information: structure fields, enum list, array length.

Name Recovery
Recover the name of each variable within target function base on the analysis above.

Review and Summary
Review the analysis check reasoning process.
Describe the key basis for inferring the result for each target variable.
Summarize the final results wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:

&lt;Output>
[
{
"original": ["__int64","v1"],
"prediction": ["int","name1","",{}] // type, name, is_complex_type?, and struct or enum details
},
{
"original": ["__int64","v2"],
"prediction": ["struct_type_a *","name2","struct",{"struct_type_a": [
["int","field1",4], // field type, field name, field size
["char","field2",1],
...
]}
]
},
{
"original": ["__uint8","v3"],
"prediction": ["enum_type_b","name3","enum",{"enum_type_b": [
["field1","value1",4], // item name, value, and size
["field2","value2",4],
...
]}
]
},
{
"original": ["__int64 *","v4"],
"prediction": ["int","name4","array","4,4"] // array type, name, array size
}
...
]
&lt;/Output>
The prediction of the variable is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable is a complex type, such as struct, enum, and array, keep "" if not.
The &lt;Output>...&lt;/Output> shoud be the end of the reasoning process, and do not append more explain after it.
"""

args_guide = """1. Understand the Task
What should be analyzed in the task.
List the objects within the target function should be analyzed base on the specific task, such as args, vars, func name, etc.

Inspect the Calling Context
Describe the calling relationship of the functions.
If a function in context is a library function, describe its functionality and definition (including arguments and return type).

Callsites Analysis
Analyze each caller of the target function, describing each argument passed into the target function.
Analyze each callsite within the target function, describing the arguments passed into each callee function.

Analyze Function Semantics
Analyze the behavior of each function, end with detailed analysis of the target function.

Data Flow Analysis
Inferring the propagation path of each target argument (cross-function and inter-procedural analysis).

Usage Patterns
Summarize the usage patterns of each argument in target function.
Based on the usage patterns, judge if the argument is a complex type, such as struct, enum, array, etc.

Type Inference
Infer the type of each argument within target function base on the data flow analysis and usage patterns.
If the type is structure, enum, or array, infer the detailed type information: structure fields, enum list, array length.

Name Recovery
Recover the name of each argument within target function base on the analysis above.

Review and Summary
Review the analysis check reasoning process.
Describe the key basis for inferring the result for each target argument.
Summarize the final results wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:

&lt;Output>
[
{
"original": ["__int64","a1"],
"prediction": ["int","name1","",{}] // type, name, is_complex_type?, and struct or enum details
},
{
"original": ["__int64","a2"],
"prediction": ["struct_type_a *","name2","struct",{"struct_type_a": [
["int","field1",4], // field type, field name, field size
["char","field2",1],
...
]}
]
},
{
"original": ["__uint8","a3"],
"prediction": ["enum_type_b","name3","enum",{"enum_type_b": [
["field1","value1",4], // item name, value, and size
["field2","value2",4],
...
]}
]
},
{
"original": ["__int64 *","a4"],
"prediction": ["int","name4","array","4,4"] // array type, name, array size
},
{
"original": ["__int64","a5"],
"prediction": ["__int64","a5@del_arg","",{}] // delete the argument erroneously recovered by decompiler
}
{
"original": [],
"prediction": ["char *","name6@add_arg","",{}] / add the argument erroneously omitted by decompiler
}
...
]
&lt;/Output>
The prediction of the variable/argument is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable/argument is a complex type, such as struct, enum, and array, keep "" if not.
The &lt;Output>...&lt;/Output> shoud be the end of the reasoning process, and do not append more explain after it.
"""

funcname_guide = """

Understand the Task
What should be analyzed in the task.
List the objects within the target function should be analyzed base on the specific task, such as args, vars, func name, etc.

Inspect the Calling Context
Describe the calling relationship of the functions.
If a function in context is a library function, describe its functionality and definition (including arguments and return type).

Callsites Analysis
Analyze each caller of the target function, describing each argument passed into the target function.
Analyze each callsite within the target function, describing the arguments passed into each callee function.

Analyze Function Semantics
Analyze the behavior of each function, end with detailed analysis of the target function.
Start from the context functions, and then analyze the target function based on the calling context.

Function Name Recovery
Infer the possible function names for all functions based on the analysis above.

Review and Summary
Review the analysis check reasoning process.
Describe the key basis for inferring the result.
Summarize the final results wrapped with &lt;Output>...&lt;/Output>, such as:

&lt;Output>
[
{"original": "sub_0xFuncAddr", "prediction": "foo"},
...
]
&lt;/Output>
The &lt;Output>...&lt;/Output> shoud be the end of the reasoning process, and do not append more explain after it.
"""

summary_guide = """

Understand the Task
What should be analyzed in the task.
List the objects within the target function should be analyzed base on the specific task, such as args, vars, func name, etc.

Inspect the Calling Context
Describe the calling relationship of the functions.
If a function in context is a library function, describe its functionality and definition (including arguments and return type).

Callsites Analysis
Analyze each caller of the target function, describing each argument passed into the target function.
Analyze each callsite within the target function, describing the arguments passed into each callee function.

Analyze Function Semantics
Analyze the behavior of each function, end with detailed analysis of the target function.
Start from the context functions, and then analyze the target function based on the calling context.

Algorithm and Category Analysis
Analyze whether the target function implements a specific algorithm, or is a part of a specific algorithm.
Analyze what category the target function belongs to, such as logging, network, data processing, etc.
If it is not one of the well-defined ones, or if you are not sure, use "none".

Comment Generation

<!-- end list -->

a. Generate doxygen comments for the whole target function based on the analysis above, including brief, detailed, parameters, return.
b. Generate inline comments (end of the line) for the target function for only key lines based on the analysis above to help user understand the code. Only comment on the key lines, such as some callsites, some important variables and usages, beginning of some loops, etc.
<!-- end list -->

Review and Summary Review the analysis check reasoning process. Describe the key basis for inferring the result. Summarize the final results wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:
&lt;Output>
{
"brief": "brief description",
"details": "detailed description",
"params": {
"arg1": "comment for arg1",
"arg2": "comment for arg2",
...
},
"return": "return description",
"inline_comment": {
"3": "comment for L3",
"5": "comment for L5",
...
},
"category": "functional category or none",
"algorithm": "algorithm name or none"
}
&lt;/Output>
The &lt;Output>...&lt;/Output> shoud be the end of the reasoning process, and do not append more explain after it.
"""

--- 任务输出格式字符串 ---
func_analysis_output_format_str = """
The final results should be wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:
&lt;Output>
{
"ret_type": "int",
"funcname": "foo", // recovered meaningful function name for meaningless original name
"args": {
"a1": ["int","name1","",{}], // type, name, is_complex_type?, and struct or enum details
"a2": ["struct_type_a *","name2","struct",{"struct_type_a": [
["int","field1",4], // field type, field name, field size
["char","field2",1],
...
]}
],
"a3": ["enum_type_b","name3","enum",{"enum_type_b": [
["field1","value1",4], // item name, value, and size
["field2","value2",4],
...
]}
],
"a4": ["char","name4","array","4,4"], // array type, name, array size
"a5@del_arg": [], // delete the argument erroneously recovered by decompiler
"a6@add_arg": [], // add the argument erroneously omitted by decompiler
...
},
"vars": {
"var1": ["int","name5","",{}],
"var2": ["struct_type_b","name6","struct",{"struct_type_b": [
["int","field3",4],
["char","field4",1],
...
]}
],
...
},
"brief": "brief description",
"details": "detailed description",
"params": {
"a1": "comment for a1",
"a2": "comment for a2",
...
},
"return": "return description",
"inline_comment": {
"3": "comment for L3",
"5": "comment for L5",
...
},
"category": "functional category or none",
"algorithm": "algorithm name or none"
}
&lt;/Output>
The prediction of the variable/argument is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable/argument is a complex type, such as struct, enum, and array, keep "" if not.
"""

decompilation_output_format_str = """
the final results should be the decompiled source code with Doxygen comment wrapped with &lt;Output>...&lt;/Output>, as well as the complex types recovered in the analysis, such as:
&lt;Output>
/**
 * @brief brief description
 * @details detailed description
 * @param arg1 comment for arg1
 * @param arg2 comment for arg2
 * ...
 * @return return description
 * @category category
 * @algorithm algorithm
 */
struct struct_type_a { // present the complex types recovered in the analysis
    ...
}
void foo(int arg1, struct_type_a arg2, ...) {
    ...
}
&lt;/Output>
"""

specific_vars_output_format_str = """
The final results should be wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:
&lt;Output>
{
"original": ["__int64", "v1"],
"prediction": ["char", "name1", "", {}] // type, name, is_complex_type?, and struct or enum details
}
&lt;/Output>
or
&lt;Output>
{
"original": ["__int64", "v1"],
"prediction": ["struct_type_a *", "name1", "struct", {"struct_type_a": [
["int","field1",4], // field type, field name, field size
["char","field2",1],
...
]}
]
}
&lt;/Output>
or
&lt;Output>
{
"original": ["__uint8","v1"],
"prediction": ["enum_type_a","name1","enum",{"enum_type_a": [
["field1","value1",4], // item name, value, and size
["field2","value2",4],
...
]}
]
}
&lt;/Output>
or
&lt;Output>
{
"original": ["__int64 *","v1"],
"prediction": ["int","name1","array","4,4"] // array type, name, array size
}
&lt;/Output>
The prediction of the variable/argument is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable/argument is a complex type, such as struct, enum, and array, keep "" if not.
If multiple variables/arguments are analyzed, the output should be a list of the above format wrapped with one &lt;Output>...&lt;/Output>.
"""

vars_output_format_str = """
The final results should be wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:
&lt;Output>
[
{
"original": ["__int64","v1"],
"prediction": ["int","name1","",{}] // type, name, is_complex_type?, and struct or enum details
},
{
"original": ["__int64","v2"],
"prediction": ["struct_type_a *","name2","struct",{"struct_type_a": [
["int","field1",4], // field type, field name, field size
["char","field2",1],
...
]}
]
},
{
"original": ["__uint8","v3"],
"prediction": ["enum_type_b","name3","enum",{"enum_type_b": [
["field1","value1",4], // item name, value, and size
["field2","value2",4],
...
]}
]
},
{
"original": ["__int64 *","v4"],
"prediction": ["int","name4","array","4,4"] // array type, name, array size
}
...
]
&lt;/Output>
The prediction of the variable/argument is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable/argument is a complex type, such as struct, enum, and array, keep "" if not.
"""

args_output_format_str = """
The final results should be wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:
&lt;Output>
[
{
"original": ["__int64","a1"],
"prediction": ["int","name1","",{}] // type, name, is_complex_type?, and struct or enum details
},
{
"original": ["__int64","a2"],
"prediction": ["struct_type_a *","name2","struct",{"struct_type_a": [
["int","field1",4], // field type, field name, field size
["char","field2",1],
...
]}
]
},
{
"original": ["__uint8","a3"],
"prediction": ["enum_type_b","name3","enum",{"enum_type_b": [
["field1","value1",4], // item name, value, and size
["field2","value2",4],
...
]}
]
},
{
"original": ["__int64 *","a4"],
"prediction": ["int","name4","array","4,4"] // array type, name, array size
},
{
"original": ["__int64","a5"],
"prediction": ["__int64","a5@del_arg","",{}] // delete the argument erroneously recovered by decompiler
}
{
"original": [],
"prediction": ["char *","name6@add_arg","",{}] / add the argument erroneously omitted by decompiler
}
...
]
&lt;/Output>
The prediction of the variable/argument is a list including type, name, is_complex_type?, and complex type details, respectively.
The third element, is_complex_type?, indicates whether the variable/argument is a complex type, such as struct, enum, and array, keep "" if not.
"""

funcname_output_format_str = """
The final results should be wrapped with &lt;Output>...&lt;/Output>, such as:
&lt;Output>
[
{"original": "sub_0xFuncAddr", "prediction": "foo"},
...
]
&lt;/Output>
"""

summary_output_format_str = """
The final results should be wrapped with &lt;Output>...&lt;/Output> in JSON format, such as:
&lt;Output>
{
"brief": "brief description",
"details": "detailed description",
"params": {
"arg1": "comment for arg1",
"arg2": "comment for arg2",
...
},
"return": "return description",
"inline_comment": {
"3": "comment for L3",
"5": "comment for L5",
...
},
"category": "functional category or none",
"algorithm": "algorithm name or none"
}
&lt;/Output>
"""

TASK_GUIDES = {
'&lt;func-analysis>': func_analysis_guide,
'&lt;decompilation>': decompilation_guide,
'&lt;specific-vars>': specific_vars_guide,
'&lt;vars>': vars_guide,
'&lt;args>': args_guide,
'&lt;funcname>': funcname_guide,
'&lt;summary>': summary_guide,
}

TASK_OUTPUT_FORMATS = {
'&lt;func-analysis>': func_analysis_output_format_str,
'&lt;decompilation>': decompilation_output_format_str,
'&lt;specific-vars>': specific_vars_output_format_str,
'&lt;vars>': vars_output_format_str,
'&lt;args>': args_output_format_str,
'&lt;funcname>': funcname_output_format_str,
'&lt;summary>': summary_output_format_str,
}

def get_mock_response(task_tag):
    """
    从 debug_mock.json 文件加载并返回指定任务的模拟响应。
    """
    # PyArmor 保护代码已省略
    mock_data = {}
    # 获取当前脚本所在的目录
    current_dir = os.path.dirname(file) # file 在 &lt;frozen ...> 环境下可能行为不同
    # 字节码直接使用了 file
    mock_file_path = os.path.join(current_dir, 'debug_mock.json')

    if not os.path.exists(mock_file_path):
        raise Exception(
            "[!💥] mock response file not found, turn off Mock Mode in settings if you are not a developer."
        )

    try:
        with open(mock_file_path, 'r', encoding='utf-8') as f:
            mock_data = json.load(f)
    except Exception as e:
        print(f"[!💥] Error loading or parsing debug_mock.json: {e}")
        return f"Error loading mock data: {e}" # 返回错误信息

    # 字节码逻辑是：如果 task_tag + "2" 存在，则从 task_tag 和 task_tag + "2" 对应的响应中随机选一个
    # 否则，直接用 task_tag 对应的响应。
    # 这允许为同一个 task_tag 提供多个（最多2个）不同的模拟响应。

    response_key_1 = task_tag
    response_key_2 = task_tag + "2" # 字节码中是 task_tag LOAD_CONST '2' BINARY_OP +

    if response_key_2 in mock_data and response_key_1 in mock_data :
        return random.choice([mock_data[response_key_1], mock_data[response_key_2]])
    elif response_key_1 in mock_data:
        return mock_data[response_key_1]
    else:
        # 返回一个通用的或错误的模拟响应
        return f"No mock response found for task: {task_tag}"

# **关键点和假设:**

# * **PyArmor**: 所有的 PyArmor 保护代码 (如 `__pyarmor_assert_XXXX__`, `__pyarmor_enter_XXXX__`) 都被省略了。
# * **常量字符串**: 模块中的大部分内容是巨大的多行字符串，它们被赋值给不同的变量，如 `func_analysis_guide`, `decompilation_output_format_str` 等。这些字符串详细定义了每个分析任务的步骤和期望的输出格式。
# * **`TASK_GUIDES` 和 `TASK_OUTPUT_FORMATS` 字典**: 这两个字典是模块的核心，它们将任务标签映射到相应的指南和输出格式描述。
# * **`get_mock_response` 函数**:
#     * 它依赖于一个名为 `debug_mock.json` 的文件，该文件应与此脚本位于同一目录。
#     * 函数首先检查该文件是否存在，如果不存在则抛出异常。
#     * 如果文件存在，它会读取并解析这个 JSON 文件。
#     * 字节码中的逻辑暗示，它可以为一个 `task_tag` 提供最多两种不同的模拟响应（通过检查 `task_tag` 和 `task_tag + "2"` 作为键）。如果两者都存在，则随机选择一个。如果只有 `task_tag` 存在，则使用它。
# * **`__file__` 的使用**: 在 `get_mock_response` 中，`os.path.dirname(__file__)` 用于确定 `debug_mock.json` 的路径。在 `<frozen ...>` 环境下（如 PyInstaller 或类似工具打包后），`__file__` 的行为可能与普通 Python 脚本不同，但字节码显示它确实直接使用了 `__file__`。
# * **模块用途**: 这个模块显然是为了给 LLM 提供清晰、结构化的指令，以确保分析结果的一致性和可用性，并且支持一个调试/模拟框架。

# 这个反编译版本应该能很好地反映原始模块的功能和结构。