config.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..config>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 10
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        'os'
        'json'
        'GENERAL_MODEL_PROMPT_TEPLATE'
        'GENERAL_MODEL_PROMPT_TEPLATE_WITHOUT_GUIDE'
        'GENERAL_MODEL_PROMPT_TEPLATE_VULN_DETECT_WITHOUT_GUIDE'
        'RECOPILOT_MODEL_PROMPT_TEPLATE'
        'RECOPILOT_MODEL_SUPERT_THOUGHT_PROMPT_TEPLATE'
        'path'
        'join'
        'dirname'
        '__file__'
        'prompt_json_path'
        'exists'
        'Exception'
        'open'
        'f'
        'load'
        'PROMPT_TEMPLATE'
        'print'
        'len'
        'list'
        'keys'
        'ReCopilotSettingsManager'
        'settings_manager'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54961__'
        '__pyarmor_enter_54962__'
        b'<COAddr>\x03\x00\x00\x1a\xc4\x01\x00\x00\x00\x00\x00\x00'
        0
        None
        '\n# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis.\n\n# Analysis Guides:\nThe following is the analysis guides for the user-specified task:\n{guide}\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\nStart analyzing:\n'
        '\n# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis. You need to analyze the binary function and output the analysis result in the specified format.\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\n# Output Format:\nDo your analysis first, then output the final result based on the analysis in the following format:\n```\n{format}\n```\n\nStart analyzing:\n'
        '# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis. You need to analyze the binary function and output the analysis result in the specified format.\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\n# Output Format:\nDo your analysis first, then output the final result based on the analysis in the following format:\n```\n{format}\n```\n\n# Additional Task:\n\nAfter the analysis, if you find a vulnerability in the binary function, you need to output the vulnerability information in the following format:\n\n```\n[🔴] Detected vulnerability: <name>\n[👉] Vulnerability details: \n......\n```\n\nStart analyzing:\n'
        '{input}<Thought>'
        '{input}<Super-Thought>'
        'prompts.json'
        '[!💥] not found '
        'r'
        'utf-8'
        (
            'encoding'
        )
        '[👏] load '
        ' prompt templates:\n'
        [Code]
            File Name: <frozen ..config>
            Object Name: ReCopilotSettingsManager
            Qualified Name: ReCopilotSettingsManager
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__doc__'
                '__assert_armored__'
                '__init__'
                'get_default_settings'
                'load_settings'
                'save_settings'
                'get_setting'
                'set_setting'
            [Locals+Names]
            [Constants]
                'ReCopilotSettingsManager'
                '\n    Manages persistent storage and retrieval of ReCopilot settings.\n    '
                '__pyarmor_assert_54964__'
                '__pyarmor_enter_54965__'
                b'<COAddr>\x03\x00\x00&:\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..config>
                    Object Name: __init__
                    Qualified Name: ReCopilotSettingsManager.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'os'
                        'path'
                        'dirname'
                        'abspath'
                        '__file__'
                        'settings_dir'
                        'join'
                        'settings_file'
                        'makedirs'
                        'print'
                        'load_settings'
                        'settings'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54967__'
                        '__pyarmor_enter_54968__'
                        b'<COAddr>\x03\x00\x00\x1a\x9a\x01\x00\x00\x00\x00\x00\x00'
                        'settings.json'
                        True
                        (
                            'exist_ok'
                        )
                        '[DEBUG🐛] Settings file: '
                        '__pyarmor_exit_54969__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54968__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x9a\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: os
                        38      LOAD_ATTR                       2: path
                        58      LOAD_ATTR                       5: dirname
                        78      LOAD_GLOBAL                     0: os
                        88      LOAD_ATTR                       2: path
                        108     LOAD_ATTR                       7: abspath
                        128     LOAD_GLOBAL                     8: __file__
                        138     CALL                            1
                        146     CALL                            1
                        154     LOAD_FAST                       0: self
                        156     STORE_ATTR                      5: settings_dir
                        166     LOAD_GLOBAL                     0: os
                        176     LOAD_ATTR                       2: path
                        196     LOAD_ATTR                       13: join
                        216     LOAD_FAST                       0: self
                        218     LOAD_ATTR                       10: settings_dir
                        238     LOAD_CONST                      4: 'settings.json'
                        240     CALL                            2
                        248     LOAD_FAST                       0: self
                        250     STORE_ATTR                      7: settings_file
                        260     LOAD_GLOBAL                     1: NULL + os
                        270     LOAD_ATTR                       16: makedirs
                        290     LOAD_FAST                       0: self
                        292     LOAD_ATTR                       10: settings_dir
                        312     LOAD_CONST                      5: True
                        314     KW_NAMES                        6: ('exist_ok',)
                        316     CALL                            2
                        324     POP_TOP                         
                        326     LOAD_GLOBAL                     19: NULL + print
                        336     LOAD_CONST                      7: '[DEBUG🐛] Settings file: '
                        338     LOAD_FAST                       0: self
                        340     LOAD_ATTR                       14: settings_file
                        360     FORMAT_VALUE                    0 (FVC_NONE)
                        362     BUILD_STRING                    2
                        364     CALL                            1
                        372     POP_TOP                         
                        374     LOAD_FAST                       0: self
                        376     LOAD_ATTR                       21: load_settings
                        396     CALL                            0
                        404     LOAD_FAST                       0: self
                        406     STORE_ATTR                      11: settings
                        416     LOAD_CONST                      0: None
                        418     NOP                             
                        420     NOP                             
                        422     NOP                             
                        424     JUMP_FORWARD                    19 (to 464)
                        432     POP_TOP                         
                        434     RETURN_CONST                    0: None
                        436     PUSH_EXC_INFO                   
                        438     PUSH_NULL                       
                        440     LOAD_CONST                      8: '__pyarmor_exit_54969__'
                        442     NOP                             
                        444     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x9a\x01\x00\x00\x00\x00\x00\x00'
                        446     CALL                            1
                        454     POP_TOP                         
                        456     RERAISE                         0
                        458     COPY                            3
                        460     POP_EXCEPT                      
                        462     RERAISE                         1
                        464     PUSH_NULL                       
                        466     LOAD_CONST                      8: '__pyarmor_exit_54969__'
                        468     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x9a\x01\x00\x00\x00\x00\x00\x00'
                        470     BUILD_TUPLE                     1
                        472     CALL_FUNCTION_EX                0
                        474     POP_TOP                         
                        476     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..config>
                    Object Name: get_default_settings
                    Qualified Name: ReCopilotSettingsManager.get_default_settings
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 14
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        'Get default settings dictionary.'
                        '__pyarmor_assert_54970__'
                        '__pyarmor_enter_54971__'
                        b'<COAddr>\x03\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        'recopilot-v0.1-beta-dpo'
                        'http://localhost:8000'
                        'sk-none'
                        'recopilot'
                        8000
                        1
                        10
                        True
                        False
                        (
                            'model_name'
                            'base_url'
                            'api_key'
                            'prompt_template'
                            'max_output_tokens'
                            'max_trace_caller_depth'
                            'max_trace_callee_depth'
                            'max_context_func_num'
                            'data_flow_analysis'
                            'measure_info_score'
                            'need_confirm'
                            'debug_mode'
                            'feedback'
                        )
                        '__pyarmor_exit_54972__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54971__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_CONST                      4: 'recopilot-v0.1-beta-dpo'
                        30      LOAD_CONST                      5: 'http://localhost:8000'
                        32      LOAD_CONST                      6: 'sk-none'
                        34      LOAD_CONST                      7: 'recopilot'
                        36      LOAD_CONST                      8: 8000
                        38      LOAD_CONST                      9: 1
                        40      LOAD_CONST                      9: 1
                        42      LOAD_CONST                      10: 10
                        44      LOAD_CONST                      11: True
                        46      LOAD_CONST                      11: True
                        48      LOAD_CONST                      11: True
                        50      LOAD_CONST                      12: False
                        52      LOAD_CONST                      12: False
                        54      LOAD_CONST                      13: ('model_name', 'base_url', 'api_key', 'prompt_template', 'max_output_tokens', 'max_trace_caller_depth', 'max_trace_callee_depth', 'max_context_func_num', 'data_flow_analysis', 'measure_info_score', 'need_confirm', 'debug_mode', 'feedback')
                        56      BUILD_CONST_KEY_MAP             13
                        58      NOP                             
                        60      NOP                             
                        62      NOP                             
                        64      JUMP_FORWARD                    20 (to 106)
                        66      CALL                            1
                        74      POP_TOP                         
                        76      RETURN_VALUE                    
                        78      PUSH_EXC_INFO                   
                        80      PUSH_NULL                       
                        82      LOAD_CONST                      14: '__pyarmor_exit_54972__'
                        84      NOP                             
                        86      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        88      CALL                            1
                        96      POP_TOP                         
                        98      RERAISE                         0
                        100     COPY                            3
                        102     POP_EXCEPT                      
                        104     RERAISE                         1
                        106     PUSH_NULL                       
                        108     LOAD_CONST                      14: '__pyarmor_exit_54972__'
                        110     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        112     BUILD_TUPLE                     1
                        114     CALL_FUNCTION_EX                0
                        116     POP_TOP                         
                        118     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..config>
                    Object Name: load_settings
                    Qualified Name: ReCopilotSettingsManager.load_settings
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'os'
                        'path'
                        'exists'
                        'settings_file'
                        'get_default_settings'
                        'open'
                        'json'
                        'load'
                        'Exception'
                        'print'
                        'str'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_0'
                        '_var_var_1'
                        '_var_var_2'
                        '_var_var_3'
                        '_var_var_4'
                    [Constants]
                        'Load settings from file or return defaults.'
                        '__pyarmor_assert_54973__'
                        '__pyarmor_enter_54974__'
                        b'<COAddr>\x03\x00\x00\x1a\x0c\x02\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54975__'
                        'r'
                        None
                        'Error loading settings: '
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54974__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x0c\x02\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: os
                        38      LOAD_ATTR                       2: path
                        58      LOAD_ATTR                       5: exists
                        78      LOAD_FAST                       0: self
                        80      LOAD_ATTR                       6: settings_file
                        100     CALL                            1
                        108     POP_JUMP_IF_TRUE                25 (to 160)
                        110     LOAD_FAST                       0: self
                        112     LOAD_ATTR                       9: get_default_settings
                        132     CALL                            0
                        140     NOP                             
                        142     NOP                             
                        144     NOP                             
                        146     JUMP_FORWARD                    215 (to 578)
                        148     CALL                            1
                        156     POP_TOP                         
                        158     RETURN_VALUE                    
                        160     NOP                             
                        162     LOAD_GLOBAL                     11: NULL + open
                        172     LOAD_FAST                       0: self
                        174     LOAD_ATTR                       6: settings_file
                        194     LOAD_CONST                      5: 'r'
                        196     CALL                            2
                        204     BEFORE_WITH                     
                        206     STORE_FAST                      2: _var_var_0
                        208     LOAD_GLOBAL                     13: NULL + json
                        218     LOAD_ATTR                       14: load
                        238     LOAD_FAST                       2: _var_var_0
                        240     CALL                            1
                        248     STORE_FAST                      3: _var_var_1
                        250     LOAD_FAST                       0: self
                        252     LOAD_ATTR                       9: get_default_settings
                        272     CALL                            0
                        280     STORE_FAST                      4: _var_var_2
                        282     LOAD_FAST                       4: _var_var_2
                        284     GET_ITER                        
                        286     FOR_ITER                        15 (to 318)
                        290     STORE_FAST                      5: _var_var_3
                        292     LOAD_FAST                       5: _var_var_3
                        294     LOAD_FAST                       3: _var_var_1
                        296     CONTAINS_OP                     1 (not in)
                        298     POP_JUMP_IF_TRUE                1 (to 302)
                        300     JUMP_BACKWARD                   8 (to 286)
                        302     LOAD_FAST                       4: _var_var_2
                        304     LOAD_FAST                       5: _var_var_3
                        306     BINARY_SUBSCR                   
                        310     LOAD_FAST                       3: _var_var_1
                        312     LOAD_FAST                       5: _var_var_3
                        314     STORE_SUBSCR                    
                        318     JUMP_BACKWARD                   17 (to 286)
                        320     END_FOR                         
                        322     LOAD_FAST                       3: _var_var_1
                        324     SWAP                            2
                        326     LOAD_CONST                      6: None
                        328     LOAD_CONST                      6: None
                        330     LOAD_CONST                      6: None
                        332     CALL                            2
                        340     POP_TOP                         
                        342     NOP                             
                        344     NOP                             
                        346     NOP                             
                        348     JUMP_FORWARD                    114 (to 578)
                        350     CALL                            1
                        358     POP_TOP                         
                        360     RETURN_VALUE                    
                        362     PUSH_EXC_INFO                   
                        364     WITH_EXCEPT_START               
                        366     POP_JUMP_IF_TRUE                1 (to 370)
                        368     RERAISE                         2
                        370     POP_TOP                         
                        372     POP_EXCEPT                      
                        374     POP_TOP                         
                        376     POP_TOP                         
                        378     JUMP_FORWARD                    3 (to 386)
                        380     COPY                            3
                        382     POP_EXCEPT                      
                        384     RERAISE                         1
                        386     JUMP_FORWARD                    70 (to 528)
                        388     PUSH_EXC_INFO                   
                        390     LOAD_GLOBAL                     16: Exception
                        400     CHECK_EXC_MATCH                 
                        402     POP_JUMP_IF_FALSE               58 (to 520)
                        404     STORE_FAST                      6: _var_var_4
                        406     LOAD_GLOBAL                     19: NULL + print
                        416     LOAD_CONST                      7: 'Error loading settings: '
                        418     LOAD_GLOBAL                     21: NULL + str
                        428     LOAD_FAST                       6: _var_var_4
                        430     CALL                            1
                        438     FORMAT_VALUE                    0 (FVC_NONE)
                        440     BUILD_STRING                    2
                        442     CALL                            1
                        450     POP_TOP                         
                        452     LOAD_FAST                       0: self
                        454     LOAD_ATTR                       9: get_default_settings
                        474     CALL                            0
                        482     SWAP                            2
                        484     POP_EXCEPT                      
                        486     LOAD_CONST                      6: None
                        488     STORE_FAST                      6: _var_var_4
                        490     DELETE_FAST                     6: _var_var_4
                        492     NOP                             
                        494     NOP                             
                        496     NOP                             
                        498     JUMP_FORWARD                    39 (to 578)
                        500     CALL                            1
                        508     POP_TOP                         
                        510     RETURN_VALUE                    
                        512     LOAD_CONST                      6: None
                        514     STORE_FAST                      6: _var_var_4
                        516     DELETE_FAST                     6: _var_var_4
                        518     RERAISE                         1
                        520     RERAISE                         0
                        522     COPY                            3
                        524     POP_EXCEPT                      
                        526     RERAISE                         1
                        528     NOP                             
                        530     LOAD_CONST                      6: None
                        532     NOP                             
                        534     NOP                             
                        536     NOP                             
                        538     JUMP_FORWARD                    19 (to 578)
                        546     POP_TOP                         
                        548     RETURN_CONST                    6: None
                        550     PUSH_EXC_INFO                   
                        552     PUSH_NULL                       
                        554     LOAD_CONST                      4: '__pyarmor_exit_54975__'
                        556     NOP                             
                        558     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x0c\x02\x00\x00\x00\x00\x00\x00'
                        560     CALL                            1
                        568     POP_TOP                         
                        570     RERAISE                         0
                        572     COPY                            3
                        574     POP_EXCEPT                      
                        576     RERAISE                         1
                        578     PUSH_NULL                       
                        580     LOAD_CONST                      4: '__pyarmor_exit_54975__'
                        582     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x0c\x02\x00\x00\x00\x00\x00\x00'
                        584     BUILD_TUPLE                     1
                        586     CALL_FUNCTION_EX                0
                        588     POP_TOP                         
                        590     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..config>
                    Object Name: save_settings
                    Qualified Name: ReCopilotSettingsManager.save_settings
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'open'
                        'settings_file'
                        'json'
                        'dump'
                        'settings'
                        'Exception'
                        'print'
                        'str'
                    [Locals+Names]
                        'self'
                        'settings'
                        '__assert_armored__'
                        '_var_var_0'
                        '_var_var_4'
                    [Constants]
                        'Save settings to file.'
                        '__pyarmor_assert_54976__'
                        '__pyarmor_enter_54977__'
                        b'<COAddr>\x01\x00\x00\x1a\x06\x01\x00\x00\x00\x00\x00\x00'
                        'w'
                        4
                        (
                            'indent'
                        )
                        None
                        'Error saving settings: '
                        '__pyarmor_exit_54978__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54977__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x06\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      LOAD_GLOBAL                     1: NULL + open
                        40      LOAD_FAST                       0: self
                        42      LOAD_ATTR                       2: settings_file
                        62      LOAD_CONST                      4: 'w'
                        64      CALL                            2
                        72      BEFORE_WITH                     
                        74      STORE_FAST                      3: _var_var_0
                        76      LOAD_GLOBAL                     5: NULL + json
                        86      LOAD_ATTR                       6: dump
                        106     LOAD_FAST                       1: settings
                        108     LOAD_FAST                       3: _var_var_0
                        110     LOAD_CONST                      5: 4
                        112     KW_NAMES                        6: ('indent',)
                        114     CALL                            3
                        122     POP_TOP                         
                        124     LOAD_CONST                      7: None
                        126     LOAD_CONST                      7: None
                        128     LOAD_CONST                      7: None
                        130     CALL                            2
                        138     POP_TOP                         
                        140     LOAD_FAST                       1: settings
                        142     LOAD_FAST                       0: self
                        144     STORE_ATTR                      4: settings
                        154     LOAD_CONST                      7: None
                        156     NOP                             
                        158     NOP                             
                        160     NOP                             
                        162     JUMP_FORWARD                    76 (to 316)
                        170     POP_TOP                         
                        172     RETURN_CONST                    7: None
                        174     PUSH_EXC_INFO                   
                        176     WITH_EXCEPT_START               
                        178     POP_JUMP_IF_TRUE                1 (to 182)
                        180     RERAISE                         2
                        182     POP_TOP                         
                        184     POP_EXCEPT                      
                        186     POP_TOP                         
                        188     POP_TOP                         
                        190     JUMP_BACKWARD                   26 (to 140)
                        192     COPY                            3
                        194     POP_EXCEPT                      
                        196     RERAISE                         1
                        198     PUSH_EXC_INFO                   
                        200     LOAD_GLOBAL                     10: Exception
                        210     CHECK_EXC_MATCH                 
                        212     POP_JUMP_IF_FALSE               33 (to 280)
                        214     STORE_FAST                      4: _var_var_4
                        216     LOAD_GLOBAL                     13: NULL + print
                        226     LOAD_CONST                      8: 'Error saving settings: '
                        228     LOAD_GLOBAL                     15: NULL + str
                        238     LOAD_FAST                       4: _var_var_4
                        240     CALL                            1
                        248     FORMAT_VALUE                    0 (FVC_NONE)
                        250     BUILD_STRING                    2
                        252     CALL                            1
                        260     POP_TOP                         
                        262     POP_EXCEPT                      
                        264     LOAD_CONST                      7: None
                        266     STORE_FAST                      4: _var_var_4
                        268     DELETE_FAST                     4: _var_var_4
                        270     JUMP_BACKWARD                   59 (to 154)
                        272     LOAD_CONST                      7: None
                        274     STORE_FAST                      4: _var_var_4
                        276     DELETE_FAST                     4: _var_var_4
                        278     RERAISE                         1
                        280     RERAISE                         0
                        282     COPY                            3
                        284     POP_EXCEPT                      
                        286     RERAISE                         1
                        288     PUSH_EXC_INFO                   
                        290     PUSH_NULL                       
                        292     LOAD_CONST                      9: '__pyarmor_exit_54978__'
                        294     NOP                             
                        296     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x06\x01\x00\x00\x00\x00\x00\x00'
                        298     CALL                            1
                        306     POP_TOP                         
                        308     RERAISE                         0
                        310     COPY                            3
                        312     POP_EXCEPT                      
                        314     RERAISE                         1
                        316     PUSH_NULL                       
                        318     LOAD_CONST                      9: '__pyarmor_exit_54978__'
                        320     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x06\x01\x00\x00\x00\x00\x00\x00'
                        322     BUILD_TUPLE                     1
                        324     CALL_FUNCTION_EX                0
                        326     POP_TOP                         
                        328     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..config>
                    Object Name: get_setting
                    Qualified Name: ReCopilotSettingsManager.get_setting
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'settings'
                        'get'
                    [Locals+Names]
                        'self'
                        'key'
                        '__assert_armored__'
                    [Constants]
                        'Get current settings.'
                        '__pyarmor_assert_54979__'
                        '__pyarmor_enter_54980__'
                        b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        None
                        '__pyarmor_exit_54981__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54980__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       0: self
                        30      LOAD_ATTR                       0: settings
                        50      LOAD_ATTR                       3: get
                        70      LOAD_FAST                       1: key
                        72      LOAD_CONST                      4: None
                        74      CALL                            2
                        82      NOP                             
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    20 (to 130)
                        90      CALL                            1
                        98      POP_TOP                         
                        100     RETURN_VALUE                    
                        102     PUSH_EXC_INFO                   
                        104     PUSH_NULL                       
                        106     LOAD_CONST                      5: '__pyarmor_exit_54981__'
                        108     NOP                             
                        110     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        112     CALL                            1
                        120     POP_TOP                         
                        122     RERAISE                         0
                        124     COPY                            3
                        126     POP_EXCEPT                      
                        128     RERAISE                         1
                        130     PUSH_NULL                       
                        132     LOAD_CONST                      5: '__pyarmor_exit_54981__'
                        134     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        136     BUILD_TUPLE                     1
                        138     CALL_FUNCTION_EX                0
                        140     POP_TOP                         
                        142     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..config>
                    Object Name: set_setting
                    Qualified Name: ReCopilotSettingsManager.set_setting
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'settings'
                        'save_settings'
                    [Locals+Names]
                        'self'
                        'key'
                        'value'
                        '__assert_armored__'
                    [Constants]
                        'Change setting and save to file.'
                        '__pyarmor_assert_54982__'
                        '__pyarmor_enter_54983__'
                        b'<COAddr>\x03\x00\x00\x1a\x86\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54984__'
                        None
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54983__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x86\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: key
                        30      LOAD_FAST                       0: self
                        32      LOAD_ATTR                       0: settings
                        52      CONTAINS_OP                     0 (in)
                        54      POP_JUMP_IF_FALSE               42 (to 140)
                        56      LOAD_FAST                       2: value
                        58      LOAD_FAST                       0: self
                        60      LOAD_ATTR                       0: settings
                        80      LOAD_FAST                       1: key
                        82      STORE_SUBSCR                    
                        86      LOAD_FAST                       0: self
                        88      LOAD_ATTR                       3: save_settings
                        108     LOAD_FAST                       0: self
                        110     LOAD_ATTR                       0: settings
                        130     CALL                            1
                        138     POP_TOP                         
                        140     LOAD_CONST                      5: None
                        142     NOP                             
                        144     NOP                             
                        146     NOP                             
                        148     JUMP_FORWARD                    19 (to 188)
                        156     POP_TOP                         
                        158     RETURN_CONST                    5: None
                        160     PUSH_EXC_INFO                   
                        162     PUSH_NULL                       
                        164     LOAD_CONST                      4: '__pyarmor_exit_54984__'
                        166     NOP                             
                        168     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x86\x00\x00\x00\x00\x00\x00\x00'
                        170     CALL                            1
                        178     POP_TOP                         
                        180     RERAISE                         0
                        182     COPY                            3
                        184     POP_EXCEPT                      
                        186     RERAISE                         1
                        188     PUSH_NULL                       
                        190     LOAD_CONST                      4: '__pyarmor_exit_54984__'
                        192     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x86\x00\x00\x00\x00\x00\x00\x00'
                        194     BUILD_TUPLE                     1
                        196     CALL_FUNCTION_EX                0
                        198     POP_TOP                         
                        200     RETURN_VALUE                    
                '__pyarmor_exit_54966__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'ReCopilotSettingsManager'
                8       STORE_NAME                      2: __qualname__
                10      LOAD_CONST                      1: '\n    Manages persistent storage and retrieval of ReCopilot settings.\n    '
                12      STORE_NAME                      3: __doc__
                14      NOP                             
                16      PUSH_NULL                       
                18      LOAD_CONST                      3: '__pyarmor_enter_54965__'
                20      LOAD_CONST                      4: b'<COAddr>\x03\x00\x00&:\x00\x00\x00\x00\x00\x00\x00'
                22      BUILD_TUPLE                     1
                24      CALL_FUNCTION_EX                0
                26      POP_TOP                         
                28      RESUME                          0
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      NOP                             
                40      LOAD_CONST                      5: <CODE> __init__
                42      MAKE_FUNCTION                   0
                44      STORE_NAME                      5: __init__
                46      LOAD_CONST                      6: <CODE> get_default_settings
                48      MAKE_FUNCTION                   0
                50      STORE_NAME                      6: get_default_settings
                52      LOAD_CONST                      7: <CODE> load_settings
                54      MAKE_FUNCTION                   0
                56      STORE_NAME                      7: load_settings
                58      LOAD_CONST                      8: <CODE> save_settings
                60      MAKE_FUNCTION                   0
                62      STORE_NAME                      8: save_settings
                64      LOAD_CONST                      9: <CODE> get_setting
                66      MAKE_FUNCTION                   0
                68      STORE_NAME                      9: get_setting
                70      LOAD_CONST                      10: <CODE> set_setting
                72      MAKE_FUNCTION                   0
                74      STORE_NAME                      10: set_setting
                76      LOAD_CONST                      12: None
                78      NOP                             
                80      NOP                             
                82      NOP                             
                84      JUMP_FORWARD                    19 (to 124)
                92      POP_TOP                         
                94      RETURN_CONST                    12: None
                96      PUSH_EXC_INFO                   
                98      PUSH_NULL                       
                100     LOAD_CONST                      11: '__pyarmor_exit_54966__'
                102     NOP                             
                104     LOAD_CONST                      4: b'<COAddr>\x03\x00\x00&:\x00\x00\x00\x00\x00\x00\x00'
                106     CALL                            1
                114     POP_TOP                         
                116     RERAISE                         0
                118     COPY                            3
                120     POP_EXCEPT                      
                122     RERAISE                         1
                124     PUSH_NULL                       
                126     LOAD_CONST                      11: '__pyarmor_exit_54966__'
                128     LOAD_CONST                      4: b'<COAddr>\x03\x00\x00&:\x00\x00\x00\x00\x00\x00\x00'
                130     BUILD_TUPLE                     1
                132     CALL_FUNCTION_EX                0
                134     POP_TOP                         
                136     RETURN_VALUE                    
        'ReCopilotSettingsManager'
        '__pyarmor_exit_54963__'
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54962__'
        8       LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a\xc4\x01\x00\x00\x00\x00\x00\x00'
        10      BUILD_TUPLE                     1
        12      CALL_FUNCTION_EX                0
        14      POP_TOP                         
        16      RESUME                          0
        18      NOP                             
        20      NOP                             
        22      NOP                             
        24      NOP                             
        26      LOAD_CONST                      3: 0
        28      LOAD_CONST                      4: None
        30      IMPORT_NAME                     1: os
        32      STORE_NAME                      1: os
        34      LOAD_CONST                      3: 0
        36      LOAD_CONST                      4: None
        38      IMPORT_NAME                     2: json
        40      STORE_NAME                      2: json
        42      LOAD_CONST                      5: '\n# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis.\n\n# Analysis Guides:\nThe following is the analysis guides for the user-specified task:\n{guide}\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\nStart analyzing:\n'
        44      STORE_NAME                      3: GENERAL_MODEL_PROMPT_TEPLATE
        46      LOAD_CONST                      6: '\n# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis. You need to analyze the binary function and output the analysis result in the specified format.\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\n# Output Format:\nDo your analysis first, then output the final result based on the analysis in the following format:\n```\n{format}\n```\n\nStart analyzing:\n'
        48      STORE_NAME                      4: GENERAL_MODEL_PROMPT_TEPLATE_WITHOUT_GUIDE
        50      LOAD_CONST                      7: '# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis. You need to analyze the binary function and output the analysis result in the specified format.\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\n# Output Format:\nDo your analysis first, then output the final result based on the analysis in the following format:\n```\n{format}\n```\n\n# Additional Task:\n\nAfter the analysis, if you find a vulnerability in the binary function, you need to output the vulnerability information in the following format:\n\n```\n[🔴] Detected vulnerability: <name>\n[👉] Vulnerability details: \n......\n```\n\nStart analyzing:\n'
        52      STORE_NAME                      5: GENERAL_MODEL_PROMPT_TEPLATE_VULN_DETECT_WITHOUT_GUIDE
        54      LOAD_CONST                      8: '{input}<Thought>'
        56      STORE_NAME                      6: RECOPILOT_MODEL_PROMPT_TEPLATE
        58      LOAD_CONST                      9: '{input}<Super-Thought>'
        60      STORE_NAME                      7: RECOPILOT_MODEL_SUPERT_THOUGHT_PROMPT_TEPLATE
        62      LOAD_NAME                       1: os
        64      LOAD_ATTR                       16: path
        84      LOAD_ATTR                       19: join
        104     LOAD_NAME                       1: os
        106     LOAD_ATTR                       16: path
        126     LOAD_ATTR                       21: dirname
        146     LOAD_NAME                       11: __file__
        148     CALL                            1
        156     LOAD_CONST                      10: 'prompts.json'
        158     CALL                            2
        166     STORE_NAME                      12: prompt_json_path
        168     LOAD_NAME                       1: os
        170     LOAD_ATTR                       16: path
        190     LOAD_ATTR                       27: exists
        210     LOAD_NAME                       12: prompt_json_path
        212     CALL                            1
        220     POP_JUMP_IF_TRUE                11 (to 244)
        222     PUSH_NULL                       
        224     LOAD_NAME                       14: Exception
        226     LOAD_CONST                      11: '[!💥] not found '
        228     LOAD_NAME                       12: prompt_json_path
        230     FORMAT_VALUE                    0 (FVC_NONE)
        232     BUILD_STRING                    2
        234     CALL                            1
        242     RAISE_VARARGS                   1
        244     PUSH_NULL                       
        246     LOAD_NAME                       15: open
        248     LOAD_NAME                       12: prompt_json_path
        250     LOAD_CONST                      12: 'r'
        252     LOAD_CONST                      13: 'utf-8'
        254     KW_NAMES                        14: ('encoding',)
        256     CALL                            3
        264     BEFORE_WITH                     
        266     STORE_NAME                      16: f
        268     PUSH_NULL                       
        270     LOAD_NAME                       2: json
        272     LOAD_ATTR                       34: load
        292     LOAD_NAME                       16: f
        294     CALL                            1
        302     STORE_NAME                      18: PROMPT_TEMPLATE
        304     PUSH_NULL                       
        306     LOAD_NAME                       19: print
        308     LOAD_CONST                      15: '[👏] load '
        310     PUSH_NULL                       
        312     LOAD_NAME                       20: len
        314     LOAD_NAME                       18: PROMPT_TEMPLATE
        316     CALL                            1
        324     FORMAT_VALUE                    0 (FVC_NONE)
        326     LOAD_CONST                      16: ' prompt templates:\n'
        328     PUSH_NULL                       
        330     LOAD_NAME                       21: list
        332     LOAD_NAME                       18: PROMPT_TEMPLATE
        334     LOAD_ATTR                       45: keys
        354     CALL                            0
        362     CALL                            1
        370     FORMAT_VALUE                    0 (FVC_NONE)
        372     BUILD_STRING                    4
        374     CALL                            1
        382     POP_TOP                         
        384     LOAD_CONST                      4: None
        386     LOAD_CONST                      4: None
        388     LOAD_CONST                      4: None
        390     CALL                            2
        398     POP_TOP                         
        400     PUSH_NULL                       
        402     LOAD_BUILD_CLASS                
        404     LOAD_CONST                      17: <CODE> ReCopilotSettingsManager
        406     MAKE_FUNCTION                   0
        408     LOAD_CONST                      18: 'ReCopilotSettingsManager'
        410     CALL                            2
        418     STORE_NAME                      23: ReCopilotSettingsManager
        420     PUSH_NULL                       
        422     LOAD_NAME                       23: ReCopilotSettingsManager
        424     CALL                            0
        432     STORE_NAME                      24: settings_manager
        434     LOAD_CONST                      4: None
        436     NOP                             
        438     NOP                             
        440     NOP                             
        442     JUMP_FORWARD                    31 (to 506)
        450     POP_TOP                         
        452     RETURN_CONST                    4: None
        454     PUSH_EXC_INFO                   
        456     WITH_EXCEPT_START               
        458     POP_JUMP_IF_TRUE                1 (to 462)
        460     RERAISE                         2
        462     POP_TOP                         
        464     POP_EXCEPT                      
        466     POP_TOP                         
        468     POP_TOP                         
        470     JUMP_BACKWARD                   36 (to 400)
        472     COPY                            3
        474     POP_EXCEPT                      
        476     RERAISE                         1
        478     PUSH_EXC_INFO                   
        480     PUSH_NULL                       
        482     LOAD_CONST                      19: '__pyarmor_exit_54963__'
        484     NOP                             
        486     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a\xc4\x01\x00\x00\x00\x00\x00\x00'
        488     CALL                            1
        496     POP_TOP                         
        498     RERAISE                         0
        500     COPY                            3
        502     POP_EXCEPT                      
        504     RERAISE                         1
        506     PUSH_NULL                       
        508     LOAD_CONST                      19: '__pyarmor_exit_54963__'
        510     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a\xc4\x01\x00\x00\x00\x00\x00\x00'
        512     BUILD_TUPLE                     1
        514     CALL_FUNCTION_EX                0
        516     POP_TOP                         
        518     RETURN_VALUE                    
