handler.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..handler>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 5
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        'ida_kernwin'
        'idc'
        'idaapi'
        'threading'
        'time'
        're'
        'json'
        'asyncio'
        'functools'
        'partial'
        'remote_model'
        'OpenAIModel'
        'ext_info'
        'build_prompt'
        'apply_prediction'
        'recopilot_qt'
        'ReCopilotSettingsDialog'
        'create_decompilation_view'
        'create_user_confirm_view'
        'create_variable_selection_view'
        'create_user_confirm_view_for_funcname'
        'add_cancel_button'
        'remove_cancel_button'
        'config'
        'settings_manager'
        'checker'
        'response_check_and_refine'
        'split_pred_to_var_arg'
        'parse_model_response_json'
        'parse_model_response_str'
        'get_func_args'
        'get_func_args_vars'
        'feedback'
        'send_feedback'
        'model'
        'MFF_WRITE'
        'ida_execute'
        'func_analysis'
        'decompilation'
        'specific_vars_analysis'
        'all_vars_analysis'
        'all_args_analysis'
        'func_name_analysis'
        'summary_analysis'
        'func_analysis_mock'
        'decompilation_mock'
        'specific_vars_analysis_mock'
        'all_vars_analysis_mock'
        'all_args_analysis_mock'
        'action_handler_t'
        'FuncAnalysisHandler'
        'DecompilationHandler'
        'SpecificVariableAnalysisHandler'
        'AllVariableAnalysisHandler'
        'AllArgumentAnalysisHandler'
        'FuncNameAnalysisHandler'
        'SummaryAnalysisHandler'
        'ReCopilotSettingsHandler'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54985__'
        '__pyarmor_enter_54986__'
        b'<COAddr>\x03\x00\x00\x1a\x9e\x02\x00\x00\x00\x00\x00\x00'
        0
        None
        (
            'partial'
        )
        (
            'OpenAIModel'
        )
        (
            'build_prompt'
            'apply_prediction'
        )
        (
            'ReCopilotSettingsDialog'
            'create_decompilation_view'
            'create_user_confirm_view'
            'create_variable_selection_view'
            'create_user_confirm_view_for_funcname'
            'add_cancel_button'
            'remove_cancel_button'
        )
        (
            'settings_manager'
        )
        (
            'response_check_and_refine'
            'split_pred_to_var_arg'
            'parse_model_response_json'
            'parse_model_response_str'
            'get_func_args'
            'get_func_args_vars'
        )
        (
            'send_feedback'
        )
        (
        )
        [Code]
            File Name: <frozen ..handler>
            Object Name: ida_execute
            Qualified Name: ida_execute
            Arg Count: 3
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'partial'
                'ida_kernwin'
                'execute_sync'
            [Locals+Names]
                'func'
                'args'
                'sync_type'
                '__assert_armored__'
                '_var_var_1'
                '_var_var_2'
                '_var_var_0'
            [Constants]
                '\n    exec func in ida main thread\n    \n    Args:\n        func: exec func\n        args: args for func\n        sync_type: default MFF_WRITE\n        \n    Returns:\n        func return value\n    '
                '__pyarmor_assert_54988__'
                '__pyarmor_enter_54989__'
                b'<COAddr>\x01\x00\x00 v\x00\x00\x00\x00\x00\x00\x00'
                'result'
                None
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: wrapper
                    Qualified Name: ida_execute.<locals>.wrapper
                    Arg Count: 0
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        '__assert_armored__'
                        'args'
                        'func'
                        '_var_var_0'
                    [Constants]
                        None
                        '__pyarmor_assert_54991__'
                        '__pyarmor_enter_54992__'
                        b'<COAddr>\x01\x00\x00\x1c&\x00\x00\x00\x00\x00\x00\x00'
                        'result'
                        '__pyarmor_exit_54993__'
                        1
                    [Disassembly]
                        0       COPY_FREE_VARS                  3
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54992__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c&\x00\x00\x00\x00\x00\x00\x00'
                        12      BUILD_TUPLE                     1
                        14      CALL_FUNCTION_EX                0
                        16      POP_TOP                         
                        18      RESUME                          0
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      PUSH_NULL                       
                        32      LOAD_DEREF                      2: func
                        34      LOAD_DEREF                      1: args
                        36      CALL_FUNCTION_EX                0
                        38      LOAD_DEREF                      3: _var_var_0
                        40      LOAD_CONST                      4: 'result'
                        42      STORE_SUBSCR                    
                        46      LOAD_CONST                      6: 1
                        48      NOP                             
                        50      NOP                             
                        52      NOP                             
                        54      JUMP_FORWARD                    19 (to 94)
                        62      POP_TOP                         
                        64      RETURN_CONST                    6: 1
                        66      PUSH_EXC_INFO                   
                        68      PUSH_NULL                       
                        70      LOAD_CONST                      5: '__pyarmor_exit_54993__'
                        72      NOP                             
                        74      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c&\x00\x00\x00\x00\x00\x00\x00'
                        76      CALL                            1
                        84      POP_TOP                         
                        86      RERAISE                         0
                        88      COPY                            3
                        90      POP_EXCEPT                      
                        92      RERAISE                         1
                        94      PUSH_NULL                       
                        96      LOAD_CONST                      5: '__pyarmor_exit_54993__'
                        98      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c&\x00\x00\x00\x00\x00\x00\x00'
                        100     BUILD_TUPLE                     1
                        102     CALL_FUNCTION_EX                0
                        104     POP_TOP                         
                        106     RETURN_VALUE                    
                '__pyarmor_exit_54990__'
            [Disassembly]
                0       MAKE_CELL                       0: func
                2       MAKE_CELL                       1: args
                4       MAKE_CELL                       6: _var_var_0
                6       NOP                             
                8       NOP                             
                10      PUSH_NULL                       
                12      LOAD_CONST                      2: '__pyarmor_enter_54989__'
                14      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00 v\x00\x00\x00\x00\x00\x00\x00'
                16      BUILD_TUPLE                     1
                18      CALL_FUNCTION_EX                0
                20      POP_TOP                         
                22      RESUME                          0
                24      NOP                             
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      LOAD_CONST                      4: 'result'
                36      LOAD_CONST                      5: None
                38      BUILD_MAP                       1
                40      STORE_DEREF                     6: _var_var_0
                42      LOAD_CLOSURE                    1: args
                44      LOAD_CLOSURE                    0: func
                46      LOAD_CLOSURE                    6: _var_var_0
                48      BUILD_TUPLE                     3
                50      LOAD_CONST                      6: <CODE> wrapper
                52      MAKE_FUNCTION                   8
                54      STORE_FAST                      4: _var_var_1
                56      LOAD_GLOBAL                     1: NULL + partial
                66      LOAD_FAST                       4: _var_var_1
                68      CALL                            1
                76      STORE_FAST                      5: _var_var_2
                78      LOAD_GLOBAL                     3: NULL + ida_kernwin
                88      LOAD_ATTR                       4: execute_sync
                108     LOAD_FAST                       5: _var_var_2
                110     LOAD_FAST                       2: sync_type
                112     CALL                            2
                120     POP_TOP                         
                122     LOAD_DEREF                      6: _var_var_0
                124     LOAD_CONST                      4: 'result'
                126     BINARY_SUBSCR                   
                130     NOP                             
                132     NOP                             
                134     NOP                             
                136     JUMP_FORWARD                    20 (to 178)
                138     CALL                            1
                146     POP_TOP                         
                148     RETURN_VALUE                    
                150     PUSH_EXC_INFO                   
                152     PUSH_NULL                       
                154     LOAD_CONST                      7: '__pyarmor_exit_54990__'
                156     NOP                             
                158     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00 v\x00\x00\x00\x00\x00\x00\x00'
                160     CALL                            1
                168     POP_TOP                         
                170     RERAISE                         0
                172     COPY                            3
                174     POP_EXCEPT                      
                176     RERAISE                         1
                178     PUSH_NULL                       
                180     LOAD_CONST                      7: '__pyarmor_exit_54990__'
                182     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00 v\x00\x00\x00\x00\x00\x00\x00'
                184     BUILD_TUPLE                     1
                186     CALL_FUNCTION_EX                0
                188     POP_TOP                         
                190     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: func_analysis
            Qualified Name: func_analysis
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 11
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_execute'
                'build_prompt'
                'settings_manager'
                'settings'
                'len'
                'idc'
                'get_func_name'
                'ida_kernwin'
                'ask_yn'
                'hex'
                'add_cancel_button'
                'model'
                'asyncio'
                'run'
                'call_model_mock'
                'call_model'
                'startswith'
                'remove_cancel_button'
                'parse_model_response_json'
                'get_func_args_vars'
                'response_check_and_refine'
                'create_user_confirm_view'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_3'
                '_var_var_4'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
                '_var_var_11'
                '_var_var_12'
            [Constants]
                None
                '__pyarmor_assert_54994__'
                '__pyarmor_enter_54995__'
                b'<COAddr>\x03\x00\x00\x1a\xb4\x03\x00\x00\x00\x00\x00\x00'
                '<func-analysis>'
                (
                )
                '__pyarmor_exit_54996__'
                'need_confirm'
                1
                'perform function analysis on '
                ':'
                ' with '
                ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                'debug_mode'
                '<Cancelled>'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54995__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xb4\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '<func-analysis>'
                30      STORE_FAST                      2: _var_var_3
                32      LOAD_GLOBAL                     1: NULL + ida_execute
                42      LOAD_GLOBAL                     2: build_prompt
                52      LOAD_FAST                       0: ea
                54      LOAD_FAST                       2: _var_var_3
                56      LOAD_CONST                      5: ()
                58      BUILD_TUPLE                     3
                60      CALL                            2
                68      STORE_FAST                      3: _var_var_4
                70      LOAD_FAST                       3: _var_var_4
                72      POP_JUMP_IF_TRUE                11 (to 96)
                74      NOP                             
                76      LOAD_CONST                      0: None
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    458 (to 1002)
                92      POP_TOP                         
                94      RETURN_CONST                    0: None
                96      LOAD_GLOBAL                     4: settings_manager
                106     LOAD_ATTR                       6: settings
                126     LOAD_CONST                      7: 'need_confirm'
                128     BINARY_SUBSCR                   
                132     POP_JUMP_IF_FALSE               101 (to 336)
                134     LOAD_GLOBAL                     9: NULL + len
                144     LOAD_FAST                       3: _var_var_4
                146     CALL                            1
                154     STORE_FAST                      4: _var_var_5
                156     LOAD_GLOBAL                     1: NULL + ida_execute
                166     LOAD_GLOBAL                     10: idc
                176     LOAD_ATTR                       12: get_func_name
                196     LOAD_FAST                       0: ea
                198     BUILD_TUPLE                     1
                200     CALL                            2
                208     STORE_FAST                      5: _var_var_6
                210     LOAD_GLOBAL                     1: NULL + ida_execute
                220     LOAD_GLOBAL                     14: ida_kernwin
                230     LOAD_ATTR                       16: ask_yn
                250     LOAD_CONST                      8: 1
                252     LOAD_CONST                      9: 'perform function analysis on '
                254     LOAD_GLOBAL                     19: NULL + hex
                264     LOAD_FAST                       0: ea
                266     CALL                            1
                274     FORMAT_VALUE                    0 (FVC_NONE)
                276     LOAD_CONST                      10: ':'
                278     LOAD_FAST                       5: _var_var_6
                280     FORMAT_VALUE                    0 (FVC_NONE)
                282     LOAD_CONST                      11: ' with '
                284     LOAD_FAST                       4: _var_var_5
                286     FORMAT_VALUE                    0 (FVC_NONE)
                288     LOAD_CONST                      12: ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                290     BUILD_STRING                    7
                292     BUILD_TUPLE                     2
                294     CALL                            2
                302     STORE_FAST                      6: _var_var_7
                304     LOAD_FAST                       6: _var_var_7
                306     LOAD_CONST                      8: 1
                308     COMPARE_OP                      55 (!=)
                312     POP_JUMP_IF_FALSE               11 (to 336)
                314     NOP                             
                316     LOAD_CONST                      0: None
                318     NOP                             
                320     NOP                             
                322     JUMP_FORWARD                    338 (to 1002)
                332     POP_TOP                         
                334     RETURN_CONST                    0: None
                336     LOAD_GLOBAL                     1: NULL + ida_execute
                346     LOAD_GLOBAL                     20: add_cancel_button
                356     LOAD_GLOBAL                     22: model
                366     BUILD_TUPLE                     1
                368     CALL                            2
                376     STORE_FAST                      7: _var_var_8
                378     NOP                             
                380     LOAD_GLOBAL                     4: settings_manager
                390     LOAD_ATTR                       6: settings
                410     LOAD_CONST                      13: 'debug_mode'
                412     BINARY_SUBSCR                   
                416     POP_JUMP_IF_FALSE               45 (to 508)
                418     LOAD_GLOBAL                     25: NULL + asyncio
                428     LOAD_ATTR                       26: run
                448     LOAD_GLOBAL                     22: model
                458     LOAD_ATTR                       29: call_model_mock
                478     LOAD_FAST                       3: _var_var_4
                480     LOAD_FAST                       2: _var_var_3
                482     CALL                            2
                490     CALL                            1
                498     UNPACK_SEQUENCE                 2
                502     STORE_FAST                      8: _var_var_9
                504     STORE_FAST                      3: _var_var_4
                506     JUMP_FORWARD                    44 (to 596)
                508     LOAD_GLOBAL                     25: NULL + asyncio
                518     LOAD_ATTR                       26: run
                538     LOAD_GLOBAL                     22: model
                548     LOAD_ATTR                       31: call_model
                568     LOAD_FAST                       3: _var_var_4
                570     LOAD_FAST                       2: _var_var_3
                572     CALL                            2
                580     CALL                            1
                588     UNPACK_SEQUENCE                 2
                592     STORE_FAST                      8: _var_var_9
                594     STORE_FAST                      3: _var_var_4
                596     LOAD_FAST                       8: _var_var_9
                598     LOAD_ATTR                       33: startswith
                618     LOAD_CONST                      14: '<Cancelled>'
                620     CALL                            1
                628     POP_JUMP_IF_FALSE               28 (to 686)
                630     NOP                             
                632     LOAD_GLOBAL                     1: NULL + ida_execute
                642     LOAD_GLOBAL                     34: remove_cancel_button
                652     LOAD_FAST                       7: _var_var_8
                654     BUILD_TUPLE                     1
                656     CALL                            2
                664     POP_TOP                         
                666     LOAD_CONST                      0: None
                668     NOP                             
                670     NOP                             
                672     NOP                             
                674     JUMP_FORWARD                    163 (to 1002)
                682     POP_TOP                         
                684     RETURN_CONST                    0: None
                686     LOAD_GLOBAL                     37: NULL + parse_model_response_json
                696     LOAD_FAST                       8: _var_var_9
                698     CALL                            1
                706     STORE_FAST                      9: _var_var_10
                708     LOAD_FAST                       9: _var_var_10
                710     POP_JUMP_IF_TRUE                28 (to 768)
                712     NOP                             
                714     LOAD_GLOBAL                     1: NULL + ida_execute
                724     LOAD_GLOBAL                     34: remove_cancel_button
                734     LOAD_FAST                       7: _var_var_8
                736     BUILD_TUPLE                     1
                738     CALL                            2
                746     POP_TOP                         
                748     LOAD_CONST                      0: None
                750     NOP                             
                752     NOP                             
                754     NOP                             
                756     JUMP_FORWARD                    122 (to 1002)
                764     POP_TOP                         
                766     RETURN_CONST                    0: None
                768     LOAD_GLOBAL                     1: NULL + ida_execute
                778     LOAD_GLOBAL                     38: get_func_args_vars
                788     LOAD_FAST                       0: ea
                790     BUILD_TUPLE                     1
                792     CALL                            2
                800     UNPACK_SEQUENCE                 2
                804     STORE_FAST                      10: _var_var_11
                806     STORE_FAST                      11: _var_var_12
                808     LOAD_GLOBAL                     41: NULL + response_check_and_refine
                818     LOAD_FAST                       9: _var_var_10
                820     LOAD_FAST                       2: _var_var_3
                822     LOAD_FAST                       10: _var_var_11
                824     LOAD_FAST                       11: _var_var_12
                826     CALL                            4
                834     STORE_FAST                      9: _var_var_10
                836     LOAD_GLOBAL                     1: NULL + ida_execute
                846     LOAD_GLOBAL                     42: create_user_confirm_view
                856     LOAD_FAST                       0: ea
                858     LOAD_FAST                       2: _var_var_3
                860     LOAD_FAST                       3: _var_var_4
                862     LOAD_FAST                       8: _var_var_9
                864     LOAD_FAST                       9: _var_var_10
                866     BUILD_TUPLE                     5
                868     CALL                            2
                876     LOAD_GLOBAL                     1: NULL + ida_execute
                886     LOAD_GLOBAL                     34: remove_cancel_button
                896     LOAD_FAST                       7: _var_var_8
                898     BUILD_TUPLE                     1
                900     CALL                            2
                908     POP_TOP                         
                910     NOP                             
                912     NOP                             
                914     NOP                             
                916     JUMP_FORWARD                    42 (to 1002)
                918     CALL                            1
                926     POP_TOP                         
                928     RETURN_VALUE                    
                930     PUSH_EXC_INFO                   
                932     LOAD_GLOBAL                     1: NULL + ida_execute
                942     LOAD_GLOBAL                     34: remove_cancel_button
                952     LOAD_FAST                       7: _var_var_8
                954     BUILD_TUPLE                     1
                956     CALL                            2
                964     POP_TOP                         
                966     RERAISE                         0
                968     COPY                            3
                970     POP_EXCEPT                      
                972     RERAISE                         1
                974     PUSH_EXC_INFO                   
                976     PUSH_NULL                       
                978     LOAD_CONST                      6: '__pyarmor_exit_54996__'
                980     NOP                             
                982     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xb4\x03\x00\x00\x00\x00\x00\x00'
                984     CALL                            1
                992     POP_TOP                         
                994     RERAISE                         0
                996     COPY                            3
                998     POP_EXCEPT                      
                1000    RERAISE                         1
                1002    PUSH_NULL                       
                1004    LOAD_CONST                      6: '__pyarmor_exit_54996__'
                1006    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xb4\x03\x00\x00\x00\x00\x00\x00'
                1008    BUILD_TUPLE                     1
                1010    CALL_FUNCTION_EX                0
                1012    POP_TOP                         
                1014    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: decompilation
            Qualified Name: decompilation
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 11
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_execute'
                'build_prompt'
                'settings_manager'
                'settings'
                'len'
                'idc'
                'get_func_name'
                'ida_kernwin'
                'ask_yn'
                'hex'
                'add_cancel_button'
                'model'
                'asyncio'
                'run'
                'call_model_mock'
                'call_model'
                'startswith'
                'remove_cancel_button'
                'parse_model_response_str'
                'send_feedback'
                'create_decompilation_view'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_3'
                '_var_var_4'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
            [Constants]
                None
                '__pyarmor_assert_54997__'
                '__pyarmor_enter_54998__'
                b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                '<decompilation>'
                (
                )
                '__pyarmor_exit_54999__'
                'need_confirm'
                1
                'perform decompilation on '
                ':'
                ' with '
                ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                'debug_mode'
                '<Cancelled>'
                'feedback'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54998__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '<decompilation>'
                30      STORE_FAST                      2: _var_var_3
                32      LOAD_GLOBAL                     1: NULL + ida_execute
                42      LOAD_GLOBAL                     2: build_prompt
                52      LOAD_FAST                       0: ea
                54      LOAD_FAST                       2: _var_var_3
                56      LOAD_CONST                      5: ()
                58      BUILD_TUPLE                     3
                60      CALL                            2
                68      STORE_FAST                      3: _var_var_4
                70      LOAD_FAST                       3: _var_var_4
                72      POP_JUMP_IF_TRUE                11 (to 96)
                74      NOP                             
                76      LOAD_CONST                      0: None
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    454 (to 994)
                92      POP_TOP                         
                94      RETURN_CONST                    0: None
                96      LOAD_GLOBAL                     4: settings_manager
                106     LOAD_ATTR                       6: settings
                126     LOAD_CONST                      7: 'need_confirm'
                128     BINARY_SUBSCR                   
                132     POP_JUMP_IF_FALSE               101 (to 336)
                134     LOAD_GLOBAL                     9: NULL + len
                144     LOAD_FAST                       3: _var_var_4
                146     CALL                            1
                154     STORE_FAST                      4: _var_var_5
                156     LOAD_GLOBAL                     1: NULL + ida_execute
                166     LOAD_GLOBAL                     10: idc
                176     LOAD_ATTR                       12: get_func_name
                196     LOAD_FAST                       0: ea
                198     BUILD_TUPLE                     1
                200     CALL                            2
                208     STORE_FAST                      5: _var_var_6
                210     LOAD_GLOBAL                     1: NULL + ida_execute
                220     LOAD_GLOBAL                     14: ida_kernwin
                230     LOAD_ATTR                       16: ask_yn
                250     LOAD_CONST                      8: 1
                252     LOAD_CONST                      9: 'perform decompilation on '
                254     LOAD_GLOBAL                     19: NULL + hex
                264     LOAD_FAST                       0: ea
                266     CALL                            1
                274     FORMAT_VALUE                    0 (FVC_NONE)
                276     LOAD_CONST                      10: ':'
                278     LOAD_FAST                       5: _var_var_6
                280     FORMAT_VALUE                    0 (FVC_NONE)
                282     LOAD_CONST                      11: ' with '
                284     LOAD_FAST                       4: _var_var_5
                286     FORMAT_VALUE                    0 (FVC_NONE)
                288     LOAD_CONST                      12: ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                290     BUILD_STRING                    7
                292     BUILD_TUPLE                     2
                294     CALL                            2
                302     STORE_FAST                      6: _var_var_7
                304     LOAD_FAST                       6: _var_var_7
                306     LOAD_CONST                      8: 1
                308     COMPARE_OP                      55 (!=)
                312     POP_JUMP_IF_FALSE               11 (to 336)
                314     NOP                             
                316     LOAD_CONST                      0: None
                318     NOP                             
                320     NOP                             
                322     JUMP_FORWARD                    334 (to 994)
                332     POP_TOP                         
                334     RETURN_CONST                    0: None
                336     LOAD_GLOBAL                     1: NULL + ida_execute
                346     LOAD_GLOBAL                     20: add_cancel_button
                356     LOAD_GLOBAL                     22: model
                366     BUILD_TUPLE                     1
                368     CALL                            2
                376     STORE_FAST                      7: _var_var_8
                378     NOP                             
                380     LOAD_GLOBAL                     4: settings_manager
                390     LOAD_ATTR                       6: settings
                410     LOAD_CONST                      13: 'debug_mode'
                412     BINARY_SUBSCR                   
                416     POP_JUMP_IF_FALSE               45 (to 508)
                418     LOAD_GLOBAL                     25: NULL + asyncio
                428     LOAD_ATTR                       26: run
                448     LOAD_GLOBAL                     22: model
                458     LOAD_ATTR                       29: call_model_mock
                478     LOAD_FAST                       3: _var_var_4
                480     LOAD_FAST                       2: _var_var_3
                482     CALL                            2
                490     CALL                            1
                498     UNPACK_SEQUENCE                 2
                502     STORE_FAST                      8: _var_var_9
                504     STORE_FAST                      3: _var_var_4
                506     JUMP_FORWARD                    44 (to 596)
                508     LOAD_GLOBAL                     25: NULL + asyncio
                518     LOAD_ATTR                       26: run
                538     LOAD_GLOBAL                     22: model
                548     LOAD_ATTR                       31: call_model
                568     LOAD_FAST                       3: _var_var_4
                570     LOAD_FAST                       2: _var_var_3
                572     CALL                            2
                580     CALL                            1
                588     UNPACK_SEQUENCE                 2
                592     STORE_FAST                      8: _var_var_9
                594     STORE_FAST                      3: _var_var_4
                596     LOAD_FAST                       8: _var_var_9
                598     LOAD_ATTR                       33: startswith
                618     LOAD_CONST                      14: '<Cancelled>'
                620     CALL                            1
                628     POP_JUMP_IF_FALSE               28 (to 686)
                630     NOP                             
                632     LOAD_GLOBAL                     1: NULL + ida_execute
                642     LOAD_GLOBAL                     34: remove_cancel_button
                652     LOAD_FAST                       7: _var_var_8
                654     BUILD_TUPLE                     1
                656     CALL                            2
                664     POP_TOP                         
                666     LOAD_CONST                      0: None
                668     NOP                             
                670     NOP                             
                672     NOP                             
                674     JUMP_FORWARD                    159 (to 994)
                682     POP_TOP                         
                684     RETURN_CONST                    0: None
                686     LOAD_GLOBAL                     37: NULL + parse_model_response_str
                696     LOAD_FAST                       8: _var_var_9
                698     CALL                            1
                706     STORE_FAST                      9: _var_var_10
                708     LOAD_FAST                       9: _var_var_10
                710     POP_JUMP_IF_TRUE                28 (to 768)
                712     NOP                             
                714     LOAD_GLOBAL                     1: NULL + ida_execute
                724     LOAD_GLOBAL                     34: remove_cancel_button
                734     LOAD_FAST                       7: _var_var_8
                736     BUILD_TUPLE                     1
                738     CALL                            2
                746     POP_TOP                         
                748     LOAD_CONST                      0: None
                750     NOP                             
                752     NOP                             
                754     NOP                             
                756     JUMP_FORWARD                    118 (to 994)
                764     POP_TOP                         
                766     RETURN_CONST                    0: None
                768     LOAD_GLOBAL                     4: settings_manager
                778     LOAD_ATTR                       6: settings
                798     LOAD_CONST                      15: 'feedback'
                800     BINARY_SUBSCR                   
                804     POP_JUMP_IF_FALSE               14 (to 834)
                806     LOAD_GLOBAL                     39: NULL + send_feedback
                816     LOAD_FAST                       3: _var_var_4
                818     LOAD_FAST                       8: _var_var_9
                820     LOAD_FAST                       9: _var_var_10
                822     LOAD_FAST                       2: _var_var_3
                824     CALL                            4
                832     POP_TOP                         
                834     LOAD_GLOBAL                     1: NULL + ida_execute
                844     LOAD_GLOBAL                     40: create_decompilation_view
                854     LOAD_FAST                       0: ea
                856     LOAD_FAST                       9: _var_var_10
                858     BUILD_TUPLE                     2
                860     CALL                            2
                868     LOAD_GLOBAL                     1: NULL + ida_execute
                878     LOAD_GLOBAL                     34: remove_cancel_button
                888     LOAD_FAST                       7: _var_var_8
                890     BUILD_TUPLE                     1
                892     CALL                            2
                900     POP_TOP                         
                902     NOP                             
                904     NOP                             
                906     NOP                             
                908     JUMP_FORWARD                    42 (to 994)
                910     CALL                            1
                918     POP_TOP                         
                920     RETURN_VALUE                    
                922     PUSH_EXC_INFO                   
                924     LOAD_GLOBAL                     1: NULL + ida_execute
                934     LOAD_GLOBAL                     34: remove_cancel_button
                944     LOAD_FAST                       7: _var_var_8
                946     BUILD_TUPLE                     1
                948     CALL                            2
                956     POP_TOP                         
                958     RERAISE                         0
                960     COPY                            3
                962     POP_EXCEPT                      
                964     RERAISE                         1
                966     PUSH_EXC_INFO                   
                968     PUSH_NULL                       
                970     LOAD_CONST                      6: '__pyarmor_exit_54999__'
                972     NOP                             
                974     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                976     CALL                            1
                984     POP_TOP                         
                986     RERAISE                         0
                988     COPY                            3
                990     POP_EXCEPT                      
                992     RERAISE                         1
                994     PUSH_NULL                       
                996     LOAD_CONST                      6: '__pyarmor_exit_54999__'
                998     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                1000    BUILD_TUPLE                     1
                1002    CALL_FUNCTION_EX                0
                1004    POP_TOP                         
                1006    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: specific_vars_analysis
            Qualified Name: specific_vars_analysis
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 8
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_execute'
                'create_variable_selection_view'
                'time'
                'sleep'
                'selected_args'
                'selected_vars'
                'print'
                'build_prompt'
                'add_cancel_button'
                'model'
                'settings_manager'
                'settings'
                'asyncio'
                'run'
                'call_model_mock'
                'call_model'
                'startswith'
                'remove_cancel_button'
                'parse_model_response_json'
                'response_check_and_refine'
                'split_pred_to_var_arg'
                'create_user_confirm_view'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_14'
                '_var_var_15'
                '_var_var_16'
                '_var_var_3'
                '_var_var_4'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
                '_var_var_13'
            [Constants]
                None
                '__pyarmor_assert_55000__'
                '__pyarmor_enter_55001__'
                b'<COAddr>\x03\x00\x00\x1c\xd2\x03\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: check_form
                    Qualified Name: specific_vars_analysis.<locals>.check_form
                    Arg Count: 0
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'selected_args'
                        'selected_vars'
                    [Locals+Names]
                        '__assert_armored__'
                        '_var_var_13'
                    [Constants]
                        None
                        '__pyarmor_assert_55003__'
                        '__pyarmor_enter_55004__'
                        b'<COAddr>\x03\x00\x00\x1c\\\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55005__'
                        True
                        False
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_55004__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\\\x00\x00\x00\x00\x00\x00\x00'
                        12      BUILD_TUPLE                     1
                        14      CALL_FUNCTION_EX                0
                        16      POP_TOP                         
                        18      RESUME                          0
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      LOAD_DEREF                      1: _var_var_13
                        32      LOAD_ATTR                       0: selected_args
                        52      POP_JUMP_IF_TRUE                12 (to 78)
                        54      LOAD_DEREF                      1: _var_var_13
                        56      LOAD_ATTR                       2: selected_vars
                        76      POP_JUMP_IF_FALSE               11 (to 100)
                        78      NOP                             
                        80      LOAD_CONST                      5: True
                        82      NOP                             
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    29 (to 148)
                        96      POP_TOP                         
                        98      RETURN_CONST                    5: True
                        100     LOAD_CONST                      6: False
                        102     NOP                             
                        104     NOP                             
                        106     NOP                             
                        108     JUMP_FORWARD                    19 (to 148)
                        116     POP_TOP                         
                        118     RETURN_CONST                    6: False
                        120     PUSH_EXC_INFO                   
                        122     PUSH_NULL                       
                        124     LOAD_CONST                      4: '__pyarmor_exit_55005__'
                        126     NOP                             
                        128     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\\\x00\x00\x00\x00\x00\x00\x00'
                        130     CALL                            1
                        138     POP_TOP                         
                        140     RERAISE                         0
                        142     COPY                            3
                        144     POP_EXCEPT                      
                        146     RERAISE                         1
                        148     PUSH_NULL                       
                        150     LOAD_CONST                      4: '__pyarmor_exit_55005__'
                        152     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\\\x00\x00\x00\x00\x00\x00\x00'
                        154     BUILD_TUPLE                     1
                        156     CALL_FUNCTION_EX                0
                        158     POP_TOP                         
                        160     RETURN_VALUE                    
                0.1
                '[!] No variables selected'
                '__pyarmor_exit_55002__'
                '[*] Selected arguments:'
                '[*] Selected variables:'
                '<specific-vars>'
                'debug_mode'
                '<Cancelled>'
            [Disassembly]
                0       MAKE_CELL                       10: _var_var_13
                2       NOP                             
                4       NOP                             
                6       PUSH_NULL                       
                8       LOAD_CONST                      2: '__pyarmor_enter_55001__'
                10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xd2\x03\x00\x00\x00\x00\x00\x00'
                12      BUILD_TUPLE                     1
                14      CALL_FUNCTION_EX                0
                16      POP_TOP                         
                18      RESUME                          0
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      NOP                             
                30      LOAD_GLOBAL                     1: NULL + ida_execute
                40      LOAD_GLOBAL                     2: create_variable_selection_view
                50      LOAD_FAST                       0: ea
                52      BUILD_TUPLE                     1
                54      CALL                            2
                62      STORE_DEREF                     10: _var_var_13
                64      BUILD_LIST                      0
                66      STORE_FAST                      2: _var_var_14
                68      BUILD_LIST                      0
                70      STORE_FAST                      3: _var_var_15
                72      LOAD_CLOSURE                    10: _var_var_13
                74      BUILD_TUPLE                     1
                76      LOAD_CONST                      4: <CODE> check_form
                78      MAKE_FUNCTION                   8
                80      STORE_FAST                      4: _var_var_16
                82      PUSH_NULL                       
                84      LOAD_FAST                       4: _var_var_16
                86      CALL                            0
                94      POP_JUMP_IF_TRUE                29 (to 154)
                96      LOAD_GLOBAL                     5: NULL + time
                106     LOAD_ATTR                       6: sleep
                126     LOAD_CONST                      5: 0.1
                128     CALL                            1
                136     POP_TOP                         
                138     PUSH_NULL                       
                140     LOAD_FAST                       4: _var_var_16
                142     CALL                            0
                150     POP_JUMP_IF_TRUE                1 (to 154)
                152     JUMP_BACKWARD                   29 (to 96)
                154     LOAD_DEREF                      10: _var_var_13
                156     LOAD_ATTR                       8: selected_args
                176     STORE_FAST                      2: _var_var_14
                178     LOAD_DEREF                      10: _var_var_13
                180     LOAD_ATTR                       10: selected_vars
                200     STORE_FAST                      3: _var_var_15
                202     LOAD_FAST                       2: _var_var_14
                204     POP_JUMP_IF_TRUE                24 (to 254)
                206     LOAD_FAST                       3: _var_var_15
                208     POP_JUMP_IF_TRUE                22 (to 254)
                210     LOAD_GLOBAL                     13: NULL + print
                220     LOAD_CONST                      6: '[!] No variables selected'
                222     CALL                            1
                230     POP_TOP                         
                232     NOP                             
                234     LOAD_CONST                      0: None
                236     NOP                             
                238     NOP                             
                240     JUMP_FORWARD                    395 (to 1034)
                250     POP_TOP                         
                252     RETURN_CONST                    0: None
                254     LOAD_GLOBAL                     13: NULL + print
                264     LOAD_CONST                      8: '[*] Selected arguments:'
                266     LOAD_FAST                       2: _var_var_14
                268     CALL                            2
                276     POP_TOP                         
                278     LOAD_GLOBAL                     13: NULL + print
                288     LOAD_CONST                      9: '[*] Selected variables:'
                290     LOAD_FAST                       3: _var_var_15
                292     CALL                            2
                300     POP_TOP                         
                302     LOAD_CONST                      10: '<specific-vars>'
                304     STORE_FAST                      5: _var_var_3
                306     LOAD_GLOBAL                     1: NULL + ida_execute
                316     LOAD_GLOBAL                     14: build_prompt
                326     LOAD_FAST                       0: ea
                328     LOAD_FAST                       5: _var_var_3
                330     LOAD_FAST                       2: _var_var_14
                332     LOAD_FAST                       3: _var_var_15
                334     BINARY_OP                       0 (+)
                338     BUILD_TUPLE                     3
                340     CALL                            2
                348     STORE_FAST                      6: _var_var_4
                350     LOAD_FAST                       6: _var_var_4
                352     POP_JUMP_IF_TRUE                11 (to 376)
                354     NOP                             
                356     LOAD_CONST                      0: None
                358     NOP                             
                360     NOP                             
                362     JUMP_FORWARD                    334 (to 1034)
                372     POP_TOP                         
                374     RETURN_CONST                    0: None
                376     LOAD_GLOBAL                     1: NULL + ida_execute
                386     LOAD_GLOBAL                     16: add_cancel_button
                396     LOAD_GLOBAL                     18: model
                406     BUILD_TUPLE                     1
                408     CALL                            2
                416     STORE_FAST                      7: _var_var_8
                418     NOP                             
                420     LOAD_GLOBAL                     20: settings_manager
                430     LOAD_ATTR                       22: settings
                450     LOAD_CONST                      11: 'debug_mode'
                452     BINARY_SUBSCR                   
                456     POP_JUMP_IF_FALSE               45 (to 548)
                458     LOAD_GLOBAL                     25: NULL + asyncio
                468     LOAD_ATTR                       26: run
                488     LOAD_GLOBAL                     18: model
                498     LOAD_ATTR                       29: call_model_mock
                518     LOAD_FAST                       6: _var_var_4
                520     LOAD_FAST                       5: _var_var_3
                522     CALL                            2
                530     CALL                            1
                538     UNPACK_SEQUENCE                 2
                542     STORE_FAST                      8: _var_var_9
                544     STORE_FAST                      6: _var_var_4
                546     JUMP_FORWARD                    44 (to 636)
                548     LOAD_GLOBAL                     25: NULL + asyncio
                558     LOAD_ATTR                       26: run
                578     LOAD_GLOBAL                     18: model
                588     LOAD_ATTR                       31: call_model
                608     LOAD_FAST                       6: _var_var_4
                610     LOAD_FAST                       5: _var_var_3
                612     CALL                            2
                620     CALL                            1
                628     UNPACK_SEQUENCE                 2
                632     STORE_FAST                      8: _var_var_9
                634     STORE_FAST                      6: _var_var_4
                636     LOAD_FAST                       8: _var_var_9
                638     LOAD_ATTR                       33: startswith
                658     LOAD_CONST                      12: '<Cancelled>'
                660     CALL                            1
                668     POP_JUMP_IF_FALSE               28 (to 726)
                670     NOP                             
                672     LOAD_GLOBAL                     1: NULL + ida_execute
                682     LOAD_GLOBAL                     34: remove_cancel_button
                692     LOAD_FAST                       7: _var_var_8
                694     BUILD_TUPLE                     1
                696     CALL                            2
                704     POP_TOP                         
                706     LOAD_CONST                      0: None
                708     NOP                             
                710     NOP                             
                712     NOP                             
                714     JUMP_FORWARD                    159 (to 1034)
                722     POP_TOP                         
                724     RETURN_CONST                    0: None
                726     LOAD_GLOBAL                     37: NULL + parse_model_response_json
                736     LOAD_FAST                       8: _var_var_9
                738     CALL                            1
                746     STORE_FAST                      9: _var_var_10
                748     LOAD_FAST                       9: _var_var_10
                750     POP_JUMP_IF_TRUE                28 (to 808)
                752     NOP                             
                754     LOAD_GLOBAL                     1: NULL + ida_execute
                764     LOAD_GLOBAL                     34: remove_cancel_button
                774     LOAD_FAST                       7: _var_var_8
                776     BUILD_TUPLE                     1
                778     CALL                            2
                786     POP_TOP                         
                788     LOAD_CONST                      0: None
                790     NOP                             
                792     NOP                             
                794     NOP                             
                796     JUMP_FORWARD                    118 (to 1034)
                804     POP_TOP                         
                806     RETURN_CONST                    0: None
                808     LOAD_GLOBAL                     39: NULL + response_check_and_refine
                818     LOAD_FAST                       9: _var_var_10
                820     LOAD_FAST                       5: _var_var_3
                822     CALL                            2
                830     STORE_FAST                      9: _var_var_10
                832     LOAD_GLOBAL                     1: NULL + ida_execute
                842     LOAD_GLOBAL                     40: split_pred_to_var_arg
                852     LOAD_FAST                       0: ea
                854     LOAD_FAST                       9: _var_var_10
                856     BUILD_TUPLE                     2
                858     CALL                            2
                866     STORE_FAST                      9: _var_var_10
                868     LOAD_GLOBAL                     1: NULL + ida_execute
                878     LOAD_GLOBAL                     42: create_user_confirm_view
                888     LOAD_FAST                       0: ea
                890     LOAD_FAST                       5: _var_var_3
                892     LOAD_FAST                       6: _var_var_4
                894     LOAD_FAST                       8: _var_var_9
                896     LOAD_FAST                       9: _var_var_10
                898     BUILD_TUPLE                     5
                900     CALL                            2
                908     LOAD_GLOBAL                     1: NULL + ida_execute
                918     LOAD_GLOBAL                     34: remove_cancel_button
                928     LOAD_FAST                       7: _var_var_8
                930     BUILD_TUPLE                     1
                932     CALL                            2
                940     POP_TOP                         
                942     NOP                             
                944     NOP                             
                946     NOP                             
                948     JUMP_FORWARD                    42 (to 1034)
                950     CALL                            1
                958     POP_TOP                         
                960     RETURN_VALUE                    
                962     PUSH_EXC_INFO                   
                964     LOAD_GLOBAL                     1: NULL + ida_execute
                974     LOAD_GLOBAL                     34: remove_cancel_button
                984     LOAD_FAST                       7: _var_var_8
                986     BUILD_TUPLE                     1
                988     CALL                            2
                996     POP_TOP                         
                998     RERAISE                         0
                1000    COPY                            3
                1002    POP_EXCEPT                      
                1004    RERAISE                         1
                1006    PUSH_EXC_INFO                   
                1008    PUSH_NULL                       
                1010    LOAD_CONST                      7: '__pyarmor_exit_55002__'
                1012    NOP                             
                1014    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xd2\x03\x00\x00\x00\x00\x00\x00'
                1016    CALL                            1
                1024    POP_TOP                         
                1026    RERAISE                         0
                1028    COPY                            3
                1030    POP_EXCEPT                      
                1032    RERAISE                         1
                1034    PUSH_NULL                       
                1036    LOAD_CONST                      7: '__pyarmor_exit_55002__'
                1038    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xd2\x03\x00\x00\x00\x00\x00\x00'
                1040    BUILD_TUPLE                     1
                1042    CALL_FUNCTION_EX                0
                1044    POP_TOP                         
                1046    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: all_vars_analysis
            Qualified Name: all_vars_analysis
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 11
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_execute'
                'build_prompt'
                'settings_manager'
                'settings'
                'len'
                'idc'
                'get_func_name'
                'ida_kernwin'
                'ask_yn'
                'hex'
                'add_cancel_button'
                'model'
                'asyncio'
                'run'
                'call_model_mock'
                'call_model'
                'startswith'
                'remove_cancel_button'
                'parse_model_response_json'
                'response_check_and_refine'
                'split_pred_to_var_arg'
                'create_user_confirm_view'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_3'
                '_var_var_4'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
            [Constants]
                None
                '__pyarmor_assert_55006__'
                '__pyarmor_enter_55007__'
                b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                '<vars>'
                (
                )
                '__pyarmor_exit_55008__'
                'need_confirm'
                1
                'perform all variable analysis on '
                ':'
                ' with '
                ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                'debug_mode'
                '<Cancelled>'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55007__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '<vars>'
                30      STORE_FAST                      2: _var_var_3
                32      LOAD_GLOBAL                     1: NULL + ida_execute
                42      LOAD_GLOBAL                     2: build_prompt
                52      LOAD_FAST                       0: ea
                54      LOAD_FAST                       2: _var_var_3
                56      LOAD_CONST                      5: ()
                58      BUILD_TUPLE                     3
                60      CALL                            2
                68      STORE_FAST                      3: _var_var_4
                70      LOAD_FAST                       3: _var_var_4
                72      POP_JUMP_IF_TRUE                11 (to 96)
                74      NOP                             
                76      LOAD_CONST                      0: None
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    454 (to 994)
                92      POP_TOP                         
                94      RETURN_CONST                    0: None
                96      LOAD_GLOBAL                     4: settings_manager
                106     LOAD_ATTR                       6: settings
                126     LOAD_CONST                      7: 'need_confirm'
                128     BINARY_SUBSCR                   
                132     POP_JUMP_IF_FALSE               101 (to 336)
                134     LOAD_GLOBAL                     9: NULL + len
                144     LOAD_FAST                       3: _var_var_4
                146     CALL                            1
                154     STORE_FAST                      4: _var_var_5
                156     LOAD_GLOBAL                     1: NULL + ida_execute
                166     LOAD_GLOBAL                     10: idc
                176     LOAD_ATTR                       12: get_func_name
                196     LOAD_FAST                       0: ea
                198     BUILD_TUPLE                     1
                200     CALL                            2
                208     STORE_FAST                      5: _var_var_6
                210     LOAD_GLOBAL                     1: NULL + ida_execute
                220     LOAD_GLOBAL                     14: ida_kernwin
                230     LOAD_ATTR                       16: ask_yn
                250     LOAD_CONST                      8: 1
                252     LOAD_CONST                      9: 'perform all variable analysis on '
                254     LOAD_GLOBAL                     19: NULL + hex
                264     LOAD_FAST                       0: ea
                266     CALL                            1
                274     FORMAT_VALUE                    0 (FVC_NONE)
                276     LOAD_CONST                      10: ':'
                278     LOAD_FAST                       5: _var_var_6
                280     FORMAT_VALUE                    0 (FVC_NONE)
                282     LOAD_CONST                      11: ' with '
                284     LOAD_FAST                       4: _var_var_5
                286     FORMAT_VALUE                    0 (FVC_NONE)
                288     LOAD_CONST                      12: ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                290     BUILD_STRING                    7
                292     BUILD_TUPLE                     2
                294     CALL                            2
                302     STORE_FAST                      6: _var_var_7
                304     LOAD_FAST                       6: _var_var_7
                306     LOAD_CONST                      8: 1
                308     COMPARE_OP                      55 (!=)
                312     POP_JUMP_IF_FALSE               11 (to 336)
                314     NOP                             
                316     LOAD_CONST                      0: None
                318     NOP                             
                320     NOP                             
                322     JUMP_FORWARD                    334 (to 994)
                332     POP_TOP                         
                334     RETURN_CONST                    0: None
                336     LOAD_GLOBAL                     1: NULL + ida_execute
                346     LOAD_GLOBAL                     20: add_cancel_button
                356     LOAD_GLOBAL                     22: model
                366     BUILD_TUPLE                     1
                368     CALL                            2
                376     STORE_FAST                      7: _var_var_8
                378     NOP                             
                380     LOAD_GLOBAL                     4: settings_manager
                390     LOAD_ATTR                       6: settings
                410     LOAD_CONST                      13: 'debug_mode'
                412     BINARY_SUBSCR                   
                416     POP_JUMP_IF_FALSE               45 (to 508)
                418     LOAD_GLOBAL                     25: NULL + asyncio
                428     LOAD_ATTR                       26: run
                448     LOAD_GLOBAL                     22: model
                458     LOAD_ATTR                       29: call_model_mock
                478     LOAD_FAST                       3: _var_var_4
                480     LOAD_FAST                       2: _var_var_3
                482     CALL                            2
                490     CALL                            1
                498     UNPACK_SEQUENCE                 2
                502     STORE_FAST                      8: _var_var_9
                504     STORE_FAST                      3: _var_var_4
                506     JUMP_FORWARD                    44 (to 596)
                508     LOAD_GLOBAL                     25: NULL + asyncio
                518     LOAD_ATTR                       26: run
                538     LOAD_GLOBAL                     22: model
                548     LOAD_ATTR                       31: call_model
                568     LOAD_FAST                       3: _var_var_4
                570     LOAD_FAST                       2: _var_var_3
                572     CALL                            2
                580     CALL                            1
                588     UNPACK_SEQUENCE                 2
                592     STORE_FAST                      8: _var_var_9
                594     STORE_FAST                      3: _var_var_4
                596     LOAD_FAST                       8: _var_var_9
                598     LOAD_ATTR                       33: startswith
                618     LOAD_CONST                      14: '<Cancelled>'
                620     CALL                            1
                628     POP_JUMP_IF_FALSE               28 (to 686)
                630     NOP                             
                632     LOAD_GLOBAL                     1: NULL + ida_execute
                642     LOAD_GLOBAL                     34: remove_cancel_button
                652     LOAD_FAST                       7: _var_var_8
                654     BUILD_TUPLE                     1
                656     CALL                            2
                664     POP_TOP                         
                666     LOAD_CONST                      0: None
                668     NOP                             
                670     NOP                             
                672     NOP                             
                674     JUMP_FORWARD                    159 (to 994)
                682     POP_TOP                         
                684     RETURN_CONST                    0: None
                686     LOAD_GLOBAL                     37: NULL + parse_model_response_json
                696     LOAD_FAST                       8: _var_var_9
                698     CALL                            1
                706     STORE_FAST                      9: _var_var_10
                708     LOAD_FAST                       9: _var_var_10
                710     POP_JUMP_IF_TRUE                28 (to 768)
                712     NOP                             
                714     LOAD_GLOBAL                     1: NULL + ida_execute
                724     LOAD_GLOBAL                     34: remove_cancel_button
                734     LOAD_FAST                       7: _var_var_8
                736     BUILD_TUPLE                     1
                738     CALL                            2
                746     POP_TOP                         
                748     LOAD_CONST                      0: None
                750     NOP                             
                752     NOP                             
                754     NOP                             
                756     JUMP_FORWARD                    118 (to 994)
                764     POP_TOP                         
                766     RETURN_CONST                    0: None
                768     LOAD_GLOBAL                     39: NULL + response_check_and_refine
                778     LOAD_FAST                       9: _var_var_10
                780     LOAD_FAST                       2: _var_var_3
                782     CALL                            2
                790     STORE_FAST                      9: _var_var_10
                792     LOAD_GLOBAL                     1: NULL + ida_execute
                802     LOAD_GLOBAL                     40: split_pred_to_var_arg
                812     LOAD_FAST                       0: ea
                814     LOAD_FAST                       9: _var_var_10
                816     BUILD_TUPLE                     2
                818     CALL                            2
                826     STORE_FAST                      9: _var_var_10
                828     LOAD_GLOBAL                     1: NULL + ida_execute
                838     LOAD_GLOBAL                     42: create_user_confirm_view
                848     LOAD_FAST                       0: ea
                850     LOAD_FAST                       2: _var_var_3
                852     LOAD_FAST                       3: _var_var_4
                854     LOAD_FAST                       8: _var_var_9
                856     LOAD_FAST                       9: _var_var_10
                858     BUILD_TUPLE                     5
                860     CALL                            2
                868     LOAD_GLOBAL                     1: NULL + ida_execute
                878     LOAD_GLOBAL                     34: remove_cancel_button
                888     LOAD_FAST                       7: _var_var_8
                890     BUILD_TUPLE                     1
                892     CALL                            2
                900     POP_TOP                         
                902     NOP                             
                904     NOP                             
                906     NOP                             
                908     JUMP_FORWARD                    42 (to 994)
                910     CALL                            1
                918     POP_TOP                         
                920     RETURN_VALUE                    
                922     PUSH_EXC_INFO                   
                924     LOAD_GLOBAL                     1: NULL + ida_execute
                934     LOAD_GLOBAL                     34: remove_cancel_button
                944     LOAD_FAST                       7: _var_var_8
                946     BUILD_TUPLE                     1
                948     CALL                            2
                956     POP_TOP                         
                958     RERAISE                         0
                960     COPY                            3
                962     POP_EXCEPT                      
                964     RERAISE                         1
                966     PUSH_EXC_INFO                   
                968     PUSH_NULL                       
                970     LOAD_CONST                      6: '__pyarmor_exit_55008__'
                972     NOP                             
                974     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                976     CALL                            1
                984     POP_TOP                         
                986     RERAISE                         0
                988     COPY                            3
                990     POP_EXCEPT                      
                992     RERAISE                         1
                994     PUSH_NULL                       
                996     LOAD_CONST                      6: '__pyarmor_exit_55008__'
                998     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xac\x03\x00\x00\x00\x00\x00\x00'
                1000    BUILD_TUPLE                     1
                1002    CALL_FUNCTION_EX                0
                1004    POP_TOP                         
                1006    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: all_args_analysis
            Qualified Name: all_args_analysis
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 11
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_execute'
                'build_prompt'
                'settings_manager'
                'settings'
                'len'
                'idc'
                'get_func_name'
                'ida_kernwin'
                'ask_yn'
                'hex'
                'add_cancel_button'
                'model'
                'asyncio'
                'run'
                'call_model_mock'
                'call_model'
                'startswith'
                'remove_cancel_button'
                'parse_model_response_json'
                'response_check_and_refine'
                'create_user_confirm_view'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_3'
                '_var_var_4'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
            [Constants]
                None
                '__pyarmor_assert_55009__'
                '__pyarmor_enter_55010__'
                b'<COAddr>\x03\x00\x00\x1a\x90\x03\x00\x00\x00\x00\x00\x00'
                '<args>'
                (
                )
                '__pyarmor_exit_55011__'
                'need_confirm'
                1
                'perform all argument analysis on '
                ':'
                ' with '
                ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                'debug_mode'
                '<Cancelled>'
                'args'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55010__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '<args>'
                30      STORE_FAST                      2: _var_var_3
                32      LOAD_GLOBAL                     1: NULL + ida_execute
                42      LOAD_GLOBAL                     2: build_prompt
                52      LOAD_FAST                       0: ea
                54      LOAD_FAST                       2: _var_var_3
                56      LOAD_CONST                      5: ()
                58      BUILD_TUPLE                     3
                60      CALL                            2
                68      STORE_FAST                      3: _var_var_4
                70      LOAD_FAST                       3: _var_var_4
                72      POP_JUMP_IF_TRUE                11 (to 96)
                74      NOP                             
                76      LOAD_CONST                      0: None
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    440 (to 966)
                92      POP_TOP                         
                94      RETURN_CONST                    0: None
                96      LOAD_GLOBAL                     4: settings_manager
                106     LOAD_ATTR                       6: settings
                126     LOAD_CONST                      7: 'need_confirm'
                128     BINARY_SUBSCR                   
                132     POP_JUMP_IF_FALSE               101 (to 336)
                134     LOAD_GLOBAL                     9: NULL + len
                144     LOAD_FAST                       3: _var_var_4
                146     CALL                            1
                154     STORE_FAST                      4: _var_var_5
                156     LOAD_GLOBAL                     1: NULL + ida_execute
                166     LOAD_GLOBAL                     10: idc
                176     LOAD_ATTR                       12: get_func_name
                196     LOAD_FAST                       0: ea
                198     BUILD_TUPLE                     1
                200     CALL                            2
                208     STORE_FAST                      5: _var_var_6
                210     LOAD_GLOBAL                     1: NULL + ida_execute
                220     LOAD_GLOBAL                     14: ida_kernwin
                230     LOAD_ATTR                       16: ask_yn
                250     LOAD_CONST                      8: 1
                252     LOAD_CONST                      9: 'perform all argument analysis on '
                254     LOAD_GLOBAL                     19: NULL + hex
                264     LOAD_FAST                       0: ea
                266     CALL                            1
                274     FORMAT_VALUE                    0 (FVC_NONE)
                276     LOAD_CONST                      10: ':'
                278     LOAD_FAST                       5: _var_var_6
                280     FORMAT_VALUE                    0 (FVC_NONE)
                282     LOAD_CONST                      11: ' with '
                284     LOAD_FAST                       4: _var_var_5
                286     FORMAT_VALUE                    0 (FVC_NONE)
                288     LOAD_CONST                      12: ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                290     BUILD_STRING                    7
                292     BUILD_TUPLE                     2
                294     CALL                            2
                302     STORE_FAST                      6: _var_var_7
                304     LOAD_FAST                       6: _var_var_7
                306     LOAD_CONST                      8: 1
                308     COMPARE_OP                      55 (!=)
                312     POP_JUMP_IF_FALSE               11 (to 336)
                314     NOP                             
                316     LOAD_CONST                      0: None
                318     NOP                             
                320     NOP                             
                322     JUMP_FORWARD                    320 (to 966)
                332     POP_TOP                         
                334     RETURN_CONST                    0: None
                336     LOAD_GLOBAL                     1: NULL + ida_execute
                346     LOAD_GLOBAL                     20: add_cancel_button
                356     LOAD_GLOBAL                     22: model
                366     BUILD_TUPLE                     1
                368     CALL                            2
                376     STORE_FAST                      7: _var_var_8
                378     NOP                             
                380     LOAD_GLOBAL                     4: settings_manager
                390     LOAD_ATTR                       6: settings
                410     LOAD_CONST                      13: 'debug_mode'
                412     BINARY_SUBSCR                   
                416     POP_JUMP_IF_FALSE               45 (to 508)
                418     LOAD_GLOBAL                     25: NULL + asyncio
                428     LOAD_ATTR                       26: run
                448     LOAD_GLOBAL                     22: model
                458     LOAD_ATTR                       29: call_model_mock
                478     LOAD_FAST                       3: _var_var_4
                480     LOAD_FAST                       2: _var_var_3
                482     CALL                            2
                490     CALL                            1
                498     UNPACK_SEQUENCE                 2
                502     STORE_FAST                      8: _var_var_9
                504     STORE_FAST                      3: _var_var_4
                506     JUMP_FORWARD                    44 (to 596)
                508     LOAD_GLOBAL                     25: NULL + asyncio
                518     LOAD_ATTR                       26: run
                538     LOAD_GLOBAL                     22: model
                548     LOAD_ATTR                       31: call_model
                568     LOAD_FAST                       3: _var_var_4
                570     LOAD_FAST                       2: _var_var_3
                572     CALL                            2
                580     CALL                            1
                588     UNPACK_SEQUENCE                 2
                592     STORE_FAST                      8: _var_var_9
                594     STORE_FAST                      3: _var_var_4
                596     LOAD_FAST                       8: _var_var_9
                598     LOAD_ATTR                       33: startswith
                618     LOAD_CONST                      14: '<Cancelled>'
                620     CALL                            1
                628     POP_JUMP_IF_FALSE               28 (to 686)
                630     NOP                             
                632     LOAD_GLOBAL                     1: NULL + ida_execute
                642     LOAD_GLOBAL                     34: remove_cancel_button
                652     LOAD_FAST                       7: _var_var_8
                654     BUILD_TUPLE                     1
                656     CALL                            2
                664     POP_TOP                         
                666     LOAD_CONST                      0: None
                668     NOP                             
                670     NOP                             
                672     NOP                             
                674     JUMP_FORWARD                    145 (to 966)
                682     POP_TOP                         
                684     RETURN_CONST                    0: None
                686     LOAD_GLOBAL                     37: NULL + parse_model_response_json
                696     LOAD_FAST                       8: _var_var_9
                698     CALL                            1
                706     STORE_FAST                      9: _var_var_10
                708     LOAD_FAST                       9: _var_var_10
                710     POP_JUMP_IF_TRUE                28 (to 768)
                712     NOP                             
                714     LOAD_GLOBAL                     1: NULL + ida_execute
                724     LOAD_GLOBAL                     34: remove_cancel_button
                734     LOAD_FAST                       7: _var_var_8
                736     BUILD_TUPLE                     1
                738     CALL                            2
                746     POP_TOP                         
                748     LOAD_CONST                      0: None
                750     NOP                             
                752     NOP                             
                754     NOP                             
                756     JUMP_FORWARD                    104 (to 966)
                764     POP_TOP                         
                766     RETURN_CONST                    0: None
                768     LOAD_GLOBAL                     39: NULL + response_check_and_refine
                778     LOAD_FAST                       9: _var_var_10
                780     LOAD_FAST                       2: _var_var_3
                782     CALL                            2
                790     STORE_FAST                      9: _var_var_10
                792     LOAD_CONST                      15: 'args'
                794     LOAD_FAST                       9: _var_var_10
                796     BUILD_MAP                       1
                798     STORE_FAST                      9: _var_var_10
                800     LOAD_GLOBAL                     1: NULL + ida_execute
                810     LOAD_GLOBAL                     40: create_user_confirm_view
                820     LOAD_FAST                       0: ea
                822     LOAD_FAST                       2: _var_var_3
                824     LOAD_FAST                       3: _var_var_4
                826     LOAD_FAST                       8: _var_var_9
                828     LOAD_FAST                       9: _var_var_10
                830     BUILD_TUPLE                     5
                832     CALL                            2
                840     LOAD_GLOBAL                     1: NULL + ida_execute
                850     LOAD_GLOBAL                     34: remove_cancel_button
                860     LOAD_FAST                       7: _var_var_8
                862     BUILD_TUPLE                     1
                864     CALL                            2
                872     POP_TOP                         
                874     NOP                             
                876     NOP                             
                878     NOP                             
                880     JUMP_FORWARD                    42 (to 966)
                882     CALL                            1
                890     POP_TOP                         
                892     RETURN_VALUE                    
                894     PUSH_EXC_INFO                   
                896     LOAD_GLOBAL                     1: NULL + ida_execute
                906     LOAD_GLOBAL                     34: remove_cancel_button
                916     LOAD_FAST                       7: _var_var_8
                918     BUILD_TUPLE                     1
                920     CALL                            2
                928     POP_TOP                         
                930     RERAISE                         0
                932     COPY                            3
                934     POP_EXCEPT                      
                936     RERAISE                         1
                938     PUSH_EXC_INFO                   
                940     PUSH_NULL                       
                942     LOAD_CONST                      6: '__pyarmor_exit_55011__'
                944     NOP                             
                946     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x03\x00\x00\x00\x00\x00\x00'
                948     CALL                            1
                956     POP_TOP                         
                958     RERAISE                         0
                960     COPY                            3
                962     POP_EXCEPT                      
                964     RERAISE                         1
                966     PUSH_NULL                       
                968     LOAD_CONST                      6: '__pyarmor_exit_55011__'
                970     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x03\x00\x00\x00\x00\x00\x00'
                972     BUILD_TUPLE                     1
                974     CALL_FUNCTION_EX                0
                976     POP_TOP                         
                978     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: func_name_analysis
            Qualified Name: func_name_analysis
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 11
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_execute'
                'build_prompt'
                'settings_manager'
                'settings'
                'len'
                'idc'
                'get_func_name'
                'ida_kernwin'
                'ask_yn'
                'hex'
                'add_cancel_button'
                'model'
                'asyncio'
                'run'
                'call_model_mock'
                'call_model'
                'startswith'
                'remove_cancel_button'
                'parse_model_response_json'
                'parse_model_response_str'
                'response_check_and_refine'
                'create_user_confirm_view_for_funcname'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_3'
                '_var_var_4'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
            [Constants]
                None
                '__pyarmor_assert_55012__'
                '__pyarmor_enter_55013__'
                b'<COAddr>\x03\x00\x00\x1a\xa2\x03\x00\x00\x00\x00\x00\x00'
                '<funcname>'
                (
                )
                '__pyarmor_exit_55014__'
                'need_confirm'
                1
                'perform function name analysis on '
                ':'
                ' with '
                ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                'debug_mode'
                '<Cancelled>'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55013__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa2\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '<funcname>'
                30      STORE_FAST                      2: _var_var_3
                32      LOAD_GLOBAL                     1: NULL + ida_execute
                42      LOAD_GLOBAL                     2: build_prompt
                52      LOAD_FAST                       0: ea
                54      LOAD_FAST                       2: _var_var_3
                56      LOAD_CONST                      5: ()
                58      BUILD_TUPLE                     3
                60      CALL                            2
                68      STORE_FAST                      3: _var_var_4
                70      LOAD_FAST                       3: _var_var_4
                72      POP_JUMP_IF_TRUE                11 (to 96)
                74      NOP                             
                76      LOAD_CONST                      0: None
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    449 (to 984)
                92      POP_TOP                         
                94      RETURN_CONST                    0: None
                96      LOAD_GLOBAL                     4: settings_manager
                106     LOAD_ATTR                       6: settings
                126     LOAD_CONST                      7: 'need_confirm'
                128     BINARY_SUBSCR                   
                132     POP_JUMP_IF_FALSE               101 (to 336)
                134     LOAD_GLOBAL                     9: NULL + len
                144     LOAD_FAST                       3: _var_var_4
                146     CALL                            1
                154     STORE_FAST                      4: _var_var_5
                156     LOAD_GLOBAL                     1: NULL + ida_execute
                166     LOAD_GLOBAL                     10: idc
                176     LOAD_ATTR                       12: get_func_name
                196     LOAD_FAST                       0: ea
                198     BUILD_TUPLE                     1
                200     CALL                            2
                208     STORE_FAST                      5: _var_var_6
                210     LOAD_GLOBAL                     1: NULL + ida_execute
                220     LOAD_GLOBAL                     14: ida_kernwin
                230     LOAD_ATTR                       16: ask_yn
                250     LOAD_CONST                      8: 1
                252     LOAD_CONST                      9: 'perform function name analysis on '
                254     LOAD_GLOBAL                     19: NULL + hex
                264     LOAD_FAST                       0: ea
                266     CALL                            1
                274     FORMAT_VALUE                    0 (FVC_NONE)
                276     LOAD_CONST                      10: ':'
                278     LOAD_FAST                       5: _var_var_6
                280     FORMAT_VALUE                    0 (FVC_NONE)
                282     LOAD_CONST                      11: ' with '
                284     LOAD_FAST                       4: _var_var_5
                286     FORMAT_VALUE                    0 (FVC_NONE)
                288     LOAD_CONST                      12: ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                290     BUILD_STRING                    7
                292     BUILD_TUPLE                     2
                294     CALL                            2
                302     STORE_FAST                      6: _var_var_7
                304     LOAD_FAST                       6: _var_var_7
                306     LOAD_CONST                      8: 1
                308     COMPARE_OP                      55 (!=)
                312     POP_JUMP_IF_FALSE               11 (to 336)
                314     NOP                             
                316     LOAD_CONST                      0: None
                318     NOP                             
                320     NOP                             
                322     JUMP_FORWARD                    329 (to 984)
                332     POP_TOP                         
                334     RETURN_CONST                    0: None
                336     LOAD_GLOBAL                     1: NULL + ida_execute
                346     LOAD_GLOBAL                     20: add_cancel_button
                356     LOAD_GLOBAL                     22: model
                366     BUILD_TUPLE                     1
                368     CALL                            2
                376     STORE_FAST                      7: _var_var_8
                378     NOP                             
                380     LOAD_GLOBAL                     4: settings_manager
                390     LOAD_ATTR                       6: settings
                410     LOAD_CONST                      13: 'debug_mode'
                412     BINARY_SUBSCR                   
                416     POP_JUMP_IF_FALSE               45 (to 508)
                418     LOAD_GLOBAL                     25: NULL + asyncio
                428     LOAD_ATTR                       26: run
                448     LOAD_GLOBAL                     22: model
                458     LOAD_ATTR                       29: call_model_mock
                478     LOAD_FAST                       3: _var_var_4
                480     LOAD_FAST                       2: _var_var_3
                482     CALL                            2
                490     CALL                            1
                498     UNPACK_SEQUENCE                 2
                502     STORE_FAST                      8: _var_var_9
                504     STORE_FAST                      3: _var_var_4
                506     JUMP_FORWARD                    44 (to 596)
                508     LOAD_GLOBAL                     25: NULL + asyncio
                518     LOAD_ATTR                       26: run
                538     LOAD_GLOBAL                     22: model
                548     LOAD_ATTR                       31: call_model
                568     LOAD_FAST                       3: _var_var_4
                570     LOAD_FAST                       2: _var_var_3
                572     CALL                            2
                580     CALL                            1
                588     UNPACK_SEQUENCE                 2
                592     STORE_FAST                      8: _var_var_9
                594     STORE_FAST                      3: _var_var_4
                596     LOAD_FAST                       8: _var_var_9
                598     LOAD_ATTR                       33: startswith
                618     LOAD_CONST                      14: '<Cancelled>'
                620     CALL                            1
                628     POP_JUMP_IF_FALSE               28 (to 686)
                630     NOP                             
                632     LOAD_GLOBAL                     1: NULL + ida_execute
                642     LOAD_GLOBAL                     34: remove_cancel_button
                652     LOAD_FAST                       7: _var_var_8
                654     BUILD_TUPLE                     1
                656     CALL                            2
                664     POP_TOP                         
                666     LOAD_CONST                      0: None
                668     NOP                             
                670     NOP                             
                672     NOP                             
                674     JUMP_FORWARD                    154 (to 984)
                682     POP_TOP                         
                684     RETURN_CONST                    0: None
                686     LOAD_GLOBAL                     37: NULL + parse_model_response_json
                696     LOAD_FAST                       8: _var_var_9
                698     CALL                            1
                706     STORE_FAST                      9: _var_var_10
                708     LOAD_FAST                       9: _var_var_10
                710     POP_JUMP_IF_TRUE                41 (to 794)
                712     LOAD_GLOBAL                     39: NULL + parse_model_response_str
                722     LOAD_FAST                       8: _var_var_9
                724     CALL                            1
                732     STORE_FAST                      9: _var_var_10
                734     LOAD_FAST                       9: _var_var_10
                736     POP_JUMP_IF_TRUE                28 (to 794)
                738     NOP                             
                740     LOAD_GLOBAL                     1: NULL + ida_execute
                750     LOAD_GLOBAL                     34: remove_cancel_button
                760     LOAD_FAST                       7: _var_var_8
                762     BUILD_TUPLE                     1
                764     CALL                            2
                772     POP_TOP                         
                774     LOAD_CONST                      0: None
                776     NOP                             
                778     NOP                             
                780     NOP                             
                782     JUMP_FORWARD                    100 (to 984)
                790     POP_TOP                         
                792     RETURN_CONST                    0: None
                794     LOAD_GLOBAL                     41: NULL + response_check_and_refine
                804     LOAD_FAST                       9: _var_var_10
                806     LOAD_FAST                       2: _var_var_3
                808     CALL                            2
                816     STORE_FAST                      9: _var_var_10
                818     LOAD_GLOBAL                     1: NULL + ida_execute
                828     LOAD_GLOBAL                     42: create_user_confirm_view_for_funcname
                838     LOAD_FAST                       0: ea
                840     LOAD_FAST                       2: _var_var_3
                842     LOAD_FAST                       3: _var_var_4
                844     LOAD_FAST                       8: _var_var_9
                846     LOAD_FAST                       9: _var_var_10
                848     BUILD_TUPLE                     5
                850     CALL                            2
                858     LOAD_GLOBAL                     1: NULL + ida_execute
                868     LOAD_GLOBAL                     34: remove_cancel_button
                878     LOAD_FAST                       7: _var_var_8
                880     BUILD_TUPLE                     1
                882     CALL                            2
                890     POP_TOP                         
                892     NOP                             
                894     NOP                             
                896     NOP                             
                898     JUMP_FORWARD                    42 (to 984)
                900     CALL                            1
                908     POP_TOP                         
                910     RETURN_VALUE                    
                912     PUSH_EXC_INFO                   
                914     LOAD_GLOBAL                     1: NULL + ida_execute
                924     LOAD_GLOBAL                     34: remove_cancel_button
                934     LOAD_FAST                       7: _var_var_8
                936     BUILD_TUPLE                     1
                938     CALL                            2
                946     POP_TOP                         
                948     RERAISE                         0
                950     COPY                            3
                952     POP_EXCEPT                      
                954     RERAISE                         1
                956     PUSH_EXC_INFO                   
                958     PUSH_NULL                       
                960     LOAD_CONST                      6: '__pyarmor_exit_55014__'
                962     NOP                             
                964     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa2\x03\x00\x00\x00\x00\x00\x00'
                966     CALL                            1
                974     POP_TOP                         
                976     RERAISE                         0
                978     COPY                            3
                980     POP_EXCEPT                      
                982     RERAISE                         1
                984     PUSH_NULL                       
                986     LOAD_CONST                      6: '__pyarmor_exit_55014__'
                988     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa2\x03\x00\x00\x00\x00\x00\x00'
                990     BUILD_TUPLE                     1
                992     CALL_FUNCTION_EX                0
                994     POP_TOP                         
                996     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: summary_analysis
            Qualified Name: summary_analysis
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 11
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_execute'
                'build_prompt'
                'settings_manager'
                'settings'
                'len'
                'idc'
                'get_func_name'
                'ida_kernwin'
                'ask_yn'
                'hex'
                'add_cancel_button'
                'model'
                'asyncio'
                'run'
                'call_model_mock'
                'call_model'
                'startswith'
                'remove_cancel_button'
                'parse_model_response_json'
                'response_check_and_refine'
                'create_user_confirm_view'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_3'
                '_var_var_4'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
            [Constants]
                None
                '__pyarmor_assert_55015__'
                '__pyarmor_enter_55016__'
                b'<COAddr>\x03\x00\x00\x1a\x88\x03\x00\x00\x00\x00\x00\x00'
                '<summary>'
                (
                )
                '__pyarmor_exit_55017__'
                'need_confirm'
                1
                'perform summary analysis on '
                ':'
                ' with '
                ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                'debug_mode'
                '<Cancelled>'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55016__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x88\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '<summary>'
                30      STORE_FAST                      2: _var_var_3
                32      LOAD_GLOBAL                     1: NULL + ida_execute
                42      LOAD_GLOBAL                     2: build_prompt
                52      LOAD_FAST                       0: ea
                54      LOAD_FAST                       2: _var_var_3
                56      LOAD_CONST                      5: ()
                58      BUILD_TUPLE                     3
                60      CALL                            2
                68      STORE_FAST                      3: _var_var_4
                70      LOAD_FAST                       3: _var_var_4
                72      POP_JUMP_IF_TRUE                11 (to 96)
                74      NOP                             
                76      LOAD_CONST                      0: None
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    436 (to 958)
                92      POP_TOP                         
                94      RETURN_CONST                    0: None
                96      LOAD_GLOBAL                     4: settings_manager
                106     LOAD_ATTR                       6: settings
                126     LOAD_CONST                      7: 'need_confirm'
                128     BINARY_SUBSCR                   
                132     POP_JUMP_IF_FALSE               101 (to 336)
                134     LOAD_GLOBAL                     9: NULL + len
                144     LOAD_FAST                       3: _var_var_4
                146     CALL                            1
                154     STORE_FAST                      4: _var_var_5
                156     LOAD_GLOBAL                     1: NULL + ida_execute
                166     LOAD_GLOBAL                     10: idc
                176     LOAD_ATTR                       12: get_func_name
                196     LOAD_FAST                       0: ea
                198     BUILD_TUPLE                     1
                200     CALL                            2
                208     STORE_FAST                      5: _var_var_6
                210     LOAD_GLOBAL                     1: NULL + ida_execute
                220     LOAD_GLOBAL                     14: ida_kernwin
                230     LOAD_ATTR                       16: ask_yn
                250     LOAD_CONST                      8: 1
                252     LOAD_CONST                      9: 'perform summary analysis on '
                254     LOAD_GLOBAL                     19: NULL + hex
                264     LOAD_FAST                       0: ea
                266     CALL                            1
                274     FORMAT_VALUE                    0 (FVC_NONE)
                276     LOAD_CONST                      10: ':'
                278     LOAD_FAST                       5: _var_var_6
                280     FORMAT_VALUE                    0 (FVC_NONE)
                282     LOAD_CONST                      11: ' with '
                284     LOAD_FAST                       4: _var_var_5
                286     FORMAT_VALUE                    0 (FVC_NONE)
                288     LOAD_CONST                      12: ' chars query?\n\n(Disable user confirmation in settings if needed)\n(可在设置中配置无需确认)'
                290     BUILD_STRING                    7
                292     BUILD_TUPLE                     2
                294     CALL                            2
                302     STORE_FAST                      6: _var_var_7
                304     LOAD_FAST                       6: _var_var_7
                306     LOAD_CONST                      8: 1
                308     COMPARE_OP                      55 (!=)
                312     POP_JUMP_IF_FALSE               11 (to 336)
                314     NOP                             
                316     LOAD_CONST                      0: None
                318     NOP                             
                320     NOP                             
                322     JUMP_FORWARD                    316 (to 958)
                332     POP_TOP                         
                334     RETURN_CONST                    0: None
                336     LOAD_GLOBAL                     1: NULL + ida_execute
                346     LOAD_GLOBAL                     20: add_cancel_button
                356     LOAD_GLOBAL                     22: model
                366     BUILD_TUPLE                     1
                368     CALL                            2
                376     STORE_FAST                      7: _var_var_8
                378     NOP                             
                380     LOAD_GLOBAL                     4: settings_manager
                390     LOAD_ATTR                       6: settings
                410     LOAD_CONST                      13: 'debug_mode'
                412     BINARY_SUBSCR                   
                416     POP_JUMP_IF_FALSE               45 (to 508)
                418     LOAD_GLOBAL                     25: NULL + asyncio
                428     LOAD_ATTR                       26: run
                448     LOAD_GLOBAL                     22: model
                458     LOAD_ATTR                       29: call_model_mock
                478     LOAD_FAST                       3: _var_var_4
                480     LOAD_FAST                       2: _var_var_3
                482     CALL                            2
                490     CALL                            1
                498     UNPACK_SEQUENCE                 2
                502     STORE_FAST                      8: _var_var_9
                504     STORE_FAST                      3: _var_var_4
                506     JUMP_FORWARD                    44 (to 596)
                508     LOAD_GLOBAL                     25: NULL + asyncio
                518     LOAD_ATTR                       26: run
                538     LOAD_GLOBAL                     22: model
                548     LOAD_ATTR                       31: call_model
                568     LOAD_FAST                       3: _var_var_4
                570     LOAD_FAST                       2: _var_var_3
                572     CALL                            2
                580     CALL                            1
                588     UNPACK_SEQUENCE                 2
                592     STORE_FAST                      8: _var_var_9
                594     STORE_FAST                      3: _var_var_4
                596     LOAD_FAST                       8: _var_var_9
                598     LOAD_ATTR                       33: startswith
                618     LOAD_CONST                      14: '<Cancelled>'
                620     CALL                            1
                628     POP_JUMP_IF_FALSE               28 (to 686)
                630     NOP                             
                632     LOAD_GLOBAL                     1: NULL + ida_execute
                642     LOAD_GLOBAL                     34: remove_cancel_button
                652     LOAD_FAST                       7: _var_var_8
                654     BUILD_TUPLE                     1
                656     CALL                            2
                664     POP_TOP                         
                666     LOAD_CONST                      0: None
                668     NOP                             
                670     NOP                             
                672     NOP                             
                674     JUMP_FORWARD                    141 (to 958)
                682     POP_TOP                         
                684     RETURN_CONST                    0: None
                686     LOAD_GLOBAL                     37: NULL + parse_model_response_json
                696     LOAD_FAST                       8: _var_var_9
                698     CALL                            1
                706     STORE_FAST                      9: _var_var_10
                708     LOAD_FAST                       9: _var_var_10
                710     POP_JUMP_IF_TRUE                28 (to 768)
                712     NOP                             
                714     LOAD_GLOBAL                     1: NULL + ida_execute
                724     LOAD_GLOBAL                     34: remove_cancel_button
                734     LOAD_FAST                       7: _var_var_8
                736     BUILD_TUPLE                     1
                738     CALL                            2
                746     POP_TOP                         
                748     LOAD_CONST                      0: None
                750     NOP                             
                752     NOP                             
                754     NOP                             
                756     JUMP_FORWARD                    100 (to 958)
                764     POP_TOP                         
                766     RETURN_CONST                    0: None
                768     LOAD_GLOBAL                     39: NULL + response_check_and_refine
                778     LOAD_FAST                       9: _var_var_10
                780     LOAD_FAST                       2: _var_var_3
                782     CALL                            2
                790     STORE_FAST                      9: _var_var_10
                792     LOAD_GLOBAL                     1: NULL + ida_execute
                802     LOAD_GLOBAL                     40: create_user_confirm_view
                812     LOAD_FAST                       0: ea
                814     LOAD_FAST                       2: _var_var_3
                816     LOAD_FAST                       3: _var_var_4
                818     LOAD_FAST                       8: _var_var_9
                820     LOAD_FAST                       9: _var_var_10
                822     BUILD_TUPLE                     5
                824     CALL                            2
                832     LOAD_GLOBAL                     1: NULL + ida_execute
                842     LOAD_GLOBAL                     34: remove_cancel_button
                852     LOAD_FAST                       7: _var_var_8
                854     BUILD_TUPLE                     1
                856     CALL                            2
                864     POP_TOP                         
                866     NOP                             
                868     NOP                             
                870     NOP                             
                872     JUMP_FORWARD                    42 (to 958)
                874     CALL                            1
                882     POP_TOP                         
                884     RETURN_VALUE                    
                886     PUSH_EXC_INFO                   
                888     LOAD_GLOBAL                     1: NULL + ida_execute
                898     LOAD_GLOBAL                     34: remove_cancel_button
                908     LOAD_FAST                       7: _var_var_8
                910     BUILD_TUPLE                     1
                912     CALL                            2
                920     POP_TOP                         
                922     RERAISE                         0
                924     COPY                            3
                926     POP_EXCEPT                      
                928     RERAISE                         1
                930     PUSH_EXC_INFO                   
                932     PUSH_NULL                       
                934     LOAD_CONST                      6: '__pyarmor_exit_55017__'
                936     NOP                             
                938     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x88\x03\x00\x00\x00\x00\x00\x00'
                940     CALL                            1
                948     POP_TOP                         
                950     RERAISE                         0
                952     COPY                            3
                954     POP_EXCEPT                      
                956     RERAISE                         1
                958     PUSH_NULL                       
                960     LOAD_CONST                      6: '__pyarmor_exit_55017__'
                962     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x88\x03\x00\x00\x00\x00\x00\x00'
                964     BUILD_TUPLE                     1
                966     CALL_FUNCTION_EX                0
                968     POP_TOP                         
                970     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: func_analysis_mock
            Qualified Name: func_analysis_mock
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'hex'
                'range'
                'time'
                'sleep'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_17'
            [Constants]
                None
                '__pyarmor_assert_55018__'
                '__pyarmor_enter_55019__'
                b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                'func_analysis: Function Analysis on ea: '
                3
                '.'
                0.5
                'func_analysis: Function Analysis finished'
                '__pyarmor_exit_55020__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55019__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + print
                38      LOAD_CONST                      4: 'func_analysis: Function Analysis on ea: '
                40      LOAD_GLOBAL                     3: NULL + hex
                50      LOAD_FAST                       0: ea
                52      CALL                            1
                60      FORMAT_VALUE                    0 (FVC_NONE)
                62      BUILD_STRING                    2
                64      CALL                            1
                72      POP_TOP                         
                74      LOAD_GLOBAL                     5: NULL + range
                84      LOAD_CONST                      5: 3
                86      CALL                            1
                94      GET_ITER                        
                96      FOR_ITER                        34 (to 166)
                100     STORE_FAST                      2: _var_var_17
                102     LOAD_GLOBAL                     1: NULL + print
                112     LOAD_CONST                      6: '.'
                114     CALL                            1
                122     POP_TOP                         
                124     LOAD_GLOBAL                     7: NULL + time
                134     LOAD_ATTR                       8: sleep
                154     LOAD_CONST                      7: 0.5
                156     CALL                            1
                164     POP_TOP                         
                166     JUMP_BACKWARD                   36 (to 96)
                168     END_FOR                         
                170     LOAD_GLOBAL                     1: NULL + print
                180     LOAD_CONST                      8: 'func_analysis: Function Analysis finished'
                182     CALL                            1
                190     POP_TOP                         
                192     LOAD_CONST                      0: None
                194     NOP                             
                196     NOP                             
                198     NOP                             
                200     JUMP_FORWARD                    19 (to 240)
                208     POP_TOP                         
                210     RETURN_CONST                    0: None
                212     PUSH_EXC_INFO                   
                214     PUSH_NULL                       
                216     LOAD_CONST                      9: '__pyarmor_exit_55020__'
                218     NOP                             
                220     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                222     CALL                            1
                230     POP_TOP                         
                232     RERAISE                         0
                234     COPY                            3
                236     POP_EXCEPT                      
                238     RERAISE                         1
                240     PUSH_NULL                       
                242     LOAD_CONST                      9: '__pyarmor_exit_55020__'
                244     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                246     BUILD_TUPLE                     1
                248     CALL_FUNCTION_EX                0
                250     POP_TOP                         
                252     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: decompilation_mock
            Qualified Name: decompilation_mock
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'hex'
                'range'
                'time'
                'sleep'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_17'
            [Constants]
                None
                '__pyarmor_assert_55021__'
                '__pyarmor_enter_55022__'
                b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                'decompilation: Decompilation on ea: '
                3
                '.'
                1.5
                'decompilation: Decompilation finished'
                '__pyarmor_exit_55023__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55022__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + print
                38      LOAD_CONST                      4: 'decompilation: Decompilation on ea: '
                40      LOAD_GLOBAL                     3: NULL + hex
                50      LOAD_FAST                       0: ea
                52      CALL                            1
                60      FORMAT_VALUE                    0 (FVC_NONE)
                62      BUILD_STRING                    2
                64      CALL                            1
                72      POP_TOP                         
                74      LOAD_GLOBAL                     5: NULL + range
                84      LOAD_CONST                      5: 3
                86      CALL                            1
                94      GET_ITER                        
                96      FOR_ITER                        34 (to 166)
                100     STORE_FAST                      2: _var_var_17
                102     LOAD_GLOBAL                     1: NULL + print
                112     LOAD_CONST                      6: '.'
                114     CALL                            1
                122     POP_TOP                         
                124     LOAD_GLOBAL                     7: NULL + time
                134     LOAD_ATTR                       8: sleep
                154     LOAD_CONST                      7: 1.5
                156     CALL                            1
                164     POP_TOP                         
                166     JUMP_BACKWARD                   36 (to 96)
                168     END_FOR                         
                170     LOAD_GLOBAL                     1: NULL + print
                180     LOAD_CONST                      8: 'decompilation: Decompilation finished'
                182     CALL                            1
                190     POP_TOP                         
                192     LOAD_CONST                      0: None
                194     NOP                             
                196     NOP                             
                198     NOP                             
                200     JUMP_FORWARD                    19 (to 240)
                208     POP_TOP                         
                210     RETURN_CONST                    0: None
                212     PUSH_EXC_INFO                   
                214     PUSH_NULL                       
                216     LOAD_CONST                      9: '__pyarmor_exit_55023__'
                218     NOP                             
                220     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                222     CALL                            1
                230     POP_TOP                         
                232     RERAISE                         0
                234     COPY                            3
                236     POP_EXCEPT                      
                238     RERAISE                         1
                240     PUSH_NULL                       
                242     LOAD_CONST                      9: '__pyarmor_exit_55023__'
                244     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                246     BUILD_TUPLE                     1
                248     CALL_FUNCTION_EX                0
                250     POP_TOP                         
                252     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: specific_vars_analysis_mock
            Qualified Name: specific_vars_analysis_mock
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'hex'
                'range'
                'time'
                'sleep'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_17'
            [Constants]
                None
                '__pyarmor_assert_55024__'
                '__pyarmor_enter_55025__'
                b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                'specific_vars_analysis: Variable Analysis on ea: '
                3
                '.'
                1.5
                'specific_vars_analysis: Variable Analysis finished'
                '__pyarmor_exit_55026__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55025__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + print
                38      LOAD_CONST                      4: 'specific_vars_analysis: Variable Analysis on ea: '
                40      LOAD_GLOBAL                     3: NULL + hex
                50      LOAD_FAST                       0: ea
                52      CALL                            1
                60      FORMAT_VALUE                    0 (FVC_NONE)
                62      BUILD_STRING                    2
                64      CALL                            1
                72      POP_TOP                         
                74      LOAD_GLOBAL                     5: NULL + range
                84      LOAD_CONST                      5: 3
                86      CALL                            1
                94      GET_ITER                        
                96      FOR_ITER                        34 (to 166)
                100     STORE_FAST                      2: _var_var_17
                102     LOAD_GLOBAL                     1: NULL + print
                112     LOAD_CONST                      6: '.'
                114     CALL                            1
                122     POP_TOP                         
                124     LOAD_GLOBAL                     7: NULL + time
                134     LOAD_ATTR                       8: sleep
                154     LOAD_CONST                      7: 1.5
                156     CALL                            1
                164     POP_TOP                         
                166     JUMP_BACKWARD                   36 (to 96)
                168     END_FOR                         
                170     LOAD_GLOBAL                     1: NULL + print
                180     LOAD_CONST                      8: 'specific_vars_analysis: Variable Analysis finished'
                182     CALL                            1
                190     POP_TOP                         
                192     LOAD_CONST                      0: None
                194     NOP                             
                196     NOP                             
                198     NOP                             
                200     JUMP_FORWARD                    19 (to 240)
                208     POP_TOP                         
                210     RETURN_CONST                    0: None
                212     PUSH_EXC_INFO                   
                214     PUSH_NULL                       
                216     LOAD_CONST                      9: '__pyarmor_exit_55026__'
                218     NOP                             
                220     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                222     CALL                            1
                230     POP_TOP                         
                232     RERAISE                         0
                234     COPY                            3
                236     POP_EXCEPT                      
                238     RERAISE                         1
                240     PUSH_NULL                       
                242     LOAD_CONST                      9: '__pyarmor_exit_55026__'
                244     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                246     BUILD_TUPLE                     1
                248     CALL_FUNCTION_EX                0
                250     POP_TOP                         
                252     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: all_vars_analysis_mock
            Qualified Name: all_vars_analysis_mock
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'hex'
                'range'
                'time'
                'sleep'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_17'
            [Constants]
                None
                '__pyarmor_assert_55027__'
                '__pyarmor_enter_55028__'
                b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                'all_vars_analysis: Variable Analysis on ea: '
                3
                '.'
                1.5
                'all_vars_analysis: Variable Analysis finished'
                '__pyarmor_exit_55029__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55028__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + print
                38      LOAD_CONST                      4: 'all_vars_analysis: Variable Analysis on ea: '
                40      LOAD_GLOBAL                     3: NULL + hex
                50      LOAD_FAST                       0: ea
                52      CALL                            1
                60      FORMAT_VALUE                    0 (FVC_NONE)
                62      BUILD_STRING                    2
                64      CALL                            1
                72      POP_TOP                         
                74      LOAD_GLOBAL                     5: NULL + range
                84      LOAD_CONST                      5: 3
                86      CALL                            1
                94      GET_ITER                        
                96      FOR_ITER                        34 (to 166)
                100     STORE_FAST                      2: _var_var_17
                102     LOAD_GLOBAL                     1: NULL + print
                112     LOAD_CONST                      6: '.'
                114     CALL                            1
                122     POP_TOP                         
                124     LOAD_GLOBAL                     7: NULL + time
                134     LOAD_ATTR                       8: sleep
                154     LOAD_CONST                      7: 1.5
                156     CALL                            1
                164     POP_TOP                         
                166     JUMP_BACKWARD                   36 (to 96)
                168     END_FOR                         
                170     LOAD_GLOBAL                     1: NULL + print
                180     LOAD_CONST                      8: 'all_vars_analysis: Variable Analysis finished'
                182     CALL                            1
                190     POP_TOP                         
                192     LOAD_CONST                      0: None
                194     NOP                             
                196     NOP                             
                198     NOP                             
                200     JUMP_FORWARD                    19 (to 240)
                208     POP_TOP                         
                210     RETURN_CONST                    0: None
                212     PUSH_EXC_INFO                   
                214     PUSH_NULL                       
                216     LOAD_CONST                      9: '__pyarmor_exit_55029__'
                218     NOP                             
                220     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                222     CALL                            1
                230     POP_TOP                         
                232     RERAISE                         0
                234     COPY                            3
                236     POP_EXCEPT                      
                238     RERAISE                         1
                240     PUSH_NULL                       
                242     LOAD_CONST                      9: '__pyarmor_exit_55029__'
                244     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                246     BUILD_TUPLE                     1
                248     CALL_FUNCTION_EX                0
                250     POP_TOP                         
                252     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: all_args_analysis_mock
            Qualified Name: all_args_analysis_mock
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'hex'
                'range'
                'time'
                'sleep'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_17'
            [Constants]
                None
                '__pyarmor_assert_55030__'
                '__pyarmor_enter_55031__'
                b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                'all_args_analysis: Variable Analysis on ea: '
                3
                '.'
                1.5
                'all_args_analysis: Variable Analysis finished'
                '__pyarmor_exit_55032__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55031__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + print
                38      LOAD_CONST                      4: 'all_args_analysis: Variable Analysis on ea: '
                40      LOAD_GLOBAL                     3: NULL + hex
                50      LOAD_FAST                       0: ea
                52      CALL                            1
                60      FORMAT_VALUE                    0 (FVC_NONE)
                62      BUILD_STRING                    2
                64      CALL                            1
                72      POP_TOP                         
                74      LOAD_GLOBAL                     5: NULL + range
                84      LOAD_CONST                      5: 3
                86      CALL                            1
                94      GET_ITER                        
                96      FOR_ITER                        34 (to 166)
                100     STORE_FAST                      2: _var_var_17
                102     LOAD_GLOBAL                     1: NULL + print
                112     LOAD_CONST                      6: '.'
                114     CALL                            1
                122     POP_TOP                         
                124     LOAD_GLOBAL                     7: NULL + time
                134     LOAD_ATTR                       8: sleep
                154     LOAD_CONST                      7: 1.5
                156     CALL                            1
                164     POP_TOP                         
                166     JUMP_BACKWARD                   36 (to 96)
                168     END_FOR                         
                170     LOAD_GLOBAL                     1: NULL + print
                180     LOAD_CONST                      8: 'all_args_analysis: Variable Analysis finished'
                182     CALL                            1
                190     POP_TOP                         
                192     LOAD_CONST                      0: None
                194     NOP                             
                196     NOP                             
                198     NOP                             
                200     JUMP_FORWARD                    19 (to 240)
                208     POP_TOP                         
                210     RETURN_CONST                    0: None
                212     PUSH_EXC_INFO                   
                214     PUSH_NULL                       
                216     LOAD_CONST                      9: '__pyarmor_exit_55032__'
                218     NOP                             
                220     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                222     CALL                            1
                230     POP_TOP                         
                232     RERAISE                         0
                234     COPY                            3
                236     POP_EXCEPT                      
                238     RERAISE                         1
                240     PUSH_NULL                       
                242     LOAD_CONST                      9: '__pyarmor_exit_55032__'
                244     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                246     BUILD_TUPLE                     1
                248     CALL_FUNCTION_EX                0
                250     POP_TOP                         
                252     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..handler>
            Object Name: FuncAnalysisHandler
            Qualified Name: FuncAnalysisHandler
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                '__init__'
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'FuncAnalysisHandler'
                '__pyarmor_assert_55033__'
                '__pyarmor_enter_55034__'
                b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: FuncAnalysisHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55036__'
                        '__pyarmor_enter_55037__'
                        b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55038__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55037__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55038__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55038__'
                        142     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: FuncAnalysisHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'idc'
                        'get_screen_ea'
                        'idaapi'
                        'get_func'
                        'get_func_name'
                        'print'
                        'hex'
                        'threading'
                        'Thread'
                        'func_analysis'
                        'start_ea'
                        'start'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_6'
                        '_var_var_20'
                    [Constants]
                        None
                        '__pyarmor_assert_55039__'
                        '__pyarmor_enter_55040__'
                        b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        'Function Analysis on ea: '
                        ', func name: '
                        (
                            'target'
                            'args'
                        )
                        '__pyarmor_exit_55041__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55040__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + idc
                        38      LOAD_ATTR                       2: get_screen_ea
                        58      CALL                            0
                        66      STORE_FAST                      3: _var_var_18
                        68      LOAD_GLOBAL                     5: NULL + idaapi
                        78      LOAD_ATTR                       6: get_func
                        98      LOAD_FAST                       3: _var_var_18
                        100     CALL                            1
                        108     STORE_FAST                      4: _var_var_19
                        110     LOAD_GLOBAL                     1: NULL + idc
                        120     LOAD_ATTR                       8: get_func_name
                        140     LOAD_FAST                       3: _var_var_18
                        142     CALL                            1
                        150     STORE_FAST                      5: _var_var_6
                        152     LOAD_GLOBAL                     11: NULL + print
                        162     LOAD_CONST                      4: 'Function Analysis on ea: '
                        164     LOAD_GLOBAL                     13: NULL + hex
                        174     LOAD_FAST                       3: _var_var_18
                        176     CALL                            1
                        184     FORMAT_VALUE                    0 (FVC_NONE)
                        186     LOAD_CONST                      5: ', func name: '
                        188     LOAD_FAST                       5: _var_var_6
                        190     FORMAT_VALUE                    0 (FVC_NONE)
                        192     BUILD_STRING                    4
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + threading
                        214     LOAD_ATTR                       16: Thread
                        234     LOAD_GLOBAL                     18: func_analysis
                        244     LOAD_FAST                       4: _var_var_19
                        246     LOAD_ATTR                       20: start_ea
                        266     BUILD_TUPLE                     1
                        268     KW_NAMES                        6: ('target', 'args')
                        270     CALL                            2
                        278     STORE_FAST                      6: _var_var_20
                        280     LOAD_FAST                       6: _var_var_20
                        282     LOAD_ATTR                       23: start
                        302     CALL                            0
                        310     POP_TOP                         
                        312     LOAD_CONST                      8: 1
                        314     NOP                             
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    19 (to 360)
                        328     POP_TOP                         
                        330     RETURN_CONST                    8: 1
                        332     PUSH_EXC_INFO                   
                        334     PUSH_NULL                       
                        336     LOAD_CONST                      7: '__pyarmor_exit_55041__'
                        338     NOP                             
                        340     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        342     CALL                            1
                        350     POP_TOP                         
                        352     RERAISE                         0
                        354     COPY                            3
                        356     POP_EXCEPT                      
                        358     RERAISE                         1
                        360     PUSH_NULL                       
                        362     LOAD_CONST                      7: '__pyarmor_exit_55041__'
                        364     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        366     BUILD_TUPLE                     1
                        368     CALL_FUNCTION_EX                0
                        370     POP_TOP                         
                        372     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: FuncAnalysisHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widget_type'
                        'ida_kernwin'
                        'BWN_PSEUDOCODE'
                        'AST_ENABLE_FOR_WIDGET'
                        'AST_DISABLE_FOR_WIDGET'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55042__'
                        '__pyarmor_enter_55043__'
                        b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55044__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55043__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: ctx
                        30      LOAD_ATTR                       0: widget_type
                        50      LOAD_GLOBAL                     2: ida_kernwin
                        60      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               16 (to 118)
                        86      LOAD_GLOBAL                     2: ida_kernwin
                        96      LOAD_ATTR                       6: AST_ENABLE_FOR_WIDGET
                        116     JUMP_FORWARD                    15 (to 148)
                        118     LOAD_GLOBAL                     2: ida_kernwin
                        128     LOAD_ATTR                       8: AST_DISABLE_FOR_WIDGET
                        148     NOP                             
                        150     NOP                             
                        152     NOP                             
                        154     JUMP_FORWARD                    20 (to 196)
                        156     CALL                            1
                        164     POP_TOP                         
                        166     RETURN_VALUE                    
                        168     PUSH_EXC_INFO                   
                        170     PUSH_NULL                       
                        172     LOAD_CONST                      4: '__pyarmor_exit_55044__'
                        174     NOP                             
                        176     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        178     CALL                            1
                        186     POP_TOP                         
                        188     RERAISE                         0
                        190     COPY                            3
                        192     POP_EXCEPT                      
                        194     RERAISE                         1
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      4: '__pyarmor_exit_55044__'
                        200     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        202     BUILD_TUPLE                     1
                        204     CALL_FUNCTION_EX                0
                        206     POP_TOP                         
                        208     RETURN_VALUE                    
                '__pyarmor_exit_55035__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'FuncAnalysisHandler'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55034__'
                16      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> __init__
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: __init__
                42      LOAD_CONST                      5: <CODE> activate
                44      MAKE_FUNCTION                   0
                46      STORE_NAME                      5: activate
                48      LOAD_CONST                      6: <CODE> update
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      6: update
                54      LOAD_CONST                      8: None
                56      NOP                             
                58      NOP                             
                60      NOP                             
                62      JUMP_FORWARD                    19 (to 102)
                70      POP_TOP                         
                72      RETURN_CONST                    8: None
                74      PUSH_EXC_INFO                   
                76      PUSH_NULL                       
                78      LOAD_CONST                      7: '__pyarmor_exit_55035__'
                80      NOP                             
                82      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                84      CALL                            1
                92      POP_TOP                         
                94      RERAISE                         0
                96      COPY                            3
                98      POP_EXCEPT                      
                100     RERAISE                         1
                102     PUSH_NULL                       
                104     LOAD_CONST                      7: '__pyarmor_exit_55035__'
                106     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                108     BUILD_TUPLE                     1
                110     CALL_FUNCTION_EX                0
                112     POP_TOP                         
                114     RETURN_VALUE                    
        'FuncAnalysisHandler'
        [Code]
            File Name: <frozen ..handler>
            Object Name: DecompilationHandler
            Qualified Name: DecompilationHandler
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                '__init__'
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'DecompilationHandler'
                '__pyarmor_assert_55045__'
                '__pyarmor_enter_55046__'
                b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: DecompilationHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55048__'
                        '__pyarmor_enter_55049__'
                        b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55050__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55049__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55050__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55050__'
                        142     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: DecompilationHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'idc'
                        'get_screen_ea'
                        'idaapi'
                        'get_func'
                        'get_func_name'
                        'print'
                        'hex'
                        'threading'
                        'Thread'
                        'decompilation'
                        'start_ea'
                        'start'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_6'
                        '_var_var_20'
                    [Constants]
                        None
                        '__pyarmor_assert_55051__'
                        '__pyarmor_enter_55052__'
                        b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        'Decompilation on ea: '
                        ', func name: '
                        (
                            'target'
                            'args'
                        )
                        '__pyarmor_exit_55053__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55052__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + idc
                        38      LOAD_ATTR                       2: get_screen_ea
                        58      CALL                            0
                        66      STORE_FAST                      3: _var_var_18
                        68      LOAD_GLOBAL                     5: NULL + idaapi
                        78      LOAD_ATTR                       6: get_func
                        98      LOAD_FAST                       3: _var_var_18
                        100     CALL                            1
                        108     STORE_FAST                      4: _var_var_19
                        110     LOAD_GLOBAL                     1: NULL + idc
                        120     LOAD_ATTR                       8: get_func_name
                        140     LOAD_FAST                       3: _var_var_18
                        142     CALL                            1
                        150     STORE_FAST                      5: _var_var_6
                        152     LOAD_GLOBAL                     11: NULL + print
                        162     LOAD_CONST                      4: 'Decompilation on ea: '
                        164     LOAD_GLOBAL                     13: NULL + hex
                        174     LOAD_FAST                       3: _var_var_18
                        176     CALL                            1
                        184     FORMAT_VALUE                    0 (FVC_NONE)
                        186     LOAD_CONST                      5: ', func name: '
                        188     LOAD_FAST                       5: _var_var_6
                        190     FORMAT_VALUE                    0 (FVC_NONE)
                        192     BUILD_STRING                    4
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + threading
                        214     LOAD_ATTR                       16: Thread
                        234     LOAD_GLOBAL                     18: decompilation
                        244     LOAD_FAST                       4: _var_var_19
                        246     LOAD_ATTR                       20: start_ea
                        266     BUILD_TUPLE                     1
                        268     KW_NAMES                        6: ('target', 'args')
                        270     CALL                            2
                        278     STORE_FAST                      6: _var_var_20
                        280     LOAD_FAST                       6: _var_var_20
                        282     LOAD_ATTR                       23: start
                        302     CALL                            0
                        310     POP_TOP                         
                        312     LOAD_CONST                      8: 1
                        314     NOP                             
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    19 (to 360)
                        328     POP_TOP                         
                        330     RETURN_CONST                    8: 1
                        332     PUSH_EXC_INFO                   
                        334     PUSH_NULL                       
                        336     LOAD_CONST                      7: '__pyarmor_exit_55053__'
                        338     NOP                             
                        340     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        342     CALL                            1
                        350     POP_TOP                         
                        352     RERAISE                         0
                        354     COPY                            3
                        356     POP_EXCEPT                      
                        358     RERAISE                         1
                        360     PUSH_NULL                       
                        362     LOAD_CONST                      7: '__pyarmor_exit_55053__'
                        364     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        366     BUILD_TUPLE                     1
                        368     CALL_FUNCTION_EX                0
                        370     POP_TOP                         
                        372     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: DecompilationHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widget_type'
                        'ida_kernwin'
                        'BWN_PSEUDOCODE'
                        'AST_ENABLE_FOR_WIDGET'
                        'AST_DISABLE_FOR_WIDGET'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55054__'
                        '__pyarmor_enter_55055__'
                        b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55056__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55055__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: ctx
                        30      LOAD_ATTR                       0: widget_type
                        50      LOAD_GLOBAL                     2: ida_kernwin
                        60      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               16 (to 118)
                        86      LOAD_GLOBAL                     2: ida_kernwin
                        96      LOAD_ATTR                       6: AST_ENABLE_FOR_WIDGET
                        116     JUMP_FORWARD                    15 (to 148)
                        118     LOAD_GLOBAL                     2: ida_kernwin
                        128     LOAD_ATTR                       8: AST_DISABLE_FOR_WIDGET
                        148     NOP                             
                        150     NOP                             
                        152     NOP                             
                        154     JUMP_FORWARD                    20 (to 196)
                        156     CALL                            1
                        164     POP_TOP                         
                        166     RETURN_VALUE                    
                        168     PUSH_EXC_INFO                   
                        170     PUSH_NULL                       
                        172     LOAD_CONST                      4: '__pyarmor_exit_55056__'
                        174     NOP                             
                        176     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        178     CALL                            1
                        186     POP_TOP                         
                        188     RERAISE                         0
                        190     COPY                            3
                        192     POP_EXCEPT                      
                        194     RERAISE                         1
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      4: '__pyarmor_exit_55056__'
                        200     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        202     BUILD_TUPLE                     1
                        204     CALL_FUNCTION_EX                0
                        206     POP_TOP                         
                        208     RETURN_VALUE                    
                '__pyarmor_exit_55047__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'DecompilationHandler'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55046__'
                16      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> __init__
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: __init__
                42      LOAD_CONST                      5: <CODE> activate
                44      MAKE_FUNCTION                   0
                46      STORE_NAME                      5: activate
                48      LOAD_CONST                      6: <CODE> update
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      6: update
                54      LOAD_CONST                      8: None
                56      NOP                             
                58      NOP                             
                60      NOP                             
                62      JUMP_FORWARD                    19 (to 102)
                70      POP_TOP                         
                72      RETURN_CONST                    8: None
                74      PUSH_EXC_INFO                   
                76      PUSH_NULL                       
                78      LOAD_CONST                      7: '__pyarmor_exit_55047__'
                80      NOP                             
                82      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                84      CALL                            1
                92      POP_TOP                         
                94      RERAISE                         0
                96      COPY                            3
                98      POP_EXCEPT                      
                100     RERAISE                         1
                102     PUSH_NULL                       
                104     LOAD_CONST                      7: '__pyarmor_exit_55047__'
                106     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                108     BUILD_TUPLE                     1
                110     CALL_FUNCTION_EX                0
                112     POP_TOP                         
                114     RETURN_VALUE                    
        'DecompilationHandler'
        [Code]
            File Name: <frozen ..handler>
            Object Name: SpecificVariableAnalysisHandler
            Qualified Name: SpecificVariableAnalysisHandler
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                '__init__'
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'SpecificVariableAnalysisHandler'
                '__pyarmor_assert_55057__'
                '__pyarmor_enter_55058__'
                b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: SpecificVariableAnalysisHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55060__'
                        '__pyarmor_enter_55061__'
                        b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55062__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55061__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55062__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55062__'
                        142     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: SpecificVariableAnalysisHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'idc'
                        'get_screen_ea'
                        'idaapi'
                        'get_func'
                        'get_func_name'
                        'print'
                        'hex'
                        'threading'
                        'Thread'
                        'specific_vars_analysis'
                        'start_ea'
                        'start'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_6'
                        '_var_var_20'
                    [Constants]
                        None
                        '__pyarmor_assert_55063__'
                        '__pyarmor_enter_55064__'
                        b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        'Variable Analysis on ea: '
                        ', func name: '
                        (
                            'target'
                            'args'
                        )
                        '__pyarmor_exit_55065__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55064__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + idc
                        38      LOAD_ATTR                       2: get_screen_ea
                        58      CALL                            0
                        66      STORE_FAST                      3: _var_var_18
                        68      LOAD_GLOBAL                     5: NULL + idaapi
                        78      LOAD_ATTR                       6: get_func
                        98      LOAD_FAST                       3: _var_var_18
                        100     CALL                            1
                        108     STORE_FAST                      4: _var_var_19
                        110     LOAD_GLOBAL                     1: NULL + idc
                        120     LOAD_ATTR                       8: get_func_name
                        140     LOAD_FAST                       3: _var_var_18
                        142     CALL                            1
                        150     STORE_FAST                      5: _var_var_6
                        152     LOAD_GLOBAL                     11: NULL + print
                        162     LOAD_CONST                      4: 'Variable Analysis on ea: '
                        164     LOAD_GLOBAL                     13: NULL + hex
                        174     LOAD_FAST                       3: _var_var_18
                        176     CALL                            1
                        184     FORMAT_VALUE                    0 (FVC_NONE)
                        186     LOAD_CONST                      5: ', func name: '
                        188     LOAD_FAST                       5: _var_var_6
                        190     FORMAT_VALUE                    0 (FVC_NONE)
                        192     BUILD_STRING                    4
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + threading
                        214     LOAD_ATTR                       16: Thread
                        234     LOAD_GLOBAL                     18: specific_vars_analysis
                        244     LOAD_FAST                       4: _var_var_19
                        246     LOAD_ATTR                       20: start_ea
                        266     BUILD_TUPLE                     1
                        268     KW_NAMES                        6: ('target', 'args')
                        270     CALL                            2
                        278     STORE_FAST                      6: _var_var_20
                        280     LOAD_FAST                       6: _var_var_20
                        282     LOAD_ATTR                       23: start
                        302     CALL                            0
                        310     POP_TOP                         
                        312     LOAD_CONST                      8: 1
                        314     NOP                             
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    19 (to 360)
                        328     POP_TOP                         
                        330     RETURN_CONST                    8: 1
                        332     PUSH_EXC_INFO                   
                        334     PUSH_NULL                       
                        336     LOAD_CONST                      7: '__pyarmor_exit_55065__'
                        338     NOP                             
                        340     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        342     CALL                            1
                        350     POP_TOP                         
                        352     RERAISE                         0
                        354     COPY                            3
                        356     POP_EXCEPT                      
                        358     RERAISE                         1
                        360     PUSH_NULL                       
                        362     LOAD_CONST                      7: '__pyarmor_exit_55065__'
                        364     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        366     BUILD_TUPLE                     1
                        368     CALL_FUNCTION_EX                0
                        370     POP_TOP                         
                        372     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: SpecificVariableAnalysisHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widget_type'
                        'ida_kernwin'
                        'BWN_PSEUDOCODE'
                        'AST_ENABLE_FOR_WIDGET'
                        'AST_DISABLE_FOR_WIDGET'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55066__'
                        '__pyarmor_enter_55067__'
                        b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55068__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55067__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: ctx
                        30      LOAD_ATTR                       0: widget_type
                        50      LOAD_GLOBAL                     2: ida_kernwin
                        60      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               16 (to 118)
                        86      LOAD_GLOBAL                     2: ida_kernwin
                        96      LOAD_ATTR                       6: AST_ENABLE_FOR_WIDGET
                        116     JUMP_FORWARD                    15 (to 148)
                        118     LOAD_GLOBAL                     2: ida_kernwin
                        128     LOAD_ATTR                       8: AST_DISABLE_FOR_WIDGET
                        148     NOP                             
                        150     NOP                             
                        152     NOP                             
                        154     JUMP_FORWARD                    20 (to 196)
                        156     CALL                            1
                        164     POP_TOP                         
                        166     RETURN_VALUE                    
                        168     PUSH_EXC_INFO                   
                        170     PUSH_NULL                       
                        172     LOAD_CONST                      4: '__pyarmor_exit_55068__'
                        174     NOP                             
                        176     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        178     CALL                            1
                        186     POP_TOP                         
                        188     RERAISE                         0
                        190     COPY                            3
                        192     POP_EXCEPT                      
                        194     RERAISE                         1
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      4: '__pyarmor_exit_55068__'
                        200     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        202     BUILD_TUPLE                     1
                        204     CALL_FUNCTION_EX                0
                        206     POP_TOP                         
                        208     RETURN_VALUE                    
                '__pyarmor_exit_55059__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'SpecificVariableAnalysisHandler'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55058__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> __init__
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: __init__
                42      LOAD_CONST                      5: <CODE> activate
                44      MAKE_FUNCTION                   0
                46      STORE_NAME                      5: activate
                48      LOAD_CONST                      6: <CODE> update
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      6: update
                54      LOAD_CONST                      8: None
                56      NOP                             
                58      NOP                             
                60      NOP                             
                62      JUMP_FORWARD                    19 (to 102)
                70      POP_TOP                         
                72      RETURN_CONST                    8: None
                74      PUSH_EXC_INFO                   
                76      PUSH_NULL                       
                78      LOAD_CONST                      7: '__pyarmor_exit_55059__'
                80      NOP                             
                82      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                84      CALL                            1
                92      POP_TOP                         
                94      RERAISE                         0
                96      COPY                            3
                98      POP_EXCEPT                      
                100     RERAISE                         1
                102     PUSH_NULL                       
                104     LOAD_CONST                      7: '__pyarmor_exit_55059__'
                106     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                108     BUILD_TUPLE                     1
                110     CALL_FUNCTION_EX                0
                112     POP_TOP                         
                114     RETURN_VALUE                    
        'SpecificVariableAnalysisHandler'
        [Code]
            File Name: <frozen ..handler>
            Object Name: AllVariableAnalysisHandler
            Qualified Name: AllVariableAnalysisHandler
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                '__init__'
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'AllVariableAnalysisHandler'
                '__pyarmor_assert_55069__'
                '__pyarmor_enter_55070__'
                b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: AllVariableAnalysisHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55072__'
                        '__pyarmor_enter_55073__'
                        b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55074__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55073__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55074__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55074__'
                        142     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: AllVariableAnalysisHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'idc'
                        'get_screen_ea'
                        'idaapi'
                        'get_func'
                        'get_func_name'
                        'print'
                        'hex'
                        'threading'
                        'Thread'
                        'all_vars_analysis'
                        'start_ea'
                        'start'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_6'
                        '_var_var_20'
                    [Constants]
                        None
                        '__pyarmor_assert_55075__'
                        '__pyarmor_enter_55076__'
                        b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        'Variable Analysis on ea: '
                        ', func name: '
                        (
                            'target'
                            'args'
                        )
                        '__pyarmor_exit_55077__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55076__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + idc
                        38      LOAD_ATTR                       2: get_screen_ea
                        58      CALL                            0
                        66      STORE_FAST                      3: _var_var_18
                        68      LOAD_GLOBAL                     5: NULL + idaapi
                        78      LOAD_ATTR                       6: get_func
                        98      LOAD_FAST                       3: _var_var_18
                        100     CALL                            1
                        108     STORE_FAST                      4: _var_var_19
                        110     LOAD_GLOBAL                     1: NULL + idc
                        120     LOAD_ATTR                       8: get_func_name
                        140     LOAD_FAST                       3: _var_var_18
                        142     CALL                            1
                        150     STORE_FAST                      5: _var_var_6
                        152     LOAD_GLOBAL                     11: NULL + print
                        162     LOAD_CONST                      4: 'Variable Analysis on ea: '
                        164     LOAD_GLOBAL                     13: NULL + hex
                        174     LOAD_FAST                       3: _var_var_18
                        176     CALL                            1
                        184     FORMAT_VALUE                    0 (FVC_NONE)
                        186     LOAD_CONST                      5: ', func name: '
                        188     LOAD_FAST                       5: _var_var_6
                        190     FORMAT_VALUE                    0 (FVC_NONE)
                        192     BUILD_STRING                    4
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + threading
                        214     LOAD_ATTR                       16: Thread
                        234     LOAD_GLOBAL                     18: all_vars_analysis
                        244     LOAD_FAST                       4: _var_var_19
                        246     LOAD_ATTR                       20: start_ea
                        266     BUILD_TUPLE                     1
                        268     KW_NAMES                        6: ('target', 'args')
                        270     CALL                            2
                        278     STORE_FAST                      6: _var_var_20
                        280     LOAD_FAST                       6: _var_var_20
                        282     LOAD_ATTR                       23: start
                        302     CALL                            0
                        310     POP_TOP                         
                        312     LOAD_CONST                      8: 1
                        314     NOP                             
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    19 (to 360)
                        328     POP_TOP                         
                        330     RETURN_CONST                    8: 1
                        332     PUSH_EXC_INFO                   
                        334     PUSH_NULL                       
                        336     LOAD_CONST                      7: '__pyarmor_exit_55077__'
                        338     NOP                             
                        340     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        342     CALL                            1
                        350     POP_TOP                         
                        352     RERAISE                         0
                        354     COPY                            3
                        356     POP_EXCEPT                      
                        358     RERAISE                         1
                        360     PUSH_NULL                       
                        362     LOAD_CONST                      7: '__pyarmor_exit_55077__'
                        364     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        366     BUILD_TUPLE                     1
                        368     CALL_FUNCTION_EX                0
                        370     POP_TOP                         
                        372     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: AllVariableAnalysisHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widget_type'
                        'ida_kernwin'
                        'BWN_PSEUDOCODE'
                        'AST_ENABLE_FOR_WIDGET'
                        'AST_DISABLE_FOR_WIDGET'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55078__'
                        '__pyarmor_enter_55079__'
                        b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55080__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55079__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: ctx
                        30      LOAD_ATTR                       0: widget_type
                        50      LOAD_GLOBAL                     2: ida_kernwin
                        60      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               16 (to 118)
                        86      LOAD_GLOBAL                     2: ida_kernwin
                        96      LOAD_ATTR                       6: AST_ENABLE_FOR_WIDGET
                        116     JUMP_FORWARD                    15 (to 148)
                        118     LOAD_GLOBAL                     2: ida_kernwin
                        128     LOAD_ATTR                       8: AST_DISABLE_FOR_WIDGET
                        148     NOP                             
                        150     NOP                             
                        152     NOP                             
                        154     JUMP_FORWARD                    20 (to 196)
                        156     CALL                            1
                        164     POP_TOP                         
                        166     RETURN_VALUE                    
                        168     PUSH_EXC_INFO                   
                        170     PUSH_NULL                       
                        172     LOAD_CONST                      4: '__pyarmor_exit_55080__'
                        174     NOP                             
                        176     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        178     CALL                            1
                        186     POP_TOP                         
                        188     RERAISE                         0
                        190     COPY                            3
                        192     POP_EXCEPT                      
                        194     RERAISE                         1
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      4: '__pyarmor_exit_55080__'
                        200     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        202     BUILD_TUPLE                     1
                        204     CALL_FUNCTION_EX                0
                        206     POP_TOP                         
                        208     RETURN_VALUE                    
                '__pyarmor_exit_55071__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'AllVariableAnalysisHandler'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55070__'
                16      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> __init__
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: __init__
                42      LOAD_CONST                      5: <CODE> activate
                44      MAKE_FUNCTION                   0
                46      STORE_NAME                      5: activate
                48      LOAD_CONST                      6: <CODE> update
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      6: update
                54      LOAD_CONST                      8: None
                56      NOP                             
                58      NOP                             
                60      NOP                             
                62      JUMP_FORWARD                    19 (to 102)
                70      POP_TOP                         
                72      RETURN_CONST                    8: None
                74      PUSH_EXC_INFO                   
                76      PUSH_NULL                       
                78      LOAD_CONST                      7: '__pyarmor_exit_55071__'
                80      NOP                             
                82      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                84      CALL                            1
                92      POP_TOP                         
                94      RERAISE                         0
                96      COPY                            3
                98      POP_EXCEPT                      
                100     RERAISE                         1
                102     PUSH_NULL                       
                104     LOAD_CONST                      7: '__pyarmor_exit_55071__'
                106     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                108     BUILD_TUPLE                     1
                110     CALL_FUNCTION_EX                0
                112     POP_TOP                         
                114     RETURN_VALUE                    
        'AllVariableAnalysisHandler'
        [Code]
            File Name: <frozen ..handler>
            Object Name: AllArgumentAnalysisHandler
            Qualified Name: AllArgumentAnalysisHandler
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                '__init__'
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'AllArgumentAnalysisHandler'
                '__pyarmor_assert_55081__'
                '__pyarmor_enter_55082__'
                b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: AllArgumentAnalysisHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55084__'
                        '__pyarmor_enter_55085__'
                        b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55086__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55085__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55086__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55086__'
                        142     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: AllArgumentAnalysisHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'idc'
                        'get_screen_ea'
                        'idaapi'
                        'get_func'
                        'get_func_name'
                        'print'
                        'hex'
                        'threading'
                        'Thread'
                        'all_args_analysis'
                        'start_ea'
                        'start'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_6'
                        '_var_var_20'
                    [Constants]
                        None
                        '__pyarmor_assert_55087__'
                        '__pyarmor_enter_55088__'
                        b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        'All Argument Analysis on ea: '
                        ', func name: '
                        (
                            'target'
                            'args'
                        )
                        '__pyarmor_exit_55089__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55088__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + idc
                        38      LOAD_ATTR                       2: get_screen_ea
                        58      CALL                            0
                        66      STORE_FAST                      3: _var_var_18
                        68      LOAD_GLOBAL                     5: NULL + idaapi
                        78      LOAD_ATTR                       6: get_func
                        98      LOAD_FAST                       3: _var_var_18
                        100     CALL                            1
                        108     STORE_FAST                      4: _var_var_19
                        110     LOAD_GLOBAL                     1: NULL + idc
                        120     LOAD_ATTR                       8: get_func_name
                        140     LOAD_FAST                       3: _var_var_18
                        142     CALL                            1
                        150     STORE_FAST                      5: _var_var_6
                        152     LOAD_GLOBAL                     11: NULL + print
                        162     LOAD_CONST                      4: 'All Argument Analysis on ea: '
                        164     LOAD_GLOBAL                     13: NULL + hex
                        174     LOAD_FAST                       3: _var_var_18
                        176     CALL                            1
                        184     FORMAT_VALUE                    0 (FVC_NONE)
                        186     LOAD_CONST                      5: ', func name: '
                        188     LOAD_FAST                       5: _var_var_6
                        190     FORMAT_VALUE                    0 (FVC_NONE)
                        192     BUILD_STRING                    4
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + threading
                        214     LOAD_ATTR                       16: Thread
                        234     LOAD_GLOBAL                     18: all_args_analysis
                        244     LOAD_FAST                       4: _var_var_19
                        246     LOAD_ATTR                       20: start_ea
                        266     BUILD_TUPLE                     1
                        268     KW_NAMES                        6: ('target', 'args')
                        270     CALL                            2
                        278     STORE_FAST                      6: _var_var_20
                        280     LOAD_FAST                       6: _var_var_20
                        282     LOAD_ATTR                       23: start
                        302     CALL                            0
                        310     POP_TOP                         
                        312     LOAD_CONST                      8: 1
                        314     NOP                             
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    19 (to 360)
                        328     POP_TOP                         
                        330     RETURN_CONST                    8: 1
                        332     PUSH_EXC_INFO                   
                        334     PUSH_NULL                       
                        336     LOAD_CONST                      7: '__pyarmor_exit_55089__'
                        338     NOP                             
                        340     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        342     CALL                            1
                        350     POP_TOP                         
                        352     RERAISE                         0
                        354     COPY                            3
                        356     POP_EXCEPT                      
                        358     RERAISE                         1
                        360     PUSH_NULL                       
                        362     LOAD_CONST                      7: '__pyarmor_exit_55089__'
                        364     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        366     BUILD_TUPLE                     1
                        368     CALL_FUNCTION_EX                0
                        370     POP_TOP                         
                        372     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: AllArgumentAnalysisHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widget_type'
                        'ida_kernwin'
                        'BWN_PSEUDOCODE'
                        'AST_ENABLE_FOR_WIDGET'
                        'AST_DISABLE_FOR_WIDGET'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55090__'
                        '__pyarmor_enter_55091__'
                        b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55092__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55091__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: ctx
                        30      LOAD_ATTR                       0: widget_type
                        50      LOAD_GLOBAL                     2: ida_kernwin
                        60      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               16 (to 118)
                        86      LOAD_GLOBAL                     2: ida_kernwin
                        96      LOAD_ATTR                       6: AST_ENABLE_FOR_WIDGET
                        116     JUMP_FORWARD                    15 (to 148)
                        118     LOAD_GLOBAL                     2: ida_kernwin
                        128     LOAD_ATTR                       8: AST_DISABLE_FOR_WIDGET
                        148     NOP                             
                        150     NOP                             
                        152     NOP                             
                        154     JUMP_FORWARD                    20 (to 196)
                        156     CALL                            1
                        164     POP_TOP                         
                        166     RETURN_VALUE                    
                        168     PUSH_EXC_INFO                   
                        170     PUSH_NULL                       
                        172     LOAD_CONST                      4: '__pyarmor_exit_55092__'
                        174     NOP                             
                        176     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        178     CALL                            1
                        186     POP_TOP                         
                        188     RERAISE                         0
                        190     COPY                            3
                        192     POP_EXCEPT                      
                        194     RERAISE                         1
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      4: '__pyarmor_exit_55092__'
                        200     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        202     BUILD_TUPLE                     1
                        204     CALL_FUNCTION_EX                0
                        206     POP_TOP                         
                        208     RETURN_VALUE                    
                '__pyarmor_exit_55083__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'AllArgumentAnalysisHandler'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55082__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> __init__
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: __init__
                42      LOAD_CONST                      5: <CODE> activate
                44      MAKE_FUNCTION                   0
                46      STORE_NAME                      5: activate
                48      LOAD_CONST                      6: <CODE> update
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      6: update
                54      LOAD_CONST                      8: None
                56      NOP                             
                58      NOP                             
                60      NOP                             
                62      JUMP_FORWARD                    19 (to 102)
                70      POP_TOP                         
                72      RETURN_CONST                    8: None
                74      PUSH_EXC_INFO                   
                76      PUSH_NULL                       
                78      LOAD_CONST                      7: '__pyarmor_exit_55083__'
                80      NOP                             
                82      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                84      CALL                            1
                92      POP_TOP                         
                94      RERAISE                         0
                96      COPY                            3
                98      POP_EXCEPT                      
                100     RERAISE                         1
                102     PUSH_NULL                       
                104     LOAD_CONST                      7: '__pyarmor_exit_55083__'
                106     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                108     BUILD_TUPLE                     1
                110     CALL_FUNCTION_EX                0
                112     POP_TOP                         
                114     RETURN_VALUE                    
        'AllArgumentAnalysisHandler'
        [Code]
            File Name: <frozen ..handler>
            Object Name: FuncNameAnalysisHandler
            Qualified Name: FuncNameAnalysisHandler
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                '__init__'
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'FuncNameAnalysisHandler'
                '__pyarmor_assert_55093__'
                '__pyarmor_enter_55094__'
                b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: FuncNameAnalysisHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55096__'
                        '__pyarmor_enter_55097__'
                        b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55098__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55097__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55098__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55098__'
                        142     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: FuncNameAnalysisHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'idc'
                        'get_screen_ea'
                        'idaapi'
                        'get_func'
                        'get_func_name'
                        'print'
                        'hex'
                        'threading'
                        'Thread'
                        'func_name_analysis'
                        'start_ea'
                        'start'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_6'
                        '_var_var_20'
                    [Constants]
                        None
                        '__pyarmor_assert_55099__'
                        '__pyarmor_enter_55100__'
                        b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        'Function Name Analysis on ea: '
                        ', func name: '
                        (
                            'target'
                            'args'
                        )
                        '__pyarmor_exit_55101__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55100__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + idc
                        38      LOAD_ATTR                       2: get_screen_ea
                        58      CALL                            0
                        66      STORE_FAST                      3: _var_var_18
                        68      LOAD_GLOBAL                     5: NULL + idaapi
                        78      LOAD_ATTR                       6: get_func
                        98      LOAD_FAST                       3: _var_var_18
                        100     CALL                            1
                        108     STORE_FAST                      4: _var_var_19
                        110     LOAD_GLOBAL                     1: NULL + idc
                        120     LOAD_ATTR                       8: get_func_name
                        140     LOAD_FAST                       3: _var_var_18
                        142     CALL                            1
                        150     STORE_FAST                      5: _var_var_6
                        152     LOAD_GLOBAL                     11: NULL + print
                        162     LOAD_CONST                      4: 'Function Name Analysis on ea: '
                        164     LOAD_GLOBAL                     13: NULL + hex
                        174     LOAD_FAST                       3: _var_var_18
                        176     CALL                            1
                        184     FORMAT_VALUE                    0 (FVC_NONE)
                        186     LOAD_CONST                      5: ', func name: '
                        188     LOAD_FAST                       5: _var_var_6
                        190     FORMAT_VALUE                    0 (FVC_NONE)
                        192     BUILD_STRING                    4
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + threading
                        214     LOAD_ATTR                       16: Thread
                        234     LOAD_GLOBAL                     18: func_name_analysis
                        244     LOAD_FAST                       4: _var_var_19
                        246     LOAD_ATTR                       20: start_ea
                        266     BUILD_TUPLE                     1
                        268     KW_NAMES                        6: ('target', 'args')
                        270     CALL                            2
                        278     STORE_FAST                      6: _var_var_20
                        280     LOAD_FAST                       6: _var_var_20
                        282     LOAD_ATTR                       23: start
                        302     CALL                            0
                        310     POP_TOP                         
                        312     LOAD_CONST                      8: 1
                        314     NOP                             
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    19 (to 360)
                        328     POP_TOP                         
                        330     RETURN_CONST                    8: 1
                        332     PUSH_EXC_INFO                   
                        334     PUSH_NULL                       
                        336     LOAD_CONST                      7: '__pyarmor_exit_55101__'
                        338     NOP                             
                        340     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        342     CALL                            1
                        350     POP_TOP                         
                        352     RERAISE                         0
                        354     COPY                            3
                        356     POP_EXCEPT                      
                        358     RERAISE                         1
                        360     PUSH_NULL                       
                        362     LOAD_CONST                      7: '__pyarmor_exit_55101__'
                        364     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        366     BUILD_TUPLE                     1
                        368     CALL_FUNCTION_EX                0
                        370     POP_TOP                         
                        372     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: FuncNameAnalysisHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widget_type'
                        'ida_kernwin'
                        'BWN_PSEUDOCODE'
                        'AST_ENABLE_FOR_WIDGET'
                        'AST_DISABLE_FOR_WIDGET'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55102__'
                        '__pyarmor_enter_55103__'
                        b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55104__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55103__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: ctx
                        30      LOAD_ATTR                       0: widget_type
                        50      LOAD_GLOBAL                     2: ida_kernwin
                        60      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               16 (to 118)
                        86      LOAD_GLOBAL                     2: ida_kernwin
                        96      LOAD_ATTR                       6: AST_ENABLE_FOR_WIDGET
                        116     JUMP_FORWARD                    15 (to 148)
                        118     LOAD_GLOBAL                     2: ida_kernwin
                        128     LOAD_ATTR                       8: AST_DISABLE_FOR_WIDGET
                        148     NOP                             
                        150     NOP                             
                        152     NOP                             
                        154     JUMP_FORWARD                    20 (to 196)
                        156     CALL                            1
                        164     POP_TOP                         
                        166     RETURN_VALUE                    
                        168     PUSH_EXC_INFO                   
                        170     PUSH_NULL                       
                        172     LOAD_CONST                      4: '__pyarmor_exit_55104__'
                        174     NOP                             
                        176     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        178     CALL                            1
                        186     POP_TOP                         
                        188     RERAISE                         0
                        190     COPY                            3
                        192     POP_EXCEPT                      
                        194     RERAISE                         1
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      4: '__pyarmor_exit_55104__'
                        200     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        202     BUILD_TUPLE                     1
                        204     CALL_FUNCTION_EX                0
                        206     POP_TOP                         
                        208     RETURN_VALUE                    
                '__pyarmor_exit_55095__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'FuncNameAnalysisHandler'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55094__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> __init__
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: __init__
                42      LOAD_CONST                      5: <CODE> activate
                44      MAKE_FUNCTION                   0
                46      STORE_NAME                      5: activate
                48      LOAD_CONST                      6: <CODE> update
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      6: update
                54      LOAD_CONST                      8: None
                56      NOP                             
                58      NOP                             
                60      NOP                             
                62      JUMP_FORWARD                    19 (to 102)
                70      POP_TOP                         
                72      RETURN_CONST                    8: None
                74      PUSH_EXC_INFO                   
                76      PUSH_NULL                       
                78      LOAD_CONST                      7: '__pyarmor_exit_55095__'
                80      NOP                             
                82      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                84      CALL                            1
                92      POP_TOP                         
                94      RERAISE                         0
                96      COPY                            3
                98      POP_EXCEPT                      
                100     RERAISE                         1
                102     PUSH_NULL                       
                104     LOAD_CONST                      7: '__pyarmor_exit_55095__'
                106     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                108     BUILD_TUPLE                     1
                110     CALL_FUNCTION_EX                0
                112     POP_TOP                         
                114     RETURN_VALUE                    
        'FuncNameAnalysisHandler'
        [Code]
            File Name: <frozen ..handler>
            Object Name: SummaryAnalysisHandler
            Qualified Name: SummaryAnalysisHandler
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                '__init__'
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'SummaryAnalysisHandler'
                '__pyarmor_assert_55105__'
                '__pyarmor_enter_55106__'
                b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: SummaryAnalysisHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55108__'
                        '__pyarmor_enter_55109__'
                        b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55110__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55109__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55110__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55110__'
                        142     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: SummaryAnalysisHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'idc'
                        'get_screen_ea'
                        'idaapi'
                        'get_func'
                        'get_func_name'
                        'print'
                        'hex'
                        'threading'
                        'Thread'
                        'summary_analysis'
                        'start_ea'
                        'start'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_6'
                        '_var_var_20'
                    [Constants]
                        None
                        '__pyarmor_assert_55111__'
                        '__pyarmor_enter_55112__'
                        b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        'Summary Analysis on ea: '
                        ', func name: '
                        (
                            'target'
                            'args'
                        )
                        '__pyarmor_exit_55113__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55112__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + idc
                        38      LOAD_ATTR                       2: get_screen_ea
                        58      CALL                            0
                        66      STORE_FAST                      3: _var_var_18
                        68      LOAD_GLOBAL                     5: NULL + idaapi
                        78      LOAD_ATTR                       6: get_func
                        98      LOAD_FAST                       3: _var_var_18
                        100     CALL                            1
                        108     STORE_FAST                      4: _var_var_19
                        110     LOAD_GLOBAL                     1: NULL + idc
                        120     LOAD_ATTR                       8: get_func_name
                        140     LOAD_FAST                       3: _var_var_18
                        142     CALL                            1
                        150     STORE_FAST                      5: _var_var_6
                        152     LOAD_GLOBAL                     11: NULL + print
                        162     LOAD_CONST                      4: 'Summary Analysis on ea: '
                        164     LOAD_GLOBAL                     13: NULL + hex
                        174     LOAD_FAST                       3: _var_var_18
                        176     CALL                            1
                        184     FORMAT_VALUE                    0 (FVC_NONE)
                        186     LOAD_CONST                      5: ', func name: '
                        188     LOAD_FAST                       5: _var_var_6
                        190     FORMAT_VALUE                    0 (FVC_NONE)
                        192     BUILD_STRING                    4
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + threading
                        214     LOAD_ATTR                       16: Thread
                        234     LOAD_GLOBAL                     18: summary_analysis
                        244     LOAD_FAST                       4: _var_var_19
                        246     LOAD_ATTR                       20: start_ea
                        266     BUILD_TUPLE                     1
                        268     KW_NAMES                        6: ('target', 'args')
                        270     CALL                            2
                        278     STORE_FAST                      6: _var_var_20
                        280     LOAD_FAST                       6: _var_var_20
                        282     LOAD_ATTR                       23: start
                        302     CALL                            0
                        310     POP_TOP                         
                        312     LOAD_CONST                      8: 1
                        314     NOP                             
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    19 (to 360)
                        328     POP_TOP                         
                        330     RETURN_CONST                    8: 1
                        332     PUSH_EXC_INFO                   
                        334     PUSH_NULL                       
                        336     LOAD_CONST                      7: '__pyarmor_exit_55113__'
                        338     NOP                             
                        340     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        342     CALL                            1
                        350     POP_TOP                         
                        352     RERAISE                         0
                        354     COPY                            3
                        356     POP_EXCEPT                      
                        358     RERAISE                         1
                        360     PUSH_NULL                       
                        362     LOAD_CONST                      7: '__pyarmor_exit_55113__'
                        364     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a2\x01\x00\x00\x00\x00\x00\x00'
                        366     BUILD_TUPLE                     1
                        368     CALL_FUNCTION_EX                0
                        370     POP_TOP                         
                        372     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: SummaryAnalysisHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widget_type'
                        'ida_kernwin'
                        'BWN_PSEUDOCODE'
                        'AST_ENABLE_FOR_WIDGET'
                        'AST_DISABLE_FOR_WIDGET'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55114__'
                        '__pyarmor_enter_55115__'
                        b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55116__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55115__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: ctx
                        30      LOAD_ATTR                       0: widget_type
                        50      LOAD_GLOBAL                     2: ida_kernwin
                        60      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               16 (to 118)
                        86      LOAD_GLOBAL                     2: ida_kernwin
                        96      LOAD_ATTR                       6: AST_ENABLE_FOR_WIDGET
                        116     JUMP_FORWARD                    15 (to 148)
                        118     LOAD_GLOBAL                     2: ida_kernwin
                        128     LOAD_ATTR                       8: AST_DISABLE_FOR_WIDGET
                        148     NOP                             
                        150     NOP                             
                        152     NOP                             
                        154     JUMP_FORWARD                    20 (to 196)
                        156     CALL                            1
                        164     POP_TOP                         
                        166     RETURN_VALUE                    
                        168     PUSH_EXC_INFO                   
                        170     PUSH_NULL                       
                        172     LOAD_CONST                      4: '__pyarmor_exit_55116__'
                        174     NOP                             
                        176     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        178     CALL                            1
                        186     POP_TOP                         
                        188     RERAISE                         0
                        190     COPY                            3
                        192     POP_EXCEPT                      
                        194     RERAISE                         1
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      4: '__pyarmor_exit_55116__'
                        200     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                        202     BUILD_TUPLE                     1
                        204     CALL_FUNCTION_EX                0
                        206     POP_TOP                         
                        208     RETURN_VALUE                    
                '__pyarmor_exit_55107__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'SummaryAnalysisHandler'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55106__'
                16      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> __init__
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: __init__
                42      LOAD_CONST                      5: <CODE> activate
                44      MAKE_FUNCTION                   0
                46      STORE_NAME                      5: activate
                48      LOAD_CONST                      6: <CODE> update
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      6: update
                54      LOAD_CONST                      8: None
                56      NOP                             
                58      NOP                             
                60      NOP                             
                62      JUMP_FORWARD                    19 (to 102)
                70      POP_TOP                         
                72      RETURN_CONST                    8: None
                74      PUSH_EXC_INFO                   
                76      PUSH_NULL                       
                78      LOAD_CONST                      7: '__pyarmor_exit_55107__'
                80      NOP                             
                82      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                84      CALL                            1
                92      POP_TOP                         
                94      RERAISE                         0
                96      COPY                            3
                98      POP_EXCEPT                      
                100     RERAISE                         1
                102     PUSH_NULL                       
                104     LOAD_CONST                      7: '__pyarmor_exit_55107__'
                106     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"(\x00\x00\x00\x00\x00\x00\x00'
                108     BUILD_TUPLE                     1
                110     CALL_FUNCTION_EX                0
                112     POP_TOP                         
                114     RETURN_VALUE                    
        'SummaryAnalysisHandler'
        [Code]
            File Name: <frozen ..handler>
            Object Name: ReCopilotSettingsHandler
            Qualified Name: ReCopilotSettingsHandler
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
                'activate'
                'update'
            [Locals+Names]
            [Constants]
                'ReCopilotSettingsHandler'
                '\n    Handler for showing ReCopilot settings dialog.\n    '
                '__pyarmor_assert_55117__'
                '__pyarmor_enter_55118__'
                b'<COAddr>\x01\x00\x00&(\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: __init__
                    Qualified Name: ReCopilotSettingsHandler.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'action_handler_t'
                        '__init__'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55120__'
                        '__pyarmor_enter_55121__'
                        b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55122__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55121__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: action_handler_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      CALL                            1
                        88      POP_TOP                         
                        90      LOAD_CONST                      0: None
                        92      NOP                             
                        94      NOP                             
                        96      NOP                             
                        98      JUMP_FORWARD                    19 (to 138)
                        106     POP_TOP                         
                        108     RETURN_CONST                    0: None
                        110     PUSH_EXC_INFO                   
                        112     PUSH_NULL                       
                        114     LOAD_CONST                      4: '__pyarmor_exit_55122__'
                        116     NOP                             
                        118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        120     CALL                            1
                        128     POP_TOP                         
                        130     RERAISE                         0
                        132     COPY                            3
                        134     POP_EXCEPT                      
                        136     RERAISE                         1
                        138     PUSH_NULL                       
                        140     LOAD_CONST                      4: '__pyarmor_exit_55122__'
                        142     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x00\x00\x00\x00\x00\x00\x00'
                        144     BUILD_TUPLE                     1
                        146     CALL_FUNCTION_EX                0
                        148     POP_TOP                         
                        150     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: activate
                    Qualified Name: ReCopilotSettingsHandler.activate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ReCopilotSettingsDialog'
                        'exec_'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                        '_var_var_21'
                    [Constants]
                        None
                        '__pyarmor_assert_55123__'
                        '__pyarmor_enter_55124__'
                        b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55125__'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55124__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + ReCopilotSettingsDialog
                        38      CALL                            0
                        46      STORE_FAST                      3: _var_var_21
                        48      LOAD_FAST                       3: _var_var_21
                        50      LOAD_ATTR                       3: exec_
                        70      CALL                            0
                        78      POP_TOP                         
                        80      LOAD_CONST                      5: 1
                        82      NOP                             
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    19 (to 128)
                        96      POP_TOP                         
                        98      RETURN_CONST                    5: 1
                        100     PUSH_EXC_INFO                   
                        102     PUSH_NULL                       
                        104     LOAD_CONST                      4: '__pyarmor_exit_55125__'
                        106     NOP                             
                        108     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        110     CALL                            1
                        118     POP_TOP                         
                        120     RERAISE                         0
                        122     COPY                            3
                        124     POP_EXCEPT                      
                        126     RERAISE                         1
                        128     PUSH_NULL                       
                        130     LOAD_CONST                      4: '__pyarmor_exit_55125__'
                        132     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        134     BUILD_TUPLE                     1
                        136     CALL_FUNCTION_EX                0
                        138     POP_TOP                         
                        140     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..handler>
                    Object Name: update
                    Qualified Name: ReCopilotSettingsHandler.update
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'AST_ENABLE_ALWAYS'
                    [Locals+Names]
                        'self'
                        'ctx'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55126__'
                        '__pyarmor_enter_55127__'
                        b'<COAddr>\x01\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55128__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55127__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_kernwin
                        38      LOAD_ATTR                       2: AST_ENABLE_ALWAYS
                        58      NOP                             
                        60      NOP                             
                        62      NOP                             
                        64      JUMP_FORWARD                    20 (to 106)
                        66      CALL                            1
                        74      POP_TOP                         
                        76      RETURN_VALUE                    
                        78      PUSH_EXC_INFO                   
                        80      PUSH_NULL                       
                        82      LOAD_CONST                      4: '__pyarmor_exit_55128__'
                        84      NOP                             
                        86      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        88      CALL                            1
                        96      POP_TOP                         
                        98      RERAISE                         0
                        100     COPY                            3
                        102     POP_EXCEPT                      
                        104     RERAISE                         1
                        106     PUSH_NULL                       
                        108     LOAD_CONST                      4: '__pyarmor_exit_55128__'
                        110     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a4\x00\x00\x00\x00\x00\x00\x00'
                        112     BUILD_TUPLE                     1
                        114     CALL_FUNCTION_EX                0
                        116     POP_TOP                         
                        118     RETURN_VALUE                    
                '__pyarmor_exit_55119__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'ReCopilotSettingsHandler'
                8       STORE_NAME                      2: __qualname__
                10      LOAD_CONST                      1: '\n    Handler for showing ReCopilot settings dialog.\n    '
                12      STORE_NAME                      3: __doc__
                14      NOP                             
                16      PUSH_NULL                       
                18      LOAD_CONST                      3: '__pyarmor_enter_55118__'
                20      LOAD_CONST                      4: b'<COAddr>\x01\x00\x00&(\x00\x00\x00\x00\x00\x00\x00'
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
                46      LOAD_CONST                      6: <CODE> activate
                48      MAKE_FUNCTION                   0
                50      STORE_NAME                      6: activate
                52      LOAD_CONST                      7: <CODE> update
                54      MAKE_FUNCTION                   0
                56      STORE_NAME                      7: update
                58      LOAD_CONST                      9: None
                60      NOP                             
                62      NOP                             
                64      NOP                             
                66      JUMP_FORWARD                    19 (to 106)
                74      POP_TOP                         
                76      RETURN_CONST                    9: None
                78      PUSH_EXC_INFO                   
                80      PUSH_NULL                       
                82      LOAD_CONST                      8: '__pyarmor_exit_55119__'
                84      NOP                             
                86      LOAD_CONST                      4: b'<COAddr>\x01\x00\x00&(\x00\x00\x00\x00\x00\x00\x00'
                88      CALL                            1
                96      POP_TOP                         
                98      RERAISE                         0
                100     COPY                            3
                102     POP_EXCEPT                      
                104     RERAISE                         1
                106     PUSH_NULL                       
                108     LOAD_CONST                      8: '__pyarmor_exit_55119__'
                110     LOAD_CONST                      4: b'<COAddr>\x01\x00\x00&(\x00\x00\x00\x00\x00\x00\x00'
                112     BUILD_TUPLE                     1
                114     CALL_FUNCTION_EX                0
                116     POP_TOP                         
                118     RETURN_VALUE                    
        'ReCopilotSettingsHandler'
        '__pyarmor_exit_54987__'
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54986__'
        8       LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a\x9e\x02\x00\x00\x00\x00\x00\x00'
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
        30      IMPORT_NAME                     1: ida_kernwin
        32      STORE_NAME                      1: ida_kernwin
        34      LOAD_CONST                      3: 0
        36      LOAD_CONST                      4: None
        38      IMPORT_NAME                     2: idc
        40      STORE_NAME                      2: idc
        42      LOAD_CONST                      3: 0
        44      LOAD_CONST                      4: None
        46      IMPORT_NAME                     3: idaapi
        48      STORE_NAME                      3: idaapi
        50      LOAD_CONST                      3: 0
        52      LOAD_CONST                      4: None
        54      IMPORT_NAME                     4: threading
        56      STORE_NAME                      4: threading
        58      LOAD_CONST                      3: 0
        60      LOAD_CONST                      4: None
        62      IMPORT_NAME                     5: time
        64      STORE_NAME                      5: time
        66      LOAD_CONST                      3: 0
        68      LOAD_CONST                      4: None
        70      IMPORT_NAME                     6: re
        72      STORE_NAME                      6: re
        74      LOAD_CONST                      3: 0
        76      LOAD_CONST                      4: None
        78      IMPORT_NAME                     7: json
        80      STORE_NAME                      7: json
        82      LOAD_CONST                      3: 0
        84      LOAD_CONST                      4: None
        86      IMPORT_NAME                     8: asyncio
        88      STORE_NAME                      8: asyncio
        90      LOAD_CONST                      3: 0
        92      LOAD_CONST                      5: ('partial',)
        94      IMPORT_NAME                     9: functools
        96      IMPORT_FROM                     10: partial
        98      STORE_NAME                      10: partial
        100     POP_TOP                         
        102     LOAD_CONST                      3: 0
        104     LOAD_CONST                      6: ('OpenAIModel',)
        106     IMPORT_NAME                     11: remote_model
        108     IMPORT_FROM                     12: OpenAIModel
        110     STORE_NAME                      12: OpenAIModel
        112     POP_TOP                         
        114     LOAD_CONST                      3: 0
        116     LOAD_CONST                      7: ('build_prompt', 'apply_prediction')
        118     IMPORT_NAME                     13: ext_info
        120     IMPORT_FROM                     14: build_prompt
        122     STORE_NAME                      14: build_prompt
        124     IMPORT_FROM                     15: apply_prediction
        126     STORE_NAME                      15: apply_prediction
        128     POP_TOP                         
        130     LOAD_CONST                      3: 0
        132     LOAD_CONST                      8: ('ReCopilotSettingsDialog', 'create_decompilation_view', 'create_user_confirm_view', 'create_variable_selection_view', 'create_user_confirm_view_for_funcname', 'add_cancel_button', 'remove_cancel_button')
        134     IMPORT_NAME                     16: recopilot_qt
        136     IMPORT_FROM                     17: ReCopilotSettingsDialog
        138     STORE_NAME                      17: ReCopilotSettingsDialog
        140     IMPORT_FROM                     18: create_decompilation_view
        142     STORE_NAME                      18: create_decompilation_view
        144     IMPORT_FROM                     19: create_user_confirm_view
        146     STORE_NAME                      19: create_user_confirm_view
        148     IMPORT_FROM                     20: create_variable_selection_view
        150     STORE_NAME                      20: create_variable_selection_view
        152     IMPORT_FROM                     21: create_user_confirm_view_for_funcname
        154     STORE_NAME                      21: create_user_confirm_view_for_funcname
        156     IMPORT_FROM                     22: add_cancel_button
        158     STORE_NAME                      22: add_cancel_button
        160     IMPORT_FROM                     23: remove_cancel_button
        162     STORE_NAME                      23: remove_cancel_button
        164     POP_TOP                         
        166     LOAD_CONST                      3: 0
        168     LOAD_CONST                      9: ('settings_manager',)
        170     IMPORT_NAME                     24: config
        172     IMPORT_FROM                     25: settings_manager
        174     STORE_NAME                      25: settings_manager
        176     POP_TOP                         
        178     LOAD_CONST                      3: 0
        180     LOAD_CONST                      10: ('response_check_and_refine', 'split_pred_to_var_arg', 'parse_model_response_json', 'parse_model_response_str', 'get_func_args', 'get_func_args_vars')
        182     IMPORT_NAME                     26: checker
        184     IMPORT_FROM                     27: response_check_and_refine
        186     STORE_NAME                      27: response_check_and_refine
        188     IMPORT_FROM                     28: split_pred_to_var_arg
        190     STORE_NAME                      28: split_pred_to_var_arg
        192     IMPORT_FROM                     29: parse_model_response_json
        194     STORE_NAME                      29: parse_model_response_json
        196     IMPORT_FROM                     30: parse_model_response_str
        198     STORE_NAME                      30: parse_model_response_str
        200     IMPORT_FROM                     31: get_func_args
        202     STORE_NAME                      31: get_func_args
        204     IMPORT_FROM                     32: get_func_args_vars
        206     STORE_NAME                      32: get_func_args_vars
        208     POP_TOP                         
        210     LOAD_CONST                      3: 0
        212     LOAD_CONST                      11: ('send_feedback',)
        214     IMPORT_NAME                     33: feedback
        216     IMPORT_FROM                     34: send_feedback
        218     STORE_NAME                      34: send_feedback
        220     POP_TOP                         
        222     PUSH_NULL                       
        224     LOAD_NAME                       12: OpenAIModel
        226     CALL                            0
        234     STORE_NAME                      35: model
        236     LOAD_CONST                      12: ()
        238     LOAD_NAME                       1: ida_kernwin
        240     LOAD_ATTR                       72: MFF_WRITE
        260     BUILD_TUPLE                     2
        262     LOAD_CONST                      13: <CODE> ida_execute
        264     MAKE_FUNCTION                   1
        266     STORE_NAME                      37: ida_execute
        268     LOAD_CONST                      14: <CODE> func_analysis
        270     MAKE_FUNCTION                   0
        272     STORE_NAME                      38: func_analysis
        274     LOAD_CONST                      15: <CODE> decompilation
        276     MAKE_FUNCTION                   0
        278     STORE_NAME                      39: decompilation
        280     LOAD_CONST                      16: <CODE> specific_vars_analysis
        282     MAKE_FUNCTION                   0
        284     STORE_NAME                      40: specific_vars_analysis
        286     LOAD_CONST                      17: <CODE> all_vars_analysis
        288     MAKE_FUNCTION                   0
        290     STORE_NAME                      41: all_vars_analysis
        292     LOAD_CONST                      18: <CODE> all_args_analysis
        294     MAKE_FUNCTION                   0
        296     STORE_NAME                      42: all_args_analysis
        298     LOAD_CONST                      19: <CODE> func_name_analysis
        300     MAKE_FUNCTION                   0
        302     STORE_NAME                      43: func_name_analysis
        304     LOAD_CONST                      20: <CODE> summary_analysis
        306     MAKE_FUNCTION                   0
        308     STORE_NAME                      44: summary_analysis
        310     LOAD_CONST                      21: <CODE> func_analysis_mock
        312     MAKE_FUNCTION                   0
        314     STORE_NAME                      45: func_analysis_mock
        316     LOAD_CONST                      22: <CODE> decompilation_mock
        318     MAKE_FUNCTION                   0
        320     STORE_NAME                      46: decompilation_mock
        322     LOAD_CONST                      23: <CODE> specific_vars_analysis_mock
        324     MAKE_FUNCTION                   0
        326     STORE_NAME                      47: specific_vars_analysis_mock
        328     LOAD_CONST                      24: <CODE> all_vars_analysis_mock
        330     MAKE_FUNCTION                   0
        332     STORE_NAME                      48: all_vars_analysis_mock
        334     LOAD_CONST                      25: <CODE> all_args_analysis_mock
        336     MAKE_FUNCTION                   0
        338     STORE_NAME                      49: all_args_analysis_mock
        340     PUSH_NULL                       
        342     LOAD_BUILD_CLASS                
        344     LOAD_CONST                      26: <CODE> FuncAnalysisHandler
        346     MAKE_FUNCTION                   0
        348     LOAD_CONST                      27: 'FuncAnalysisHandler'
        350     LOAD_NAME                       1: ida_kernwin
        352     LOAD_ATTR                       100: action_handler_t
        372     CALL                            3
        380     STORE_NAME                      51: FuncAnalysisHandler
        382     PUSH_NULL                       
        384     LOAD_BUILD_CLASS                
        386     LOAD_CONST                      28: <CODE> DecompilationHandler
        388     MAKE_FUNCTION                   0
        390     LOAD_CONST                      29: 'DecompilationHandler'
        392     LOAD_NAME                       1: ida_kernwin
        394     LOAD_ATTR                       100: action_handler_t
        414     CALL                            3
        422     STORE_NAME                      52: DecompilationHandler
        424     PUSH_NULL                       
        426     LOAD_BUILD_CLASS                
        428     LOAD_CONST                      30: <CODE> SpecificVariableAnalysisHandler
        430     MAKE_FUNCTION                   0
        432     LOAD_CONST                      31: 'SpecificVariableAnalysisHandler'
        434     LOAD_NAME                       1: ida_kernwin
        436     LOAD_ATTR                       100: action_handler_t
        456     CALL                            3
        464     STORE_NAME                      53: SpecificVariableAnalysisHandler
        466     PUSH_NULL                       
        468     LOAD_BUILD_CLASS                
        470     LOAD_CONST                      32: <CODE> AllVariableAnalysisHandler
        472     MAKE_FUNCTION                   0
        474     LOAD_CONST                      33: 'AllVariableAnalysisHandler'
        476     LOAD_NAME                       1: ida_kernwin
        478     LOAD_ATTR                       100: action_handler_t
        498     CALL                            3
        506     STORE_NAME                      54: AllVariableAnalysisHandler
        508     PUSH_NULL                       
        510     LOAD_BUILD_CLASS                
        512     LOAD_CONST                      34: <CODE> AllArgumentAnalysisHandler
        514     MAKE_FUNCTION                   0
        516     LOAD_CONST                      35: 'AllArgumentAnalysisHandler'
        518     LOAD_NAME                       1: ida_kernwin
        520     LOAD_ATTR                       100: action_handler_t
        540     CALL                            3
        548     STORE_NAME                      55: AllArgumentAnalysisHandler
        550     PUSH_NULL                       
        552     LOAD_BUILD_CLASS                
        554     LOAD_CONST                      36: <CODE> FuncNameAnalysisHandler
        556     MAKE_FUNCTION                   0
        558     LOAD_CONST                      37: 'FuncNameAnalysisHandler'
        560     LOAD_NAME                       1: ida_kernwin
        562     LOAD_ATTR                       100: action_handler_t
        582     CALL                            3
        590     STORE_NAME                      56: FuncNameAnalysisHandler
        592     PUSH_NULL                       
        594     LOAD_BUILD_CLASS                
        596     LOAD_CONST                      38: <CODE> SummaryAnalysisHandler
        598     MAKE_FUNCTION                   0
        600     LOAD_CONST                      39: 'SummaryAnalysisHandler'
        602     LOAD_NAME                       1: ida_kernwin
        604     LOAD_ATTR                       100: action_handler_t
        624     CALL                            3
        632     STORE_NAME                      57: SummaryAnalysisHandler
        634     PUSH_NULL                       
        636     LOAD_BUILD_CLASS                
        638     LOAD_CONST                      40: <CODE> ReCopilotSettingsHandler
        640     MAKE_FUNCTION                   0
        642     LOAD_CONST                      41: 'ReCopilotSettingsHandler'
        644     LOAD_NAME                       1: ida_kernwin
        646     LOAD_ATTR                       100: action_handler_t
        666     CALL                            3
        674     STORE_NAME                      58: ReCopilotSettingsHandler
        676     LOAD_CONST                      4: None
        678     NOP                             
        680     NOP                             
        682     NOP                             
        684     JUMP_FORWARD                    19 (to 724)
        692     POP_TOP                         
        694     RETURN_CONST                    4: None
        696     PUSH_EXC_INFO                   
        698     PUSH_NULL                       
        700     LOAD_CONST                      42: '__pyarmor_exit_54987__'
        702     NOP                             
        704     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a\x9e\x02\x00\x00\x00\x00\x00\x00'
        706     CALL                            1
        714     POP_TOP                         
        716     RERAISE                         0
        718     COPY                            3
        720     POP_EXCEPT                      
        722     RERAISE                         1
        724     PUSH_NULL                       
        726     LOAD_CONST                      42: '__pyarmor_exit_54987__'
        728     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a\x9e\x02\x00\x00\x00\x00\x00\x00'
        730     BUILD_TUPLE                     1
        732     CALL_FUNCTION_EX                0
        734     POP_TOP                         
        736     RETURN_VALUE                    
