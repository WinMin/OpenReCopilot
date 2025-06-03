ext_info.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..ext_info>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 5
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        'os'
        're'
        'idc'
        'json'
        'hashlib'
        'idaapi'
        'ida_ua'
        'ida_idp'
        'ida_name'
        'idautils'
        'ida_nalt'
        'ida_auto'
        'ida_funcs'
        'ida_xref'
        'ida_kernwin'
        'ida_typeinf'
        'ida_segment'
        'ida_hexrays'
        'collections'
        'defaultdict'
        'decompile'
        'DecompilationFailure'
        'data_flow'
        'DataFlowAnalyzer'
        'config'
        'settings_manager'
        'checker'
        'parse_var_pred'
        'task_guides'
        'TASK_GUIDES'
        'settings'
        'MAX_TRACE_CALLER_DEPTH'
        'MAX_TRACE_CALLEE_DEPTH'
        'MAX_CONTEXT_FUNC_NUM'
        'MEASURE_INFO_SCORE'
        'set'
        'keys'
        'SUPPORT_FUNC_TYPES'
        'DATA_FLOW_TEMPLATE'
        'INPUT_TEMPLATE'
        'dict'
        'IMPORT_FUNCS'
        'collect_import_funcs'
        'is_thunk'
        'is_thunk_func'
        'is_import_name'
        'get_import_name_info'
        'demangle'
        'str'
        'get_pcode_md5'
        'int'
        'get_struc'
        'get_enum'
        'list_enum_members'
        'StructUnroller'
        'get_structs_enums'
        'get_callee_name'
        'get_var_info'
        'get_local_vars'
        'get_args'
        'omit_too_long_pcode'
        'build_pcode_with_struct_and_enum'
        'measure_informative_score_strings'
        'measure_informative_score_callees'
        '_real_measure_informative_score'
        'measure_informative_score'
        'ContextBuilder'
        'get_numbers_from_pcode'
        'get_functions_in_text_like_seg'
        'MEANINGLESS_NAME_LIST'
        'is_good_func_for_build_input'
        'build_prompt'
        'apply_prediction_ret_type'
        'apply_prediction_func_name'
        'add_array_type'
        'add_enum_type'
        'add_empty_struct_type'
        'add_struct_type'
        'list'
        'apply_prediction_arg'
        'apply_prediction_args_old'
        'apply_prediction_vars'
        'build_doxygen_comment'
        'apply_prediction_func_comment'
        'apply_prediction_inline_comment'
        'bool'
        'apply_prediction'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_55129__'
        '__pyarmor_enter_55130__'
        b'<COAddr>\x01\x00\x00\x1a\x08\x03\x00\x00\x00\x00\x00\x00'
        0
        None
        (
            'defaultdict'
        )
        (
            'decompile'
            'DecompilationFailure'
        )
        (
            'DataFlowAnalyzer'
        )
        (
            'settings_manager'
        )
        (
            'parse_var_pred'
        )
        (
            'TASK_GUIDES'
        )
        'max_trace_caller_depth'
        'max_trace_callee_depth'
        'max_context_func_num'
        'measure_info_score'
        '<Data-Flow>\nTips: the alias expressions below are used to present the relationship between the local variable and the variable in target function. And the left value of `==` is the local variable and type, the right value is the usage pattern of the variable in target function.\n{}\n</Data-Flow>'
        '<context-pseudocode>\n{context}\n</context-pseudocode>\n<pseudocode>\n{target_func}\n</pseudocode>\n<Call-Chains>\n{call_chains}\n</Call-Chains>\n{data_flow}\nAnalysis Task Tag:\n{task_tag}'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: collect_import_funcs
            Qualified Name: collect_import_funcs
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'idaapi'
                'get_import_module_qty'
                'range'
                'get_import_module_name'
                'print'
                'dict'
                'enum_import_names'
                'IMPORT_FUNCS'
                'update'
            [Locals+Names]
                '__assert_armored__'
                '_var_var_2'
                '_var_var_3'
                '_var_var_4'
                '_var_var_0'
                '_var_var_1'
            [Constants]
                None
                '__pyarmor_assert_55132__'
                '__pyarmor_enter_55133__'
                b'<COAddr>\x01\x00\x00\x1e"\x01\x00\x00\x00\x00\x00\x00'
                '[!] Err: fail to get import module '
                ' name'
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: imp_cb
                    Qualified Name: collect_import_funcs.<locals>.imp_cb
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'update'
                    [Locals+Names]
                        'ea'
                        'name'
                        '_ord'
                        '__assert_armored__'
                        '_var_var_0'
                        '_var_var_1'
                    [Constants]
                        None
                        '__pyarmor_assert_55135__'
                        '__pyarmor_enter_55136__'
                        b'<COAddr>\x01\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55137__'
                        True
                    [Disassembly]
                        0       COPY_FREE_VARS                  2
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_55136__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
                        12      BUILD_TUPLE                     1
                        14      CALL_FUNCTION_EX                0
                        16      POP_TOP                         
                        18      RESUME                          0
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      LOAD_FAST                       1: name
                        32      POP_JUMP_IF_FALSE               21 (to 76)
                        34      LOAD_DEREF                      4: _var_var_0
                        36      LOAD_ATTR                       1: update
                        56      LOAD_FAST                       0: ea
                        58      LOAD_FAST                       1: name
                        60      LOAD_DEREF                      5: _var_var_1
                        62      BUILD_LIST                      2
                        64      BUILD_MAP                       1
                        66      CALL                            1
                        74      POP_TOP                         
                        76      LOAD_CONST                      5: True
                        78      NOP                             
                        80      NOP                             
                        82      NOP                             
                        84      JUMP_FORWARD                    19 (to 124)
                        92      POP_TOP                         
                        94      RETURN_CONST                    5: True
                        96      PUSH_EXC_INFO                   
                        98      PUSH_NULL                       
                        100     LOAD_CONST                      4: '__pyarmor_exit_55137__'
                        102     NOP                             
                        104     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
                        106     CALL                            1
                        114     POP_TOP                         
                        116     RERAISE                         0
                        118     COPY                            3
                        120     POP_EXCEPT                      
                        122     RERAISE                         1
                        124     PUSH_NULL                       
                        126     LOAD_CONST                      4: '__pyarmor_exit_55137__'
                        128     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
                        130     BUILD_TUPLE                     1
                        132     CALL_FUNCTION_EX                0
                        134     POP_TOP                         
                        136     RETURN_VALUE                    
                '__pyarmor_exit_55134__'
                True
            [Disassembly]
                0       MAKE_CELL                       4: _var_var_0
                2       MAKE_CELL                       5: _var_var_1
                4       NOP                             
                6       NOP                             
                8       PUSH_NULL                       
                10      LOAD_CONST                      2: '__pyarmor_enter_55133__'
                12      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e"\x01\x00\x00\x00\x00\x00\x00'
                14      BUILD_TUPLE                     1
                16      CALL_FUNCTION_EX                0
                18      POP_TOP                         
                20      RESUME                          0
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      LOAD_GLOBAL                     1: NULL + idaapi
                42      LOAD_ATTR                       2: get_import_module_qty
                62      CALL                            0
                70      STORE_FAST                      1: _var_var_2
                72      LOAD_GLOBAL                     5: NULL + range
                82      LOAD_FAST                       1: _var_var_2
                84      CALL                            1
                92      GET_ITER                        
                94      FOR_ITER                        100 (to 296)
                98      STORE_FAST                      2: _var_var_3
                100     LOAD_GLOBAL                     1: NULL + idaapi
                110     LOAD_ATTR                       6: get_import_module_name
                130     LOAD_FAST                       2: _var_var_3
                132     CALL                            1
                140     STORE_DEREF                     5: _var_var_1
                142     LOAD_DEREF                      5: _var_var_1
                144     POP_JUMP_IF_TRUE                16 (to 178)
                146     LOAD_GLOBAL                     9: NULL + print
                156     LOAD_CONST                      4: '[!] Err: fail to get import module '
                158     LOAD_FAST                       2: _var_var_3
                160     FORMAT_VALUE                    0 (FVC_NONE)
                162     LOAD_CONST                      5: ' name'
                164     BUILD_STRING                    3
                166     CALL                            1
                174     POP_TOP                         
                176     JUMP_BACKWARD                   42 (to 94)
                178     LOAD_GLOBAL                     11: NULL + dict
                188     CALL                            0
                196     STORE_DEREF                     4: _var_var_0
                198     LOAD_CLOSURE                    4: _var_var_0
                200     LOAD_CLOSURE                    5: _var_var_1
                202     BUILD_TUPLE                     2
                204     LOAD_CONST                      6: <CODE> imp_cb
                206     MAKE_FUNCTION                   8
                208     STORE_FAST                      3: _var_var_4
                210     LOAD_GLOBAL                     1: NULL + idaapi
                220     LOAD_ATTR                       12: enum_import_names
                240     LOAD_FAST                       2: _var_var_3
                242     LOAD_FAST                       3: _var_var_4
                244     CALL                            2
                252     POP_TOP                         
                254     LOAD_GLOBAL                     14: IMPORT_FUNCS
                264     LOAD_ATTR                       17: update
                284     LOAD_DEREF                      4: _var_var_0
                286     CALL                            1
                294     POP_TOP                         
                296     JUMP_BACKWARD                   102 (to 94)
                298     END_FOR                         
                300     LOAD_CONST                      8: True
                302     NOP                             
                304     NOP                             
                306     NOP                             
                308     JUMP_FORWARD                    19 (to 348)
                316     POP_TOP                         
                318     RETURN_CONST                    8: True
                320     PUSH_EXC_INFO                   
                322     PUSH_NULL                       
                324     LOAD_CONST                      7: '__pyarmor_exit_55134__'
                326     NOP                             
                328     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e"\x01\x00\x00\x00\x00\x00\x00'
                330     CALL                            1
                338     POP_TOP                         
                340     RERAISE                         0
                342     COPY                            3
                344     POP_EXCEPT                      
                346     RERAISE                         1
                348     PUSH_NULL                       
                350     LOAD_CONST                      7: '__pyarmor_exit_55134__'
                352     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e"\x01\x00\x00\x00\x00\x00\x00'
                354     BUILD_TUPLE                     1
                356     CALL_FUNCTION_EX                0
                358     POP_TOP                         
                360     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: is_thunk
            Qualified Name: is_thunk
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'idc'
                'get_func_flags'
                'ida_funcs'
                'FUNC_THUNK'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_5'
            [Constants]
                None
                '__pyarmor_assert_55138__'
                '__pyarmor_enter_55139__'
                b'<COAddr>\x03\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_55140__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55139__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
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
                38      LOAD_ATTR                       2: get_func_flags
                58      LOAD_FAST                       0: ea
                60      CALL                            1
                68      STORE_FAST                      2: _var_var_5
                70      LOAD_CONST                      4: 0
                72      LOAD_FAST                       2: _var_var_5
                74      COMPARE_OP                      2 (<)
                78      COPY                            1
                80      POP_JUMP_IF_FALSE               22 (to 126)
                82      POP_TOP                         
                84      LOAD_CONST                      4: 0
                86      LOAD_FAST                       2: _var_var_5
                88      LOAD_GLOBAL                     4: ida_funcs
                98      LOAD_ATTR                       6: FUNC_THUNK
                118     BINARY_OP                       1 (&)
                122     COMPARE_OP                      55 (!=)
                126     NOP                             
                128     NOP                             
                130     NOP                             
                132     JUMP_FORWARD                    20 (to 174)
                134     CALL                            1
                142     POP_TOP                         
                144     RETURN_VALUE                    
                146     PUSH_EXC_INFO                   
                148     PUSH_NULL                       
                150     LOAD_CONST                      5: '__pyarmor_exit_55140__'
                152     NOP                             
                154     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                156     CALL                            1
                164     POP_TOP                         
                166     RERAISE                         0
                168     COPY                            3
                170     POP_EXCEPT                      
                172     RERAISE                         1
                174     PUSH_NULL                       
                176     LOAD_CONST                      5: '__pyarmor_exit_55140__'
                178     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                180     BUILD_TUPLE                     1
                182     CALL_FUNCTION_EX                0
                184     POP_TOP                         
                186     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: is_thunk_func
            Qualified Name: is_thunk_func
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'flags'
                'ida_funcs'
                'FUNC_THUNK'
            [Locals+Names]
                'func'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_55141__'
                '__pyarmor_enter_55142__'
                b'<COAddr>\x03\x00\x00\x1av\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_55143__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55142__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1av\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: 0
                30      LOAD_FAST                       0: func
                32      LOAD_ATTR                       0: flags
                52      COMPARE_OP                      2 (<)
                56      COPY                            1
                58      POP_JUMP_IF_FALSE               32 (to 124)
                60      POP_TOP                         
                62      LOAD_CONST                      4: 0
                64      LOAD_FAST                       0: func
                66      LOAD_ATTR                       0: flags
                86      LOAD_GLOBAL                     2: ida_funcs
                96      LOAD_ATTR                       4: FUNC_THUNK
                116     BINARY_OP                       1 (&)
                120     COMPARE_OP                      55 (!=)
                124     NOP                             
                126     NOP                             
                128     NOP                             
                130     JUMP_FORWARD                    20 (to 172)
                132     CALL                            1
                140     POP_TOP                         
                142     RETURN_VALUE                    
                144     PUSH_EXC_INFO                   
                146     PUSH_NULL                       
                148     LOAD_CONST                      5: '__pyarmor_exit_55143__'
                150     NOP                             
                152     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1av\x00\x00\x00\x00\x00\x00\x00'
                154     CALL                            1
                162     POP_TOP                         
                164     RERAISE                         0
                166     COPY                            3
                168     POP_EXCEPT                      
                170     RERAISE                         1
                172     PUSH_NULL                       
                174     LOAD_CONST                      5: '__pyarmor_exit_55143__'
                176     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1av\x00\x00\x00\x00\x00\x00\x00'
                178     BUILD_TUPLE                     1
                180     CALL_FUNCTION_EX                0
                182     POP_TOP                         
                184     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: is_import_name
            Qualified Name: is_import_name
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'is_thunk'
                'ida_funcs'
                'calc_thunk_func_target'
                'idaapi'
                'BADADDR'
                'IMPORT_FUNCS'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_6'
            [Constants]
                None
                '__pyarmor_assert_55144__'
                '__pyarmor_enter_55145__'
                b'<COAddr>\x01\x00\x00\x1a\xb0\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_55146__'
                True
                False
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55145__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb0\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: ea
                30      STORE_FAST                      2: _var_var_6
                32      LOAD_GLOBAL                     1: NULL + is_thunk
                42      LOAD_FAST                       0: ea
                44      CALL                            1
                52      POP_JUMP_IF_FALSE               45 (to 144)
                54      LOAD_GLOBAL                     3: NULL + ida_funcs
                64      LOAD_ATTR                       4: calc_thunk_func_target
                84      LOAD_FAST                       0: ea
                86      CALL                            1
                94      LOAD_CONST                      4: 0
                96      BINARY_SUBSCR                   
                100     STORE_FAST                      2: _var_var_6
                102     LOAD_FAST                       2: _var_var_6
                104     LOAD_GLOBAL                     6: idaapi
                114     LOAD_ATTR                       8: BADADDR
                134     COMPARE_OP                      40 (==)
                138     POP_JUMP_IF_FALSE               2 (to 144)
                140     LOAD_FAST                       0: ea
                142     STORE_FAST                      2: _var_var_6
                144     LOAD_FAST                       2: _var_var_6
                146     LOAD_GLOBAL                     10: IMPORT_FUNCS
                156     CONTAINS_OP                     0 (in)
                158     POP_JUMP_IF_FALSE               11 (to 182)
                160     NOP                             
                162     LOAD_CONST                      6: True
                164     NOP                             
                166     NOP                             
                168     NOP                             
                170     JUMP_FORWARD                    29 (to 230)
                178     POP_TOP                         
                180     RETURN_CONST                    6: True
                182     LOAD_CONST                      7: False
                184     NOP                             
                186     NOP                             
                188     NOP                             
                190     JUMP_FORWARD                    19 (to 230)
                198     POP_TOP                         
                200     RETURN_CONST                    7: False
                202     PUSH_EXC_INFO                   
                204     PUSH_NULL                       
                206     LOAD_CONST                      5: '__pyarmor_exit_55146__'
                208     NOP                             
                210     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb0\x00\x00\x00\x00\x00\x00\x00'
                212     CALL                            1
                220     POP_TOP                         
                222     RERAISE                         0
                224     COPY                            3
                226     POP_EXCEPT                      
                228     RERAISE                         1
                230     PUSH_NULL                       
                232     LOAD_CONST                      5: '__pyarmor_exit_55146__'
                234     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb0\x00\x00\x00\x00\x00\x00\x00'
                236     BUILD_TUPLE                     1
                238     CALL_FUNCTION_EX                0
                240     POP_TOP                         
                242     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_import_name_info
            Qualified Name: get_import_name_info
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'is_thunk'
                'ida_funcs'
                'calc_thunk_func_target'
                'idaapi'
                'BADADDR'
                'IMPORT_FUNCS'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_6'
            [Constants]
                None
                '__pyarmor_assert_55147__'
                '__pyarmor_enter_55148__'
                b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_55149__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55148__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: ea
                30      STORE_FAST                      2: _var_var_6
                32      LOAD_GLOBAL                     1: NULL + is_thunk
                42      LOAD_FAST                       0: ea
                44      CALL                            1
                52      POP_JUMP_IF_FALSE               45 (to 144)
                54      LOAD_GLOBAL                     3: NULL + ida_funcs
                64      LOAD_ATTR                       4: calc_thunk_func_target
                84      LOAD_FAST                       0: ea
                86      CALL                            1
                94      LOAD_CONST                      4: 0
                96      BINARY_SUBSCR                   
                100     STORE_FAST                      2: _var_var_6
                102     LOAD_FAST                       2: _var_var_6
                104     LOAD_GLOBAL                     6: idaapi
                114     LOAD_ATTR                       8: BADADDR
                134     COMPARE_OP                      40 (==)
                138     POP_JUMP_IF_FALSE               2 (to 144)
                140     LOAD_FAST                       0: ea
                142     STORE_FAST                      2: _var_var_6
                144     LOAD_FAST                       2: _var_var_6
                146     LOAD_GLOBAL                     10: IMPORT_FUNCS
                156     CONTAINS_OP                     0 (in)
                158     POP_JUMP_IF_FALSE               18 (to 196)
                160     LOAD_GLOBAL                     10: IMPORT_FUNCS
                170     LOAD_FAST                       2: _var_var_6
                172     BINARY_SUBSCR                   
                176     NOP                             
                178     NOP                             
                180     NOP                             
                182     JUMP_FORWARD                    30 (to 244)
                184     CALL                            1
                192     POP_TOP                         
                194     RETURN_VALUE                    
                196     LOAD_CONST                      0: None
                198     NOP                             
                200     NOP                             
                202     NOP                             
                204     JUMP_FORWARD                    19 (to 244)
                212     POP_TOP                         
                214     RETURN_CONST                    0: None
                216     PUSH_EXC_INFO                   
                218     PUSH_NULL                       
                220     LOAD_CONST                      5: '__pyarmor_exit_55149__'
                222     NOP                             
                224     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                226     CALL                            1
                234     POP_TOP                         
                236     RERAISE                         0
                238     COPY                            3
                240     POP_EXCEPT                      
                242     RERAISE                         1
                244     PUSH_NULL                       
                246     LOAD_CONST                      5: '__pyarmor_exit_55149__'
                248     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                250     BUILD_TUPLE                     1
                252     CALL_FUNCTION_EX                0
                254     POP_TOP                         
                256     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: demangle
            Qualified Name: demangle
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'idaapi'
                'demangle_name'
                'DQT_FULL'
            [Locals+Names]
                'name'
                'disable_mask'
                '__assert_armored__'
                '_var_var_7'
            [Constants]
                None
                '__pyarmor_assert_55150__'
                '__pyarmor_enter_55151__'
                b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_55152__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55151__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + idaapi
                38      LOAD_ATTR                       2: demangle_name
                58      LOAD_FAST                       0: name
                60      LOAD_FAST                       1: disable_mask
                62      LOAD_GLOBAL                     0: idaapi
                72      LOAD_ATTR                       4: DQT_FULL
                92      CALL                            3
                100     STORE_FAST                      3: _var_var_7
                102     LOAD_FAST                       3: _var_var_7
                104     POP_JUMP_IF_FALSE               11 (to 128)
                106     LOAD_FAST                       3: _var_var_7
                108     NOP                             
                110     NOP                             
                112     NOP                             
                114     JUMP_FORWARD                    31 (to 178)
                116     CALL                            1
                124     POP_TOP                         
                126     RETURN_VALUE                    
                128     LOAD_FAST                       0: name
                130     NOP                             
                132     NOP                             
                134     NOP                             
                136     JUMP_FORWARD                    20 (to 178)
                138     CALL                            1
                146     POP_TOP                         
                148     RETURN_VALUE                    
                150     PUSH_EXC_INFO                   
                152     PUSH_NULL                       
                154     LOAD_CONST                      4: '__pyarmor_exit_55152__'
                156     NOP                             
                158     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                160     CALL                            1
                168     POP_TOP                         
                170     RERAISE                         0
                172     COPY                            3
                174     POP_EXCEPT                      
                176     RERAISE                         1
                178     PUSH_NULL                       
                180     LOAD_CONST                      4: '__pyarmor_exit_55152__'
                182     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                184     BUILD_TUPLE                     1
                186     CALL_FUNCTION_EX                0
                188     POP_TOP                         
                190     RETURN_VALUE                    
        's'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_pcode_md5
            Qualified Name: get_pcode_md5
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'hashlib'
                'md5'
                'encode'
                'hexdigest'
            [Locals+Names]
                's'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_55153__'
                '__pyarmor_enter_55154__'
                b'<COAddr>\x01\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                'utf-8'
                '__pyarmor_exit_55155__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55154__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + hashlib
                38      LOAD_ATTR                       2: md5
                58      LOAD_FAST                       0: s
                60      LOAD_ATTR                       5: encode
                80      LOAD_CONST                      4: 'utf-8'
                82      CALL                            1
                90      CALL                            1
                98      LOAD_ATTR                       7: hexdigest
                118     CALL                            0
                126     NOP                             
                128     NOP                             
                130     NOP                             
                132     JUMP_FORWARD                    20 (to 174)
                134     CALL                            1
                142     POP_TOP                         
                144     RETURN_VALUE                    
                146     PUSH_EXC_INFO                   
                148     PUSH_NULL                       
                150     LOAD_CONST                      5: '__pyarmor_exit_55155__'
                152     NOP                             
                154     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                156     CALL                            1
                164     POP_TOP                         
                166     RERAISE                         0
                168     COPY                            3
                170     POP_EXCEPT                      
                172     RERAISE                         1
                174     PUSH_NULL                       
                176     LOAD_CONST                      5: '__pyarmor_exit_55155__'
                178     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                180     BUILD_TUPLE                     1
                182     CALL_FUNCTION_EX                0
                184     POP_TOP                         
                186     RETURN_VALUE                    
        'struct_tid'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_struc
            Qualified Name: get_struc
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_typeinf'
                'tinfo_t'
                'get_type_by_tid'
                'is_struct'
                'idaapi'
                'BADADDR'
            [Locals+Names]
                'struct_tid'
                '__assert_armored__'
                '_var_var_8'
            [Constants]
                None
                '__pyarmor_assert_55156__'
                '__pyarmor_enter_55157__'
                b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_55158__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55157__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + ida_typeinf
                38      LOAD_ATTR                       2: tinfo_t
                58      CALL                            0
                66      STORE_FAST                      2: _var_var_8
                68      LOAD_FAST                       2: _var_var_8
                70      LOAD_ATTR                       5: get_type_by_tid
                90      LOAD_FAST                       0: struct_tid
                92      CALL                            1
                100     POP_JUMP_IF_FALSE               27 (to 156)
                102     LOAD_FAST                       2: _var_var_8
                104     LOAD_ATTR                       7: is_struct
                124     CALL                            0
                132     POP_JUMP_IF_FALSE               11 (to 156)
                134     LOAD_FAST                       2: _var_var_8
                136     NOP                             
                138     NOP                             
                140     NOP                             
                142     JUMP_FORWARD                    45 (to 234)
                144     CALL                            1
                152     POP_TOP                         
                154     RETURN_VALUE                    
                156     LOAD_GLOBAL                     8: idaapi
                166     LOAD_ATTR                       10: BADADDR
                186     NOP                             
                188     NOP                             
                190     NOP                             
                192     JUMP_FORWARD                    20 (to 234)
                194     CALL                            1
                202     POP_TOP                         
                204     RETURN_VALUE                    
                206     PUSH_EXC_INFO                   
                208     PUSH_NULL                       
                210     LOAD_CONST                      4: '__pyarmor_exit_55158__'
                212     NOP                             
                214     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                216     CALL                            1
                224     POP_TOP                         
                226     RERAISE                         0
                228     COPY                            3
                230     POP_EXCEPT                      
                232     RERAISE                         1
                234     PUSH_NULL                       
                236     LOAD_CONST                      4: '__pyarmor_exit_55158__'
                238     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                240     BUILD_TUPLE                     1
                242     CALL_FUNCTION_EX                0
                244     POP_TOP                         
                246     RETURN_VALUE                    
        'enum_tid'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_enum
            Qualified Name: get_enum
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_typeinf'
                'tinfo_t'
                'get_type_by_tid'
                'is_enum'
                'idaapi'
                'BADADDR'
            [Locals+Names]
                'enum_tid'
                '__assert_armored__'
                '_var_var_8'
            [Constants]
                None
                '__pyarmor_assert_55159__'
                '__pyarmor_enter_55160__'
                b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_55161__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55160__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + ida_typeinf
                38      LOAD_ATTR                       2: tinfo_t
                58      CALL                            0
                66      STORE_FAST                      2: _var_var_8
                68      LOAD_FAST                       2: _var_var_8
                70      LOAD_ATTR                       5: get_type_by_tid
                90      LOAD_FAST                       0: enum_tid
                92      CALL                            1
                100     POP_JUMP_IF_FALSE               27 (to 156)
                102     LOAD_FAST                       2: _var_var_8
                104     LOAD_ATTR                       7: is_enum
                124     CALL                            0
                132     POP_JUMP_IF_FALSE               11 (to 156)
                134     LOAD_FAST                       2: _var_var_8
                136     NOP                             
                138     NOP                             
                140     NOP                             
                142     JUMP_FORWARD                    45 (to 234)
                144     CALL                            1
                152     POP_TOP                         
                154     RETURN_VALUE                    
                156     LOAD_GLOBAL                     8: idaapi
                166     LOAD_ATTR                       10: BADADDR
                186     NOP                             
                188     NOP                             
                190     NOP                             
                192     JUMP_FORWARD                    20 (to 234)
                194     CALL                            1
                202     POP_TOP                         
                204     RETURN_VALUE                    
                206     PUSH_EXC_INFO                   
                208     PUSH_NULL                       
                210     LOAD_CONST                      4: '__pyarmor_exit_55161__'
                212     NOP                             
                214     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                216     CALL                            1
                224     POP_TOP                         
                226     RERAISE                         0
                228     COPY                            3
                230     POP_EXCEPT                      
                232     RERAISE                         1
                234     PUSH_NULL                       
                236     LOAD_CONST                      4: '__pyarmor_exit_55161__'
                238     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x00\x00\x00\x00\x00\x00\x00'
                240     BUILD_TUPLE                     1
                242     CALL_FUNCTION_EX                0
                244     POP_TOP                         
                246     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: list_enum_members
            Qualified Name: list_enum_members
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_typeinf'
                'get_idati'
                'tinfo_t'
                'get_named_type'
                'BTF_ENUM'
                'get_size'
                'hex'
                'enum_type_data_t'
                'get_enum_details'
                'is_bf'
                'enumerate'
                'get_type_by_tid'
                'get_tid'
                'name'
                'value'
            [Locals+Names]
                'name'
                '__assert_armored__'
                '_var_var_9'
                '_var_var_10'
                '_var_var_8'
                '_var_var_11'
                '_var_var_12'
                '_var_var_13'
                '_var_var_14'
                '_var_var_15'
                '_var_var_16'
                '_var_var_17'
            [Constants]
                None
                '__pyarmor_assert_55162__'
                '__pyarmor_enter_55163__'
                b'<COAddr>\x01\x00\x00\x1a\x82\x02\x00\x00\x00\x00\x00\x00'
                'enum '
                ' {\n'
                True
                False
                '??\n}'
                ' // sizeof='
                '\n{\n'
                ''
                '(bitfield)'
                '?'
                '    '
                ' = '
                ',\n'
                '}'
                '__pyarmor_exit_55164__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55163__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x82\x02\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: 'enum '
                30      LOAD_FAST                       0: name
                32      FORMAT_VALUE                    0 (FVC_NONE)
                34      LOAD_CONST                      5: ' {\n'
                36      BUILD_STRING                    3
                38      STORE_FAST                      2: _var_var_9
                40      LOAD_GLOBAL                     1: NULL + ida_typeinf
                50      LOAD_ATTR                       2: get_idati
                70      CALL                            0
                78      STORE_FAST                      3: _var_var_10
                80      LOAD_GLOBAL                     1: NULL + ida_typeinf
                90      LOAD_ATTR                       4: tinfo_t
                110     CALL                            0
                118     STORE_FAST                      4: _var_var_8
                120     LOAD_FAST                       4: _var_var_8
                122     LOAD_ATTR                       7: get_named_type
                142     LOAD_FAST                       3: _var_var_10
                144     LOAD_FAST                       0: name
                146     LOAD_GLOBAL                     0: ida_typeinf
                156     LOAD_ATTR                       8: BTF_ENUM
                176     LOAD_CONST                      6: True
                178     LOAD_CONST                      7: False
                180     CALL                            5
                188     POP_JUMP_IF_TRUE                6 (to 202)
                190     LOAD_FAST                       2: _var_var_9
                192     LOAD_CONST                      8: '??\n}'
                194     BINARY_OP                       13 (+=)
                198     STORE_FAST                      2: _var_var_9
                200     JUMP_FORWARD                    222 (to 646)
                202     LOAD_FAST                       4: _var_var_8
                204     LOAD_ATTR                       11: get_size
                224     CALL                            0
                232     STORE_FAST                      5: _var_var_11
                234     LOAD_CONST                      4: 'enum '
                236     LOAD_FAST                       0: name
                238     FORMAT_VALUE                    0 (FVC_NONE)
                240     LOAD_CONST                      9: ' // sizeof='
                242     LOAD_GLOBAL                     13: NULL + hex
                252     LOAD_FAST                       5: _var_var_11
                254     CALL                            1
                262     FORMAT_VALUE                    0 (FVC_NONE)
                264     LOAD_CONST                      10: '\n{\n'
                266     BUILD_STRING                    5
                268     STORE_FAST                      2: _var_var_9
                270     LOAD_GLOBAL                     1: NULL + ida_typeinf
                280     LOAD_ATTR                       14: enum_type_data_t
                300     CALL                            0
                308     STORE_FAST                      6: _var_var_12
                310     LOAD_FAST                       4: _var_var_8
                312     LOAD_ATTR                       17: get_enum_details
                332     LOAD_FAST                       6: _var_var_12
                334     CALL                            1
                342     POP_JUMP_IF_FALSE               146 (to 636)
                344     LOAD_CONST                      11: ''
                346     STORE_FAST                      7: _var_var_13
                348     LOAD_FAST                       6: _var_var_12
                350     LOAD_ATTR                       19: is_bf
                370     CALL                            0
                378     POP_JUMP_IF_FALSE               2 (to 384)
                380     LOAD_CONST                      12: '(bitfield)'
                382     STORE_FAST                      7: _var_var_13
                384     LOAD_GLOBAL                     21: NULL + enumerate
                394     LOAD_FAST                       6: _var_var_12
                396     CALL                            1
                404     GET_ITER                        
                406     FOR_ITER                        106 (to 620)
                410     UNPACK_SEQUENCE                 2
                414     STORE_FAST                      8: _var_var_14
                416     STORE_FAST                      9: _var_var_15
                418     LOAD_GLOBAL                     1: NULL + ida_typeinf
                428     LOAD_ATTR                       4: tinfo_t
                448     CALL                            0
                456     STORE_FAST                      10: _var_var_16
                458     LOAD_CONST                      13: '?'
                460     STORE_FAST                      11: _var_var_17
                462     LOAD_FAST                       10: _var_var_16
                464     LOAD_ATTR                       23: get_type_by_tid
                484     LOAD_FAST                       9: _var_var_15
                486     LOAD_ATTR                       25: get_tid
                506     CALL                            0
                514     CALL                            1
                522     POP_JUMP_IF_FALSE               16 (to 556)
                524     LOAD_FAST                       10: _var_var_16
                526     LOAD_ATTR                       11: get_size
                546     CALL                            0
                554     STORE_FAST                      11: _var_var_17
                556     LOAD_FAST                       2: _var_var_9
                558     LOAD_CONST                      14: '    '
                560     LOAD_FAST                       9: _var_var_15
                562     LOAD_ATTR                       26: name
                582     FORMAT_VALUE                    0 (FVC_NONE)
                584     LOAD_CONST                      15: ' = '
                586     LOAD_FAST                       9: _var_var_15
                588     LOAD_ATTR                       28: value
                608     FORMAT_VALUE                    0 (FVC_NONE)
                610     LOAD_CONST                      16: ',\n'
                612     BUILD_STRING                    5
                614     BINARY_OP                       13 (+=)
                618     STORE_FAST                      2: _var_var_9
                620     JUMP_BACKWARD                   108 (to 406)
                622     END_FOR                         
                624     LOAD_FAST                       2: _var_var_9
                626     LOAD_CONST                      17: '}'
                628     BINARY_OP                       13 (+=)
                632     STORE_FAST                      2: _var_var_9
                634     JUMP_FORWARD                    5 (to 646)
                636     LOAD_FAST                       2: _var_var_9
                638     LOAD_CONST                      8: '??\n}'
                640     BINARY_OP                       13 (+=)
                644     STORE_FAST                      2: _var_var_9
                646     LOAD_FAST                       2: _var_var_9
                648     NOP                             
                650     NOP                             
                652     NOP                             
                654     JUMP_FORWARD                    20 (to 696)
                656     CALL                            1
                664     POP_TOP                         
                666     RETURN_VALUE                    
                668     PUSH_EXC_INFO                   
                670     PUSH_NULL                       
                672     LOAD_CONST                      18: '__pyarmor_exit_55164__'
                674     NOP                             
                676     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x82\x02\x00\x00\x00\x00\x00\x00'
                678     CALL                            1
                686     POP_TOP                         
                688     RERAISE                         0
                690     COPY                            3
                692     POP_EXCEPT                      
                694     RERAISE                         1
                696     PUSH_NULL                       
                698     LOAD_CONST                      18: '__pyarmor_exit_55164__'
                700     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x82\x02\x00\x00\x00\x00\x00\x00'
                702     BUILD_TUPLE                     1
                704     CALL_FUNCTION_EX                0
                706     POP_TOP                         
                708     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: StructUnroller
            Qualified Name: StructUnroller
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
                'get_member'
                'unroll_struct_type'
            [Locals+Names]
            [Constants]
                'StructUnroller'
                '__pyarmor_assert_55165__'
                '__pyarmor_enter_55166__'
                b'<COAddr>\x03\x00\x00",\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: __init__
                    Qualified Name: StructUnroller.__init__
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'structs'
                        'structs_size'
                        'MAX_DEPTH'
                    [Locals+Names]
                        'self'
                        'max_depth'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55168__'
                        '__pyarmor_enter_55169__'
                        b'<COAddr>\x01\x00\x00\x1a@\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55170__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55169__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a@\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      BUILD_MAP                       0
                        30      LOAD_FAST                       0: self
                        32      STORE_ATTR                      0: structs
                        42      BUILD_MAP                       0
                        44      LOAD_FAST                       0: self
                        46      STORE_ATTR                      1: structs_size
                        56      LOAD_FAST                       1: max_depth
                        58      LOAD_FAST                       0: self
                        60      STORE_ATTR                      2: MAX_DEPTH
                        70      LOAD_CONST                      0: None
                        72      NOP                             
                        74      NOP                             
                        76      NOP                             
                        78      JUMP_FORWARD                    19 (to 118)
                        86      POP_TOP                         
                        88      RETURN_CONST                    0: None
                        90      PUSH_EXC_INFO                   
                        92      PUSH_NULL                       
                        94      LOAD_CONST                      4: '__pyarmor_exit_55170__'
                        96      NOP                             
                        98      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a@\x00\x00\x00\x00\x00\x00\x00'
                        100     CALL                            1
                        108     POP_TOP                         
                        110     RERAISE                         0
                        112     COPY                            3
                        114     POP_EXCEPT                      
                        116     RERAISE                         1
                        118     PUSH_NULL                       
                        120     LOAD_CONST                      4: '__pyarmor_exit_55170__'
                        122     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a@\x00\x00\x00\x00\x00\x00\x00'
                        124     BUILD_TUPLE                     1
                        126     CALL_FUNCTION_EX                0
                        128     POP_TOP                         
                        130     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: get_member
                    Qualified Name: StructUnroller.get_member
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'is_struct'
                        'ida_typeinf'
                        'udm_t'
                        'offset'
                        'find_udm'
                        'STRMEM_OFFSET'
                    [Locals+Names]
                        'self'
                        'tif'
                        'offset'
                        '__assert_armored__'
                        '_var_var_18'
                        '_var_var_14'
                    [Constants]
                        None
                        '__pyarmor_assert_55171__'
                        '__pyarmor_enter_55172__'
                        b'<COAddr>\x03\x00\x00\x1a\xe8\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55173__'
                        8
                        -1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55172__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xe8\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: tif
                        30      LOAD_ATTR                       1: is_struct
                        50      CALL                            0
                        58      POP_JUMP_IF_TRUE                11 (to 82)
                        60      NOP                             
                        62      LOAD_CONST                      0: None
                        64      NOP                             
                        66      NOP                             
                        68      NOP                             
                        70      JUMP_FORWARD                    107 (to 286)
                        78      POP_TOP                         
                        80      RETURN_CONST                    0: None
                        82      LOAD_GLOBAL                     3: NULL + ida_typeinf
                        92      LOAD_ATTR                       4: udm_t
                        112     CALL                            0
                        120     STORE_FAST                      4: _var_var_18
                        122     LOAD_FAST                       2: offset
                        124     LOAD_CONST                      5: 8
                        126     BINARY_OP                       5 (*)
                        130     LOAD_FAST                       4: _var_var_18
                        132     STORE_ATTR                      3: offset
                        142     LOAD_FAST                       1: tif
                        144     LOAD_ATTR                       9: find_udm
                        164     LOAD_FAST                       4: _var_var_18
                        166     LOAD_GLOBAL                     2: ida_typeinf
                        176     LOAD_ATTR                       10: STRMEM_OFFSET
                        196     CALL                            2
                        204     STORE_FAST                      5: _var_var_14
                        206     LOAD_FAST                       5: _var_var_14
                        208     LOAD_CONST                      6: -1
                        210     COMPARE_OP                      55 (!=)
                        214     POP_JUMP_IF_FALSE               11 (to 238)
                        216     LOAD_FAST                       4: _var_var_18
                        218     NOP                             
                        220     NOP                             
                        222     NOP                             
                        224     JUMP_FORWARD                    30 (to 286)
                        226     CALL                            1
                        234     POP_TOP                         
                        236     RETURN_VALUE                    
                        238     LOAD_CONST                      0: None
                        240     NOP                             
                        242     NOP                             
                        244     NOP                             
                        246     JUMP_FORWARD                    19 (to 286)
                        254     POP_TOP                         
                        256     RETURN_CONST                    0: None
                        258     PUSH_EXC_INFO                   
                        260     PUSH_NULL                       
                        262     LOAD_CONST                      4: '__pyarmor_exit_55173__'
                        264     NOP                             
                        266     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xe8\x00\x00\x00\x00\x00\x00\x00'
                        268     CALL                            1
                        276     POP_TOP                         
                        278     RERAISE                         0
                        280     COPY                            3
                        282     POP_EXCEPT                      
                        284     RERAISE                         1
                        286     PUSH_NULL                       
                        288     LOAD_CONST                      4: '__pyarmor_exit_55173__'
                        290     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xe8\x00\x00\x00\x00\x00\x00\x00'
                        292     BUILD_TUPLE                     1
                        294     CALL_FUNCTION_EX                0
                        296     POP_TOP                         
                        298     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: unroll_struct_type
                    Qualified Name: StructUnroller.unroll_struct_type
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 9
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'MAX_DEPTH'
                        'str'
                        'idc'
                        'get_struc_id'
                        'idaapi'
                        'BADADDR'
                        'is_struct'
                        'structs'
                        'get_size'
                        'structs_size'
                        'hex'
                        'idautils'
                        'StructMembers'
                        'get_member'
                        'type'
                        'copy'
                        'unroll_struct_type'
                        'is_enum'
                        'list_enum_members'
                        'dstr'
                        'is_ptr'
                        'is_const'
                        'remove_ptr_or_array'
                        'clr_const'
                        'join'
                        'split'
                        'append'
                    [Locals+Names]
                        'self'
                        'struct_type'
                        'cur_depth'
                        '__assert_armored__'
                        '_var_var_19'
                        '_var_var_20'
                        '_var_var_21'
                        '_var_var_22'
                        '_var_var_23'
                        '_var_var_24'
                        '_var_var_25'
                        '_var_var_26'
                        '_var_var_27'
                        '_var_var_28'
                        '_var_var_29'
                        '_var_var_30'
                        '_var_var_31'
                        '_var_var_3'
                    [Constants]
                        None
                        '__pyarmor_assert_55174__'
                        '__pyarmor_enter_55175__'
                        b'<COAddr>\x01\x00\x00\x1a.\x06\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55176__'
                        0
                        'struct '
                        ' // sizeof='
                        '\n{\n'
                        1
                        2
                        ''
                        ' *'
                        'const '
                        '\n'
                        '    '
                        ' '
                        '; // sizeof='
                        '}'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55175__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a.\x06\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       2: cur_depth
                        30      LOAD_FAST                       0: self
                        32      LOAD_ATTR                       0: MAX_DEPTH
                        52      COMPARE_OP                      68 (>)
                        56      POP_JUMP_IF_FALSE               20 (to 98)
                        58      LOAD_GLOBAL                     3: NULL + str
                        68      LOAD_FAST                       1: struct_type
                        70      CALL                            1
                        78      NOP                             
                        80      NOP                             
                        82      JUMP_FORWARD                    775 (to 1636)
                        86      CALL                            1
                        94      POP_TOP                         
                        96      RETURN_VALUE                    
                        98      LOAD_GLOBAL                     5: NULL + idc
                        108     LOAD_ATTR                       6: get_struc_id
                        128     LOAD_GLOBAL                     3: NULL + str
                        138     LOAD_FAST                       1: struct_type
                        140     CALL                            1
                        148     CALL                            1
                        156     STORE_FAST                      4: _var_var_19
                        158     LOAD_FAST                       4: _var_var_19
                        160     LOAD_GLOBAL                     8: idaapi
                        170     LOAD_ATTR                       10: BADADDR
                        190     COMPARE_OP                      40 (==)
                        194     POP_JUMP_IF_FALSE               65 (to 326)
                        196     LOAD_FAST                       2: cur_depth
                        198     LOAD_CONST                      5: 0
                        200     COMPARE_OP                      40 (==)
                        204     POP_JUMP_IF_FALSE               40 (to 286)
                        206     LOAD_FAST                       1: struct_type
                        208     LOAD_ATTR                       13: is_struct
                        228     CALL                            0
                        236     POP_JUMP_IF_FALSE               24 (to 286)
                        238     BUILD_LIST                      0
                        240     LOAD_FAST                       0: self
                        242     LOAD_ATTR                       14: structs
                        262     LOAD_GLOBAL                     3: NULL + str
                        272     LOAD_FAST                       1: struct_type
                        274     CALL                            1
                        282     STORE_SUBSCR                    
                        286     LOAD_GLOBAL                     3: NULL + str
                        296     LOAD_FAST                       1: struct_type
                        298     CALL                            1
                        306     NOP                             
                        308     NOP                             
                        310     JUMP_FORWARD                    661 (to 1636)
                        314     CALL                            1
                        322     POP_TOP                         
                        324     RETURN_VALUE                    
                        326     LOAD_GLOBAL                     3: NULL + str
                        336     LOAD_FAST                       1: struct_type
                        338     CALL                            1
                        346     STORE_FAST                      5: _var_var_20
                        348     LOAD_FAST                       1: struct_type
                        350     LOAD_ATTR                       17: get_size
                        370     CALL                            0
                        378     STORE_FAST                      6: _var_var_21
                        380     BUILD_LIST                      0
                        382     LOAD_FAST                       0: self
                        384     LOAD_ATTR                       14: structs
                        404     LOAD_FAST                       5: _var_var_20
                        406     STORE_SUBSCR                    
                        410     LOAD_FAST                       6: _var_var_21
                        412     LOAD_FAST                       0: self
                        414     LOAD_ATTR                       18: structs_size
                        434     LOAD_FAST                       5: _var_var_20
                        436     STORE_SUBSCR                    
                        440     LOAD_CONST                      6: 'struct '
                        442     LOAD_FAST                       5: _var_var_20
                        444     FORMAT_VALUE                    0 (FVC_NONE)
                        446     LOAD_CONST                      7: ' // sizeof='
                        448     LOAD_GLOBAL                     21: NULL + hex
                        458     LOAD_FAST                       6: _var_var_21
                        460     CALL                            1
                        468     FORMAT_VALUE                    0 (FVC_NONE)
                        470     LOAD_CONST                      8: '\n{\n'
                        472     BUILD_STRING                    5
                        474     STORE_FAST                      7: _var_var_22
                        476     LOAD_GLOBAL                     23: NULL + idautils
                        486     LOAD_ATTR                       24: StructMembers
                        506     LOAD_FAST                       4: _var_var_19
                        508     CALL                            1
                        516     GET_ITER                        
                        518     FOR_ITER                        520 (to 1562)
                        524     STORE_FAST                      8: _var_var_23
                        526     LOAD_FAST                       8: _var_var_23
                        528     LOAD_CONST                      5: 0
                        530     BINARY_SUBSCR                   
                        534     STORE_FAST                      9: _var_var_24
                        536     LOAD_FAST                       8: _var_var_23
                        538     LOAD_CONST                      9: 1
                        540     BINARY_SUBSCR                   
                        544     STORE_FAST                      10: _var_var_25
                        546     LOAD_FAST                       8: _var_var_23
                        548     LOAD_CONST                      10: 2
                        550     BINARY_SUBSCR                   
                        554     STORE_FAST                      11: _var_var_26
                        556     LOAD_FAST                       0: self
                        558     LOAD_ATTR                       27: get_member
                        578     LOAD_FAST                       1: struct_type
                        580     LOAD_FAST                       9: _var_var_24
                        582     CALL                            2
                        590     STORE_FAST                      12: _var_var_27
                        592     LOAD_CONST                      11: ''
                        594     STORE_FAST                      13: _var_var_28
                        596     LOAD_CONST                      11: ''
                        598     STORE_FAST                      14: _var_var_29
                        600     LOAD_FAST                       12: _var_var_27
                        602     LOAD_ATTR                       28: type
                        622     LOAD_ATTR                       31: copy
                        642     CALL                            0
                        650     STORE_FAST                      15: _var_var_30
                        652     LOAD_GLOBAL                     3: NULL + str
                        662     LOAD_FAST                       15: _var_var_30
                        664     CALL                            1
                        672     STORE_FAST                      16: _var_var_31
                        674     LOAD_FAST                       15: _var_var_30
                        676     LOAD_ATTR                       13: is_struct
                        696     CALL                            0
                        704     POP_JUMP_IF_FALSE               23 (to 752)
                        706     LOAD_FAST                       0: self
                        708     LOAD_ATTR                       33: unroll_struct_type
                        728     LOAD_FAST                       15: _var_var_30
                        730     LOAD_FAST                       2: cur_depth
                        732     LOAD_CONST                      9: 1
                        734     BINARY_OP                       0 (+)
                        738     CALL                            2
                        746     STORE_FAST                      15: _var_var_30
                        748     JUMP_FORWARD                    291 (to 1334)
                        752     LOAD_FAST                       15: _var_var_30
                        754     LOAD_ATTR                       35: is_enum
                        774     CALL                            0
                        782     POP_JUMP_IF_FALSE               26 (to 836)
                        784     LOAD_GLOBAL                     37: NULL + list_enum_members
                        794     LOAD_FAST                       15: _var_var_30
                        796     LOAD_ATTR                       39: dstr
                        816     CALL                            0
                        824     CALL                            1
                        832     STORE_FAST                      15: _var_var_30
                        834     JUMP_FORWARD                    249 (to 1334)
                        836     LOAD_FAST                       15: _var_var_30
                        838     LOAD_ATTR                       41: is_ptr
                        858     CALL                            0
                        866     POP_JUMP_IF_TRUE                16 (to 900)
                        868     LOAD_FAST                       15: _var_var_30
                        870     LOAD_ATTR                       43: is_const
                        890     CALL                            0
                        898     POP_JUMP_IF_FALSE               206 (to 1312)
                        900     LOAD_FAST                       15: _var_var_30
                        902     LOAD_ATTR                       41: is_ptr
                        922     CALL                            0
                        930     POP_JUMP_IF_FALSE               38 (to 1008)
                        932     LOAD_FAST                       15: _var_var_30
                        934     LOAD_ATTR                       45: remove_ptr_or_array
                        954     CALL                            0
                        962     POP_JUMP_IF_FALSE               22 (to 1008)
                        964     LOAD_FAST                       13: _var_var_28
                        966     LOAD_CONST                      12: ' *'
                        968     BINARY_OP                       13 (+=)
                        972     STORE_FAST                      13: _var_var_28
                        974     LOAD_FAST                       15: _var_var_30
                        976     LOAD_ATTR                       45: remove_ptr_or_array
                        996     CALL                            0
                        1004    POP_JUMP_IF_FALSE               1 (to 1008)
                        1006    JUMP_BACKWARD                   22 (to 964)
                        1008    LOAD_FAST                       15: _var_var_30
                        1010    LOAD_ATTR                       43: is_const
                        1030    CALL                            0
                        1038    POP_JUMP_IF_FALSE               21 (to 1082)
                        1040    LOAD_FAST                       15: _var_var_30
                        1042    LOAD_ATTR                       47: clr_const
                        1062    CALL                            0
                        1070    POP_JUMP_IF_FALSE               5 (to 1082)
                        1072    LOAD_FAST                       14: _var_var_29
                        1074    LOAD_CONST                      13: 'const '
                        1076    BINARY_OP                       13 (+=)
                        1080    STORE_FAST                      14: _var_var_29
                        1082    LOAD_FAST                       15: _var_var_30
                        1084    LOAD_ATTR                       13: is_struct
                        1104    CALL                            0
                        1112    POP_JUMP_IF_FALSE               45 (to 1204)
                        1114    LOAD_GLOBAL                     3: NULL + str
                        1124    LOAD_FAST                       15: _var_var_30
                        1126    CALL                            1
                        1134    LOAD_GLOBAL                     3: NULL + str
                        1144    LOAD_FAST                       1: struct_type
                        1146    CALL                            1
                        1154    COMPARE_OP                      55 (!=)
                        1158    POP_JUMP_IF_FALSE               22 (to 1204)
                        1160    LOAD_FAST                       0: self
                        1162    LOAD_ATTR                       33: unroll_struct_type
                        1182    LOAD_FAST                       15: _var_var_30
                        1184    LOAD_FAST                       2: cur_depth
                        1186    LOAD_CONST                      9: 1
                        1188    BINARY_OP                       0 (+)
                        1192    CALL                            2
                        1200    STORE_FAST                      15: _var_var_30
                        1202    JUMP_FORWARD                    65 (to 1334)
                        1204    LOAD_FAST                       15: _var_var_30
                        1206    LOAD_ATTR                       35: is_enum
                        1226    CALL                            0
                        1234    POP_JUMP_IF_FALSE               26 (to 1288)
                        1236    LOAD_GLOBAL                     37: NULL + list_enum_members
                        1246    LOAD_FAST                       15: _var_var_30
                        1248    LOAD_ATTR                       39: dstr
                        1268    CALL                            0
                        1276    CALL                            1
                        1284    STORE_FAST                      15: _var_var_30
                        1286    JUMP_FORWARD                    23 (to 1334)
                        1288    LOAD_GLOBAL                     3: NULL + str
                        1298    LOAD_FAST                       15: _var_var_30
                        1300    CALL                            1
                        1308    STORE_FAST                      15: _var_var_30
                        1310    JUMP_FORWARD                    11 (to 1334)
                        1312    LOAD_GLOBAL                     3: NULL + str
                        1322    LOAD_FAST                       15: _var_var_30
                        1324    CALL                            1
                        1332    STORE_FAST                      15: _var_var_30
                        1334    LOAD_FAST                       14: _var_var_29
                        1336    LOAD_FAST                       15: _var_var_30
                        1338    BINARY_OP                       0 (+)
                        1342    LOAD_FAST                       13: _var_var_28
                        1344    BINARY_OP                       0 (+)
                        1348    STORE_FAST                      15: _var_var_30
                        1350    LOAD_CONST                      14: '\n'
                        1352    LOAD_ATTR                       49: join
                        1372    LOAD_FAST                       15: _var_var_30
                        1374    LOAD_ATTR                       51: split
                        1394    LOAD_CONST                      14: '\n'
                        1396    CALL                            1
                        1404    GET_ITER                        
                        1406    LOAD_FAST_AND_CLEAR             17: _var_var_3
                        1408    SWAP                            2
                        1410    BUILD_LIST                      0
                        1412    SWAP                            2
                        1414    FOR_ITER                        7 (to 1430)
                        1418    STORE_FAST                      17: _var_var_3
                        1420    LOAD_CONST                      15: '    '
                        1422    LOAD_FAST                       17: _var_var_3
                        1424    BINARY_OP                       0 (+)
                        1428    LIST_APPEND                     2
                        1430    JUMP_BACKWARD                   9 (to 1414)
                        1432    END_FOR                         
                        1434    SWAP                            2
                        1436    STORE_FAST                      17: _var_var_3
                        1438    CALL                            1
                        1446    STORE_FAST                      15: _var_var_30
                        1448    LOAD_FAST                       7: _var_var_22
                        1450    LOAD_FAST                       15: _var_var_30
                        1452    FORMAT_VALUE                    0 (FVC_NONE)
                        1454    LOAD_CONST                      16: ' '
                        1456    LOAD_FAST                       10: _var_var_25
                        1458    FORMAT_VALUE                    0 (FVC_NONE)
                        1460    LOAD_CONST                      17: '; // sizeof='
                        1462    LOAD_GLOBAL                     21: NULL + hex
                        1472    LOAD_FAST                       11: _var_var_26
                        1474    CALL                            1
                        1482    FORMAT_VALUE                    0 (FVC_NONE)
                        1484    LOAD_CONST                      14: '\n'
                        1486    BUILD_STRING                    6
                        1488    BINARY_OP                       13 (+=)
                        1492    STORE_FAST                      7: _var_var_22
                        1494    LOAD_FAST                       0: self
                        1496    LOAD_ATTR                       14: structs
                        1516    LOAD_FAST                       5: _var_var_20
                        1518    BINARY_SUBSCR                   
                        1522    LOAD_ATTR                       53: append
                        1542    LOAD_FAST                       16: _var_var_31
                        1544    LOAD_FAST                       10: _var_var_25
                        1546    LOAD_FAST                       11: _var_var_26
                        1548    BUILD_LIST                      3
                        1550    CALL                            1
                        1558    POP_TOP                         
                        1560    JUMP_BACKWARD                   523 (to 518)
                        1564    END_FOR                         
                        1566    LOAD_FAST                       7: _var_var_22
                        1568    LOAD_CONST                      18: '}'
                        1570    BINARY_OP                       13 (+=)
                        1574    STORE_FAST                      7: _var_var_22
                        1576    LOAD_FAST                       7: _var_var_22
                        1578    NOP                             
                        1580    NOP                             
                        1582    NOP                             
                        1584    JUMP_FORWARD                    25 (to 1636)
                        1586    CALL                            1
                        1594    POP_TOP                         
                        1596    RETURN_VALUE                    
                        1598    SWAP                            2
                        1600    POP_TOP                         
                        1602    SWAP                            2
                        1604    STORE_FAST                      17: _var_var_3
                        1606    RERAISE                         0
                        1608    PUSH_EXC_INFO                   
                        1610    PUSH_NULL                       
                        1612    LOAD_CONST                      4: '__pyarmor_exit_55176__'
                        1614    NOP                             
                        1616    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a.\x06\x00\x00\x00\x00\x00\x00'
                        1618    CALL                            1
                        1626    POP_TOP                         
                        1628    RERAISE                         0
                        1630    COPY                            3
                        1632    POP_EXCEPT                      
                        1634    RERAISE                         1
                        1636    PUSH_NULL                       
                        1638    LOAD_CONST                      4: '__pyarmor_exit_55176__'
                        1640    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a.\x06\x00\x00\x00\x00\x00\x00'
                        1642    BUILD_TUPLE                     1
                        1644    CALL_FUNCTION_EX                0
                        1646    POP_TOP                         
                        1648    RETURN_VALUE                    
                '__pyarmor_exit_55167__'
                None
                (
                    3
                )
                (
                    0
                )
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'StructUnroller'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_55166__'
                16      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00",\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      9: (3,)
                38      LOAD_CONST                      4: <CODE> __init__
                40      MAKE_FUNCTION                   1
                42      STORE_NAME                      4: __init__
                44      LOAD_CONST                      5: <CODE> get_member
                46      MAKE_FUNCTION                   0
                48      STORE_NAME                      5: get_member
                50      LOAD_CONST                      10: (0,)
                52      LOAD_CONST                      6: <CODE> unroll_struct_type
                54      MAKE_FUNCTION                   1
                56      STORE_NAME                      6: unroll_struct_type
                58      LOAD_CONST                      8: None
                60      NOP                             
                62      NOP                             
                64      NOP                             
                66      JUMP_FORWARD                    19 (to 106)
                74      POP_TOP                         
                76      RETURN_CONST                    8: None
                78      PUSH_EXC_INFO                   
                80      PUSH_NULL                       
                82      LOAD_CONST                      7: '__pyarmor_exit_55167__'
                84      NOP                             
                86      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00",\x00\x00\x00\x00\x00\x00\x00'
                88      CALL                            1
                96      POP_TOP                         
                98      RERAISE                         0
                100     COPY                            3
                102     POP_EXCEPT                      
                104     RERAISE                         1
                106     PUSH_NULL                       
                108     LOAD_CONST                      7: '__pyarmor_exit_55167__'
                110     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00",\x00\x00\x00\x00\x00\x00\x00'
                112     BUILD_TUPLE                     1
                114     CALL_FUNCTION_EX                0
                116     POP_TOP                         
                118     RETURN_VALUE                    
        'StructUnroller'
        'return'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_structs_enums
            Qualified Name: get_structs_enums
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'dict'
                'type'
                'copy'
                'str'
                'is_struct'
                'is_enum'
                'is_ptr'
                'is_const'
                'remove_ptr_or_array'
                'clr_const'
                'StructUnroller'
                'unroll_struct_type'
                'list_enum_members'
            [Locals+Names]
                'var_list'
                '__assert_armored__'
                '_var_var_32'
                '_var_var_33'
                '_var_var_34'
                '_var_var_35'
                '_var_var_36'
                '_var_var_37'
                '_var_var_38'
            [Constants]
                None
                '__pyarmor_assert_55177__'
                '__pyarmor_enter_55178__'
                b'<COAddr>\x03\x00\x00\x1a\xa0\x02\x00\x00\x00\x00\x00\x00'
                'struct'
                'not-struct'
                'enum'
                'not-enum'
                0
                (
                    'max_depth'
                )
                '__pyarmor_exit_55179__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55178__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa0\x02\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + dict
                38      CALL                            0
                46      STORE_FAST                      2: _var_var_32
                48      LOAD_FAST                       0: var_list
                50      GET_ITER                        
                52      FOR_ITER                        308 (to 672)
                58      STORE_FAST                      3: _var_var_33
                60      LOAD_FAST                       3: _var_var_33
                62      LOAD_ATTR                       3: type
                82      CALL                            0
                90      LOAD_ATTR                       5: copy
                110     CALL                            0
                118     STORE_FAST                      4: _var_var_34
                120     LOAD_GLOBAL                     7: NULL + str
                130     LOAD_FAST                       4: _var_var_34
                132     CALL                            1
                140     STORE_FAST                      5: _var_var_35
                142     LOAD_FAST                       4: _var_var_34
                144     LOAD_ATTR                       9: is_struct
                164     CALL                            0
                172     POP_JUMP_IF_FALSE               2 (to 178)
                174     LOAD_CONST                      4: 'struct'
                176     JUMP_FORWARD                    1 (to 180)
                178     LOAD_CONST                      5: 'not-struct'
                180     STORE_FAST                      6: _var_var_36
                182     LOAD_FAST                       4: _var_var_34
                184     LOAD_ATTR                       11: is_enum
                204     CALL                            0
                212     POP_JUMP_IF_FALSE               2 (to 218)
                214     LOAD_CONST                      6: 'enum'
                216     JUMP_FORWARD                    1 (to 220)
                218     LOAD_CONST                      7: 'not-enum'
                220     STORE_FAST                      7: _var_var_37
                222     LOAD_FAST                       4: _var_var_34
                224     LOAD_ATTR                       13: is_ptr
                244     CALL                            0
                252     POP_JUMP_IF_TRUE                16 (to 286)
                254     LOAD_FAST                       4: _var_var_34
                256     LOAD_ATTR                       15: is_const
                276     CALL                            0
                284     POP_JUMP_IF_FALSE               105 (to 496)
                286     LOAD_FAST                       4: _var_var_34
                288     LOAD_ATTR                       13: is_ptr
                308     CALL                            0
                316     POP_JUMP_IF_FALSE               17 (to 352)
                318     LOAD_FAST                       4: _var_var_34
                320     LOAD_ATTR                       17: remove_ptr_or_array
                340     CALL                            0
                348     POP_JUMP_IF_FALSE               1 (to 352)
                350     JUMP_BACKWARD                   17 (to 318)
                352     LOAD_FAST                       4: _var_var_34
                354     LOAD_ATTR                       15: is_const
                374     CALL                            0
                382     POP_JUMP_IF_FALSE               16 (to 416)
                384     LOAD_FAST                       4: _var_var_34
                386     LOAD_ATTR                       19: clr_const
                406     CALL                            0
                414     POP_TOP                         
                416     LOAD_FAST                       4: _var_var_34
                418     LOAD_ATTR                       9: is_struct
                438     CALL                            0
                446     POP_JUMP_IF_FALSE               2 (to 452)
                448     LOAD_CONST                      4: 'struct'
                450     JUMP_FORWARD                    1 (to 454)
                452     LOAD_CONST                      5: 'not-struct'
                454     STORE_FAST                      6: _var_var_36
                456     LOAD_FAST                       4: _var_var_34
                458     LOAD_ATTR                       11: is_enum
                478     CALL                            0
                486     POP_JUMP_IF_FALSE               2 (to 492)
                488     LOAD_CONST                      6: 'enum'
                490     JUMP_FORWARD                    1 (to 494)
                492     LOAD_CONST                      7: 'not-enum'
                494     STORE_FAST                      7: _var_var_37
                496     LOAD_FAST                       6: _var_var_36
                498     LOAD_CONST                      4: 'struct'
                500     COMPARE_OP                      40 (==)
                504     POP_JUMP_IF_FALSE               43 (to 592)
                506     LOAD_GLOBAL                     21: NULL + StructUnroller
                516     LOAD_CONST                      8: 0
                518     KW_NAMES                        9: ('max_depth',)
                520     CALL                            1
                528     STORE_FAST                      8: _var_var_38
                530     LOAD_FAST                       8: _var_var_38
                532     LOAD_ATTR                       23: unroll_struct_type
                552     LOAD_FAST                       4: _var_var_34
                554     CALL                            1
                562     LOAD_FAST                       2: _var_var_32
                564     LOAD_GLOBAL                     7: NULL + str
                574     LOAD_FAST                       4: _var_var_34
                576     CALL                            1
                584     STORE_SUBSCR                    
                588     JUMP_BACKWARD                   270 (to 52)
                592     LOAD_FAST                       7: _var_var_37
                594     LOAD_CONST                      6: 'enum'
                596     COMPARE_OP                      40 (==)
                600     POP_JUMP_IF_FALSE               34 (to 670)
                602     LOAD_GLOBAL                     25: NULL + list_enum_members
                612     LOAD_GLOBAL                     7: NULL + str
                622     LOAD_FAST                       4: _var_var_34
                624     CALL                            1
                632     CALL                            1
                640     LOAD_FAST                       2: _var_var_32
                642     LOAD_GLOBAL                     7: NULL + str
                652     LOAD_FAST                       4: _var_var_34
                654     CALL                            1
                662     STORE_SUBSCR                    
                666     JUMP_BACKWARD                   309 (to 52)
                670     JUMP_BACKWARD                   311 (to 52)
                674     END_FOR                         
                676     LOAD_FAST                       2: _var_var_32
                678     NOP                             
                680     NOP                             
                682     NOP                             
                684     JUMP_FORWARD                    20 (to 726)
                686     CALL                            1
                694     POP_TOP                         
                696     RETURN_VALUE                    
                698     PUSH_EXC_INFO                   
                700     PUSH_NULL                       
                702     LOAD_CONST                      10: '__pyarmor_exit_55179__'
                704     NOP                             
                706     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa0\x02\x00\x00\x00\x00\x00\x00'
                708     CALL                            1
                716     POP_TOP                         
                718     RERAISE                         0
                720     COPY                            3
                722     POP_EXCEPT                      
                724     RERAISE                         1
                726     PUSH_NULL                       
                728     LOAD_CONST                      10: '__pyarmor_exit_55179__'
                730     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa0\x02\x00\x00\x00\x00\x00\x00'
                732     BUILD_TUPLE                     1
                734     CALL_FUNCTION_EX                0
                736     POP_TOP                         
                738     RETURN_VALUE                    
        'inst_head_ea'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_callee_name
            Qualified Name: get_callee_name
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'idautils'
                'XrefsFrom'
                'type'
                'ida_xref'
                'fl_CN'
                'fl_CF'
                'fl_JN'
                'fl_JF'
                'to'
                'is_thunk'
                'ida_funcs'
                'calc_thunk_func_target'
                'idaapi'
                'BADADDR'
                'idc'
                'get_func_name'
                'XrefsTo'
                'frm'
                'append'
            [Locals+Names]
                'inst_head_ea'
                '__assert_armored__'
                '_var_var_39'
                '_var_var_40'
                '_var_var_41'
                '_var_var_42'
                '_var_var_43'
            [Constants]
                None
                '__pyarmor_assert_55180__'
                '__pyarmor_enter_55181__'
                b'<COAddr>\x03\x00\x00\x1a\x9c\x02\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_55182__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55181__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x9c\x02\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      BUILD_LIST                      0
                30      STORE_FAST                      2: _var_var_39
                32      LOAD_GLOBAL                     1: NULL + idautils
                42      LOAD_ATTR                       2: XrefsFrom
                62      LOAD_FAST                       0: inst_head_ea
                64      CALL                            1
                72      GET_ITER                        
                74      FOR_ITER                        295 (to 668)
                80      STORE_FAST                      3: _var_var_40
                82      LOAD_FAST                       3: _var_var_40
                84      LOAD_ATTR                       4: type
                104     LOAD_GLOBAL                     6: ida_xref
                114     LOAD_ATTR                       8: fl_CN
                134     COMPARE_OP                      40 (==)
                138     POP_JUMP_IF_TRUE                88 (to 316)
                140     LOAD_FAST                       3: _var_var_40
                142     LOAD_ATTR                       4: type
                162     LOAD_GLOBAL                     6: ida_xref
                172     LOAD_ATTR                       10: fl_CF
                192     COMPARE_OP                      40 (==)
                196     POP_JUMP_IF_TRUE                59 (to 316)
                198     LOAD_FAST                       3: _var_var_40
                200     LOAD_ATTR                       4: type
                220     LOAD_GLOBAL                     6: ida_xref
                230     LOAD_ATTR                       12: fl_JN
                250     COMPARE_OP                      40 (==)
                254     POP_JUMP_IF_TRUE                30 (to 316)
                256     LOAD_FAST                       3: _var_var_40
                258     LOAD_ATTR                       4: type
                278     LOAD_GLOBAL                     6: ida_xref
                288     LOAD_ATTR                       14: fl_JF
                308     COMPARE_OP                      40 (==)
                312     POP_JUMP_IF_TRUE                1 (to 316)
                314     JUMP_BACKWARD                   121 (to 74)
                316     LOAD_FAST                       3: _var_var_40
                318     LOAD_ATTR                       16: to
                338     STORE_FAST                      4: _var_var_41
                340     LOAD_GLOBAL                     19: NULL + is_thunk
                350     LOAD_FAST                       4: _var_var_41
                352     CALL                            1
                360     POP_JUMP_IF_FALSE               45 (to 452)
                362     LOAD_GLOBAL                     21: NULL + ida_funcs
                372     LOAD_ATTR                       22: calc_thunk_func_target
                392     LOAD_FAST                       4: _var_var_41
                394     CALL                            1
                402     LOAD_CONST                      4: 0
                404     BINARY_SUBSCR                   
                408     STORE_FAST                      5: _var_var_42
                410     LOAD_FAST                       5: _var_var_42
                412     LOAD_GLOBAL                     24: idaapi
                422     LOAD_ATTR                       26: BADADDR
                442     COMPARE_OP                      55 (!=)
                446     POP_JUMP_IF_FALSE               2 (to 452)
                448     LOAD_FAST                       5: _var_var_42
                450     STORE_FAST                      4: _var_var_41
                452     LOAD_GLOBAL                     29: NULL + idc
                462     LOAD_ATTR                       30: get_func_name
                482     LOAD_FAST                       4: _var_var_41
                484     CALL                            1
                492     STORE_FAST                      6: _var_var_43
                494     LOAD_FAST                       6: _var_var_43
                496     POP_JUMP_IF_TRUE                61 (to 620)
                498     LOAD_GLOBAL                     1: NULL + idautils
                508     LOAD_ATTR                       32: XrefsTo
                528     LOAD_FAST                       4: _var_var_41
                530     CALL                            1
                538     GET_ITER                        
                540     FOR_ITER                        37 (to 616)
                544     STORE_FAST                      3: _var_var_40
                546     LOAD_GLOBAL                     29: NULL + idc
                556     LOAD_ATTR                       30: get_func_name
                576     LOAD_FAST                       3: _var_var_40
                578     LOAD_ATTR                       34: frm
                598     CALL                            1
                606     STORE_FAST                      6: _var_var_43
                608     LOAD_FAST                       6: _var_var_43
                610     POP_JUMP_IF_TRUE                1 (to 614)
                612     JUMP_BACKWARD                   37 (to 540)
                614     POP_TOP                         
                616     JUMP_FORWARD                    1 (to 620)
                618     END_FOR                         
                620     LOAD_FAST                       6: _var_var_43
                622     POP_JUMP_IF_TRUE                2 (to 628)
                624     JUMP_BACKWARD                   277 (to 74)
                628     LOAD_FAST                       2: _var_var_39
                630     LOAD_ATTR                       37: append
                650     LOAD_FAST                       4: _var_var_41
                652     LOAD_FAST                       6: _var_var_43
                654     BUILD_LIST                      2
                656     CALL                            1
                664     POP_TOP                         
                666     JUMP_BACKWARD                   298 (to 74)
                670     END_FOR                         
                672     LOAD_FAST                       2: _var_var_39
                674     NOP                             
                676     NOP                             
                678     NOP                             
                680     JUMP_FORWARD                    20 (to 722)
                682     CALL                            1
                690     POP_TOP                         
                692     RETURN_VALUE                    
                694     PUSH_EXC_INFO                   
                696     PUSH_NULL                       
                698     LOAD_CONST                      5: '__pyarmor_exit_55182__'
                700     NOP                             
                702     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x9c\x02\x00\x00\x00\x00\x00\x00'
                704     CALL                            1
                712     POP_TOP                         
                714     RERAISE                         0
                716     COPY                            3
                718     POP_EXCEPT                      
                720     RERAISE                         1
                722     PUSH_NULL                       
                724     LOAD_CONST                      5: '__pyarmor_exit_55182__'
                726     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x9c\x02\x00\x00\x00\x00\x00\x00'
                728     BUILD_TUPLE                     1
                730     CALL_FUNCTION_EX                0
                732     POP_TOP                         
                734     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_var_info
            Qualified Name: get_var_info
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 11
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'name'
                'type'
                'copy'
                'str'
                'defea'
                'location'
                'is_stkoff'
                'stkoff'
                'is_reg1'
                'reg1'
                'is_reg2'
                'reg2'
                'is_ptr'
                'is_struct'
                'is_enum'
                'is_const'
                'remove_ptr_or_array'
                'clr_const'
                'append'
            [Locals+Names]
                'var_list'
                '__assert_armored__'
                '_var_var_44'
                '_var_var_33'
                '_var_var_45'
                '_var_var_34'
                '_var_var_35'
                '_var_var_46'
                '_var_var_47'
                '_var_var_48'
                '_var_var_49'
                '_var_var_36'
                '_var_var_37'
            [Constants]
                None
                '__pyarmor_assert_55183__'
                '__pyarmor_enter_55184__'
                b'<COAddr>\x01\x00\x00\x1a\x94\x03\x00\x00\x00\x00\x00\x00'
                'stack_offset@%d'
                'register@%s'
                'register_pair@'
                ','
                ''
                'ptr'
                'not-ptr'
                'struct'
                'not-struct'
                'enum'
                'not-enum'
                '__pyarmor_exit_55185__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55184__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x94\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      BUILD_LIST                      0
                30      STORE_FAST                      2: _var_var_44
                32      LOAD_FAST                       0: var_list
                34      GET_ITER                        
                36      FOR_ITER                        438 (to 916)
                42      STORE_FAST                      3: _var_var_33
                44      LOAD_FAST                       3: _var_var_33
                46      LOAD_ATTR                       0: name
                66      STORE_FAST                      4: _var_var_45
                68      LOAD_FAST                       3: _var_var_33
                70      LOAD_ATTR                       3: type
                90      CALL                            0
                98      LOAD_ATTR                       5: copy
                118     CALL                            0
                126     STORE_FAST                      5: _var_var_34
                128     LOAD_GLOBAL                     7: NULL + str
                138     LOAD_FAST                       5: _var_var_34
                140     CALL                            1
                148     STORE_FAST                      6: _var_var_35
                150     LOAD_FAST                       3: _var_var_33
                152     LOAD_ATTR                       8: defea
                172     STORE_FAST                      7: _var_var_46
                174     LOAD_FAST                       3: _var_var_33
                176     LOAD_ATTR                       10: location
                196     STORE_FAST                      8: _var_var_47
                198     LOAD_FAST                       8: _var_var_47
                200     LOAD_ATTR                       13: is_stkoff
                220     CALL                            0
                228     POP_JUMP_IF_FALSE               20 (to 270)
                230     LOAD_CONST                      4: 'stack_offset@%d'
                232     LOAD_FAST                       8: _var_var_47
                234     LOAD_ATTR                       15: stkoff
                254     CALL                            0
                262     BINARY_OP                       6 (%)
                266     STORE_FAST                      9: _var_var_48
                268     JUMP_FORWARD                    91 (to 452)
                270     LOAD_FAST                       8: _var_var_47
                272     LOAD_ATTR                       17: is_reg1
                292     CALL                            0
                300     POP_JUMP_IF_FALSE               20 (to 342)
                302     LOAD_CONST                      5: 'register@%s'
                304     LOAD_FAST                       8: _var_var_47
                306     LOAD_ATTR                       19: reg1
                326     CALL                            0
                334     BINARY_OP                       6 (%)
                338     STORE_FAST                      9: _var_var_48
                340     JUMP_FORWARD                    55 (to 452)
                342     LOAD_FAST                       8: _var_var_47
                344     LOAD_ATTR                       21: is_reg2
                364     CALL                            0
                372     POP_JUMP_IF_FALSE               37 (to 448)
                374     LOAD_CONST                      6: 'register_pair@'
                376     LOAD_FAST                       8: _var_var_47
                378     LOAD_ATTR                       19: reg1
                398     CALL                            0
                406     FORMAT_VALUE                    1 (FVC_STR)
                408     LOAD_CONST                      7: ','
                410     LOAD_FAST                       8: _var_var_47
                412     LOAD_ATTR                       23: reg2
                432     CALL                            0
                440     FORMAT_VALUE                    1 (FVC_STR)
                442     BUILD_STRING                    4
                444     STORE_FAST                      9: _var_var_48
                446     JUMP_FORWARD                    2 (to 452)
                448     LOAD_CONST                      8: ''
                450     STORE_FAST                      9: _var_var_48
                452     LOAD_FAST                       5: _var_var_34
                454     LOAD_ATTR                       25: is_ptr
                474     CALL                            0
                482     POP_JUMP_IF_FALSE               2 (to 488)
                484     LOAD_CONST                      9: 'ptr'
                486     JUMP_FORWARD                    1 (to 490)
                488     LOAD_CONST                      10: 'not-ptr'
                490     STORE_FAST                      10: _var_var_49
                492     LOAD_FAST                       5: _var_var_34
                494     LOAD_ATTR                       27: is_struct
                514     CALL                            0
                522     POP_JUMP_IF_FALSE               2 (to 528)
                524     LOAD_CONST                      11: 'struct'
                526     JUMP_FORWARD                    1 (to 530)
                528     LOAD_CONST                      12: 'not-struct'
                530     STORE_FAST                      11: _var_var_36
                532     LOAD_FAST                       5: _var_var_34
                534     LOAD_ATTR                       29: is_enum
                554     CALL                            0
                562     POP_JUMP_IF_FALSE               2 (to 568)
                564     LOAD_CONST                      13: 'enum'
                566     JUMP_FORWARD                    1 (to 570)
                568     LOAD_CONST                      14: 'not-enum'
                570     STORE_FAST                      12: _var_var_37
                572     LOAD_FAST                       5: _var_var_34
                574     LOAD_ATTR                       25: is_ptr
                594     CALL                            0
                602     POP_JUMP_IF_TRUE                16 (to 636)
                604     LOAD_FAST                       5: _var_var_34
                606     LOAD_ATTR                       31: is_const
                626     CALL                            0
                634     POP_JUMP_IF_FALSE               105 (to 846)
                636     LOAD_FAST                       5: _var_var_34
                638     LOAD_ATTR                       25: is_ptr
                658     CALL                            0
                666     POP_JUMP_IF_FALSE               17 (to 702)
                668     LOAD_FAST                       5: _var_var_34
                670     LOAD_ATTR                       33: remove_ptr_or_array
                690     CALL                            0
                698     POP_JUMP_IF_FALSE               1 (to 702)
                700     JUMP_BACKWARD                   17 (to 668)
                702     LOAD_FAST                       5: _var_var_34
                704     LOAD_ATTR                       31: is_const
                724     CALL                            0
                732     POP_JUMP_IF_FALSE               16 (to 766)
                734     LOAD_FAST                       5: _var_var_34
                736     LOAD_ATTR                       35: clr_const
                756     CALL                            0
                764     POP_TOP                         
                766     LOAD_FAST                       5: _var_var_34
                768     LOAD_ATTR                       27: is_struct
                788     CALL                            0
                796     POP_JUMP_IF_FALSE               2 (to 802)
                798     LOAD_CONST                      11: 'struct'
                800     JUMP_FORWARD                    1 (to 804)
                802     LOAD_CONST                      12: 'not-struct'
                804     STORE_FAST                      11: _var_var_36
                806     LOAD_FAST                       5: _var_var_34
                808     LOAD_ATTR                       29: is_enum
                828     CALL                            0
                836     POP_JUMP_IF_FALSE               2 (to 842)
                838     LOAD_CONST                      13: 'enum'
                840     JUMP_FORWARD                    1 (to 844)
                842     LOAD_CONST                      14: 'not-enum'
                844     STORE_FAST                      12: _var_var_37
                846     LOAD_FAST                       2: _var_var_44
                848     LOAD_ATTR                       37: append
                868     LOAD_FAST                       4: _var_var_45
                870     LOAD_FAST                       6: _var_var_35
                872     LOAD_GLOBAL                     7: NULL + str
                882     LOAD_FAST                       5: _var_var_34
                884     CALL                            1
                892     LOAD_FAST                       9: _var_var_48
                894     LOAD_FAST                       7: _var_var_46
                896     LOAD_FAST                       10: _var_var_49
                898     LOAD_FAST                       11: _var_var_36
                900     LOAD_FAST                       12: _var_var_37
                902     BUILD_LIST                      8
                904     CALL                            1
                912     POP_TOP                         
                914     JUMP_BACKWARD                   441 (to 36)
                918     END_FOR                         
                920     LOAD_FAST                       2: _var_var_44
                922     NOP                             
                924     NOP                             
                926     NOP                             
                928     JUMP_FORWARD                    20 (to 970)
                930     CALL                            1
                938     POP_TOP                         
                940     RETURN_VALUE                    
                942     PUSH_EXC_INFO                   
                944     PUSH_NULL                       
                946     LOAD_CONST                      15: '__pyarmor_exit_55185__'
                948     NOP                             
                950     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x94\x03\x00\x00\x00\x00\x00\x00'
                952     CALL                            1
                960     POP_TOP                         
                962     RERAISE                         0
                964     COPY                            3
                966     POP_EXCEPT                      
                968     RERAISE                         1
                970     PUSH_NULL                       
                972     LOAD_CONST                      15: '__pyarmor_exit_55185__'
                974     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x94\x03\x00\x00\x00\x00\x00\x00'
                976     BUILD_TUPLE                     1
                978     CALL_FUNCTION_EX                0
                980     POP_TOP                         
                982     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_local_vars
            Qualified Name: get_local_vars
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'decompile'
                'DecompilationFailure'
                'print'
                'hex'
                'lvars'
                'name'
                'is_arg_var'
                'append'
            [Locals+Names]
                'func_ea'
                '__assert_armored__'
                '_var_var_50'
                '_var_var_44'
                '_var_var_51'
            [Constants]
                None
                '__pyarmor_assert_55186__'
                '__pyarmor_enter_55187__'
                b'<COAddr>\x03\x00\x00\x1a6\x01\x00\x00\x00\x00\x00\x00'
                '[!] Failed to decompile function at '
                '__pyarmor_exit_55188__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55187__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a6\x01\x00\x00\x00\x00\x00\x00'
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
                30      LOAD_GLOBAL                     1: NULL + decompile
                40      LOAD_FAST                       0: func_ea
                42      CALL                            1
                50      STORE_FAST                      2: _var_var_50
                52      LOAD_FAST                       2: _var_var_50
                54      LOAD_CONST                      0: None
                56      COMPARE_OP                      40 (==)
                60      POP_JUMP_IF_FALSE               6 (to 74)
                62      LOAD_GLOBAL                     2: DecompilationFailure
                72      RAISE_VARARGS                   1
                74      NOP                             
                76      BUILD_LIST                      0
                78      STORE_FAST                      3: _var_var_44
                80      LOAD_FAST                       2: _var_var_50
                82      LOAD_ATTR                       8: lvars
                102     GET_ITER                        
                104     FOR_ITER                        55 (to 216)
                108     STORE_FAST                      4: _var_var_51
                110     LOAD_FAST                       4: _var_var_51
                112     LOAD_ATTR                       10: name
                132     POP_JUMP_IF_TRUE                1 (to 136)
                134     JUMP_BACKWARD                   16 (to 104)
                136     LOAD_FAST                       4: _var_var_51
                138     LOAD_ATTR                       12: is_arg_var
                158     POP_JUMP_IF_FALSE               1 (to 162)
                160     JUMP_BACKWARD                   29 (to 104)
                162     LOAD_FAST                       3: _var_var_44
                164     LOAD_ATTR                       15: append
                184     LOAD_FAST                       4: _var_var_51
                186     LOAD_ATTR                       10: name
                206     CALL                            1
                214     POP_TOP                         
                216     JUMP_BACKWARD                   57 (to 104)
                218     END_FOR                         
                220     LOAD_FAST                       3: _var_var_44
                222     NOP                             
                224     NOP                             
                226     NOP                             
                228     JUMP_FORWARD                    67 (to 364)
                230     CALL                            1
                238     POP_TOP                         
                240     RETURN_VALUE                    
                242     PUSH_EXC_INFO                   
                244     LOAD_GLOBAL                     2: DecompilationFailure
                254     CHECK_EXC_MATCH                 
                256     POP_JUMP_IF_FALSE               35 (to 328)
                258     POP_TOP                         
                260     LOAD_GLOBAL                     5: NULL + print
                270     LOAD_CONST                      4: '[!] Failed to decompile function at '
                272     LOAD_GLOBAL                     7: NULL + hex
                282     LOAD_FAST                       0: func_ea
                284     CALL                            1
                292     FORMAT_VALUE                    0 (FVC_NONE)
                294     BUILD_STRING                    2
                296     CALL                            1
                304     POP_TOP                         
                306     POP_EXCEPT                      
                308     LOAD_CONST                      0: None
                310     NOP                             
                312     NOP                             
                314     NOP                             
                316     JUMP_FORWARD                    23 (to 364)
                324     POP_TOP                         
                326     RETURN_CONST                    0: None
                328     RERAISE                         0
                330     COPY                            3
                332     POP_EXCEPT                      
                334     RERAISE                         1
                336     PUSH_EXC_INFO                   
                338     PUSH_NULL                       
                340     LOAD_CONST                      5: '__pyarmor_exit_55188__'
                342     NOP                             
                344     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a6\x01\x00\x00\x00\x00\x00\x00'
                346     CALL                            1
                354     POP_TOP                         
                356     RERAISE                         0
                358     COPY                            3
                360     POP_EXCEPT                      
                362     RERAISE                         1
                364     PUSH_NULL                       
                366     LOAD_CONST                      5: '__pyarmor_exit_55188__'
                368     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a6\x01\x00\x00\x00\x00\x00\x00'
                370     BUILD_TUPLE                     1
                372     CALL_FUNCTION_EX                0
                374     POP_TOP                         
                376     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_args
            Qualified Name: get_args
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'decompile'
                'DecompilationFailure'
                'print'
                'hex'
                'arguments'
                'name'
                'append'
            [Locals+Names]
                'func_ea'
                '__assert_armored__'
                '_var_var_50'
                '_var_var_52'
                '_var_var_53'
            [Constants]
                None
                '__pyarmor_assert_55189__'
                '__pyarmor_enter_55190__'
                b'<COAddr>\x01\x00\x00\x1a\x1c\x01\x00\x00\x00\x00\x00\x00'
                '[!] Failed to decompile function at '
                '__pyarmor_exit_55191__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55190__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x1c\x01\x00\x00\x00\x00\x00\x00'
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
                30      LOAD_GLOBAL                     1: NULL + decompile
                40      LOAD_FAST                       0: func_ea
                42      CALL                            1
                50      STORE_FAST                      2: _var_var_50
                52      LOAD_FAST                       2: _var_var_50
                54      LOAD_CONST                      0: None
                56      COMPARE_OP                      40 (==)
                60      POP_JUMP_IF_FALSE               6 (to 74)
                62      LOAD_GLOBAL                     2: DecompilationFailure
                72      RAISE_VARARGS                   1
                74      NOP                             
                76      BUILD_LIST                      0
                78      STORE_FAST                      3: _var_var_52
                80      LOAD_FAST                       2: _var_var_50
                82      LOAD_ATTR                       8: arguments
                102     GET_ITER                        
                104     FOR_ITER                        42 (to 190)
                108     STORE_FAST                      4: _var_var_53
                110     LOAD_FAST                       4: _var_var_53
                112     LOAD_ATTR                       10: name
                132     POP_JUMP_IF_TRUE                1 (to 136)
                134     JUMP_BACKWARD                   16 (to 104)
                136     LOAD_FAST                       3: _var_var_52
                138     LOAD_ATTR                       13: append
                158     LOAD_FAST                       4: _var_var_53
                160     LOAD_ATTR                       10: name
                180     CALL                            1
                188     POP_TOP                         
                190     JUMP_BACKWARD                   44 (to 104)
                192     END_FOR                         
                194     LOAD_FAST                       3: _var_var_52
                196     NOP                             
                198     NOP                             
                200     NOP                             
                202     JUMP_FORWARD                    67 (to 338)
                204     CALL                            1
                212     POP_TOP                         
                214     RETURN_VALUE                    
                216     PUSH_EXC_INFO                   
                218     LOAD_GLOBAL                     2: DecompilationFailure
                228     CHECK_EXC_MATCH                 
                230     POP_JUMP_IF_FALSE               35 (to 302)
                232     POP_TOP                         
                234     LOAD_GLOBAL                     5: NULL + print
                244     LOAD_CONST                      4: '[!] Failed to decompile function at '
                246     LOAD_GLOBAL                     7: NULL + hex
                256     LOAD_FAST                       0: func_ea
                258     CALL                            1
                266     FORMAT_VALUE                    0 (FVC_NONE)
                268     BUILD_STRING                    2
                270     CALL                            1
                278     POP_TOP                         
                280     POP_EXCEPT                      
                282     LOAD_CONST                      0: None
                284     NOP                             
                286     NOP                             
                288     NOP                             
                290     JUMP_FORWARD                    23 (to 338)
                298     POP_TOP                         
                300     RETURN_CONST                    0: None
                302     RERAISE                         0
                304     COPY                            3
                306     POP_EXCEPT                      
                308     RERAISE                         1
                310     PUSH_EXC_INFO                   
                312     PUSH_NULL                       
                314     LOAD_CONST                      5: '__pyarmor_exit_55191__'
                316     NOP                             
                318     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x1c\x01\x00\x00\x00\x00\x00\x00'
                320     CALL                            1
                328     POP_TOP                         
                330     RERAISE                         0
                332     COPY                            3
                334     POP_EXCEPT                      
                336     RERAISE                         1
                338     PUSH_NULL                       
                340     LOAD_CONST                      5: '__pyarmor_exit_55191__'
                342     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x1c\x01\x00\x00\x00\x00\x00\x00'
                344     BUILD_TUPLE                     1
                346     CALL_FUNCTION_EX                0
                348     POP_TOP                         
                350     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: omit_too_long_pcode
            Qualified Name: omit_too_long_pcode
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
            [Locals+Names]
                'pcode_lines'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_55192__'
                '__pyarmor_enter_55193__'
                b'<COAddr>\x01\x00\x00\x1a&\x00\x00\x00\x00\x00\x00\x00'
                800
                '... // omit too long pseudo-code'
                '__pyarmor_exit_55194__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55193__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a&\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: pcode_lines
                30      LOAD_CONST                      0: None
                32      LOAD_CONST                      4: 800
                34      BINARY_SLICE                    
                36      LOAD_CONST                      5: '... // omit too long pseudo-code'
                38      BUILD_LIST                      1
                40      BINARY_OP                       0 (+)
                44      NOP                             
                46      NOP                             
                48      NOP                             
                50      JUMP_FORWARD                    20 (to 92)
                52      CALL                            1
                60      POP_TOP                         
                62      RETURN_VALUE                    
                64      PUSH_EXC_INFO                   
                66      PUSH_NULL                       
                68      LOAD_CONST                      6: '__pyarmor_exit_55194__'
                70      NOP                             
                72      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a&\x00\x00\x00\x00\x00\x00\x00'
                74      CALL                            1
                82      POP_TOP                         
                84      RERAISE                         0
                86      COPY                            3
                88      POP_EXCEPT                      
                90      RERAISE                         1
                92      PUSH_NULL                       
                94      LOAD_CONST                      6: '__pyarmor_exit_55194__'
                96      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a&\x00\x00\x00\x00\x00\x00\x00'
                98      BUILD_TUPLE                     1
                100     CALL_FUNCTION_EX                0
                102     POP_TOP                         
                104     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: build_pcode_with_struct_and_enum
            Qualified Name: build_pcode_with_struct_and_enum
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'is_import_name'
                'get_import_name_info'
                'dict'
                'decompile'
                'DecompilationFailure'
                'idc'
                'get_func_name'
                'demangle'
                'hex'
                'str'
                'enumerate'
                'split'
                'len'
                'omit_too_long_pcode'
                'join'
                'get_structs_enums'
                'lvars'
            [Locals+Names]
                'func_ea'
                '__assert_armored__'
                '_var_var_54'
                '_var_var_55'
                '_var_var_50'
                '_var_var_56'
                '_var_var_3'
                '_var_var_57'
                '_var_var_58'
                '_var_var_32'
            [Constants]
                None
                '__pyarmor_assert_55195__'
                '__pyarmor_enter_55196__'
                b'<COAddr>\x01\x00\x00\x1aj\x02\x00\x00\x00\x00\x00\x00'
                'An imported function with name: '
                ' in library: '
                (
                    'pcode'
                    'struct_enum_dict'
                )
                '__pyarmor_exit_55197__'
                'Fail to decompile func_ea: '
                ', name: '
                '\n'
                '| '
                800
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55196__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aj\x02\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + is_import_name
                38      LOAD_FAST                       0: func_ea
                40      CALL                            1
                48      POP_JUMP_IF_FALSE               42 (to 134)
                50      LOAD_GLOBAL                     3: NULL + get_import_name_info
                60      LOAD_FAST                       0: func_ea
                62      CALL                            1
                70      UNPACK_SEQUENCE                 2
                74      STORE_FAST                      2: _var_var_54
                76      STORE_FAST                      3: _var_var_55
                78      LOAD_CONST                      4: 'An imported function with name: '
                80      LOAD_FAST                       2: _var_var_54
                82      FORMAT_VALUE                    0 (FVC_NONE)
                84      LOAD_CONST                      5: ' in library: '
                86      LOAD_FAST                       3: _var_var_55
                88      FORMAT_VALUE                    0 (FVC_NONE)
                90      BUILD_STRING                    4
                92      LOAD_GLOBAL                     5: NULL + dict
                102     CALL                            0
                110     LOAD_CONST                      6: ('pcode', 'struct_enum_dict')
                112     BUILD_CONST_KEY_MAP             2
                114     NOP                             
                116     NOP                             
                118     JUMP_FORWARD                    275 (to 672)
                122     CALL                            1
                130     POP_TOP                         
                132     RETURN_VALUE                    
                134     NOP                             
                136     LOAD_GLOBAL                     7: NULL + decompile
                146     LOAD_FAST                       0: func_ea
                148     CALL                            1
                156     STORE_FAST                      4: _var_var_50
                158     LOAD_FAST                       4: _var_var_50
                160     LOAD_CONST                      0: None
                162     COMPARE_OP                      40 (==)
                166     POP_JUMP_IF_FALSE               6 (to 180)
                168     LOAD_GLOBAL                     8: DecompilationFailure
                178     RAISE_VARARGS                   1
                180     NOP                             
                182     LOAD_GLOBAL                     19: NULL + str
                192     LOAD_FAST                       4: _var_var_50
                194     CALL                            1
                202     STORE_FAST                      5: _var_var_56
                204     LOAD_GLOBAL                     21: NULL + enumerate
                214     LOAD_FAST                       5: _var_var_56
                216     LOAD_ATTR                       23: split
                236     LOAD_CONST                      10: '\n'
                238     CALL                            1
                246     CALL                            1
                254     GET_ITER                        
                256     LOAD_FAST_AND_CLEAR             6: _var_var_3
                258     LOAD_FAST_AND_CLEAR             7: _var_var_57
                260     SWAP                            3
                262     BUILD_LIST                      0
                264     SWAP                            2
                266     FOR_ITER                        12 (to 292)
                270     UNPACK_SEQUENCE                 2
                274     STORE_FAST                      6: _var_var_3
                276     STORE_FAST                      7: _var_var_57
                278     LOAD_FAST                       6: _var_var_3
                280     FORMAT_VALUE                    0 (FVC_NONE)
                282     LOAD_CONST                      11: '| '
                284     LOAD_FAST                       7: _var_var_57
                286     FORMAT_VALUE                    0 (FVC_NONE)
                288     BUILD_STRING                    3
                290     LIST_APPEND                     2
                292     JUMP_BACKWARD                   14 (to 266)
                294     END_FOR                         
                296     STORE_FAST                      5: _var_var_56
                298     STORE_FAST                      6: _var_var_3
                300     STORE_FAST                      7: _var_var_57
                302     LOAD_GLOBAL                     25: NULL + len
                312     LOAD_FAST                       5: _var_var_56
                314     CALL                            1
                322     STORE_FAST                      8: _var_var_58
                324     LOAD_FAST                       8: _var_var_58
                326     LOAD_CONST                      12: 800
                328     COMPARE_OP                      68 (>)
                332     POP_JUMP_IF_FALSE               11 (to 356)
                334     LOAD_GLOBAL                     27: NULL + omit_too_long_pcode
                344     LOAD_FAST                       5: _var_var_56
                346     CALL                            1
                354     STORE_FAST                      5: _var_var_56
                356     LOAD_CONST                      10: '\n'
                358     LOAD_ATTR                       29: join
                378     LOAD_FAST                       5: _var_var_56
                380     CALL                            1
                388     STORE_FAST                      5: _var_var_56
                390     LOAD_GLOBAL                     31: NULL + get_structs_enums
                400     LOAD_FAST                       4: _var_var_50
                402     LOAD_ATTR                       32: lvars
                422     CALL                            1
                430     STORE_FAST                      9: _var_var_32
                432     LOAD_FAST                       5: _var_var_56
                434     LOAD_FAST                       9: _var_var_32
                436     LOAD_CONST                      6: ('pcode', 'struct_enum_dict')
                438     BUILD_CONST_KEY_MAP             2
                440     NOP                             
                442     NOP                             
                444     NOP                             
                446     JUMP_FORWARD                    112 (to 672)
                448     CALL                            1
                456     POP_TOP                         
                458     RETURN_VALUE                    
                460     PUSH_EXC_INFO                   
                462     LOAD_GLOBAL                     8: DecompilationFailure
                472     CHECK_EXC_MATCH                 
                474     POP_JUMP_IF_FALSE               74 (to 624)
                476     POP_TOP                         
                478     LOAD_GLOBAL                     11: NULL + idc
                488     LOAD_ATTR                       12: get_func_name
                508     LOAD_FAST                       0: func_ea
                510     CALL                            1
                518     STORE_FAST                      2: _var_var_54
                520     LOAD_GLOBAL                     15: NULL + demangle
                530     LOAD_FAST                       2: _var_var_54
                532     CALL                            1
                540     STORE_FAST                      2: _var_var_54
                542     LOAD_CONST                      8: 'Fail to decompile func_ea: '
                544     LOAD_GLOBAL                     17: NULL + hex
                554     LOAD_FAST                       0: func_ea
                556     CALL                            1
                564     FORMAT_VALUE                    0 (FVC_NONE)
                566     LOAD_CONST                      9: ', name: '
                568     LOAD_FAST                       2: _var_var_54
                570     FORMAT_VALUE                    0 (FVC_NONE)
                572     BUILD_STRING                    4
                574     STORE_FAST                      5: _var_var_56
                576     LOAD_FAST                       5: _var_var_56
                578     LOAD_GLOBAL                     5: NULL + dict
                588     CALL                            0
                596     LOAD_CONST                      6: ('pcode', 'struct_enum_dict')
                598     BUILD_CONST_KEY_MAP             2
                600     SWAP                            2
                602     POP_EXCEPT                      
                604     NOP                             
                606     NOP                             
                608     NOP                             
                610     JUMP_FORWARD                    30 (to 672)
                612     CALL                            1
                620     POP_TOP                         
                622     RETURN_VALUE                    
                624     RERAISE                         0
                626     COPY                            3
                628     POP_EXCEPT                      
                630     RERAISE                         1
                632     SWAP                            2
                634     POP_TOP                         
                636     SWAP                            3
                638     STORE_FAST                      7: _var_var_57
                640     STORE_FAST                      6: _var_var_3
                642     RERAISE                         0
                644     PUSH_EXC_INFO                   
                646     PUSH_NULL                       
                648     LOAD_CONST                      7: '__pyarmor_exit_55197__'
                650     NOP                             
                652     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aj\x02\x00\x00\x00\x00\x00\x00'
                654     CALL                            1
                662     POP_TOP                         
                664     RERAISE                         0
                666     COPY                            3
                668     POP_EXCEPT                      
                670     RERAISE                         1
                672     PUSH_NULL                       
                674     LOAD_CONST                      7: '__pyarmor_exit_55197__'
                676     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aj\x02\x00\x00\x00\x00\x00\x00'
                678     BUILD_TUPLE                     1
                680     CALL_FUNCTION_EX                0
                682     POP_TOP                         
                684     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: measure_informative_score_strings
            Qualified Name: measure_informative_score_strings
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'idautils'
                'Heads'
                'start_ea'
                'end_ea'
                'XrefsFrom'
                'ida_xref'
                'XREF_DATA'
                'idc'
                'is_strlit'
                'get_full_flags'
                'to'
                'get_strlit_contents'
                'min'
            [Locals+Names]
                'func'
                'pcode_line_cnt'
                '__assert_armored__'
                '_var_var_59'
                '_var_var_60'
                '_var_var_40'
                '_var_var_61'
            [Constants]
                None
                '__pyarmor_assert_55198__'
                '__pyarmor_enter_55199__'
                b'<COAddr>\x01\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                0
                1
                25
                1
                '__pyarmor_exit_55200__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55199__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: 0
                30      STORE_FAST                      3: _var_var_59
                32      LOAD_GLOBAL                     1: NULL + idautils
                42      LOAD_ATTR                       2: Heads
                62      LOAD_FAST                       0: func
                64      LOAD_ATTR                       4: start_ea
                84      LOAD_FAST                       0: func
                86      LOAD_ATTR                       6: end_ea
                106     CALL                            2
                114     GET_ITER                        
                116     FOR_ITER                        136 (to 390)
                120     STORE_FAST                      4: _var_var_60
                122     LOAD_GLOBAL                     1: NULL + idautils
                132     LOAD_ATTR                       8: XrefsFrom
                152     LOAD_FAST                       4: _var_var_60
                154     LOAD_GLOBAL                     10: ida_xref
                164     LOAD_ATTR                       12: XREF_DATA
                184     CALL                            2
                192     GET_ITER                        
                194     FOR_ITER                        95 (to 386)
                198     STORE_FAST                      5: _var_var_40
                200     LOAD_GLOBAL                     15: NULL + idc
                210     LOAD_ATTR                       16: is_strlit
                230     LOAD_GLOBAL                     15: NULL + idc
                240     LOAD_ATTR                       18: get_full_flags
                260     LOAD_FAST                       5: _var_var_40
                262     LOAD_ATTR                       20: to
                282     CALL                            1
                290     CALL                            1
                298     POP_JUMP_IF_TRUE                1 (to 302)
                300     JUMP_BACKWARD                   54 (to 194)
                302     LOAD_GLOBAL                     15: NULL + idc
                312     LOAD_ATTR                       22: get_strlit_contents
                332     LOAD_FAST                       5: _var_var_40
                334     LOAD_ATTR                       20: to
                354     CALL                            1
                362     STORE_FAST                      6: _var_var_61
                364     LOAD_FAST                       6: _var_var_61
                366     LOAD_CONST                      0: None
                368     COMPARE_OP                      55 (!=)
                372     POP_JUMP_IF_TRUE                1 (to 376)
                374     JUMP_BACKWARD                   91 (to 194)
                376     LOAD_FAST                       3: _var_var_59
                378     LOAD_CONST                      5: 1
                380     BINARY_OP                       13 (+=)
                384     STORE_FAST                      3: _var_var_59
                386     JUMP_BACKWARD                   97 (to 194)
                388     END_FOR                         
                390     JUMP_BACKWARD                   138 (to 116)
                392     END_FOR                         
                394     LOAD_GLOBAL                     25: NULL + min
                404     LOAD_FAST                       3: _var_var_59
                406     LOAD_FAST                       1: pcode_line_cnt
                408     BINARY_OP                       11 (/)
                412     LOAD_CONST                      6: 25
                414     BINARY_OP                       5 (*)
                418     LOAD_CONST                      7: 1
                420     CALL                            2
                428     NOP                             
                430     NOP                             
                432     NOP                             
                434     JUMP_FORWARD                    20 (to 476)
                436     CALL                            1
                444     POP_TOP                         
                446     RETURN_VALUE                    
                448     PUSH_EXC_INFO                   
                450     PUSH_NULL                       
                452     LOAD_CONST                      8: '__pyarmor_exit_55200__'
                454     NOP                             
                456     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                458     CALL                            1
                466     POP_TOP                         
                468     RERAISE                         0
                470     COPY                            3
                472     POP_EXCEPT                      
                474     RERAISE                         1
                476     PUSH_NULL                       
                478     LOAD_CONST                      8: '__pyarmor_exit_55200__'
                480     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                482     BUILD_TUPLE                     1
                484     CALL_FUNCTION_EX                0
                486     POP_TOP                         
                488     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: measure_informative_score_callees
            Qualified Name: measure_informative_score_callees
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'idautils'
                'Heads'
                'start_ea'
                'end_ea'
                'idc'
                'is_code'
                'get_full_flags'
                'ida_ua'
                'insn_t'
                'decode_insn'
                'ida_idp'
                'is_call_insn'
                'extend'
                'get_callee_name'
                'ida_funcs'
                'get_func'
                'idaapi'
                'has_name'
                'min'
                'len'
            [Locals+Names]
                'func'
                '__assert_armored__'
                '_var_var_39'
                '_var_var_60'
                '_var_var_62'
                '_var_var_63'
                '_var_var_41'
                '_var_var_43'
                '_var_var_64'
            [Constants]
                None
                '__pyarmor_assert_55201__'
                '__pyarmor_enter_55202__'
                b'<COAddr>\x01\x00\x00\x1a\x88\x02\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_55203__'
                0
                0
                1
                2
                1
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55202__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x88\x02\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      BUILD_LIST                      0
                30      STORE_FAST                      2: _var_var_39
                32      LOAD_GLOBAL                     1: NULL + idautils
                42      LOAD_ATTR                       2: Heads
                62      LOAD_FAST                       0: func
                64      LOAD_ATTR                       4: start_ea
                84      LOAD_FAST                       0: func
                86      LOAD_ATTR                       6: end_ea
                106     CALL                            2
                114     GET_ITER                        
                116     FOR_ITER                        133 (to 384)
                120     STORE_FAST                      3: _var_var_60
                122     LOAD_GLOBAL                     9: NULL + idc
                132     LOAD_ATTR                       10: is_code
                152     LOAD_GLOBAL                     9: NULL + idc
                162     LOAD_ATTR                       12: get_full_flags
                182     LOAD_FAST                       3: _var_var_60
                184     CALL                            1
                192     CALL                            1
                200     POP_JUMP_IF_TRUE                1 (to 204)
                202     JUMP_BACKWARD                   44 (to 116)
                204     LOAD_GLOBAL                     15: NULL + ida_ua
                214     LOAD_ATTR                       16: insn_t
                234     CALL                            0
                242     STORE_FAST                      4: _var_var_62
                244     LOAD_GLOBAL                     15: NULL + ida_ua
                254     LOAD_ATTR                       18: decode_insn
                274     LOAD_FAST                       4: _var_var_62
                276     LOAD_FAST                       3: _var_var_60
                278     CALL                            2
                286     POP_TOP                         
                288     LOAD_GLOBAL                     21: NULL + ida_idp
                298     LOAD_ATTR                       22: is_call_insn
                318     LOAD_FAST                       4: _var_var_62
                320     CALL                            1
                328     POP_JUMP_IF_TRUE                1 (to 332)
                330     JUMP_BACKWARD                   108 (to 116)
                332     LOAD_FAST                       2: _var_var_39
                334     LOAD_ATTR                       25: extend
                354     LOAD_GLOBAL                     27: NULL + get_callee_name
                364     LOAD_FAST                       3: _var_var_60
                366     CALL                            1
                374     CALL                            1
                382     POP_TOP                         
                384     JUMP_BACKWARD                   135 (to 116)
                386     END_FOR                         
                388     LOAD_FAST                       2: _var_var_39
                390     POP_JUMP_IF_TRUE                11 (to 414)
                392     NOP                             
                394     LOAD_CONST                      5: 0
                396     NOP                             
                398     NOP                             
                400     NOP                             
                402     JUMP_FORWARD                    149 (to 702)
                410     POP_TOP                         
                412     RETURN_CONST                    5: 0
                414     LOAD_CONST                      6: 0
                416     STORE_FAST                      5: _var_var_63
                418     LOAD_FAST                       2: _var_var_39
                420     GET_ITER                        
                422     FOR_ITER                        87 (to 598)
                426     UNPACK_SEQUENCE                 2
                430     STORE_FAST                      6: _var_var_41
                432     STORE_FAST                      7: _var_var_43
                434     LOAD_GLOBAL                     29: NULL + ida_funcs
                444     LOAD_ATTR                       30: get_func
                464     LOAD_FAST                       6: _var_var_41
                466     CALL                            1
                474     STORE_FAST                      0: func
                476     LOAD_FAST                       0: func
                478     POP_JUMP_IF_TRUE                1 (to 482)
                480     JUMP_BACKWARD                   30 (to 422)
                482     LOAD_GLOBAL                     33: NULL + idaapi
                492     LOAD_ATTR                       34: has_name
                512     LOAD_GLOBAL                     33: NULL + idaapi
                522     LOAD_ATTR                       12: get_full_flags
                542     LOAD_FAST                       0: func
                544     LOAD_ATTR                       4: start_ea
                564     CALL                            1
                572     CALL                            1
                580     STORE_FAST                      8: _var_var_64
                582     LOAD_FAST                       8: _var_var_64
                584     POP_JUMP_IF_TRUE                1 (to 588)
                586     JUMP_BACKWARD                   83 (to 422)
                588     LOAD_FAST                       5: _var_var_63
                590     LOAD_CONST                      7: 1
                592     BINARY_OP                       13 (+=)
                596     STORE_FAST                      5: _var_var_63
                598     JUMP_BACKWARD                   89 (to 422)
                600     END_FOR                         
                602     LOAD_GLOBAL                     37: NULL + min
                612     LOAD_FAST                       5: _var_var_63
                614     LOAD_GLOBAL                     39: NULL + len
                624     LOAD_FAST                       2: _var_var_39
                626     CALL                            1
                634     BINARY_OP                       11 (/)
                638     LOAD_CONST                      8: 2
                640     BINARY_OP                       5 (*)
                644     LOAD_CONST                      9: 1
                646     CALL                            2
                654     NOP                             
                656     NOP                             
                658     NOP                             
                660     JUMP_FORWARD                    20 (to 702)
                662     CALL                            1
                670     POP_TOP                         
                672     RETURN_VALUE                    
                674     PUSH_EXC_INFO                   
                676     PUSH_NULL                       
                678     LOAD_CONST                      4: '__pyarmor_exit_55203__'
                680     NOP                             
                682     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x88\x02\x00\x00\x00\x00\x00\x00'
                684     CALL                            1
                692     POP_TOP                         
                694     RERAISE                         0
                696     COPY                            3
                698     POP_EXCEPT                      
                700     RERAISE                         1
                702     PUSH_NULL                       
                704     LOAD_CONST                      4: '__pyarmor_exit_55203__'
                706     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x88\x02\x00\x00\x00\x00\x00\x00'
                708     BUILD_TUPLE                     1
                710     CALL_FUNCTION_EX                0
                712     POP_TOP                         
                714     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: _real_measure_informative_score
            Qualified Name: _real_measure_informative_score
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_funcs'
                'get_func'
                'idaapi'
                'has_name'
                'get_full_flags'
                'start_ea'
                'decompile'
                'len'
                'get_pseudocode'
                'DecompilationFailure'
                'measure_informative_score_strings'
                'measure_informative_score_callees'
                'max'
            [Locals+Names]
                'func_ea'
                '__assert_armored__'
                '_var_var_65'
                '_var_var_66'
                '_var_var_64'
                '_var_var_58'
                '_var_var_50'
            [Constants]
                None
                '__pyarmor_assert_55204__'
                '__pyarmor_enter_55205__'
                b'<COAddr>\x03\x00\x00\x1a\xce\x01\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_55206__'
                -999
                2
                1
                100
                0
                -1
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55205__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xce\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: 0
                30      STORE_FAST                      2: _var_var_65
                32      LOAD_GLOBAL                     1: NULL + ida_funcs
                42      LOAD_ATTR                       2: get_func
                62      LOAD_FAST                       0: func_ea
                64      CALL                            1
                72      STORE_FAST                      3: _var_var_66
                74      LOAD_FAST                       3: _var_var_66
                76      POP_JUMP_IF_TRUE                11 (to 100)
                78      NOP                             
                80      LOAD_CONST                      6: -999
                82      NOP                             
                84      NOP                             
                86      NOP                             
                88      JUMP_FORWARD                    213 (to 516)
                96      POP_TOP                         
                98      RETURN_CONST                    6: -999
                100     LOAD_GLOBAL                     5: NULL + idaapi
                110     LOAD_ATTR                       6: has_name
                130     LOAD_GLOBAL                     5: NULL + idaapi
                140     LOAD_ATTR                       8: get_full_flags
                160     LOAD_FAST                       3: _var_var_66
                162     LOAD_ATTR                       10: start_ea
                182     CALL                            1
                190     CALL                            1
                198     STORE_FAST                      4: _var_var_64
                200     LOAD_FAST                       4: _var_var_64
                202     POP_JUMP_IF_FALSE               5 (to 214)
                204     LOAD_FAST                       2: _var_var_65
                206     LOAD_CONST                      7: 2
                208     BINARY_OP                       13 (+=)
                212     STORE_FAST                      2: _var_var_65
                214     LOAD_CONST                      8: 1
                216     STORE_FAST                      5: _var_var_58
                218     NOP                             
                220     LOAD_GLOBAL                     13: NULL + decompile
                230     LOAD_FAST                       0: func_ea
                232     CALL                            1
                240     STORE_FAST                      6: _var_var_50
                242     LOAD_FAST                       6: _var_var_50
                244     POP_JUMP_IF_FALSE               26 (to 298)
                246     LOAD_GLOBAL                     15: NULL + len
                256     LOAD_FAST                       6: _var_var_50
                258     LOAD_ATTR                       17: get_pseudocode
                278     CALL                            0
                286     CALL                            1
                294     STORE_FAST                      5: _var_var_58
                296     JUMP_FORWARD                    6 (to 310)
                298     LOAD_GLOBAL                     18: DecompilationFailure
                308     RAISE_VARARGS                   1
                310     NOP                             
                312     LOAD_FAST                       2: _var_var_65
                314     LOAD_GLOBAL                     21: NULL + measure_informative_score_strings
                324     LOAD_FAST                       3: _var_var_66
                326     LOAD_FAST                       5: _var_var_58
                328     CALL                            2
                336     BINARY_OP                       13 (+=)
                340     STORE_FAST                      2: _var_var_65
                342     LOAD_FAST                       2: _var_var_65
                344     LOAD_GLOBAL                     23: NULL + measure_informative_score_callees
                354     LOAD_FAST                       3: _var_var_66
                356     CALL                            1
                364     BINARY_OP                       13 (+=)
                368     STORE_FAST                      2: _var_var_65
                370     LOAD_FAST                       2: _var_var_65
                372     LOAD_GLOBAL                     25: NULL + max
                382     LOAD_FAST                       5: _var_var_58
                384     LOAD_CONST                      9: 100
                386     BINARY_OP                       2 (//)
                390     LOAD_CONST                      8: 1
                392     BINARY_OP                       10 (-)
                396     LOAD_CONST                      10: 0
                398     CALL                            2
                406     LOAD_CONST                      11: -1
                408     BINARY_OP                       5 (*)
                412     BINARY_OP                       13 (+=)
                416     STORE_FAST                      2: _var_var_65
                418     LOAD_FAST                       2: _var_var_65
                420     NOP                             
                422     NOP                             
                424     NOP                             
                426     JUMP_FORWARD                    44 (to 516)
                428     CALL                            1
                436     POP_TOP                         
                438     RETURN_VALUE                    
                440     PUSH_EXC_INFO                   
                442     LOAD_GLOBAL                     18: DecompilationFailure
                452     CHECK_EXC_MATCH                 
                454     POP_JUMP_IF_FALSE               12 (to 480)
                456     POP_TOP                         
                458     POP_EXCEPT                      
                460     LOAD_CONST                      6: -999
                462     NOP                             
                464     NOP                             
                466     NOP                             
                468     JUMP_FORWARD                    23 (to 516)
                476     POP_TOP                         
                478     RETURN_CONST                    6: -999
                480     RERAISE                         0
                482     COPY                            3
                484     POP_EXCEPT                      
                486     RERAISE                         1
                488     PUSH_EXC_INFO                   
                490     PUSH_NULL                       
                492     LOAD_CONST                      5: '__pyarmor_exit_55206__'
                494     NOP                             
                496     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xce\x01\x00\x00\x00\x00\x00\x00'
                498     CALL                            1
                506     POP_TOP                         
                508     RERAISE                         0
                510     COPY                            3
                512     POP_EXCEPT                      
                514     RERAISE                         1
                516     PUSH_NULL                       
                518     LOAD_CONST                      5: '__pyarmor_exit_55206__'
                520     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xce\x01\x00\x00\x00\x00\x00\x00'
                522     BUILD_TUPLE                     1
                524     CALL_FUNCTION_EX                0
                526     POP_TOP                         
                528     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: measure_informative_score
            Qualified Name: measure_informative_score
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'MEASURE_INFO_SCORE'
                '_real_measure_informative_score'
            [Locals+Names]
                'func_ea'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_55207__'
                '__pyarmor_enter_55208__'
                b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_55209__'
                1
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55208__'
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
                28      LOAD_GLOBAL                     0: MEASURE_INFO_SCORE
                38      POP_JUMP_IF_FALSE               20 (to 80)
                40      LOAD_GLOBAL                     3: NULL + _real_measure_informative_score
                50      LOAD_FAST                       0: func_ea
                52      CALL                            1
                60      NOP                             
                62      NOP                             
                64      NOP                             
                66      JUMP_FORWARD                    31 (to 130)
                68      CALL                            1
                76      POP_TOP                         
                78      RETURN_VALUE                    
                80      NOP                             
                82      LOAD_CONST                      5: 1
                84      NOP                             
                86      NOP                             
                88      NOP                             
                90      JUMP_FORWARD                    19 (to 130)
                98      POP_TOP                         
                100     RETURN_CONST                    5: 1
                102     PUSH_EXC_INFO                   
                104     PUSH_NULL                       
                106     LOAD_CONST                      4: '__pyarmor_exit_55209__'
                108     NOP                             
                110     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                112     CALL                            1
                120     POP_TOP                         
                122     RERAISE                         0
                124     COPY                            3
                126     POP_EXCEPT                      
                128     RERAISE                         1
                130     PUSH_NULL                       
                132     LOAD_CONST                      4: '__pyarmor_exit_55209__'
                134     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                136     BUILD_TUPLE                     1
                138     CALL_FUNCTION_EX                0
                140     POP_TOP                         
                142     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: ContextBuilder
            Qualified Name: ContextBuilder
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
                'set'
                '__init__'
                'build_context_forward'
                'build_context_backward'
                'build_context'
                'str'
                'get_context_pcode'
                'get_call_chains'
                'list'
                'get_incontext_funcs'
            [Locals+Names]
            [Constants]
                'ContextBuilder'
                '\n    build pseudo-code context and call-chains for the target function\n    '
                '__pyarmor_assert_55210__'
                '__pyarmor_enter_55211__'
                b'<COAddr>\x01\x00\x00&n\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: __init__
                    Qualified Name: ContextBuilder.__init__
                    Arg Count: 5
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'dict'
                        'context_callee_funcs'
                        'defaultdict'
                        'int'
                        'context_caller_funcs'
                        'set'
                        'call_chains'
                        'limited_funcs'
                        'MAX_TRACE_CALLEE_DEPTH'
                        'MAX_TRACE_CALLER_DEPTH'
                        'MAX_CONTEXT_FUNC_NUM'
                    [Locals+Names]
                        'self'
                        'max_trace_callee_depth'
                        'max_trace_caller_depth'
                        'max_context_func_num'
                        'limit_funcs'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55213__'
                        '__pyarmor_enter_55214__'
                        b'<COAddr>\x01\x00\x00\x1a\xb2\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55215__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55214__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb2\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + dict
                        38      CALL                            0
                        46      LOAD_FAST                       0: self
                        48      STORE_ATTR                      1: context_callee_funcs
                        58      LOAD_GLOBAL                     5: NULL + defaultdict
                        68      LOAD_GLOBAL                     6: int
                        78      CALL                            1
                        86      LOAD_FAST                       0: self
                        88      STORE_ATTR                      4: context_caller_funcs
                        98      LOAD_GLOBAL                     11: NULL + set
                        108     CALL                            0
                        116     LOAD_FAST                       0: self
                        118     STORE_ATTR                      6: call_chains
                        128     LOAD_FAST                       4: limit_funcs
                        130     LOAD_FAST                       0: self
                        132     STORE_ATTR                      7: limited_funcs
                        142     LOAD_FAST                       1: max_trace_callee_depth
                        144     LOAD_FAST                       0: self
                        146     STORE_ATTR                      8: MAX_TRACE_CALLEE_DEPTH
                        156     LOAD_FAST                       2: max_trace_caller_depth
                        158     LOAD_FAST                       0: self
                        160     STORE_ATTR                      9: MAX_TRACE_CALLER_DEPTH
                        170     LOAD_FAST                       3: max_context_func_num
                        172     LOAD_FAST                       0: self
                        174     STORE_ATTR                      10: MAX_CONTEXT_FUNC_NUM
                        184     LOAD_CONST                      0: None
                        186     NOP                             
                        188     NOP                             
                        190     NOP                             
                        192     JUMP_FORWARD                    19 (to 232)
                        200     POP_TOP                         
                        202     RETURN_CONST                    0: None
                        204     PUSH_EXC_INFO                   
                        206     PUSH_NULL                       
                        208     LOAD_CONST                      4: '__pyarmor_exit_55215__'
                        210     NOP                             
                        212     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb2\x00\x00\x00\x00\x00\x00\x00'
                        214     CALL                            1
                        222     POP_TOP                         
                        224     RERAISE                         0
                        226     COPY                            3
                        228     POP_EXCEPT                      
                        230     RERAISE                         1
                        232     PUSH_NULL                       
                        234     LOAD_CONST                      4: '__pyarmor_exit_55215__'
                        236     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb2\x00\x00\x00\x00\x00\x00\x00'
                        238     BUILD_TUPLE                     1
                        240     CALL_FUNCTION_EX                0
                        242     POP_TOP                         
                        244     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: build_context_forward
                    Qualified Name: ContextBuilder.build_context_forward
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 8
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'limited_funcs'
                        'MAX_TRACE_CALLEE_DEPTH'
                        'context_callee_funcs'
                        'idautils'
                        'FuncItems'
                        'idaapi'
                        'is_call_insn'
                        'XrefsFrom'
                        'type'
                        'ida_xref'
                        'fl_CN'
                        'fl_CF'
                        'fl_JN'
                        'fl_JF'
                        'iscode'
                        'to'
                        'ida_funcs'
                        'get_func'
                        'start_ea'
                        'idc'
                        'get_func_name'
                        'XrefsTo'
                        'frm'
                        'demangle'
                        'build_context_forward'
                        'call_chains'
                        'add'
                    [Locals+Names]
                        'self'
                        'func_ea'
                        'temp_call_chain'
                        'depth'
                        '__assert_armored__'
                        '_var_var_67'
                        '_var_var_68'
                        '_var_var_40'
                        '_var_var_41'
                        '_var_var_69'
                        '_var_var_43'
                    [Constants]
                        None
                        '__pyarmor_assert_55216__'
                        '__pyarmor_enter_55217__'
                        b'<COAddr>\x01\x00\x00\x1a\xaa\x04\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55218__'
                        False
                        True
                        '-->'
                        1
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55217__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x04\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: limited_funcs
                        50      POP_JUMP_IF_FALSE               25 (to 102)
                        52      LOAD_FAST                       1: func_ea
                        54      LOAD_FAST                       0: self
                        56      LOAD_ATTR                       0: limited_funcs
                        76      CONTAINS_OP                     1 (not in)
                        78      POP_JUMP_IF_FALSE               11 (to 102)
                        80      NOP                             
                        82      LOAD_CONST                      0: None
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    578 (to 1248)
                        98      POP_TOP                         
                        100     RETURN_CONST                    0: None
                        102     LOAD_FAST                       3: depth
                        104     LOAD_FAST                       0: self
                        106     LOAD_ATTR                       2: MAX_TRACE_CALLEE_DEPTH
                        126     COMPARE_OP                      68 (>)
                        130     POP_JUMP_IF_FALSE               11 (to 154)
                        132     NOP                             
                        134     LOAD_CONST                      0: None
                        136     NOP                             
                        138     NOP                             
                        140     JUMP_FORWARD                    552 (to 1248)
                        150     POP_TOP                         
                        152     RETURN_CONST                    0: None
                        154     LOAD_FAST                       1: func_ea
                        156     LOAD_FAST                       0: self
                        158     LOAD_ATTR                       4: context_callee_funcs
                        178     CONTAINS_OP                     1 (not in)
                        180     POP_JUMP_IF_TRUE                18 (to 218)
                        182     LOAD_FAST                       0: self
                        184     LOAD_ATTR                       4: context_callee_funcs
                        204     LOAD_FAST                       1: func_ea
                        206     BINARY_SUBSCR                   
                        210     LOAD_FAST                       3: depth
                        212     COMPARE_OP                      2 (<)
                        216     POP_JUMP_IF_FALSE               15 (to 248)
                        218     LOAD_FAST                       3: depth
                        220     LOAD_FAST                       0: self
                        222     LOAD_ATTR                       4: context_callee_funcs
                        242     LOAD_FAST                       1: func_ea
                        244     STORE_SUBSCR                    
                        248     LOAD_CONST                      5: False
                        250     STORE_FAST                      5: _var_var_67
                        252     LOAD_GLOBAL                     7: NULL + idautils
                        262     LOAD_ATTR                       8: FuncItems
                        282     LOAD_FAST                       1: func_ea
                        284     CALL                            1
                        292     GET_ITER                        
                        294     LOAD_FAST_AND_CLEAR             6: _var_var_68
                        296     SWAP                            2
                        298     BUILD_LIST                      0
                        300     SWAP                            2
                        302     FOR_ITER                        26 (to 356)
                        306     STORE_FAST                      6: _var_var_68
                        308     LOAD_GLOBAL                     11: NULL + idaapi
                        318     LOAD_ATTR                       12: is_call_insn
                        338     LOAD_FAST                       6: _var_var_68
                        340     CALL                            1
                        348     POP_JUMP_IF_TRUE                1 (to 352)
                        350     JUMP_BACKWARD                   25 (to 302)
                        352     LOAD_FAST                       6: _var_var_68
                        354     LIST_APPEND                     2
                        356     JUMP_BACKWARD                   28 (to 302)
                        358     END_FOR                         
                        360     SWAP                            2
                        362     STORE_FAST                      6: _var_var_68
                        364     GET_ITER                        
                        366     FOR_ITER                        332 (to 1034)
                        372     STORE_FAST                      6: _var_var_68
                        374     LOAD_GLOBAL                     7: NULL + idautils
                        384     LOAD_ATTR                       14: XrefsFrom
                        404     LOAD_FAST                       6: _var_var_68
                        406     CALL                            1
                        414     GET_ITER                        
                        416     FOR_ITER                        304 (to 1028)
                        422     STORE_FAST                      7: _var_var_40
                        424     LOAD_FAST                       7: _var_var_40
                        426     LOAD_ATTR                       16: type
                        446     LOAD_GLOBAL                     18: ida_xref
                        456     LOAD_ATTR                       20: fl_CN
                        476     LOAD_GLOBAL                     18: ida_xref
                        486     LOAD_ATTR                       22: fl_CF
                        506     LOAD_GLOBAL                     18: ida_xref
                        516     LOAD_ATTR                       24: fl_JN
                        536     LOAD_GLOBAL                     18: ida_xref
                        546     LOAD_ATTR                       26: fl_JF
                        566     BUILD_TUPLE                     4
                        568     CONTAINS_OP                     1 (not in)
                        570     POP_JUMP_IF_FALSE               1 (to 574)
                        572     JUMP_BACKWARD                   79 (to 416)
                        574     LOAD_FAST                       7: _var_var_40
                        576     LOAD_ATTR                       28: iscode
                        596     POP_JUMP_IF_TRUE                1 (to 600)
                        598     JUMP_BACKWARD                   92 (to 416)
                        600     LOAD_FAST                       7: _var_var_40
                        602     LOAD_ATTR                       30: to
                        622     STORE_FAST                      8: _var_var_41
                        624     LOAD_GLOBAL                     33: NULL + ida_funcs
                        634     LOAD_ATTR                       34: get_func
                        654     LOAD_FAST                       8: _var_var_41
                        656     CALL                            1
                        664     STORE_FAST                      9: _var_var_69
                        666     LOAD_FAST                       9: _var_var_69
                        668     POP_JUMP_IF_TRUE                1 (to 672)
                        670     JUMP_BACKWARD                   128 (to 416)
                        672     LOAD_FAST                       9: _var_var_69
                        674     LOAD_ATTR                       36: start_ea
                        694     STORE_FAST                      8: _var_var_41
                        696     LOAD_GLOBAL                     39: NULL + idc
                        706     LOAD_ATTR                       40: get_func_name
                        726     LOAD_FAST                       8: _var_var_41
                        728     CALL                            1
                        736     STORE_FAST                      10: _var_var_43
                        738     LOAD_FAST                       10: _var_var_43
                        740     POP_JUMP_IF_TRUE                97 (to 936)
                        742     LOAD_GLOBAL                     7: NULL + idautils
                        752     LOAD_ATTR                       42: XrefsTo
                        772     LOAD_FAST                       8: _var_var_41
                        774     CALL                            1
                        782     GET_ITER                        
                        784     FOR_ITER                        73 (to 932)
                        788     STORE_FAST                      7: _var_var_40
                        790     LOAD_GLOBAL                     33: NULL + ida_funcs
                        800     LOAD_ATTR                       34: get_func
                        820     LOAD_FAST                       7: _var_var_40
                        822     LOAD_ATTR                       44: frm
                        842     CALL                            1
                        850     STORE_FAST                      9: _var_var_69
                        852     LOAD_FAST                       9: _var_var_69
                        854     POP_JUMP_IF_TRUE                1 (to 858)
                        856     JUMP_BACKWARD                   37 (to 784)
                        858     LOAD_FAST                       9: _var_var_69
                        860     LOAD_ATTR                       36: start_ea
                        880     STORE_FAST                      8: _var_var_41
                        882     LOAD_GLOBAL                     39: NULL + idc
                        892     LOAD_ATTR                       40: get_func_name
                        912     LOAD_FAST                       8: _var_var_41
                        914     CALL                            1
                        922     STORE_FAST                      10: _var_var_43
                        924     LOAD_FAST                       10: _var_var_43
                        926     POP_JUMP_IF_TRUE                1 (to 930)
                        928     JUMP_BACKWARD                   73 (to 784)
                        930     POP_TOP                         
                        932     JUMP_FORWARD                    1 (to 936)
                        934     END_FOR                         
                        936     LOAD_FAST                       10: _var_var_43
                        938     POP_JUMP_IF_TRUE                2 (to 944)
                        940     JUMP_BACKWARD                   264 (to 416)
                        944     LOAD_CONST                      6: True
                        946     STORE_FAST                      5: _var_var_67
                        948     LOAD_GLOBAL                     47: NULL + demangle
                        958     LOAD_FAST                       10: _var_var_43
                        960     CALL                            1
                        968     STORE_FAST                      10: _var_var_43
                        970     LOAD_FAST                       0: self
                        972     LOAD_ATTR                       49: build_context_forward
                        992     LOAD_FAST                       8: _var_var_41
                        994     LOAD_FAST                       2: temp_call_chain
                        996     LOAD_CONST                      7: '-->'
                        998     BINARY_OP                       0 (+)
                        1002    LOAD_FAST                       10: _var_var_43
                        1004    BINARY_OP                       0 (+)
                        1008    LOAD_FAST                       3: depth
                        1010    LOAD_CONST                      8: 1
                        1012    BINARY_OP                       0 (+)
                        1016    CALL                            3
                        1024    POP_TOP                         
                        1026    JUMP_BACKWARD                   307 (to 416)
                        1030    END_FOR                         
                        1032    JUMP_BACKWARD                   335 (to 366)
                        1036    END_FOR                         
                        1038    LOAD_FAST                       3: depth
                        1040    LOAD_FAST                       0: self
                        1042    LOAD_ATTR                       2: MAX_TRACE_CALLEE_DEPTH
                        1062    COMPARE_OP                      40 (==)
                        1066    POP_JUMP_IF_FALSE               27 (to 1122)
                        1068    LOAD_FAST                       0: self
                        1070    LOAD_ATTR                       50: call_chains
                        1090    LOAD_ATTR                       53: add
                        1110    LOAD_FAST                       2: temp_call_chain
                        1112    CALL                            1
                        1120    POP_TOP                         
                        1122    LOAD_FAST                       3: depth
                        1124    LOAD_CONST                      8: 1
                        1126    COMPARE_OP                      92 (>=)
                        1130    POP_JUMP_IF_FALSE               29 (to 1190)
                        1132    LOAD_FAST                       5: _var_var_67
                        1134    POP_JUMP_IF_TRUE                27 (to 1190)
                        1136    LOAD_FAST                       0: self
                        1138    LOAD_ATTR                       50: call_chains
                        1158    LOAD_ATTR                       53: add
                        1178    LOAD_FAST                       2: temp_call_chain
                        1180    CALL                            1
                        1188    POP_TOP                         
                        1190    LOAD_CONST                      0: None
                        1192    NOP                             
                        1194    NOP                             
                        1196    NOP                             
                        1198    JUMP_FORWARD                    24 (to 1248)
                        1206    POP_TOP                         
                        1208    RETURN_CONST                    0: None
                        1210    SWAP                            2
                        1212    POP_TOP                         
                        1214    SWAP                            2
                        1216    STORE_FAST                      6: _var_var_68
                        1218    RERAISE                         0
                        1220    PUSH_EXC_INFO                   
                        1222    PUSH_NULL                       
                        1224    LOAD_CONST                      4: '__pyarmor_exit_55218__'
                        1226    NOP                             
                        1228    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x04\x00\x00\x00\x00\x00\x00'
                        1230    CALL                            1
                        1238    POP_TOP                         
                        1240    RERAISE                         0
                        1242    COPY                            3
                        1244    POP_EXCEPT                      
                        1246    RERAISE                         1
                        1248    PUSH_NULL                       
                        1250    LOAD_CONST                      4: '__pyarmor_exit_55218__'
                        1252    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x04\x00\x00\x00\x00\x00\x00'
                        1254    BUILD_TUPLE                     1
                        1256    CALL_FUNCTION_EX                0
                        1258    POP_TOP                         
                        1260    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: build_context_backward
                    Qualified Name: ContextBuilder.build_context_backward
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'limited_funcs'
                        'abs'
                        'MAX_TRACE_CALLER_DEPTH'
                        'ida_funcs'
                        'get_func'
                        'start_ea'
                        'context_caller_funcs'
                        'idautils'
                        'CodeRefsTo'
                        'idaapi'
                        'BADADDR'
                        'idc'
                        'get_func_name'
                        'demangle'
                        'build_context_backward'
                        'call_chains'
                        'add'
                    [Locals+Names]
                        'self'
                        'func_ea'
                        'temp_call_chain'
                        'depth'
                        '__assert_armored__'
                        '_var_var_66'
                        '_var_var_70'
                        '_var_var_71'
                        '_var_var_72'
                        '_var_var_73'
                    [Constants]
                        None
                        '__pyarmor_assert_55219__'
                        '__pyarmor_enter_55220__'
                        b'<COAddr>\x01\x00\x00\x1aZ\x03\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55221__'
                        False
                        1
                        True
                        '-->'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55220__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x03\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: limited_funcs
                        50      POP_JUMP_IF_FALSE               25 (to 102)
                        52      LOAD_FAST                       1: func_ea
                        54      LOAD_FAST                       0: self
                        56      LOAD_ATTR                       0: limited_funcs
                        76      CONTAINS_OP                     1 (not in)
                        78      POP_JUMP_IF_FALSE               11 (to 102)
                        80      NOP                             
                        82      LOAD_CONST                      0: None
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    410 (to 912)
                        98      POP_TOP                         
                        100     RETURN_CONST                    0: None
                        102     LOAD_GLOBAL                     3: NULL + abs
                        112     LOAD_FAST                       3: depth
                        114     CALL                            1
                        122     LOAD_FAST                       0: self
                        124     LOAD_ATTR                       4: MAX_TRACE_CALLER_DEPTH
                        144     COMPARE_OP                      68 (>)
                        148     POP_JUMP_IF_FALSE               11 (to 172)
                        150     NOP                             
                        152     LOAD_CONST                      0: None
                        154     NOP                             
                        156     NOP                             
                        158     JUMP_FORWARD                    375 (to 912)
                        168     POP_TOP                         
                        170     RETURN_CONST                    0: None
                        172     LOAD_GLOBAL                     7: NULL + ida_funcs
                        182     LOAD_ATTR                       8: get_func
                        202     LOAD_FAST                       1: func_ea
                        204     CALL                            1
                        212     STORE_FAST                      5: _var_var_66
                        214     LOAD_FAST                       5: _var_var_66
                        216     POP_JUMP_IF_TRUE                11 (to 240)
                        218     NOP                             
                        220     LOAD_CONST                      0: None
                        222     NOP                             
                        224     NOP                             
                        226     JUMP_FORWARD                    341 (to 912)
                        236     POP_TOP                         
                        238     RETURN_CONST                    0: None
                        240     LOAD_FAST                       5: _var_var_66
                        242     LOAD_ATTR                       10: start_ea
                        262     STORE_FAST                      1: func_ea
                        264     LOAD_FAST                       1: func_ea
                        266     LOAD_FAST                       0: self
                        268     LOAD_ATTR                       12: context_caller_funcs
                        288     CONTAINS_OP                     1 (not in)
                        290     POP_JUMP_IF_TRUE                27 (to 346)
                        292     LOAD_FAST                       0: self
                        294     LOAD_ATTR                       12: context_caller_funcs
                        314     LOAD_FAST                       1: func_ea
                        316     BINARY_SUBSCR                   
                        320     LOAD_GLOBAL                     3: NULL + abs
                        330     LOAD_FAST                       3: depth
                        332     CALL                            1
                        340     COMPARE_OP                      2 (<)
                        344     POP_JUMP_IF_FALSE               15 (to 376)
                        346     LOAD_FAST                       3: depth
                        348     LOAD_FAST                       0: self
                        350     LOAD_ATTR                       12: context_caller_funcs
                        370     LOAD_FAST                       1: func_ea
                        372     STORE_SUBSCR                    
                        376     LOAD_CONST                      5: False
                        378     STORE_FAST                      6: _var_var_70
                        380     LOAD_GLOBAL                     15: NULL + idautils
                        390     LOAD_ATTR                       16: CodeRefsTo
                        410     LOAD_FAST                       1: func_ea
                        412     LOAD_CONST                      6: 1
                        414     CALL                            2
                        422     GET_ITER                        
                        424     FOR_ITER                        123 (to 672)
                        428     STORE_FAST                      7: _var_var_71
                        430     LOAD_FAST                       7: _var_var_71
                        432     LOAD_GLOBAL                     18: idaapi
                        442     LOAD_ATTR                       20: BADADDR
                        462     COMPARE_OP                      40 (==)
                        466     POP_JUMP_IF_FALSE               1 (to 470)
                        468     JUMP_BACKWARD                   23 (to 424)
                        470     LOAD_GLOBAL                     7: NULL + ida_funcs
                        480     LOAD_ATTR                       8: get_func
                        500     LOAD_FAST                       7: _var_var_71
                        502     CALL                            1
                        510     STORE_FAST                      8: _var_var_72
                        512     LOAD_FAST                       8: _var_var_72
                        514     POP_JUMP_IF_TRUE                1 (to 518)
                        516     JUMP_BACKWARD                   47 (to 424)
                        518     LOAD_FAST                       8: _var_var_72
                        520     LOAD_ATTR                       10: start_ea
                        540     STORE_FAST                      7: _var_var_71
                        542     LOAD_GLOBAL                     23: NULL + idc
                        552     LOAD_ATTR                       24: get_func_name
                        572     LOAD_FAST                       7: _var_var_71
                        574     CALL                            1
                        582     STORE_FAST                      9: _var_var_73
                        584     LOAD_FAST                       9: _var_var_73
                        586     POP_JUMP_IF_TRUE                1 (to 590)
                        588     JUMP_BACKWARD                   83 (to 424)
                        590     LOAD_CONST                      7: True
                        592     STORE_FAST                      6: _var_var_70
                        594     LOAD_GLOBAL                     27: NULL + demangle
                        604     LOAD_FAST                       9: _var_var_73
                        606     CALL                            1
                        614     STORE_FAST                      9: _var_var_73
                        616     LOAD_FAST                       0: self
                        618     LOAD_ATTR                       29: build_context_backward
                        638     LOAD_FAST                       7: _var_var_71
                        640     LOAD_FAST                       9: _var_var_73
                        642     LOAD_CONST                      8: '-->'
                        644     BINARY_OP                       0 (+)
                        648     LOAD_FAST                       2: temp_call_chain
                        650     BINARY_OP                       0 (+)
                        654     LOAD_FAST                       3: depth
                        656     LOAD_CONST                      6: 1
                        658     BINARY_OP                       10 (-)
                        662     CALL                            3
                        670     POP_TOP                         
                        672     JUMP_BACKWARD                   125 (to 424)
                        674     END_FOR                         
                        676     LOAD_GLOBAL                     3: NULL + abs
                        686     LOAD_FAST                       3: depth
                        688     CALL                            1
                        696     LOAD_FAST                       0: self
                        698     LOAD_ATTR                       4: MAX_TRACE_CALLER_DEPTH
                        718     COMPARE_OP                      40 (==)
                        722     POP_JUMP_IF_FALSE               27 (to 778)
                        724     LOAD_FAST                       0: self
                        726     LOAD_ATTR                       30: call_chains
                        746     LOAD_ATTR                       33: add
                        766     LOAD_FAST                       2: temp_call_chain
                        768     CALL                            1
                        776     POP_TOP                         
                        778     LOAD_GLOBAL                     3: NULL + abs
                        788     LOAD_FAST                       3: depth
                        790     CALL                            1
                        798     LOAD_CONST                      6: 1
                        800     COMPARE_OP                      92 (>=)
                        804     POP_JUMP_IF_FALSE               29 (to 864)
                        806     LOAD_FAST                       6: _var_var_70
                        808     POP_JUMP_IF_TRUE                27 (to 864)
                        810     LOAD_FAST                       0: self
                        812     LOAD_ATTR                       30: call_chains
                        832     LOAD_ATTR                       33: add
                        852     LOAD_FAST                       2: temp_call_chain
                        854     CALL                            1
                        862     POP_TOP                         
                        864     LOAD_CONST                      0: None
                        866     NOP                             
                        868     NOP                             
                        870     NOP                             
                        872     JUMP_FORWARD                    19 (to 912)
                        880     POP_TOP                         
                        882     RETURN_CONST                    0: None
                        884     PUSH_EXC_INFO                   
                        886     PUSH_NULL                       
                        888     LOAD_CONST                      4: '__pyarmor_exit_55221__'
                        890     NOP                             
                        892     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x03\x00\x00\x00\x00\x00\x00'
                        894     CALL                            1
                        902     POP_TOP                         
                        904     RERAISE                         0
                        906     COPY                            3
                        908     POP_EXCEPT                      
                        910     RERAISE                         1
                        912     PUSH_NULL                       
                        914     LOAD_CONST                      4: '__pyarmor_exit_55221__'
                        916     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x03\x00\x00\x00\x00\x00\x00'
                        918     BUILD_TUPLE                     1
                        920     CALL_FUNCTION_EX                0
                        922     POP_TOP                         
                        924     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: build_context
                    Qualified Name: ContextBuilder.build_context
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'dict'
                        'context_callee_funcs'
                        'defaultdict'
                        'int'
                        'context_caller_funcs'
                        'set'
                        'call_chains'
                        'demangle'
                        'idc'
                        'get_func_name'
                        'build_context_forward'
                        'build_context_backward'
                    [Locals+Names]
                        'self'
                        'func_ea'
                        '__assert_armored__'
                        '_var_var_74'
                    [Constants]
                        None
                        '__pyarmor_assert_55222__'
                        '__pyarmor_enter_55223__'
                        b'<COAddr>\x03\x00\x00\x1a\x02\x01\x00\x00\x00\x00\x00\x00'
                        0
                        '__pyarmor_exit_55224__'
                        True
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55223__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x02\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + dict
                        38      CALL                            0
                        46      LOAD_FAST                       0: self
                        48      STORE_ATTR                      1: context_callee_funcs
                        58      LOAD_GLOBAL                     5: NULL + defaultdict
                        68      LOAD_GLOBAL                     6: int
                        78      CALL                            1
                        86      LOAD_FAST                       0: self
                        88      STORE_ATTR                      4: context_caller_funcs
                        98      LOAD_GLOBAL                     11: NULL + set
                        108     CALL                            0
                        116     LOAD_FAST                       0: self
                        118     STORE_ATTR                      6: call_chains
                        128     LOAD_GLOBAL                     15: NULL + demangle
                        138     LOAD_GLOBAL                     17: NULL + idc
                        148     LOAD_ATTR                       18: get_func_name
                        168     LOAD_FAST                       1: func_ea
                        170     CALL                            1
                        178     CALL                            1
                        186     STORE_FAST                      3: _var_var_74
                        188     LOAD_FAST                       0: self
                        190     LOAD_ATTR                       21: build_context_forward
                        210     LOAD_FAST                       1: func_ea
                        212     LOAD_FAST                       3: _var_var_74
                        214     LOAD_CONST                      4: 0
                        216     CALL                            3
                        224     POP_TOP                         
                        226     LOAD_FAST                       0: self
                        228     LOAD_ATTR                       23: build_context_backward
                        248     LOAD_FAST                       1: func_ea
                        250     LOAD_FAST                       3: _var_var_74
                        252     LOAD_CONST                      4: 0
                        254     CALL                            3
                        262     POP_TOP                         
                        264     LOAD_CONST                      6: True
                        266     NOP                             
                        268     NOP                             
                        270     NOP                             
                        272     JUMP_FORWARD                    19 (to 312)
                        280     POP_TOP                         
                        282     RETURN_CONST                    6: True
                        284     PUSH_EXC_INFO                   
                        286     PUSH_NULL                       
                        288     LOAD_CONST                      5: '__pyarmor_exit_55224__'
                        290     NOP                             
                        292     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x02\x01\x00\x00\x00\x00\x00\x00'
                        294     CALL                            1
                        302     POP_TOP                         
                        304     RERAISE                         0
                        306     COPY                            3
                        308     POP_EXCEPT                      
                        310     RERAISE                         1
                        312     PUSH_NULL                       
                        314     LOAD_CONST                      5: '__pyarmor_exit_55224__'
                        316     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x02\x01\x00\x00\x00\x00\x00\x00'
                        318     BUILD_TUPLE                     1
                        320     CALL_FUNCTION_EX                0
                        322     POP_TOP                         
                        324     RETURN_VALUE                    
                'return'
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: get_context_pcode
                    Qualified Name: ContextBuilder.get_context_pcode
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_funcs'
                        'get_func'
                        'start_ea'
                        'get_incontext_funcs'
                        'remove'
                        'MAX_CONTEXT_FUNC_NUM'
                        'len'
                        'copy'
                        'measure_informative_score'
                        'items'
                        'sorted'
                        'set'
                        'build_pcode_with_struct_and_enum'
                        'add'
                        'append'
                    [Locals+Names]
                        'self'
                        'target_func_ea'
                        'analyzed_funcs_in_dataflow'
                        '__assert_armored__'
                        '_var_var_66'
                        '_var_var_76'
                        '_var_var_77'
                        '_var_var_78'
                        '_var_var_79'
                        '_var_var_80'
                        '_var_var_81'
                        '_var_var_82'
                        '_var_var_83'
                        '_var_var_84'
                        '_var_var_85'
                        '_var_var_75'
                    [Constants]
                        None
                        '__pyarmor_assert_55225__'
                        '__pyarmor_enter_55226__'
                        b'<COAddr>\x03\x00\x00\x1c\xca\x03\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_55227__'
                        (
                            None
                            None
                            None
                        )
                        0
                        1
                        [Code]
                            File Name: <frozen ..ext_info>
                            Object Name: <lambda>
                            Qualified Name: ContextBuilder.get_context_pcode.<locals>.<lambda>
                            Arg Count: 1
                            Pos Only Arg Count: 0
                            KW Only Arg Count: 0
                            Stack Size: 2
                            Flags: 0x00000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED)
                            [Names]
                            [Locals+Names]
                                'x'
                                '_var_var_75'
                            [Constants]
                                None
                            [Disassembly]
                                0       COPY_FREE_VARS                  1
                                2       RESUME                          0
                                4       LOAD_DEREF                      1: _var_var_75
                                6       LOAD_FAST                       0: x
                                8       BINARY_SUBSCR                   
                                12      RETURN_VALUE                    
                        True
                        (
                            'key'
                            'reverse'
                        )
                        ''
                        'struct_enum_dict'
                        '\n'
                        'pcode'
                        '\n\n'
                    [Disassembly]
                        0       MAKE_CELL                       15: _var_var_75
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_55226__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xca\x03\x00\x00\x00\x00\x00\x00'
                        12      BUILD_TUPLE                     1
                        14      CALL_FUNCTION_EX                0
                        16      POP_TOP                         
                        18      RESUME                          0
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      LOAD_GLOBAL                     1: NULL + ida_funcs
                        40      LOAD_ATTR                       2: get_func
                        60      LOAD_FAST                       1: target_func_ea
                        62      CALL                            1
                        70      STORE_FAST                      4: _var_var_66
                        72      LOAD_FAST                       4: _var_var_66
                        74      POP_JUMP_IF_TRUE                11 (to 98)
                        76      NOP                             
                        78      LOAD_CONST                      5: (None, None, None)
                        80      NOP                             
                        82      NOP                             
                        84      JUMP_FORWARD                    469 (to 1026)
                        94      POP_TOP                         
                        96      RETURN_CONST                    5: (None, None, None)
                        98      LOAD_FAST                       4: _var_var_66
                        100     LOAD_ATTR                       4: start_ea
                        120     STORE_FAST                      1: target_func_ea
                        122     LOAD_FAST                       0: self
                        124     LOAD_ATTR                       7: get_incontext_funcs
                        144     CALL                            0
                        152     STORE_FAST                      5: _var_var_76
                        154     LOAD_FAST                       1: target_func_ea
                        156     LOAD_FAST                       5: _var_var_76
                        158     CONTAINS_OP                     0 (in)
                        160     POP_JUMP_IF_FALSE               17 (to 196)
                        162     LOAD_FAST                       5: _var_var_76
                        164     LOAD_ATTR                       9: remove
                        184     LOAD_FAST                       1: target_func_ea
                        186     CALL                            1
                        194     POP_TOP                         
                        196     LOAD_FAST                       0: self
                        198     LOAD_ATTR                       10: MAX_CONTEXT_FUNC_NUM
                        218     LOAD_CONST                      6: 0
                        220     COMPARE_OP                      92 (>=)
                        224     POP_JUMP_IF_FALSE               163 (to 552)
                        226     LOAD_GLOBAL                     13: NULL + len
                        236     LOAD_FAST                       5: _var_var_76
                        238     CALL                            1
                        246     LOAD_FAST                       0: self
                        248     LOAD_ATTR                       10: MAX_CONTEXT_FUNC_NUM
                        268     COMPARE_OP                      68 (>)
                        272     POP_JUMP_IF_FALSE               139 (to 552)
                        274     LOAD_FAST                       5: _var_var_76
                        276     LOAD_ATTR                       15: copy
                        296     CALL                            0
                        304     STORE_FAST                      6: _var_var_77
                        306     LOAD_FAST                       6: _var_var_77
                        308     GET_ITER                        
                        310     LOAD_FAST_AND_CLEAR             7: _var_var_78
                        312     SWAP                            2
                        314     BUILD_MAP                       0
                        316     SWAP                            2
                        318     FOR_ITER                        14 (to 348)
                        322     STORE_FAST                      7: _var_var_78
                        324     LOAD_FAST                       7: _var_var_78
                        326     LOAD_GLOBAL                     17: NULL + measure_informative_score
                        336     LOAD_FAST                       7: _var_var_78
                        338     CALL                            1
                        346     MAP_ADD                         2
                        348     JUMP_BACKWARD                   16 (to 318)
                        350     END_FOR                         
                        352     SWAP                            2
                        354     STORE_FAST                      7: _var_var_78
                        356     STORE_DEREF                     15: _var_var_75
                        358     LOAD_DEREF                      15: _var_var_75
                        360     LOAD_ATTR                       19: items
                        380     CALL                            0
                        388     GET_ITER                        
                        390     LOAD_FAST_AND_CLEAR             7: _var_var_78
                        392     LOAD_FAST_AND_CLEAR             8: _var_var_79
                        394     SWAP                            3
                        396     BUILD_MAP                       0
                        398     SWAP                            2
                        400     FOR_ITER                        17 (to 436)
                        404     UNPACK_SEQUENCE                 2
                        408     STORE_FAST                      7: _var_var_78
                        410     STORE_FAST                      8: _var_var_79
                        412     LOAD_FAST                       7: _var_var_78
                        414     LOAD_FAST                       7: _var_var_78
                        416     LOAD_FAST                       2: analyzed_funcs_in_dataflow
                        418     CONTAINS_OP                     0 (in)
                        420     POP_JUMP_IF_FALSE               5 (to 432)
                        422     LOAD_FAST                       8: _var_var_79
                        424     LOAD_CONST                      7: 1
                        426     BINARY_OP                       0 (+)
                        430     JUMP_FORWARD                    1 (to 434)
                        432     LOAD_FAST                       8: _var_var_79
                        434     MAP_ADD                         2
                        436     JUMP_BACKWARD                   19 (to 400)
                        438     END_FOR                         
                        440     SWAP                            3
                        442     STORE_FAST                      8: _var_var_79
                        444     STORE_FAST                      7: _var_var_78
                        446     STORE_DEREF                     15: _var_var_75
                        448     LOAD_GLOBAL                     21: NULL + sorted
                        458     LOAD_FAST                       6: _var_var_77
                        460     LOAD_CLOSURE                    15: _var_var_75
                        462     BUILD_TUPLE                     1
                        464     LOAD_CONST                      8: <CODE> <lambda>
                        466     MAKE_FUNCTION                   8
                        468     LOAD_CONST                      9: True
                        470     KW_NAMES                        10: ('key', 'reverse')
                        472     CALL                            3
                        480     STORE_FAST                      6: _var_var_77
                        482     LOAD_FAST                       6: _var_var_77
                        484     LOAD_CONST                      0: None
                        486     LOAD_FAST                       0: self
                        488     LOAD_ATTR                       10: MAX_CONTEXT_FUNC_NUM
                        508     BINARY_SLICE                    
                        510     STORE_FAST                      6: _var_var_77
                        512     LOAD_FAST                       5: _var_var_76
                        514     GET_ITER                        
                        516     LOAD_FAST_AND_CLEAR             7: _var_var_78
                        518     SWAP                            2
                        520     BUILD_LIST                      0
                        522     SWAP                            2
                        524     FOR_ITER                        9 (to 544)
                        528     STORE_FAST                      7: _var_var_78
                        530     LOAD_FAST                       7: _var_var_78
                        532     LOAD_FAST                       6: _var_var_77
                        534     CONTAINS_OP                     0 (in)
                        536     POP_JUMP_IF_TRUE                1 (to 540)
                        538     JUMP_BACKWARD                   8 (to 524)
                        540     LOAD_FAST                       7: _var_var_78
                        542     LIST_APPEND                     2
                        544     JUMP_BACKWARD                   11 (to 524)
                        546     END_FOR                         
                        548     STORE_FAST                      5: _var_var_76
                        550     STORE_FAST                      7: _var_var_78
                        552     LOAD_CONST                      11: ''
                        554     STORE_FAST                      9: _var_var_80
                        556     LOAD_GLOBAL                     23: NULL + set
                        566     CALL                            0
                        574     STORE_FAST                      10: _var_var_81
                        576     LOAD_FAST                       5: _var_var_76
                        578     GET_ITER                        
                        580     FOR_ITER                        81 (to 744)
                        584     STORE_FAST                      7: _var_var_78
                        586     LOAD_GLOBAL                     25: NULL + build_pcode_with_struct_and_enum
                        596     LOAD_FAST                       7: _var_var_78
                        598     CALL                            1
                        606     STORE_FAST                      11: _var_var_82
                        608     LOAD_FAST                       11: _var_var_82
                        610     LOAD_CONST                      12: 'struct_enum_dict'
                        612     BINARY_SUBSCR                   
                        616     LOAD_ATTR                       19: items
                        636     CALL                            0
                        644     GET_ITER                        
                        646     FOR_ITER                        35 (to 718)
                        650     UNPACK_SEQUENCE                 2
                        654     STORE_FAST                      12: _var_var_83
                        656     STORE_FAST                      13: _var_var_84
                        658     LOAD_FAST                       12: _var_var_83
                        660     LOAD_FAST                       10: _var_var_81
                        662     CONTAINS_OP                     1 (not in)
                        664     POP_JUMP_IF_TRUE                1 (to 668)
                        666     JUMP_BACKWARD                   11 (to 646)
                        668     LOAD_FAST                       9: _var_var_80
                        670     LOAD_FAST                       13: _var_var_84
                        672     LOAD_CONST                      13: '\n'
                        674     BINARY_OP                       0 (+)
                        678     BINARY_OP                       13 (+=)
                        682     STORE_FAST                      9: _var_var_80
                        684     LOAD_FAST                       10: _var_var_81
                        686     LOAD_ATTR                       27: add
                        706     LOAD_FAST                       12: _var_var_83
                        708     CALL                            1
                        716     POP_TOP                         
                        718     JUMP_BACKWARD                   37 (to 646)
                        720     END_FOR                         
                        722     LOAD_FAST                       9: _var_var_80
                        724     LOAD_FAST                       11: _var_var_82
                        726     LOAD_CONST                      14: 'pcode'
                        728     BINARY_SUBSCR                   
                        732     LOAD_CONST                      15: '\n\n'
                        734     BINARY_OP                       0 (+)
                        738     BINARY_OP                       13 (+=)
                        742     STORE_FAST                      9: _var_var_80
                        744     JUMP_BACKWARD                   83 (to 580)
                        746     END_FOR                         
                        748     LOAD_CONST                      11: ''
                        750     STORE_FAST                      14: _var_var_85
                        752     LOAD_GLOBAL                     25: NULL + build_pcode_with_struct_and_enum
                        762     LOAD_FAST                       1: target_func_ea
                        764     CALL                            1
                        772     STORE_FAST                      11: _var_var_82
                        774     LOAD_FAST                       11: _var_var_82
                        776     LOAD_CONST                      12: 'struct_enum_dict'
                        778     BINARY_SUBSCR                   
                        782     LOAD_ATTR                       19: items
                        802     CALL                            0
                        810     GET_ITER                        
                        812     FOR_ITER                        35 (to 884)
                        816     UNPACK_SEQUENCE                 2
                        820     STORE_FAST                      12: _var_var_83
                        822     STORE_FAST                      13: _var_var_84
                        824     LOAD_FAST                       12: _var_var_83
                        826     LOAD_FAST                       10: _var_var_81
                        828     CONTAINS_OP                     1 (not in)
                        830     POP_JUMP_IF_TRUE                1 (to 834)
                        832     JUMP_BACKWARD                   11 (to 812)
                        834     LOAD_FAST                       14: _var_var_85
                        836     LOAD_FAST                       13: _var_var_84
                        838     LOAD_CONST                      13: '\n'
                        840     BINARY_OP                       0 (+)
                        844     BINARY_OP                       13 (+=)
                        848     STORE_FAST                      14: _var_var_85
                        850     LOAD_FAST                       10: _var_var_81
                        852     LOAD_ATTR                       27: add
                        872     LOAD_FAST                       12: _var_var_83
                        874     CALL                            1
                        882     POP_TOP                         
                        884     JUMP_BACKWARD                   37 (to 812)
                        886     END_FOR                         
                        888     LOAD_FAST                       14: _var_var_85
                        890     LOAD_FAST                       11: _var_var_82
                        892     LOAD_CONST                      14: 'pcode'
                        894     BINARY_SUBSCR                   
                        898     BINARY_OP                       13 (+=)
                        902     STORE_FAST                      14: _var_var_85
                        904     LOAD_FAST                       5: _var_var_76
                        906     LOAD_ATTR                       29: append
                        926     LOAD_FAST                       1: target_func_ea
                        928     CALL                            1
                        936     POP_TOP                         
                        938     LOAD_FAST                       9: _var_var_80
                        940     LOAD_FAST                       14: _var_var_85
                        942     LOAD_FAST                       5: _var_var_76
                        944     BUILD_TUPLE                     3
                        946     NOP                             
                        948     NOP                             
                        950     NOP                             
                        952     JUMP_FORWARD                    36 (to 1026)
                        954     CALL                            1
                        962     POP_TOP                         
                        964     RETURN_VALUE                    
                        966     SWAP                            2
                        968     POP_TOP                         
                        970     SWAP                            2
                        972     STORE_FAST                      7: _var_var_78
                        974     RERAISE                         0
                        976     SWAP                            2
                        978     POP_TOP                         
                        980     SWAP                            3
                        982     STORE_FAST                      8: _var_var_79
                        984     STORE_FAST                      7: _var_var_78
                        986     RERAISE                         0
                        988     SWAP                            2
                        990     POP_TOP                         
                        992     SWAP                            2
                        994     STORE_FAST                      7: _var_var_78
                        996     RERAISE                         0
                        998     PUSH_EXC_INFO                   
                        1000    PUSH_NULL                       
                        1002    LOAD_CONST                      4: '__pyarmor_exit_55227__'
                        1004    NOP                             
                        1006    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xca\x03\x00\x00\x00\x00\x00\x00'
                        1008    CALL                            1
                        1016    POP_TOP                         
                        1018    RERAISE                         0
                        1020    COPY                            3
                        1022    POP_EXCEPT                      
                        1024    RERAISE                         1
                        1026    PUSH_NULL                       
                        1028    LOAD_CONST                      4: '__pyarmor_exit_55227__'
                        1030    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xca\x03\x00\x00\x00\x00\x00\x00'
                        1032    BUILD_TUPLE                     1
                        1034    CALL_FUNCTION_EX                0
                        1036    POP_TOP                         
                        1038    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: get_call_chains
                    Qualified Name: ContextBuilder.get_call_chains
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'join'
                        'call_chains'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_55228__'
                        '__pyarmor_enter_55229__'
                        b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        '\n'
                        '__pyarmor_exit_55230__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_55229__'
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
                        28      LOAD_CONST                      4: '\n'
                        30      LOAD_ATTR                       1: join
                        50      LOAD_FAST                       0: self
                        52      LOAD_ATTR                       2: call_chains
                        72      CALL                            1
                        80      NOP                             
                        82      NOP                             
                        84      NOP                             
                        86      JUMP_FORWARD                    20 (to 128)
                        88      CALL                            1
                        96      POP_TOP                         
                        98      RETURN_VALUE                    
                        100     PUSH_EXC_INFO                   
                        102     PUSH_NULL                       
                        104     LOAD_CONST                      5: '__pyarmor_exit_55230__'
                        106     NOP                             
                        108     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        110     CALL                            1
                        118     POP_TOP                         
                        120     RERAISE                         0
                        122     COPY                            3
                        124     POP_EXCEPT                      
                        126     RERAISE                         1
                        128     PUSH_NULL                       
                        130     LOAD_CONST                      5: '__pyarmor_exit_55230__'
                        132     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        134     BUILD_TUPLE                     1
                        136     CALL_FUNCTION_EX                0
                        138     POP_TOP                         
                        140     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..ext_info>
                    Object Name: get_incontext_funcs
                    Qualified Name: ContextBuilder.get_incontext_funcs
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'set'
                        'context_callee_funcs'
                        'keys'
                        'context_caller_funcs'
                        'sorted'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_86'
                    [Constants]
                        '\n        按keys(ea)去重，按values(depth)排序，value的绝对值大的在前\n        '
                        '__pyarmor_assert_55231__'
                        '__pyarmor_enter_55232__'
                        b'<COAddr>\x03\x00\x00\x1c\xc8\x00\x00\x00\x00\x00\x00\x00'
                        [Code]
                            File Name: <frozen ..ext_info>
                            Object Name: <lambda>
                            Qualified Name: ContextBuilder.get_incontext_funcs.<locals>.<lambda>
                            Arg Count: 1
                            Pos Only Arg Count: 0
                            KW Only Arg Count: 0
                            Stack Size: 9
                            Flags: 0x00000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED)
                            [Names]
                                'max'
                                'context_callee_funcs'
                                'get'
                                'abs'
                                'context_caller_funcs'
                            [Locals+Names]
                                'x'
                                'self'
                            [Constants]
                                None
                                0
                            [Disassembly]
                                0       COPY_FREE_VARS                  1
                                2       RESUME                          0
                                4       LOAD_GLOBAL                     1: NULL + max
                                14      LOAD_DEREF                      1: self
                                16      LOAD_ATTR                       2: context_callee_funcs
                                36      LOAD_ATTR                       5: get
                                56      LOAD_FAST                       0: x
                                58      LOAD_CONST                      1: 0
                                60      CALL                            2
                                68      LOAD_GLOBAL                     7: NULL + abs
                                78      LOAD_DEREF                      1: self
                                80      LOAD_ATTR                       8: context_caller_funcs
                                100     LOAD_ATTR                       5: get
                                120     LOAD_FAST                       0: x
                                122     LOAD_CONST                      1: 0
                                124     CALL                            2
                                132     CALL                            1
                                140     CALL                            2
                                148     RETURN_VALUE                    
                        True
                        (
                            'key'
                            'reverse'
                        )
                        '__pyarmor_exit_55233__'
                    [Disassembly]
                        0       MAKE_CELL                       0: self
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_55232__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xc8\x00\x00\x00\x00\x00\x00\x00'
                        12      BUILD_TUPLE                     1
                        14      CALL_FUNCTION_EX                0
                        16      POP_TOP                         
                        18      RESUME                          0
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      LOAD_GLOBAL                     1: NULL + set
                        40      LOAD_DEREF                      0: self
                        42      LOAD_ATTR                       2: context_callee_funcs
                        62      LOAD_ATTR                       5: keys
                        82      CALL                            0
                        90      CALL                            1
                        98      LOAD_GLOBAL                     1: NULL + set
                        108     LOAD_DEREF                      0: self
                        110     LOAD_ATTR                       6: context_caller_funcs
                        130     LOAD_ATTR                       5: keys
                        150     CALL                            0
                        158     CALL                            1
                        166     BINARY_OP                       7 (|)
                        170     STORE_FAST                      2: _var_var_86
                        172     LOAD_GLOBAL                     9: NULL + sorted
                        182     LOAD_FAST                       2: _var_var_86
                        184     LOAD_CLOSURE                    0: self
                        186     BUILD_TUPLE                     1
                        188     LOAD_CONST                      4: <CODE> <lambda>
                        190     MAKE_FUNCTION                   8
                        192     LOAD_CONST                      5: True
                        194     KW_NAMES                        6: ('key', 'reverse')
                        196     CALL                            3
                        204     STORE_FAST                      2: _var_var_86
                        206     LOAD_FAST                       2: _var_var_86
                        208     NOP                             
                        210     NOP                             
                        212     NOP                             
                        214     JUMP_FORWARD                    20 (to 256)
                        216     CALL                            1
                        224     POP_TOP                         
                        226     RETURN_VALUE                    
                        228     PUSH_EXC_INFO                   
                        230     PUSH_NULL                       
                        232     LOAD_CONST                      7: '__pyarmor_exit_55233__'
                        234     NOP                             
                        236     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xc8\x00\x00\x00\x00\x00\x00\x00'
                        238     CALL                            1
                        246     POP_TOP                         
                        248     RERAISE                         0
                        250     COPY                            3
                        252     POP_EXCEPT                      
                        254     RERAISE                         1
                        256     PUSH_NULL                       
                        258     LOAD_CONST                      7: '__pyarmor_exit_55233__'
                        260     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xc8\x00\x00\x00\x00\x00\x00\x00'
                        262     BUILD_TUPLE                     1
                        264     CALL_FUNCTION_EX                0
                        266     POP_TOP                         
                        268     RETURN_VALUE                    
                '__pyarmor_exit_55212__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'ContextBuilder'
                8       STORE_NAME                      2: __qualname__
                10      LOAD_CONST                      1: '\n    build pseudo-code context and call-chains for the target function\n    '
                12      STORE_NAME                      3: __doc__
                14      NOP                             
                16      PUSH_NULL                       
                18      LOAD_CONST                      3: '__pyarmor_enter_55211__'
                20      LOAD_CONST                      4: b'<COAddr>\x01\x00\x00&n\x00\x00\x00\x00\x00\x00\x00'
                22      BUILD_TUPLE                     1
                24      CALL_FUNCTION_EX                0
                26      POP_TOP                         
                28      RESUME                          0
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      NOP                             
                40      PUSH_NULL                       
                42      LOAD_NAME                       5: set
                44      CALL                            0
                52      BUILD_TUPLE                     1
                54      LOAD_CONST                      5: <CODE> __init__
                56      MAKE_FUNCTION                   1
                58      STORE_NAME                      6: __init__
                60      LOAD_CONST                      6: <CODE> build_context_forward
                62      MAKE_FUNCTION                   0
                64      STORE_NAME                      7: build_context_forward
                66      LOAD_CONST                      7: <CODE> build_context_backward
                68      MAKE_FUNCTION                   0
                70      STORE_NAME                      8: build_context_backward
                72      LOAD_CONST                      8: <CODE> build_context
                74      MAKE_FUNCTION                   0
                76      STORE_NAME                      9: build_context
                78      PUSH_NULL                       
                80      LOAD_NAME                       5: set
                82      CALL                            0
                90      BUILD_TUPLE                     1
                92      LOAD_CONST                      9: 'return'
                94      LOAD_NAME                       10: str
                96      BUILD_TUPLE                     2
                98      LOAD_CONST                      10: <CODE> get_context_pcode
                100     MAKE_FUNCTION                   5
                102     STORE_NAME                      11: get_context_pcode
                104     LOAD_CONST                      9: 'return'
                106     LOAD_NAME                       10: str
                108     BUILD_TUPLE                     2
                110     LOAD_CONST                      11: <CODE> get_call_chains
                112     MAKE_FUNCTION                   4
                114     STORE_NAME                      12: get_call_chains
                116     LOAD_CONST                      9: 'return'
                118     LOAD_NAME                       13: list
                120     BUILD_TUPLE                     2
                122     LOAD_CONST                      12: <CODE> get_incontext_funcs
                124     MAKE_FUNCTION                   4
                126     STORE_NAME                      14: get_incontext_funcs
                128     LOAD_CONST                      14: None
                130     NOP                             
                132     NOP                             
                134     NOP                             
                136     JUMP_FORWARD                    19 (to 176)
                144     POP_TOP                         
                146     RETURN_CONST                    14: None
                148     PUSH_EXC_INFO                   
                150     PUSH_NULL                       
                152     LOAD_CONST                      13: '__pyarmor_exit_55212__'
                154     NOP                             
                156     LOAD_CONST                      4: b'<COAddr>\x01\x00\x00&n\x00\x00\x00\x00\x00\x00\x00'
                158     CALL                            1
                166     POP_TOP                         
                168     RERAISE                         0
                170     COPY                            3
                172     POP_EXCEPT                      
                174     RERAISE                         1
                176     PUSH_NULL                       
                178     LOAD_CONST                      13: '__pyarmor_exit_55212__'
                180     LOAD_CONST                      4: b'<COAddr>\x01\x00\x00&n\x00\x00\x00\x00\x00\x00\x00'
                182     BUILD_TUPLE                     1
                184     CALL_FUNCTION_EX                0
                186     POP_TOP                         
                188     RETURN_VALUE                    
        'ContextBuilder'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_numbers_from_pcode
            Qualified Name: get_numbers_from_pcode
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'enumerate'
                'split'
                're'
                'findall'
                'append'
            [Locals+Names]
                'pcode'
                '__assert_armored__'
                '_var_var_87'
                '_var_var_88'
                '_var_var_89'
                '_var_var_90'
                '_var_var_91'
            [Constants]
                None
                '__pyarmor_assert_55234__'
                '__pyarmor_enter_55235__'
                b'<COAddr>\x01\x00\x00\x1a\xbc\x00\x00\x00\x00\x00\x00\x00'
                '(?<!\\w)[+-]?0[xX][0-9a-fA-F]+(?:uLL|LL)?|(?<!\\w)[+-]?\\d+(?:uLL|LL)?(?!\\w)'
                '\n'
                '__pyarmor_exit_55236__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55235__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbc\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '(?<!\\w)[+-]?0[xX][0-9a-fA-F]+(?:uLL|LL)?|(?<!\\w)[+-]?\\d+(?:uLL|LL)?(?!\\w)'
                30      STORE_FAST                      2: _var_var_87
                32      BUILD_LIST                      0
                34      STORE_FAST                      3: _var_var_88
                36      LOAD_GLOBAL                     1: NULL + enumerate
                46      LOAD_FAST                       0: pcode
                48      LOAD_ATTR                       3: split
                68      LOAD_CONST                      5: '\n'
                70      CALL                            1
                78      CALL                            1
                86      GET_ITER                        
                88      FOR_ITER                        49 (to 188)
                92      UNPACK_SEQUENCE                 2
                96      STORE_FAST                      4: _var_var_89
                98      STORE_FAST                      5: _var_var_90
                100     LOAD_GLOBAL                     5: NULL + re
                110     LOAD_ATTR                       6: findall
                130     LOAD_FAST                       2: _var_var_87
                132     LOAD_FAST                       5: _var_var_90
                134     CALL                            2
                142     GET_ITER                        
                144     FOR_ITER                        19 (to 184)
                148     STORE_FAST                      6: _var_var_91
                150     LOAD_FAST                       3: _var_var_88
                152     LOAD_ATTR                       9: append
                172     LOAD_FAST                       6: _var_var_91
                174     CALL                            1
                182     POP_TOP                         
                184     JUMP_BACKWARD                   21 (to 144)
                186     END_FOR                         
                188     JUMP_BACKWARD                   51 (to 88)
                190     END_FOR                         
                192     LOAD_FAST                       3: _var_var_88
                194     NOP                             
                196     NOP                             
                198     NOP                             
                200     JUMP_FORWARD                    20 (to 242)
                202     CALL                            1
                210     POP_TOP                         
                212     RETURN_VALUE                    
                214     PUSH_EXC_INFO                   
                216     PUSH_NULL                       
                218     LOAD_CONST                      6: '__pyarmor_exit_55236__'
                220     NOP                             
                222     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbc\x00\x00\x00\x00\x00\x00\x00'
                224     CALL                            1
                232     POP_TOP                         
                234     RERAISE                         0
                236     COPY                            3
                238     POP_EXCEPT                      
                240     RERAISE                         1
                242     PUSH_NULL                       
                244     LOAD_CONST                      6: '__pyarmor_exit_55236__'
                246     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbc\x00\x00\x00\x00\x00\x00\x00'
                248     BUILD_TUPLE                     1
                250     CALL_FUNCTION_EX                0
                252     POP_TOP                         
                254     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: get_functions_in_text_like_seg
            Qualified Name: get_functions_in_text_like_seg
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_segment'
                'get_first_seg'
                'get_segm_name'
                'list'
                'idautils'
                'Functions'
                'start_ea'
                'end_ea'
                'extend'
                'get_next_seg'
            [Locals+Names]
                '__assert_armored__'
                '_var_var_92'
                '_var_var_93'
                '_var_var_94'
                '_var_var_95'
            [Constants]
                None
                '__pyarmor_assert_55237__'
                '__pyarmor_enter_55238__'
                b'<COAddr>\x03\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                'text'
                '__pyarmor_exit_55239__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55238__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + ida_segment
                38      LOAD_ATTR                       2: get_first_seg
                58      CALL                            0
                66      STORE_FAST                      1: _var_var_92
                68      BUILD_LIST                      0
                70      STORE_FAST                      2: _var_var_93
                72      LOAD_FAST                       1: _var_var_92
                74      POP_JUMP_IF_FALSE               127 (to 330)
                76      LOAD_GLOBAL                     1: NULL + ida_segment
                86      LOAD_ATTR                       4: get_segm_name
                106     LOAD_FAST                       1: _var_var_92
                108     CALL                            1
                116     STORE_FAST                      3: _var_var_94
                118     LOAD_CONST                      4: 'text'
                120     LOAD_FAST                       3: _var_var_94
                122     CONTAINS_OP                     0 (in)
                124     POP_JUMP_IF_FALSE               68 (to 262)
                126     LOAD_GLOBAL                     7: NULL + list
                136     LOAD_GLOBAL                     9: NULL + idautils
                146     LOAD_ATTR                       10: Functions
                166     LOAD_FAST                       1: _var_var_92
                168     LOAD_ATTR                       12: start_ea
                188     LOAD_FAST                       1: _var_var_92
                190     LOAD_ATTR                       14: end_ea
                210     CALL                            2
                218     CALL                            1
                226     STORE_FAST                      4: _var_var_95
                228     LOAD_FAST                       2: _var_var_93
                230     LOAD_ATTR                       17: extend
                250     LOAD_FAST                       4: _var_var_95
                252     CALL                            1
                260     POP_TOP                         
                262     LOAD_GLOBAL                     1: NULL + ida_segment
                272     LOAD_ATTR                       18: get_next_seg
                292     LOAD_FAST                       1: _var_var_92
                294     LOAD_ATTR                       12: start_ea
                314     CALL                            1
                322     STORE_FAST                      1: _var_var_92
                324     LOAD_FAST                       1: _var_var_92
                326     POP_JUMP_IF_FALSE               1 (to 330)
                328     JUMP_BACKWARD                   127 (to 76)
                330     LOAD_FAST                       2: _var_var_93
                332     NOP                             
                334     NOP                             
                336     NOP                             
                338     JUMP_FORWARD                    20 (to 380)
                340     CALL                            1
                348     POP_TOP                         
                350     RETURN_VALUE                    
                352     PUSH_EXC_INFO                   
                354     PUSH_NULL                       
                356     LOAD_CONST                      5: '__pyarmor_exit_55239__'
                358     NOP                             
                360     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                362     CALL                            1
                370     POP_TOP                         
                372     RERAISE                         0
                374     COPY                            3
                376     POP_EXCEPT                      
                378     RERAISE                         1
                380     PUSH_NULL                       
                382     LOAD_CONST                      5: '__pyarmor_exit_55239__'
                384     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                386     BUILD_TUPLE                     1
                388     CALL_FUNCTION_EX                0
                390     POP_TOP                         
                392     RETURN_VALUE                    
        frozenset({
            'frame_dummy'
            'call_weak_fn'
            '__libc_csu_fini'
            '__libc_csu_init'
            'register_tm_clones'
            'deregister_tm_clones'
            '__do_global_ctors_aux'
            '__do_global_dtors_aux'
            '__x86.get_pc_thunk.ax'
            '__x86.get_pc_thunk.bp'
            '__x86.get_pc_thunk.bx'
            '__x86.get_pc_thunk.cx'
            '__x86.get_pc_thunk.di'
            '__x86.get_pc_thunk.dx'
            '__x86.get_pc_thunk.si'
        })
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: is_good_func_for_build_input
            Qualified Name: is_good_func_for_build_input
            Arg Count: 4
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'MEANINGLESS_NAME_LIST'
            [Locals+Names]
                'func_ea'
                'demangled_name'
                'pcode_line_cnt'
                'pcode_var_cnt'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_55240__'
                '__pyarmor_enter_55241__'
                b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_55242__'
                False
                100
                30
                True
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55241__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       1: demangled_name
                30      LOAD_GLOBAL                     0: MEANINGLESS_NAME_LIST
                40      CONTAINS_OP                     0 (in)
                42      POP_JUMP_IF_FALSE               11 (to 66)
                44      NOP                             
                46      LOAD_CONST                      5: False
                48      NOP                             
                50      NOP                             
                52      NOP                             
                54      JUMP_FORWARD                    61 (to 178)
                62      POP_TOP                         
                64      RETURN_CONST                    5: False
                66      LOAD_FAST                       2: pcode_line_cnt
                68      LOAD_CONST                      6: 100
                70      COMPARE_OP                      68 (>)
                74      POP_JUMP_IF_FALSE               11 (to 98)
                76      NOP                             
                78      LOAD_CONST                      5: False
                80      NOP                             
                82      NOP                             
                84      NOP                             
                86      JUMP_FORWARD                    45 (to 178)
                94      POP_TOP                         
                96      RETURN_CONST                    5: False
                98      LOAD_FAST                       3: pcode_var_cnt
                100     LOAD_CONST                      7: 30
                102     COMPARE_OP                      68 (>)
                106     POP_JUMP_IF_FALSE               11 (to 130)
                108     NOP                             
                110     LOAD_CONST                      5: False
                112     NOP                             
                114     NOP                             
                116     NOP                             
                118     JUMP_FORWARD                    29 (to 178)
                126     POP_TOP                         
                128     RETURN_CONST                    5: False
                130     LOAD_CONST                      8: True
                132     NOP                             
                134     NOP                             
                136     NOP                             
                138     JUMP_FORWARD                    19 (to 178)
                146     POP_TOP                         
                148     RETURN_CONST                    8: True
                150     PUSH_EXC_INFO                   
                152     PUSH_NULL                       
                154     LOAD_CONST                      4: '__pyarmor_exit_55242__'
                156     NOP                             
                158     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                160     CALL                            1
                168     POP_TOP                         
                170     RERAISE                         0
                172     COPY                            3
                174     POP_EXCEPT                      
                176     RERAISE                         1
                178     PUSH_NULL                       
                180     LOAD_CONST                      4: '__pyarmor_exit_55242__'
                182     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                184     BUILD_TUPLE                     1
                186     CALL_FUNCTION_EX                0
                188     POP_TOP                         
                190     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: build_prompt
            Qualified Name: build_prompt
            Arg Count: 3
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 12
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'settings_manager'
                'settings'
                'MAX_TRACE_CALLEE_DEPTH'
                'MAX_TRACE_CALLER_DEPTH'
                'MAX_CONTEXT_FUNC_NUM'
                'MEASURE_INFO_SCORE'
                'print'
                'SUPPORT_FUNC_TYPES'
                'ida_funcs'
                'get_func'
                'hex'
                'is_thunk'
                'start_ea'
                'end_ea'
                'idc'
                'get_func_name'
                'demangle'
                'decompile'
                'DecompilationFailure'
                'len'
                'get_pseudocode'
                'lvars'
                'name'
                'is_arg_var'
                'arguments'
                'MEANINGLESS_NAME_LIST'
                'DataFlowAnalyzer'
                'get_var_dataflow'
                'ContextBuilder'
                'build_context'
                'get_call_chains'
                'get_context_pcode'
                'analyzed_funcs'
                'filter_data_flow_by_context_func'
                'DATA_FLOW_TEMPLATE'
                'format'
                'INPUT_TEMPLATE'
                'type'
                'str'
                'list'
                'isinstance'
                'NotImplementedError'
            [Locals+Names]
                'func_ea'
                'task_tag'
                'args'
                '__assert_armored__'
                '_var_var_96'
                '_var_var_66'
                '_var_var_97'
                '_var_var_98'
                '_var_var_99'
                '_var_var_7'
                '_var_var_50'
                '_var_var_58'
                '_var_var_51'
                '_var_var_100'
                '_var_var_101'
                '_var_var_102'
                '_var_var_103'
                '_var_var_104'
                '_var_var_105'
                '_var_var_106'
                '_var_var_107'
                '_var_var_80'
                '_var_var_85'
                '_var_var_76'
                '_var_var_108'
                '_var_var_109'
            [Constants]
                None
                '__pyarmor_assert_55243__'
                '__pyarmor_enter_55244__'
                b'<COAddr>\x03\x00\x00\x1ap\x0c\x00\x00\x00\x00\x00\x00'
                'max_trace_callee_depth'
                'max_trace_caller_depth'
                'max_context_func_num'
                'measure_info_score'
                'data_flow_analysis'
                '[DEBUG🐛] MAX_TRACE_CALLEE_DEPTH='
                ', MAX_TRACE_CALLER_DEPTH='
                ', MAX_CONTEXT_FUNC_NUM='
                ', MEASURE_INFO_SCORE='
                ', DATA_FLOW_ANALYSIS='
                '[!] Unsupported task tag: '
                '__pyarmor_exit_55245__'
                '[!] Fail to get function at '
                '[!] Thunk function is not supported'
                '[!] Failed to decompile function at '
                '[!] Function '
                ' is not good for building input'
                (
                    '<func-analysis>'
                    '<decompilation>'
                    '<funcname>'
                    '<summary>'
                )
                ''
                (
                    'context'
                    'target_func'
                    'call_chains'
                    'data_flow'
                    'task_tag'
                )
                '<vars>'
                '[!] No local variables or arguments found in function '
                '<args>'
                '[!] No arguments found in function '
                (
                    'var_name'
                )
                '<specific-vars>'
                '[!] Bad specified vars: '
                '<var:'
                '>'
                'Not implemented func_type='
                ' yet'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55244__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ap\x0c\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     0: settings_manager
                38      LOAD_ATTR                       2: settings
                58      LOAD_CONST                      4: 'max_trace_callee_depth'
                60      BINARY_SUBSCR                   
                64      STORE_GLOBAL                    2: MAX_TRACE_CALLEE_DEPTH
                66      LOAD_GLOBAL                     0: settings_manager
                76      LOAD_ATTR                       2: settings
                96      LOAD_CONST                      5: 'max_trace_caller_depth'
                98      BINARY_SUBSCR                   
                102     STORE_GLOBAL                    3: MAX_TRACE_CALLER_DEPTH
                104     LOAD_GLOBAL                     0: settings_manager
                114     LOAD_ATTR                       2: settings
                134     LOAD_CONST                      6: 'max_context_func_num'
                136     BINARY_SUBSCR                   
                140     STORE_GLOBAL                    4: MAX_CONTEXT_FUNC_NUM
                142     LOAD_GLOBAL                     0: settings_manager
                152     LOAD_ATTR                       2: settings
                172     LOAD_CONST                      7: 'measure_info_score'
                174     BINARY_SUBSCR                   
                178     STORE_GLOBAL                    5: MEASURE_INFO_SCORE
                180     LOAD_GLOBAL                     0: settings_manager
                190     LOAD_ATTR                       2: settings
                210     LOAD_CONST                      8: 'data_flow_analysis'
                212     BINARY_SUBSCR                   
                216     STORE_FAST                      4: _var_var_96
                218     LOAD_GLOBAL                     13: NULL + print
                228     LOAD_CONST                      9: '[DEBUG🐛] MAX_TRACE_CALLEE_DEPTH='
                230     LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                240     FORMAT_VALUE                    0 (FVC_NONE)
                242     LOAD_CONST                      10: ', MAX_TRACE_CALLER_DEPTH='
                244     LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                254     FORMAT_VALUE                    0 (FVC_NONE)
                256     LOAD_CONST                      11: ', MAX_CONTEXT_FUNC_NUM='
                258     LOAD_GLOBAL                     8: MAX_CONTEXT_FUNC_NUM
                268     FORMAT_VALUE                    0 (FVC_NONE)
                270     LOAD_CONST                      12: ', MEASURE_INFO_SCORE='
                272     LOAD_GLOBAL                     10: MEASURE_INFO_SCORE
                282     FORMAT_VALUE                    0 (FVC_NONE)
                284     LOAD_CONST                      13: ', DATA_FLOW_ANALYSIS='
                286     LOAD_FAST                       4: _var_var_96
                288     FORMAT_VALUE                    0 (FVC_NONE)
                290     BUILD_STRING                    10
                292     CALL                            1
                300     POP_TOP                         
                302     LOAD_FAST                       1: task_tag
                304     LOAD_GLOBAL                     14: SUPPORT_FUNC_TYPES
                314     CONTAINS_OP                     1 (not in)
                316     POP_JUMP_IF_FALSE               25 (to 368)
                318     LOAD_GLOBAL                     13: NULL + print
                328     LOAD_CONST                      14: '[!] Unsupported task tag: '
                330     LOAD_FAST                       1: task_tag
                332     FORMAT_VALUE                    0 (FVC_NONE)
                334     BUILD_STRING                    2
                336     CALL                            1
                344     POP_TOP                         
                346     NOP                             
                348     LOAD_CONST                      0: None
                350     NOP                             
                352     NOP                             
                354     JUMP_FORWARD                    1440 (to 3238)
                364     POP_TOP                         
                366     RETURN_CONST                    0: None
                368     LOAD_GLOBAL                     17: NULL + ida_funcs
                378     LOAD_ATTR                       18: get_func
                398     LOAD_FAST                       0: func_ea
                400     CALL                            1
                408     STORE_FAST                      5: _var_var_66
                410     LOAD_FAST                       5: _var_var_66
                412     POP_JUMP_IF_TRUE                34 (to 482)
                414     LOAD_GLOBAL                     13: NULL + print
                424     LOAD_CONST                      16: '[!] Fail to get function at '
                426     LOAD_GLOBAL                     21: NULL + hex
                436     LOAD_FAST                       0: func_ea
                438     CALL                            1
                446     FORMAT_VALUE                    0 (FVC_NONE)
                448     BUILD_STRING                    2
                450     CALL                            1
                458     POP_TOP                         
                460     NOP                             
                462     LOAD_CONST                      0: None
                464     NOP                             
                466     NOP                             
                468     JUMP_FORWARD                    1383 (to 3238)
                478     POP_TOP                         
                480     RETURN_CONST                    0: None
                482     LOAD_GLOBAL                     23: NULL + is_thunk
                492     LOAD_FAST                       0: func_ea
                494     CALL                            1
                502     POP_JUMP_IF_FALSE               22 (to 548)
                504     LOAD_GLOBAL                     13: NULL + print
                514     LOAD_CONST                      17: '[!] Thunk function is not supported'
                516     CALL                            1
                524     POP_TOP                         
                526     NOP                             
                528     LOAD_CONST                      0: None
                530     NOP                             
                532     NOP                             
                534     JUMP_FORWARD                    1350 (to 3238)
                544     POP_TOP                         
                546     RETURN_CONST                    0: None
                548     LOAD_FAST                       5: _var_var_66
                550     LOAD_ATTR                       24: start_ea
                570     STORE_FAST                      6: _var_var_97
                572     LOAD_FAST                       5: _var_var_66
                574     LOAD_ATTR                       26: end_ea
                594     STORE_FAST                      7: _var_var_98
                596     LOAD_GLOBAL                     29: NULL + idc
                606     LOAD_ATTR                       30: get_func_name
                626     LOAD_FAST                       6: _var_var_97
                628     CALL                            1
                636     STORE_FAST                      8: _var_var_99
                638     LOAD_GLOBAL                     33: NULL + demangle
                648     LOAD_FAST                       8: _var_var_99
                650     CALL                            1
                658     STORE_FAST                      9: _var_var_7
                660     NOP                             
                662     LOAD_GLOBAL                     35: NULL + decompile
                672     LOAD_FAST                       0: func_ea
                674     CALL                            1
                682     STORE_FAST                      10: _var_var_50
                684     LOAD_FAST                       10: _var_var_50
                686     LOAD_CONST                      0: None
                688     COMPARE_OP                      40 (==)
                692     POP_JUMP_IF_FALSE               6 (to 706)
                694     LOAD_GLOBAL                     36: DecompilationFailure
                704     RAISE_VARARGS                   1
                706     LOAD_GLOBAL                     39: NULL + len
                716     LOAD_FAST                       10: _var_var_50
                718     LOAD_ATTR                       41: get_pseudocode
                738     CALL                            0
                746     CALL                            1
                754     STORE_FAST                      11: _var_var_58
                756     LOAD_FAST                       10: _var_var_50
                758     LOAD_ATTR                       42: lvars
                778     GET_ITER                        
                780     LOAD_FAST_AND_CLEAR             12: _var_var_51
                782     SWAP                            2
                784     BUILD_LIST                      0
                786     SWAP                            2
                788     FOR_ITER                        40 (to 870)
                792     STORE_FAST                      12: _var_var_51
                794     LOAD_FAST                       12: _var_var_51
                796     LOAD_ATTR                       44: name
                816     POP_JUMP_IF_TRUE                1 (to 820)
                818     JUMP_BACKWARD                   16 (to 788)
                820     LOAD_FAST                       12: _var_var_51
                822     LOAD_ATTR                       46: is_arg_var
                842     POP_JUMP_IF_FALSE               1 (to 846)
                844     JUMP_BACKWARD                   29 (to 788)
                846     LOAD_FAST                       12: _var_var_51
                848     LOAD_ATTR                       44: name
                868     LIST_APPEND                     2
                870     JUMP_BACKWARD                   42 (to 788)
                872     END_FOR                         
                874     STORE_FAST                      13: _var_var_100
                876     STORE_FAST                      12: _var_var_51
                878     LOAD_FAST                       10: _var_var_50
                880     LOAD_ATTR                       48: arguments
                900     GET_ITER                        
                902     LOAD_FAST_AND_CLEAR             12: _var_var_51
                904     SWAP                            2
                906     BUILD_LIST                      0
                908     SWAP                            2
                910     FOR_ITER                        27 (to 966)
                914     STORE_FAST                      12: _var_var_51
                916     LOAD_FAST                       12: _var_var_51
                918     LOAD_ATTR                       44: name
                938     POP_JUMP_IF_TRUE                1 (to 942)
                940     JUMP_BACKWARD                   16 (to 910)
                942     LOAD_FAST                       12: _var_var_51
                944     LOAD_ATTR                       44: name
                964     LIST_APPEND                     2
                966     JUMP_BACKWARD                   29 (to 910)
                968     END_FOR                         
                970     STORE_FAST                      14: _var_var_101
                972     STORE_FAST                      12: _var_var_51
                974     LOAD_GLOBAL                     39: NULL + len
                984     LOAD_FAST                       13: _var_var_100
                986     CALL                            1
                994     STORE_FAST                      15: _var_var_102
                996     LOAD_GLOBAL                     39: NULL + len
                1006    LOAD_FAST                       14: _var_var_101
                1008    CALL                            1
                1016    STORE_FAST                      16: _var_var_103
                1018    LOAD_FAST                       9: _var_var_7
                1020    LOAD_GLOBAL                     50: MEANINGLESS_NAME_LIST
                1030    CONTAINS_OP                     0 (in)
                1032    POP_JUMP_IF_FALSE               26 (to 1086)
                1034    LOAD_GLOBAL                     13: NULL + print
                1044    LOAD_CONST                      19: '[!] Function '
                1046    LOAD_FAST                       9: _var_var_7
                1048    FORMAT_VALUE                    0 (FVC_NONE)
                1050    LOAD_CONST                      20: ' is not good for building input'
                1052    BUILD_STRING                    3
                1054    CALL                            1
                1062    POP_TOP                         
                1064    NOP                             
                1066    LOAD_CONST                      0: None
                1068    NOP                             
                1070    NOP                             
                1072    JUMP_FORWARD                    1081 (to 3238)
                1082    POP_TOP                         
                1084    RETURN_CONST                    0: None
                1086    LOAD_FAST                       1: task_tag
                1088    LOAD_CONST                      21: ('<func-analysis>', '<decompilation>', '<funcname>', '<summary>')
                1090    CONTAINS_OP                     0 (in)
                1092    POP_JUMP_IF_FALSE               210 (to 1514)
                1094    LOAD_GLOBAL                     53: NULL + DataFlowAnalyzer
                1104    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                1114    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                1124    CALL                            2
                1132    STORE_FAST                      17: _var_var_104
                1134    LOAD_FAST                       4: _var_var_96
                1136    POP_JUMP_IF_FALSE               18 (to 1174)
                1138    LOAD_FAST                       17: _var_var_104
                1140    LOAD_ATTR                       55: get_var_dataflow
                1160    LOAD_FAST                       0: func_ea
                1162    CALL                            1
                1170    STORE_FAST                      18: _var_var_105
                1172    JUMP_FORWARD                    2 (to 1178)
                1174    LOAD_CONST                      22: ''
                1176    STORE_FAST                      18: _var_var_105
                1178    LOAD_GLOBAL                     57: NULL + ContextBuilder
                1188    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                1198    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                1208    LOAD_GLOBAL                     8: MAX_CONTEXT_FUNC_NUM
                1218    CALL                            3
                1226    STORE_FAST                      19: _var_var_106
                1228    LOAD_FAST                       19: _var_var_106
                1230    LOAD_ATTR                       59: build_context
                1250    LOAD_FAST                       0: func_ea
                1252    CALL                            1
                1260    POP_TOP                         
                1262    LOAD_FAST                       19: _var_var_106
                1264    LOAD_ATTR                       61: get_call_chains
                1284    CALL                            0
                1292    STORE_FAST                      20: _var_var_107
                1294    LOAD_FAST                       19: _var_var_106
                1296    LOAD_ATTR                       63: get_context_pcode
                1316    LOAD_FAST                       0: func_ea
                1318    LOAD_FAST                       17: _var_var_104
                1320    LOAD_ATTR                       64: analyzed_funcs
                1340    CALL                            2
                1348    UNPACK_SEQUENCE                 3
                1352    STORE_FAST                      21: _var_var_80
                1354    STORE_FAST                      22: _var_var_85
                1356    STORE_FAST                      23: _var_var_76
                1358    LOAD_FAST                       4: _var_var_96
                1360    POP_JUMP_IF_FALSE               39 (to 1440)
                1362    LOAD_FAST                       17: _var_var_104
                1364    LOAD_ATTR                       67: filter_data_flow_by_context_func
                1384    LOAD_FAST                       18: _var_var_105
                1386    LOAD_FAST                       23: _var_var_76
                1388    CALL                            2
                1396    STORE_FAST                      18: _var_var_105
                1398    LOAD_GLOBAL                     68: DATA_FLOW_TEMPLATE
                1408    LOAD_ATTR                       71: format
                1428    LOAD_FAST                       18: _var_var_105
                1430    CALL                            1
                1438    STORE_FAST                      18: _var_var_105
                1440    LOAD_GLOBAL                     72: INPUT_TEMPLATE
                1450    LOAD_ATTR                       71: format
                1470    LOAD_FAST                       21: _var_var_80
                1472    LOAD_FAST                       22: _var_var_85
                1474    LOAD_FAST                       20: _var_var_107
                1476    LOAD_FAST                       18: _var_var_105
                1478    LOAD_FAST                       1: task_tag
                1480    KW_NAMES                        23: ('context', 'target_func', 'call_chains', 'data_flow', 'task_tag')
                1482    CALL                            5
                1490    STORE_FAST                      24: _var_var_108
                1492    LOAD_FAST                       24: _var_var_108
                1494    NOP                             
                1496    NOP                             
                1498    JUMP_FORWARD                    868 (to 3238)
                1502    CALL                            1
                1510    POP_TOP                         
                1512    RETURN_VALUE                    
                1514    LOAD_FAST                       1: task_tag
                1516    LOAD_CONST                      24: '<vars>'
                1518    COMPARE_OP                      40 (==)
                1522    POP_JUMP_IF_FALSE               239 (to 2002)
                1524    LOAD_GLOBAL                     53: NULL + DataFlowAnalyzer
                1534    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                1544    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                1554    CALL                            2
                1562    STORE_FAST                      17: _var_var_104
                1564    LOAD_FAST                       13: _var_var_100
                1566    POP_JUMP_IF_TRUE                27 (to 1622)
                1568    LOAD_FAST                       14: _var_var_101
                1570    POP_JUMP_IF_TRUE                25 (to 1622)
                1572    LOAD_GLOBAL                     13: NULL + print
                1582    LOAD_CONST                      25: '[!] No local variables or arguments found in function '
                1584    LOAD_FAST                       9: _var_var_7
                1586    FORMAT_VALUE                    0 (FVC_NONE)
                1588    BUILD_STRING                    2
                1590    CALL                            1
                1598    POP_TOP                         
                1600    NOP                             
                1602    LOAD_CONST                      0: None
                1604    NOP                             
                1606    NOP                             
                1608    JUMP_FORWARD                    813 (to 3238)
                1618    POP_TOP                         
                1620    RETURN_CONST                    0: None
                1622    LOAD_FAST                       4: _var_var_96
                1624    POP_JUMP_IF_FALSE               18 (to 1662)
                1626    LOAD_FAST                       17: _var_var_104
                1628    LOAD_ATTR                       55: get_var_dataflow
                1648    LOAD_FAST                       0: func_ea
                1650    CALL                            1
                1658    STORE_FAST                      18: _var_var_105
                1660    JUMP_FORWARD                    2 (to 1666)
                1662    LOAD_CONST                      22: ''
                1664    STORE_FAST                      18: _var_var_105
                1666    LOAD_GLOBAL                     57: NULL + ContextBuilder
                1676    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                1686    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                1696    LOAD_GLOBAL                     8: MAX_CONTEXT_FUNC_NUM
                1706    CALL                            3
                1714    STORE_FAST                      19: _var_var_106
                1716    LOAD_FAST                       19: _var_var_106
                1718    LOAD_ATTR                       59: build_context
                1738    LOAD_FAST                       0: func_ea
                1740    CALL                            1
                1748    POP_TOP                         
                1750    LOAD_FAST                       19: _var_var_106
                1752    LOAD_ATTR                       61: get_call_chains
                1772    CALL                            0
                1780    STORE_FAST                      20: _var_var_107
                1782    LOAD_FAST                       19: _var_var_106
                1784    LOAD_ATTR                       63: get_context_pcode
                1804    LOAD_FAST                       0: func_ea
                1806    LOAD_FAST                       17: _var_var_104
                1808    LOAD_ATTR                       64: analyzed_funcs
                1828    CALL                            2
                1836    UNPACK_SEQUENCE                 3
                1840    STORE_FAST                      21: _var_var_80
                1842    STORE_FAST                      22: _var_var_85
                1844    STORE_FAST                      23: _var_var_76
                1846    LOAD_FAST                       4: _var_var_96
                1848    POP_JUMP_IF_FALSE               39 (to 1928)
                1850    LOAD_FAST                       17: _var_var_104
                1852    LOAD_ATTR                       67: filter_data_flow_by_context_func
                1872    LOAD_FAST                       18: _var_var_105
                1874    LOAD_FAST                       23: _var_var_76
                1876    CALL                            2
                1884    STORE_FAST                      18: _var_var_105
                1886    LOAD_GLOBAL                     68: DATA_FLOW_TEMPLATE
                1896    LOAD_ATTR                       71: format
                1916    LOAD_FAST                       18: _var_var_105
                1918    CALL                            1
                1926    STORE_FAST                      18: _var_var_105
                1928    LOAD_GLOBAL                     72: INPUT_TEMPLATE
                1938    LOAD_ATTR                       71: format
                1958    LOAD_FAST                       21: _var_var_80
                1960    LOAD_FAST                       22: _var_var_85
                1962    LOAD_FAST                       20: _var_var_107
                1964    LOAD_FAST                       18: _var_var_105
                1966    LOAD_FAST                       1: task_tag
                1968    KW_NAMES                        23: ('context', 'target_func', 'call_chains', 'data_flow', 'task_tag')
                1970    CALL                            5
                1978    STORE_FAST                      24: _var_var_108
                1980    LOAD_FAST                       24: _var_var_108
                1982    NOP                             
                1984    NOP                             
                1986    JUMP_FORWARD                    624 (to 3238)
                1990    CALL                            1
                1998    POP_TOP                         
                2000    RETURN_VALUE                    
                2002    LOAD_FAST                       1: task_tag
                2004    LOAD_CONST                      26: '<args>'
                2006    COMPARE_OP                      40 (==)
                2010    POP_JUMP_IF_FALSE               239 (to 2490)
                2012    LOAD_GLOBAL                     53: NULL + DataFlowAnalyzer
                2022    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                2032    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                2042    CALL                            2
                2050    STORE_FAST                      17: _var_var_104
                2052    LOAD_FAST                       14: _var_var_101
                2054    POP_JUMP_IF_TRUE                25 (to 2106)
                2056    LOAD_GLOBAL                     13: NULL + print
                2066    LOAD_CONST                      27: '[!] No arguments found in function '
                2068    LOAD_FAST                       9: _var_var_7
                2070    FORMAT_VALUE                    0 (FVC_NONE)
                2072    BUILD_STRING                    2
                2074    CALL                            1
                2082    POP_TOP                         
                2084    NOP                             
                2086    LOAD_CONST                      0: None
                2088    NOP                             
                2090    NOP                             
                2092    JUMP_FORWARD                    571 (to 3238)
                2102    POP_TOP                         
                2104    RETURN_CONST                    0: None
                2106    LOAD_FAST                       4: _var_var_96
                2108    POP_JUMP_IF_FALSE               20 (to 2150)
                2110    LOAD_FAST                       17: _var_var_104
                2112    LOAD_ATTR                       55: get_var_dataflow
                2132    LOAD_FAST                       0: func_ea
                2134    LOAD_FAST                       14: _var_var_101
                2136    KW_NAMES                        28: ('var_name',)
                2138    CALL                            2
                2146    STORE_FAST                      18: _var_var_105
                2148    JUMP_FORWARD                    2 (to 2154)
                2150    LOAD_CONST                      22: ''
                2152    STORE_FAST                      18: _var_var_105
                2154    LOAD_GLOBAL                     57: NULL + ContextBuilder
                2164    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                2174    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                2184    LOAD_GLOBAL                     8: MAX_CONTEXT_FUNC_NUM
                2194    CALL                            3
                2202    STORE_FAST                      19: _var_var_106
                2204    LOAD_FAST                       19: _var_var_106
                2206    LOAD_ATTR                       59: build_context
                2226    LOAD_FAST                       0: func_ea
                2228    CALL                            1
                2236    POP_TOP                         
                2238    LOAD_FAST                       19: _var_var_106
                2240    LOAD_ATTR                       61: get_call_chains
                2260    CALL                            0
                2268    STORE_FAST                      20: _var_var_107
                2270    LOAD_FAST                       19: _var_var_106
                2272    LOAD_ATTR                       63: get_context_pcode
                2292    LOAD_FAST                       0: func_ea
                2294    LOAD_FAST                       17: _var_var_104
                2296    LOAD_ATTR                       64: analyzed_funcs
                2316    CALL                            2
                2324    UNPACK_SEQUENCE                 3
                2328    STORE_FAST                      21: _var_var_80
                2330    STORE_FAST                      22: _var_var_85
                2332    STORE_FAST                      23: _var_var_76
                2334    LOAD_FAST                       4: _var_var_96
                2336    POP_JUMP_IF_FALSE               39 (to 2416)
                2338    LOAD_FAST                       17: _var_var_104
                2340    LOAD_ATTR                       67: filter_data_flow_by_context_func
                2360    LOAD_FAST                       18: _var_var_105
                2362    LOAD_FAST                       23: _var_var_76
                2364    CALL                            2
                2372    STORE_FAST                      18: _var_var_105
                2374    LOAD_GLOBAL                     68: DATA_FLOW_TEMPLATE
                2384    LOAD_ATTR                       71: format
                2404    LOAD_FAST                       18: _var_var_105
                2406    CALL                            1
                2414    STORE_FAST                      18: _var_var_105
                2416    LOAD_GLOBAL                     72: INPUT_TEMPLATE
                2426    LOAD_ATTR                       71: format
                2446    LOAD_FAST                       21: _var_var_80
                2448    LOAD_FAST                       22: _var_var_85
                2450    LOAD_FAST                       20: _var_var_107
                2452    LOAD_FAST                       18: _var_var_105
                2454    LOAD_FAST                       1: task_tag
                2456    KW_NAMES                        23: ('context', 'target_func', 'call_chains', 'data_flow', 'task_tag')
                2458    CALL                            5
                2466    STORE_FAST                      24: _var_var_108
                2468    LOAD_FAST                       24: _var_var_108
                2470    NOP                             
                2472    NOP                             
                2474    JUMP_FORWARD                    380 (to 3238)
                2478    CALL                            1
                2486    POP_TOP                         
                2488    RETURN_VALUE                    
                2490    LOAD_FAST                       1: task_tag
                2492    LOAD_CONST                      29: '<specific-vars>'
                2494    COMPARE_OP                      40 (==)
                2498    POP_JUMP_IF_FALSE               282 (to 3066)
                2502    LOAD_FAST                       2: args
                2504    STORE_FAST                      25: _var_var_109
                2506    LOAD_GLOBAL                     75: NULL + type
                2516    LOAD_FAST                       25: _var_var_109
                2518    CALL                            1
                2526    LOAD_GLOBAL                     76: str
                2536    LOAD_GLOBAL                     78: list
                2546    BUILD_TUPLE                     2
                2548    CONTAINS_OP                     0 (in)
                2550    POP_JUMP_IF_TRUE                10 (to 2572)
                2552    LOAD_ASSERTION_ERROR            
                2554    LOAD_CONST                      30: '[!] Bad specified vars: '
                2556    LOAD_FAST                       25: _var_var_109
                2558    FORMAT_VALUE                    0 (FVC_NONE)
                2560    BUILD_STRING                    2
                2562    CALL                            0
                2570    RAISE_VARARGS                   1
                2572    LOAD_GLOBAL                     81: NULL + isinstance
                2582    LOAD_FAST                       25: _var_var_109
                2584    LOAD_GLOBAL                     76: str
                2594    CALL                            2
                2602    POP_JUMP_IF_FALSE               3 (to 2610)
                2604    LOAD_FAST                       25: _var_var_109
                2606    BUILD_LIST                      1
                2608    STORE_FAST                      25: _var_var_109
                2610    LOAD_GLOBAL                     53: NULL + DataFlowAnalyzer
                2620    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                2630    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                2640    CALL                            2
                2648    STORE_FAST                      17: _var_var_104
                2650    LOAD_FAST                       4: _var_var_96
                2652    POP_JUMP_IF_FALSE               20 (to 2694)
                2654    LOAD_FAST                       17: _var_var_104
                2656    LOAD_ATTR                       55: get_var_dataflow
                2676    LOAD_FAST                       0: func_ea
                2678    LOAD_FAST                       25: _var_var_109
                2680    KW_NAMES                        28: ('var_name',)
                2682    CALL                            2
                2690    STORE_FAST                      18: _var_var_105
                2692    JUMP_FORWARD                    2 (to 2698)
                2694    LOAD_CONST                      22: ''
                2696    STORE_FAST                      18: _var_var_105
                2698    LOAD_GLOBAL                     57: NULL + ContextBuilder
                2708    LOAD_GLOBAL                     4: MAX_TRACE_CALLEE_DEPTH
                2718    LOAD_GLOBAL                     6: MAX_TRACE_CALLER_DEPTH
                2728    LOAD_GLOBAL                     8: MAX_CONTEXT_FUNC_NUM
                2738    CALL                            3
                2746    STORE_FAST                      19: _var_var_106
                2748    LOAD_FAST                       19: _var_var_106
                2750    LOAD_ATTR                       59: build_context
                2770    LOAD_FAST                       0: func_ea
                2772    CALL                            1
                2780    POP_TOP                         
                2782    LOAD_FAST                       19: _var_var_106
                2784    LOAD_ATTR                       61: get_call_chains
                2804    CALL                            0
                2812    STORE_FAST                      20: _var_var_107
                2814    LOAD_FAST                       19: _var_var_106
                2816    LOAD_ATTR                       63: get_context_pcode
                2836    LOAD_FAST                       0: func_ea
                2838    LOAD_FAST                       17: _var_var_104
                2840    LOAD_ATTR                       64: analyzed_funcs
                2860    CALL                            2
                2868    UNPACK_SEQUENCE                 3
                2872    STORE_FAST                      21: _var_var_80
                2874    STORE_FAST                      22: _var_var_85
                2876    STORE_FAST                      23: _var_var_76
                2878    LOAD_FAST                       4: _var_var_96
                2880    POP_JUMP_IF_FALSE               39 (to 2960)
                2882    LOAD_FAST                       17: _var_var_104
                2884    LOAD_ATTR                       67: filter_data_flow_by_context_func
                2904    LOAD_FAST                       18: _var_var_105
                2906    LOAD_FAST                       23: _var_var_76
                2908    CALL                            2
                2916    STORE_FAST                      18: _var_var_105
                2918    LOAD_GLOBAL                     68: DATA_FLOW_TEMPLATE
                2928    LOAD_ATTR                       71: format
                2948    LOAD_FAST                       18: _var_var_105
                2950    CALL                            1
                2958    STORE_FAST                      18: _var_var_105
                2960    LOAD_FAST                       25: _var_var_109
                2962    GET_ITER                        
                2964    FOR_ITER                        11 (to 2988)
                2968    STORE_FAST                      12: _var_var_51
                2970    LOAD_FAST                       1: task_tag
                2972    LOAD_CONST                      31: '<var:'
                2974    LOAD_FAST                       12: _var_var_51
                2976    FORMAT_VALUE                    0 (FVC_NONE)
                2978    LOAD_CONST                      32: '>'
                2980    BUILD_STRING                    3
                2982    BINARY_OP                       13 (+=)
                2986    STORE_FAST                      1: task_tag
                2988    JUMP_BACKWARD                   13 (to 2964)
                2990    END_FOR                         
                2992    LOAD_GLOBAL                     72: INPUT_TEMPLATE
                3002    LOAD_ATTR                       71: format
                3022    LOAD_FAST                       21: _var_var_80
                3024    LOAD_FAST                       22: _var_var_85
                3026    LOAD_FAST                       20: _var_var_107
                3028    LOAD_FAST                       18: _var_var_105
                3030    LOAD_FAST                       1: task_tag
                3032    KW_NAMES                        23: ('context', 'target_func', 'call_chains', 'data_flow', 'task_tag')
                3034    CALL                            5
                3042    STORE_FAST                      24: _var_var_108
                3044    LOAD_FAST                       24: _var_var_108
                3046    NOP                             
                3048    NOP                             
                3050    NOP                             
                3052    JUMP_FORWARD                    92 (to 3238)
                3054    CALL                            1
                3062    POP_TOP                         
                3064    RETURN_VALUE                    
                3066    LOAD_GLOBAL                     83: NULL + NotImplementedError
                3076    LOAD_CONST                      33: 'Not implemented func_type='
                3078    LOAD_FAST                       1: task_tag
                3080    FORMAT_VALUE                    0 (FVC_NONE)
                3082    LOAD_CONST                      34: ' yet'
                3084    BUILD_STRING                    3
                3086    CALL                            1
                3094    RAISE_VARARGS                   1
                3096    SWAP                            2
                3098    POP_TOP                         
                3100    SWAP                            2
                3102    STORE_FAST                      12: _var_var_51
                3104    RERAISE                         0
                3106    SWAP                            2
                3108    POP_TOP                         
                3110    SWAP                            2
                3112    STORE_FAST                      12: _var_var_51
                3114    RERAISE                         0
                3116    PUSH_EXC_INFO                   
                3118    LOAD_GLOBAL                     36: DecompilationFailure
                3128    CHECK_EXC_MATCH                 
                3130    POP_JUMP_IF_FALSE               35 (to 3202)
                3132    POP_TOP                         
                3134    LOAD_GLOBAL                     13: NULL + print
                3144    LOAD_CONST                      18: '[!] Failed to decompile function at '
                3146    LOAD_GLOBAL                     21: NULL + hex
                3156    LOAD_FAST                       0: func_ea
                3158    CALL                            1
                3166    FORMAT_VALUE                    0 (FVC_NONE)
                3168    BUILD_STRING                    2
                3170    CALL                            1
                3178    POP_TOP                         
                3180    POP_EXCEPT                      
                3182    LOAD_CONST                      0: None
                3184    NOP                             
                3186    NOP                             
                3188    NOP                             
                3190    JUMP_FORWARD                    23 (to 3238)
                3198    POP_TOP                         
                3200    RETURN_CONST                    0: None
                3202    RERAISE                         0
                3204    COPY                            3
                3206    POP_EXCEPT                      
                3208    RERAISE                         1
                3210    PUSH_EXC_INFO                   
                3212    PUSH_NULL                       
                3214    LOAD_CONST                      15: '__pyarmor_exit_55245__'
                3216    NOP                             
                3218    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ap\x0c\x00\x00\x00\x00\x00\x00'
                3220    CALL                            1
                3228    POP_TOP                         
                3230    RERAISE                         0
                3232    COPY                            3
                3234    POP_EXCEPT                      
                3236    RERAISE                         1
                3238    PUSH_NULL                       
                3240    LOAD_CONST                      15: '__pyarmor_exit_55245__'
                3242    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ap\x0c\x00\x00\x00\x00\x00\x00'
                3244    BUILD_TUPLE                     1
                3246    CALL_FUNCTION_EX                0
                3248    POP_TOP                         
                3250    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction_ret_type
            Qualified Name: apply_prediction_ret_type
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 8
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'get'
                'isinstance'
                'str'
                'print'
                'endswith'
                'ida_typeinf'
                'tinfo_t'
                'idaapi'
                'get_idati'
                'parse_decl'
                'PT_TYP'
                'PT_SIL'
                'get_named_type'
                'BTF_TYPEDEF'
                'ida_nalt'
                'get_tinfo'
                'hex'
                'func_type_data_t'
                'get_func_details'
                'rettype'
                'create_func'
                'set_tinfo'
                'open_pseudocode'
                'cfunc'
                'refresh_func_ctext'
            [Locals+Names]
                'func_ea'
                'prediction'
                '__assert_armored__'
                '_var_var_110'
                '_var_var_111'
                '_var_var_10'
                '_var_var_112'
                '_var_var_113'
                '_var_var_114'
                '_var_var_115'
                '_var_var_116'
            [Constants]
                None
                '__pyarmor_assert_55246__'
                '__pyarmor_enter_55247__'
                b'<COAddr>\x03\x00\x00\x1a\xd0\x04\x00\x00\x00\x00\x00\x00'
                'ret_type'
                '[!] found bad ret_type in prediction: '
                '__pyarmor_exit_55248__'
                ';'
                -1
                True
                False
                '[!] Failed to parse or find type '
                '[!] Fail to get function type info at '
                '[!] Fail to get function details at '
                '[!] Fail to create new function type at '
                '[!] Fail to apply new function type at '
                '[+] Successfully set return type '
                ' for function '
                0
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55247__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xd0\x04\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       1: prediction
                30      LOAD_ATTR                       1: get
                50      LOAD_CONST                      4: 'ret_type'
                52      LOAD_CONST                      0: None
                54      CALL                            2
                62      STORE_FAST                      3: _var_var_110
                64      LOAD_FAST                       3: _var_var_110
                66      POP_JUMP_IF_FALSE               16 (to 100)
                68      LOAD_GLOBAL                     3: NULL + isinstance
                78      LOAD_FAST                       3: _var_var_110
                80      LOAD_GLOBAL                     4: str
                90      CALL                            2
                98      POP_JUMP_IF_TRUE                25 (to 150)
                100     LOAD_GLOBAL                     7: NULL + print
                110     LOAD_CONST                      5: '[!] found bad ret_type in prediction: '
                112     LOAD_FAST                       3: _var_var_110
                114     FORMAT_VALUE                    0 (FVC_NONE)
                116     BUILD_STRING                    2
                118     CALL                            1
                126     POP_TOP                         
                128     NOP                             
                130     LOAD_CONST                      0: None
                132     NOP                             
                134     NOP                             
                136     JUMP_FORWARD                    573 (to 1286)
                146     POP_TOP                         
                148     RETURN_CONST                    0: None
                150     LOAD_FAST                       3: _var_var_110
                152     LOAD_ATTR                       9: endswith
                172     LOAD_CONST                      7: ';'
                174     CALL                            1
                182     POP_JUMP_IF_TRUE                5 (to 194)
                184     LOAD_FAST                       3: _var_var_110
                186     LOAD_CONST                      7: ';'
                188     BINARY_OP                       13 (+=)
                192     STORE_FAST                      3: _var_var_110
                194     LOAD_GLOBAL                     11: NULL + ida_typeinf
                204     LOAD_ATTR                       12: tinfo_t
                224     CALL                            0
                232     STORE_FAST                      4: _var_var_111
                234     LOAD_GLOBAL                     15: NULL + idaapi
                244     LOAD_ATTR                       16: get_idati
                264     CALL                            0
                272     STORE_FAST                      5: _var_var_10
                274     LOAD_GLOBAL                     11: NULL + ida_typeinf
                284     LOAD_ATTR                       18: parse_decl
                304     LOAD_FAST                       4: _var_var_111
                306     LOAD_FAST                       5: _var_var_10
                308     LOAD_FAST                       3: _var_var_110
                310     LOAD_GLOBAL                     10: ida_typeinf
                320     LOAD_ATTR                       20: PT_TYP
                340     LOAD_GLOBAL                     10: ida_typeinf
                350     LOAD_ATTR                       22: PT_SIL
                370     BINARY_OP                       7 (|)
                374     CALL                            4
                382     STORE_FAST                      6: _var_var_112
                384     LOAD_FAST                       6: _var_var_112
                386     LOAD_CONST                      0: None
                388     COMPARE_OP                      40 (==)
                392     POP_JUMP_IF_FALSE               65 (to 524)
                394     LOAD_FAST                       3: _var_var_110
                396     LOAD_CONST                      0: None
                398     LOAD_CONST                      8: -1
                400     BINARY_SLICE                    
                402     STORE_FAST                      3: _var_var_110
                404     LOAD_FAST                       4: _var_var_111
                406     LOAD_ATTR                       25: get_named_type
                426     LOAD_FAST                       5: _var_var_10
                428     LOAD_FAST                       3: _var_var_110
                430     LOAD_GLOBAL                     10: ida_typeinf
                440     LOAD_ATTR                       26: BTF_TYPEDEF
                460     LOAD_CONST                      9: True
                462     LOAD_CONST                      10: False
                464     CALL                            5
                472     POP_JUMP_IF_TRUE                25 (to 524)
                474     LOAD_GLOBAL                     7: NULL + print
                484     LOAD_CONST                      11: '[!] Failed to parse or find type '
                486     LOAD_FAST                       3: _var_var_110
                488     FORMAT_VALUE                    0 (FVC_NONE)
                490     BUILD_STRING                    2
                492     CALL                            1
                500     POP_TOP                         
                502     NOP                             
                504     LOAD_CONST                      0: None
                506     NOP                             
                508     NOP                             
                510     JUMP_FORWARD                    386 (to 1286)
                520     POP_TOP                         
                522     RETURN_CONST                    0: None
                524     LOAD_GLOBAL                     11: NULL + ida_typeinf
                534     LOAD_ATTR                       12: tinfo_t
                554     CALL                            0
                562     STORE_FAST                      7: _var_var_113
                564     LOAD_GLOBAL                     29: NULL + ida_nalt
                574     LOAD_ATTR                       30: get_tinfo
                594     LOAD_FAST                       7: _var_var_113
                596     LOAD_FAST                       0: func_ea
                598     CALL                            2
                606     POP_JUMP_IF_TRUE                34 (to 676)
                608     LOAD_GLOBAL                     7: NULL + print
                618     LOAD_CONST                      12: '[!] Fail to get function type info at '
                620     LOAD_GLOBAL                     33: NULL + hex
                630     LOAD_FAST                       0: func_ea
                632     CALL                            1
                640     FORMAT_VALUE                    0 (FVC_NONE)
                642     BUILD_STRING                    2
                644     CALL                            1
                652     POP_TOP                         
                654     NOP                             
                656     LOAD_CONST                      0: None
                658     NOP                             
                660     NOP                             
                662     JUMP_FORWARD                    310 (to 1286)
                672     POP_TOP                         
                674     RETURN_CONST                    0: None
                676     LOAD_GLOBAL                     11: NULL + ida_typeinf
                686     LOAD_ATTR                       34: func_type_data_t
                706     CALL                            0
                714     STORE_FAST                      8: _var_var_114
                716     LOAD_FAST                       7: _var_var_113
                718     LOAD_ATTR                       37: get_func_details
                738     LOAD_FAST                       8: _var_var_114
                740     CALL                            1
                748     POP_JUMP_IF_TRUE                34 (to 818)
                750     LOAD_GLOBAL                     7: NULL + print
                760     LOAD_CONST                      13: '[!] Fail to get function details at '
                762     LOAD_GLOBAL                     33: NULL + hex
                772     LOAD_FAST                       0: func_ea
                774     CALL                            1
                782     FORMAT_VALUE                    0 (FVC_NONE)
                784     BUILD_STRING                    2
                786     CALL                            1
                794     POP_TOP                         
                796     NOP                             
                798     LOAD_CONST                      0: None
                800     NOP                             
                802     NOP                             
                804     NOP                             
                806     JUMP_FORWARD                    239 (to 1286)
                814     POP_TOP                         
                816     RETURN_CONST                    0: None
                818     LOAD_FAST                       4: _var_var_111
                820     LOAD_FAST                       8: _var_var_114
                822     STORE_ATTR                      19: rettype
                832     LOAD_GLOBAL                     11: NULL + ida_typeinf
                842     LOAD_ATTR                       12: tinfo_t
                862     CALL                            0
                870     STORE_FAST                      9: _var_var_115
                872     LOAD_FAST                       9: _var_var_115
                874     LOAD_ATTR                       41: create_func
                894     LOAD_FAST                       8: _var_var_114
                896     CALL                            1
                904     POP_JUMP_IF_TRUE                34 (to 974)
                906     LOAD_GLOBAL                     7: NULL + print
                916     LOAD_CONST                      14: '[!] Fail to create new function type at '
                918     LOAD_GLOBAL                     33: NULL + hex
                928     LOAD_FAST                       0: func_ea
                930     CALL                            1
                938     FORMAT_VALUE                    0 (FVC_NONE)
                940     BUILD_STRING                    2
                942     CALL                            1
                950     POP_TOP                         
                952     NOP                             
                954     LOAD_CONST                      0: None
                956     NOP                             
                958     NOP                             
                960     NOP                             
                962     JUMP_FORWARD                    161 (to 1286)
                970     POP_TOP                         
                972     RETURN_CONST                    0: None
                974     LOAD_GLOBAL                     29: NULL + ida_nalt
                984     LOAD_ATTR                       42: set_tinfo
                1004    LOAD_FAST                       0: func_ea
                1006    LOAD_FAST                       9: _var_var_115
                1008    CALL                            2
                1016    POP_JUMP_IF_TRUE                34 (to 1086)
                1018    LOAD_GLOBAL                     7: NULL + print
                1028    LOAD_CONST                      15: '[!] Fail to apply new function type at '
                1030    LOAD_GLOBAL                     33: NULL + hex
                1040    LOAD_FAST                       0: func_ea
                1042    CALL                            1
                1050    FORMAT_VALUE                    0 (FVC_NONE)
                1052    BUILD_STRING                    2
                1054    CALL                            1
                1062    POP_TOP                         
                1064    NOP                             
                1066    LOAD_CONST                      0: None
                1068    NOP                             
                1070    NOP                             
                1072    NOP                             
                1074    JUMP_FORWARD                    105 (to 1286)
                1082    POP_TOP                         
                1084    RETURN_CONST                    0: None
                1086    LOAD_GLOBAL                     7: NULL + print
                1096    LOAD_CONST                      16: '[+] Successfully set return type '
                1098    LOAD_FAST                       3: _var_var_110
                1100    FORMAT_VALUE                    0 (FVC_NONE)
                1102    LOAD_CONST                      17: ' for function '
                1104    LOAD_GLOBAL                     33: NULL + hex
                1114    LOAD_FAST                       0: func_ea
                1116    CALL                            1
                1124    FORMAT_VALUE                    0 (FVC_NONE)
                1126    BUILD_STRING                    4
                1128    CALL                            1
                1136    POP_TOP                         
                1138    LOAD_GLOBAL                     15: NULL + idaapi
                1148    LOAD_ATTR                       44: open_pseudocode
                1168    LOAD_FAST                       0: func_ea
                1170    LOAD_CONST                      18: 0
                1172    CALL                            2
                1180    STORE_FAST                      10: _var_var_116
                1182    LOAD_FAST                       10: _var_var_116
                1184    POP_JUMP_IF_FALSE               26 (to 1238)
                1186    LOAD_FAST                       10: _var_var_116
                1188    LOAD_ATTR                       46: cfunc
                1208    LOAD_ATTR                       49: refresh_func_ctext
                1228    CALL                            0
                1236    POP_TOP                         
                1238    LOAD_CONST                      9: True
                1240    NOP                             
                1242    NOP                             
                1244    NOP                             
                1246    JUMP_FORWARD                    19 (to 1286)
                1254    POP_TOP                         
                1256    RETURN_CONST                    9: True
                1258    PUSH_EXC_INFO                   
                1260    PUSH_NULL                       
                1262    LOAD_CONST                      6: '__pyarmor_exit_55248__'
                1264    NOP                             
                1266    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xd0\x04\x00\x00\x00\x00\x00\x00'
                1268    CALL                            1
                1276    POP_TOP                         
                1278    RERAISE                         0
                1280    COPY                            3
                1282    POP_EXCEPT                      
                1284    RERAISE                         1
                1286    PUSH_NULL                       
                1288    LOAD_CONST                      6: '__pyarmor_exit_55248__'
                1290    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xd0\x04\x00\x00\x00\x00\x00\x00'
                1292    BUILD_TUPLE                     1
                1294    CALL_FUNCTION_EX                0
                1296    POP_TOP                         
                1298    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction_func_name
            Qualified Name: apply_prediction_func_name
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 8
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'isinstance'
                'str'
                'idc'
                'set_name'
                'print'
                'hex'
                'dict'
                'get_func_name'
                'get'
                'get_name_ea_simple'
                'idaapi'
                'BADADDR'
                'list'
                'open_pseudocode'
                'cfunc'
                'refresh_func_ctext'
            [Locals+Names]
                'func_ea'
                'prediction'
                '__assert_armored__'
                '_var_var_74'
                '_var_var_117'
                '_var_var_118'
                '_var_var_119'
                '_var_var_116'
            [Constants]
                None
                '__pyarmor_assert_55249__'
                '__pyarmor_enter_55250__'
                b'<COAddr>\x01\x00\x00\x1a\x98\x04\x00\x00\x00\x00\x00\x00'
                '[!] Fail to set function name '
                ' at '
                '__pyarmor_exit_55251__'
                'funcname'
                'original'
                'prediction'
                '[!] found bad funcname in prediction: '
                '[!] Fail to apply new name to original name: '
                '[+] Successfully set new name '
                ' for old name: '
                0
                True
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55250__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x98\x04\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + isinstance
                38      LOAD_FAST                       1: prediction
                40      LOAD_GLOBAL                     2: str
                50      CALL                            2
                58      POP_JUMP_IF_FALSE               62 (to 184)
                60      LOAD_FAST                       1: prediction
                62      STORE_FAST                      3: _var_var_74
                64      LOAD_GLOBAL                     5: NULL + idc
                74      LOAD_ATTR                       6: set_name
                94      LOAD_FAST                       0: func_ea
                96      LOAD_FAST                       3: _var_var_74
                98      CALL                            2
                106     POP_JUMP_IF_TRUE                486 (to 1082)
                110     LOAD_GLOBAL                     9: NULL + print
                120     LOAD_CONST                      4: '[!] Fail to set function name '
                122     LOAD_FAST                       3: _var_var_74
                124     FORMAT_VALUE                    0 (FVC_NONE)
                126     LOAD_CONST                      5: ' at '
                128     LOAD_GLOBAL                     11: NULL + hex
                138     LOAD_FAST                       0: func_ea
                140     CALL                            1
                148     FORMAT_VALUE                    0 (FVC_NONE)
                150     BUILD_STRING                    4
                152     CALL                            1
                160     POP_TOP                         
                162     NOP                             
                164     LOAD_CONST                      0: None
                166     NOP                             
                168     NOP                             
                170     JUMP_FORWARD                    528 (to 1230)
                180     POP_TOP                         
                182     RETURN_CONST                    0: None
                184     LOAD_GLOBAL                     1: NULL + isinstance
                194     LOAD_FAST                       1: prediction
                196     LOAD_GLOBAL                     12: dict
                206     CALL                            2
                214     POP_JUMP_IF_FALSE               218 (to 652)
                216     LOAD_GLOBAL                     5: NULL + idc
                226     LOAD_ATTR                       14: get_func_name
                246     LOAD_FAST                       0: func_ea
                248     CALL                            1
                256     STORE_FAST                      4: _var_var_117
                258     LOAD_FAST                       1: prediction
                260     LOAD_ATTR                       17: get
                280     LOAD_CONST                      7: 'funcname'
                282     LOAD_CONST                      0: None
                284     CALL                            2
                292     STORE_FAST                      3: _var_var_74
                294     LOAD_FAST                       3: _var_var_74
                296     POP_JUMP_IF_TRUE                63 (to 424)
                298     LOAD_FAST                       1: prediction
                300     LOAD_ATTR                       17: get
                320     LOAD_CONST                      8: 'original'
                322     LOAD_CONST                      0: None
                324     CALL                            2
                332     STORE_FAST                      4: _var_var_117
                334     LOAD_FAST                       1: prediction
                336     LOAD_ATTR                       17: get
                356     LOAD_CONST                      9: 'prediction'
                358     LOAD_CONST                      0: None
                360     CALL                            2
                368     STORE_FAST                      3: _var_var_74
                370     LOAD_FAST                       3: _var_var_74
                372     POP_JUMP_IF_TRUE                25 (to 424)
                374     LOAD_GLOBAL                     9: NULL + print
                384     LOAD_CONST                      10: '[!] found bad funcname in prediction: '
                386     LOAD_FAST                       1: prediction
                388     FORMAT_VALUE                    0 (FVC_NONE)
                390     BUILD_STRING                    2
                392     CALL                            1
                400     POP_TOP                         
                402     NOP                             
                404     LOAD_CONST                      0: None
                406     NOP                             
                408     NOP                             
                410     JUMP_FORWARD                    408 (to 1230)
                420     POP_TOP                         
                422     RETURN_CONST                    0: None
                424     LOAD_GLOBAL                     5: NULL + idc
                434     LOAD_ATTR                       18: get_name_ea_simple
                454     LOAD_FAST                       4: _var_var_117
                456     CALL                            1
                464     STORE_FAST                      5: _var_var_118
                466     LOAD_FAST                       5: _var_var_118
                468     POP_JUMP_IF_FALSE               19 (to 508)
                470     LOAD_FAST                       5: _var_var_118
                472     LOAD_GLOBAL                     20: idaapi
                482     LOAD_ATTR                       22: BADADDR
                502     COMPARE_OP                      40 (==)
                506     POP_JUMP_IF_FALSE               25 (to 558)
                508     LOAD_GLOBAL                     9: NULL + print
                518     LOAD_CONST                      11: '[!] Fail to apply new name to original name: '
                520     LOAD_FAST                       4: _var_var_117
                522     FORMAT_VALUE                    0 (FVC_NONE)
                524     BUILD_STRING                    2
                526     CALL                            1
                534     POP_TOP                         
                536     NOP                             
                538     LOAD_CONST                      0: None
                540     NOP                             
                542     NOP                             
                544     JUMP_FORWARD                    341 (to 1230)
                554     POP_TOP                         
                556     RETURN_CONST                    0: None
                558     LOAD_GLOBAL                     5: NULL + idc
                568     LOAD_ATTR                       6: set_name
                588     LOAD_FAST                       5: _var_var_118
                590     LOAD_FAST                       3: _var_var_74
                592     CALL                            2
                600     POP_JUMP_IF_TRUE                240 (to 1082)
                602     LOAD_GLOBAL                     9: NULL + print
                612     LOAD_CONST                      11: '[!] Fail to apply new name to original name: '
                614     LOAD_FAST                       4: _var_var_117
                616     FORMAT_VALUE                    0 (FVC_NONE)
                618     BUILD_STRING                    2
                620     CALL                            1
                628     POP_TOP                         
                630     NOP                             
                632     LOAD_CONST                      0: None
                634     NOP                             
                636     NOP                             
                638     JUMP_FORWARD                    294 (to 1230)
                648     POP_TOP                         
                650     RETURN_CONST                    0: None
                652     LOAD_GLOBAL                     1: NULL + isinstance
                662     LOAD_FAST                       1: prediction
                664     LOAD_GLOBAL                     24: list
                674     CALL                            2
                682     POP_JUMP_IF_FALSE               174 (to 1032)
                684     LOAD_FAST                       1: prediction
                686     GET_ITER                        
                688     FOR_ITER                        168 (to 1026)
                692     STORE_FAST                      6: _var_var_119
                694     LOAD_FAST                       6: _var_var_119
                696     LOAD_ATTR                       17: get
                716     LOAD_CONST                      8: 'original'
                718     LOAD_CONST                      0: None
                720     CALL                            2
                728     STORE_FAST                      4: _var_var_117
                730     LOAD_FAST                       6: _var_var_119
                732     LOAD_ATTR                       17: get
                752     LOAD_CONST                      9: 'prediction'
                754     LOAD_CONST                      0: None
                756     CALL                            2
                764     STORE_FAST                      3: _var_var_74
                766     LOAD_FAST                       3: _var_var_74
                768     POP_JUMP_IF_FALSE               2 (to 774)
                770     LOAD_FAST                       4: _var_var_117
                772     POP_JUMP_IF_TRUE                15 (to 804)
                774     LOAD_GLOBAL                     9: NULL + print
                784     LOAD_CONST                      10: '[!] found bad funcname in prediction: '
                786     LOAD_FAST                       6: _var_var_119
                788     FORMAT_VALUE                    0 (FVC_NONE)
                790     BUILD_STRING                    2
                792     CALL                            1
                800     POP_TOP                         
                802     JUMP_BACKWARD                   58 (to 688)
                804     LOAD_GLOBAL                     5: NULL + idc
                814     LOAD_ATTR                       18: get_name_ea_simple
                834     LOAD_FAST                       4: _var_var_117
                836     CALL                            1
                844     STORE_FAST                      5: _var_var_118
                846     LOAD_FAST                       5: _var_var_118
                848     POP_JUMP_IF_FALSE               19 (to 888)
                850     LOAD_FAST                       5: _var_var_118
                852     LOAD_GLOBAL                     20: idaapi
                862     LOAD_ATTR                       22: BADADDR
                882     COMPARE_OP                      40 (==)
                886     POP_JUMP_IF_FALSE               15 (to 918)
                888     LOAD_GLOBAL                     9: NULL + print
                898     LOAD_CONST                      11: '[!] Fail to apply new name to original name: '
                900     LOAD_FAST                       4: _var_var_117
                902     FORMAT_VALUE                    0 (FVC_NONE)
                904     BUILD_STRING                    2
                906     CALL                            1
                914     POP_TOP                         
                916     JUMP_BACKWARD                   115 (to 688)
                918     LOAD_GLOBAL                     5: NULL + idc
                928     LOAD_ATTR                       6: set_name
                948     LOAD_FAST                       5: _var_var_118
                950     LOAD_FAST                       3: _var_var_74
                952     CALL                            2
                960     POP_JUMP_IF_TRUE                15 (to 992)
                962     LOAD_GLOBAL                     9: NULL + print
                972     LOAD_CONST                      11: '[!] Fail to apply new name to original name: '
                974     LOAD_FAST                       4: _var_var_117
                976     FORMAT_VALUE                    0 (FVC_NONE)
                978     BUILD_STRING                    2
                980     CALL                            1
                988     POP_TOP                         
                990     JUMP_BACKWARD                   152 (to 688)
                992     LOAD_GLOBAL                     9: NULL + print
                1002    LOAD_CONST                      12: '[+] Successfully set new name '
                1004    LOAD_FAST                       3: _var_var_74
                1006    FORMAT_VALUE                    0 (FVC_NONE)
                1008    LOAD_CONST                      13: ' for old name: '
                1010    LOAD_FAST                       4: _var_var_117
                1012    FORMAT_VALUE                    0 (FVC_NONE)
                1014    BUILD_STRING                    4
                1016    CALL                            1
                1024    POP_TOP                         
                1026    JUMP_BACKWARD                   170 (to 688)
                1028    END_FOR                         
                1030    JUMP_FORWARD                    25 (to 1082)
                1032    LOAD_GLOBAL                     9: NULL + print
                1042    LOAD_CONST                      10: '[!] found bad funcname in prediction: '
                1044    LOAD_FAST                       1: prediction
                1046    FORMAT_VALUE                    0 (FVC_NONE)
                1048    BUILD_STRING                    2
                1050    CALL                            1
                1058    POP_TOP                         
                1060    NOP                             
                1062    LOAD_CONST                      0: None
                1064    NOP                             
                1066    NOP                             
                1068    NOP                             
                1070    JUMP_FORWARD                    79 (to 1230)
                1078    POP_TOP                         
                1080    RETURN_CONST                    0: None
                1082    LOAD_GLOBAL                     21: NULL + idaapi
                1092    LOAD_ATTR                       26: open_pseudocode
                1112    LOAD_FAST                       0: func_ea
                1114    LOAD_CONST                      14: 0
                1116    CALL                            2
                1124    STORE_FAST                      7: _var_var_116
                1126    LOAD_FAST                       7: _var_var_116
                1128    POP_JUMP_IF_FALSE               26 (to 1182)
                1130    LOAD_FAST                       7: _var_var_116
                1132    LOAD_ATTR                       28: cfunc
                1152    LOAD_ATTR                       31: refresh_func_ctext
                1172    CALL                            0
                1180    POP_TOP                         
                1182    LOAD_CONST                      15: True
                1184    NOP                             
                1186    NOP                             
                1188    NOP                             
                1190    JUMP_FORWARD                    19 (to 1230)
                1198    POP_TOP                         
                1200    RETURN_CONST                    15: True
                1202    PUSH_EXC_INFO                   
                1204    PUSH_NULL                       
                1206    LOAD_CONST                      6: '__pyarmor_exit_55251__'
                1208    NOP                             
                1210    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x98\x04\x00\x00\x00\x00\x00\x00'
                1212    CALL                            1
                1220    POP_TOP                         
                1222    RERAISE                         0
                1224    COPY                            3
                1226    POP_EXCEPT                      
                1228    RERAISE                         1
                1230    PUSH_NULL                       
                1232    LOAD_CONST                      6: '__pyarmor_exit_55251__'
                1234    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x98\x04\x00\x00\x00\x00\x00\x00'
                1236    BUILD_TUPLE                     1
                1238    CALL_FUNCTION_EX                0
                1240    POP_TOP                         
                1242    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: add_array_type
            Qualified Name: add_array_type
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'ida_typeinf'
                'tinfo_t'
                'endswith'
                'parse_decl'
                'idaapi'
                'get_idati'
                'PT_TYP'
                'PT_SIL'
                'copy'
                'reversed'
                'create_array'
            [Locals+Names]
                'type_name'
                'array_dims'
                '__assert_armored__'
                '_var_var_120'
                '_var_var_121'
                '_var_var_122'
                '_var_var_111'
            [Constants]
                '添加数组类型定义\n    Args:\n        type_name: 类型名称，如 "char"\n        array_dims: 数组维度列表，如 [32] 表示一维数组，[4,4] 表示二维数组\n    Returns:\n        tinfo_t: 添加成功的类型\n    '
                '__pyarmor_assert_55252__'
                '__pyarmor_enter_55253__'
                b'<COAddr>\x03\x00\x00\x1a\x14\x02\x00\x00\x00\x00\x00\x00'
                '[+] Adding typedef for array type '
                ';'
                None
                '[!] Failed to parse base type '
                '__pyarmor_exit_55254__'
                '[!] Failed to create array with dimension '
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55253__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x14\x02\x00\x00\x00\x00\x00\x00'
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
                38      LOAD_CONST                      4: '[+] Adding typedef for array type '
                40      LOAD_FAST                       0: type_name
                42      FORMAT_VALUE                    0 (FVC_NONE)
                44      BUILD_STRING                    2
                46      CALL                            1
                54      POP_TOP                         
                56      LOAD_GLOBAL                     3: NULL + ida_typeinf
                66      LOAD_ATTR                       4: tinfo_t
                86      CALL                            0
                94      STORE_FAST                      3: _var_var_120
                96      LOAD_FAST                       0: type_name
                98      LOAD_ATTR                       7: endswith
                118     LOAD_CONST                      5: ';'
                120     CALL                            1
                128     POP_JUMP_IF_TRUE                5 (to 140)
                130     LOAD_FAST                       0: type_name
                132     FORMAT_VALUE                    0 (FVC_NONE)
                134     LOAD_CONST                      5: ';'
                136     BUILD_STRING                    2
                138     STORE_FAST                      0: type_name
                140     LOAD_GLOBAL                     3: NULL + ida_typeinf
                150     LOAD_ATTR                       8: parse_decl
                170     LOAD_FAST                       3: _var_var_120
                172     LOAD_GLOBAL                     11: NULL + idaapi
                182     LOAD_ATTR                       12: get_idati
                202     CALL                            0
                210     LOAD_FAST                       0: type_name
                212     LOAD_GLOBAL                     2: ida_typeinf
                222     LOAD_ATTR                       14: PT_TYP
                242     LOAD_GLOBAL                     2: ida_typeinf
                252     LOAD_ATTR                       16: PT_SIL
                272     BINARY_OP                       7 (|)
                276     CALL                            4
                284     LOAD_CONST                      6: None
                286     COMPARE_OP                      40 (==)
                290     POP_JUMP_IF_FALSE               25 (to 342)
                292     LOAD_GLOBAL                     1: NULL + print
                302     LOAD_CONST                      7: '[!] Failed to parse base type '
                304     LOAD_FAST                       0: type_name
                306     FORMAT_VALUE                    0 (FVC_NONE)
                308     BUILD_STRING                    2
                310     CALL                            1
                318     POP_TOP                         
                320     NOP                             
                322     LOAD_CONST                      6: None
                324     NOP                             
                326     NOP                             
                328     NOP                             
                330     JUMP_FORWARD                    127 (to 586)
                338     POP_TOP                         
                340     RETURN_CONST                    6: None
                342     LOAD_FAST                       3: _var_var_120
                344     LOAD_ATTR                       19: copy
                364     CALL                            0
                372     STORE_FAST                      4: _var_var_121
                374     LOAD_GLOBAL                     21: NULL + reversed
                384     LOAD_FAST                       1: array_dims
                386     CALL                            1
                394     GET_ITER                        
                396     FOR_ITER                        67 (to 532)
                400     STORE_FAST                      5: _var_var_122
                402     LOAD_GLOBAL                     3: NULL + ida_typeinf
                412     LOAD_ATTR                       4: tinfo_t
                432     CALL                            0
                440     STORE_FAST                      6: _var_var_111
                442     LOAD_FAST                       6: _var_var_111
                444     LOAD_ATTR                       23: create_array
                464     LOAD_FAST                       4: _var_var_121
                466     LOAD_FAST                       5: _var_var_122
                468     CALL                            2
                476     POP_JUMP_IF_TRUE                25 (to 528)
                478     LOAD_GLOBAL                     1: NULL + print
                488     LOAD_CONST                      9: '[!] Failed to create array with dimension '
                490     LOAD_FAST                       5: _var_var_122
                492     FORMAT_VALUE                    0 (FVC_NONE)
                494     BUILD_STRING                    2
                496     CALL                            1
                504     POP_TOP                         
                506     POP_TOP                         
                508     LOAD_CONST                      6: None
                510     NOP                             
                512     NOP                             
                514     NOP                             
                516     JUMP_FORWARD                    34 (to 586)
                524     POP_TOP                         
                526     RETURN_CONST                    6: None
                528     LOAD_FAST                       6: _var_var_111
                530     STORE_FAST                      4: _var_var_121
                532     JUMP_BACKWARD                   69 (to 396)
                534     END_FOR                         
                536     LOAD_FAST                       4: _var_var_121
                538     NOP                             
                540     NOP                             
                542     NOP                             
                544     JUMP_FORWARD                    20 (to 586)
                546     CALL                            1
                554     POP_TOP                         
                556     RETURN_VALUE                    
                558     PUSH_EXC_INFO                   
                560     PUSH_NULL                       
                562     LOAD_CONST                      8: '__pyarmor_exit_55254__'
                564     NOP                             
                566     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x14\x02\x00\x00\x00\x00\x00\x00'
                568     CALL                            1
                576     POP_TOP                         
                578     RERAISE                         0
                580     COPY                            3
                582     POP_EXCEPT                      
                584     RERAISE                         1
                586     PUSH_NULL                       
                588     LOAD_CONST                      8: '__pyarmor_exit_55254__'
                590     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x14\x02\x00\x00\x00\x00\x00\x00'
                592     BUILD_TUPLE                     1
                594     CALL_FUNCTION_EX                0
                596     POP_TOP                         
                598     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: add_enum_type
            Qualified Name: add_enum_type
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'list'
                'keys'
                'print'
                'idc'
                'get_enum'
                'idaapi'
                'BADADDR'
                'del_enum'
                'add_enum'
                'isinstance'
                'str'
                'split'
                'strip'
                'len'
                'type'
                'int'
                'ord'
                'add_enum_member'
            [Locals+Names]
                'enum_name'
                'enum_details'
                '__assert_armored__'
                '_var_var_123'
                '_var_var_124'
                '_var_var_27'
                '_var_var_125'
                '_var_var_126'
            [Constants]
                '添加枚举类型\n    Args:\n        enum_name: 枚举名称\n        enum_details: 枚举成员列表，每项格式为 [name, value]\n    Returns:\n        tinfo_t: 添加成功的枚举类型\n    '
                '__pyarmor_assert_55255__'
                '__pyarmor_enter_55256__'
                b'<COAddr>\x01\x00\x00\x1ab\x04\x00\x00\x00\x00\x00\x00'
                0
                '[+] Adding enum '
                '[*] Removing existing enum '
                -1
                '[!] Failed to create enum '
                '__pyarmor_exit_55257__'
                None
                '='
                1
                2
                '[!] Bad enum member '
                '[!] Bad enum member value '
                ' = '
                '[*] Adding enum member '
                '[!] Failed to add enum member '
                '[+] Successfully added enum member '
                '[+] Successfully created enum '
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55256__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ab\x04\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + list
                38      LOAD_FAST                       1: enum_details
                40      LOAD_ATTR                       3: keys
                60      CALL                            0
                68      CALL                            1
                76      LOAD_CONST                      4: 0
                78      BINARY_SUBSCR                   
                82      STORE_FAST                      0: enum_name
                84      LOAD_FAST                       1: enum_details
                86      LOAD_FAST                       0: enum_name
                88      BINARY_SUBSCR                   
                92      STORE_FAST                      1: enum_details
                94      LOAD_GLOBAL                     5: NULL + print
                104     LOAD_CONST                      5: '[+] Adding enum '
                106     LOAD_FAST                       0: enum_name
                108     FORMAT_VALUE                    0 (FVC_NONE)
                110     BUILD_STRING                    2
                112     CALL                            1
                120     POP_TOP                         
                122     LOAD_GLOBAL                     7: NULL + idc
                132     LOAD_ATTR                       8: get_enum
                152     LOAD_FAST                       0: enum_name
                154     CALL                            1
                162     STORE_FAST                      3: _var_var_123
                164     LOAD_FAST                       3: _var_var_123
                166     LOAD_GLOBAL                     10: idaapi
                176     LOAD_ATTR                       12: BADADDR
                196     COMPARE_OP                      55 (!=)
                200     POP_JUMP_IF_FALSE               35 (to 272)
                202     LOAD_GLOBAL                     5: NULL + print
                212     LOAD_CONST                      6: '[*] Removing existing enum '
                214     LOAD_FAST                       0: enum_name
                216     FORMAT_VALUE                    0 (FVC_NONE)
                218     BUILD_STRING                    2
                220     CALL                            1
                228     POP_TOP                         
                230     LOAD_GLOBAL                     7: NULL + idc
                240     LOAD_ATTR                       14: del_enum
                260     LOAD_FAST                       3: _var_var_123
                262     CALL                            1
                270     POP_TOP                         
                272     LOAD_GLOBAL                     7: NULL + idc
                282     LOAD_ATTR                       16: add_enum
                302     LOAD_CONST                      7: -1
                304     LOAD_FAST                       0: enum_name
                306     LOAD_CONST                      4: 0
                308     CALL                            3
                316     STORE_FAST                      4: _var_var_124
                318     LOAD_FAST                       4: _var_var_124
                320     LOAD_CONST                      7: -1
                322     COMPARE_OP                      40 (==)
                326     POP_JUMP_IF_TRUE                19 (to 366)
                328     LOAD_FAST                       4: _var_var_124
                330     LOAD_GLOBAL                     10: idaapi
                340     LOAD_ATTR                       12: BADADDR
                360     COMPARE_OP                      40 (==)
                364     POP_JUMP_IF_FALSE               25 (to 416)
                366     LOAD_GLOBAL                     5: NULL + print
                376     LOAD_CONST                      8: '[!] Failed to create enum '
                378     LOAD_FAST                       0: enum_name
                380     FORMAT_VALUE                    0 (FVC_NONE)
                382     BUILD_STRING                    2
                384     CALL                            1
                392     POP_TOP                         
                394     NOP                             
                396     LOAD_CONST                      10: None
                398     NOP                             
                400     NOP                             
                402     JUMP_FORWARD                    385 (to 1176)
                412     POP_TOP                         
                414     RETURN_CONST                    10: None
                416     LOAD_FAST                       1: enum_details
                418     GET_ITER                        
                420     FOR_ITER                        326 (to 1076)
                426     STORE_FAST                      5: _var_var_27
                428     LOAD_GLOBAL                     19: NULL + isinstance
                438     LOAD_FAST                       5: _var_var_27
                440     LOAD_GLOBAL                     20: str
                450     CALL                            2
                458     POP_JUMP_IF_FALSE               56 (to 572)
                460     LOAD_FAST                       5: _var_var_27
                462     LOAD_ATTR                       23: split
                482     LOAD_CONST                      11: '='
                484     CALL                            1
                492     STORE_FAST                      5: _var_var_27
                494     LOAD_FAST                       5: _var_var_27
                496     LOAD_CONST                      4: 0
                498     BINARY_SUBSCR                   
                502     LOAD_ATTR                       25: strip
                522     CALL                            0
                530     LOAD_FAST                       5: _var_var_27
                532     LOAD_CONST                      12: 1
                534     BINARY_SUBSCR                   
                538     LOAD_ATTR                       25: strip
                558     CALL                            0
                566     STORE_FAST                      7: _var_var_126
                568     STORE_FAST                      6: _var_var_125
                570     JUMP_FORWARD                    101 (to 774)
                572     LOAD_GLOBAL                     19: NULL + isinstance
                582     LOAD_FAST                       5: _var_var_27
                584     LOAD_GLOBAL                     0: list
                594     CALL                            2
                602     POP_JUMP_IF_FALSE               70 (to 744)
                604     LOAD_GLOBAL                     27: NULL + len
                614     LOAD_FAST                       5: _var_var_27
                616     CALL                            1
                624     LOAD_CONST                      13: 2
                626     COMPARE_OP                      92 (>=)
                630     POP_JUMP_IF_FALSE               56 (to 744)
                632     LOAD_GLOBAL                     19: NULL + isinstance
                642     LOAD_FAST                       5: _var_var_27
                644     LOAD_CONST                      4: 0
                646     BINARY_SUBSCR                   
                650     LOAD_GLOBAL                     20: str
                660     CALL                            2
                668     POP_JUMP_IF_FALSE               37 (to 744)
                670     LOAD_GLOBAL                     29: NULL + type
                680     LOAD_FAST                       5: _var_var_27
                682     LOAD_CONST                      12: 1
                684     BINARY_SUBSCR                   
                688     CALL                            1
                696     LOAD_GLOBAL                     30: int
                706     LOAD_GLOBAL                     20: str
                716     BUILD_TUPLE                     2
                718     CONTAINS_OP                     0 (in)
                720     POP_JUMP_IF_FALSE               11 (to 744)
                722     LOAD_FAST                       5: _var_var_27
                724     LOAD_CONST                      4: 0
                726     BINARY_SUBSCR                   
                730     LOAD_FAST                       5: _var_var_27
                732     LOAD_CONST                      12: 1
                734     BINARY_SUBSCR                   
                738     STORE_FAST                      7: _var_var_126
                740     STORE_FAST                      6: _var_var_125
                742     JUMP_FORWARD                    15 (to 774)
                744     LOAD_GLOBAL                     5: NULL + print
                754     LOAD_CONST                      14: '[!] Bad enum member '
                756     LOAD_FAST                       5: _var_var_27
                758     FORMAT_VALUE                    0 (FVC_NONE)
                760     BUILD_STRING                    2
                762     CALL                            1
                770     POP_TOP                         
                772     JUMP_BACKWARD                   177 (to 420)
                774     LOAD_GLOBAL                     19: NULL + isinstance
                784     LOAD_FAST                       7: _var_var_126
                786     LOAD_GLOBAL                     20: str
                796     CALL                            2
                804     POP_JUMP_IF_FALSE               26 (to 858)
                806     LOAD_GLOBAL                     27: NULL + len
                816     LOAD_FAST                       7: _var_var_126
                818     CALL                            1
                826     LOAD_CONST                      12: 1
                828     COMPARE_OP                      40 (==)
                832     POP_JUMP_IF_FALSE               12 (to 858)
                834     LOAD_GLOBAL                     33: NULL + ord
                844     LOAD_FAST                       7: _var_var_126
                846     CALL                            1
                854     STORE_FAST                      7: _var_var_126
                856     JUMP_FORWARD                    35 (to 928)
                858     LOAD_GLOBAL                     19: NULL + isinstance
                868     LOAD_FAST                       7: _var_var_126
                870     LOAD_GLOBAL                     30: int
                880     CALL                            2
                888     POP_JUMP_IF_FALSE               1 (to 892)
                890     JUMP_FORWARD                    18 (to 928)
                892     LOAD_GLOBAL                     5: NULL + print
                902     LOAD_CONST                      15: '[!] Bad enum member value '
                904     LOAD_FAST                       6: _var_var_125
                906     FORMAT_VALUE                    0 (FVC_NONE)
                908     LOAD_CONST                      16: ' = '
                910     LOAD_FAST                       7: _var_var_126
                912     FORMAT_VALUE                    0 (FVC_NONE)
                914     BUILD_STRING                    4
                916     CALL                            1
                924     POP_TOP                         
                926     JUMP_BACKWARD                   254 (to 420)
                928     LOAD_GLOBAL                     5: NULL + print
                938     LOAD_CONST                      17: '[*] Adding enum member '
                940     LOAD_FAST                       6: _var_var_125
                942     FORMAT_VALUE                    0 (FVC_NONE)
                944     LOAD_CONST                      16: ' = '
                946     LOAD_FAST                       7: _var_var_126
                948     FORMAT_VALUE                    0 (FVC_NONE)
                950     BUILD_STRING                    4
                952     CALL                            1
                960     POP_TOP                         
                962     LOAD_GLOBAL                     7: NULL + idc
                972     LOAD_ATTR                       34: add_enum_member
                992     LOAD_FAST                       4: _var_var_124
                994     LOAD_FAST                       6: _var_var_125
                996     LOAD_FAST                       7: _var_var_126
                998     CALL                            3
                1006    LOAD_CONST                      4: 0
                1008    COMPARE_OP                      55 (!=)
                1012    POP_JUMP_IF_FALSE               16 (to 1046)
                1014    LOAD_GLOBAL                     5: NULL + print
                1024    LOAD_CONST                      18: '[!] Failed to add enum member '
                1026    LOAD_FAST                       6: _var_var_125
                1028    FORMAT_VALUE                    0 (FVC_NONE)
                1030    BUILD_STRING                    2
                1032    CALL                            1
                1040    POP_TOP                         
                1042    JUMP_BACKWARD                   313 (to 420)
                1046    LOAD_GLOBAL                     5: NULL + print
                1056    LOAD_CONST                      19: '[+] Successfully added enum member '
                1058    LOAD_FAST                       6: _var_var_125
                1060    FORMAT_VALUE                    0 (FVC_NONE)
                1062    BUILD_STRING                    2
                1064    CALL                            1
                1072    POP_TOP                         
                1074    JUMP_BACKWARD                   329 (to 420)
                1078    END_FOR                         
                1080    LOAD_GLOBAL                     5: NULL + print
                1090    LOAD_CONST                      20: '[+] Successfully created enum '
                1092    LOAD_FAST                       0: enum_name
                1094    FORMAT_VALUE                    0 (FVC_NONE)
                1096    BUILD_STRING                    2
                1098    CALL                            1
                1106    POP_TOP                         
                1108    LOAD_GLOBAL                     9: NULL + get_enum
                1118    LOAD_FAST                       4: _var_var_124
                1120    CALL                            1
                1128    NOP                             
                1130    NOP                             
                1132    NOP                             
                1134    JUMP_FORWARD                    20 (to 1176)
                1136    CALL                            1
                1144    POP_TOP                         
                1146    RETURN_VALUE                    
                1148    PUSH_EXC_INFO                   
                1150    PUSH_NULL                       
                1152    LOAD_CONST                      9: '__pyarmor_exit_55257__'
                1154    NOP                             
                1156    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ab\x04\x00\x00\x00\x00\x00\x00'
                1158    CALL                            1
                1166    POP_TOP                         
                1168    RERAISE                         0
                1170    COPY                            3
                1172    POP_EXCEPT                      
                1174    RERAISE                         1
                1176    PUSH_NULL                       
                1178    LOAD_CONST                      9: '__pyarmor_exit_55257__'
                1180    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ab\x04\x00\x00\x00\x00\x00\x00'
                1182    BUILD_TUPLE                     1
                1184    CALL_FUNCTION_EX                0
                1186    POP_TOP                         
                1188    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: add_empty_struct_type
            Qualified Name: add_empty_struct_type
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'replace'
                'strip'
                'get_struc'
                'idc'
                'add_struc'
                'idaapi'
                'BADADDR'
                'print'
                'set_fixed_struct'
                'set_struct_size'
            [Locals+Names]
                'struct_name'
                'struct_size'
                '__assert_armored__'
                '_var_var_84'
            [Constants]
                None
                '__pyarmor_assert_55258__'
                '__pyarmor_enter_55259__'
                b'<COAddr>\x01\x00\x00\x1aT\x01\x00\x00\x00\x00\x00\x00'
                '*'
                ''
                'struct '
                -1
                0
                '[!] Failed to create struct '
                '__pyarmor_exit_55260__'
                True
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55259__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: struct_name
                30      LOAD_ATTR                       1: replace
                50      LOAD_CONST                      4: '*'
                52      LOAD_CONST                      5: ''
                54      CALL                            2
                62      LOAD_ATTR                       1: replace
                82      LOAD_CONST                      6: 'struct '
                84      LOAD_CONST                      5: ''
                86      CALL                            2
                94      LOAD_ATTR                       3: strip
                114     CALL                            0
                122     STORE_FAST                      0: struct_name
                124     LOAD_GLOBAL                     5: NULL + get_struc
                134     LOAD_GLOBAL                     7: NULL + idc
                144     LOAD_ATTR                       8: add_struc
                164     LOAD_CONST                      7: -1
                166     LOAD_FAST                       0: struct_name
                168     LOAD_CONST                      8: 0
                170     CALL                            3
                178     CALL                            1
                186     STORE_FAST                      3: _var_var_84
                188     LOAD_FAST                       3: _var_var_84
                190     LOAD_GLOBAL                     10: idaapi
                200     LOAD_ATTR                       12: BADADDR
                220     COMPARE_OP                      40 (==)
                224     POP_JUMP_IF_FALSE               25 (to 276)
                226     LOAD_GLOBAL                     15: NULL + print
                236     LOAD_CONST                      9: '[!] Failed to create struct '
                238     LOAD_FAST                       0: struct_name
                240     FORMAT_VALUE                    0 (FVC_NONE)
                242     BUILD_STRING                    2
                244     CALL                            1
                252     POP_TOP                         
                254     NOP                             
                256     LOAD_CONST                      0: None
                258     NOP                             
                260     NOP                             
                262     NOP                             
                264     JUMP_FORWARD                    64 (to 394)
                272     POP_TOP                         
                274     RETURN_CONST                    0: None
                276     LOAD_FAST                       3: _var_var_84
                278     LOAD_ATTR                       17: set_fixed_struct
                298     LOAD_CONST                      11: True
                300     CALL                            1
                308     POP_TOP                         
                310     LOAD_FAST                       3: _var_var_84
                312     LOAD_ATTR                       19: set_struct_size
                332     LOAD_FAST                       1: struct_size
                334     CALL                            1
                342     POP_TOP                         
                344     LOAD_FAST                       3: _var_var_84
                346     NOP                             
                348     NOP                             
                350     NOP                             
                352     JUMP_FORWARD                    20 (to 394)
                354     CALL                            1
                362     POP_TOP                         
                364     RETURN_VALUE                    
                366     PUSH_EXC_INFO                   
                368     PUSH_NULL                       
                370     LOAD_CONST                      10: '__pyarmor_exit_55260__'
                372     NOP                             
                374     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x01\x00\x00\x00\x00\x00\x00'
                376     CALL                            1
                384     POP_TOP                         
                386     RERAISE                         0
                388     COPY                            3
                390     POP_EXCEPT                      
                392     RERAISE                         1
                394     PUSH_NULL                       
                396     LOAD_CONST                      10: '__pyarmor_exit_55260__'
                398     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aT\x01\x00\x00\x00\x00\x00\x00'
                400     BUILD_TUPLE                     1
                402     CALL_FUNCTION_EX                0
                404     POP_TOP                         
                406     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: add_struct_type
            Qualified Name: add_struct_type
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 9
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'list'
                'keys'
                'print'
                'idc'
                'get_struc_id'
                'idaapi'
                'BADADDR'
                'del_struc'
                'add_struc'
                'ida_typeinf'
                'tinfo_t'
                'parse_decl'
                'get_idati'
                'PT_TYP'
                'PT_SIL'
                'add_empty_struct_type'
                'get_size'
                'FF_BYTE'
                'FF_DATA'
                'FF_WORD'
                'FF_DWORD'
                'FF_QWORD'
                'get_tid'
                'FF_STRUCT'
                'copy'
                'remove_ptr_or_array'
                'add_struc_member'
                'get_struc'
                'get_udt_nmembers'
                'set_udm_type'
            [Locals+Names]
                'struct_name'
                'struct_details'
                '__assert_armored__'
                '_var_var_127'
                '_var_var_128'
                '_var_var_129'
                '_var_var_30'
                '_var_var_25'
                '_var_var_26'
                '_var_var_84'
                '_var_var_130'
                '_var_var_131'
                '_var_var_132'
                '_var_var_133'
                '_var_var_134'
                '_var_var_112'
                '_var_var_135'
            [Constants]
                '添加结构体类型\n    Args:\n        struct_name: 结构体名称\n        struct_details: 结构体定义细节 {struct_name: [type_str, name, size]}\n    Returns:\n        tinfo_t: 添加成功的结构体类型\n    '
                '__pyarmor_assert_55261__'
                '__pyarmor_enter_55262__'
                b'<COAddr>\x03\x00\x00\x1a\x00\x08\x00\x00\x00\x00\x00\x00'
                0
                '[+] Adding struct '
                '[*] Removing existing struct '
                -1
                '[!] Failed to create struct '
                '__pyarmor_exit_55263__'
                None
                '[*] Adding member '
                ' with type '
                ' at offset '
                False
                ';'
                '[!] Failed to parse type '
                ' for member '
                True
                1
                2
                4
                8
                '[!] Failed to add member: '
                ' '
                '[+] Successfully added member '
                '[+] Successfully created struct '
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55262__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x00\x08\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + list
                38      LOAD_FAST                       1: struct_details
                40      LOAD_ATTR                       3: keys
                60      CALL                            0
                68      CALL                            1
                76      LOAD_CONST                      4: 0
                78      BINARY_SUBSCR                   
                82      STORE_FAST                      0: struct_name
                84      LOAD_FAST                       1: struct_details
                86      LOAD_FAST                       0: struct_name
                88      BINARY_SUBSCR                   
                92      STORE_FAST                      1: struct_details
                94      LOAD_GLOBAL                     5: NULL + print
                104     LOAD_CONST                      5: '[+] Adding struct '
                106     LOAD_FAST                       0: struct_name
                108     FORMAT_VALUE                    0 (FVC_NONE)
                110     BUILD_STRING                    2
                112     CALL                            1
                120     POP_TOP                         
                122     LOAD_GLOBAL                     7: NULL + idc
                132     LOAD_ATTR                       8: get_struc_id
                152     LOAD_FAST                       0: struct_name
                154     CALL                            1
                162     STORE_FAST                      3: _var_var_127
                164     LOAD_FAST                       3: _var_var_127
                166     LOAD_GLOBAL                     10: idaapi
                176     LOAD_ATTR                       12: BADADDR
                196     COMPARE_OP                      55 (!=)
                200     POP_JUMP_IF_FALSE               35 (to 272)
                202     LOAD_GLOBAL                     5: NULL + print
                212     LOAD_CONST                      6: '[*] Removing existing struct '
                214     LOAD_FAST                       0: struct_name
                216     FORMAT_VALUE                    0 (FVC_NONE)
                218     BUILD_STRING                    2
                220     CALL                            1
                228     POP_TOP                         
                230     LOAD_GLOBAL                     7: NULL + idc
                240     LOAD_ATTR                       14: del_struc
                260     LOAD_FAST                       3: _var_var_127
                262     CALL                            1
                270     POP_TOP                         
                272     LOAD_GLOBAL                     7: NULL + idc
                282     LOAD_ATTR                       16: add_struc
                302     LOAD_CONST                      7: -1
                304     LOAD_FAST                       0: struct_name
                306     LOAD_CONST                      4: 0
                308     CALL                            3
                316     STORE_FAST                      4: _var_var_128
                318     LOAD_FAST                       4: _var_var_128
                320     LOAD_CONST                      7: -1
                322     COMPARE_OP                      40 (==)
                326     POP_JUMP_IF_TRUE                19 (to 366)
                328     LOAD_FAST                       4: _var_var_128
                330     LOAD_GLOBAL                     10: idaapi
                340     LOAD_ATTR                       12: BADADDR
                360     COMPARE_OP                      40 (==)
                364     POP_JUMP_IF_FALSE               25 (to 416)
                366     LOAD_GLOBAL                     5: NULL + print
                376     LOAD_CONST                      8: '[!] Failed to create struct '
                378     LOAD_FAST                       0: struct_name
                380     FORMAT_VALUE                    0 (FVC_NONE)
                382     BUILD_STRING                    2
                384     CALL                            1
                392     POP_TOP                         
                394     NOP                             
                396     LOAD_CONST                      10: None
                398     NOP                             
                400     NOP                             
                402     JUMP_FORWARD                    848 (to 2102)
                412     POP_TOP                         
                414     RETURN_CONST                    10: None
                416     LOAD_CONST                      4: 0
                418     STORE_FAST                      5: _var_var_129
                420     LOAD_FAST                       1: struct_details
                422     GET_ITER                        
                424     FOR_ITER                        787 (to 2002)
                430     UNPACK_SEQUENCE                 3
                434     STORE_FAST                      6: _var_var_30
                436     STORE_FAST                      7: _var_var_25
                438     STORE_FAST                      8: _var_var_26
                440     LOAD_GLOBAL                     5: NULL + print
                450     LOAD_CONST                      11: '[*] Adding member '
                452     LOAD_FAST                       7: _var_var_25
                454     FORMAT_VALUE                    0 (FVC_NONE)
                456     LOAD_CONST                      12: ' with type '
                458     LOAD_FAST                       6: _var_var_30
                460     FORMAT_VALUE                    0 (FVC_NONE)
                462     LOAD_CONST                      13: ' at offset '
                464     LOAD_FAST                       5: _var_var_129
                466     FORMAT_VALUE                    0 (FVC_NONE)
                468     BUILD_STRING                    6
                470     CALL                            1
                478     POP_TOP                         
                480     LOAD_GLOBAL                     19: NULL + ida_typeinf
                490     LOAD_ATTR                       20: tinfo_t
                510     CALL                            0
                518     STORE_FAST                      9: _var_var_84
                520     LOAD_CONST                      14: False
                522     STORE_FAST                      10: _var_var_130
                524     LOAD_GLOBAL                     19: NULL + ida_typeinf
                534     LOAD_ATTR                       22: parse_decl
                554     LOAD_FAST                       9: _var_var_84
                556     LOAD_GLOBAL                     11: NULL + idaapi
                566     LOAD_ATTR                       24: get_idati
                586     CALL                            0
                594     LOAD_FAST                       6: _var_var_30
                596     FORMAT_VALUE                    0 (FVC_NONE)
                598     LOAD_CONST                      15: ';'
                600     BUILD_STRING                    2
                602     LOAD_GLOBAL                     18: ida_typeinf
                612     LOAD_ATTR                       26: PT_TYP
                632     LOAD_GLOBAL                     18: ida_typeinf
                642     LOAD_ATTR                       28: PT_SIL
                662     BINARY_OP                       7 (|)
                666     CALL                            4
                674     LOAD_CONST                      10: None
                676     COMPARE_OP                      40 (==)
                680     POP_JUMP_IF_FALSE               171 (to 1024)
                682     LOAD_GLOBAL                     31: NULL + add_empty_struct_type
                692     LOAD_FAST                       6: _var_var_30
                694     LOAD_FAST                       8: _var_var_26
                696     CALL                            2
                704     STORE_FAST                      9: _var_var_84
                706     LOAD_FAST                       9: _var_var_84
                708     POP_JUMP_IF_FALSE               19 (to 748)
                710     LOAD_FAST                       9: _var_var_84
                712     LOAD_GLOBAL                     10: idaapi
                722     LOAD_ATTR                       12: BADADDR
                742     COMPARE_OP                      40 (==)
                746     POP_JUMP_IF_FALSE               18 (to 784)
                748     LOAD_GLOBAL                     5: NULL + print
                758     LOAD_CONST                      16: '[!] Failed to parse type '
                760     LOAD_FAST                       6: _var_var_30
                762     FORMAT_VALUE                    0 (FVC_NONE)
                764     LOAD_CONST                      17: ' for member '
                766     LOAD_FAST                       7: _var_var_25
                768     FORMAT_VALUE                    0 (FVC_NONE)
                770     BUILD_STRING                    4
                772     CALL                            1
                780     POP_TOP                         
                782     JUMP_BACKWARD                   180 (to 424)
                784     LOAD_CONST                      18: True
                786     STORE_FAST                      10: _var_var_130
                788     LOAD_GLOBAL                     19: NULL + ida_typeinf
                798     LOAD_ATTR                       20: tinfo_t
                818     CALL                            0
                826     STORE_FAST                      9: _var_var_84
                828     LOAD_GLOBAL                     19: NULL + ida_typeinf
                838     LOAD_ATTR                       22: parse_decl
                858     LOAD_FAST                       9: _var_var_84
                860     LOAD_GLOBAL                     11: NULL + idaapi
                870     LOAD_ATTR                       24: get_idati
                890     CALL                            0
                898     LOAD_FAST                       6: _var_var_30
                900     FORMAT_VALUE                    0 (FVC_NONE)
                902     LOAD_CONST                      15: ';'
                904     BUILD_STRING                    2
                906     LOAD_GLOBAL                     18: ida_typeinf
                916     LOAD_ATTR                       26: PT_TYP
                936     LOAD_GLOBAL                     18: ida_typeinf
                946     LOAD_ATTR                       28: PT_SIL
                966     BINARY_OP                       7 (|)
                970     CALL                            4
                978     LOAD_CONST                      10: None
                980     COMPARE_OP                      40 (==)
                984     POP_JUMP_IF_FALSE               19 (to 1024)
                986     LOAD_GLOBAL                     5: NULL + print
                996     LOAD_CONST                      16: '[!] Failed to parse type '
                998     LOAD_FAST                       6: _var_var_30
                1000    FORMAT_VALUE                    0 (FVC_NONE)
                1002    LOAD_CONST                      17: ' for member '
                1004    LOAD_FAST                       7: _var_var_25
                1006    FORMAT_VALUE                    0 (FVC_NONE)
                1008    BUILD_STRING                    4
                1010    CALL                            1
                1018    POP_TOP                         
                1020    JUMP_BACKWARD                   300 (to 424)
                1024    LOAD_GLOBAL                     10: idaapi
                1034    LOAD_ATTR                       12: BADADDR
                1054    STORE_FAST                      11: _var_var_131
                1056    LOAD_GLOBAL                     10: idaapi
                1066    LOAD_ATTR                       12: BADADDR
                1086    STORE_FAST                      12: _var_var_132
                1088    LOAD_FAST                       9: _var_var_84
                1090    LOAD_ATTR                       33: get_size
                1110    CALL                            0
                1118    STORE_FAST                      13: _var_var_133
                1120    LOAD_FAST                       13: _var_var_133
                1122    LOAD_CONST                      19: 1
                1124    COMPARE_OP                      40 (==)
                1128    POP_JUMP_IF_FALSE               34 (to 1198)
                1130    LOAD_GLOBAL                     6: idc
                1140    LOAD_ATTR                       34: FF_BYTE
                1160    LOAD_GLOBAL                     6: idc
                1170    LOAD_ATTR                       36: FF_DATA
                1190    BINARY_OP                       7 (|)
                1194    STORE_FAST                      11: _var_var_131
                1196    JUMP_FORWARD                    149 (to 1496)
                1198    LOAD_FAST                       13: _var_var_133
                1200    LOAD_CONST                      20: 2
                1202    COMPARE_OP                      40 (==)
                1206    POP_JUMP_IF_FALSE               34 (to 1276)
                1208    LOAD_GLOBAL                     6: idc
                1218    LOAD_ATTR                       38: FF_WORD
                1238    LOAD_GLOBAL                     6: idc
                1248    LOAD_ATTR                       36: FF_DATA
                1268    BINARY_OP                       7 (|)
                1272    STORE_FAST                      11: _var_var_131
                1274    JUMP_FORWARD                    110 (to 1496)
                1276    LOAD_FAST                       13: _var_var_133
                1278    LOAD_CONST                      21: 4
                1280    COMPARE_OP                      40 (==)
                1284    POP_JUMP_IF_FALSE               34 (to 1354)
                1286    LOAD_GLOBAL                     6: idc
                1296    LOAD_ATTR                       40: FF_DWORD
                1316    LOAD_GLOBAL                     6: idc
                1326    LOAD_ATTR                       36: FF_DATA
                1346    BINARY_OP                       7 (|)
                1350    STORE_FAST                      11: _var_var_131
                1352    JUMP_FORWARD                    71 (to 1496)
                1354    LOAD_FAST                       13: _var_var_133
                1356    LOAD_CONST                      22: 8
                1358    COMPARE_OP                      40 (==)
                1362    POP_JUMP_IF_FALSE               34 (to 1432)
                1364    LOAD_GLOBAL                     6: idc
                1374    LOAD_ATTR                       42: FF_QWORD
                1394    LOAD_GLOBAL                     6: idc
                1404    LOAD_ATTR                       36: FF_DATA
                1424    BINARY_OP                       7 (|)
                1428    STORE_FAST                      11: _var_var_131
                1430    JUMP_FORWARD                    32 (to 1496)
                1432    LOAD_GLOBAL                     6: idc
                1442    LOAD_ATTR                       36: FF_DATA
                1462    STORE_FAST                      11: _var_var_131
                1464    LOAD_FAST                       9: _var_var_84
                1466    LOAD_ATTR                       45: get_tid
                1486    CALL                            0
                1494    STORE_FAST                      12: _var_var_132
                1496    LOAD_FAST                       10: _var_var_130
                1498    POP_JUMP_IF_FALSE               67 (to 1634)
                1500    LOAD_GLOBAL                     6: idc
                1510    LOAD_ATTR                       46: FF_STRUCT
                1530    LOAD_FAST                       11: _var_var_131
                1532    BINARY_OP                       7 (|)
                1536    STORE_FAST                      11: _var_var_131
                1538    LOAD_FAST                       9: _var_var_84
                1540    LOAD_ATTR                       49: copy
                1560    CALL                            0
                1568    STORE_FAST                      14: _var_var_134
                1570    LOAD_FAST                       14: _var_var_134
                1572    LOAD_ATTR                       51: remove_ptr_or_array
                1592    CALL                            0
                1600    POP_TOP                         
                1602    LOAD_FAST                       14: _var_var_134
                1604    LOAD_ATTR                       45: get_tid
                1624    CALL                            0
                1632    STORE_FAST                      12: _var_var_132
                1634    LOAD_GLOBAL                     7: NULL + idc
                1644    LOAD_ATTR                       52: add_struc_member
                1664    LOAD_FAST                       4: _var_var_128
                1666    LOAD_FAST                       7: _var_var_25
                1668    LOAD_FAST                       5: _var_var_129
                1670    LOAD_FAST                       11: _var_var_131
                1672    LOAD_GLOBAL                     10: idaapi
                1682    LOAD_ATTR                       12: BADADDR
                1702    COMPARE_OP                      55 (!=)
                1706    POP_JUMP_IF_FALSE               2 (to 1712)
                1708    LOAD_FAST                       11: _var_var_131
                1710    JUMP_FORWARD                    1 (to 1714)
                1712    LOAD_CONST                      4: 0
                1714    LOAD_FAST                       12: _var_var_132
                1716    LOAD_GLOBAL                     10: idaapi
                1726    LOAD_ATTR                       12: BADADDR
                1746    COMPARE_OP                      55 (!=)
                1750    POP_JUMP_IF_FALSE               2 (to 1756)
                1752    LOAD_FAST                       12: _var_var_132
                1754    JUMP_FORWARD                    1 (to 1758)
                1756    LOAD_CONST                      7: -1
                1758    LOAD_FAST                       8: _var_var_26
                1760    CALL                            6
                1768    STORE_FAST                      15: _var_var_112
                1770    LOAD_FAST                       15: _var_var_112
                1772    LOAD_CONST                      4: 0
                1774    COMPARE_OP                      55 (!=)
                1778    POP_JUMP_IF_FALSE               19 (to 1818)
                1780    LOAD_GLOBAL                     5: NULL + print
                1790    LOAD_CONST                      23: '[!] Failed to add member: '
                1792    LOAD_FAST                       6: _var_var_30
                1794    FORMAT_VALUE                    0 (FVC_NONE)
                1796    LOAD_CONST                      24: ' '
                1798    LOAD_FAST                       7: _var_var_25
                1800    FORMAT_VALUE                    0 (FVC_NONE)
                1802    BUILD_STRING                    4
                1804    CALL                            1
                1812    POP_TOP                         
                1814    JUMP_BACKWARD                   697 (to 424)
                1818    LOAD_FAST                       10: _var_var_130
                1820    POP_JUMP_IF_FALSE               67 (to 1956)
                1822    LOAD_GLOBAL                     55: NULL + get_struc
                1832    LOAD_FAST                       4: _var_var_128
                1834    CALL                            1
                1842    STORE_FAST                      16: _var_var_135
                1844    LOAD_FAST                       16: _var_var_135
                1846    POP_JUMP_IF_FALSE               54 (to 1956)
                1848    LOAD_FAST                       16: _var_var_135
                1850    LOAD_ATTR                       57: get_udt_nmembers
                1870    CALL                            0
                1878    LOAD_CONST                      4: 0
                1880    COMPARE_OP                      68 (>)
                1884    POP_JUMP_IF_FALSE               35 (to 1956)
                1886    LOAD_FAST                       16: _var_var_135
                1888    LOAD_ATTR                       59: set_udm_type
                1908    LOAD_FAST                       16: _var_var_135
                1910    LOAD_ATTR                       57: get_udt_nmembers
                1930    CALL                            0
                1938    LOAD_CONST                      19: 1
                1940    BINARY_OP                       10 (-)
                1944    LOAD_FAST                       9: _var_var_84
                1946    CALL                            2
                1954    POP_TOP                         
                1956    LOAD_GLOBAL                     5: NULL + print
                1966    LOAD_CONST                      25: '[+] Successfully added member '
                1968    LOAD_FAST                       7: _var_var_25
                1970    FORMAT_VALUE                    0 (FVC_NONE)
                1972    LOAD_CONST                      13: ' at offset '
                1974    LOAD_FAST                       5: _var_var_129
                1976    FORMAT_VALUE                    0 (FVC_NONE)
                1978    BUILD_STRING                    4
                1980    CALL                            1
                1988    POP_TOP                         
                1990    LOAD_FAST                       5: _var_var_129
                1992    LOAD_FAST                       8: _var_var_26
                1994    BINARY_OP                       13 (+=)
                1998    STORE_FAST                      5: _var_var_129
                2000    JUMP_BACKWARD                   790 (to 424)
                2004    END_FOR                         
                2006    LOAD_GLOBAL                     5: NULL + print
                2016    LOAD_CONST                      26: '[+] Successfully created struct '
                2018    LOAD_FAST                       0: struct_name
                2020    FORMAT_VALUE                    0 (FVC_NONE)
                2022    BUILD_STRING                    2
                2024    CALL                            1
                2032    POP_TOP                         
                2034    LOAD_GLOBAL                     55: NULL + get_struc
                2044    LOAD_FAST                       4: _var_var_128
                2046    CALL                            1
                2054    NOP                             
                2056    NOP                             
                2058    NOP                             
                2060    JUMP_FORWARD                    20 (to 2102)
                2062    CALL                            1
                2070    POP_TOP                         
                2072    RETURN_VALUE                    
                2074    PUSH_EXC_INFO                   
                2076    PUSH_NULL                       
                2078    LOAD_CONST                      9: '__pyarmor_exit_55263__'
                2080    NOP                             
                2082    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x00\x08\x00\x00\x00\x00\x00\x00'
                2084    CALL                            1
                2092    POP_TOP                         
                2094    RERAISE                         0
                2096    COPY                            3
                2098    POP_EXCEPT                      
                2100    RERAISE                         1
                2102    PUSH_NULL                       
                2104    LOAD_CONST                      9: '__pyarmor_exit_55263__'
                2106    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x00\x08\x00\x00\x00\x00\x00\x00'
                2108    BUILD_TUPLE                     1
                2110    CALL_FUNCTION_EX                0
                2112    POP_TOP                         
                2114    RETURN_VALUE                    
        'arg_pred'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction_arg
            Qualified Name: apply_prediction_arg
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 9
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'name'
                'ida_typeinf'
                'tinfo_t'
                'get_idati'
                'isinstance'
                'list'
                'join'
                'endswith'
                'parse_decl'
                'PT_SIL'
                'PT_NDC'
                'get_named_type'
                'BTF_TYPEDEF'
                'add_struct_type'
                'add_enum_type'
                'add_array_type'
                'dstr'
                'type'
                'replace'
            [Locals+Names]
                'arg'
                'arg_pred'
                '__assert_armored__'
                '_var_var_136'
                '_var_var_137'
                '_var_var_138'
                '_var_var_139'
                '_var_var_117'
                '_var_var_111'
                '_var_var_10'
                '_var_var_140'
                '_var_var_141'
                '_var_var_142'
            [Constants]
                None
                '__pyarmor_assert_55264__'
                '__pyarmor_enter_55265__'
                b'<COAddr>\x03\x00\x00\x1a\xc8\x03\x00\x00\x00\x00\x00\x00'
                '[!] found bad arg prediction for '
                ': '
                '__pyarmor_exit_55266__'
                'array'
                '['
                ''
                ']'
                ';'
                -1
                True
                False
                'struct'
                'enum'
                '[!] Failed to parse or find type '
                '?'
                '[+] Successfully change original arg '
                ' to: '
                ' '
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55265__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xc8\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       1: arg_pred
                30      UNPACK_SEQUENCE                 4
                34      STORE_FAST                      3: _var_var_136
                36      STORE_FAST                      4: _var_var_137
                38      STORE_FAST                      5: _var_var_138
                40      STORE_FAST                      6: _var_var_139
                42      LOAD_FAST                       3: _var_var_136
                44      POP_JUMP_IF_TRUE                40 (to 126)
                46      LOAD_FAST                       4: _var_var_137
                48      POP_JUMP_IF_TRUE                38 (to 126)
                50      LOAD_GLOBAL                     1: NULL + print
                60      LOAD_CONST                      4: '[!] found bad arg prediction for '
                62      LOAD_FAST                       0: arg
                64      LOAD_ATTR                       2: name
                84      FORMAT_VALUE                    0 (FVC_NONE)
                86      LOAD_CONST                      5: ': '
                88      LOAD_FAST                       1: arg_pred
                90      FORMAT_VALUE                    0 (FVC_NONE)
                92      BUILD_STRING                    4
                94      CALL                            1
                102     POP_TOP                         
                104     NOP                             
                106     LOAD_CONST                      0: None
                108     NOP                             
                110     NOP                             
                112     JUMP_FORWARD                    453 (to 1022)
                122     POP_TOP                         
                124     RETURN_CONST                    0: None
                126     LOAD_FAST                       0: arg
                128     LOAD_ATTR                       2: name
                148     STORE_FAST                      7: _var_var_117
                150     LOAD_FAST                       4: _var_var_137
                152     POP_JUMP_IF_FALSE               7 (to 168)
                154     LOAD_FAST                       4: _var_var_137
                156     LOAD_FAST                       0: arg
                158     STORE_ATTR                      1: name
                168     LOAD_GLOBAL                     5: NULL + ida_typeinf
                178     LOAD_ATTR                       6: tinfo_t
                198     CALL                            0
                206     STORE_FAST                      8: _var_var_111
                208     LOAD_FAST                       3: _var_var_136
                210     POP_JUMP_IF_FALSE               339 (to 892)
                214     LOAD_GLOBAL                     5: NULL + ida_typeinf
                224     LOAD_ATTR                       8: get_idati
                244     CALL                            0
                252     STORE_FAST                      9: _var_var_10
                254     LOAD_FAST                       5: _var_var_138
                256     LOAD_CONST                      7: 'array'
                258     COMPARE_OP                      40 (==)
                262     POP_JUMP_IF_FALSE               58 (to 380)
                264     LOAD_CONST                      8: '['
                266     LOAD_FAST                       3: _var_var_136
                268     CONTAINS_OP                     1 (not in)
                270     POP_JUMP_IF_FALSE               54 (to 380)
                272     LOAD_GLOBAL                     11: NULL + isinstance
                282     LOAD_FAST                       6: _var_var_139
                284     LOAD_GLOBAL                     12: list
                294     CALL                            2
                302     POP_JUMP_IF_FALSE               38 (to 380)
                304     LOAD_FAST                       3: _var_var_136
                306     LOAD_CONST                      9: ''
                308     LOAD_ATTR                       15: join
                328     LOAD_FAST                       6: _var_var_139
                330     GET_ITER                        
                332     LOAD_FAST_AND_CLEAR             10: _var_var_140
                334     SWAP                            2
                336     BUILD_LIST                      0
                338     SWAP                            2
                340     FOR_ITER                        8 (to 358)
                344     STORE_FAST                      10: _var_var_140
                346     LOAD_CONST                      8: '['
                348     LOAD_FAST                       10: _var_var_140
                350     FORMAT_VALUE                    0 (FVC_NONE)
                352     LOAD_CONST                      10: ']'
                354     BUILD_STRING                    3
                356     LIST_APPEND                     2
                358     JUMP_BACKWARD                   10 (to 340)
                360     END_FOR                         
                362     SWAP                            2
                364     STORE_FAST                      10: _var_var_140
                366     CALL                            1
                374     BINARY_OP                       13 (+=)
                378     STORE_FAST                      3: _var_var_136
                380     LOAD_FAST                       3: _var_var_136
                382     LOAD_ATTR                       17: endswith
                402     LOAD_CONST                      11: ';'
                404     CALL                            1
                412     POP_JUMP_IF_TRUE                5 (to 424)
                414     LOAD_FAST                       3: _var_var_136
                416     LOAD_CONST                      11: ';'
                418     BINARY_OP                       13 (+=)
                422     STORE_FAST                      3: _var_var_136
                424     LOAD_GLOBAL                     5: NULL + ida_typeinf
                434     LOAD_ATTR                       18: parse_decl
                454     LOAD_FAST                       8: _var_var_111
                456     LOAD_FAST                       9: _var_var_10
                458     LOAD_FAST                       3: _var_var_136
                460     LOAD_GLOBAL                     4: ida_typeinf
                470     LOAD_ATTR                       20: PT_SIL
                490     LOAD_GLOBAL                     4: ida_typeinf
                500     LOAD_ATTR                       22: PT_NDC
                520     BINARY_OP                       7 (|)
                524     CALL                            4
                532     STORE_FAST                      11: _var_var_141
                534     LOAD_FAST                       11: _var_var_141
                536     LOAD_CONST                      0: None
                538     COMPARE_OP                      40 (==)
                542     POP_JUMP_IF_FALSE               121 (to 786)
                544     LOAD_FAST                       3: _var_var_136
                546     LOAD_CONST                      0: None
                548     LOAD_CONST                      12: -1
                550     BINARY_SLICE                    
                552     STORE_FAST                      3: _var_var_136
                554     LOAD_FAST                       8: _var_var_111
                556     LOAD_ATTR                       25: get_named_type
                576     LOAD_FAST                       9: _var_var_10
                578     LOAD_FAST                       3: _var_var_136
                580     LOAD_GLOBAL                     4: ida_typeinf
                590     LOAD_ATTR                       26: BTF_TYPEDEF
                610     LOAD_CONST                      13: True
                612     LOAD_CONST                      14: False
                614     CALL                            5
                622     STORE_FAST                      12: _var_var_142
                624     LOAD_FAST                       12: _var_var_142
                626     POP_JUMP_IF_TRUE                79 (to 786)
                628     LOAD_FAST                       5: _var_var_138
                630     LOAD_CONST                      15: 'struct'
                632     COMPARE_OP                      40 (==)
                636     POP_JUMP_IF_FALSE               13 (to 664)
                638     LOAD_GLOBAL                     29: NULL + add_struct_type
                648     LOAD_FAST                       3: _var_var_136
                650     LOAD_FAST                       6: _var_var_139
                652     CALL                            2
                660     STORE_FAST                      8: _var_var_111
                662     JUMP_FORWARD                    61 (to 786)
                664     LOAD_FAST                       5: _var_var_138
                666     LOAD_CONST                      16: 'enum'
                668     COMPARE_OP                      40 (==)
                672     POP_JUMP_IF_FALSE               13 (to 700)
                674     LOAD_GLOBAL                     31: NULL + add_enum_type
                684     LOAD_FAST                       3: _var_var_136
                686     LOAD_FAST                       6: _var_var_139
                688     CALL                            2
                696     STORE_FAST                      8: _var_var_111
                698     JUMP_FORWARD                    43 (to 786)
                700     LOAD_FAST                       5: _var_var_138
                702     LOAD_CONST                      7: 'array'
                704     COMPARE_OP                      40 (==)
                708     POP_JUMP_IF_FALSE               13 (to 736)
                710     LOAD_GLOBAL                     33: NULL + add_array_type
                720     LOAD_FAST                       3: _var_var_136
                722     LOAD_FAST                       6: _var_var_139
                724     CALL                            2
                732     STORE_FAST                      8: _var_var_111
                734     JUMP_FORWARD                    25 (to 786)
                736     LOAD_GLOBAL                     1: NULL + print
                746     LOAD_CONST                      17: '[!] Failed to parse or find type '
                748     LOAD_FAST                       3: _var_var_136
                750     FORMAT_VALUE                    0 (FVC_NONE)
                752     BUILD_STRING                    2
                754     CALL                            1
                762     POP_TOP                         
                764     NOP                             
                766     LOAD_CONST                      0: None
                768     NOP                             
                770     NOP                             
                772     NOP                             
                774     JUMP_FORWARD                    123 (to 1022)
                782     POP_TOP                         
                784     RETURN_CONST                    0: None
                786     LOAD_FAST                       8: _var_var_111
                788     POP_JUMP_IF_FALSE               19 (to 828)
                790     LOAD_FAST                       8: _var_var_111
                792     LOAD_ATTR                       35: dstr
                812     CALL                            0
                820     LOAD_CONST                      18: '?'
                822     COMPARE_OP                      40 (==)
                826     POP_JUMP_IF_FALSE               25 (to 878)
                828     LOAD_GLOBAL                     1: NULL + print
                838     LOAD_CONST                      17: '[!] Failed to parse or find type '
                840     LOAD_FAST                       3: _var_var_136
                842     FORMAT_VALUE                    0 (FVC_NONE)
                844     BUILD_STRING                    2
                846     CALL                            1
                854     POP_TOP                         
                856     NOP                             
                858     LOAD_CONST                      0: None
                860     NOP                             
                862     NOP                             
                864     NOP                             
                866     JUMP_FORWARD                    77 (to 1022)
                874     POP_TOP                         
                876     RETURN_CONST                    0: None
                878     LOAD_FAST                       8: _var_var_111
                880     LOAD_FAST                       0: arg
                882     STORE_ATTR                      18: type
                892     LOAD_GLOBAL                     1: NULL + print
                902     LOAD_CONST                      19: '[+] Successfully change original arg '
                904     LOAD_FAST                       7: _var_var_117
                906     FORMAT_VALUE                    0 (FVC_NONE)
                908     LOAD_CONST                      20: ' to: '
                910     LOAD_FAST                       3: _var_var_136
                912     LOAD_ATTR                       39: replace
                932     LOAD_CONST                      11: ';'
                934     LOAD_CONST                      9: ''
                936     CALL                            2
                944     FORMAT_VALUE                    0 (FVC_NONE)
                946     LOAD_CONST                      21: ' '
                948     LOAD_FAST                       4: _var_var_137
                950     FORMAT_VALUE                    0 (FVC_NONE)
                952     BUILD_STRING                    6
                954     CALL                            1
                962     POP_TOP                         
                964     LOAD_CONST                      13: True
                966     NOP                             
                968     NOP                             
                970     NOP                             
                972     JUMP_FORWARD                    24 (to 1022)
                980     POP_TOP                         
                982     RETURN_CONST                    13: True
                984     SWAP                            2
                986     POP_TOP                         
                988     SWAP                            2
                990     STORE_FAST                      10: _var_var_140
                992     RERAISE                         0
                994     PUSH_EXC_INFO                   
                996     PUSH_NULL                       
                998     LOAD_CONST                      6: '__pyarmor_exit_55266__'
                1000    NOP                             
                1002    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xc8\x03\x00\x00\x00\x00\x00\x00'
                1004    CALL                            1
                1012    POP_TOP                         
                1014    RERAISE                         0
                1016    COPY                            3
                1018    POP_EXCEPT                      
                1020    RERAISE                         1
                1022    PUSH_NULL                       
                1024    LOAD_CONST                      6: '__pyarmor_exit_55266__'
                1026    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xc8\x03\x00\x00\x00\x00\x00\x00'
                1028    BUILD_TUPLE                     1
                1030    CALL_FUNCTION_EX                0
                1032    POP_TOP                         
                1034    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction_args_old
            Qualified Name: apply_prediction_args_old
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 9
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'get'
                'dict'
                'print'
                'isinstance'
                'ida_typeinf'
                'tinfo_t'
                'ida_nalt'
                'get_tinfo'
                'hex'
                'func_type_data_t'
                'get_func_details'
                'ida_hexrays'
                'decompile'
                'DecompilationFailure'
                'len'
                'arguments'
                'items'
                'enumerate'
                'name'
                'apply_prediction_arg'
                'create_func'
                'idaapi'
                'apply_tinfo'
                'TINFO_DEFINITE'
            [Locals+Names]
                'func_ea'
                'prediction'
                '__assert_armored__'
                '_var_var_143'
                '_var_var_113'
                '_var_var_114'
                '_var_var_50'
                '_var_var_117'
                '_var_var_144'
                '_var_var_14'
                '_var_var_145'
            [Constants]
                None
                '__pyarmor_assert_55267__'
                '__pyarmor_enter_55268__'
                b'<COAddr>\x03\x00\x00\x1a`\x04\x00\x00\x00\x00\x00\x00'
                'args'
                '[-] found empty args in prediction: '
                '__pyarmor_exit_55269__'
                '[!] found bad args in prediction: '
                '[!] Fail to get function type info at '
                '[!] Fail to get function details at '
                '[DEBUG🐛] apply_prediction_args_old: Arguments count not match'
                '[!] Fail to decompile function at '
                '[!] Fail to find argument '
                ' in function '
                '[!] Error: failed to apply func new type info'
                False
                True
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55268__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a`\x04\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       1: prediction
                30      LOAD_ATTR                       1: get
                50      LOAD_CONST                      4: 'args'
                52      LOAD_GLOBAL                     3: NULL + dict
                62      CALL                            0
                70      CALL                            2
                78      STORE_FAST                      3: _var_var_143
                80      LOAD_FAST                       3: _var_var_143
                82      POP_JUMP_IF_TRUE                25 (to 134)
                84      LOAD_GLOBAL                     5: NULL + print
                94      LOAD_CONST                      5: '[-] found empty args in prediction: '
                96      LOAD_FAST                       3: _var_var_143
                98      FORMAT_VALUE                    0 (FVC_NONE)
                100     BUILD_STRING                    2
                102     CALL                            1
                110     POP_TOP                         
                112     NOP                             
                114     LOAD_CONST                      0: None
                116     NOP                             
                118     NOP                             
                120     JUMP_FORWARD                    525 (to 1174)
                130     POP_TOP                         
                132     RETURN_CONST                    0: None
                134     LOAD_GLOBAL                     7: NULL + isinstance
                144     LOAD_FAST                       3: _var_var_143
                146     LOAD_GLOBAL                     2: dict
                156     CALL                            2
                164     POP_JUMP_IF_TRUE                25 (to 216)
                166     LOAD_GLOBAL                     5: NULL + print
                176     LOAD_CONST                      7: '[!] found bad args in prediction: '
                178     LOAD_FAST                       3: _var_var_143
                180     FORMAT_VALUE                    0 (FVC_NONE)
                182     BUILD_STRING                    2
                184     CALL                            1
                192     POP_TOP                         
                194     NOP                             
                196     LOAD_CONST                      0: None
                198     NOP                             
                200     NOP                             
                202     JUMP_FORWARD                    484 (to 1174)
                212     POP_TOP                         
                214     RETURN_CONST                    0: None
                216     LOAD_GLOBAL                     9: NULL + ida_typeinf
                226     LOAD_ATTR                       10: tinfo_t
                246     CALL                            0
                254     STORE_FAST                      4: _var_var_113
                256     LOAD_GLOBAL                     13: NULL + ida_nalt
                266     LOAD_ATTR                       14: get_tinfo
                286     LOAD_FAST                       4: _var_var_113
                288     LOAD_FAST                       0: func_ea
                290     CALL                            2
                298     POP_JUMP_IF_TRUE                34 (to 368)
                300     LOAD_GLOBAL                     5: NULL + print
                310     LOAD_CONST                      8: '[!] Fail to get function type info at '
                312     LOAD_GLOBAL                     17: NULL + hex
                322     LOAD_FAST                       0: func_ea
                324     CALL                            1
                332     FORMAT_VALUE                    0 (FVC_NONE)
                334     BUILD_STRING                    2
                336     CALL                            1
                344     POP_TOP                         
                346     NOP                             
                348     LOAD_CONST                      0: None
                350     NOP                             
                352     NOP                             
                354     JUMP_FORWARD                    408 (to 1174)
                364     POP_TOP                         
                366     RETURN_CONST                    0: None
                368     LOAD_GLOBAL                     9: NULL + ida_typeinf
                378     LOAD_ATTR                       18: func_type_data_t
                398     CALL                            0
                406     STORE_FAST                      5: _var_var_114
                408     LOAD_FAST                       4: _var_var_113
                410     LOAD_ATTR                       21: get_func_details
                430     LOAD_FAST                       5: _var_var_114
                432     CALL                            1
                440     POP_JUMP_IF_TRUE                34 (to 510)
                442     LOAD_GLOBAL                     5: NULL + print
                452     LOAD_CONST                      9: '[!] Fail to get function details at '
                454     LOAD_GLOBAL                     17: NULL + hex
                464     LOAD_FAST                       0: func_ea
                466     CALL                            1
                474     FORMAT_VALUE                    0 (FVC_NONE)
                476     BUILD_STRING                    2
                478     CALL                            1
                486     POP_TOP                         
                488     NOP                             
                490     LOAD_CONST                      0: None
                492     NOP                             
                494     NOP                             
                496     JUMP_FORWARD                    337 (to 1174)
                506     POP_TOP                         
                508     RETURN_CONST                    0: None
                510     NOP                             
                512     LOAD_GLOBAL                     23: NULL + ida_hexrays
                522     LOAD_ATTR                       24: decompile
                542     LOAD_FAST                       0: func_ea
                544     CALL                            1
                552     STORE_FAST                      6: _var_var_50
                554     LOAD_FAST                       6: _var_var_50
                556     POP_JUMP_IF_TRUE                6 (to 570)
                558     LOAD_GLOBAL                     26: DecompilationFailure
                568     RAISE_VARARGS                   1
                570     LOAD_GLOBAL                     29: NULL + len
                580     LOAD_FAST                       6: _var_var_50
                582     LOAD_ATTR                       30: arguments
                602     CALL                            1
                610     LOAD_GLOBAL                     29: NULL + len
                620     LOAD_FAST                       5: _var_var_114
                622     CALL                            1
                630     COMPARE_OP                      55 (!=)
                634     POP_JUMP_IF_FALSE               11 (to 658)
                636     LOAD_GLOBAL                     5: NULL + print
                646     LOAD_CONST                      10: '[DEBUG🐛] apply_prediction_args_old: Arguments count not match'
                648     CALL                            1
                656     POP_TOP                         
                658     LOAD_FAST                       3: _var_var_143
                660     LOAD_ATTR                       33: items
                680     CALL                            0
                688     GET_ITER                        
                690     FOR_ITER                        92 (to 876)
                694     UNPACK_SEQUENCE                 2
                698     STORE_FAST                      7: _var_var_117
                700     STORE_FAST                      8: _var_var_144
                702     LOAD_GLOBAL                     35: NULL + enumerate
                712     LOAD_FAST                       6: _var_var_50
                714     LOAD_ATTR                       30: arguments
                734     CALL                            1
                742     GET_ITER                        
                744     FOR_ITER                        37 (to 820)
                748     UNPACK_SEQUENCE                 2
                752     STORE_FAST                      9: _var_var_14
                754     STORE_FAST                      10: _var_var_145
                756     LOAD_FAST                       10: _var_var_145
                758     LOAD_ATTR                       36: name
                778     LOAD_FAST                       7: _var_var_117
                780     COMPARE_OP                      40 (==)
                784     POP_JUMP_IF_TRUE                1 (to 788)
                786     JUMP_BACKWARD                   22 (to 744)
                788     LOAD_GLOBAL                     39: NULL + apply_prediction_arg
                798     LOAD_FAST                       5: _var_var_114
                800     LOAD_FAST                       9: _var_var_14
                802     BINARY_SUBSCR                   
                806     LOAD_FAST                       8: _var_var_144
                808     CALL                            2
                816     POP_TOP                         
                818     POP_TOP                         
                820     JUMP_BACKWARD                   66 (to 690)
                822     END_FOR                         
                824     LOAD_GLOBAL                     5: NULL + print
                834     LOAD_CONST                      12: '[!] Fail to find argument '
                836     LOAD_FAST                       7: _var_var_117
                838     FORMAT_VALUE                    0 (FVC_NONE)
                840     LOAD_CONST                      13: ' in function '
                842     LOAD_GLOBAL                     17: NULL + hex
                852     LOAD_FAST                       0: func_ea
                854     CALL                            1
                862     FORMAT_VALUE                    0 (FVC_NONE)
                864     BUILD_STRING                    4
                866     CALL                            1
                874     POP_TOP                         
                876     JUMP_BACKWARD                   94 (to 690)
                878     END_FOR                         
                880     LOAD_FAST                       4: _var_var_113
                882     LOAD_ATTR                       41: create_func
                902     LOAD_FAST                       5: _var_var_114
                904     CALL                            1
                912     POP_TOP                         
                914     LOAD_GLOBAL                     43: NULL + idaapi
                924     LOAD_ATTR                       44: apply_tinfo
                944     LOAD_FAST                       0: func_ea
                946     LOAD_FAST                       4: _var_var_113
                948     LOAD_GLOBAL                     42: idaapi
                958     LOAD_ATTR                       46: TINFO_DEFINITE
                978     CALL                            3
                986     POP_JUMP_IF_TRUE                22 (to 1032)
                988     LOAD_GLOBAL                     5: NULL + print
                998     LOAD_CONST                      14: '[!] Error: failed to apply func new type info'
                1000    CALL                            1
                1008    POP_TOP                         
                1010    NOP                             
                1012    LOAD_CONST                      15: False
                1014    NOP                             
                1016    NOP                             
                1018    NOP                             
                1020    JUMP_FORWARD                    76 (to 1174)
                1028    POP_TOP                         
                1030    RETURN_CONST                    15: False
                1032    LOAD_CONST                      16: True
                1034    NOP                             
                1036    NOP                             
                1038    NOP                             
                1040    JUMP_FORWARD                    66 (to 1174)
                1048    POP_TOP                         
                1050    RETURN_CONST                    16: True
                1052    PUSH_EXC_INFO                   
                1054    LOAD_GLOBAL                     26: DecompilationFailure
                1064    CHECK_EXC_MATCH                 
                1066    POP_JUMP_IF_FALSE               35 (to 1138)
                1068    POP_TOP                         
                1070    LOAD_GLOBAL                     5: NULL + print
                1080    LOAD_CONST                      11: '[!] Fail to decompile function at '
                1082    LOAD_GLOBAL                     17: NULL + hex
                1092    LOAD_FAST                       0: func_ea
                1094    CALL                            1
                1102    FORMAT_VALUE                    0 (FVC_NONE)
                1104    BUILD_STRING                    2
                1106    CALL                            1
                1114    POP_TOP                         
                1116    POP_EXCEPT                      
                1118    LOAD_CONST                      0: None
                1120    NOP                             
                1122    NOP                             
                1124    NOP                             
                1126    JUMP_FORWARD                    23 (to 1174)
                1134    POP_TOP                         
                1136    RETURN_CONST                    0: None
                1138    RERAISE                         0
                1140    COPY                            3
                1142    POP_EXCEPT                      
                1144    RERAISE                         1
                1146    PUSH_EXC_INFO                   
                1148    PUSH_NULL                       
                1150    LOAD_CONST                      6: '__pyarmor_exit_55269__'
                1152    NOP                             
                1154    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a`\x04\x00\x00\x00\x00\x00\x00'
                1156    CALL                            1
                1164    POP_TOP                         
                1166    RERAISE                         0
                1168    COPY                            3
                1170    POP_EXCEPT                      
                1172    RERAISE                         1
                1174    PUSH_NULL                       
                1176    LOAD_CONST                      6: '__pyarmor_exit_55269__'
                1178    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a`\x04\x00\x00\x00\x00\x00\x00'
                1180    BUILD_TUPLE                     1
                1182    CALL_FUNCTION_EX                0
                1184    POP_TOP                         
                1186    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction_vars
            Qualified Name: apply_prediction_vars
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 13
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'get'
                'dict'
                'print'
                'isinstance'
                'ida_funcs'
                'get_func'
                'hex'
                'items'
                'idaapi'
                'open_pseudocode'
                'start_ea'
                'ida_typeinf'
                'tinfo_t'
                'list'
                'join'
                'endswith'
                'get_idati'
                'parse_decl'
                'PT_SIL'
                'PT_NDC'
                'get_named_type'
                'BTF_TYPEDEF'
                'add_struct_type'
                'add_enum_type'
                'add_array_type'
                'cfunc'
                'lvars'
                'is_arg_var'
                'name'
                'type'
                'dstr'
                'rename_lvar'
                'set_lvar_type'
                'replace'
                'refresh_func_ctext'
            [Locals+Names]
                'func_ea'
                'prediction'
                '__assert_armored__'
                '_var_var_146'
                '_var_var_66'
                '_var_var_117'
                '_var_var_147'
                '_var_var_116'
                '_var_var_136'
                '_var_var_137'
                '_var_var_138'
                '_var_var_139'
                '_var_var_111'
                '_var_var_140'
                '_var_var_10'
                '_var_var_148'
                '_var_var_142'
                '_var_var_33'
                '_var_var_149'
                '_var_var_150'
                '_var_var_151'
            [Constants]
                None
                '__pyarmor_assert_55270__'
                '__pyarmor_enter_55271__'
                b'<COAddr>\x01\x00\x00\x1a\xf8\x06\x00\x00\x00\x00\x00\x00'
                'vars'
                '[-] found empty vars in prediction: '
                '__pyarmor_exit_55272__'
                '[!] found bad vars in prediction: '
                '[!] Fail to get function at '
                0
                '[!] Fail to open pseudocode view for function at '
                '[!] found bad var prediction for '
                ': '
                'array'
                '['
                ''
                ']'
                ';'
                -1
                True
                False
                'struct'
                'enum'
                '[!] Failed to parse or find type '
                (
                    True
                    True
                )
                1
                '[+] Successfully change var: '
                ' '
                ' to: '
                '[!] Fail change var: '
                '[!] Fail to find variable '
                ' in function '
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55271__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf8\x06\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       1: prediction
                30      LOAD_ATTR                       1: get
                50      LOAD_CONST                      4: 'vars'
                52      LOAD_GLOBAL                     3: NULL + dict
                62      CALL                            0
                70      CALL                            2
                78      STORE_FAST                      3: _var_var_146
                80      LOAD_FAST                       3: _var_var_146
                82      POP_JUMP_IF_TRUE                25 (to 134)
                84      LOAD_GLOBAL                     5: NULL + print
                94      LOAD_CONST                      5: '[-] found empty vars in prediction: '
                96      LOAD_FAST                       3: _var_var_146
                98      FORMAT_VALUE                    0 (FVC_NONE)
                100     BUILD_STRING                    2
                102     CALL                            1
                110     POP_TOP                         
                112     NOP                             
                114     LOAD_CONST                      0: None
                116     NOP                             
                118     NOP                             
                120     JUMP_FORWARD                    857 (to 1838)
                130     POP_TOP                         
                132     RETURN_CONST                    0: None
                134     LOAD_GLOBAL                     7: NULL + isinstance
                144     LOAD_FAST                       3: _var_var_146
                146     LOAD_GLOBAL                     2: dict
                156     CALL                            2
                164     POP_JUMP_IF_TRUE                25 (to 216)
                166     LOAD_GLOBAL                     5: NULL + print
                176     LOAD_CONST                      7: '[!] found bad vars in prediction: '
                178     LOAD_FAST                       3: _var_var_146
                180     FORMAT_VALUE                    0 (FVC_NONE)
                182     BUILD_STRING                    2
                184     CALL                            1
                192     POP_TOP                         
                194     NOP                             
                196     LOAD_CONST                      0: None
                198     NOP                             
                200     NOP                             
                202     JUMP_FORWARD                    816 (to 1838)
                212     POP_TOP                         
                214     RETURN_CONST                    0: None
                216     LOAD_GLOBAL                     9: NULL + ida_funcs
                226     LOAD_ATTR                       10: get_func
                246     LOAD_FAST                       0: func_ea
                248     CALL                            1
                256     STORE_FAST                      4: _var_var_66
                258     LOAD_FAST                       4: _var_var_66
                260     POP_JUMP_IF_TRUE                34 (to 330)
                262     LOAD_GLOBAL                     5: NULL + print
                272     LOAD_CONST                      8: '[!] Fail to get function at '
                274     LOAD_GLOBAL                     13: NULL + hex
                284     LOAD_FAST                       0: func_ea
                286     CALL                            1
                294     FORMAT_VALUE                    0 (FVC_NONE)
                296     BUILD_STRING                    2
                298     CALL                            1
                306     POP_TOP                         
                308     NOP                             
                310     LOAD_CONST                      0: None
                312     NOP                             
                314     NOP                             
                316     JUMP_FORWARD                    759 (to 1838)
                326     POP_TOP                         
                328     RETURN_CONST                    0: None
                330     LOAD_FAST                       3: _var_var_146
                332     LOAD_ATTR                       15: items
                352     CALL                            0
                360     GET_ITER                        
                362     FOR_ITER                        705 (to 1776)
                368     UNPACK_SEQUENCE                 2
                372     STORE_FAST                      5: _var_var_117
                374     STORE_FAST                      6: _var_var_147
                376     LOAD_GLOBAL                     17: NULL + idaapi
                386     LOAD_ATTR                       18: open_pseudocode
                406     LOAD_FAST                       4: _var_var_66
                408     LOAD_ATTR                       20: start_ea
                428     LOAD_CONST                      9: 0
                430     CALL                            2
                438     STORE_FAST                      7: _var_var_116
                440     LOAD_FAST                       7: _var_var_116
                442     POP_JUMP_IF_TRUE                34 (to 512)
                444     LOAD_GLOBAL                     5: NULL + print
                454     LOAD_CONST                      10: '[!] Fail to open pseudocode view for function at '
                456     LOAD_GLOBAL                     13: NULL + hex
                466     LOAD_FAST                       0: func_ea
                468     CALL                            1
                476     FORMAT_VALUE                    0 (FVC_NONE)
                478     BUILD_STRING                    2
                480     CALL                            1
                488     POP_TOP                         
                490     POP_TOP                         
                492     LOAD_CONST                      0: None
                494     NOP                             
                496     NOP                             
                498     JUMP_FORWARD                    668 (to 1838)
                508     POP_TOP                         
                510     RETURN_CONST                    0: None
                512     LOAD_FAST                       6: _var_var_147
                514     UNPACK_SEQUENCE                 4
                518     STORE_FAST                      8: _var_var_136
                520     STORE_FAST                      9: _var_var_137
                522     STORE_FAST                      10: _var_var_138
                524     STORE_FAST                      11: _var_var_139
                526     LOAD_FAST                       8: _var_var_136
                528     POP_JUMP_IF_TRUE                20 (to 570)
                530     LOAD_FAST                       9: _var_var_137
                532     POP_JUMP_IF_TRUE                18 (to 570)
                534     LOAD_GLOBAL                     5: NULL + print
                544     LOAD_CONST                      11: '[!] found bad var prediction for '
                546     LOAD_FAST                       5: _var_var_117
                548     FORMAT_VALUE                    0 (FVC_NONE)
                550     LOAD_CONST                      12: ': '
                552     LOAD_FAST                       6: _var_var_147
                554     FORMAT_VALUE                    0 (FVC_NONE)
                556     BUILD_STRING                    4
                558     CALL                            1
                566     POP_TOP                         
                568     JUMP_BACKWARD                   104 (to 362)
                570     LOAD_GLOBAL                     23: NULL + ida_typeinf
                580     LOAD_ATTR                       24: tinfo_t
                600     CALL                            0
                608     STORE_FAST                      12: _var_var_111
                610     LOAD_FAST                       8: _var_var_136
                612     POP_JUMP_IF_FALSE               277 (to 1170)
                616     LOAD_FAST                       10: _var_var_138
                618     LOAD_CONST                      13: 'array'
                620     COMPARE_OP                      40 (==)
                624     POP_JUMP_IF_FALSE               58 (to 742)
                626     LOAD_CONST                      14: '['
                628     LOAD_FAST                       8: _var_var_136
                630     CONTAINS_OP                     1 (not in)
                632     POP_JUMP_IF_FALSE               54 (to 742)
                634     LOAD_GLOBAL                     7: NULL + isinstance
                644     LOAD_FAST                       11: _var_var_139
                646     LOAD_GLOBAL                     26: list
                656     CALL                            2
                664     POP_JUMP_IF_FALSE               38 (to 742)
                666     LOAD_FAST                       8: _var_var_136
                668     LOAD_CONST                      15: ''
                670     LOAD_ATTR                       29: join
                690     LOAD_FAST                       11: _var_var_139
                692     GET_ITER                        
                694     LOAD_FAST_AND_CLEAR             13: _var_var_140
                696     SWAP                            2
                698     BUILD_LIST                      0
                700     SWAP                            2
                702     FOR_ITER                        8 (to 720)
                706     STORE_FAST                      13: _var_var_140
                708     LOAD_CONST                      14: '['
                710     LOAD_FAST                       13: _var_var_140
                712     FORMAT_VALUE                    0 (FVC_NONE)
                714     LOAD_CONST                      16: ']'
                716     BUILD_STRING                    3
                718     LIST_APPEND                     2
                720     JUMP_BACKWARD                   10 (to 702)
                722     END_FOR                         
                724     SWAP                            2
                726     STORE_FAST                      13: _var_var_140
                728     CALL                            1
                736     BINARY_OP                       13 (+=)
                740     STORE_FAST                      8: _var_var_136
                742     LOAD_FAST                       8: _var_var_136
                744     LOAD_ATTR                       31: endswith
                764     LOAD_CONST                      17: ';'
                766     CALL                            1
                774     POP_JUMP_IF_TRUE                5 (to 786)
                776     LOAD_FAST                       8: _var_var_136
                778     LOAD_CONST                      17: ';'
                780     BINARY_OP                       13 (+=)
                784     STORE_FAST                      8: _var_var_136
                786     LOAD_GLOBAL                     17: NULL + idaapi
                796     LOAD_ATTR                       32: get_idati
                816     CALL                            0
                824     STORE_FAST                      14: _var_var_10
                826     LOAD_GLOBAL                     23: NULL + ida_typeinf
                836     LOAD_ATTR                       34: parse_decl
                856     LOAD_FAST                       12: _var_var_111
                858     LOAD_FAST                       14: _var_var_10
                860     LOAD_FAST                       8: _var_var_136
                862     LOAD_GLOBAL                     22: ida_typeinf
                872     LOAD_ATTR                       36: PT_SIL
                892     LOAD_GLOBAL                     22: ida_typeinf
                902     LOAD_ATTR                       38: PT_NDC
                922     BINARY_OP                       7 (|)
                926     CALL                            4
                934     LOAD_CONST                      0: None
                936     COMPARE_OP                      55 (!=)
                940     STORE_FAST                      15: _var_var_148
                942     LOAD_FAST                       15: _var_var_148
                944     POP_JUMP_IF_TRUE                112 (to 1170)
                946     LOAD_FAST                       8: _var_var_136
                948     LOAD_CONST                      0: None
                950     LOAD_CONST                      18: -1
                952     BINARY_SLICE                    
                954     STORE_FAST                      8: _var_var_136
                956     LOAD_FAST                       12: _var_var_111
                958     LOAD_ATTR                       41: get_named_type
                978     LOAD_FAST                       14: _var_var_10
                980     LOAD_FAST                       8: _var_var_136
                982     LOAD_GLOBAL                     22: ida_typeinf
                992     LOAD_ATTR                       42: BTF_TYPEDEF
                1012    LOAD_CONST                      19: True
                1014    LOAD_CONST                      20: False
                1016    CALL                            5
                1024    STORE_FAST                      16: _var_var_142
                1026    LOAD_FAST                       16: _var_var_142
                1028    POP_JUMP_IF_TRUE                70 (to 1170)
                1030    LOAD_FAST                       10: _var_var_138
                1032    LOAD_CONST                      21: 'struct'
                1034    COMPARE_OP                      40 (==)
                1038    POP_JUMP_IF_FALSE               13 (to 1066)
                1040    LOAD_GLOBAL                     45: NULL + add_struct_type
                1050    LOAD_FAST                       8: _var_var_136
                1052    LOAD_FAST                       11: _var_var_139
                1054    CALL                            2
                1062    STORE_FAST                      12: _var_var_111
                1064    JUMP_FORWARD                    52 (to 1170)
                1066    LOAD_FAST                       10: _var_var_138
                1068    LOAD_CONST                      22: 'enum'
                1070    COMPARE_OP                      40 (==)
                1074    POP_JUMP_IF_FALSE               13 (to 1102)
                1076    LOAD_GLOBAL                     47: NULL + add_enum_type
                1086    LOAD_FAST                       8: _var_var_136
                1088    LOAD_FAST                       11: _var_var_139
                1090    CALL                            2
                1098    STORE_FAST                      12: _var_var_111
                1100    JUMP_FORWARD                    34 (to 1170)
                1102    LOAD_FAST                       10: _var_var_138
                1104    LOAD_CONST                      13: 'array'
                1106    COMPARE_OP                      40 (==)
                1110    POP_JUMP_IF_FALSE               13 (to 1138)
                1112    LOAD_GLOBAL                     49: NULL + add_array_type
                1122    LOAD_FAST                       8: _var_var_136
                1124    LOAD_FAST                       11: _var_var_139
                1126    CALL                            2
                1134    STORE_FAST                      12: _var_var_111
                1136    JUMP_FORWARD                    16 (to 1170)
                1138    LOAD_GLOBAL                     5: NULL + print
                1148    LOAD_CONST                      23: '[!] Failed to parse or find type '
                1150    LOAD_FAST                       8: _var_var_136
                1152    FORMAT_VALUE                    0 (FVC_NONE)
                1154    BUILD_STRING                    2
                1156    CALL                            1
                1164    POP_TOP                         
                1166    JUMP_BACKWARD                   404 (to 362)
                1170    LOAD_GLOBAL                     27: NULL + list
                1180    LOAD_FAST                       7: _var_var_116
                1182    LOAD_ATTR                       50: cfunc
                1202    LOAD_ATTR                       52: lvars
                1222    CALL                            1
                1230    GET_ITER                        
                1232    FOR_ITER                        216 (to 1666)
                1236    STORE_FAST                      17: _var_var_33
                1238    LOAD_FAST                       17: _var_var_33
                1240    LOAD_ATTR                       54: is_arg_var
                1260    POP_JUMP_IF_FALSE               1 (to 1264)
                1262    JUMP_BACKWARD                   16 (to 1232)
                1264    LOAD_FAST                       17: _var_var_33
                1266    POP_JUMP_IF_FALSE               12 (to 1292)
                1268    LOAD_FAST                       17: _var_var_33
                1270    LOAD_ATTR                       56: name
                1290    POP_JUMP_IF_TRUE                1 (to 1294)
                1292    JUMP_BACKWARD                   31 (to 1232)
                1294    LOAD_FAST                       17: _var_var_33
                1296    LOAD_ATTR                       56: name
                1316    LOAD_FAST                       5: _var_var_117
                1318    COMPARE_OP                      55 (!=)
                1322    POP_JUMP_IF_FALSE               1 (to 1326)
                1324    JUMP_BACKWARD                   47 (to 1232)
                1326    LOAD_FAST                       17: _var_var_33
                1328    LOAD_ATTR                       59: type
                1348    CALL                            0
                1356    LOAD_ATTR                       61: dstr
                1376    CALL                            0
                1384    STORE_FAST                      18: _var_var_149
                1386    LOAD_CONST                      24: (True, True)
                1388    UNPACK_SEQUENCE                 2
                1392    STORE_FAST                      19: _var_var_150
                1394    STORE_FAST                      20: _var_var_151
                1396    LOAD_FAST                       9: _var_var_137
                1398    POP_JUMP_IF_FALSE               24 (to 1448)
                1400    LOAD_FAST                       9: _var_var_137
                1402    LOAD_FAST                       5: _var_var_117
                1404    COMPARE_OP                      55 (!=)
                1408    POP_JUMP_IF_FALSE               19 (to 1448)
                1410    LOAD_FAST                       7: _var_var_116
                1412    LOAD_ATTR                       63: rename_lvar
                1432    LOAD_FAST                       17: _var_var_33
                1434    LOAD_FAST                       9: _var_var_137
                1436    LOAD_CONST                      25: 1
                1438    CALL                            3
                1446    STORE_FAST                      19: _var_var_150
                1448    LOAD_FAST                       8: _var_var_136
                1450    POP_JUMP_IF_FALSE               23 (to 1498)
                1452    LOAD_FAST                       8: _var_var_136
                1454    LOAD_FAST                       18: _var_var_149
                1456    COMPARE_OP                      55 (!=)
                1460    POP_JUMP_IF_FALSE               18 (to 1498)
                1462    LOAD_FAST                       7: _var_var_116
                1464    LOAD_ATTR                       65: set_lvar_type
                1484    LOAD_FAST                       17: _var_var_33
                1486    LOAD_FAST                       12: _var_var_111
                1488    CALL                            2
                1496    STORE_FAST                      20: _var_var_151
                1498    LOAD_FAST                       19: _var_var_150
                1500    POP_JUMP_IF_FALSE               42 (to 1586)
                1502    LOAD_FAST                       20: _var_var_151
                1504    POP_JUMP_IF_FALSE               40 (to 1586)
                1506    LOAD_GLOBAL                     5: NULL + print
                1516    LOAD_CONST                      26: '[+] Successfully change var: '
                1518    LOAD_FAST                       18: _var_var_149
                1520    FORMAT_VALUE                    0 (FVC_NONE)
                1522    LOAD_CONST                      27: ' '
                1524    LOAD_FAST                       5: _var_var_117
                1526    FORMAT_VALUE                    0 (FVC_NONE)
                1528    LOAD_CONST                      28: ' to: '
                1530    LOAD_FAST                       8: _var_var_136
                1532    LOAD_ATTR                       67: replace
                1552    LOAD_CONST                      17: ';'
                1554    LOAD_CONST                      15: ''
                1556    CALL                            2
                1564    FORMAT_VALUE                    0 (FVC_NONE)
                1566    LOAD_CONST                      27: ' '
                1568    LOAD_FAST                       9: _var_var_137
                1570    FORMAT_VALUE                    0 (FVC_NONE)
                1572    BUILD_STRING                    8
                1574    CALL                            1
                1582    POP_TOP                         
                1584    JUMP_FORWARD                    39 (to 1664)
                1586    LOAD_GLOBAL                     5: NULL + print
                1596    LOAD_CONST                      29: '[!] Fail change var: '
                1598    LOAD_FAST                       18: _var_var_149
                1600    FORMAT_VALUE                    0 (FVC_NONE)
                1602    LOAD_CONST                      27: ' '
                1604    LOAD_FAST                       5: _var_var_117
                1606    FORMAT_VALUE                    0 (FVC_NONE)
                1608    LOAD_CONST                      28: ' to: '
                1610    LOAD_FAST                       8: _var_var_136
                1612    LOAD_ATTR                       67: replace
                1632    LOAD_CONST                      17: ';'
                1634    LOAD_CONST                      15: ''
                1636    CALL                            2
                1644    FORMAT_VALUE                    0 (FVC_NONE)
                1646    LOAD_CONST                      27: ' '
                1648    LOAD_FAST                       9: _var_var_137
                1650    FORMAT_VALUE                    0 (FVC_NONE)
                1652    BUILD_STRING                    8
                1654    CALL                            1
                1662    POP_TOP                         
                1664    POP_TOP                         
                1666    JUMP_FORWARD                    27 (to 1722)
                1668    END_FOR                         
                1670    LOAD_GLOBAL                     5: NULL + print
                1680    LOAD_CONST                      30: '[!] Fail to find variable '
                1682    LOAD_FAST                       5: _var_var_117
                1684    FORMAT_VALUE                    0 (FVC_NONE)
                1686    LOAD_CONST                      31: ' in function '
                1688    LOAD_GLOBAL                     13: NULL + hex
                1698    LOAD_FAST                       0: func_ea
                1700    CALL                            1
                1708    FORMAT_VALUE                    0 (FVC_NONE)
                1710    BUILD_STRING                    4
                1712    CALL                            1
                1720    POP_TOP                         
                1722    LOAD_FAST                       7: _var_var_116
                1724    LOAD_ATTR                       50: cfunc
                1744    LOAD_ATTR                       69: refresh_func_ctext
                1764    CALL                            0
                1772    POP_TOP                         
                1774    JUMP_BACKWARD                   708 (to 362)
                1778    END_FOR                         
                1780    LOAD_CONST                      19: True
                1782    NOP                             
                1784    NOP                             
                1786    NOP                             
                1788    JUMP_FORWARD                    24 (to 1838)
                1796    POP_TOP                         
                1798    RETURN_CONST                    19: True
                1800    SWAP                            2
                1802    POP_TOP                         
                1804    SWAP                            2
                1806    STORE_FAST                      13: _var_var_140
                1808    RERAISE                         0
                1810    PUSH_EXC_INFO                   
                1812    PUSH_NULL                       
                1814    LOAD_CONST                      6: '__pyarmor_exit_55272__'
                1816    NOP                             
                1818    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf8\x06\x00\x00\x00\x00\x00\x00'
                1820    CALL                            1
                1828    POP_TOP                         
                1830    RERAISE                         0
                1832    COPY                            3
                1834    POP_EXCEPT                      
                1836    RERAISE                         1
                1838    PUSH_NULL                       
                1840    LOAD_CONST                      6: '__pyarmor_exit_55272__'
                1842    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf8\x06\x00\x00\x00\x00\x00\x00'
                1844    BUILD_TUPLE                     1
                1846    CALL_FUNCTION_EX                0
                1848    POP_TOP                         
                1850    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: build_doxygen_comment
            Qualified Name: build_doxygen_comment
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 10
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'get'
                'dict'
                'items'
                'isinstance'
            [Locals+Names]
                'prediction'
                '__assert_armored__'
                '_var_var_152'
                '_var_var_153'
                '_var_var_154'
                '_var_var_155'
                '_var_var_156'
                '_var_var_157'
                '_var_var_158'
                '_var_var_159'
                '_var_var_160'
                '_var_var_161'
                '_var_var_162'
                '_var_var_163'
            [Constants]
                None
                '__pyarmor_assert_55273__'
                '__pyarmor_enter_55274__'
                b'<COAddr>\x03\x00\x00\x1a\xd8\x01\x00\x00\x00\x00\x00\x00'
                'brief'
                ''
                'details'
                'params'
                'return'
                'category'
                'algorithm'
                (
                    'brief'
                    'details'
                    'params'
                    'return'
                    'category'
                    'algorithm'
                )
                '/**\n'
                ' * @'
                ' '
                ': '
                '\n'
                ' */'
                '__pyarmor_exit_55275__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55274__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xd8\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: prediction
                30      LOAD_ATTR                       1: get
                50      LOAD_CONST                      4: 'brief'
                52      LOAD_CONST                      5: ''
                54      CALL                            2
                62      STORE_FAST                      2: _var_var_152
                64      LOAD_FAST                       0: prediction
                66      LOAD_ATTR                       1: get
                86      LOAD_CONST                      6: 'details'
                88      LOAD_CONST                      5: ''
                90      CALL                            2
                98      STORE_FAST                      3: _var_var_153
                100     LOAD_FAST                       0: prediction
                102     LOAD_ATTR                       1: get
                122     LOAD_CONST                      7: 'params'
                124     LOAD_GLOBAL                     3: NULL + dict
                134     CALL                            0
                142     CALL                            2
                150     STORE_FAST                      4: _var_var_154
                152     LOAD_FAST                       0: prediction
                154     LOAD_ATTR                       1: get
                174     LOAD_CONST                      8: 'return'
                176     LOAD_CONST                      5: ''
                178     CALL                            2
                186     STORE_FAST                      5: _var_var_155
                188     LOAD_FAST                       0: prediction
                190     LOAD_ATTR                       1: get
                210     LOAD_CONST                      9: 'category'
                212     LOAD_CONST                      5: ''
                214     CALL                            2
                222     STORE_FAST                      6: _var_var_156
                224     LOAD_FAST                       0: prediction
                226     LOAD_ATTR                       1: get
                246     LOAD_CONST                      10: 'algorithm'
                248     LOAD_CONST                      5: ''
                250     CALL                            2
                258     STORE_FAST                      7: _var_var_157
                260     LOAD_FAST                       2: _var_var_152
                262     LOAD_FAST                       3: _var_var_153
                264     LOAD_FAST                       4: _var_var_154
                266     LOAD_FAST                       5: _var_var_155
                268     LOAD_FAST                       6: _var_var_156
                270     LOAD_FAST                       7: _var_var_157
                272     LOAD_CONST                      11: ('brief', 'details', 'params', 'return', 'category', 'algorithm')
                274     BUILD_CONST_KEY_MAP             6
                276     STORE_FAST                      8: _var_var_158
                278     LOAD_CONST                      12: '/**\n'
                280     STORE_FAST                      9: _var_var_159
                282     LOAD_FAST                       8: _var_var_158
                284     LOAD_ATTR                       5: items
                304     CALL                            0
                312     GET_ITER                        
                314     FOR_ITER                        73 (to 462)
                318     UNPACK_SEQUENCE                 2
                322     STORE_FAST                      10: _var_var_160
                324     STORE_FAST                      11: _var_var_161
                326     LOAD_GLOBAL                     7: NULL + isinstance
                336     LOAD_FAST                       11: _var_var_161
                338     LOAD_GLOBAL                     2: dict
                348     CALL                            2
                356     POP_JUMP_IF_FALSE               40 (to 438)
                358     LOAD_FAST                       11: _var_var_161
                360     LOAD_ATTR                       5: items
                380     CALL                            0
                388     GET_ITER                        
                390     FOR_ITER                        20 (to 432)
                394     UNPACK_SEQUENCE                 2
                398     STORE_FAST                      12: _var_var_162
                400     STORE_FAST                      13: _var_var_163
                402     LOAD_FAST                       9: _var_var_159
                404     LOAD_CONST                      13: ' * @'
                406     LOAD_FAST                       10: _var_var_160
                408     FORMAT_VALUE                    0 (FVC_NONE)
                410     LOAD_CONST                      14: ' '
                412     LOAD_FAST                       12: _var_var_162
                414     FORMAT_VALUE                    0 (FVC_NONE)
                416     LOAD_CONST                      15: ': '
                418     LOAD_FAST                       13: _var_var_163
                420     FORMAT_VALUE                    0 (FVC_NONE)
                422     LOAD_CONST                      16: '\n'
                424     BUILD_STRING                    7
                426     BINARY_OP                       13 (+=)
                430     STORE_FAST                      9: _var_var_159
                432     JUMP_BACKWARD                   22 (to 390)
                434     END_FOR                         
                436     JUMP_BACKWARD                   62 (to 314)
                438     LOAD_FAST                       9: _var_var_159
                440     LOAD_CONST                      13: ' * @'
                442     LOAD_FAST                       10: _var_var_160
                444     FORMAT_VALUE                    0 (FVC_NONE)
                446     LOAD_CONST                      15: ': '
                448     LOAD_FAST                       11: _var_var_161
                450     FORMAT_VALUE                    0 (FVC_NONE)
                452     LOAD_CONST                      16: '\n'
                454     BUILD_STRING                    5
                456     BINARY_OP                       13 (+=)
                460     STORE_FAST                      9: _var_var_159
                462     JUMP_BACKWARD                   75 (to 314)
                464     END_FOR                         
                466     LOAD_FAST                       9: _var_var_159
                468     LOAD_CONST                      17: ' */'
                470     BINARY_OP                       13 (+=)
                474     STORE_FAST                      9: _var_var_159
                476     LOAD_FAST                       9: _var_var_159
                478     NOP                             
                480     NOP                             
                482     NOP                             
                484     JUMP_FORWARD                    20 (to 526)
                486     CALL                            1
                494     POP_TOP                         
                496     RETURN_VALUE                    
                498     PUSH_EXC_INFO                   
                500     PUSH_NULL                       
                502     LOAD_CONST                      18: '__pyarmor_exit_55275__'
                504     NOP                             
                506     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xd8\x01\x00\x00\x00\x00\x00\x00'
                508     CALL                            1
                516     POP_TOP                         
                518     RERAISE                         0
                520     COPY                            3
                522     POP_EXCEPT                      
                524     RERAISE                         1
                526     PUSH_NULL                       
                528     LOAD_CONST                      18: '__pyarmor_exit_55275__'
                530     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xd8\x01\x00\x00\x00\x00\x00\x00'
                532     BUILD_TUPLE                     1
                534     CALL_FUNCTION_EX                0
                536     POP_TOP                         
                538     RETURN_VALUE                    
        'comment'
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction_func_comment
            Qualified Name: apply_prediction_func_comment
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_funcs'
                'get_func'
                'print'
                'hex'
                'idc'
                'set_func_cmt'
                'start_ea'
                'idaapi'
                'open_pseudocode'
                'cfunc'
                'refresh_func_ctext'
            [Locals+Names]
                'func_ea'
                'comment'
                '__assert_armored__'
                '_var_var_66'
                '_var_var_116'
            [Constants]
                None
                '__pyarmor_assert_55276__'
                '__pyarmor_enter_55277__'
                b'<COAddr>\x01\x00\x00\x1a\xfe\x01\x00\x00\x00\x00\x00\x00'
                '[!] Fail to get function at '
                '__pyarmor_exit_55278__'
                False
                '[!] Apply empty comment to '
                True
                0
                '[+] Successfully set comment for function '
                '[!] Fail to set comment for function '
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55277__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xfe\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + ida_funcs
                38      LOAD_ATTR                       2: get_func
                58      LOAD_FAST                       0: func_ea
                60      CALL                            1
                68      STORE_FAST                      3: _var_var_66
                70      LOAD_FAST                       3: _var_var_66
                72      POP_JUMP_IF_TRUE                34 (to 142)
                74      LOAD_GLOBAL                     5: NULL + print
                84      LOAD_CONST                      4: '[!] Fail to get function at '
                86      LOAD_GLOBAL                     7: NULL + hex
                96      LOAD_FAST                       0: func_ea
                98      CALL                            1
                106     FORMAT_VALUE                    0 (FVC_NONE)
                108     BUILD_STRING                    2
                110     CALL                            1
                118     POP_TOP                         
                120     NOP                             
                122     LOAD_CONST                      6: False
                124     NOP                             
                126     NOP                             
                128     NOP                             
                130     JUMP_FORWARD                    216 (to 564)
                138     POP_TOP                         
                140     RETURN_CONST                    6: False
                142     LOAD_FAST                       1: comment
                144     POP_JUMP_IF_TRUE                34 (to 214)
                146     LOAD_GLOBAL                     5: NULL + print
                156     LOAD_CONST                      7: '[!] Apply empty comment to '
                158     LOAD_GLOBAL                     7: NULL + hex
                168     LOAD_FAST                       0: func_ea
                170     CALL                            1
                178     FORMAT_VALUE                    0 (FVC_NONE)
                180     BUILD_STRING                    2
                182     CALL                            1
                190     POP_TOP                         
                192     NOP                             
                194     LOAD_CONST                      8: True
                196     NOP                             
                198     NOP                             
                200     NOP                             
                202     JUMP_FORWARD                    180 (to 564)
                210     POP_TOP                         
                212     RETURN_CONST                    8: True
                214     LOAD_GLOBAL                     9: NULL + idc
                224     LOAD_ATTR                       10: set_func_cmt
                244     LOAD_FAST                       3: _var_var_66
                246     LOAD_ATTR                       12: start_ea
                266     LOAD_FAST                       1: comment
                268     LOAD_CONST                      9: 0
                270     CALL                            3
                278     POP_JUMP_IF_FALSE               94 (to 468)
                280     LOAD_GLOBAL                     5: NULL + print
                290     LOAD_CONST                      10: '[+] Successfully set comment for function '
                292     LOAD_GLOBAL                     7: NULL + hex
                302     LOAD_FAST                       0: func_ea
                304     CALL                            1
                312     FORMAT_VALUE                    0 (FVC_NONE)
                314     BUILD_STRING                    2
                316     CALL                            1
                324     POP_TOP                         
                326     LOAD_GLOBAL                     15: NULL + idaapi
                336     LOAD_ATTR                       16: open_pseudocode
                356     LOAD_FAST                       3: _var_var_66
                358     LOAD_ATTR                       12: start_ea
                378     LOAD_CONST                      9: 0
                380     CALL                            2
                388     STORE_FAST                      4: _var_var_116
                390     LOAD_FAST                       4: _var_var_116
                392     POP_JUMP_IF_FALSE               26 (to 446)
                394     LOAD_FAST                       4: _var_var_116
                396     LOAD_ATTR                       18: cfunc
                416     LOAD_ATTR                       21: refresh_func_ctext
                436     CALL                            0
                444     POP_TOP                         
                446     NOP                             
                448     LOAD_CONST                      8: True
                450     NOP                             
                452     NOP                             
                454     NOP                             
                456     JUMP_FORWARD                    53 (to 564)
                464     POP_TOP                         
                466     RETURN_CONST                    8: True
                468     LOAD_GLOBAL                     5: NULL + print
                478     LOAD_CONST                      11: '[!] Fail to set comment for function '
                480     LOAD_GLOBAL                     7: NULL + hex
                490     LOAD_FAST                       0: func_ea
                492     CALL                            1
                500     FORMAT_VALUE                    0 (FVC_NONE)
                502     BUILD_STRING                    2
                504     CALL                            1
                512     POP_TOP                         
                514     NOP                             
                516     LOAD_CONST                      6: False
                518     NOP                             
                520     NOP                             
                522     NOP                             
                524     JUMP_FORWARD                    19 (to 564)
                532     POP_TOP                         
                534     RETURN_CONST                    6: False
                536     PUSH_EXC_INFO                   
                538     PUSH_NULL                       
                540     LOAD_CONST                      5: '__pyarmor_exit_55278__'
                542     NOP                             
                544     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xfe\x01\x00\x00\x00\x00\x00\x00'
                546     CALL                            1
                554     POP_TOP                         
                556     RERAISE                         0
                558     COPY                            3
                560     POP_EXCEPT                      
                562     RERAISE                         1
                564     PUSH_NULL                       
                566     LOAD_CONST                      5: '__pyarmor_exit_55278__'
                568     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xfe\x01\x00\x00\x00\x00\x00\x00'
                570     BUILD_TUPLE                     1
                572     CALL_FUNCTION_EX                0
                574     POP_TOP                         
                576     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction_inline_comment
            Qualified Name: apply_prediction_inline_comment
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 9
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'get'
                'dict'
                'isinstance'
                'print'
                'idaapi'
                'open_pseudocode'
                'hex'
                'cfunc'
                'get_pseudocode'
                'items'
                'isdigit'
                'int'
                'len'
                'ida_hexrays'
                'ctree_item_t'
                'get_line_item'
                'line'
                'treeloc_t'
                'it'
                'ea'
                'ITP_SEMI'
                'itp'
                'set_user_cmt'
                'save_user_cmts'
                'refresh_func_ctext'
            [Locals+Names]
                'func_ea'
                'prediction'
                '__assert_armored__'
                '_var_var_164'
                '_var_var_116'
                '_var_var_165'
                '_var_var_166'
                '_var_var_167'
                '_var_var_168'
                '_var_var_169'
                '_var_var_170'
                '_var_var_171'
                '_var_var_172'
            [Constants]
                None
                '__pyarmor_assert_55279__'
                '__pyarmor_enter_55280__'
                b'<COAddr>\x01\x00\x00\x1a(\x05\x00\x00\x00\x00\x00\x00'
                'inline_comment'
                '[!] found bad inline_comment in prediction: '
                '__pyarmor_exit_55281__'
                0
                '[!] Fail to open pseudocode view for function at '
                '[!] Fail to get cfunc for function at '
                '[!] Fail to get pseudocode for function at '
                '[!] bad line number '
                ' with comment: '
                1
                True
                '[-] get no item for line number == '
                ', jump to next line'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55280__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x05\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       1: prediction
                30      LOAD_ATTR                       1: get
                50      LOAD_CONST                      4: 'inline_comment'
                52      LOAD_GLOBAL                     3: NULL + dict
                62      CALL                            0
                70      CALL                            2
                78      STORE_FAST                      3: _var_var_164
                80      LOAD_FAST                       3: _var_var_164
                82      POP_JUMP_IF_FALSE               16 (to 116)
                84      LOAD_GLOBAL                     5: NULL + isinstance
                94      LOAD_FAST                       3: _var_var_164
                96      LOAD_GLOBAL                     2: dict
                106     CALL                            2
                114     POP_JUMP_IF_TRUE                25 (to 166)
                116     LOAD_GLOBAL                     7: NULL + print
                126     LOAD_CONST                      5: '[!] found bad inline_comment in prediction: '
                128     LOAD_FAST                       3: _var_var_164
                130     FORMAT_VALUE                    0 (FVC_NONE)
                132     BUILD_STRING                    2
                134     CALL                            1
                142     POP_TOP                         
                144     NOP                             
                146     LOAD_CONST                      0: None
                148     NOP                             
                150     NOP                             
                152     JUMP_FORWARD                    609 (to 1374)
                162     POP_TOP                         
                164     RETURN_CONST                    0: None
                166     LOAD_GLOBAL                     9: NULL + idaapi
                176     LOAD_ATTR                       10: open_pseudocode
                196     LOAD_FAST                       0: func_ea
                198     LOAD_CONST                      7: 0
                200     CALL                            2
                208     STORE_FAST                      4: _var_var_116
                210     LOAD_FAST                       4: _var_var_116
                212     POP_JUMP_IF_TRUE                34 (to 282)
                214     LOAD_GLOBAL                     7: NULL + print
                224     LOAD_CONST                      8: '[!] Fail to open pseudocode view for function at '
                226     LOAD_GLOBAL                     13: NULL + hex
                236     LOAD_FAST                       0: func_ea
                238     CALL                            1
                246     FORMAT_VALUE                    0 (FVC_NONE)
                248     BUILD_STRING                    2
                250     CALL                            1
                258     POP_TOP                         
                260     NOP                             
                262     LOAD_CONST                      0: None
                264     NOP                             
                266     NOP                             
                268     JUMP_FORWARD                    551 (to 1374)
                278     POP_TOP                         
                280     RETURN_CONST                    0: None
                282     LOAD_FAST                       4: _var_var_116
                284     LOAD_ATTR                       14: cfunc
                304     POP_JUMP_IF_TRUE                34 (to 374)
                306     LOAD_GLOBAL                     7: NULL + print
                316     LOAD_CONST                      9: '[!] Fail to get cfunc for function at '
                318     LOAD_GLOBAL                     13: NULL + hex
                328     LOAD_FAST                       0: func_ea
                330     CALL                            1
                338     FORMAT_VALUE                    0 (FVC_NONE)
                340     BUILD_STRING                    2
                342     CALL                            1
                350     POP_TOP                         
                352     NOP                             
                354     LOAD_CONST                      0: None
                356     NOP                             
                358     NOP                             
                360     JUMP_FORWARD                    505 (to 1374)
                370     POP_TOP                         
                372     RETURN_CONST                    0: None
                374     LOAD_FAST                       4: _var_var_116
                376     LOAD_ATTR                       14: cfunc
                396     LOAD_ATTR                       17: get_pseudocode
                416     CALL                            0
                424     STORE_FAST                      5: _var_var_165
                426     LOAD_FAST                       5: _var_var_165
                428     POP_JUMP_IF_TRUE                34 (to 498)
                430     LOAD_GLOBAL                     7: NULL + print
                440     LOAD_CONST                      10: '[!] Fail to get pseudocode for function at '
                442     LOAD_GLOBAL                     13: NULL + hex
                452     LOAD_FAST                       0: func_ea
                454     CALL                            1
                462     FORMAT_VALUE                    0 (FVC_NONE)
                464     BUILD_STRING                    2
                466     CALL                            1
                474     POP_TOP                         
                476     NOP                             
                478     LOAD_CONST                      0: None
                480     NOP                             
                482     NOP                             
                484     JUMP_FORWARD                    443 (to 1374)
                494     POP_TOP                         
                496     RETURN_CONST                    0: None
                498     LOAD_FAST                       3: _var_var_164
                500     LOAD_ATTR                       19: items
                520     CALL                            0
                528     GET_ITER                        
                530     FOR_ITER                        342 (to 1218)
                536     UNPACK_SEQUENCE                 2
                540     STORE_FAST                      6: _var_var_166
                542     STORE_FAST                      7: _var_var_167
                544     LOAD_FAST                       6: _var_var_166
                546     LOAD_ATTR                       21: isdigit
                566     CALL                            0
                574     POP_JUMP_IF_FALSE               12 (to 600)
                576     LOAD_GLOBAL                     23: NULL + int
                586     LOAD_FAST                       6: _var_var_166
                588     CALL                            1
                596     STORE_FAST                      6: _var_var_166
                598     JUMP_FORWARD                    18 (to 636)
                600     LOAD_GLOBAL                     7: NULL + print
                610     LOAD_CONST                      11: '[!] bad line number '
                612     LOAD_FAST                       6: _var_var_166
                614     FORMAT_VALUE                    0 (FVC_NONE)
                616     LOAD_CONST                      12: ' with comment: '
                618     LOAD_FAST                       7: _var_var_167
                620     FORMAT_VALUE                    0 (FVC_NONE)
                622     BUILD_STRING                    4
                624     CALL                            1
                632     POP_TOP                         
                634     JUMP_BACKWARD                   53 (to 530)
                636     LOAD_FAST                       6: _var_var_166
                638     LOAD_CONST                      13: 1
                640     COMPARE_OP                      2 (<)
                644     POP_JUMP_IF_TRUE                14 (to 674)
                646     LOAD_FAST                       6: _var_var_166
                648     LOAD_GLOBAL                     25: NULL + len
                658     LOAD_FAST                       5: _var_var_165
                660     CALL                            1
                668     COMPARE_OP                      92 (>=)
                672     POP_JUMP_IF_FALSE               18 (to 710)
                674     LOAD_GLOBAL                     7: NULL + print
                684     LOAD_CONST                      11: '[!] bad line number '
                686     LOAD_FAST                       6: _var_var_166
                688     FORMAT_VALUE                    0 (FVC_NONE)
                690     LOAD_CONST                      12: ' with comment: '
                692     LOAD_FAST                       7: _var_var_167
                694     FORMAT_VALUE                    0 (FVC_NONE)
                696     BUILD_STRING                    4
                698     CALL                            1
                706     POP_TOP                         
                708     JUMP_BACKWARD                   90 (to 530)
                710     LOAD_CONST                      14: True
                712     STORE_FAST                      8: _var_var_168
                714     LOAD_GLOBAL                     27: NULL + ida_hexrays
                724     LOAD_ATTR                       28: ctree_item_t
                744     CALL                            0
                752     STORE_FAST                      9: _var_var_169
                754     LOAD_GLOBAL                     27: NULL + ida_hexrays
                764     LOAD_ATTR                       28: ctree_item_t
                784     CALL                            0
                792     STORE_FAST                      10: _var_var_170
                794     LOAD_GLOBAL                     27: NULL + ida_hexrays
                804     LOAD_ATTR                       28: ctree_item_t
                824     CALL                            0
                832     STORE_FAST                      11: _var_var_171
                834     LOAD_FAST                       6: _var_var_166
                836     LOAD_GLOBAL                     25: NULL + len
                846     LOAD_FAST                       5: _var_var_165
                848     CALL                            1
                856     COMPARE_OP                      2 (<)
                860     POP_JUMP_IF_FALSE               66 (to 994)
                862     LOAD_FAST                       4: _var_var_116
                864     LOAD_ATTR                       14: cfunc
                884     LOAD_ATTR                       31: get_line_item
                904     LOAD_FAST                       5: _var_var_165
                906     LOAD_FAST                       6: _var_var_166
                908     BINARY_SUBSCR                   
                912     LOAD_ATTR                       32: line
                932     LOAD_CONST                      7: 0
                934     LOAD_FAST                       8: _var_var_168
                936     LOAD_FAST                       9: _var_var_169
                938     LOAD_FAST                       10: _var_var_170
                940     LOAD_FAST                       11: _var_var_171
                942     CALL                            6
                950     POP_JUMP_IF_TRUE                21 (to 994)
                952     LOAD_GLOBAL                     7: NULL + print
                962     LOAD_CONST                      15: '[-] get no item for line number == '
                964     LOAD_FAST                       6: _var_var_166
                966     FORMAT_VALUE                    0 (FVC_NONE)
                968     LOAD_CONST                      16: ', jump to next line'
                970     BUILD_STRING                    3
                972     CALL                            1
                980     POP_TOP                         
                982     LOAD_FAST                       6: _var_var_166
                984     LOAD_CONST                      13: 1
                986     BINARY_OP                       13 (+=)
                990     STORE_FAST                      6: _var_var_166
                992     JUMP_BACKWARD                   80 (to 834)
                994     LOAD_FAST                       6: _var_var_166
                996     LOAD_GLOBAL                     25: NULL + len
                1006    LOAD_FAST                       5: _var_var_165
                1008    CALL                            1
                1016    COMPARE_OP                      92 (>=)
                1020    POP_JUMP_IF_FALSE               1 (to 1024)
                1022    JUMP_BACKWARD                   247 (to 530)
                1024    LOAD_GLOBAL                     27: NULL + ida_hexrays
                1034    LOAD_ATTR                       34: treeloc_t
                1054    CALL                            0
                1062    STORE_FAST                      12: _var_var_172
                1064    LOAD_FAST                       10: _var_var_170
                1066    LOAD_ATTR                       36: it
                1086    LOAD_ATTR                       38: ea
                1106    LOAD_FAST                       12: _var_var_172
                1108    STORE_ATTR                      19: ea
                1118    LOAD_GLOBAL                     26: ida_hexrays
                1128    LOAD_ATTR                       40: ITP_SEMI
                1148    LOAD_FAST                       12: _var_var_172
                1150    STORE_ATTR                      21: itp
                1160    LOAD_FAST                       4: _var_var_116
                1162    LOAD_ATTR                       14: cfunc
                1182    LOAD_ATTR                       45: set_user_cmt
                1202    LOAD_FAST                       12: _var_var_172
                1204    LOAD_FAST                       7: _var_var_167
                1206    CALL                            2
                1214    POP_TOP                         
                1216    JUMP_BACKWARD                   345 (to 530)
                1220    END_FOR                         
                1222    LOAD_FAST                       4: _var_var_116
                1224    LOAD_ATTR                       14: cfunc
                1244    LOAD_ATTR                       47: save_user_cmts
                1264    CALL                            0
                1272    POP_TOP                         
                1274    LOAD_FAST                       4: _var_var_116
                1276    LOAD_ATTR                       14: cfunc
                1296    LOAD_ATTR                       49: refresh_func_ctext
                1316    CALL                            0
                1324    POP_TOP                         
                1326    LOAD_CONST                      14: True
                1328    NOP                             
                1330    NOP                             
                1332    NOP                             
                1334    JUMP_FORWARD                    19 (to 1374)
                1342    POP_TOP                         
                1344    RETURN_CONST                    14: True
                1346    PUSH_EXC_INFO                   
                1348    PUSH_NULL                       
                1350    LOAD_CONST                      6: '__pyarmor_exit_55281__'
                1352    NOP                             
                1354    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x05\x00\x00\x00\x00\x00\x00'
                1356    CALL                            1
                1364    POP_TOP                         
                1366    RERAISE                         0
                1368    COPY                            3
                1370    POP_EXCEPT                      
                1372    RERAISE                         1
                1374    PUSH_NULL                       
                1376    LOAD_CONST                      6: '__pyarmor_exit_55281__'
                1378    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x05\x00\x00\x00\x00\x00\x00'
                1380    BUILD_TUPLE                     1
                1382    CALL_FUNCTION_EX                0
                1384    POP_TOP                         
                1386    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..ext_info>
            Object Name: apply_prediction
            Qualified Name: apply_prediction
            Arg Count: 3
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'SUPPORT_FUNC_TYPES'
                'ida_funcs'
                'get_func'
                'hex'
                'is_thunk'
                'start_ea'
                'end_ea'
                'idc'
                'get_func_name'
                'demangle'
                'MEANINGLESS_NAME_LIST'
                'decompile'
                'DecompilationFailure'
                'apply_prediction_inline_comment'
                'apply_prediction_ret_type'
                'apply_prediction_func_name'
                'apply_prediction_args_old'
                'apply_prediction_vars'
                'build_doxygen_comment'
                'apply_prediction_func_comment'
                'NotImplementedError'
            [Locals+Names]
                'func_ea'
                'task_tag'
                'prediction'
                '__assert_armored__'
                '_var_var_66'
                '_var_var_97'
                '_var_var_98'
                '_var_var_99'
                '_var_var_7'
                '_var_var_50'
                '_var_var_173'
            [Constants]
                None
                '__pyarmor_assert_55282__'
                '__pyarmor_enter_55283__'
                b'<COAddr>\x01\x00\x00\x1a"\x05\x00\x00\x00\x00\x00\x00'
                '[🐛DEBUG] invoke apply_prediction'
                '[🐛DEBUG] task_tag: '
                '[🐛DEBUG] prediction: '
                '[!] Unsupported task tag: '
                '__pyarmor_exit_55284__'
                False
                '[!] Fail to get function at '
                '[!] Thunk function is not supported'
                '[!] apply_prediction: receive empty prediction'
                '[!] Function '
                ' is not good for building input'
                '[!] Failed to decompile function at '
                '<func-analysis>'
                'inline_comment'
                True
                '<specific-vars>'
                '<vars>'
                '<args>'
                '<funcname>'
                '<summary>'
                'Not implemented func_type == `'
                '` yet'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_55283__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a"\x05\x00\x00\x00\x00\x00\x00'
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
                38      LOAD_CONST                      4: '[🐛DEBUG] invoke apply_prediction'
                40      CALL                            1
                48      POP_TOP                         
                50      LOAD_GLOBAL                     1: NULL + print
                60      LOAD_CONST                      5: '[🐛DEBUG] task_tag: '
                62      LOAD_FAST                       1: task_tag
                64      FORMAT_VALUE                    0 (FVC_NONE)
                66      BUILD_STRING                    2
                68      CALL                            1
                76      POP_TOP                         
                78      LOAD_GLOBAL                     1: NULL + print
                88      LOAD_CONST                      6: '[🐛DEBUG] prediction: '
                90      LOAD_FAST                       2: prediction
                92      FORMAT_VALUE                    0 (FVC_NONE)
                94      BUILD_STRING                    2
                96      CALL                            1
                104     POP_TOP                         
                106     LOAD_FAST                       1: task_tag
                108     LOAD_GLOBAL                     2: SUPPORT_FUNC_TYPES
                118     CONTAINS_OP                     1 (not in)
                120     POP_JUMP_IF_FALSE               25 (to 172)
                122     LOAD_GLOBAL                     1: NULL + print
                132     LOAD_CONST                      7: '[!] Unsupported task tag: '
                134     LOAD_FAST                       1: task_tag
                136     FORMAT_VALUE                    0 (FVC_NONE)
                138     BUILD_STRING                    2
                140     CALL                            1
                148     POP_TOP                         
                150     NOP                             
                152     LOAD_CONST                      9: False
                154     NOP                             
                156     NOP                             
                158     JUMP_FORWARD                    603 (to 1368)
                168     POP_TOP                         
                170     RETURN_CONST                    9: False
                172     LOAD_GLOBAL                     5: NULL + ida_funcs
                182     LOAD_ATTR                       6: get_func
                202     LOAD_FAST                       0: func_ea
                204     CALL                            1
                212     STORE_FAST                      4: _var_var_66
                214     LOAD_FAST                       4: _var_var_66
                216     POP_JUMP_IF_TRUE                34 (to 286)
                218     LOAD_GLOBAL                     1: NULL + print
                228     LOAD_CONST                      10: '[!] Fail to get function at '
                230     LOAD_GLOBAL                     9: NULL + hex
                240     LOAD_FAST                       0: func_ea
                242     CALL                            1
                250     FORMAT_VALUE                    0 (FVC_NONE)
                252     BUILD_STRING                    2
                254     CALL                            1
                262     POP_TOP                         
                264     NOP                             
                266     LOAD_CONST                      9: False
                268     NOP                             
                270     NOP                             
                272     JUMP_FORWARD                    546 (to 1368)
                282     POP_TOP                         
                284     RETURN_CONST                    9: False
                286     LOAD_GLOBAL                     11: NULL + is_thunk
                296     LOAD_FAST                       0: func_ea
                298     CALL                            1
                306     POP_JUMP_IF_FALSE               22 (to 352)
                308     LOAD_GLOBAL                     1: NULL + print
                318     LOAD_CONST                      11: '[!] Thunk function is not supported'
                320     CALL                            1
                328     POP_TOP                         
                330     NOP                             
                332     LOAD_CONST                      9: False
                334     NOP                             
                336     NOP                             
                338     JUMP_FORWARD                    513 (to 1368)
                348     POP_TOP                         
                350     RETURN_CONST                    9: False
                352     LOAD_FAST                       2: prediction
                354     POP_JUMP_IF_TRUE                22 (to 400)
                356     LOAD_GLOBAL                     1: NULL + print
                366     LOAD_CONST                      12: '[!] apply_prediction: receive empty prediction'
                368     CALL                            1
                376     POP_TOP                         
                378     NOP                             
                380     LOAD_CONST                      9: False
                382     NOP                             
                384     NOP                             
                386     JUMP_FORWARD                    489 (to 1368)
                396     POP_TOP                         
                398     RETURN_CONST                    9: False
                400     LOAD_FAST                       4: _var_var_66
                402     LOAD_ATTR                       12: start_ea
                422     STORE_FAST                      5: _var_var_97
                424     LOAD_FAST                       4: _var_var_66
                426     LOAD_ATTR                       14: end_ea
                446     STORE_FAST                      6: _var_var_98
                448     LOAD_GLOBAL                     17: NULL + idc
                458     LOAD_ATTR                       18: get_func_name
                478     LOAD_FAST                       5: _var_var_97
                480     CALL                            1
                488     STORE_FAST                      7: _var_var_99
                490     LOAD_GLOBAL                     21: NULL + demangle
                500     LOAD_FAST                       7: _var_var_99
                502     CALL                            1
                510     STORE_FAST                      8: _var_var_7
                512     LOAD_FAST                       8: _var_var_7
                514     LOAD_GLOBAL                     22: MEANINGLESS_NAME_LIST
                524     CONTAINS_OP                     0 (in)
                526     POP_JUMP_IF_FALSE               26 (to 580)
                528     LOAD_GLOBAL                     1: NULL + print
                538     LOAD_CONST                      13: '[!] Function '
                540     LOAD_FAST                       8: _var_var_7
                542     FORMAT_VALUE                    0 (FVC_NONE)
                544     LOAD_CONST                      14: ' is not good for building input'
                546     BUILD_STRING                    3
                548     CALL                            1
                556     POP_TOP                         
                558     NOP                             
                560     LOAD_CONST                      9: False
                562     NOP                             
                564     NOP                             
                566     JUMP_FORWARD                    399 (to 1368)
                576     POP_TOP                         
                578     RETURN_CONST                    9: False
                580     NOP                             
                582     LOAD_GLOBAL                     25: NULL + decompile
                592     LOAD_FAST                       0: func_ea
                594     CALL                            1
                602     STORE_FAST                      9: _var_var_50
                604     LOAD_FAST                       9: _var_var_50
                606     LOAD_CONST                      0: None
                608     COMPARE_OP                      40 (==)
                612     POP_JUMP_IF_FALSE               6 (to 626)
                614     LOAD_GLOBAL                     26: DecompilationFailure
                624     RAISE_VARARGS                   1
                626     NOP                             
                628     LOAD_FAST                       1: task_tag
                630     LOAD_CONST                      16: '<func-analysis>'
                632     COMPARE_OP                      40 (==)
                636     POP_JUMP_IF_FALSE               98 (to 834)
                638     LOAD_CONST                      17: 'inline_comment'
                640     LOAD_FAST                       2: prediction
                642     CONTAINS_OP                     0 (in)
                644     POP_JUMP_IF_FALSE               12 (to 670)
                646     LOAD_GLOBAL                     29: NULL + apply_prediction_inline_comment
                656     LOAD_FAST                       0: func_ea
                658     LOAD_FAST                       2: prediction
                660     CALL                            2
                668     POP_TOP                         
                670     LOAD_GLOBAL                     31: NULL + apply_prediction_ret_type
                680     LOAD_FAST                       0: func_ea
                682     LOAD_FAST                       2: prediction
                684     CALL                            2
                692     POP_TOP                         
                694     LOAD_GLOBAL                     33: NULL + apply_prediction_func_name
                704     LOAD_FAST                       0: func_ea
                706     LOAD_FAST                       2: prediction
                708     CALL                            2
                716     POP_TOP                         
                718     LOAD_GLOBAL                     35: NULL + apply_prediction_args_old
                728     LOAD_FAST                       0: func_ea
                730     LOAD_FAST                       2: prediction
                732     CALL                            2
                740     POP_TOP                         
                742     LOAD_GLOBAL                     37: NULL + apply_prediction_vars
                752     LOAD_FAST                       0: func_ea
                754     LOAD_FAST                       2: prediction
                756     CALL                            2
                764     POP_TOP                         
                766     LOAD_GLOBAL                     39: NULL + build_doxygen_comment
                776     LOAD_FAST                       2: prediction
                778     CALL                            1
                786     STORE_FAST                      10: _var_var_173
                788     LOAD_GLOBAL                     41: NULL + apply_prediction_func_comment
                798     LOAD_FAST                       0: func_ea
                800     LOAD_FAST                       10: _var_var_173
                802     CALL                            2
                810     POP_TOP                         
                812     NOP                             
                814     LOAD_CONST                      18: True
                816     NOP                             
                818     NOP                             
                820     JUMP_FORWARD                    272 (to 1368)
                830     POP_TOP                         
                832     RETURN_CONST                    18: True
                834     LOAD_FAST                       1: task_tag
                836     LOAD_CONST                      19: '<specific-vars>'
                838     COMPARE_OP                      40 (==)
                842     POP_JUMP_IF_FALSE               35 (to 914)
                844     LOAD_GLOBAL                     35: NULL + apply_prediction_args_old
                854     LOAD_FAST                       0: func_ea
                856     LOAD_FAST                       2: prediction
                858     CALL                            2
                866     POP_TOP                         
                868     LOAD_GLOBAL                     37: NULL + apply_prediction_vars
                878     LOAD_FAST                       0: func_ea
                880     LOAD_FAST                       2: prediction
                882     CALL                            2
                890     POP_TOP                         
                892     NOP                             
                894     LOAD_CONST                      18: True
                896     NOP                             
                898     NOP                             
                900     NOP                             
                902     JUMP_FORWARD                    232 (to 1368)
                910     POP_TOP                         
                912     RETURN_CONST                    18: True
                914     LOAD_FAST                       1: task_tag
                916     LOAD_CONST                      20: '<vars>'
                918     COMPARE_OP                      40 (==)
                922     POP_JUMP_IF_FALSE               35 (to 994)
                924     LOAD_GLOBAL                     35: NULL + apply_prediction_args_old
                934     LOAD_FAST                       0: func_ea
                936     LOAD_FAST                       2: prediction
                938     CALL                            2
                946     POP_TOP                         
                948     LOAD_GLOBAL                     37: NULL + apply_prediction_vars
                958     LOAD_FAST                       0: func_ea
                960     LOAD_FAST                       2: prediction
                962     CALL                            2
                970     POP_TOP                         
                972     NOP                             
                974     LOAD_CONST                      18: True
                976     NOP                             
                978     NOP                             
                980     NOP                             
                982     JUMP_FORWARD                    192 (to 1368)
                990     POP_TOP                         
                992     RETURN_CONST                    18: True
                994     LOAD_FAST                       1: task_tag
                996     LOAD_CONST                      21: '<args>'
                998     COMPARE_OP                      40 (==)
                1002    POP_JUMP_IF_FALSE               23 (to 1050)
                1004    LOAD_GLOBAL                     35: NULL + apply_prediction_args_old
                1014    LOAD_FAST                       0: func_ea
                1016    LOAD_FAST                       2: prediction
                1018    CALL                            2
                1026    POP_TOP                         
                1028    NOP                             
                1030    LOAD_CONST                      18: True
                1032    NOP                             
                1034    NOP                             
                1036    NOP                             
                1038    JUMP_FORWARD                    164 (to 1368)
                1046    POP_TOP                         
                1048    RETURN_CONST                    18: True
                1050    LOAD_FAST                       1: task_tag
                1052    LOAD_CONST                      22: '<funcname>'
                1054    COMPARE_OP                      40 (==)
                1058    POP_JUMP_IF_FALSE               23 (to 1106)
                1060    LOAD_GLOBAL                     33: NULL + apply_prediction_func_name
                1070    LOAD_FAST                       0: func_ea
                1072    LOAD_FAST                       2: prediction
                1074    CALL                            2
                1082    POP_TOP                         
                1084    NOP                             
                1086    LOAD_CONST                      18: True
                1088    NOP                             
                1090    NOP                             
                1092    NOP                             
                1094    JUMP_FORWARD                    136 (to 1368)
                1102    POP_TOP                         
                1104    RETURN_CONST                    18: True
                1106    LOAD_FAST                       1: task_tag
                1108    LOAD_CONST                      23: '<summary>'
                1110    COMPARE_OP                      40 (==)
                1114    POP_JUMP_IF_FALSE               50 (to 1216)
                1116    LOAD_CONST                      17: 'inline_comment'
                1118    LOAD_FAST                       2: prediction
                1120    CONTAINS_OP                     0 (in)
                1122    POP_JUMP_IF_FALSE               12 (to 1148)
                1124    LOAD_GLOBAL                     29: NULL + apply_prediction_inline_comment
                1134    LOAD_FAST                       0: func_ea
                1136    LOAD_FAST                       2: prediction
                1138    CALL                            2
                1146    POP_TOP                         
                1148    LOAD_GLOBAL                     39: NULL + build_doxygen_comment
                1158    LOAD_FAST                       2: prediction
                1160    CALL                            1
                1168    STORE_FAST                      10: _var_var_173
                1170    LOAD_GLOBAL                     41: NULL + apply_prediction_func_comment
                1180    LOAD_FAST                       0: func_ea
                1182    LOAD_FAST                       10: _var_var_173
                1184    CALL                            2
                1192    POP_TOP                         
                1194    NOP                             
                1196    LOAD_CONST                      18: True
                1198    NOP                             
                1200    NOP                             
                1202    NOP                             
                1204    JUMP_FORWARD                    81 (to 1368)
                1212    POP_TOP                         
                1214    RETURN_CONST                    18: True
                1216    LOAD_GLOBAL                     43: NULL + NotImplementedError
                1226    LOAD_CONST                      24: 'Not implemented func_type == `'
                1228    LOAD_FAST                       1: task_tag
                1230    FORMAT_VALUE                    0 (FVC_NONE)
                1232    LOAD_CONST                      25: '` yet'
                1234    BUILD_STRING                    3
                1236    CALL                            1
                1244    RAISE_VARARGS                   1
                1246    PUSH_EXC_INFO                   
                1248    LOAD_GLOBAL                     26: DecompilationFailure
                1258    CHECK_EXC_MATCH                 
                1260    POP_JUMP_IF_FALSE               35 (to 1332)
                1262    POP_TOP                         
                1264    LOAD_GLOBAL                     1: NULL + print
                1274    LOAD_CONST                      15: '[!] Failed to decompile function at '
                1276    LOAD_GLOBAL                     9: NULL + hex
                1286    LOAD_FAST                       0: func_ea
                1288    CALL                            1
                1296    FORMAT_VALUE                    0 (FVC_NONE)
                1298    BUILD_STRING                    2
                1300    CALL                            1
                1308    POP_TOP                         
                1310    POP_EXCEPT                      
                1312    LOAD_CONST                      0: None
                1314    NOP                             
                1316    NOP                             
                1318    NOP                             
                1320    JUMP_FORWARD                    23 (to 1368)
                1328    POP_TOP                         
                1330    RETURN_CONST                    0: None
                1332    RERAISE                         0
                1334    COPY                            3
                1336    POP_EXCEPT                      
                1338    RERAISE                         1
                1340    PUSH_EXC_INFO                   
                1342    PUSH_NULL                       
                1344    LOAD_CONST                      8: '__pyarmor_exit_55284__'
                1346    NOP                             
                1348    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a"\x05\x00\x00\x00\x00\x00\x00'
                1350    CALL                            1
                1358    POP_TOP                         
                1360    RERAISE                         0
                1362    COPY                            3
                1364    POP_EXCEPT                      
                1366    RERAISE                         1
                1368    PUSH_NULL                       
                1370    LOAD_CONST                      8: '__pyarmor_exit_55284__'
                1372    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a"\x05\x00\x00\x00\x00\x00\x00'
                1374    BUILD_TUPLE                     1
                1376    CALL_FUNCTION_EX                0
                1378    POP_TOP                         
                1380    RETURN_VALUE                    
        '__pyarmor_exit_55131__'
        (
            0
        )
        (
            (
            )
        )
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_55130__'
        8       LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\x08\x03\x00\x00\x00\x00\x00\x00'
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
        38      IMPORT_NAME                     2: re
        40      STORE_NAME                      2: re
        42      LOAD_CONST                      3: 0
        44      LOAD_CONST                      4: None
        46      IMPORT_NAME                     3: idc
        48      STORE_NAME                      3: idc
        50      LOAD_CONST                      3: 0
        52      LOAD_CONST                      4: None
        54      IMPORT_NAME                     4: json
        56      STORE_NAME                      4: json
        58      LOAD_CONST                      3: 0
        60      LOAD_CONST                      4: None
        62      IMPORT_NAME                     5: hashlib
        64      STORE_NAME                      5: hashlib
        66      LOAD_CONST                      3: 0
        68      LOAD_CONST                      4: None
        70      IMPORT_NAME                     6: idaapi
        72      STORE_NAME                      6: idaapi
        74      LOAD_CONST                      3: 0
        76      LOAD_CONST                      4: None
        78      IMPORT_NAME                     7: ida_ua
        80      STORE_NAME                      7: ida_ua
        82      LOAD_CONST                      3: 0
        84      LOAD_CONST                      4: None
        86      IMPORT_NAME                     8: ida_idp
        88      STORE_NAME                      8: ida_idp
        90      LOAD_CONST                      3: 0
        92      LOAD_CONST                      4: None
        94      IMPORT_NAME                     9: ida_name
        96      STORE_NAME                      9: ida_name
        98      LOAD_CONST                      3: 0
        100     LOAD_CONST                      4: None
        102     IMPORT_NAME                     10: idautils
        104     STORE_NAME                      10: idautils
        106     LOAD_CONST                      3: 0
        108     LOAD_CONST                      4: None
        110     IMPORT_NAME                     11: ida_nalt
        112     STORE_NAME                      11: ida_nalt
        114     LOAD_CONST                      3: 0
        116     LOAD_CONST                      4: None
        118     IMPORT_NAME                     12: ida_auto
        120     STORE_NAME                      12: ida_auto
        122     LOAD_CONST                      3: 0
        124     LOAD_CONST                      4: None
        126     IMPORT_NAME                     13: ida_funcs
        128     STORE_NAME                      13: ida_funcs
        130     LOAD_CONST                      3: 0
        132     LOAD_CONST                      4: None
        134     IMPORT_NAME                     14: ida_xref
        136     STORE_NAME                      14: ida_xref
        138     LOAD_CONST                      3: 0
        140     LOAD_CONST                      4: None
        142     IMPORT_NAME                     15: ida_kernwin
        144     STORE_NAME                      15: ida_kernwin
        146     LOAD_CONST                      3: 0
        148     LOAD_CONST                      4: None
        150     IMPORT_NAME                     16: ida_typeinf
        152     STORE_NAME                      16: ida_typeinf
        154     LOAD_CONST                      3: 0
        156     LOAD_CONST                      4: None
        158     IMPORT_NAME                     17: ida_segment
        160     STORE_NAME                      17: ida_segment
        162     LOAD_CONST                      3: 0
        164     LOAD_CONST                      4: None
        166     IMPORT_NAME                     18: ida_hexrays
        168     STORE_NAME                      18: ida_hexrays
        170     LOAD_CONST                      3: 0
        172     LOAD_CONST                      5: ('defaultdict',)
        174     IMPORT_NAME                     19: collections
        176     IMPORT_FROM                     20: defaultdict
        178     STORE_NAME                      20: defaultdict
        180     POP_TOP                         
        182     LOAD_CONST                      3: 0
        184     LOAD_CONST                      6: ('decompile', 'DecompilationFailure')
        186     IMPORT_NAME                     18: ida_hexrays
        188     IMPORT_FROM                     21: decompile
        190     STORE_NAME                      21: decompile
        192     IMPORT_FROM                     22: DecompilationFailure
        194     STORE_NAME                      22: DecompilationFailure
        196     POP_TOP                         
        198     LOAD_CONST                      3: 0
        200     LOAD_CONST                      7: ('DataFlowAnalyzer',)
        202     IMPORT_NAME                     23: data_flow
        204     IMPORT_FROM                     24: DataFlowAnalyzer
        206     STORE_NAME                      24: DataFlowAnalyzer
        208     POP_TOP                         
        210     LOAD_CONST                      3: 0
        212     LOAD_CONST                      8: ('settings_manager',)
        214     IMPORT_NAME                     25: config
        216     IMPORT_FROM                     26: settings_manager
        218     STORE_NAME                      26: settings_manager
        220     POP_TOP                         
        222     LOAD_CONST                      3: 0
        224     LOAD_CONST                      9: ('parse_var_pred',)
        226     IMPORT_NAME                     27: checker
        228     IMPORT_FROM                     28: parse_var_pred
        230     STORE_NAME                      28: parse_var_pred
        232     POP_TOP                         
        234     LOAD_CONST                      3: 0
        236     LOAD_CONST                      10: ('TASK_GUIDES',)
        238     IMPORT_NAME                     29: task_guides
        240     IMPORT_FROM                     30: TASK_GUIDES
        242     STORE_NAME                      30: TASK_GUIDES
        244     POP_TOP                         
        246     LOAD_NAME                       26: settings_manager
        248     LOAD_ATTR                       62: settings
        268     LOAD_CONST                      11: 'max_trace_caller_depth'
        270     BINARY_SUBSCR                   
        274     STORE_GLOBAL                    32: MAX_TRACE_CALLER_DEPTH
        276     LOAD_NAME                       26: settings_manager
        278     LOAD_ATTR                       62: settings
        298     LOAD_CONST                      12: 'max_trace_callee_depth'
        300     BINARY_SUBSCR                   
        304     STORE_GLOBAL                    33: MAX_TRACE_CALLEE_DEPTH
        306     LOAD_NAME                       26: settings_manager
        308     LOAD_ATTR                       62: settings
        328     LOAD_CONST                      13: 'max_context_func_num'
        330     BINARY_SUBSCR                   
        334     STORE_GLOBAL                    34: MAX_CONTEXT_FUNC_NUM
        336     LOAD_NAME                       26: settings_manager
        338     LOAD_ATTR                       62: settings
        358     LOAD_CONST                      14: 'measure_info_score'
        360     BINARY_SUBSCR                   
        364     STORE_GLOBAL                    35: MEASURE_INFO_SCORE
        366     PUSH_NULL                       
        368     LOAD_NAME                       36: set
        370     PUSH_NULL                       
        372     LOAD_NAME                       30: TASK_GUIDES
        374     LOAD_ATTR                       74: keys
        394     CALL                            0
        402     CALL                            1
        410     STORE_NAME                      38: SUPPORT_FUNC_TYPES
        412     LOAD_CONST                      15: '<Data-Flow>\nTips: the alias expressions below are used to present the relationship between the local variable and the variable in target function. And the left value of `==` is the local variable and type, the right value is the usage pattern of the variable in target function.\n{}\n</Data-Flow>'
        414     STORE_NAME                      39: DATA_FLOW_TEMPLATE
        416     LOAD_CONST                      16: '<context-pseudocode>\n{context}\n</context-pseudocode>\n<pseudocode>\n{target_func}\n</pseudocode>\n<Call-Chains>\n{call_chains}\n</Call-Chains>\n{data_flow}\nAnalysis Task Tag:\n{task_tag}'
        418     STORE_NAME                      40: INPUT_TEMPLATE
        420     PUSH_NULL                       
        422     LOAD_NAME                       41: dict
        424     CALL                            0
        432     STORE_NAME                      42: IMPORT_FUNCS
        434     LOAD_CONST                      17: <CODE> collect_import_funcs
        436     MAKE_FUNCTION                   0
        438     STORE_NAME                      43: collect_import_funcs
        440     PUSH_NULL                       
        442     LOAD_NAME                       43: collect_import_funcs
        444     CALL                            0
        452     POP_TOP                         
        454     LOAD_CONST                      18: <CODE> is_thunk
        456     MAKE_FUNCTION                   0
        458     STORE_NAME                      44: is_thunk
        460     LOAD_CONST                      19: <CODE> is_thunk_func
        462     MAKE_FUNCTION                   0
        464     STORE_NAME                      45: is_thunk_func
        466     LOAD_CONST                      20: <CODE> is_import_name
        468     MAKE_FUNCTION                   0
        470     STORE_NAME                      46: is_import_name
        472     LOAD_CONST                      21: <CODE> get_import_name_info
        474     MAKE_FUNCTION                   0
        476     STORE_NAME                      47: get_import_name_info
        478     LOAD_CONST                      68: (0,)
        480     LOAD_CONST                      22: <CODE> demangle
        482     MAKE_FUNCTION                   1
        484     STORE_NAME                      48: demangle
        486     LOAD_CONST                      23: 's'
        488     LOAD_NAME                       49: str
        490     BUILD_TUPLE                     2
        492     LOAD_CONST                      24: <CODE> get_pcode_md5
        494     MAKE_FUNCTION                   4
        496     STORE_NAME                      50: get_pcode_md5
        498     LOAD_CONST                      25: 'struct_tid'
        500     LOAD_NAME                       51: int
        502     BUILD_TUPLE                     2
        504     LOAD_CONST                      26: <CODE> get_struc
        506     MAKE_FUNCTION                   4
        508     STORE_NAME                      52: get_struc
        510     LOAD_CONST                      27: 'enum_tid'
        512     LOAD_NAME                       51: int
        514     BUILD_TUPLE                     2
        516     LOAD_CONST                      28: <CODE> get_enum
        518     MAKE_FUNCTION                   4
        520     STORE_NAME                      53: get_enum
        522     LOAD_CONST                      29: <CODE> list_enum_members
        524     MAKE_FUNCTION                   0
        526     STORE_NAME                      54: list_enum_members
        528     PUSH_NULL                       
        530     LOAD_BUILD_CLASS                
        532     LOAD_CONST                      30: <CODE> StructUnroller
        534     MAKE_FUNCTION                   0
        536     LOAD_CONST                      31: 'StructUnroller'
        538     CALL                            2
        546     STORE_NAME                      55: StructUnroller
        548     LOAD_CONST                      32: 'return'
        550     LOAD_NAME                       41: dict
        552     BUILD_TUPLE                     2
        554     LOAD_CONST                      33: <CODE> get_structs_enums
        556     MAKE_FUNCTION                   4
        558     STORE_NAME                      56: get_structs_enums
        560     LOAD_CONST                      34: 'inst_head_ea'
        562     LOAD_NAME                       51: int
        564     BUILD_TUPLE                     2
        566     LOAD_CONST                      35: <CODE> get_callee_name
        568     MAKE_FUNCTION                   4
        570     STORE_NAME                      57: get_callee_name
        572     LOAD_CONST                      36: <CODE> get_var_info
        574     MAKE_FUNCTION                   0
        576     STORE_NAME                      58: get_var_info
        578     LOAD_CONST                      37: <CODE> get_local_vars
        580     MAKE_FUNCTION                   0
        582     STORE_NAME                      59: get_local_vars
        584     LOAD_CONST                      38: <CODE> get_args
        586     MAKE_FUNCTION                   0
        588     STORE_NAME                      60: get_args
        590     LOAD_CONST                      39: <CODE> omit_too_long_pcode
        592     MAKE_FUNCTION                   0
        594     STORE_NAME                      61: omit_too_long_pcode
        596     LOAD_CONST                      32: 'return'
        598     LOAD_NAME                       41: dict
        600     BUILD_TUPLE                     2
        602     LOAD_CONST                      40: <CODE> build_pcode_with_struct_and_enum
        604     MAKE_FUNCTION                   4
        606     STORE_NAME                      62: build_pcode_with_struct_and_enum
        608     LOAD_CONST                      41: <CODE> measure_informative_score_strings
        610     MAKE_FUNCTION                   0
        612     STORE_NAME                      63: measure_informative_score_strings
        614     LOAD_CONST                      42: <CODE> measure_informative_score_callees
        616     MAKE_FUNCTION                   0
        618     STORE_NAME                      64: measure_informative_score_callees
        620     LOAD_CONST                      43: <CODE> _real_measure_informative_score
        622     MAKE_FUNCTION                   0
        624     STORE_NAME                      65: _real_measure_informative_score
        626     LOAD_CONST                      44: <CODE> measure_informative_score
        628     MAKE_FUNCTION                   0
        630     STORE_NAME                      66: measure_informative_score
        632     PUSH_NULL                       
        634     LOAD_BUILD_CLASS                
        636     LOAD_CONST                      45: <CODE> ContextBuilder
        638     MAKE_FUNCTION                   0
        640     LOAD_CONST                      46: 'ContextBuilder'
        642     CALL                            2
        650     STORE_NAME                      67: ContextBuilder
        652     LOAD_CONST                      47: <CODE> get_numbers_from_pcode
        654     MAKE_FUNCTION                   0
        656     STORE_NAME                      68: get_numbers_from_pcode
        658     LOAD_CONST                      48: <CODE> get_functions_in_text_like_seg
        660     MAKE_FUNCTION                   0
        662     STORE_NAME                      69: get_functions_in_text_like_seg
        664     BUILD_SET                       0
        666     LOAD_CONST                      49: frozenset({'frame_dummy', 'call_weak_fn', '__libc_csu_fini', '__libc_csu_init', 'register_tm_clones', 'deregister_tm_clones', '__do_global_ctors_aux', '__do_global_dtors_aux', '__x86.get_pc_thunk.ax', '__x86.get_pc_thunk.bp', '__x86.get_pc_thunk.bx', '__x86.get_pc_thunk.cx', '__x86.get_pc_thunk.di', '__x86.get_pc_thunk.dx', '__x86.get_pc_thunk.si'})
        668     SET_UPDATE                      1
        670     STORE_NAME                      70: MEANINGLESS_NAME_LIST
        672     LOAD_CONST                      50: <CODE> is_good_func_for_build_input
        674     MAKE_FUNCTION                   0
        676     STORE_NAME                      71: is_good_func_for_build_input
        678     LOAD_CONST                      69: ((),)
        680     LOAD_CONST                      51: <CODE> build_prompt
        682     MAKE_FUNCTION                   1
        684     STORE_NAME                      72: build_prompt
        686     LOAD_CONST                      52: <CODE> apply_prediction_ret_type
        688     MAKE_FUNCTION                   0
        690     STORE_NAME                      73: apply_prediction_ret_type
        692     LOAD_CONST                      53: <CODE> apply_prediction_func_name
        694     MAKE_FUNCTION                   0
        696     STORE_NAME                      74: apply_prediction_func_name
        698     LOAD_CONST                      54: <CODE> add_array_type
        700     MAKE_FUNCTION                   0
        702     STORE_NAME                      75: add_array_type
        704     LOAD_CONST                      55: <CODE> add_enum_type
        706     MAKE_FUNCTION                   0
        708     STORE_NAME                      76: add_enum_type
        710     LOAD_CONST                      56: <CODE> add_empty_struct_type
        712     MAKE_FUNCTION                   0
        714     STORE_NAME                      77: add_empty_struct_type
        716     LOAD_CONST                      57: <CODE> add_struct_type
        718     MAKE_FUNCTION                   0
        720     STORE_NAME                      78: add_struct_type
        722     LOAD_CONST                      58: 'arg_pred'
        724     LOAD_NAME                       79: list
        726     BUILD_TUPLE                     2
        728     LOAD_CONST                      59: <CODE> apply_prediction_arg
        730     MAKE_FUNCTION                   4
        732     STORE_NAME                      80: apply_prediction_arg
        734     LOAD_CONST                      60: <CODE> apply_prediction_args_old
        736     MAKE_FUNCTION                   0
        738     STORE_NAME                      81: apply_prediction_args_old
        740     LOAD_CONST                      61: <CODE> apply_prediction_vars
        742     MAKE_FUNCTION                   0
        744     STORE_NAME                      82: apply_prediction_vars
        746     LOAD_CONST                      62: <CODE> build_doxygen_comment
        748     MAKE_FUNCTION                   0
        750     STORE_NAME                      83: build_doxygen_comment
        752     LOAD_CONST                      63: 'comment'
        754     LOAD_NAME                       49: str
        756     BUILD_TUPLE                     2
        758     LOAD_CONST                      64: <CODE> apply_prediction_func_comment
        760     MAKE_FUNCTION                   4
        762     STORE_NAME                      84: apply_prediction_func_comment
        764     LOAD_CONST                      65: <CODE> apply_prediction_inline_comment
        766     MAKE_FUNCTION                   0
        768     STORE_NAME                      85: apply_prediction_inline_comment
        770     LOAD_CONST                      32: 'return'
        772     LOAD_NAME                       86: bool
        774     BUILD_TUPLE                     2
        776     LOAD_CONST                      66: <CODE> apply_prediction
        778     MAKE_FUNCTION                   4
        780     STORE_NAME                      87: apply_prediction
        782     LOAD_CONST                      4: None
        784     NOP                             
        786     NOP                             
        788     NOP                             
        790     JUMP_FORWARD                    19 (to 830)
        798     POP_TOP                         
        800     RETURN_CONST                    4: None
        802     PUSH_EXC_INFO                   
        804     PUSH_NULL                       
        806     LOAD_CONST                      67: '__pyarmor_exit_55131__'
        808     NOP                             
        810     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\x08\x03\x00\x00\x00\x00\x00\x00'
        812     CALL                            1
        820     POP_TOP                         
        822     RERAISE                         0
        824     COPY                            3
        826     POP_EXCEPT                      
        828     RERAISE                         1
        830     PUSH_NULL                       
        832     LOAD_CONST                      67: '__pyarmor_exit_55131__'
        834     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\x08\x03\x00\x00\x00\x00\x00\x00'
        836     BUILD_TUPLE                     1
        838     CALL_FUNCTION_EX                0
        840     POP_TOP                         
        842     RETURN_VALUE                    
