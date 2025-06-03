data_flow.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..data_flow>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 5
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        're'
        'idc'
        'json'
        'ida_hexrays'
        'ida_funcs'
        'ida_auto'
        'ida_name'
        'ida_lines'
        'ida_idaapi'
        'ida_xref'
        'idaapi'
        'idautils'
        'ida_segment'
        'collections'
        'defaultdict'
        'termcolor'
        'colored'
        'dict'
        'IMPORT_FUNCS'
        'collect_import_funcs'
        'is_thunk'
        'is_thunk_func'
        'is_import_name'
        'get_import_name_info'
        'find_var_declaration'
        'demangle'
        'get_final_x'
        'clear_cast'
        'VarUsage'
        'FunctionContext'
        'DataFlowAnalyzer'
        'ctree_visitor_t'
        'DataFlowVisitor'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54739__'
        '__pyarmor_enter_54740__'
        b'<COAddr>\x03\x00\x00\x1aP\x01\x00\x00\x00\x00\x00\x00'
        0
        None
        (
            'defaultdict'
        )
        (
            'colored'
        )
        [Code]
            File Name: <frozen ..data_flow>
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
                '__pyarmor_assert_54742__'
                '__pyarmor_enter_54743__'
                b'<COAddr>\x01\x00\x00\x1e"\x01\x00\x00\x00\x00\x00\x00'
                '[!] Err: fail to get import module '
                ' name'
                [Code]
                    File Name: <frozen ..data_flow>
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
                        '__pyarmor_assert_54745__'
                        '__pyarmor_enter_54746__'
                        b'<COAddr>\x03\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54747__'
                        True
                    [Disassembly]
                        0       COPY_FREE_VARS                  2
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54746__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
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
                        100     LOAD_CONST                      4: '__pyarmor_exit_54747__'
                        102     NOP                             
                        104     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
                        106     CALL                            1
                        114     POP_TOP                         
                        116     RERAISE                         0
                        118     COPY                            3
                        120     POP_EXCEPT                      
                        122     RERAISE                         1
                        124     PUSH_NULL                       
                        126     LOAD_CONST                      4: '__pyarmor_exit_54747__'
                        128     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cD\x00\x00\x00\x00\x00\x00\x00'
                        130     BUILD_TUPLE                     1
                        132     CALL_FUNCTION_EX                0
                        134     POP_TOP                         
                        136     RETURN_VALUE                    
                '__pyarmor_exit_54744__'
                True
            [Disassembly]
                0       MAKE_CELL                       4: _var_var_0
                2       MAKE_CELL                       5: _var_var_1
                4       NOP                             
                6       NOP                             
                8       PUSH_NULL                       
                10      LOAD_CONST                      2: '__pyarmor_enter_54743__'
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
                324     LOAD_CONST                      7: '__pyarmor_exit_54744__'
                326     NOP                             
                328     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e"\x01\x00\x00\x00\x00\x00\x00'
                330     CALL                            1
                338     POP_TOP                         
                340     RERAISE                         0
                342     COPY                            3
                344     POP_EXCEPT                      
                346     RERAISE                         1
                348     PUSH_NULL                       
                350     LOAD_CONST                      7: '__pyarmor_exit_54744__'
                352     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e"\x01\x00\x00\x00\x00\x00\x00'
                354     BUILD_TUPLE                     1
                356     CALL_FUNCTION_EX                0
                358     POP_TOP                         
                360     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
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
                '__pyarmor_assert_54748__'
                '__pyarmor_enter_54749__'
                b'<COAddr>\x03\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_54750__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54749__'
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
                150     LOAD_CONST                      5: '__pyarmor_exit_54750__'
                152     NOP                             
                154     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                156     CALL                            1
                164     POP_TOP                         
                166     RERAISE                         0
                168     COPY                            3
                170     POP_EXCEPT                      
                172     RERAISE                         1
                174     PUSH_NULL                       
                176     LOAD_CONST                      5: '__pyarmor_exit_54750__'
                178     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x00\x00\x00\x00\x00\x00\x00'
                180     BUILD_TUPLE                     1
                182     CALL_FUNCTION_EX                0
                184     POP_TOP                         
                186     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
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
                '__pyarmor_assert_54751__'
                '__pyarmor_enter_54752__'
                b'<COAddr>\x03\x00\x00\x1av\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_54753__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54752__'
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
                148     LOAD_CONST                      5: '__pyarmor_exit_54753__'
                150     NOP                             
                152     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1av\x00\x00\x00\x00\x00\x00\x00'
                154     CALL                            1
                162     POP_TOP                         
                164     RERAISE                         0
                166     COPY                            3
                168     POP_EXCEPT                      
                170     RERAISE                         1
                172     PUSH_NULL                       
                174     LOAD_CONST                      5: '__pyarmor_exit_54753__'
                176     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1av\x00\x00\x00\x00\x00\x00\x00'
                178     BUILD_TUPLE                     1
                180     CALL_FUNCTION_EX                0
                182     POP_TOP                         
                184     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
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
                '__pyarmor_assert_54754__'
                '__pyarmor_enter_54755__'
                b'<COAddr>\x01\x00\x00\x1a\xb0\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_54756__'
                True
                False
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54755__'
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
                206     LOAD_CONST                      5: '__pyarmor_exit_54756__'
                208     NOP                             
                210     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb0\x00\x00\x00\x00\x00\x00\x00'
                212     CALL                            1
                220     POP_TOP                         
                222     RERAISE                         0
                224     COPY                            3
                226     POP_EXCEPT                      
                228     RERAISE                         1
                230     PUSH_NULL                       
                232     LOAD_CONST                      5: '__pyarmor_exit_54756__'
                234     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb0\x00\x00\x00\x00\x00\x00\x00'
                236     BUILD_TUPLE                     1
                238     CALL_FUNCTION_EX                0
                240     POP_TOP                         
                242     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
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
                '__pyarmor_assert_54757__'
                '__pyarmor_enter_54758__'
                b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                0
                '__pyarmor_exit_54759__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54758__'
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
                220     LOAD_CONST                      5: '__pyarmor_exit_54759__'
                222     NOP                             
                224     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                226     CALL                            1
                234     POP_TOP                         
                236     RERAISE                         0
                238     COPY                            3
                240     POP_EXCEPT                      
                242     RERAISE                         1
                244     PUSH_NULL                       
                246     LOAD_CONST                      5: '__pyarmor_exit_54759__'
                248     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                250     BUILD_TUPLE                     1
                252     CALL_FUNCTION_EX                0
                254     POP_TOP                         
                256     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: find_var_declaration
            Qualified Name: find_var_declaration
            Arg Count: 4
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                're'
                'escape'
                'enumerate'
                'get_pseudocode'
                'ida_lines'
                'tag_remove'
                'line'
                'strip'
                'search'
                'DOTALL'
            [Locals+Names]
                'cfunc'
                'type_name'
                'var_name'
                'is_arg'
                '__assert_armored__'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
                '_var_var_11'
            [Constants]
                None
                '__pyarmor_assert_54760__'
                '__pyarmor_enter_54761__'
                b'<COAddr>\x03\x00\x00\x1a\xf4\x01\x00\x00\x00\x00\x00\x00'
                '.*'
                '\\s*'
                '[\\[\\]0-9xA-Fa-f]*;.*'
                '__pyarmor_exit_54762__'
                (
                    '??'
                    'VARIABLE DECLARATION STATEMENT'
                )
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54761__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf4\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       3: is_arg
                30      POP_JUMP_IF_FALSE               53 (to 138)
                32      LOAD_CONST                      4: '.*'
                34      LOAD_GLOBAL                     1: NULL + re
                44      LOAD_ATTR                       2: escape
                64      LOAD_FAST                       1: type_name
                66      CALL                            1
                74      BINARY_OP                       0 (+)
                78      LOAD_CONST                      5: '\\s*'
                80      BINARY_OP                       0 (+)
                84      LOAD_GLOBAL                     1: NULL + re
                94      LOAD_ATTR                       2: escape
                114     LOAD_FAST                       2: var_name
                116     CALL                            1
                124     BINARY_OP                       0 (+)
                128     LOAD_CONST                      4: '.*'
                130     BINARY_OP                       0 (+)
                134     STORE_FAST                      5: _var_var_7
                136     JUMP_FORWARD                    52 (to 242)
                138     LOAD_CONST                      5: '\\s*'
                140     LOAD_GLOBAL                     1: NULL + re
                150     LOAD_ATTR                       2: escape
                170     LOAD_FAST                       1: type_name
                172     CALL                            1
                180     BINARY_OP                       0 (+)
                184     LOAD_CONST                      5: '\\s*'
                186     BINARY_OP                       0 (+)
                190     LOAD_GLOBAL                     1: NULL + re
                200     LOAD_ATTR                       2: escape
                220     LOAD_FAST                       2: var_name
                222     CALL                            1
                230     BINARY_OP                       0 (+)
                234     LOAD_CONST                      6: '[\\[\\]0-9xA-Fa-f]*;.*'
                236     BINARY_OP                       0 (+)
                240     STORE_FAST                      5: _var_var_7
                242     LOAD_GLOBAL                     5: NULL + enumerate
                252     LOAD_FAST                       0: cfunc
                254     LOAD_ATTR                       7: get_pseudocode
                274     CALL                            0
                282     CALL                            1
                290     GET_ITER                        
                292     FOR_ITER                        104 (to 502)
                296     UNPACK_SEQUENCE                 2
                300     STORE_FAST                      6: _var_var_8
                302     STORE_FAST                      7: _var_var_9
                304     LOAD_GLOBAL                     9: NULL + ida_lines
                314     LOAD_ATTR                       10: tag_remove
                334     LOAD_FAST                       7: _var_var_9
                336     LOAD_ATTR                       12: line
                356     LOAD_ATTR                       15: strip
                376     CALL                            0
                384     CALL                            1
                392     STORE_FAST                      8: _var_var_10
                394     LOAD_GLOBAL                     1: NULL + re
                404     LOAD_ATTR                       16: search
                424     LOAD_FAST                       5: _var_var_7
                426     LOAD_FAST                       8: _var_var_10
                428     LOAD_GLOBAL                     0: re
                438     LOAD_ATTR                       18: DOTALL
                458     CALL                            3
                466     STORE_FAST                      9: _var_var_11
                468     LOAD_FAST                       9: _var_var_11
                470     POP_JUMP_IF_TRUE                1 (to 474)
                472     JUMP_BACKWARD                   91 (to 292)
                474     LOAD_FAST                       6: _var_var_8
                476     LOAD_FAST                       8: _var_var_10
                478     BUILD_TUPLE                     2
                480     SWAP                            2
                482     POP_TOP                         
                484     NOP                             
                486     NOP                             
                488     NOP                             
                490     JUMP_FORWARD                    31 (to 554)
                492     CALL                            1
                500     POP_TOP                         
                502     RETURN_VALUE                    
                504     END_FOR                         
                506     LOAD_CONST                      8: ('??', 'VARIABLE DECLARATION STATEMENT')
                508     NOP                             
                510     NOP                             
                512     NOP                             
                514     JUMP_FORWARD                    19 (to 554)
                522     POP_TOP                         
                524     RETURN_CONST                    8: ('??', 'VARIABLE DECLARATION STATEMENT')
                526     PUSH_EXC_INFO                   
                528     PUSH_NULL                       
                530     LOAD_CONST                      7: '__pyarmor_exit_54762__'
                532     NOP                             
                534     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf4\x01\x00\x00\x00\x00\x00\x00'
                536     CALL                            1
                544     POP_TOP                         
                546     RERAISE                         0
                548     COPY                            3
                550     POP_EXCEPT                      
                552     RERAISE                         1
                554     PUSH_NULL                       
                556     LOAD_CONST                      7: '__pyarmor_exit_54762__'
                558     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf4\x01\x00\x00\x00\x00\x00\x00'
                560     BUILD_TUPLE                     1
                562     CALL_FUNCTION_EX                0
                564     POP_TOP                         
                566     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: demangle
            Qualified Name: demangle
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_name'
                'demangle_name'
                'DQT_FULL'
            [Locals+Names]
                'name'
                'disable_mask'
                '__assert_armored__'
                '_var_var_12'
            [Constants]
                None
                '__pyarmor_assert_54763__'
                '__pyarmor_enter_54764__'
                b'<COAddr>\x03\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54765__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54764__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + ida_name
                38      LOAD_ATTR                       2: demangle_name
                58      LOAD_FAST                       0: name
                60      LOAD_FAST                       1: disable_mask
                62      LOAD_GLOBAL                     0: ida_name
                72      LOAD_ATTR                       4: DQT_FULL
                92      CALL                            3
                100     STORE_FAST                      3: _var_var_12
                102     LOAD_FAST                       3: _var_var_12
                104     POP_JUMP_IF_FALSE               11 (to 128)
                106     LOAD_FAST                       3: _var_var_12
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
                154     LOAD_CONST                      4: '__pyarmor_exit_54765__'
                156     NOP                             
                158     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                160     CALL                            1
                168     POP_TOP                         
                170     RERAISE                         0
                172     COPY                            3
                174     POP_EXCEPT                      
                176     RERAISE                         1
                178     PUSH_NULL                       
                180     LOAD_CONST                      4: '__pyarmor_exit_54765__'
                182     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a|\x00\x00\x00\x00\x00\x00\x00'
                184     BUILD_TUPLE                     1
                186     CALL_FUNCTION_EX                0
                188     POP_TOP                         
                190     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: get_final_x
            Qualified Name: get_final_x
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'x'
                'get_final_x'
            [Locals+Names]
                'cexpr'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_54766__'
                '__pyarmor_enter_54767__'
                b'<COAddr>\x03\x00\x00\x1al\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54768__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54767__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1al\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: cexpr
                30      LOAD_ATTR                       0: x
                50      POP_JUMP_IF_FALSE               30 (to 112)
                52      LOAD_GLOBAL                     3: NULL + get_final_x
                62      LOAD_FAST                       0: cexpr
                64      LOAD_ATTR                       0: x
                84      CALL                            1
                92      NOP                             
                94      NOP                             
                96      NOP                             
                98      JUMP_FORWARD                    31 (to 162)
                100     CALL                            1
                108     POP_TOP                         
                110     RETURN_VALUE                    
                112     LOAD_FAST                       0: cexpr
                114     NOP                             
                116     NOP                             
                118     NOP                             
                120     JUMP_FORWARD                    20 (to 162)
                122     CALL                            1
                130     POP_TOP                         
                132     RETURN_VALUE                    
                134     PUSH_EXC_INFO                   
                136     PUSH_NULL                       
                138     LOAD_CONST                      4: '__pyarmor_exit_54768__'
                140     NOP                             
                142     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1al\x00\x00\x00\x00\x00\x00\x00'
                144     CALL                            1
                152     POP_TOP                         
                154     RERAISE                         0
                156     COPY                            3
                158     POP_EXCEPT                      
                160     RERAISE                         1
                162     PUSH_NULL                       
                164     LOAD_CONST                      4: '__pyarmor_exit_54768__'
                166     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1al\x00\x00\x00\x00\x00\x00\x00'
                168     BUILD_TUPLE                     1
                170     CALL_FUNCTION_EX                0
                172     POP_TOP                         
                174     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: clear_cast
            Qualified Name: clear_cast
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'op'
                'ida_hexrays'
                'cot_cast'
                'cot_ref'
                'cot_ptr'
                'clear_cast'
                'x'
            [Locals+Names]
                'cexpr'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_54769__'
                '__pyarmor_enter_54770__'
                b'<COAddr>\x01\x00\x00\x1a\xca\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54771__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54770__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xca\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: cexpr
                30      LOAD_ATTR                       0: op
                50      LOAD_GLOBAL                     2: ida_hexrays
                60      LOAD_ATTR                       4: cot_cast
                80      LOAD_GLOBAL                     2: ida_hexrays
                90      LOAD_ATTR                       6: cot_ref
                110     LOAD_GLOBAL                     2: ida_hexrays
                120     LOAD_ATTR                       8: cot_ptr
                140     BUILD_TUPLE                     3
                142     CONTAINS_OP                     0 (in)
                144     POP_JUMP_IF_FALSE               30 (to 206)
                146     LOAD_GLOBAL                     11: NULL + clear_cast
                156     LOAD_FAST                       0: cexpr
                158     LOAD_ATTR                       12: x
                178     CALL                            1
                186     NOP                             
                188     NOP                             
                190     NOP                             
                192     JUMP_FORWARD                    31 (to 256)
                194     CALL                            1
                202     POP_TOP                         
                204     RETURN_VALUE                    
                206     LOAD_FAST                       0: cexpr
                208     NOP                             
                210     NOP                             
                212     NOP                             
                214     JUMP_FORWARD                    20 (to 256)
                216     CALL                            1
                224     POP_TOP                         
                226     RETURN_VALUE                    
                228     PUSH_EXC_INFO                   
                230     PUSH_NULL                       
                232     LOAD_CONST                      4: '__pyarmor_exit_54771__'
                234     NOP                             
                236     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xca\x00\x00\x00\x00\x00\x00\x00'
                238     CALL                            1
                246     POP_TOP                         
                248     RERAISE                         0
                250     COPY                            3
                252     POP_EXCEPT                      
                254     RERAISE                         1
                256     PUSH_NULL                       
                258     LOAD_CONST                      4: '__pyarmor_exit_54771__'
                260     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xca\x00\x00\x00\x00\x00\x00\x00'
                262     BUILD_TUPLE                     1
                264     CALL_FUNCTION_EX                0
                266     POP_TOP                         
                268     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: VarUsage
            Qualified Name: VarUsage
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
                '__str__'
                'colored_print'
            [Locals+Names]
            [Constants]
                'VarUsage'
                '__pyarmor_assert_54772__'
                '__pyarmor_enter_54773__'
                b'<COAddr>\x01\x00\x00".\x00\x00\x00\x00\x00\x00\x00'
                None
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: __init__
                    Qualified Name: VarUsage.__init__
                    Arg Count: 13
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'var_name'
                        'var_type'
                        'ori_var_name'
                        'ori_var_type'
                        'alias_name'
                        'pcode_line'
                        'access_type'
                        'usage_type'
                        'offset'
                        'line_addr'
                        'func_name'
                        'context_depth'
                    [Locals+Names]
                        'self'
                        'var_name'
                        'var_type'
                        'pcode_line'
                        'ori_var_name'
                        'ori_var_type'
                        'alias_name'
                        'usage_type'
                        'access_type'
                        'offset'
                        'line_addr'
                        'func_name'
                        'context_depth'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54775__'
                        '__pyarmor_enter_54776__'
                        b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54777__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54776__'
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
                        28      LOAD_FAST                       1: var_name
                        30      LOAD_FAST                       0: self
                        32      STORE_ATTR                      0: var_name
                        42      LOAD_FAST                       2: var_type
                        44      LOAD_FAST                       0: self
                        46      STORE_ATTR                      1: var_type
                        56      LOAD_FAST                       4: ori_var_name
                        58      LOAD_FAST                       0: self
                        60      STORE_ATTR                      2: ori_var_name
                        70      LOAD_FAST                       5: ori_var_type
                        72      LOAD_FAST                       0: self
                        74      STORE_ATTR                      3: ori_var_type
                        84      LOAD_FAST                       6: alias_name
                        86      LOAD_FAST                       0: self
                        88      STORE_ATTR                      4: alias_name
                        98      LOAD_FAST                       3: pcode_line
                        100     LOAD_FAST                       0: self
                        102     STORE_ATTR                      5: pcode_line
                        112     LOAD_FAST                       8: access_type
                        114     LOAD_FAST                       0: self
                        116     STORE_ATTR                      6: access_type
                        126     LOAD_FAST                       7: usage_type
                        128     LOAD_FAST                       0: self
                        130     STORE_ATTR                      7: usage_type
                        140     LOAD_FAST                       9: offset
                        142     LOAD_FAST                       0: self
                        144     STORE_ATTR                      8: offset
                        154     LOAD_FAST                       10: line_addr
                        156     LOAD_FAST                       0: self
                        158     STORE_ATTR                      9: line_addr
                        168     LOAD_FAST                       11: func_name
                        170     LOAD_FAST                       0: self
                        172     STORE_ATTR                      10: func_name
                        182     LOAD_FAST                       12: context_depth
                        184     LOAD_FAST                       0: self
                        186     STORE_ATTR                      11: context_depth
                        196     LOAD_CONST                      0: None
                        198     NOP                             
                        200     NOP                             
                        202     NOP                             
                        204     JUMP_FORWARD                    19 (to 244)
                        212     POP_TOP                         
                        214     RETURN_CONST                    0: None
                        216     PUSH_EXC_INFO                   
                        218     PUSH_NULL                       
                        220     LOAD_CONST                      4: '__pyarmor_exit_54777__'
                        222     NOP                             
                        224     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                        226     CALL                            1
                        234     POP_TOP                         
                        236     RERAISE                         0
                        238     COPY                            3
                        240     POP_EXCEPT                      
                        242     RERAISE                         1
                        244     PUSH_NULL                       
                        246     LOAD_CONST                      4: '__pyarmor_exit_54777__'
                        248     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xbe\x00\x00\x00\x00\x00\x00\x00'
                        250     BUILD_TUPLE                     1
                        252     CALL_FUNCTION_EX                0
                        254     POP_TOP                         
                        256     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: __str__
                    Qualified Name: VarUsage.__str__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 8
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'pcode_line'
                        'strip'
                        'var_type'
                        'var_name'
                        'alias_name'
                        'abs'
                        'context_depth'
                        'func_name'
                        'line_addr'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_13'
                        '_var_var_14'
                    [Constants]
                        None
                        '__pyarmor_assert_54778__'
                        '__pyarmor_enter_54779__'
                        b'<COAddr>\x03\x00\x00\x1a,\x01\x00\x00\x00\x00\x00\x00'
                        'Get pseudocode line error'
                        '// alias: '
                        ' '
                        ' == '
                        '\t'
                        '@L'
                        '||'
                        '__pyarmor_exit_54780__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54779__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a,\x01\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: pcode_line
                        50      POP_JUMP_IF_FALSE               27 (to 106)
                        52      LOAD_FAST                       0: self
                        54      LOAD_ATTR                       0: pcode_line
                        74      LOAD_ATTR                       3: strip
                        94      CALL                            0
                        102     STORE_FAST                      2: _var_var_13
                        104     JUMP_FORWARD                    2 (to 110)
                        106     LOAD_CONST                      4: 'Get pseudocode line error'
                        108     STORE_FAST                      2: _var_var_13
                        110     LOAD_CONST                      5: '// alias: '
                        112     LOAD_FAST                       0: self
                        114     LOAD_ATTR                       4: var_type
                        134     FORMAT_VALUE                    0 (FVC_NONE)
                        136     LOAD_CONST                      6: ' '
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       6: var_name
                        160     FORMAT_VALUE                    0 (FVC_NONE)
                        162     LOAD_CONST                      7: ' == '
                        164     LOAD_FAST                       0: self
                        166     LOAD_ATTR                       8: alias_name
                        186     FORMAT_VALUE                    0 (FVC_NONE)
                        188     BUILD_STRING                    6
                        190     STORE_FAST                      3: _var_var_14
                        192     LOAD_CONST                      8: '\t'
                        194     LOAD_GLOBAL                     11: NULL + abs
                        204     LOAD_FAST                       0: self
                        206     LOAD_ATTR                       12: context_depth
                        226     CALL                            1
                        234     BINARY_OP                       5 (*)
                        238     LOAD_FAST                       0: self
                        240     LOAD_ATTR                       14: func_name
                        260     FORMAT_VALUE                    0 (FVC_NONE)
                        262     LOAD_CONST                      9: '@L'
                        264     LOAD_FAST                       0: self
                        266     LOAD_ATTR                       16: line_addr
                        286     FORMAT_VALUE                    0 (FVC_NONE)
                        288     LOAD_CONST                      10: '||'
                        290     LOAD_FAST                       2: _var_var_13
                        292     FORMAT_VALUE                    0 (FVC_NONE)
                        294     LOAD_CONST                      6: ' '
                        296     LOAD_FAST                       3: _var_var_14
                        298     FORMAT_VALUE                    0 (FVC_NONE)
                        300     BUILD_STRING                    7
                        302     BINARY_OP                       0 (+)
                        306     NOP                             
                        308     NOP                             
                        310     NOP                             
                        312     JUMP_FORWARD                    20 (to 354)
                        314     CALL                            1
                        322     POP_TOP                         
                        324     RETURN_VALUE                    
                        326     PUSH_EXC_INFO                   
                        328     PUSH_NULL                       
                        330     LOAD_CONST                      11: '__pyarmor_exit_54780__'
                        332     NOP                             
                        334     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a,\x01\x00\x00\x00\x00\x00\x00'
                        336     CALL                            1
                        344     POP_TOP                         
                        346     RERAISE                         0
                        348     COPY                            3
                        350     POP_EXCEPT                      
                        352     RERAISE                         1
                        354     PUSH_NULL                       
                        356     LOAD_CONST                      11: '__pyarmor_exit_54780__'
                        358     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a,\x01\x00\x00\x00\x00\x00\x00'
                        360     BUILD_TUPLE                     1
                        362     CALL_FUNCTION_EX                0
                        364     POP_TOP                         
                        366     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: colored_print
                    Qualified Name: VarUsage.colored_print
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 11
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'pcode_line'
                        'colored'
                        'strip'
                        'var_type'
                        'var_name'
                        'alias_name'
                        'abs'
                        'context_depth'
                        'func_name'
                        'line_addr'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_13'
                        '_var_var_14'
                    [Constants]
                        None
                        '__pyarmor_assert_54781__'
                        '__pyarmor_enter_54782__'
                        b'<COAddr>\x01\x00\x00\x1a\xb4\x01\x00\x00\x00\x00\x00\x00'
                        'VARIABLE DECLARATION STATEMENT'
                        'red'
                        'Get pseudocode line error'
                        '// alias: '
                        ' '
                        ' == '
                        '\t'
                        'blue'
                        '@L'
                        '||'
                        'green'
                        '__pyarmor_exit_54783__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54782__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x01\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: pcode_line
                        50      LOAD_CONST                      4: 'VARIABLE DECLARATION STATEMENT'
                        52      COMPARE_OP                      40 (==)
                        56      POP_JUMP_IF_FALSE               13 (to 84)
                        58      LOAD_GLOBAL                     3: NULL + colored
                        68      LOAD_CONST                      4: 'VARIABLE DECLARATION STATEMENT'
                        70      LOAD_CONST                      5: 'red'
                        72      CALL                            2
                        80      STORE_FAST                      2: _var_var_13
                        82      JUMP_FORWARD                    51 (to 186)
                        84      LOAD_FAST                       0: self
                        86      LOAD_ATTR                       0: pcode_line
                        106     POP_JUMP_IF_FALSE               27 (to 162)
                        108     LOAD_FAST                       0: self
                        110     LOAD_ATTR                       0: pcode_line
                        130     LOAD_ATTR                       5: strip
                        150     CALL                            0
                        158     STORE_FAST                      2: _var_var_13
                        160     JUMP_FORWARD                    12 (to 186)
                        162     LOAD_GLOBAL                     3: NULL + colored
                        172     LOAD_CONST                      6: 'Get pseudocode line error'
                        174     LOAD_CONST                      5: 'red'
                        176     CALL                            2
                        184     STORE_FAST                      2: _var_var_13
                        186     LOAD_CONST                      7: '// alias: '
                        188     LOAD_FAST                       0: self
                        190     LOAD_ATTR                       6: var_type
                        210     FORMAT_VALUE                    0 (FVC_NONE)
                        212     LOAD_CONST                      8: ' '
                        214     LOAD_FAST                       0: self
                        216     LOAD_ATTR                       8: var_name
                        236     FORMAT_VALUE                    0 (FVC_NONE)
                        238     LOAD_CONST                      9: ' == '
                        240     LOAD_FAST                       0: self
                        242     LOAD_ATTR                       10: alias_name
                        262     FORMAT_VALUE                    0 (FVC_NONE)
                        264     BUILD_STRING                    6
                        266     STORE_FAST                      3: _var_var_14
                        268     LOAD_CONST                      10: '\t'
                        270     LOAD_GLOBAL                     13: NULL + abs
                        280     LOAD_FAST                       0: self
                        282     LOAD_ATTR                       14: context_depth
                        302     CALL                            1
                        310     BINARY_OP                       5 (*)
                        314     LOAD_GLOBAL                     3: NULL + colored
                        324     LOAD_FAST                       0: self
                        326     LOAD_ATTR                       16: func_name
                        346     LOAD_CONST                      11: 'blue'
                        348     CALL                            2
                        356     FORMAT_VALUE                    0 (FVC_NONE)
                        358     LOAD_CONST                      12: '@L'
                        360     LOAD_GLOBAL                     3: NULL + colored
                        370     LOAD_FAST                       0: self
                        372     LOAD_ATTR                       18: line_addr
                        392     LOAD_CONST                      11: 'blue'
                        394     CALL                            2
                        402     FORMAT_VALUE                    0 (FVC_NONE)
                        404     LOAD_CONST                      13: '||'
                        406     LOAD_FAST                       2: _var_var_13
                        408     FORMAT_VALUE                    0 (FVC_NONE)
                        410     LOAD_CONST                      8: ' '
                        412     LOAD_GLOBAL                     3: NULL + colored
                        422     LOAD_FAST                       3: _var_var_14
                        424     LOAD_CONST                      14: 'green'
                        426     CALL                            2
                        434     FORMAT_VALUE                    0 (FVC_NONE)
                        436     BUILD_STRING                    7
                        438     BINARY_OP                       0 (+)
                        442     NOP                             
                        444     NOP                             
                        446     NOP                             
                        448     JUMP_FORWARD                    20 (to 490)
                        450     CALL                            1
                        458     POP_TOP                         
                        460     RETURN_VALUE                    
                        462     PUSH_EXC_INFO                   
                        464     PUSH_NULL                       
                        466     LOAD_CONST                      15: '__pyarmor_exit_54783__'
                        468     NOP                             
                        470     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x01\x00\x00\x00\x00\x00\x00'
                        472     CALL                            1
                        480     POP_TOP                         
                        482     RERAISE                         0
                        484     COPY                            3
                        486     POP_EXCEPT                      
                        488     RERAISE                         1
                        490     PUSH_NULL                       
                        492     LOAD_CONST                      15: '__pyarmor_exit_54783__'
                        494     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb4\x01\x00\x00\x00\x00\x00\x00'
                        496     BUILD_TUPLE                     1
                        498     CALL_FUNCTION_EX                0
                        500     POP_TOP                         
                        502     RETURN_VALUE                    
                '__pyarmor_exit_54774__'
                (
                    None
                    None
                    None
                    None
                    None
                    None
                    None
                    None
                    0
                )
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'VarUsage'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_54773__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00".\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      NOP                             
                40      LOAD_CONST                      9: (None, None, None, None, None, None, None, None, 0)
                42      LOAD_CONST                      5: <CODE> __init__
                44      MAKE_FUNCTION                   1
                46      STORE_NAME                      4: __init__
                48      LOAD_CONST                      6: <CODE> __str__
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      5: __str__
                54      LOAD_CONST                      7: <CODE> colored_print
                56      MAKE_FUNCTION                   0
                58      STORE_NAME                      6: colored_print
                60      LOAD_CONST                      4: None
                62      NOP                             
                64      NOP                             
                66      NOP                             
                68      JUMP_FORWARD                    19 (to 108)
                76      POP_TOP                         
                78      RETURN_CONST                    4: None
                80      PUSH_EXC_INFO                   
                82      PUSH_NULL                       
                84      LOAD_CONST                      8: '__pyarmor_exit_54774__'
                86      NOP                             
                88      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00".\x00\x00\x00\x00\x00\x00\x00'
                90      CALL                            1
                98      POP_TOP                         
                100     RERAISE                         0
                102     COPY                            3
                104     POP_EXCEPT                      
                106     RERAISE                         1
                108     PUSH_NULL                       
                110     LOAD_CONST                      8: '__pyarmor_exit_54774__'
                112     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00".\x00\x00\x00\x00\x00\x00\x00'
                114     BUILD_TUPLE                     1
                116     CALL_FUNCTION_EX                0
                118     POP_TOP                         
                120     RETURN_VALUE                    
        'VarUsage'
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: FunctionContext
            Qualified Name: FunctionContext
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
                '__str__'
            [Locals+Names]
            [Constants]
                'FunctionContext'
                '__pyarmor_assert_54784__'
                '__pyarmor_enter_54785__'
                b'<COAddr>\x01\x00\x00"$\x00\x00\x00\x00\x00\x00\x00'
                None
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: __init__
                    Qualified Name: FunctionContext.__init__
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'func_ea'
                        'caller_ea'
                        'dict'
                        'var_mappings'
                        'depth'
                    [Locals+Names]
                        'self'
                        'func_ea'
                        'caller_ea'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54787__'
                        '__pyarmor_enter_54788__'
                        b'<COAddr>\x03\x00\x00\x1a^\x00\x00\x00\x00\x00\x00\x00'
                        0
                        '__pyarmor_exit_54789__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54788__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a^\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: func_ea
                        30      LOAD_FAST                       0: self
                        32      STORE_ATTR                      0: func_ea
                        42      LOAD_FAST                       2: caller_ea
                        44      LOAD_FAST                       0: self
                        46      STORE_ATTR                      1: caller_ea
                        56      LOAD_GLOBAL                     5: NULL + dict
                        66      CALL                            0
                        74      LOAD_FAST                       0: self
                        76      STORE_ATTR                      3: var_mappings
                        86      LOAD_CONST                      4: 0
                        88      LOAD_FAST                       0: self
                        90      STORE_ATTR                      4: depth
                        100     LOAD_CONST                      0: None
                        102     NOP                             
                        104     NOP                             
                        106     NOP                             
                        108     JUMP_FORWARD                    19 (to 148)
                        116     POP_TOP                         
                        118     RETURN_CONST                    0: None
                        120     PUSH_EXC_INFO                   
                        122     PUSH_NULL                       
                        124     LOAD_CONST                      5: '__pyarmor_exit_54789__'
                        126     NOP                             
                        128     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a^\x00\x00\x00\x00\x00\x00\x00'
                        130     CALL                            1
                        138     POP_TOP                         
                        140     RERAISE                         0
                        142     COPY                            3
                        144     POP_EXCEPT                      
                        146     RERAISE                         1
                        148     PUSH_NULL                       
                        150     LOAD_CONST                      5: '__pyarmor_exit_54789__'
                        152     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a^\x00\x00\x00\x00\x00\x00\x00'
                        154     BUILD_TUPLE                     1
                        156     CALL_FUNCTION_EX                0
                        158     POP_TOP                         
                        160     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: __str__
                    Qualified Name: FunctionContext.__str__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'hex'
                        'func_ea'
                        'caller_ea'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54790__'
                        '__pyarmor_enter_54791__'
                        b'<COAddr>\x03\x00\x00\x1a\x8c\x00\x00\x00\x00\x00\x00\x00'
                        'Function at '
                        ' called from '
                        'None'
                        '__pyarmor_exit_54792__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54791__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8c\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_CONST                      4: 'Function at '
                        30      LOAD_GLOBAL                     1: NULL + hex
                        40      LOAD_FAST                       0: self
                        42      LOAD_ATTR                       2: func_ea
                        62      CALL                            1
                        70      FORMAT_VALUE                    0 (FVC_NONE)
                        72      LOAD_CONST                      5: ' called from '
                        74      LOAD_FAST                       0: self
                        76      LOAD_ATTR                       4: caller_ea
                        96      POP_JUMP_IF_FALSE               21 (to 140)
                        98      LOAD_GLOBAL                     1: NULL + hex
                        108     LOAD_FAST                       0: self
                        110     LOAD_ATTR                       4: caller_ea
                        130     CALL                            1
                        138     JUMP_FORWARD                    1 (to 142)
                        140     LOAD_CONST                      6: 'None'
                        142     FORMAT_VALUE                    0 (FVC_NONE)
                        144     BUILD_STRING                    4
                        146     NOP                             
                        148     NOP                             
                        150     NOP                             
                        152     JUMP_FORWARD                    20 (to 194)
                        154     CALL                            1
                        162     POP_TOP                         
                        164     RETURN_VALUE                    
                        166     PUSH_EXC_INFO                   
                        168     PUSH_NULL                       
                        170     LOAD_CONST                      7: '__pyarmor_exit_54792__'
                        172     NOP                             
                        174     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8c\x00\x00\x00\x00\x00\x00\x00'
                        176     CALL                            1
                        184     POP_TOP                         
                        186     RERAISE                         0
                        188     COPY                            3
                        190     POP_EXCEPT                      
                        192     RERAISE                         1
                        194     PUSH_NULL                       
                        196     LOAD_CONST                      7: '__pyarmor_exit_54792__'
                        198     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8c\x00\x00\x00\x00\x00\x00\x00'
                        200     BUILD_TUPLE                     1
                        202     CALL_FUNCTION_EX                0
                        204     POP_TOP                         
                        206     RETURN_VALUE                    
                '__pyarmor_exit_54786__'
                (
                    None
                )
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'FunctionContext'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_54785__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"$\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      8: (None,)
                38      LOAD_CONST                      5: <CODE> __init__
                40      MAKE_FUNCTION                   1
                42      STORE_NAME                      4: __init__
                44      LOAD_CONST                      6: <CODE> __str__
                46      MAKE_FUNCTION                   0
                48      STORE_NAME                      5: __str__
                50      LOAD_CONST                      4: None
                52      NOP                             
                54      NOP                             
                56      NOP                             
                58      JUMP_FORWARD                    19 (to 98)
                66      POP_TOP                         
                68      RETURN_CONST                    4: None
                70      PUSH_EXC_INFO                   
                72      PUSH_NULL                       
                74      LOAD_CONST                      7: '__pyarmor_exit_54786__'
                76      NOP                             
                78      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"$\x00\x00\x00\x00\x00\x00\x00'
                80      CALL                            1
                88      POP_TOP                         
                90      RERAISE                         0
                92      COPY                            3
                94      POP_EXCEPT                      
                96      RERAISE                         1
                98      PUSH_NULL                       
                100     LOAD_CONST                      7: '__pyarmor_exit_54786__'
                102     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"$\x00\x00\x00\x00\x00\x00\x00'
                104     BUILD_TUPLE                     1
                106     CALL_FUNCTION_EX                0
                108     POP_TOP                         
                110     RETURN_VALUE                    
        'FunctionContext'
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: DataFlowAnalyzer
            Qualified Name: DataFlowAnalyzer
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
                'set'
                '__init__'
                '_get_func_args'
                '_get_pcode_line'
                'analyze_function_dataflow_forward'
                'analyze_function_dataflow_backward'
                'get_var_dataflow'
                'filter_data_flow_by_context_func'
            [Locals+Names]
            [Constants]
                'DataFlowAnalyzer'
                '__pyarmor_assert_54793__'
                '__pyarmor_enter_54794__'
                b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: __init__
                    Qualified Name: DataFlowAnalyzer.__init__
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'set'
                        'analyzed_funcs'
                        'current_cfunc'
                        'usage_lines'
                        'limited_funcs'
                        'MAX_TRACE_CALLEE_DEPTH'
                        'MAX_TRACE_CALLER_DEPTH'
                    [Locals+Names]
                        'self'
                        'max_trace_callee_depth'
                        'max_trace_caller_depth'
                        'limit_funcs'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54796__'
                        '__pyarmor_enter_54797__'
                        b'<COAddr>\x01\x00\x00\x1az\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54798__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54797__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1az\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + set
                        38      CALL                            0
                        46      LOAD_FAST                       0: self
                        48      STORE_ATTR                      1: analyzed_funcs
                        58      LOAD_CONST                      0: None
                        60      LOAD_FAST                       0: self
                        62      STORE_ATTR                      2: current_cfunc
                        72      BUILD_LIST                      0
                        74      LOAD_FAST                       0: self
                        76      STORE_ATTR                      3: usage_lines
                        86      LOAD_FAST                       3: limit_funcs
                        88      LOAD_FAST                       0: self
                        90      STORE_ATTR                      4: limited_funcs
                        100     LOAD_FAST                       1: max_trace_callee_depth
                        102     LOAD_FAST                       0: self
                        104     STORE_ATTR                      5: MAX_TRACE_CALLEE_DEPTH
                        114     LOAD_FAST                       2: max_trace_caller_depth
                        116     LOAD_FAST                       0: self
                        118     STORE_ATTR                      6: MAX_TRACE_CALLER_DEPTH
                        128     LOAD_CONST                      0: None
                        130     NOP                             
                        132     NOP                             
                        134     NOP                             
                        136     JUMP_FORWARD                    19 (to 176)
                        144     POP_TOP                         
                        146     RETURN_CONST                    0: None
                        148     PUSH_EXC_INFO                   
                        150     PUSH_NULL                       
                        152     LOAD_CONST                      4: '__pyarmor_exit_54798__'
                        154     NOP                             
                        156     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1az\x00\x00\x00\x00\x00\x00\x00'
                        158     CALL                            1
                        166     POP_TOP                         
                        168     RERAISE                         0
                        170     COPY                            3
                        172     POP_EXCEPT                      
                        174     RERAISE                         1
                        176     PUSH_NULL                       
                        178     LOAD_CONST                      4: '__pyarmor_exit_54798__'
                        180     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1az\x00\x00\x00\x00\x00\x00\x00'
                        182     BUILD_TUPLE                     1
                        184     CALL_FUNCTION_EX                0
                        186     POP_TOP                         
                        188     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: _get_func_args
                    Qualified Name: DataFlowAnalyzer._get_func_args
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'arguments'
                        'append'
                        'name'
                    [Locals+Names]
                        'self'
                        'cfunc'
                        '__assert_armored__'
                        '_var_var_15'
                        '_var_var_16'
                    [Constants]
                        "Get function's arguments"
                        '__pyarmor_assert_54799__'
                        '__pyarmor_enter_54800__'
                        b'<COAddr>\x03\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54801__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54800__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
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
                        30      STORE_FAST                      3: _var_var_15
                        32      LOAD_FAST                       1: cfunc
                        34      POP_JUMP_IF_FALSE               56 (to 148)
                        36      LOAD_FAST                       1: cfunc
                        38      LOAD_ATTR                       0: arguments
                        58      POP_JUMP_IF_FALSE               44 (to 148)
                        60      LOAD_FAST                       1: cfunc
                        62      LOAD_ATTR                       0: arguments
                        82      GET_ITER                        
                        84      FOR_ITER                        29 (to 144)
                        88      STORE_FAST                      4: _var_var_16
                        90      LOAD_FAST                       3: _var_var_15
                        92      LOAD_ATTR                       3: append
                        112     LOAD_FAST                       4: _var_var_16
                        114     LOAD_ATTR                       4: name
                        134     CALL                            1
                        142     POP_TOP                         
                        144     JUMP_BACKWARD                   31 (to 84)
                        146     END_FOR                         
                        148     LOAD_FAST                       3: _var_var_15
                        150     NOP                             
                        152     NOP                             
                        154     NOP                             
                        156     JUMP_FORWARD                    20 (to 198)
                        158     CALL                            1
                        166     POP_TOP                         
                        168     RETURN_VALUE                    
                        170     PUSH_EXC_INFO                   
                        172     PUSH_NULL                       
                        174     LOAD_CONST                      4: '__pyarmor_exit_54801__'
                        176     NOP                             
                        178     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        180     CALL                            1
                        188     POP_TOP                         
                        190     RERAISE                         0
                        192     COPY                            3
                        194     POP_EXCEPT                      
                        196     RERAISE                         1
                        198     PUSH_NULL                       
                        200     LOAD_CONST                      4: '__pyarmor_exit_54801__'
                        202     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        204     BUILD_TUPLE                     1
                        206     CALL_FUNCTION_EX                0
                        208     POP_TOP                         
                        210     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: _get_pcode_line
                    Qualified Name: DataFlowAnalyzer._get_pcode_line
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'current_cfunc'
                        'ida_lines'
                        'tag_remove'
                        'get_pseudocode'
                        'line'
                    [Locals+Names]
                        'self'
                        'line_no'
                        '__assert_armored__'
                        '_var_var_13'
                    [Constants]
                        None
                        '__pyarmor_assert_54802__'
                        '__pyarmor_enter_54803__'
                        b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54804__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54803__'
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
                        28      LOAD_FAST                       0: self
                        30      LOAD_ATTR                       0: current_cfunc
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      0: None
                        56      NOP                             
                        58      NOP                             
                        60      NOP                             
                        62      JUMP_FORWARD                    88 (to 240)
                        70      POP_TOP                         
                        72      RETURN_CONST                    0: None
                        74      LOAD_GLOBAL                     3: NULL + ida_lines
                        84      LOAD_ATTR                       4: tag_remove
                        104     LOAD_FAST                       0: self
                        106     LOAD_ATTR                       0: current_cfunc
                        126     LOAD_ATTR                       7: get_pseudocode
                        146     CALL                            0
                        154     LOAD_FAST                       1: line_no
                        156     BINARY_SUBSCR                   
                        160     LOAD_ATTR                       8: line
                        180     CALL                            1
                        188     STORE_FAST                      3: _var_var_13
                        190     LOAD_FAST                       3: _var_var_13
                        192     NOP                             
                        194     NOP                             
                        196     NOP                             
                        198     JUMP_FORWARD                    20 (to 240)
                        200     CALL                            1
                        208     POP_TOP                         
                        210     RETURN_VALUE                    
                        212     PUSH_EXC_INFO                   
                        214     PUSH_NULL                       
                        216     LOAD_CONST                      4: '__pyarmor_exit_54804__'
                        218     NOP                             
                        220     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                        222     CALL                            1
                        230     POP_TOP                         
                        232     RERAISE                         0
                        234     COPY                            3
                        236     POP_EXCEPT                      
                        238     RERAISE                         1
                        240     PUSH_NULL                       
                        242     LOAD_CONST                      4: '__pyarmor_exit_54804__'
                        244     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
                        246     BUILD_TUPLE                     1
                        248     CALL_FUNCTION_EX                0
                        250     POP_TOP                         
                        252     RETURN_VALUE                    
                None
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: analyze_function_dataflow_forward
                    Qualified Name: DataFlowAnalyzer.analyze_function_dataflow_forward
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'FunctionContext'
                        'abs'
                        'depth'
                        'MAX_TRACE_CALLEE_DEPTH'
                        'limited_funcs'
                        'ida_funcs'
                        'get_func'
                        'ida_hexrays'
                        'decompile'
                        'current_cfunc'
                        'analyzed_funcs'
                        'add'
                        'set'
                        'var_mappings'
                        'update'
                        'keys'
                        'get_lvars'
                        'name'
                        'DataFlowVisitor'
                        'apply_to'
                        'body'
                    [Locals+Names]
                        'self'
                        'func_ea'
                        'context'
                        '__assert_armored__'
                        '_var_var_17'
                        '_var_var_18'
                        '_var_var_19'
                        '_var_var_20'
                        '_var_var_21'
                        '_var_var_22'
                        '_var_var_23'
                    [Constants]
                        'trace data flow, forward on call stack (callee only)\n        \n        Args:\n            func_ea: func addr\n            context: func calling context for cross-function analysis\n        '
                        '__pyarmor_assert_54805__'
                        '__pyarmor_enter_54806__'
                        b'<COAddr>\x01\x00\x00\x1a6\x03\x00\x00\x00\x00\x00\x00'
                        None
                        (
                            'caller_ea'
                        )
                        '__pyarmor_exit_54807__'
                        0
                        (
                            'alias_mapping'
                        )
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54806__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a6\x03\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       2: context
                        30      POP_JUMP_IF_TRUE                13 (to 58)
                        32      LOAD_GLOBAL                     1: NULL + FunctionContext
                        42      LOAD_FAST                       1: func_ea
                        44      LOAD_CONST                      4: None
                        46      KW_NAMES                        5: ('caller_ea',)
                        48      CALL                            2
                        56      STORE_FAST                      2: context
                        58      LOAD_GLOBAL                     3: NULL + abs
                        68      LOAD_FAST                       2: context
                        70      LOAD_ATTR                       4: depth
                        90      CALL                            1
                        98      LOAD_FAST                       0: self
                        100     LOAD_ATTR                       6: MAX_TRACE_CALLEE_DEPTH
                        120     COMPARE_OP                      68 (>)
                        124     POP_JUMP_IF_FALSE               11 (to 148)
                        126     NOP                             
                        128     LOAD_CONST                      4: None
                        130     NOP                             
                        132     NOP                             
                        134     JUMP_FORWARD                    369 (to 876)
                        144     POP_TOP                         
                        146     RETURN_CONST                    4: None
                        148     LOAD_FAST                       2: context
                        150     LOAD_ATTR                       4: depth
                        170     LOAD_CONST                      7: 0
                        172     COMPARE_OP                      55 (!=)
                        176     POP_JUMP_IF_FALSE               37 (to 252)
                        178     LOAD_FAST                       0: self
                        180     LOAD_ATTR                       8: limited_funcs
                        200     POP_JUMP_IF_FALSE               25 (to 252)
                        202     LOAD_FAST                       1: func_ea
                        204     LOAD_FAST                       0: self
                        206     LOAD_ATTR                       8: limited_funcs
                        226     CONTAINS_OP                     1 (not in)
                        228     POP_JUMP_IF_FALSE               11 (to 252)
                        230     NOP                             
                        232     LOAD_CONST                      4: None
                        234     NOP                             
                        236     NOP                             
                        238     JUMP_FORWARD                    317 (to 876)
                        248     POP_TOP                         
                        250     RETURN_CONST                    4: None
                        252     LOAD_GLOBAL                     11: NULL + ida_funcs
                        262     LOAD_ATTR                       12: get_func
                        282     LOAD_FAST                       1: func_ea
                        284     CALL                            1
                        292     STORE_FAST                      4: _var_var_17
                        294     LOAD_FAST                       4: _var_var_17
                        296     POP_JUMP_IF_TRUE                11 (to 320)
                        298     NOP                             
                        300     LOAD_CONST                      4: None
                        302     NOP                             
                        304     NOP                             
                        306     JUMP_FORWARD                    283 (to 876)
                        316     POP_TOP                         
                        318     RETURN_CONST                    4: None
                        320     LOAD_GLOBAL                     15: NULL + ida_hexrays
                        330     LOAD_ATTR                       16: decompile
                        350     LOAD_FAST                       4: _var_var_17
                        352     CALL                            1
                        360     STORE_FAST                      5: _var_var_18
                        362     LOAD_FAST                       5: _var_var_18
                        364     POP_JUMP_IF_TRUE                11 (to 388)
                        366     NOP                             
                        368     LOAD_CONST                      4: None
                        370     NOP                             
                        372     NOP                             
                        374     NOP                             
                        376     JUMP_FORWARD                    249 (to 876)
                        384     POP_TOP                         
                        386     RETURN_CONST                    4: None
                        388     LOAD_FAST                       0: self
                        390     LOAD_ATTR                       18: current_cfunc
                        410     STORE_FAST                      6: _var_var_19
                        412     LOAD_FAST                       5: _var_var_18
                        414     LOAD_FAST                       0: self
                        416     STORE_ATTR                      9: current_cfunc
                        426     LOAD_FAST                       0: self
                        428     LOAD_ATTR                       20: analyzed_funcs
                        448     LOAD_ATTR                       23: add
                        468     LOAD_FAST                       1: func_ea
                        470     CALL                            1
                        478     POP_TOP                         
                        480     LOAD_GLOBAL                     25: NULL + set
                        490     CALL                            0
                        498     STORE_FAST                      7: _var_var_20
                        500     LOAD_FAST                       2: context
                        502     LOAD_ATTR                       26: var_mappings
                        522     POP_JUMP_IF_FALSE               42 (to 608)
                        524     LOAD_FAST                       7: _var_var_20
                        526     LOAD_ATTR                       29: update
                        546     LOAD_FAST                       2: context
                        548     LOAD_ATTR                       26: var_mappings
                        568     LOAD_ATTR                       31: keys
                        588     CALL                            0
                        596     CALL                            1
                        604     POP_TOP                         
                        606     JUMP_FORWARD                    48 (to 704)
                        608     LOAD_FAST                       5: _var_var_18
                        610     LOAD_ATTR                       33: get_lvars
                        630     CALL                            0
                        638     GET_ITER                        
                        640     FOR_ITER                        29 (to 700)
                        644     STORE_FAST                      8: _var_var_21
                        646     LOAD_FAST                       7: _var_var_20
                        648     LOAD_ATTR                       23: add
                        668     LOAD_FAST                       8: _var_var_21
                        670     LOAD_ATTR                       34: name
                        690     CALL                            1
                        698     POP_TOP                         
                        700     JUMP_BACKWARD                   31 (to 640)
                        702     END_FOR                         
                        704     LOAD_FAST                       2: context
                        706     LOAD_ATTR                       26: var_mappings
                        726     STORE_FAST                      9: _var_var_22
                        728     LOAD_GLOBAL                     37: NULL + DataFlowVisitor
                        738     LOAD_FAST                       0: self
                        740     LOAD_FAST                       2: context
                        742     LOAD_FAST                       7: _var_var_20
                        744     LOAD_FAST                       9: _var_var_22
                        746     KW_NAMES                        8: ('alias_mapping',)
                        748     CALL                            4
                        756     STORE_FAST                      10: _var_var_23
                        758     LOAD_FAST                       10: _var_var_23
                        760     LOAD_ATTR                       39: apply_to
                        780     LOAD_FAST                       5: _var_var_18
                        782     LOAD_ATTR                       40: body
                        802     LOAD_CONST                      4: None
                        804     CALL                            2
                        812     POP_TOP                         
                        814     LOAD_FAST                       6: _var_var_19
                        816     LOAD_FAST                       0: self
                        818     STORE_ATTR                      9: current_cfunc
                        828     LOAD_CONST                      4: None
                        830     NOP                             
                        832     NOP                             
                        834     NOP                             
                        836     JUMP_FORWARD                    19 (to 876)
                        844     POP_TOP                         
                        846     RETURN_CONST                    4: None
                        848     PUSH_EXC_INFO                   
                        850     PUSH_NULL                       
                        852     LOAD_CONST                      6: '__pyarmor_exit_54807__'
                        854     NOP                             
                        856     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a6\x03\x00\x00\x00\x00\x00\x00'
                        858     CALL                            1
                        866     POP_TOP                         
                        868     RERAISE                         0
                        870     COPY                            3
                        872     POP_EXCEPT                      
                        874     RERAISE                         1
                        876     PUSH_NULL                       
                        878     LOAD_CONST                      6: '__pyarmor_exit_54807__'
                        880     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a6\x03\x00\x00\x00\x00\x00\x00'
                        882     BUILD_TUPLE                     1
                        884     CALL_FUNCTION_EX                0
                        886     POP_TOP                         
                        888     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: analyze_function_dataflow_backward
                    Qualified Name: DataFlowAnalyzer.analyze_function_dataflow_backward
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 9
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'FunctionContext'
                        'abs'
                        'depth'
                        'MAX_TRACE_CALLER_DEPTH'
                        'limited_funcs'
                        'ida_funcs'
                        'get_func'
                        'ida_hexrays'
                        'decompile'
                        'current_cfunc'
                        'analyzed_funcs'
                        'add'
                        'set'
                        'var_mappings'
                        'update'
                        'keys'
                        'get_lvars'
                        'name'
                        'DataFlowVisitor'
                        'apply_to'
                        'body'
                        'alias_mapping'
                        'idautils'
                        'CodeRefsTo'
                        'is_thunk'
                        'calc_thunk_func_target'
                        'ida_idaapi'
                        'BADADDR'
                        'ctree_visitor_t'
                        'call_expr'
                        'start_ea'
                        'enumerate'
                        'arguments'
                        'len'
                        'a'
                        'op'
                        'cot_var'
                        'v'
                        'getv'
                        'cot_cast'
                        'cot_memptr'
                        'cot_memref'
                        'cot_ref'
                        'cot_ptr'
                        'cot_idx'
                        'x'
                        'dstr'
                        'analyze_function_dataflow_backward'
                    [Locals+Names]
                        'self'
                        'func_ea'
                        'context'
                        '__assert_armored__'
                        '_var_var_17'
                        '_var_var_18'
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
                        '_var_var_3'
                        '_var_var_16'
                        '_var_var_31'
                        '_var_var_32'
                    [Constants]
                        'trace data flow, backward on call stack (caller only)\n        从 context.var_mappings 中的获取要追踪的变量，找到其在当前函数中的使用情况，分析时调用 DataFlowVisitor 注意此时不对 callee expr 进行分析，\n        当前函数分析完成后，获取当前函数的所有arguments 判断每个参数是否在 context.var_mappings 中，如果一个arg存在于 context.var_mappings 中，\n        则构建这个参数在caller中的var与arg alias的映射关系，存储到new_context.var_mappings 中，然后递归调用 analyze_function_dataflow_backward \n\n        Args:\n            func_ea: func addr\n            context: func calling context for cross-function analysis\n        '
                        '__pyarmor_assert_54808__'
                        '__pyarmor_enter_54809__'
                        b'<COAddr>\x03\x00\x00\x1a\xcc\x08\x00\x00\x00\x00\x00\x00'
                        None
                        (
                            'caller_ea'
                        )
                        '__pyarmor_exit_54810__'
                        0
                        True
                        (
                            'alias_mapping'
                            'not_trace_callee'
                        )
                        1
                        [Code]
                            File Name: <frozen ..data_flow>
                            Object Name: CallSiteVisitor
                            Qualified Name: DataFlowAnalyzer.analyze_function_dataflow_backward.<locals>.CallSiteVisitor
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
                                'visit_expr'
                            [Locals+Names]
                            [Constants]
                                'DataFlowAnalyzer.analyze_function_dataflow_backward.<locals>.CallSiteVisitor'
                                '__pyarmor_assert_54811__'
                                '__pyarmor_enter_54812__'
                                b'<COAddr>\x01\x00\x00""\x00\x00\x00\x00\x00\x00\x00'
                                [Code]
                                    File Name: <frozen ..data_flow>
                                    Object Name: __init__
                                    Qualified Name: DataFlowAnalyzer.analyze_function_dataflow_backward.<locals>.CallSiteVisitor.__init__
                                    Arg Count: 2
                                    Pos Only Arg Count: 0
                                    KW Only Arg Count: 0
                                    Stack Size: 5
                                    Flags: 0x20000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_PYARMOR_OBFUSCATED)
                                    [Names]
                                        'ida_hexrays'
                                        'ctree_visitor_t'
                                        '__init__'
                                        'CV_FAST'
                                        'target_ea'
                                        'call_expr'
                                    [Locals+Names]
                                        'self'
                                        'target_ea'
                                        '__assert_armored__'
                                    [Constants]
                                        None
                                        '__pyarmor_assert_54814__'
                                        '__pyarmor_enter_54815__'
                                        b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                                        '__pyarmor_exit_54816__'
                                    [Disassembly]
                                        0       NOP                             
                                        2       NOP                             
                                        4       PUSH_NULL                       
                                        6       LOAD_CONST                      2: '__pyarmor_enter_54815__'
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
                                        28      LOAD_GLOBAL                     0: ida_hexrays
                                        38      LOAD_ATTR                       2: ctree_visitor_t
                                        58      LOAD_ATTR                       5: __init__
                                        78      LOAD_FAST                       0: self
                                        80      LOAD_GLOBAL                     0: ida_hexrays
                                        90      LOAD_ATTR                       6: CV_FAST
                                        110     CALL                            2
                                        118     POP_TOP                         
                                        120     LOAD_FAST                       1: target_ea
                                        122     LOAD_FAST                       0: self
                                        124     STORE_ATTR                      4: target_ea
                                        134     LOAD_CONST                      0: None
                                        136     LOAD_FAST                       0: self
                                        138     STORE_ATTR                      5: call_expr
                                        148     LOAD_CONST                      0: None
                                        150     NOP                             
                                        152     NOP                             
                                        154     NOP                             
                                        156     JUMP_FORWARD                    19 (to 196)
                                        164     POP_TOP                         
                                        166     RETURN_CONST                    0: None
                                        168     PUSH_EXC_INFO                   
                                        170     PUSH_NULL                       
                                        172     LOAD_CONST                      4: '__pyarmor_exit_54816__'
                                        174     NOP                             
                                        176     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                                        178     CALL                            1
                                        186     POP_TOP                         
                                        188     RERAISE                         0
                                        190     COPY                            3
                                        192     POP_EXCEPT                      
                                        194     RERAISE                         1
                                        196     PUSH_NULL                       
                                        198     LOAD_CONST                      4: '__pyarmor_exit_54816__'
                                        200     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8e\x00\x00\x00\x00\x00\x00\x00'
                                        202     BUILD_TUPLE                     1
                                        204     CALL_FUNCTION_EX                0
                                        206     POP_TOP                         
                                        208     RETURN_VALUE                    
                                [Code]
                                    File Name: <frozen ..data_flow>
                                    Object Name: visit_expr
                                    Qualified Name: DataFlowAnalyzer.analyze_function_dataflow_backward.<locals>.CallSiteVisitor.visit_expr
                                    Arg Count: 2
                                    Pos Only Arg Count: 0
                                    KW Only Arg Count: 0
                                    Stack Size: 5
                                    Flags: 0x20000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_PYARMOR_OBFUSCATED)
                                    [Names]
                                        'op'
                                        'ida_hexrays'
                                        'cot_call'
                                        'x'
                                        'cot_obj'
                                        'obj_ea'
                                        'target_ea'
                                        'call_expr'
                                    [Locals+Names]
                                        'self'
                                        'expr'
                                        '__assert_armored__'
                                    [Constants]
                                        None
                                        '__pyarmor_assert_54817__'
                                        '__pyarmor_enter_54818__'
                                        b'<COAddr>\x01\x00\x00\x1a\xf2\x00\x00\x00\x00\x00\x00\x00'
                                        '__pyarmor_exit_54819__'
                                        0
                                    [Disassembly]
                                        0       NOP                             
                                        2       NOP                             
                                        4       PUSH_NULL                       
                                        6       LOAD_CONST                      2: '__pyarmor_enter_54818__'
                                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf2\x00\x00\x00\x00\x00\x00\x00'
                                        10      BUILD_TUPLE                     1
                                        12      CALL_FUNCTION_EX                0
                                        14      POP_TOP                         
                                        16      RESUME                          0
                                        18      NOP                             
                                        20      NOP                             
                                        22      NOP                             
                                        24      NOP                             
                                        26      NOP                             
                                        28      LOAD_FAST                       1: expr
                                        30      LOAD_ATTR                       0: op
                                        50      LOAD_GLOBAL                     2: ida_hexrays
                                        60      LOAD_ATTR                       4: cot_call
                                        80      COMPARE_OP                      40 (==)
                                        84      POP_JUMP_IF_FALSE               81 (to 248)
                                        86      LOAD_FAST                       1: expr
                                        88      LOAD_ATTR                       6: x
                                        108     LOAD_ATTR                       0: op
                                        128     LOAD_GLOBAL                     2: ida_hexrays
                                        138     LOAD_ATTR                       8: cot_obj
                                        158     COMPARE_OP                      40 (==)
                                        162     POP_JUMP_IF_FALSE               42 (to 248)
                                        164     LOAD_FAST                       1: expr
                                        166     LOAD_ATTR                       6: x
                                        186     LOAD_ATTR                       10: obj_ea
                                        206     LOAD_FAST                       0: self
                                        208     LOAD_ATTR                       12: target_ea
                                        228     COMPARE_OP                      40 (==)
                                        232     POP_JUMP_IF_FALSE               7 (to 248)
                                        234     LOAD_FAST                       1: expr
                                        236     LOAD_FAST                       0: self
                                        238     STORE_ATTR                      7: call_expr
                                        248     LOAD_CONST                      5: 0
                                        250     NOP                             
                                        252     NOP                             
                                        254     NOP                             
                                        256     JUMP_FORWARD                    19 (to 296)
                                        264     POP_TOP                         
                                        266     RETURN_CONST                    5: 0
                                        268     PUSH_EXC_INFO                   
                                        270     PUSH_NULL                       
                                        272     LOAD_CONST                      4: '__pyarmor_exit_54819__'
                                        274     NOP                             
                                        276     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf2\x00\x00\x00\x00\x00\x00\x00'
                                        278     CALL                            1
                                        286     POP_TOP                         
                                        288     RERAISE                         0
                                        290     COPY                            3
                                        292     POP_EXCEPT                      
                                        294     RERAISE                         1
                                        296     PUSH_NULL                       
                                        298     LOAD_CONST                      4: '__pyarmor_exit_54819__'
                                        300     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf2\x00\x00\x00\x00\x00\x00\x00'
                                        302     BUILD_TUPLE                     1
                                        304     CALL_FUNCTION_EX                0
                                        306     POP_TOP                         
                                        308     RETURN_VALUE                    
                                '__pyarmor_exit_54813__'
                                None
                            [Disassembly]
                                0       NOP                             
                                2       LOAD_NAME                       0: __name__
                                4       STORE_NAME                      1: __module__
                                6       LOAD_CONST                      0: 'DataFlowAnalyzer.analyze_function_dataflow_backward.<locals>.CallSiteVisitor'
                                8       STORE_NAME                      2: __qualname__
                                10      NOP                             
                                12      PUSH_NULL                       
                                14      LOAD_CONST                      2: '__pyarmor_enter_54812__'
                                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00""\x00\x00\x00\x00\x00\x00\x00'
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
                                42      LOAD_CONST                      5: <CODE> visit_expr
                                44      MAKE_FUNCTION                   0
                                46      STORE_NAME                      5: visit_expr
                                48      LOAD_CONST                      7: None
                                50      NOP                             
                                52      NOP                             
                                54      NOP                             
                                56      JUMP_FORWARD                    19 (to 96)
                                64      POP_TOP                         
                                66      RETURN_CONST                    7: None
                                68      PUSH_EXC_INFO                   
                                70      PUSH_NULL                       
                                72      LOAD_CONST                      6: '__pyarmor_exit_54813__'
                                74      NOP                             
                                76      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00""\x00\x00\x00\x00\x00\x00\x00'
                                78      CALL                            1
                                86      POP_TOP                         
                                88      RERAISE                         0
                                90      COPY                            3
                                92      POP_EXCEPT                      
                                94      RERAISE                         1
                                96      PUSH_NULL                       
                                98      LOAD_CONST                      6: '__pyarmor_exit_54813__'
                                100     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00""\x00\x00\x00\x00\x00\x00\x00'
                                102     BUILD_TUPLE                     1
                                104     CALL_FUNCTION_EX                0
                                106     POP_TOP                         
                                108     RETURN_VALUE                    
                        'CallSiteVisitor'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54809__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xcc\x08\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       2: context
                        30      POP_JUMP_IF_TRUE                13 (to 58)
                        32      LOAD_GLOBAL                     1: NULL + FunctionContext
                        42      LOAD_FAST                       1: func_ea
                        44      LOAD_CONST                      4: None
                        46      KW_NAMES                        5: ('caller_ea',)
                        48      CALL                            2
                        56      STORE_FAST                      2: context
                        58      LOAD_GLOBAL                     3: NULL + abs
                        68      LOAD_FAST                       2: context
                        70      LOAD_ATTR                       4: depth
                        90      CALL                            1
                        98      LOAD_FAST                       0: self
                        100     LOAD_ATTR                       6: MAX_TRACE_CALLER_DEPTH
                        120     COMPARE_OP                      68 (>)
                        124     POP_JUMP_IF_FALSE               11 (to 148)
                        126     NOP                             
                        128     LOAD_CONST                      4: None
                        130     NOP                             
                        132     NOP                             
                        134     JUMP_FORWARD                    1084 (to 2306)
                        144     POP_TOP                         
                        146     RETURN_CONST                    4: None
                        148     LOAD_FAST                       2: context
                        150     LOAD_ATTR                       4: depth
                        170     LOAD_CONST                      7: 0
                        172     COMPARE_OP                      55 (!=)
                        176     POP_JUMP_IF_FALSE               37 (to 252)
                        178     LOAD_FAST                       0: self
                        180     LOAD_ATTR                       8: limited_funcs
                        200     POP_JUMP_IF_FALSE               25 (to 252)
                        202     LOAD_FAST                       1: func_ea
                        204     LOAD_FAST                       0: self
                        206     LOAD_ATTR                       8: limited_funcs
                        226     CONTAINS_OP                     1 (not in)
                        228     POP_JUMP_IF_FALSE               11 (to 252)
                        230     NOP                             
                        232     LOAD_CONST                      4: None
                        234     NOP                             
                        236     NOP                             
                        238     JUMP_FORWARD                    1032 (to 2306)
                        248     POP_TOP                         
                        250     RETURN_CONST                    4: None
                        252     LOAD_GLOBAL                     11: NULL + ida_funcs
                        262     LOAD_ATTR                       12: get_func
                        282     LOAD_FAST                       1: func_ea
                        284     CALL                            1
                        292     STORE_FAST                      4: _var_var_17
                        294     LOAD_FAST                       4: _var_var_17
                        296     POP_JUMP_IF_TRUE                11 (to 320)
                        298     NOP                             
                        300     LOAD_CONST                      4: None
                        302     NOP                             
                        304     NOP                             
                        306     JUMP_FORWARD                    998 (to 2306)
                        316     POP_TOP                         
                        318     RETURN_CONST                    4: None
                        320     LOAD_GLOBAL                     15: NULL + ida_hexrays
                        330     LOAD_ATTR                       16: decompile
                        350     LOAD_FAST                       4: _var_var_17
                        352     CALL                            1
                        360     STORE_FAST                      5: _var_var_18
                        362     LOAD_FAST                       5: _var_var_18
                        364     POP_JUMP_IF_TRUE                11 (to 388)
                        366     NOP                             
                        368     LOAD_CONST                      4: None
                        370     NOP                             
                        372     NOP                             
                        374     JUMP_FORWARD                    964 (to 2306)
                        384     POP_TOP                         
                        386     RETURN_CONST                    4: None
                        388     LOAD_FAST                       0: self
                        390     LOAD_ATTR                       18: current_cfunc
                        410     STORE_FAST                      6: _var_var_19
                        412     LOAD_FAST                       5: _var_var_18
                        414     LOAD_FAST                       0: self
                        416     STORE_ATTR                      9: current_cfunc
                        426     LOAD_FAST                       0: self
                        428     LOAD_ATTR                       20: analyzed_funcs
                        448     LOAD_ATTR                       23: add
                        468     LOAD_FAST                       1: func_ea
                        470     CALL                            1
                        478     POP_TOP                         
                        480     LOAD_GLOBAL                     25: NULL + set
                        490     CALL                            0
                        498     STORE_FAST                      7: _var_var_20
                        500     LOAD_FAST                       2: context
                        502     LOAD_ATTR                       26: var_mappings
                        522     POP_JUMP_IF_FALSE               42 (to 608)
                        524     LOAD_FAST                       7: _var_var_20
                        526     LOAD_ATTR                       29: update
                        546     LOAD_FAST                       2: context
                        548     LOAD_ATTR                       26: var_mappings
                        568     LOAD_ATTR                       31: keys
                        588     CALL                            0
                        596     CALL                            1
                        604     POP_TOP                         
                        606     JUMP_FORWARD                    48 (to 704)
                        608     LOAD_FAST                       5: _var_var_18
                        610     LOAD_ATTR                       33: get_lvars
                        630     CALL                            0
                        638     GET_ITER                        
                        640     FOR_ITER                        29 (to 700)
                        644     STORE_FAST                      8: _var_var_21
                        646     LOAD_FAST                       7: _var_var_20
                        648     LOAD_ATTR                       23: add
                        668     LOAD_FAST                       8: _var_var_21
                        670     LOAD_ATTR                       34: name
                        690     CALL                            1
                        698     POP_TOP                         
                        700     JUMP_BACKWARD                   31 (to 640)
                        702     END_FOR                         
                        704     LOAD_FAST                       2: context
                        706     LOAD_ATTR                       26: var_mappings
                        726     STORE_FAST                      9: _var_var_22
                        728     LOAD_FAST                       2: context
                        730     LOAD_ATTR                       4: depth
                        750     LOAD_CONST                      7: 0
                        752     COMPARE_OP                      55 (!=)
                        756     POP_JUMP_IF_FALSE               56 (to 870)
                        758     LOAD_GLOBAL                     37: NULL + DataFlowVisitor
                        768     LOAD_FAST                       0: self
                        770     LOAD_FAST                       2: context
                        772     LOAD_FAST                       7: _var_var_20
                        774     LOAD_FAST                       9: _var_var_22
                        776     LOAD_CONST                      8: True
                        778     KW_NAMES                        9: ('alias_mapping', 'not_trace_callee')
                        780     CALL                            5
                        788     STORE_FAST                      10: _var_var_23
                        790     LOAD_FAST                       10: _var_var_23
                        792     LOAD_ATTR                       39: apply_to
                        812     LOAD_FAST                       5: _var_var_18
                        814     LOAD_ATTR                       40: body
                        834     LOAD_CONST                      4: None
                        836     CALL                            2
                        844     POP_TOP                         
                        846     LOAD_FAST                       10: _var_var_23
                        848     LOAD_ATTR                       42: alias_mapping
                        868     STORE_FAST                      9: _var_var_22
                        870     LOAD_GLOBAL                     45: NULL + idautils
                        880     LOAD_ATTR                       46: CodeRefsTo
                        900     LOAD_FAST                       1: func_ea
                        902     LOAD_CONST                      10: 1
                        904     CALL                            2
                        912     GET_ITER                        
                        914     FOR_ITER                        661 (to 2240)
                        920     STORE_FAST                      11: _var_var_24
                        922     LOAD_GLOBAL                     49: NULL + is_thunk
                        932     LOAD_FAST                       11: _var_var_24
                        934     CALL                            1
                        942     POP_JUMP_IF_FALSE               45 (to 1034)
                        944     LOAD_GLOBAL                     11: NULL + ida_funcs
                        954     LOAD_ATTR                       50: calc_thunk_func_target
                        974     LOAD_FAST                       11: _var_var_24
                        976     CALL                            1
                        984     LOAD_CONST                      7: 0
                        986     BINARY_SUBSCR                   
                        990     STORE_FAST                      12: _var_var_25
                        992     LOAD_FAST                       12: _var_var_25
                        994     LOAD_GLOBAL                     52: ida_idaapi
                        1004    LOAD_ATTR                       54: BADADDR
                        1024    COMPARE_OP                      55 (!=)
                        1028    POP_JUMP_IF_FALSE               2 (to 1034)
                        1030    LOAD_FAST                       12: _var_var_25
                        1032    STORE_FAST                      11: _var_var_24
                        1034    LOAD_FAST                       11: _var_var_24
                        1036    LOAD_GLOBAL                     52: ida_idaapi
                        1046    LOAD_ATTR                       54: BADADDR
                        1066    COMPARE_OP                      40 (==)
                        1070    POP_JUMP_IF_FALSE               1 (to 1074)
                        1072    JUMP_BACKWARD                   80 (to 914)
                        1074    LOAD_GLOBAL                     11: NULL + ida_funcs
                        1084    LOAD_ATTR                       12: get_func
                        1104    LOAD_FAST                       11: _var_var_24
                        1106    CALL                            1
                        1114    STORE_FAST                      13: _var_var_26
                        1116    LOAD_FAST                       13: _var_var_26
                        1118    POP_JUMP_IF_TRUE                1 (to 1122)
                        1120    JUMP_BACKWARD                   104 (to 914)
                        1122    LOAD_GLOBAL                     15: NULL + ida_hexrays
                        1132    LOAD_ATTR                       16: decompile
                        1152    LOAD_FAST                       13: _var_var_26
                        1154    CALL                            1
                        1162    STORE_FAST                      14: _var_var_27
                        1164    LOAD_FAST                       14: _var_var_27
                        1166    POP_JUMP_IF_TRUE                1 (to 1170)
                        1168    JUMP_BACKWARD                   128 (to 914)
                        1170    PUSH_NULL                       
                        1172    LOAD_BUILD_CLASS                
                        1174    LOAD_CONST                      11: <CODE> CallSiteVisitor
                        1176    MAKE_FUNCTION                   0
                        1178    LOAD_CONST                      12: 'CallSiteVisitor'
                        1180    LOAD_GLOBAL                     14: ida_hexrays
                        1190    LOAD_ATTR                       56: ctree_visitor_t
                        1210    CALL                            3
                        1218    STORE_FAST                      15: _var_var_28
                        1220    PUSH_NULL                       
                        1222    LOAD_FAST                       15: _var_var_28
                        1224    LOAD_FAST                       1: func_ea
                        1226    CALL                            1
                        1234    STORE_FAST                      16: _var_var_29
                        1236    LOAD_FAST                       16: _var_var_29
                        1238    LOAD_ATTR                       39: apply_to
                        1258    LOAD_FAST                       14: _var_var_27
                        1260    LOAD_ATTR                       40: body
                        1280    LOAD_CONST                      4: None
                        1282    CALL                            2
                        1290    POP_TOP                         
                        1292    LOAD_FAST                       16: _var_var_29
                        1294    LOAD_ATTR                       58: call_expr
                        1314    POP_JUMP_IF_TRUE                1 (to 1318)
                        1316    JUMP_BACKWARD                   202 (to 914)
                        1318    LOAD_GLOBAL                     1: NULL + FunctionContext
                        1328    LOAD_FAST                       1: func_ea
                        1330    LOAD_FAST                       13: _var_var_26
                        1332    LOAD_ATTR                       60: start_ea
                        1352    CALL                            2
                        1360    STORE_FAST                      17: _var_var_30
                        1362    LOAD_FAST                       2: context
                        1364    LOAD_ATTR                       4: depth
                        1384    LOAD_CONST                      10: 1
                        1386    BINARY_OP                       10 (-)
                        1390    LOAD_FAST                       17: _var_var_30
                        1392    STORE_ATTR                      2: depth
                        1402    LOAD_GLOBAL                     63: NULL + enumerate
                        1412    LOAD_FAST                       5: _var_var_18
                        1414    LOAD_ATTR                       64: arguments
                        1434    CALL                            1
                        1442    GET_ITER                        
                        1444    FOR_ITER                        351 (to 2150)
                        1450    UNPACK_SEQUENCE                 2
                        1454    STORE_FAST                      18: _var_var_3
                        1456    STORE_FAST                      19: _var_var_16
                        1458    LOAD_FAST                       19: _var_var_16
                        1460    LOAD_ATTR                       34: name
                        1480    LOAD_FAST                       9: _var_var_22
                        1482    CONTAINS_OP                     0 (in)
                        1484    POP_JUMP_IF_TRUE                1 (to 1488)
                        1486    JUMP_BACKWARD                   22 (to 1444)
                        1488    LOAD_FAST                       18: _var_var_3
                        1490    LOAD_GLOBAL                     67: NULL + len
                        1500    LOAD_FAST                       16: _var_var_29
                        1502    LOAD_ATTR                       58: call_expr
                        1522    LOAD_ATTR                       68: a
                        1542    CALL                            1
                        1550    COMPARE_OP                      2 (<)
                        1554    POP_JUMP_IF_TRUE                1 (to 1558)
                        1556    JUMP_BACKWARD                   57 (to 1444)
                        1558    LOAD_FAST                       9: _var_var_22
                        1560    LOAD_FAST                       19: _var_var_16
                        1562    LOAD_ATTR                       34: name
                        1582    BINARY_SUBSCR                   
                        1586    STORE_FAST                      20: _var_var_31
                        1588    LOAD_FAST                       16: _var_var_29
                        1590    LOAD_ATTR                       58: call_expr
                        1610    LOAD_ATTR                       68: a
                        1630    LOAD_FAST                       18: _var_var_3
                        1632    BINARY_SUBSCR                   
                        1636    STORE_FAST                      21: _var_var_32
                        1638    LOAD_FAST                       21: _var_var_32
                        1640    LOAD_ATTR                       70: op
                        1660    LOAD_GLOBAL                     14: ida_hexrays
                        1670    LOAD_ATTR                       72: cot_var
                        1690    COMPARE_OP                      40 (==)
                        1694    POP_JUMP_IF_FALSE               50 (to 1796)
                        1696    LOAD_FAST                       20: _var_var_31
                        1698    LOAD_FAST                       17: _var_var_30
                        1700    LOAD_ATTR                       26: var_mappings
                        1720    LOAD_FAST                       21: _var_var_32
                        1722    LOAD_ATTR                       74: v
                        1742    LOAD_ATTR                       77: getv
                        1762    CALL                            0
                        1770    LOAD_ATTR                       34: name
                        1790    STORE_SUBSCR                    
                        1794    JUMP_BACKWARD                   176 (to 1444)
                        1796    LOAD_FAST                       21: _var_var_32
                        1798    LOAD_ATTR                       70: op
                        1818    LOAD_GLOBAL                     14: ida_hexrays
                        1828    LOAD_ATTR                       78: cot_cast
                        1848    LOAD_GLOBAL                     14: ida_hexrays
                        1858    LOAD_ATTR                       80: cot_memptr
                        1878    LOAD_GLOBAL                     14: ida_hexrays
                        1888    LOAD_ATTR                       82: cot_memref
                        1908    LOAD_GLOBAL                     14: ida_hexrays
                        1918    LOAD_ATTR                       84: cot_ref
                        1938    LOAD_GLOBAL                     14: ida_hexrays
                        1948    LOAD_ATTR                       86: cot_ptr
                        1968    LOAD_GLOBAL                     14: ida_hexrays
                        1978    LOAD_ATTR                       88: cot_idx
                        1998    BUILD_TUPLE                     6
                        2000    CONTAINS_OP                     0 (in)
                        2002    POP_JUMP_IF_TRUE                2 (to 2008)
                        2004    JUMP_BACKWARD                   282 (to 1444)
                        2008    LOAD_FAST                       21: _var_var_32
                        2010    LOAD_ATTR                       70: op
                        2030    LOAD_GLOBAL                     14: ida_hexrays
                        2040    LOAD_ATTR                       78: cot_cast
                        2060    COMPARE_OP                      40 (==)
                        2064    POP_JUMP_IF_FALSE               12 (to 2090)
                        2066    LOAD_FAST                       21: _var_var_32
                        2068    LOAD_ATTR                       90: x
                        2088    STORE_FAST                      21: _var_var_32
                        2090    LOAD_FAST                       20: _var_var_31
                        2092    LOAD_FAST                       17: _var_var_30
                        2094    LOAD_ATTR                       26: var_mappings
                        2114    LOAD_FAST                       21: _var_var_32
                        2116    LOAD_ATTR                       93: dstr
                        2136    CALL                            0
                        2144    STORE_SUBSCR                    
                        2148    JUMP_BACKWARD                   354 (to 1444)
                        2152    END_FOR                         
                        2154    LOAD_FAST                       17: _var_var_30
                        2156    LOAD_ATTR                       26: var_mappings
                        2176    POP_JUMP_IF_TRUE                2 (to 2182)
                        2178    JUMP_BACKWARD                   634 (to 914)
                        2182    LOAD_FAST                       0: self
                        2184    LOAD_ATTR                       95: analyze_function_dataflow_backward
                        2204    LOAD_FAST                       13: _var_var_26
                        2206    LOAD_ATTR                       60: start_ea
                        2226    LOAD_FAST                       17: _var_var_30
                        2228    CALL                            2
                        2236    POP_TOP                         
                        2238    JUMP_BACKWARD                   664 (to 914)
                        2242    END_FOR                         
                        2244    LOAD_FAST                       6: _var_var_19
                        2246    LOAD_FAST                       0: self
                        2248    STORE_ATTR                      9: current_cfunc
                        2258    LOAD_CONST                      4: None
                        2260    NOP                             
                        2262    NOP                             
                        2264    NOP                             
                        2266    JUMP_FORWARD                    19 (to 2306)
                        2274    POP_TOP                         
                        2276    RETURN_CONST                    4: None
                        2278    PUSH_EXC_INFO                   
                        2280    PUSH_NULL                       
                        2282    LOAD_CONST                      6: '__pyarmor_exit_54810__'
                        2284    NOP                             
                        2286    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xcc\x08\x00\x00\x00\x00\x00\x00'
                        2288    CALL                            1
                        2296    POP_TOP                         
                        2298    RERAISE                         0
                        2300    COPY                            3
                        2302    POP_EXCEPT                      
                        2304    RERAISE                         1
                        2306    PUSH_NULL                       
                        2308    LOAD_CONST                      6: '__pyarmor_exit_54810__'
                        2310    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xcc\x08\x00\x00\x00\x00\x00\x00'
                        2312    BUILD_TUPLE                     1
                        2314    CALL_FUNCTION_EX                0
                        2316    POP_TOP                         
                        2318    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: get_var_dataflow
                    Qualified Name: DataFlowAnalyzer.get_var_dataflow
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 12
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'analyzed_funcs'
                        'clear'
                        'usage_lines'
                        'FunctionContext'
                        'isinstance'
                        'str'
                        'var_mappings'
                        'list'
                        'ida_hexrays'
                        'decompile'
                        'get_lvars'
                        'name'
                        'hex'
                        'ValueError'
                        'analyze_function_dataflow_forward'
                        'analyze_function_dataflow_backward'
                        'dict'
                        'func_name'
                        'line_addr'
                        'pcode_line'
                        'alias_name'
                        'var_name'
                        'values'
                        'context_depth'
                        'access_type'
                        'colored'
                        'var_type'
                        'colored_print'
                        'demangle'
                        'idc'
                        'get_func_name'
                        'print'
                        'join'
                    [Locals+Names]
                        'self'
                        'func_ea'
                        'var_name'
                        'verbose'
                        '__assert_armored__'
                        '_var_var_33'
                        '_var_var_34'
                        '_var_var_18'
                        '_var_var_3'
                        '_var_var_35'
                        '_var_var_36'
                        '_var_var_37'
                        '_var_var_38'
                        '_var_var_39'
                        '_var_var_40'
                    [Constants]
                        'get specific variable data flow in the target function\n        \n        Args:\n            func_ea: func addr\n            var_name: specific variable, str or List[str]\n            \n        Returns:\n            formatted data flow string\n        '
                        '__pyarmor_assert_54820__'
                        '__pyarmor_enter_54821__'
                        b'<COAddr>\x03\x00\x00\x1ab\x08\x00\x00\x00\x00\x00\x00'
                        None
                        '__pyarmor_exit_54822__'
                        'No local variables or arguments found in the func_ea: '
                        'Invalid var_name: '
                        0
                        'call'
                        ', '
                        ' '
                        ' == '
                        'green'
                        '==== final usages for traced variable: `'
                        '` in `'
                        '` ===='
                        '---- trace callee usages 🚀----'
                        1
                        '---- trace caller usages 🚀----'
                        '` ====\n'
                        '---- trace callee usages ----\n'
                        '\n'
                        '\n---- trace caller usages ----\n'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54821__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ab\x08\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: analyzed_funcs
                        50      LOAD_ATTR                       3: clear
                        70      CALL                            0
                        78      POP_TOP                         
                        80      LOAD_FAST                       0: self
                        82      LOAD_ATTR                       4: usage_lines
                        102     LOAD_ATTR                       3: clear
                        122     CALL                            0
                        130     POP_TOP                         
                        132     LOAD_GLOBAL                     7: NULL + FunctionContext
                        142     LOAD_FAST                       1: func_ea
                        144     CALL                            1
                        152     STORE_FAST                      5: _var_var_33
                        154     LOAD_GLOBAL                     9: NULL + isinstance
                        164     LOAD_FAST                       2: var_name
                        166     LOAD_GLOBAL                     10: str
                        176     CALL                            2
                        184     POP_JUMP_IF_FALSE               10 (to 206)
                        186     LOAD_FAST                       2: var_name
                        188     LOAD_FAST                       2: var_name
                        190     BUILD_MAP                       1
                        192     LOAD_FAST                       5: _var_var_33
                        194     STORE_ATTR                      6: var_mappings
                        204     JUMP_FORWARD                    195 (to 596)
                        206     LOAD_GLOBAL                     9: NULL + isinstance
                        216     LOAD_FAST                       2: var_name
                        218     LOAD_GLOBAL                     14: list
                        228     CALL                            2
                        236     POP_JUMP_IF_FALSE               23 (to 284)
                        238     LOAD_FAST                       2: var_name
                        240     GET_ITER                        
                        242     LOAD_FAST_AND_CLEAR             6: _var_var_34
                        244     SWAP                            2
                        246     BUILD_MAP                       0
                        248     SWAP                            2
                        250     FOR_ITER                        5 (to 262)
                        254     STORE_FAST                      6: _var_var_34
                        256     LOAD_FAST                       6: _var_var_34
                        258     LOAD_FAST                       6: _var_var_34
                        260     MAP_ADD                         2
                        262     JUMP_BACKWARD                   7 (to 250)
                        264     END_FOR                         
                        266     SWAP                            2
                        268     STORE_FAST                      6: _var_var_34
                        270     LOAD_FAST                       5: _var_var_33
                        272     STORE_ATTR                      6: var_mappings
                        282     JUMP_FORWARD                    156 (to 596)
                        284     LOAD_FAST                       2: var_name
                        286     LOAD_CONST                      4: None
                        288     COMPARE_OP                      40 (==)
                        292     POP_JUMP_IF_FALSE               137 (to 568)
                        294     LOAD_GLOBAL                     17: NULL + ida_hexrays
                        304     LOAD_ATTR                       18: decompile
                        324     LOAD_FAST                       1: func_ea
                        326     CALL                            1
                        334     STORE_FAST                      7: _var_var_18
                        336     LOAD_FAST                       7: _var_var_18
                        338     POP_JUMP_IF_TRUE                11 (to 362)
                        340     NOP                             
                        342     LOAD_CONST                      4: None
                        344     NOP                             
                        346     NOP                             
                        348     JUMP_FORWARD                    924 (to 2200)
                        358     POP_TOP                         
                        360     RETURN_CONST                    4: None
                        362     LOAD_FAST                       7: _var_var_18
                        364     LOAD_ATTR                       21: get_lvars
                        384     CALL                            0
                        392     GET_ITER                        
                        394     LOAD_FAST_AND_CLEAR             8: _var_var_3
                        396     SWAP                            2
                        398     BUILD_LIST                      0
                        400     SWAP                            2
                        402     FOR_ITER                        30 (to 464)
                        406     STORE_FAST                      8: _var_var_3
                        408     LOAD_FAST                       8: _var_var_3
                        410     POP_JUMP_IF_TRUE                1 (to 414)
                        412     JUMP_BACKWARD                   6 (to 402)
                        414     LOAD_FAST                       8: _var_var_3
                        416     LOAD_ATTR                       22: name
                        436     POP_JUMP_IF_TRUE                1 (to 440)
                        438     JUMP_BACKWARD                   19 (to 402)
                        440     LOAD_FAST                       8: _var_var_3
                        442     LOAD_ATTR                       22: name
                        462     LIST_APPEND                     2
                        464     JUMP_BACKWARD                   32 (to 402)
                        466     END_FOR                         
                        468     STORE_FAST                      2: var_name
                        470     STORE_FAST                      8: _var_var_3
                        472     LOAD_FAST                       2: var_name
                        474     POP_JUMP_IF_TRUE                23 (to 522)
                        476     LOAD_CONST                      6: 'No local variables or arguments found in the func_ea: '
                        478     LOAD_GLOBAL                     25: NULL + hex
                        488     LOAD_FAST                       1: func_ea
                        490     CALL                            1
                        498     FORMAT_VALUE                    0 (FVC_NONE)
                        500     BUILD_STRING                    2
                        502     NOP                             
                        504     NOP                             
                        506     JUMP_FORWARD                    845 (to 2200)
                        510     CALL                            1
                        518     POP_TOP                         
                        520     RETURN_VALUE                    
                        522     LOAD_FAST                       2: var_name
                        524     GET_ITER                        
                        526     LOAD_FAST_AND_CLEAR             6: _var_var_34
                        528     SWAP                            2
                        530     BUILD_MAP                       0
                        532     SWAP                            2
                        534     FOR_ITER                        5 (to 546)
                        538     STORE_FAST                      6: _var_var_34
                        540     LOAD_FAST                       6: _var_var_34
                        542     LOAD_FAST                       6: _var_var_34
                        544     MAP_ADD                         2
                        546     JUMP_BACKWARD                   7 (to 534)
                        548     END_FOR                         
                        550     SWAP                            2
                        552     STORE_FAST                      6: _var_var_34
                        554     LOAD_FAST                       5: _var_var_33
                        556     STORE_ATTR                      6: var_mappings
                        566     JUMP_FORWARD                    14 (to 596)
                        568     LOAD_GLOBAL                     27: NULL + ValueError
                        578     LOAD_CONST                      7: 'Invalid var_name: '
                        580     LOAD_FAST                       2: var_name
                        582     FORMAT_VALUE                    0 (FVC_NONE)
                        584     BUILD_STRING                    2
                        586     CALL                            1
                        594     RAISE_VARARGS                   1
                        596     LOAD_FAST                       0: self
                        598     LOAD_ATTR                       29: analyze_function_dataflow_forward
                        618     LOAD_FAST                       1: func_ea
                        620     LOAD_FAST                       5: _var_var_33
                        622     CALL                            2
                        630     POP_TOP                         
                        632     LOAD_FAST                       0: self
                        634     LOAD_ATTR                       31: analyze_function_dataflow_backward
                        654     LOAD_FAST                       1: func_ea
                        656     LOAD_FAST                       5: _var_var_33
                        658     CALL                            2
                        666     POP_TOP                         
                        668     LOAD_GLOBAL                     33: NULL + dict
                        678     CALL                            0
                        686     STORE_FAST                      9: _var_var_35
                        688     LOAD_FAST                       0: self
                        690     LOAD_ATTR                       4: usage_lines
                        710     GET_ITER                        
                        712     FOR_ITER                        74 (to 862)
                        716     STORE_FAST                      8: _var_var_3
                        718     LOAD_FAST                       8: _var_var_3
                        720     LOAD_ATTR                       34: func_name
                        740     FORMAT_VALUE                    0 (FVC_NONE)
                        742     LOAD_FAST                       8: _var_var_3
                        744     LOAD_ATTR                       36: line_addr
                        764     FORMAT_VALUE                    0 (FVC_NONE)
                        766     LOAD_FAST                       8: _var_var_3
                        768     LOAD_ATTR                       38: pcode_line
                        788     FORMAT_VALUE                    0 (FVC_NONE)
                        790     LOAD_FAST                       8: _var_var_3
                        792     LOAD_ATTR                       40: alias_name
                        812     FORMAT_VALUE                    0 (FVC_NONE)
                        814     LOAD_FAST                       8: _var_var_3
                        816     LOAD_ATTR                       42: var_name
                        836     FORMAT_VALUE                    0 (FVC_NONE)
                        838     BUILD_STRING                    5
                        840     STORE_FAST                      10: _var_var_36
                        842     LOAD_FAST                       10: _var_var_36
                        844     LOAD_FAST                       9: _var_var_35
                        846     CONTAINS_OP                     0 (in)
                        848     POP_JUMP_IF_FALSE               1 (to 852)
                        850     JUMP_BACKWARD                   70 (to 712)
                        852     LOAD_FAST                       8: _var_var_3
                        854     LOAD_FAST                       9: _var_var_35
                        856     LOAD_FAST                       10: _var_var_36
                        858     STORE_SUBSCR                    
                        862     JUMP_BACKWARD                   76 (to 712)
                        864     END_FOR                         
                        866     LOAD_GLOBAL                     33: NULL + dict
                        876     CALL                            0
                        884     STORE_FAST                      11: _var_var_37
                        886     LOAD_GLOBAL                     33: NULL + dict
                        896     CALL                            0
                        904     STORE_FAST                      12: _var_var_38
                        906     LOAD_FAST                       9: _var_var_35
                        908     LOAD_ATTR                       45: values
                        928     CALL                            0
                        936     GET_ITER                        
                        938     FOR_ITER                        282 (to 1506)
                        944     STORE_FAST                      8: _var_var_3
                        946     LOAD_FAST                       8: _var_var_3
                        948     LOAD_ATTR                       34: func_name
                        968     FORMAT_VALUE                    0 (FVC_NONE)
                        970     LOAD_FAST                       8: _var_var_3
                        972     LOAD_ATTR                       36: line_addr
                        992     FORMAT_VALUE                    0 (FVC_NONE)
                        994     LOAD_FAST                       8: _var_var_3
                        996     LOAD_ATTR                       38: pcode_line
                        1016    FORMAT_VALUE                    0 (FVC_NONE)
                        1018    BUILD_STRING                    3
                        1020    STORE_FAST                      10: _var_var_36
                        1022    LOAD_FAST                       8: _var_var_3
                        1024    LOAD_ATTR                       46: context_depth
                        1044    LOAD_CONST                      8: 0
                        1046    COMPARE_OP                      55 (!=)
                        1050    POP_JUMP_IF_FALSE               40 (to 1132)
                        1052    LOAD_CONST                      9: 'call'
                        1054    LOAD_FAST                       8: _var_var_3
                        1056    LOAD_ATTR                       48: access_type
                        1076    CONTAINS_OP                     1 (not in)
                        1078    POP_JUMP_IF_FALSE               26 (to 1132)
                        1080    LOAD_FAST                       8: _var_var_3
                        1082    LOAD_ATTR                       40: alias_name
                        1102    LOAD_FAST                       8: _var_var_3
                        1104    LOAD_ATTR                       42: var_name
                        1124    COMPARE_OP                      40 (==)
                        1128    POP_JUMP_IF_FALSE               1 (to 1132)
                        1130    JUMP_BACKWARD                   97 (to 938)
                        1132    LOAD_FAST                       10: _var_var_36
                        1134    LOAD_FAST                       11: _var_var_37
                        1136    CONTAINS_OP                     0 (in)
                        1138    POP_JUMP_IF_FALSE               123 (to 1386)
                        1140    LOAD_FAST                       3: verbose
                        1142    POP_JUMP_IF_FALSE               65 (to 1274)
                        1144    LOAD_FAST                       12: _var_var_38
                        1146    LOAD_FAST                       10: _var_var_36
                        1148    BINARY_SUBSCR                   
                        1152    LOAD_CONST                      8: 0
                        1154    COPY                            2
                        1156    COPY                            2
                        1158    BINARY_SUBSCR                   
                        1162    LOAD_GLOBAL                     51: NULL + colored
                        1172    LOAD_CONST                      10: ', '
                        1174    LOAD_FAST                       8: _var_var_3
                        1176    LOAD_ATTR                       52: var_type
                        1196    FORMAT_VALUE                    0 (FVC_NONE)
                        1198    LOAD_CONST                      11: ' '
                        1200    LOAD_FAST                       8: _var_var_3
                        1202    LOAD_ATTR                       42: var_name
                        1222    FORMAT_VALUE                    0 (FVC_NONE)
                        1224    LOAD_CONST                      12: ' == '
                        1226    LOAD_FAST                       8: _var_var_3
                        1228    LOAD_ATTR                       40: alias_name
                        1248    FORMAT_VALUE                    0 (FVC_NONE)
                        1250    BUILD_STRING                    6
                        1252    LOAD_CONST                      13: 'green'
                        1254    CALL                            2
                        1262    BINARY_OP                       13 (+=)
                        1266    SWAP                            3
                        1268    SWAP                            2
                        1270    STORE_SUBSCR                    
                        1274    LOAD_FAST                       11: _var_var_37
                        1276    LOAD_FAST                       10: _var_var_36
                        1278    BINARY_SUBSCR                   
                        1282    LOAD_CONST                      8: 0
                        1284    COPY                            2
                        1286    COPY                            2
                        1288    BINARY_SUBSCR                   
                        1292    LOAD_CONST                      10: ', '
                        1294    LOAD_FAST                       8: _var_var_3
                        1296    LOAD_ATTR                       52: var_type
                        1316    FORMAT_VALUE                    0 (FVC_NONE)
                        1318    LOAD_CONST                      11: ' '
                        1320    LOAD_FAST                       8: _var_var_3
                        1322    LOAD_ATTR                       42: var_name
                        1342    FORMAT_VALUE                    0 (FVC_NONE)
                        1344    LOAD_CONST                      12: ' == '
                        1346    LOAD_FAST                       8: _var_var_3
                        1348    LOAD_ATTR                       40: alias_name
                        1368    FORMAT_VALUE                    0 (FVC_NONE)
                        1370    BUILD_STRING                    6
                        1372    BINARY_OP                       13 (+=)
                        1376    SWAP                            3
                        1378    SWAP                            2
                        1380    STORE_SUBSCR                    
                        1384    JUMP_BACKWARD                   224 (to 938)
                        1386    LOAD_FAST                       3: verbose
                        1388    POP_JUMP_IF_FALSE               31 (to 1452)
                        1390    LOAD_FAST                       8: _var_var_3
                        1392    LOAD_ATTR                       55: colored_print
                        1412    CALL                            0
                        1420    LOAD_FAST                       8: _var_var_3
                        1422    LOAD_ATTR                       46: context_depth
                        1442    BUILD_LIST                      2
                        1444    LOAD_FAST                       12: _var_var_38
                        1446    LOAD_FAST                       10: _var_var_36
                        1448    STORE_SUBSCR                    
                        1452    LOAD_GLOBAL                     11: NULL + str
                        1462    LOAD_FAST                       8: _var_var_3
                        1464    CALL                            1
                        1472    LOAD_FAST                       8: _var_var_3
                        1474    LOAD_ATTR                       46: context_depth
                        1494    BUILD_LIST                      2
                        1496    LOAD_FAST                       11: _var_var_37
                        1498    LOAD_FAST                       10: _var_var_36
                        1500    STORE_SUBSCR                    
                        1504    JUMP_BACKWARD                   285 (to 938)
                        1508    END_FOR                         
                        1510    LOAD_FAST                       11: _var_var_37
                        1512    LOAD_ATTR                       45: values
                        1532    CALL                            0
                        1540    STORE_FAST                      9: _var_var_35
                        1542    LOAD_GLOBAL                     57: NULL + demangle
                        1552    LOAD_GLOBAL                     59: NULL + idc
                        1562    LOAD_ATTR                       60: get_func_name
                        1582    LOAD_FAST                       1: func_ea
                        1584    CALL                            1
                        1592    CALL                            1
                        1600    STORE_FAST                      13: _var_var_39
                        1602    LOAD_FAST                       3: verbose
                        1604    POP_JUMP_IF_FALSE               136 (to 1878)
                        1606    LOAD_FAST                       12: _var_var_38
                        1608    LOAD_ATTR                       45: values
                        1628    CALL                            0
                        1636    STORE_FAST                      12: _var_var_38
                        1638    LOAD_GLOBAL                     63: NULL + print
                        1648    LOAD_CONST                      14: '==== final usages for traced variable: `'
                        1650    LOAD_GLOBAL                     51: NULL + colored
                        1660    LOAD_FAST                       2: var_name
                        1662    LOAD_CONST                      13: 'green'
                        1664    CALL                            2
                        1672    FORMAT_VALUE                    0 (FVC_NONE)
                        1674    LOAD_CONST                      15: '` in `'
                        1676    LOAD_GLOBAL                     51: NULL + colored
                        1686    LOAD_FAST                       13: _var_var_39
                        1688    LOAD_CONST                      13: 'green'
                        1690    CALL                            2
                        1698    FORMAT_VALUE                    0 (FVC_NONE)
                        1700    LOAD_CONST                      16: '` ===='
                        1702    BUILD_STRING                    5
                        1704    CALL                            1
                        1712    POP_TOP                         
                        1714    LOAD_GLOBAL                     63: NULL + print
                        1724    LOAD_CONST                      17: '---- trace callee usages 🚀----'
                        1726    CALL                            1
                        1734    POP_TOP                         
                        1736    LOAD_FAST                       12: _var_var_38
                        1738    GET_ITER                        
                        1740    FOR_ITER                        25 (to 1792)
                        1744    STORE_FAST                      8: _var_var_3
                        1746    LOAD_FAST                       8: _var_var_3
                        1748    LOAD_CONST                      18: 1
                        1750    BINARY_SUBSCR                   
                        1754    LOAD_CONST                      8: 0
                        1756    COMPARE_OP                      92 (>=)
                        1760    POP_JUMP_IF_TRUE                1 (to 1764)
                        1762    JUMP_BACKWARD                   12 (to 1740)
                        1764    LOAD_GLOBAL                     63: NULL + print
                        1774    LOAD_FAST                       8: _var_var_3
                        1776    LOAD_CONST                      8: 0
                        1778    BINARY_SUBSCR                   
                        1782    CALL                            1
                        1790    POP_TOP                         
                        1792    JUMP_BACKWARD                   27 (to 1740)
                        1794    END_FOR                         
                        1796    LOAD_GLOBAL                     63: NULL + print
                        1806    LOAD_CONST                      19: '---- trace caller usages 🚀----'
                        1808    CALL                            1
                        1816    POP_TOP                         
                        1818    LOAD_FAST                       12: _var_var_38
                        1820    GET_ITER                        
                        1822    FOR_ITER                        25 (to 1874)
                        1826    STORE_FAST                      8: _var_var_3
                        1828    LOAD_FAST                       8: _var_var_3
                        1830    LOAD_CONST                      18: 1
                        1832    BINARY_SUBSCR                   
                        1836    LOAD_CONST                      8: 0
                        1838    COMPARE_OP                      2 (<)
                        1842    POP_JUMP_IF_TRUE                1 (to 1846)
                        1844    JUMP_BACKWARD                   12 (to 1822)
                        1846    LOAD_GLOBAL                     63: NULL + print
                        1856    LOAD_FAST                       8: _var_var_3
                        1858    LOAD_CONST                      8: 0
                        1860    BINARY_SUBSCR                   
                        1864    CALL                            1
                        1872    POP_TOP                         
                        1874    JUMP_BACKWARD                   27 (to 1822)
                        1876    END_FOR                         
                        1878    LOAD_CONST                      14: '==== final usages for traced variable: `'
                        1880    LOAD_FAST                       2: var_name
                        1882    FORMAT_VALUE                    0 (FVC_NONE)
                        1884    LOAD_CONST                      15: '` in `'
                        1886    LOAD_FAST                       13: _var_var_39
                        1888    FORMAT_VALUE                    0 (FVC_NONE)
                        1890    LOAD_CONST                      20: '` ====\n'
                        1892    BUILD_STRING                    5
                        1894    STORE_FAST                      14: _var_var_40
                        1896    LOAD_FAST                       14: _var_var_40
                        1898    LOAD_CONST                      21: '---- trace callee usages ----\n'
                        1900    BINARY_OP                       13 (+=)
                        1904    STORE_FAST                      14: _var_var_40
                        1906    LOAD_FAST                       14: _var_var_40
                        1908    LOAD_CONST                      22: '\n'
                        1910    LOAD_ATTR                       65: join
                        1930    LOAD_FAST                       9: _var_var_35
                        1932    GET_ITER                        
                        1934    LOAD_FAST_AND_CLEAR             8: _var_var_3
                        1936    SWAP                            2
                        1938    BUILD_LIST                      0
                        1940    SWAP                            2
                        1942    FOR_ITER                        16 (to 1976)
                        1946    STORE_FAST                      8: _var_var_3
                        1948    LOAD_FAST                       8: _var_var_3
                        1950    LOAD_CONST                      18: 1
                        1952    BINARY_SUBSCR                   
                        1956    LOAD_CONST                      8: 0
                        1958    COMPARE_OP                      92 (>=)
                        1962    POP_JUMP_IF_TRUE                1 (to 1966)
                        1964    JUMP_BACKWARD                   12 (to 1942)
                        1966    LOAD_FAST                       8: _var_var_3
                        1968    LOAD_CONST                      8: 0
                        1970    BINARY_SUBSCR                   
                        1974    LIST_APPEND                     2
                        1976    JUMP_BACKWARD                   18 (to 1942)
                        1978    END_FOR                         
                        1980    SWAP                            2
                        1982    STORE_FAST                      8: _var_var_3
                        1984    CALL                            1
                        1992    BINARY_OP                       13 (+=)
                        1996    STORE_FAST                      14: _var_var_40
                        1998    LOAD_FAST                       14: _var_var_40
                        2000    LOAD_CONST                      23: '\n---- trace caller usages ----\n'
                        2002    BINARY_OP                       13 (+=)
                        2006    STORE_FAST                      14: _var_var_40
                        2008    LOAD_FAST                       14: _var_var_40
                        2010    LOAD_CONST                      22: '\n'
                        2012    LOAD_ATTR                       65: join
                        2032    LOAD_FAST                       9: _var_var_35
                        2034    GET_ITER                        
                        2036    LOAD_FAST_AND_CLEAR             8: _var_var_3
                        2038    SWAP                            2
                        2040    BUILD_LIST                      0
                        2042    SWAP                            2
                        2044    FOR_ITER                        16 (to 2078)
                        2048    STORE_FAST                      8: _var_var_3
                        2050    LOAD_FAST                       8: _var_var_3
                        2052    LOAD_CONST                      18: 1
                        2054    BINARY_SUBSCR                   
                        2058    LOAD_CONST                      8: 0
                        2060    COMPARE_OP                      2 (<)
                        2064    POP_JUMP_IF_TRUE                1 (to 2068)
                        2066    JUMP_BACKWARD                   12 (to 2044)
                        2068    LOAD_FAST                       8: _var_var_3
                        2070    LOAD_CONST                      8: 0
                        2072    BINARY_SUBSCR                   
                        2076    LIST_APPEND                     2
                        2078    JUMP_BACKWARD                   18 (to 2044)
                        2080    END_FOR                         
                        2082    SWAP                            2
                        2084    STORE_FAST                      8: _var_var_3
                        2086    CALL                            1
                        2094    BINARY_OP                       13 (+=)
                        2098    STORE_FAST                      14: _var_var_40
                        2100    LOAD_FAST                       14: _var_var_40
                        2102    NOP                             
                        2104    NOP                             
                        2106    NOP                             
                        2108    JUMP_FORWARD                    45 (to 2200)
                        2110    CALL                            1
                        2118    POP_TOP                         
                        2120    RETURN_VALUE                    
                        2122    SWAP                            2
                        2124    POP_TOP                         
                        2126    SWAP                            2
                        2128    STORE_FAST                      6: _var_var_34
                        2130    RERAISE                         0
                        2132    SWAP                            2
                        2134    POP_TOP                         
                        2136    SWAP                            2
                        2138    STORE_FAST                      8: _var_var_3
                        2140    RERAISE                         0
                        2142    SWAP                            2
                        2144    POP_TOP                         
                        2146    SWAP                            2
                        2148    STORE_FAST                      6: _var_var_34
                        2150    RERAISE                         0
                        2152    SWAP                            2
                        2154    POP_TOP                         
                        2156    SWAP                            2
                        2158    STORE_FAST                      8: _var_var_3
                        2160    RERAISE                         0
                        2162    SWAP                            2
                        2164    POP_TOP                         
                        2166    SWAP                            2
                        2168    STORE_FAST                      8: _var_var_3
                        2170    RERAISE                         0
                        2172    PUSH_EXC_INFO                   
                        2174    PUSH_NULL                       
                        2176    LOAD_CONST                      5: '__pyarmor_exit_54822__'
                        2178    NOP                             
                        2180    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ab\x08\x00\x00\x00\x00\x00\x00'
                        2182    CALL                            1
                        2190    POP_TOP                         
                        2192    RERAISE                         0
                        2194    COPY                            3
                        2196    POP_EXCEPT                      
                        2198    RERAISE                         1
                        2200    PUSH_NULL                       
                        2202    LOAD_CONST                      5: '__pyarmor_exit_54822__'
                        2204    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ab\x08\x00\x00\x00\x00\x00\x00'
                        2206    BUILD_TUPLE                     1
                        2208    CALL_FUNCTION_EX                0
                        2210    POP_TOP                         
                        2212    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: filter_data_flow_by_context_func
                    Qualified Name: DataFlowAnalyzer.filter_data_flow_by_context_func
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 10
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'set'
                        'demangle'
                        'ida_funcs'
                        'get_func_name'
                        'dict'
                        'usage_lines'
                        'func_name'
                        'line_addr'
                        'pcode_line'
                        'alias_name'
                        'var_name'
                        'values'
                        'context_depth'
                        'access_type'
                        'var_type'
                        'str'
                        'split'
                        'join'
                    [Locals+Names]
                        'self'
                        'original_data_flow_str'
                        'context_funcs'
                        '__assert_armored__'
                        '_var_var_41'
                        '_var_var_42'
                        '_var_var_35'
                        '_var_var_3'
                        '_var_var_36'
                        '_var_var_37'
                        '_var_var_40'
                    [Constants]
                        'filter data flow, keep the ones within context_funcs'
                        '__pyarmor_assert_54823__'
                        '__pyarmor_enter_54824__'
                        b'<COAddr>\x03\x00\x00\x1aB\x04\x00\x00\x00\x00\x00\x00'
                        0
                        'call'
                        ', '
                        ' '
                        ' == '
                        '\n'
                        '---- trace callee usages ----\n'
                        1
                        '\n---- trace caller usages ----\n'
                        '__pyarmor_exit_54825__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54824__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aB\x04\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + set
                        38      LOAD_FAST                       2: context_funcs
                        40      GET_ITER                        
                        42      LOAD_FAST_AND_CLEAR             4: _var_var_41
                        44      SWAP                            2
                        46      BUILD_LIST                      0
                        48      SWAP                            2
                        50      FOR_ITER                        32 (to 116)
                        54      STORE_FAST                      4: _var_var_41
                        56      LOAD_GLOBAL                     3: NULL + demangle
                        66      LOAD_GLOBAL                     5: NULL + ida_funcs
                        76      LOAD_ATTR                       6: get_func_name
                        96      LOAD_FAST                       4: _var_var_41
                        98      CALL                            1
                        106     CALL                            1
                        114     LIST_APPEND                     2
                        116     JUMP_BACKWARD                   34 (to 50)
                        118     END_FOR                         
                        120     SWAP                            2
                        122     STORE_FAST                      4: _var_var_41
                        124     CALL                            1
                        132     STORE_FAST                      5: _var_var_42
                        134     LOAD_GLOBAL                     9: NULL + dict
                        144     CALL                            0
                        152     STORE_FAST                      6: _var_var_35
                        154     LOAD_FAST                       0: self
                        156     LOAD_ATTR                       10: usage_lines
                        176     GET_ITER                        
                        178     FOR_ITER                        89 (to 358)
                        182     STORE_FAST                      7: _var_var_3
                        184     LOAD_FAST                       7: _var_var_3
                        186     LOAD_ATTR                       12: func_name
                        206     LOAD_FAST                       5: _var_var_42
                        208     CONTAINS_OP                     1 (not in)
                        210     POP_JUMP_IF_FALSE               1 (to 214)
                        212     JUMP_BACKWARD                   18 (to 178)
                        214     LOAD_FAST                       7: _var_var_3
                        216     LOAD_ATTR                       12: func_name
                        236     FORMAT_VALUE                    0 (FVC_NONE)
                        238     LOAD_FAST                       7: _var_var_3
                        240     LOAD_ATTR                       14: line_addr
                        260     FORMAT_VALUE                    0 (FVC_NONE)
                        262     LOAD_FAST                       7: _var_var_3
                        264     LOAD_ATTR                       16: pcode_line
                        284     FORMAT_VALUE                    0 (FVC_NONE)
                        286     LOAD_FAST                       7: _var_var_3
                        288     LOAD_ATTR                       18: alias_name
                        308     FORMAT_VALUE                    0 (FVC_NONE)
                        310     LOAD_FAST                       7: _var_var_3
                        312     LOAD_ATTR                       20: var_name
                        332     FORMAT_VALUE                    0 (FVC_NONE)
                        334     BUILD_STRING                    5
                        336     STORE_FAST                      8: _var_var_36
                        338     LOAD_FAST                       8: _var_var_36
                        340     LOAD_FAST                       6: _var_var_35
                        342     CONTAINS_OP                     0 (in)
                        344     POP_JUMP_IF_FALSE               1 (to 348)
                        346     JUMP_BACKWARD                   85 (to 178)
                        348     LOAD_FAST                       7: _var_var_3
                        350     LOAD_FAST                       6: _var_var_35
                        352     LOAD_FAST                       8: _var_var_36
                        354     STORE_SUBSCR                    
                        358     JUMP_BACKWARD                   91 (to 178)
                        360     END_FOR                         
                        362     LOAD_GLOBAL                     9: NULL + dict
                        372     CALL                            0
                        380     STORE_FAST                      9: _var_var_37
                        382     LOAD_FAST                       6: _var_var_35
                        384     LOAD_ATTR                       23: values
                        404     CALL                            0
                        412     GET_ITER                        
                        414     FOR_ITER                        181 (to 778)
                        418     STORE_FAST                      7: _var_var_3
                        420     LOAD_FAST                       7: _var_var_3
                        422     LOAD_ATTR                       12: func_name
                        442     FORMAT_VALUE                    0 (FVC_NONE)
                        444     LOAD_FAST                       7: _var_var_3
                        446     LOAD_ATTR                       14: line_addr
                        466     FORMAT_VALUE                    0 (FVC_NONE)
                        468     LOAD_FAST                       7: _var_var_3
                        470     LOAD_ATTR                       16: pcode_line
                        490     FORMAT_VALUE                    0 (FVC_NONE)
                        492     BUILD_STRING                    3
                        494     STORE_FAST                      8: _var_var_36
                        496     LOAD_FAST                       7: _var_var_3
                        498     LOAD_ATTR                       24: context_depth
                        518     LOAD_CONST                      4: 0
                        520     COMPARE_OP                      55 (!=)
                        524     POP_JUMP_IF_FALSE               40 (to 606)
                        526     LOAD_CONST                      5: 'call'
                        528     LOAD_FAST                       7: _var_var_3
                        530     LOAD_ATTR                       26: access_type
                        550     CONTAINS_OP                     1 (not in)
                        552     POP_JUMP_IF_FALSE               26 (to 606)
                        554     LOAD_FAST                       7: _var_var_3
                        556     LOAD_ATTR                       18: alias_name
                        576     LOAD_FAST                       7: _var_var_3
                        578     LOAD_ATTR                       20: var_name
                        598     COMPARE_OP                      40 (==)
                        602     POP_JUMP_IF_FALSE               1 (to 606)
                        604     JUMP_BACKWARD                   96 (to 414)
                        606     LOAD_FAST                       8: _var_var_36
                        608     LOAD_FAST                       9: _var_var_37
                        610     CONTAINS_OP                     0 (in)
                        612     POP_JUMP_IF_FALSE               56 (to 726)
                        614     LOAD_FAST                       9: _var_var_37
                        616     LOAD_FAST                       8: _var_var_36
                        618     BINARY_SUBSCR                   
                        622     LOAD_CONST                      4: 0
                        624     COPY                            2
                        626     COPY                            2
                        628     BINARY_SUBSCR                   
                        632     LOAD_CONST                      6: ', '
                        634     LOAD_FAST                       7: _var_var_3
                        636     LOAD_ATTR                       28: var_type
                        656     FORMAT_VALUE                    0 (FVC_NONE)
                        658     LOAD_CONST                      7: ' '
                        660     LOAD_FAST                       7: _var_var_3
                        662     LOAD_ATTR                       20: var_name
                        682     FORMAT_VALUE                    0 (FVC_NONE)
                        684     LOAD_CONST                      8: ' == '
                        686     LOAD_FAST                       7: _var_var_3
                        688     LOAD_ATTR                       18: alias_name
                        708     FORMAT_VALUE                    0 (FVC_NONE)
                        710     BUILD_STRING                    6
                        712     BINARY_OP                       13 (+=)
                        716     SWAP                            3
                        718     SWAP                            2
                        720     STORE_SUBSCR                    
                        724     JUMP_BACKWARD                   156 (to 414)
                        726     LOAD_GLOBAL                     31: NULL + str
                        736     LOAD_FAST                       7: _var_var_3
                        738     CALL                            1
                        746     LOAD_FAST                       7: _var_var_3
                        748     LOAD_ATTR                       24: context_depth
                        768     BUILD_LIST                      2
                        770     LOAD_FAST                       9: _var_var_37
                        772     LOAD_FAST                       8: _var_var_36
                        774     STORE_SUBSCR                    
                        778     JUMP_BACKWARD                   183 (to 414)
                        780     END_FOR                         
                        782     LOAD_FAST                       9: _var_var_37
                        784     LOAD_ATTR                       23: values
                        804     CALL                            0
                        812     STORE_FAST                      6: _var_var_35
                        814     LOAD_FAST                       1: original_data_flow_str
                        816     LOAD_ATTR                       33: split
                        836     LOAD_CONST                      9: '\n'
                        838     CALL                            1
                        846     LOAD_CONST                      4: 0
                        848     BINARY_SUBSCR                   
                        852     LOAD_CONST                      9: '\n'
                        854     BINARY_OP                       0 (+)
                        858     STORE_FAST                      10: _var_var_40
                        860     LOAD_FAST                       10: _var_var_40
                        862     LOAD_CONST                      10: '---- trace callee usages ----\n'
                        864     BINARY_OP                       13 (+=)
                        868     STORE_FAST                      10: _var_var_40
                        870     LOAD_FAST                       10: _var_var_40
                        872     LOAD_CONST                      9: '\n'
                        874     LOAD_ATTR                       35: join
                        894     LOAD_FAST                       6: _var_var_35
                        896     GET_ITER                        
                        898     LOAD_FAST_AND_CLEAR             7: _var_var_3
                        900     SWAP                            2
                        902     BUILD_LIST                      0
                        904     SWAP                            2
                        906     FOR_ITER                        16 (to 940)
                        910     STORE_FAST                      7: _var_var_3
                        912     LOAD_FAST                       7: _var_var_3
                        914     LOAD_CONST                      11: 1
                        916     BINARY_SUBSCR                   
                        920     LOAD_CONST                      4: 0
                        922     COMPARE_OP                      92 (>=)
                        926     POP_JUMP_IF_TRUE                1 (to 930)
                        928     JUMP_BACKWARD                   12 (to 906)
                        930     LOAD_FAST                       7: _var_var_3
                        932     LOAD_CONST                      4: 0
                        934     BINARY_SUBSCR                   
                        938     LIST_APPEND                     2
                        940     JUMP_BACKWARD                   18 (to 906)
                        942     END_FOR                         
                        944     SWAP                            2
                        946     STORE_FAST                      7: _var_var_3
                        948     CALL                            1
                        956     BINARY_OP                       13 (+=)
                        960     STORE_FAST                      10: _var_var_40
                        962     LOAD_FAST                       10: _var_var_40
                        964     LOAD_CONST                      12: '\n---- trace caller usages ----\n'
                        966     BINARY_OP                       13 (+=)
                        970     STORE_FAST                      10: _var_var_40
                        972     LOAD_FAST                       10: _var_var_40
                        974     LOAD_CONST                      9: '\n'
                        976     LOAD_ATTR                       35: join
                        996     LOAD_FAST                       6: _var_var_35
                        998     GET_ITER                        
                        1000    LOAD_FAST_AND_CLEAR             7: _var_var_3
                        1002    SWAP                            2
                        1004    BUILD_LIST                      0
                        1006    SWAP                            2
                        1008    FOR_ITER                        16 (to 1042)
                        1012    STORE_FAST                      7: _var_var_3
                        1014    LOAD_FAST                       7: _var_var_3
                        1016    LOAD_CONST                      11: 1
                        1018    BINARY_SUBSCR                   
                        1022    LOAD_CONST                      4: 0
                        1024    COMPARE_OP                      2 (<)
                        1028    POP_JUMP_IF_TRUE                1 (to 1032)
                        1030    JUMP_BACKWARD                   12 (to 1008)
                        1032    LOAD_FAST                       7: _var_var_3
                        1034    LOAD_CONST                      4: 0
                        1036    BINARY_SUBSCR                   
                        1040    LIST_APPEND                     2
                        1042    JUMP_BACKWARD                   18 (to 1008)
                        1044    END_FOR                         
                        1046    SWAP                            2
                        1048    STORE_FAST                      7: _var_var_3
                        1050    CALL                            1
                        1058    BINARY_OP                       13 (+=)
                        1062    STORE_FAST                      10: _var_var_40
                        1064    LOAD_FAST                       10: _var_var_40
                        1066    NOP                             
                        1068    NOP                             
                        1070    NOP                             
                        1072    JUMP_FORWARD                    35 (to 1144)
                        1074    CALL                            1
                        1082    POP_TOP                         
                        1084    RETURN_VALUE                    
                        1086    SWAP                            2
                        1088    POP_TOP                         
                        1090    SWAP                            2
                        1092    STORE_FAST                      4: _var_var_41
                        1094    RERAISE                         0
                        1096    SWAP                            2
                        1098    POP_TOP                         
                        1100    SWAP                            2
                        1102    STORE_FAST                      7: _var_var_3
                        1104    RERAISE                         0
                        1106    SWAP                            2
                        1108    POP_TOP                         
                        1110    SWAP                            2
                        1112    STORE_FAST                      7: _var_var_3
                        1114    RERAISE                         0
                        1116    PUSH_EXC_INFO                   
                        1118    PUSH_NULL                       
                        1120    LOAD_CONST                      13: '__pyarmor_exit_54825__'
                        1122    NOP                             
                        1124    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aB\x04\x00\x00\x00\x00\x00\x00'
                        1126    CALL                            1
                        1134    POP_TOP                         
                        1136    RERAISE                         0
                        1138    COPY                            3
                        1140    POP_EXCEPT                      
                        1142    RERAISE                         1
                        1144    PUSH_NULL                       
                        1146    LOAD_CONST                      13: '__pyarmor_exit_54825__'
                        1148    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aB\x04\x00\x00\x00\x00\x00\x00'
                        1150    BUILD_TUPLE                     1
                        1152    CALL_FUNCTION_EX                0
                        1154    POP_TOP                         
                        1156    RETURN_VALUE                    
                '__pyarmor_exit_54795__'
                (
                    None
                )
                (
                    None
                    False
                )
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'DataFlowAnalyzer'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_54794__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      PUSH_NULL                       
                38      LOAD_NAME                       4: set
                40      CALL                            0
                48      BUILD_TUPLE                     1
                50      LOAD_CONST                      4: <CODE> __init__
                52      MAKE_FUNCTION                   1
                54      STORE_NAME                      5: __init__
                56      LOAD_CONST                      5: <CODE> _get_func_args
                58      MAKE_FUNCTION                   0
                60      STORE_NAME                      6: _get_func_args
                62      LOAD_CONST                      6: <CODE> _get_pcode_line
                64      MAKE_FUNCTION                   0
                66      STORE_NAME                      7: _get_pcode_line
                68      LOAD_CONST                      13: (None,)
                70      LOAD_CONST                      8: <CODE> analyze_function_dataflow_forward
                72      MAKE_FUNCTION                   1
                74      STORE_NAME                      8: analyze_function_dataflow_forward
                76      LOAD_CONST                      13: (None,)
                78      LOAD_CONST                      9: <CODE> analyze_function_dataflow_backward
                80      MAKE_FUNCTION                   1
                82      STORE_NAME                      9: analyze_function_dataflow_backward
                84      LOAD_CONST                      14: (None, False)
                86      LOAD_CONST                      10: <CODE> get_var_dataflow
                88      MAKE_FUNCTION                   1
                90      STORE_NAME                      10: get_var_dataflow
                92      LOAD_CONST                      11: <CODE> filter_data_flow_by_context_func
                94      MAKE_FUNCTION                   0
                96      STORE_NAME                      11: filter_data_flow_by_context_func
                98      LOAD_CONST                      7: None
                100     NOP                             
                102     NOP                             
                104     NOP                             
                106     JUMP_FORWARD                    19 (to 146)
                114     POP_TOP                         
                116     RETURN_CONST                    7: None
                118     PUSH_EXC_INFO                   
                120     PUSH_NULL                       
                122     LOAD_CONST                      12: '__pyarmor_exit_54795__'
                124     NOP                             
                126     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                128     CALL                            1
                136     POP_TOP                         
                138     RERAISE                         0
                140     COPY                            3
                142     POP_EXCEPT                      
                144     RERAISE                         1
                146     PUSH_NULL                       
                148     LOAD_CONST                      12: '__pyarmor_exit_54795__'
                150     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                152     BUILD_TUPLE                     1
                154     CALL_FUNCTION_EX                0
                156     POP_TOP                         
                158     RETURN_VALUE                    
        'DataFlowAnalyzer'
        [Code]
            File Name: <frozen ..data_flow>
            Object Name: DataFlowVisitor
            Qualified Name: DataFlowVisitor
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 9
            Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
            [Names]
                '__name__'
                '__module__'
                '__qualname__'
                '__assert_armored__'
                'DataFlowAnalyzer'
                'FunctionContext'
                'set'
                'dict'
                '__init__'
                '_find_final_alias'
                '_track_var_in_expr'
                '_track_var_in_callee'
                '_track_var_in_asg'
                'visit_expr'
                'visit_insn'
            [Locals+Names]
            [Constants]
                'DataFlowVisitor'
                '__pyarmor_assert_54826__'
                '__pyarmor_enter_54827__'
                b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                None
                'analyzer'
                'context'
                'tracked_vars'
                'alias_mapping'
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: __init__
                    Qualified Name: DataFlowVisitor.__init__
                    Arg Count: 6
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 11
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_hexrays'
                        'ctree_visitor_t'
                        '__init__'
                        'CV_PARENTS'
                        'CV_FAST'
                        'CV_PRUNE'
                        'analyzer'
                        'context'
                        'tracked_vars'
                        'defaultdict'
                        'list'
                        'usage_lines'
                        'dict'
                        'alias_mapping'
                        'current_cfunc'
                        'entry_ea'
                        'current_func_ea'
                        'demangle'
                        'ida_funcs'
                        'get_func_name'
                        'current_func_name'
                        'not_trace_callee'
                        'get_lvars'
                        'name'
                        'type'
                        'dstr'
                        'copy'
                        'is_array'
                        'remove_ptr_or_array'
                        'is_arg_var'
                        'find_var_declaration'
                        'get'
                        'VarUsage'
                        'depth'
                        'append'
                    [Locals+Names]
                        'self'
                        'analyzer'
                        'context'
                        'tracked_vars'
                        'alias_mapping'
                        'not_trace_callee'
                        '__assert_armored__'
                        '_var_var_21'
                        '_var_var_43'
                        '_var_var_44'
                        '_var_var_45'
                        '_var_var_46'
                        '_var_var_13'
                        '_var_var_31'
                        '_var_var_47'
                    [Constants]
                        None
                        '__pyarmor_assert_54829__'
                        '__pyarmor_enter_54830__'
                        b'<COAddr>\x03\x00\x00\x1a\x10\x05\x00\x00\x00\x00\x00\x00'
                        True
                        (
                            'is_arg'
                        )
                        'decl'
                        (
                            'access_type'
                            'alias_name'
                            'line_addr'
                            'func_name'
                            'context_depth'
                        )
                        '__pyarmor_exit_54831__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54830__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x10\x05\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     0: ida_hexrays
                        38      LOAD_ATTR                       2: ctree_visitor_t
                        58      LOAD_ATTR                       5: __init__
                        78      LOAD_FAST                       0: self
                        80      LOAD_GLOBAL                     0: ida_hexrays
                        90      LOAD_ATTR                       6: CV_PARENTS
                        110     LOAD_GLOBAL                     0: ida_hexrays
                        120     LOAD_ATTR                       8: CV_FAST
                        140     BINARY_OP                       7 (|)
                        144     LOAD_GLOBAL                     0: ida_hexrays
                        154     LOAD_ATTR                       10: CV_PRUNE
                        174     BINARY_OP                       7 (|)
                        178     CALL                            2
                        186     POP_TOP                         
                        188     LOAD_FAST                       1: analyzer
                        190     LOAD_FAST                       0: self
                        192     STORE_ATTR                      6: analyzer
                        202     LOAD_FAST                       2: context
                        204     LOAD_FAST                       0: self
                        206     STORE_ATTR                      7: context
                        216     LOAD_FAST                       3: tracked_vars
                        218     LOAD_FAST                       0: self
                        220     STORE_ATTR                      8: tracked_vars
                        230     LOAD_GLOBAL                     19: NULL + defaultdict
                        240     LOAD_GLOBAL                     20: list
                        250     CALL                            1
                        258     LOAD_FAST                       0: self
                        260     STORE_ATTR                      11: usage_lines
                        270     LOAD_FAST                       4: alias_mapping
                        272     POP_JUMP_IF_FALSE               2 (to 278)
                        274     LOAD_FAST                       4: alias_mapping
                        276     JUMP_FORWARD                    9 (to 296)
                        278     LOAD_GLOBAL                     25: NULL + dict
                        288     CALL                            0
                        296     LOAD_FAST                       0: self
                        298     STORE_ATTR                      13: alias_mapping
                        308     LOAD_FAST                       0: self
                        310     LOAD_ATTR                       12: analyzer
                        330     LOAD_ATTR                       28: current_cfunc
                        350     LOAD_ATTR                       30: entry_ea
                        370     LOAD_FAST                       0: self
                        372     STORE_ATTR                      16: current_func_ea
                        382     LOAD_GLOBAL                     35: NULL + demangle
                        392     LOAD_GLOBAL                     37: NULL + ida_funcs
                        402     LOAD_ATTR                       38: get_func_name
                        422     LOAD_FAST                       0: self
                        424     LOAD_ATTR                       32: current_func_ea
                        444     CALL                            1
                        452     CALL                            1
                        460     LOAD_FAST                       0: self
                        462     STORE_ATTR                      20: current_func_name
                        472     LOAD_FAST                       5: not_trace_callee
                        474     LOAD_FAST                       0: self
                        476     STORE_ATTR                      21: not_trace_callee
                        486     LOAD_FAST                       1: analyzer
                        488     LOAD_ATTR                       28: current_cfunc
                        508     LOAD_ATTR                       45: get_lvars
                        528     CALL                            0
                        536     GET_ITER                        
                        538     FOR_ITER                        378 (to 1298)
                        544     STORE_FAST                      7: _var_var_21
                        546     LOAD_FAST                       7: _var_var_21
                        548     LOAD_ATTR                       46: name
                        568     LOAD_FAST                       3: tracked_vars
                        570     CONTAINS_OP                     0 (in)
                        572     POP_JUMP_IF_TRUE                1 (to 576)
                        574     JUMP_BACKWARD                   19 (to 538)
                        576     LOAD_FAST                       7: _var_var_21
                        578     LOAD_ATTR                       49: type
                        598     CALL                            0
                        606     LOAD_ATTR                       51: dstr
                        626     CALL                            0
                        634     STORE_FAST                      8: _var_var_43
                        636     LOAD_FAST                       7: _var_var_21
                        638     LOAD_ATTR                       46: name
                        658     STORE_FAST                      9: _var_var_44
                        660     LOAD_FAST                       7: _var_var_21
                        662     LOAD_ATTR                       49: type
                        682     CALL                            0
                        690     LOAD_ATTR                       53: copy
                        710     CALL                            0
                        718     STORE_FAST                      10: _var_var_45
                        720     LOAD_FAST                       10: _var_var_45
                        722     LOAD_ATTR                       55: is_array
                        742     CALL                            0
                        750     POP_JUMP_IF_FALSE               33 (to 818)
                        752     LOAD_FAST                       10: _var_var_45
                        754     LOAD_ATTR                       57: remove_ptr_or_array
                        774     CALL                            0
                        782     POP_JUMP_IF_FALSE               1 (to 786)
                        784     JUMP_BACKWARD                   17 (to 752)
                        786     LOAD_FAST                       10: _var_var_45
                        788     LOAD_ATTR                       51: dstr
                        808     CALL                            0
                        816     STORE_FAST                      8: _var_var_43
                        818     LOAD_FAST                       7: _var_var_21
                        820     LOAD_ATTR                       58: is_arg_var
                        840     POP_JUMP_IF_FALSE               29 (to 900)
                        842     LOAD_GLOBAL                     61: NULL + find_var_declaration
                        852     LOAD_FAST                       1: analyzer
                        854     LOAD_ATTR                       28: current_cfunc
                        874     LOAD_FAST                       8: _var_var_43
                        876     LOAD_FAST                       9: _var_var_44
                        878     LOAD_CONST                      4: True
                        880     KW_NAMES                        5: ('is_arg',)
                        882     CALL                            4
                        890     UNPACK_SEQUENCE                 2
                        894     STORE_FAST                      11: _var_var_46
                        896     STORE_FAST                      12: _var_var_13
                        898     JUMP_FORWARD                    26 (to 952)
                        900     LOAD_GLOBAL                     61: NULL + find_var_declaration
                        910     LOAD_FAST                       1: analyzer
                        912     LOAD_ATTR                       28: current_cfunc
                        932     LOAD_FAST                       8: _var_var_43
                        934     LOAD_FAST                       9: _var_var_44
                        936     CALL                            3
                        944     UNPACK_SEQUENCE                 2
                        948     STORE_FAST                      11: _var_var_46
                        950     STORE_FAST                      12: _var_var_13
                        952     LOAD_FAST                       0: self
                        954     LOAD_ATTR                       26: alias_mapping
                        974     LOAD_ATTR                       63: get
                        994     LOAD_FAST                       9: _var_var_44
                        996     LOAD_CONST                      0: None
                        998     CALL                            2
                        1006    STORE_FAST                      13: _var_var_31
                        1008    LOAD_GLOBAL                     65: NULL + VarUsage
                        1018    LOAD_FAST                       9: _var_var_44
                        1020    LOAD_FAST                       7: _var_var_21
                        1022    LOAD_ATTR                       49: type
                        1042    CALL                            0
                        1050    LOAD_ATTR                       51: dstr
                        1070    CALL                            0
                        1078    LOAD_FAST                       12: _var_var_13
                        1080    LOAD_CONST                      6: 'decl'
                        1082    LOAD_FAST                       13: _var_var_31
                        1084    LOAD_FAST                       11: _var_var_46
                        1086    LOAD_FAST                       0: self
                        1088    LOAD_ATTR                       40: current_func_name
                        1108    LOAD_FAST                       0: self
                        1110    LOAD_ATTR                       14: context
                        1130    LOAD_ATTR                       66: depth
                        1150    KW_NAMES                        7: ('access_type', 'alias_name', 'line_addr', 'func_name', 'context_depth')
                        1152    CALL                            8
                        1160    STORE_FAST                      14: _var_var_47
                        1162    LOAD_FAST                       0: self
                        1164    LOAD_ATTR                       22: usage_lines
                        1184    LOAD_FAST                       9: _var_var_44
                        1186    BINARY_SUBSCR                   
                        1190    LOAD_ATTR                       69: append
                        1210    LOAD_FAST                       14: _var_var_47
                        1212    CALL                            1
                        1220    POP_TOP                         
                        1222    LOAD_FAST                       0: self
                        1224    LOAD_ATTR                       12: analyzer
                        1244    LOAD_ATTR                       22: usage_lines
                        1264    LOAD_ATTR                       69: append
                        1284    LOAD_FAST                       14: _var_var_47
                        1286    CALL                            1
                        1294    POP_TOP                         
                        1296    JUMP_BACKWARD                   381 (to 538)
                        1300    END_FOR                         
                        1302    LOAD_CONST                      0: None
                        1304    NOP                             
                        1306    NOP                             
                        1308    NOP                             
                        1310    JUMP_FORWARD                    19 (to 1350)
                        1318    POP_TOP                         
                        1320    RETURN_CONST                    0: None
                        1322    PUSH_EXC_INFO                   
                        1324    PUSH_NULL                       
                        1326    LOAD_CONST                      8: '__pyarmor_exit_54831__'
                        1328    NOP                             
                        1330    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x10\x05\x00\x00\x00\x00\x00\x00'
                        1332    CALL                            1
                        1340    POP_TOP                         
                        1342    RERAISE                         0
                        1344    COPY                            3
                        1346    POP_EXCEPT                      
                        1348    RERAISE                         1
                        1350    PUSH_NULL                       
                        1352    LOAD_CONST                      8: '__pyarmor_exit_54831__'
                        1354    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x10\x05\x00\x00\x00\x00\x00\x00'
                        1356    BUILD_TUPLE                     1
                        1358    CALL_FUNCTION_EX                0
                        1360    POP_TOP                         
                        1362    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: _find_final_alias
                    Qualified Name: DataFlowVisitor._find_final_alias
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'set'
                        'alias_mapping'
                        'get'
                        'add'
                    [Locals+Names]
                        'self'
                        'var_name'
                        '__assert_armored__'
                        '_var_var_48'
                        '_var_var_31'
                    [Constants]
                        None
                        '__pyarmor_assert_54832__'
                        '__pyarmor_enter_54833__'
                        b'<COAddr>\x01\x00\x00\x1a\xf0\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54834__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54833__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf0\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + set
                        38      CALL                            0
                        46      STORE_FAST                      3: _var_var_48
                        48      LOAD_FAST                       0: self
                        50      LOAD_ATTR                       2: alias_mapping
                        70      LOAD_ATTR                       5: get
                        90      LOAD_FAST                       1: var_name
                        92      LOAD_CONST                      0: None
                        94      CALL                            2
                        102     STORE_FAST                      4: _var_var_31
                        104     LOAD_FAST                       4: _var_var_31
                        106     POP_JUMP_IF_FALSE               68 (to 244)
                        108     LOAD_FAST                       4: _var_var_31
                        110     LOAD_FAST                       1: var_name
                        112     COMPARE_OP                      55 (!=)
                        116     POP_JUMP_IF_FALSE               63 (to 244)
                        118     LOAD_FAST                       4: _var_var_31
                        120     LOAD_FAST                       3: _var_var_48
                        122     CONTAINS_OP                     1 (not in)
                        124     POP_JUMP_IF_FALSE               59 (to 244)
                        126     LOAD_FAST                       4: _var_var_31
                        128     STORE_FAST                      1: var_name
                        130     LOAD_FAST                       3: _var_var_48
                        132     LOAD_ATTR                       7: add
                        152     LOAD_FAST                       4: _var_var_31
                        154     CALL                            1
                        162     POP_TOP                         
                        164     LOAD_FAST                       0: self
                        166     LOAD_ATTR                       2: alias_mapping
                        186     LOAD_ATTR                       5: get
                        206     LOAD_FAST                       1: var_name
                        208     LOAD_CONST                      0: None
                        210     CALL                            2
                        218     STORE_FAST                      4: _var_var_31
                        220     LOAD_FAST                       4: _var_var_31
                        222     POP_JUMP_IF_FALSE               10 (to 244)
                        224     LOAD_FAST                       4: _var_var_31
                        226     LOAD_FAST                       1: var_name
                        228     COMPARE_OP                      55 (!=)
                        232     POP_JUMP_IF_FALSE               5 (to 244)
                        234     LOAD_FAST                       4: _var_var_31
                        236     LOAD_FAST                       3: _var_var_48
                        238     CONTAINS_OP                     1 (not in)
                        240     POP_JUMP_IF_FALSE               1 (to 244)
                        242     JUMP_BACKWARD                   59 (to 126)
                        244     LOAD_FAST                       1: var_name
                        246     NOP                             
                        248     NOP                             
                        250     NOP                             
                        252     JUMP_FORWARD                    20 (to 294)
                        254     CALL                            1
                        262     POP_TOP                         
                        264     RETURN_VALUE                    
                        266     PUSH_EXC_INFO                   
                        268     PUSH_NULL                       
                        270     LOAD_CONST                      4: '__pyarmor_exit_54834__'
                        272     NOP                             
                        274     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf0\x00\x00\x00\x00\x00\x00\x00'
                        276     CALL                            1
                        284     POP_TOP                         
                        286     RERAISE                         0
                        288     COPY                            3
                        290     POP_EXCEPT                      
                        292     RERAISE                         1
                        294     PUSH_NULL                       
                        296     LOAD_CONST                      4: '__pyarmor_exit_54834__'
                        298     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf0\x00\x00\x00\x00\x00\x00\x00'
                        300     BUILD_TUPLE                     1
                        302     CALL_FUNCTION_EX                0
                        304     POP_TOP                         
                        306     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: _track_var_in_expr
                    Qualified Name: DataFlowVisitor._track_var_in_expr
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 10
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'op'
                        'ida_hexrays'
                        'cot_var'
                        'v'
                        'getv'
                        'name'
                        'type'
                        'dstr'
                        'tracked_vars'
                        'cot_memptr'
                        'cot_memref'
                        'cot_idx'
                        'cot_ref'
                        'cot_ptr'
                        'parents'
                        'cexpr'
                        'cot_asg'
                        'x'
                        'clear_cast'
                        'cot_call'
                        'analyzer'
                        'current_cfunc'
                        'find_item_coords'
                        '_get_pcode_line'
                        '_find_final_alias'
                        'VarUsage'
                        'current_func_name'
                        'context'
                        'depth'
                        'usage_lines'
                        'append'
                    [Locals+Names]
                        'self'
                        'expr'
                        '__assert_armored__'
                        '_var_var_49'
                        '_var_var_50'
                        '_var_var_51'
                        '_var_var_52'
                        '_var_var_53'
                        '_var_var_54'
                        '_var_var_46'
                        '_var_var_13'
                        '_var_var_31'
                        '_var_var_47'
                    [Constants]
                        None
                        '__pyarmor_assert_54835__'
                        '__pyarmor_enter_54836__'
                        b'<COAddr>\x01\x00\x00\x1a\xaa\x05\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54837__'
                        0
                        ''
                        'r'
                        'w'
                        '(call)'
                        (
                            'access_type'
                            'alias_name'
                            'line_addr'
                            'func_name'
                            'context_depth'
                        )
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54836__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x05\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: expr
                        30      LOAD_ATTR                       0: op
                        50      LOAD_GLOBAL                     2: ida_hexrays
                        60      LOAD_ATTR                       4: cot_var
                        80      COMPARE_OP                      40 (==)
                        84      POP_JUMP_IF_FALSE               127 (to 340)
                        86      LOAD_FAST                       1: expr
                        88      LOAD_ATTR                       6: v
                        108     POP_JUMP_IF_FALSE               115 (to 340)
                        110     LOAD_FAST                       1: expr
                        112     LOAD_ATTR                       6: v
                        132     LOAD_ATTR                       9: getv
                        152     CALL                            0
                        160     LOAD_ATTR                       10: name
                        180     STORE_FAST                      3: _var_var_49
                        182     LOAD_FAST                       1: expr
                        184     LOAD_ATTR                       6: v
                        204     LOAD_ATTR                       9: getv
                        224     CALL                            0
                        232     LOAD_ATTR                       13: type
                        252     CALL                            0
                        260     LOAD_ATTR                       15: dstr
                        280     CALL                            0
                        288     STORE_FAST                      4: _var_var_50
                        290     LOAD_FAST                       3: _var_var_49
                        292     LOAD_FAST                       0: self
                        294     LOAD_ATTR                       16: tracked_vars
                        314     CONTAINS_OP                     1 (not in)
                        316     POP_JUMP_IF_FALSE               143 (to 604)
                        318     NOP                             
                        320     LOAD_CONST                      5: 0
                        322     NOP                             
                        324     NOP                             
                        326     JUMP_FORWARD                    587 (to 1504)
                        336     POP_TOP                         
                        338     RETURN_CONST                    5: 0
                        340     LOAD_FAST                       1: expr
                        342     LOAD_ATTR                       0: op
                        362     LOAD_GLOBAL                     2: ida_hexrays
                        372     LOAD_ATTR                       18: cot_memptr
                        392     LOAD_GLOBAL                     2: ida_hexrays
                        402     LOAD_ATTR                       20: cot_memref
                        422     LOAD_GLOBAL                     2: ida_hexrays
                        432     LOAD_ATTR                       22: cot_idx
                        452     LOAD_GLOBAL                     2: ida_hexrays
                        462     LOAD_ATTR                       24: cot_ref
                        482     LOAD_GLOBAL                     2: ida_hexrays
                        492     LOAD_ATTR                       26: cot_ptr
                        512     BUILD_TUPLE                     5
                        514     CONTAINS_OP                     0 (in)
                        516     POP_JUMP_IF_FALSE               43 (to 604)
                        518     LOAD_FAST                       1: expr
                        520     LOAD_ATTR                       15: dstr
                        540     CALL                            0
                        548     STORE_FAST                      3: _var_var_49
                        550     LOAD_CONST                      6: ''
                        552     STORE_FAST                      4: _var_var_50
                        554     LOAD_FAST                       3: _var_var_49
                        556     LOAD_FAST                       0: self
                        558     LOAD_ATTR                       16: tracked_vars
                        578     CONTAINS_OP                     1 (not in)
                        580     POP_JUMP_IF_FALSE               11 (to 604)
                        582     NOP                             
                        584     LOAD_CONST                      5: 0
                        586     NOP                             
                        588     NOP                             
                        590     JUMP_FORWARD                    455 (to 1504)
                        600     POP_TOP                         
                        602     RETURN_CONST                    5: 0
                        604     LOAD_CONST                      7: 'r'
                        606     STORE_FAST                      5: _var_var_51
                        608     LOAD_FAST                       0: self
                        610     LOAD_ATTR                       28: parents
                        630     GET_ITER                        
                        632     FOR_ITER                        139 (to 912)
                        636     STORE_FAST                      6: _var_var_52
                        638     LOAD_FAST                       6: _var_var_52
                        640     POP_JUMP_IF_TRUE                1 (to 644)
                        642     JUMP_BACKWARD                   6 (to 632)
                        644     LOAD_FAST                       6: _var_var_52
                        646     LOAD_ATTR                       30: cexpr
                        666     LOAD_ATTR                       0: op
                        686     LOAD_GLOBAL                     2: ida_hexrays
                        696     LOAD_ATTR                       32: cot_asg
                        716     COMPARE_OP                      40 (==)
                        720     POP_JUMP_IF_TRUE                1 (to 724)
                        722     JUMP_BACKWARD                   46 (to 632)
                        724     LOAD_FAST                       6: _var_var_52
                        726     LOAD_ATTR                       30: cexpr
                        746     LOAD_ATTR                       34: x
                        766     LOAD_ATTR                       15: dstr
                        786     CALL                            0
                        794     LOAD_FAST_CHECK                 3: _var_var_49
                        796     COMPARE_OP                      40 (==)
                        800     POP_JUMP_IF_TRUE                49 (to 900)
                        802     LOAD_GLOBAL                     37: NULL + clear_cast
                        812     LOAD_FAST                       6: _var_var_52
                        814     LOAD_ATTR                       30: cexpr
                        834     LOAD_ATTR                       34: x
                        854     CALL                            1
                        862     LOAD_ATTR                       15: dstr
                        882     CALL                            0
                        890     LOAD_FAST                       3: _var_var_49
                        892     COMPARE_OP                      40 (==)
                        896     POP_JUMP_IF_TRUE                1 (to 900)
                        898     JUMP_BACKWARD                   134 (to 632)
                        900     LOAD_FAST                       5: _var_var_51
                        902     LOAD_CONST                      8: 'w'
                        904     BINARY_OP                       13 (+=)
                        908     STORE_FAST                      5: _var_var_51
                        910     POP_TOP                         
                        912     JUMP_FORWARD                    1 (to 916)
                        914     END_FOR                         
                        916     LOAD_FAST                       0: self
                        918     LOAD_ATTR                       28: parents
                        938     GET_ITER                        
                        940     FOR_ITER                        51 (to 1044)
                        944     STORE_FAST                      6: _var_var_52
                        946     LOAD_FAST                       6: _var_var_52
                        948     POP_JUMP_IF_TRUE                1 (to 952)
                        950     JUMP_BACKWARD                   6 (to 940)
                        952     LOAD_FAST                       6: _var_var_52
                        954     LOAD_ATTR                       30: cexpr
                        974     LOAD_ATTR                       0: op
                        994     LOAD_GLOBAL                     2: ida_hexrays
                        1004    LOAD_ATTR                       38: cot_call
                        1024    COMPARE_OP                      40 (==)
                        1028    POP_JUMP_IF_TRUE                1 (to 1032)
                        1030    JUMP_BACKWARD                   46 (to 940)
                        1032    LOAD_FAST                       5: _var_var_51
                        1034    LOAD_CONST                      9: '(call)'
                        1036    BINARY_OP                       13 (+=)
                        1040    STORE_FAST                      5: _var_var_51
                        1042    POP_TOP                         
                        1044    JUMP_FORWARD                    1 (to 1048)
                        1046    END_FOR                         
                        1048    LOAD_FAST                       0: self
                        1050    LOAD_ATTR                       40: analyzer
                        1070    LOAD_ATTR                       42: current_cfunc
                        1090    LOAD_ATTR                       45: find_item_coords
                        1110    LOAD_FAST                       1: expr
                        1112    CALL                            1
                        1120    STORE_FAST                      7: _var_var_53
                        1122    LOAD_FAST                       7: _var_var_53
                        1124    POP_JUMP_IF_FALSE               165 (to 1456)
                        1126    LOAD_FAST                       7: _var_var_53
                        1128    UNPACK_SEQUENCE                 2
                        1132    STORE_FAST                      8: _var_var_54
                        1134    STORE_FAST                      9: _var_var_46
                        1136    LOAD_FAST                       0: self
                        1138    LOAD_ATTR                       40: analyzer
                        1158    LOAD_ATTR                       47: _get_pcode_line
                        1178    LOAD_FAST                       9: _var_var_46
                        1180    CALL                            1
                        1188    STORE_FAST                      10: _var_var_13
                        1190    LOAD_FAST                       0: self
                        1192    LOAD_ATTR                       49: _find_final_alias
                        1212    LOAD_FAST_CHECK                 3: _var_var_49
                        1214    CALL                            1
                        1222    STORE_FAST                      11: _var_var_31
                        1224    LOAD_GLOBAL                     51: NULL + VarUsage
                        1234    LOAD_FAST                       3: _var_var_49
                        1236    LOAD_FAST_CHECK                 4: _var_var_50
                        1238    LOAD_FAST                       10: _var_var_13
                        1240    LOAD_FAST                       5: _var_var_51
                        1242    LOAD_FAST                       11: _var_var_31
                        1244    LOAD_FAST                       9: _var_var_46
                        1246    LOAD_FAST                       0: self
                        1248    LOAD_ATTR                       52: current_func_name
                        1268    LOAD_FAST                       0: self
                        1270    LOAD_ATTR                       54: context
                        1290    LOAD_ATTR                       56: depth
                        1310    KW_NAMES                        10: ('access_type', 'alias_name', 'line_addr', 'func_name', 'context_depth')
                        1312    CALL                            8
                        1320    STORE_FAST                      12: _var_var_47
                        1322    LOAD_FAST                       0: self
                        1324    LOAD_ATTR                       58: usage_lines
                        1344    LOAD_FAST                       3: _var_var_49
                        1346    BINARY_SUBSCR                   
                        1350    LOAD_ATTR                       61: append
                        1370    LOAD_FAST                       12: _var_var_47
                        1372    CALL                            1
                        1380    POP_TOP                         
                        1382    LOAD_FAST                       0: self
                        1384    LOAD_ATTR                       40: analyzer
                        1404    LOAD_ATTR                       58: usage_lines
                        1424    LOAD_ATTR                       61: append
                        1444    LOAD_FAST                       12: _var_var_47
                        1446    CALL                            1
                        1454    POP_TOP                         
                        1456    LOAD_CONST                      5: 0
                        1458    NOP                             
                        1460    NOP                             
                        1462    NOP                             
                        1464    JUMP_FORWARD                    19 (to 1504)
                        1472    POP_TOP                         
                        1474    RETURN_CONST                    5: 0
                        1476    PUSH_EXC_INFO                   
                        1478    PUSH_NULL                       
                        1480    LOAD_CONST                      4: '__pyarmor_exit_54837__'
                        1482    NOP                             
                        1484    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x05\x00\x00\x00\x00\x00\x00'
                        1486    CALL                            1
                        1494    POP_TOP                         
                        1496    RERAISE                         0
                        1498    COPY                            3
                        1500    POP_EXCEPT                      
                        1502    RERAISE                         1
                        1504    PUSH_NULL                       
                        1506    LOAD_CONST                      4: '__pyarmor_exit_54837__'
                        1508    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x05\x00\x00\x00\x00\x00\x00'
                        1510    BUILD_TUPLE                     1
                        1512    CALL_FUNCTION_EX                0
                        1514    POP_TOP                         
                        1516    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: _track_var_in_callee
                    Qualified Name: DataFlowVisitor._track_var_in_callee
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 10
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'x'
                        'obj_ea'
                        'ida_idaapi'
                        'BADADDR'
                        'is_thunk'
                        'is_import_name'
                        'ida_funcs'
                        'get_func'
                        'ida_hexrays'
                        'decompile'
                        'dstr'
                        'enumerate'
                        'a'
                        'len'
                        'arguments'
                        'op'
                        'cot_cast'
                        'clear_cast'
                        'cot_var'
                        'cot_ptr'
                        'cot_ref'
                        'cot_idx'
                        'cot_memptr'
                        'cot_memref'
                        'cot_add'
                        'cot_sub'
                        'v'
                        'getv'
                        'name'
                        'tracked_vars'
                        'FunctionContext'
                        'current_func_ea'
                        'context'
                        'depth'
                        '_find_final_alias'
                        'var_mappings'
                        '_track_var_in_expr'
                        'analyzer'
                        'analyze_function_dataflow_forward'
                        'get_final_x'
                    [Locals+Names]
                        'self'
                        'expr'
                        '__assert_armored__'
                        '_var_var_55'
                        '_var_var_56'
                        '_var_var_57'
                        '_var_var_39'
                        '_var_var_3'
                        '_var_var_16'
                        '_var_var_58'
                        '_var_var_59'
                        '_var_var_30'
                        '_var_var_31'
                        '_var_var_60'
                        '_var_var_61'
                        '_var_var_49'
                    [Constants]
                        None
                        '__pyarmor_assert_54838__'
                        '__pyarmor_enter_54839__'
                        b'<COAddr>\x01\x00\x00\x1aZ\x0e\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54840__'
                        0
                        ''
                        2
                        1
                        '('
                        ')'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54839__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x0e\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: expr
                        30      LOAD_ATTR                       0: x
                        50      LOAD_ATTR                       2: obj_ea
                        70      STORE_FAST                      3: _var_var_55
                        72      LOAD_FAST                       3: _var_var_55
                        74      LOAD_GLOBAL                     4: ida_idaapi
                        84      LOAD_ATTR                       6: BADADDR
                        104     COMPARE_OP                      40 (==)
                        108     POP_JUMP_IF_FALSE               11 (to 132)
                        110     NOP                             
                        112     LOAD_CONST                      5: 0
                        114     NOP                             
                        116     NOP                             
                        118     JUMP_FORWARD                    1803 (to 3728)
                        128     POP_TOP                         
                        130     RETURN_CONST                    5: 0
                        132     LOAD_GLOBAL                     9: NULL + is_thunk
                        142     LOAD_FAST                       3: _var_var_55
                        144     CALL                            1
                        152     POP_JUMP_IF_TRUE                11 (to 176)
                        154     LOAD_GLOBAL                     11: NULL + is_import_name
                        164     LOAD_FAST                       3: _var_var_55
                        166     CALL                            1
                        174     POP_JUMP_IF_FALSE               11 (to 198)
                        176     NOP                             
                        178     LOAD_CONST                      5: 0
                        180     NOP                             
                        182     NOP                             
                        184     JUMP_FORWARD                    1770 (to 3728)
                        194     POP_TOP                         
                        196     RETURN_CONST                    5: 0
                        198     LOAD_GLOBAL                     13: NULL + ida_funcs
                        208     LOAD_ATTR                       14: get_func
                        228     LOAD_FAST                       3: _var_var_55
                        230     CALL                            1
                        238     STORE_FAST                      4: _var_var_56
                        240     LOAD_FAST                       4: _var_var_56
                        242     POP_JUMP_IF_TRUE                11 (to 266)
                        244     NOP                             
                        246     LOAD_CONST                      5: 0
                        248     NOP                             
                        250     NOP                             
                        252     JUMP_FORWARD                    1736 (to 3728)
                        262     POP_TOP                         
                        264     RETURN_CONST                    5: 0
                        266     LOAD_GLOBAL                     17: NULL + ida_hexrays
                        276     LOAD_ATTR                       18: decompile
                        296     LOAD_FAST                       4: _var_var_56
                        298     CALL                            1
                        306     STORE_FAST                      5: _var_var_57
                        308     LOAD_FAST                       5: _var_var_57
                        310     POP_JUMP_IF_TRUE                11 (to 334)
                        312     NOP                             
                        314     LOAD_CONST                      5: 0
                        316     NOP                             
                        318     NOP                             
                        320     JUMP_FORWARD                    1702 (to 3728)
                        330     POP_TOP                         
                        332     RETURN_CONST                    5: 0
                        334     LOAD_FAST                       1: expr
                        336     LOAD_ATTR                       0: x
                        356     LOAD_ATTR                       21: dstr
                        376     CALL                            0
                        384     STORE_FAST                      6: _var_var_39
                        386     LOAD_GLOBAL                     23: NULL + enumerate
                        396     LOAD_FAST                       1: expr
                        398     LOAD_ATTR                       24: a
                        418     CALL                            1
                        426     GET_ITER                        
                        428     FOR_ITER                        1622 (to 3676)
                        434     UNPACK_SEQUENCE                 2
                        438     STORE_FAST                      7: _var_var_3
                        440     STORE_FAST                      8: _var_var_16
                        442     LOAD_FAST                       7: _var_var_3
                        444     LOAD_GLOBAL                     27: NULL + len
                        454     LOAD_FAST                       5: _var_var_57
                        456     LOAD_ATTR                       28: arguments
                        476     CALL                            1
                        484     COMPARE_OP                      92 (>=)
                        488     POP_JUMP_IF_FALSE               1 (to 492)
                        490     JUMP_BACKWARD                   32 (to 428)
                        492     LOAD_CONST                      6: ''
                        494     STORE_FAST                      9: _var_var_58
                        496     LOAD_FAST                       8: _var_var_16
                        498     LOAD_ATTR                       30: op
                        518     LOAD_GLOBAL                     16: ida_hexrays
                        528     LOAD_ATTR                       32: cot_cast
                        548     COMPARE_OP                      40 (==)
                        552     POP_JUMP_IF_FALSE               281 (to 1118)
                        556     LOAD_GLOBAL                     35: NULL + clear_cast
                        566     LOAD_FAST                       8: _var_var_16
                        568     CALL                            1
                        576     STORE_FAST                      10: _var_var_59
                        578     LOAD_FAST                       10: _var_var_59
                        580     LOAD_ATTR                       30: op
                        600     LOAD_GLOBAL                     16: ida_hexrays
                        610     LOAD_ATTR                       36: cot_var
                        630     LOAD_GLOBAL                     16: ida_hexrays
                        640     LOAD_ATTR                       38: cot_ptr
                        660     LOAD_GLOBAL                     16: ida_hexrays
                        670     LOAD_ATTR                       40: cot_ref
                        690     LOAD_GLOBAL                     16: ida_hexrays
                        700     LOAD_ATTR                       42: cot_idx
                        720     LOAD_GLOBAL                     16: ida_hexrays
                        730     LOAD_ATTR                       44: cot_memptr
                        750     LOAD_GLOBAL                     16: ida_hexrays
                        760     LOAD_ATTR                       46: cot_memref
                        780     LOAD_GLOBAL                     16: ida_hexrays
                        790     LOAD_ATTR                       48: cot_add
                        810     LOAD_GLOBAL                     16: ida_hexrays
                        820     LOAD_ATTR                       50: cot_sub
                        840     BUILD_TUPLE                     8
                        842     CONTAINS_OP                     0 (in)
                        844     POP_JUMP_IF_FALSE               136 (to 1118)
                        846     LOAD_FAST                       10: _var_var_59
                        848     LOAD_ATTR                       30: op
                        868     LOAD_GLOBAL                     16: ida_hexrays
                        878     LOAD_ATTR                       48: cot_add
                        898     LOAD_GLOBAL                     16: ida_hexrays
                        908     LOAD_ATTR                       50: cot_sub
                        928     BUILD_TUPLE                     2
                        930     CONTAINS_OP                     0 (in)
                        932     POP_JUMP_IF_FALSE               47 (to 1028)
                        934     LOAD_FAST                       8: _var_var_16
                        936     LOAD_ATTR                       21: dstr
                        956     CALL                            0
                        964     LOAD_CONST                      0: None
                        966     LOAD_GLOBAL                     27: NULL + len
                        976     LOAD_FAST                       10: _var_var_59
                        978     LOAD_ATTR                       21: dstr
                        998     CALL                            0
                        1006    CALL                            1
                        1014    UNARY_NEGATIVE                  
                        1016    LOAD_CONST                      7: 2
                        1018    BINARY_OP                       10 (-)
                        1022    BINARY_SLICE                    
                        1024    STORE_FAST                      9: _var_var_58
                        1026    JUMP_FORWARD                    43 (to 1114)
                        1028    LOAD_FAST                       8: _var_var_16
                        1030    LOAD_ATTR                       21: dstr
                        1050    CALL                            0
                        1058    LOAD_CONST                      0: None
                        1060    LOAD_GLOBAL                     27: NULL + len
                        1070    LOAD_FAST                       10: _var_var_59
                        1072    LOAD_ATTR                       21: dstr
                        1092    CALL                            0
                        1100    CALL                            1
                        1108    UNARY_NEGATIVE                  
                        1110    BINARY_SLICE                    
                        1112    STORE_FAST                      9: _var_var_58
                        1114    LOAD_FAST                       10: _var_var_59
                        1116    STORE_FAST                      8: _var_var_16
                        1118    LOAD_FAST                       8: _var_var_16
                        1120    LOAD_ATTR                       30: op
                        1140    LOAD_GLOBAL                     16: ida_hexrays
                        1150    LOAD_ATTR                       36: cot_var
                        1170    COMPARE_OP                      40 (==)
                        1174    POP_JUMP_IF_FALSE               233 (to 1642)
                        1176    LOAD_FAST                       8: _var_var_16
                        1178    LOAD_ATTR                       52: v
                        1198    LOAD_ATTR                       55: getv
                        1218    CALL                            0
                        1226    LOAD_ATTR                       56: name
                        1246    LOAD_FAST                       0: self
                        1248    LOAD_ATTR                       58: tracked_vars
                        1268    CONTAINS_OP                     0 (in)
                        1270    POP_JUMP_IF_FALSE               185 (to 1642)
                        1272    LOAD_GLOBAL                     61: NULL + FunctionContext
                        1282    LOAD_FAST                       3: _var_var_55
                        1284    LOAD_FAST                       0: self
                        1286    LOAD_ATTR                       62: current_func_ea
                        1306    CALL                            2
                        1314    STORE_FAST                      11: _var_var_30
                        1316    LOAD_FAST                       0: self
                        1318    LOAD_ATTR                       64: context
                        1338    LOAD_ATTR                       66: depth
                        1358    LOAD_CONST                      8: 1
                        1360    BINARY_OP                       0 (+)
                        1364    LOAD_FAST                       11: _var_var_30
                        1366    STORE_ATTR                      33: depth
                        1376    LOAD_FAST                       0: self
                        1378    LOAD_ATTR                       69: _find_final_alias
                        1398    LOAD_FAST                       8: _var_var_16
                        1400    LOAD_ATTR                       52: v
                        1420    LOAD_ATTR                       55: getv
                        1440    CALL                            0
                        1448    LOAD_ATTR                       56: name
                        1468    CALL                            1
                        1476    STORE_FAST                      12: _var_var_31
                        1478    LOAD_FAST                       5: _var_var_57
                        1480    LOAD_ATTR                       28: arguments
                        1500    LOAD_FAST                       7: _var_var_3
                        1502    BINARY_SUBSCR                   
                        1506    LOAD_ATTR                       56: name
                        1526    LOAD_FAST                       9: _var_var_58
                        1528    LOAD_FAST                       12: _var_var_31
                        1530    BINARY_OP                       0 (+)
                        1534    BUILD_MAP                       1
                        1536    LOAD_FAST                       11: _var_var_30
                        1538    STORE_ATTR                      35: var_mappings
                        1548    LOAD_FAST                       0: self
                        1550    LOAD_ATTR                       73: _track_var_in_expr
                        1570    LOAD_FAST                       8: _var_var_16
                        1572    CALL                            1
                        1580    POP_TOP                         
                        1582    LOAD_FAST                       0: self
                        1584    LOAD_ATTR                       74: analyzer
                        1604    LOAD_ATTR                       77: analyze_function_dataflow_forward
                        1624    LOAD_FAST                       3: _var_var_55
                        1626    LOAD_FAST                       11: _var_var_30
                        1628    CALL                            2
                        1636    POP_TOP                         
                        1638    JUMP_BACKWARD                   607 (to 428)
                        1642    LOAD_FAST                       8: _var_var_16
                        1644    LOAD_ATTR                       30: op
                        1664    LOAD_GLOBAL                     16: ida_hexrays
                        1674    LOAD_ATTR                       44: cot_memptr
                        1694    LOAD_GLOBAL                     16: ida_hexrays
                        1704    LOAD_ATTR                       46: cot_memref
                        1724    LOAD_GLOBAL                     16: ida_hexrays
                        1734    LOAD_ATTR                       40: cot_ref
                        1754    LOAD_GLOBAL                     16: ida_hexrays
                        1764    LOAD_ATTR                       38: cot_ptr
                        1784    LOAD_GLOBAL                     16: ida_hexrays
                        1794    LOAD_ATTR                       42: cot_idx
                        1814    BUILD_TUPLE                     5
                        1816    CONTAINS_OP                     0 (in)
                        1818    POP_JUMP_IF_FALSE               400 (to 2622)
                        1822    LOAD_GLOBAL                     79: NULL + get_final_x
                        1832    LOAD_FAST                       8: _var_var_16
                        1834    CALL                            1
                        1842    STORE_FAST                      13: _var_var_60
                        1844    LOAD_FAST                       13: _var_var_60
                        1846    LOAD_ATTR                       30: op
                        1866    LOAD_GLOBAL                     16: ida_hexrays
                        1876    LOAD_ATTR                       36: cot_var
                        1896    COMPARE_OP                      40 (==)
                        1900    POP_JUMP_IF_TRUE                2 (to 1906)
                        1902    JUMP_BACKWARD                   739 (to 428)
                        1906    LOAD_FAST                       13: _var_var_60
                        1908    LOAD_ATTR                       52: v
                        1928    POP_JUMP_IF_TRUE                2 (to 1934)
                        1930    JUMP_BACKWARD                   753 (to 428)
                        1934    LOAD_FAST                       13: _var_var_60
                        1936    LOAD_ATTR                       52: v
                        1956    LOAD_ATTR                       55: getv
                        1976    CALL                            0
                        1984    LOAD_ATTR                       56: name
                        2004    LOAD_FAST                       0: self
                        2006    LOAD_ATTR                       58: tracked_vars
                        2026    CONTAINS_OP                     0 (in)
                        2028    POP_JUMP_IF_TRUE                2 (to 2034)
                        2030    JUMP_BACKWARD                   803 (to 428)
                        2034    LOAD_FAST                       8: _var_var_16
                        2036    LOAD_ATTR                       21: dstr
                        2056    CALL                            0
                        2064    STORE_FAST                      14: _var_var_61
                        2066    LOAD_FAST                       13: _var_var_60
                        2068    LOAD_ATTR                       52: v
                        2088    LOAD_ATTR                       55: getv
                        2108    CALL                            0
                        2116    LOAD_ATTR                       56: name
                        2136    STORE_FAST                      15: _var_var_49
                        2138    LOAD_GLOBAL                     61: NULL + FunctionContext
                        2148    LOAD_FAST                       3: _var_var_55
                        2150    LOAD_FAST                       0: self
                        2152    LOAD_ATTR                       62: current_func_ea
                        2172    CALL                            2
                        2180    STORE_FAST                      11: _var_var_30
                        2182    LOAD_FAST                       0: self
                        2184    LOAD_ATTR                       64: context
                        2204    LOAD_ATTR                       66: depth
                        2224    LOAD_CONST                      8: 1
                        2226    BINARY_OP                       0 (+)
                        2230    LOAD_FAST                       11: _var_var_30
                        2232    STORE_ATTR                      33: depth
                        2242    LOAD_FAST                       0: self
                        2244    LOAD_ATTR                       69: _find_final_alias
                        2264    LOAD_FAST                       15: _var_var_49
                        2266    CALL                            1
                        2274    STORE_FAST                      12: _var_var_31
                        2276    LOAD_FAST                       12: _var_var_31
                        2278    POP_JUMP_IF_FALSE               89 (to 2458)
                        2280    LOAD_FAST                       12: _var_var_31
                        2282    LOAD_FAST                       15: _var_var_49
                        2284    COMPARE_OP                      55 (!=)
                        2288    POP_JUMP_IF_FALSE               84 (to 2458)
                        2290    LOAD_CONST                      9: '('
                        2292    LOAD_FAST                       12: _var_var_31
                        2294    FORMAT_VALUE                    0 (FVC_NONE)
                        2296    LOAD_CONST                      10: ')'
                        2298    BUILD_STRING                    3
                        2300    STORE_FAST                      12: _var_var_31
                        2302    LOAD_FAST                       12: _var_var_31
                        2304    LOAD_FAST                       13: _var_var_60
                        2306    LOAD_ATTR                       52: v
                        2326    LOAD_ATTR                       55: getv
                        2346    CALL                            0
                        2354    STORE_ATTR                      28: name
                        2364    LOAD_FAST                       8: _var_var_16
                        2366    LOAD_ATTR                       21: dstr
                        2386    CALL                            0
                        2394    STORE_FAST                      14: _var_var_61
                        2396    LOAD_FAST                       15: _var_var_49
                        2398    LOAD_FAST                       13: _var_var_60
                        2400    LOAD_ATTR                       52: v
                        2420    LOAD_ATTR                       55: getv
                        2440    CALL                            0
                        2448    STORE_ATTR                      28: name
                        2458    LOAD_FAST                       5: _var_var_57
                        2460    LOAD_ATTR                       28: arguments
                        2480    LOAD_FAST                       7: _var_var_3
                        2482    BINARY_SUBSCR                   
                        2486    LOAD_ATTR                       56: name
                        2506    LOAD_FAST                       9: _var_var_58
                        2508    LOAD_FAST                       14: _var_var_61
                        2510    BINARY_OP                       0 (+)
                        2514    BUILD_MAP                       1
                        2516    LOAD_FAST                       11: _var_var_30
                        2518    STORE_ATTR                      35: var_mappings
                        2528    LOAD_FAST                       0: self
                        2530    LOAD_ATTR                       73: _track_var_in_expr
                        2550    LOAD_FAST                       13: _var_var_60
                        2552    CALL                            1
                        2560    POP_TOP                         
                        2562    LOAD_FAST                       0: self
                        2564    LOAD_ATTR                       74: analyzer
                        2584    LOAD_ATTR                       77: analyze_function_dataflow_forward
                        2604    LOAD_FAST                       3: _var_var_55
                        2606    LOAD_FAST                       11: _var_var_30
                        2608    CALL                            2
                        2616    POP_TOP                         
                        2618    JUMP_BACKWARD                   1097 (to 428)
                        2622    LOAD_FAST                       8: _var_var_16
                        2624    LOAD_ATTR                       30: op
                        2644    LOAD_GLOBAL                     16: ida_hexrays
                        2654    LOAD_ATTR                       48: cot_add
                        2674    LOAD_GLOBAL                     16: ida_hexrays
                        2684    LOAD_ATTR                       50: cot_sub
                        2704    BUILD_TUPLE                     2
                        2706    CONTAINS_OP                     0 (in)
                        2708    POP_JUMP_IF_TRUE                2 (to 2714)
                        2710    JUMP_BACKWARD                   1143 (to 428)
                        2714    LOAD_FAST                       8: _var_var_16
                        2716    LOAD_ATTR                       0: x
                        2736    LOAD_ATTR                       30: op
                        2756    LOAD_GLOBAL                     16: ida_hexrays
                        2766    LOAD_ATTR                       36: cot_var
                        2786    COMPARE_OP                      40 (==)
                        2790    POP_JUMP_IF_TRUE                2 (to 2796)
                        2792    JUMP_BACKWARD                   1184 (to 428)
                        2796    LOAD_FAST                       8: _var_var_16
                        2798    LOAD_ATTR                       0: x
                        2818    LOAD_ATTR                       52: v
                        2838    LOAD_ATTR                       55: getv
                        2858    CALL                            0
                        2866    LOAD_ATTR                       56: name
                        2886    LOAD_FAST                       0: self
                        2888    LOAD_ATTR                       58: tracked_vars
                        2908    CONTAINS_OP                     0 (in)
                        2910    POP_JUMP_IF_TRUE                2 (to 2916)
                        2912    JUMP_BACKWARD                   1244 (to 428)
                        2916    LOAD_FAST                       8: _var_var_16
                        2918    LOAD_ATTR                       21: dstr
                        2938    CALL                            0
                        2946    STORE_FAST                      14: _var_var_61
                        2948    LOAD_FAST                       8: _var_var_16
                        2950    LOAD_ATTR                       0: x
                        2970    LOAD_ATTR                       52: v
                        2990    LOAD_ATTR                       55: getv
                        3010    CALL                            0
                        3018    LOAD_ATTR                       56: name
                        3038    STORE_FAST                      15: _var_var_49
                        3040    LOAD_GLOBAL                     61: NULL + FunctionContext
                        3050    LOAD_FAST                       3: _var_var_55
                        3052    LOAD_FAST                       0: self
                        3054    LOAD_ATTR                       62: current_func_ea
                        3074    CALL                            2
                        3082    STORE_FAST                      11: _var_var_30
                        3084    LOAD_FAST                       0: self
                        3086    LOAD_ATTR                       64: context
                        3106    LOAD_ATTR                       66: depth
                        3126    LOAD_CONST                      8: 1
                        3128    BINARY_OP                       0 (+)
                        3132    LOAD_FAST                       11: _var_var_30
                        3134    STORE_ATTR                      33: depth
                        3144    LOAD_FAST                       0: self
                        3146    LOAD_ATTR                       69: _find_final_alias
                        3166    LOAD_FAST                       8: _var_var_16
                        3168    LOAD_ATTR                       0: x
                        3188    LOAD_ATTR                       52: v
                        3208    LOAD_ATTR                       55: getv
                        3228    CALL                            0
                        3236    LOAD_ATTR                       56: name
                        3256    CALL                            1
                        3264    STORE_FAST                      12: _var_var_31
                        3266    LOAD_FAST                       12: _var_var_31
                        3268    POP_JUMP_IF_FALSE               109 (to 3488)
                        3270    LOAD_FAST                       12: _var_var_31
                        3272    LOAD_FAST                       15: _var_var_49
                        3274    COMPARE_OP                      55 (!=)
                        3278    POP_JUMP_IF_FALSE               104 (to 3488)
                        3280    LOAD_CONST                      9: '('
                        3282    LOAD_FAST                       12: _var_var_31
                        3284    FORMAT_VALUE                    0 (FVC_NONE)
                        3286    LOAD_CONST                      10: ')'
                        3288    BUILD_STRING                    3
                        3290    STORE_FAST                      12: _var_var_31
                        3292    LOAD_FAST                       12: _var_var_31
                        3294    LOAD_FAST                       8: _var_var_16
                        3296    LOAD_ATTR                       0: x
                        3316    LOAD_ATTR                       52: v
                        3336    LOAD_ATTR                       55: getv
                        3356    CALL                            0
                        3364    STORE_ATTR                      28: name
                        3374    LOAD_FAST                       8: _var_var_16
                        3376    LOAD_ATTR                       21: dstr
                        3396    CALL                            0
                        3404    STORE_FAST                      14: _var_var_61
                        3406    LOAD_FAST                       15: _var_var_49
                        3408    LOAD_FAST                       8: _var_var_16
                        3410    LOAD_ATTR                       0: x
                        3430    LOAD_ATTR                       52: v
                        3450    LOAD_ATTR                       55: getv
                        3470    CALL                            0
                        3478    STORE_ATTR                      28: name
                        3488    LOAD_FAST                       5: _var_var_57
                        3490    LOAD_ATTR                       28: arguments
                        3510    LOAD_FAST                       7: _var_var_3
                        3512    BINARY_SUBSCR                   
                        3516    LOAD_ATTR                       56: name
                        3536    LOAD_FAST                       9: _var_var_58
                        3538    FORMAT_VALUE                    0 (FVC_NONE)
                        3540    LOAD_CONST                      9: '('
                        3542    LOAD_FAST                       14: _var_var_61
                        3544    FORMAT_VALUE                    0 (FVC_NONE)
                        3546    LOAD_CONST                      10: ')'
                        3548    BUILD_STRING                    4
                        3550    BUILD_MAP                       1
                        3552    LOAD_FAST                       11: _var_var_30
                        3554    STORE_ATTR                      35: var_mappings
                        3564    LOAD_FAST                       0: self
                        3566    LOAD_ATTR                       73: _track_var_in_expr
                        3586    LOAD_FAST                       8: _var_var_16
                        3588    LOAD_ATTR                       0: x
                        3608    CALL                            1
                        3616    POP_TOP                         
                        3618    LOAD_FAST                       0: self
                        3620    LOAD_ATTR                       74: analyzer
                        3640    LOAD_ATTR                       77: analyze_function_dataflow_forward
                        3660    LOAD_FAST                       3: _var_var_55
                        3662    LOAD_FAST                       11: _var_var_30
                        3664    CALL                            2
                        3672    POP_TOP                         
                        3674    JUMP_BACKWARD                   1625 (to 428)
                        3678    END_FOR                         
                        3680    LOAD_CONST                      5: 0
                        3682    NOP                             
                        3684    NOP                             
                        3686    NOP                             
                        3688    JUMP_FORWARD                    19 (to 3728)
                        3696    POP_TOP                         
                        3698    RETURN_CONST                    5: 0
                        3700    PUSH_EXC_INFO                   
                        3702    PUSH_NULL                       
                        3704    LOAD_CONST                      4: '__pyarmor_exit_54840__'
                        3706    NOP                             
                        3708    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x0e\x00\x00\x00\x00\x00\x00'
                        3710    CALL                            1
                        3718    POP_TOP                         
                        3720    RERAISE                         0
                        3722    COPY                            3
                        3724    POP_EXCEPT                      
                        3726    RERAISE                         1
                        3728    PUSH_NULL                       
                        3730    LOAD_CONST                      4: '__pyarmor_exit_54840__'
                        3732    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x0e\x00\x00\x00\x00\x00\x00'
                        3734    BUILD_TUPLE                     1
                        3736    CALL_FUNCTION_EX                0
                        3738    POP_TOP                         
                        3740    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: _track_var_in_asg
                    Qualified Name: DataFlowVisitor._track_var_in_asg
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'op'
                        'ida_hexrays'
                        'cot_asg'
                        'y'
                        'cot_var'
                        'cot_ptr'
                        'cot_ref'
                        'cot_idx'
                        'cot_memptr'
                        'cot_memref'
                        'get_final_x'
                        'cot_obj'
                        'dstr'
                        'tracked_vars'
                        '_find_final_alias'
                        'v'
                        'getv'
                        'name'
                        'x'
                        'alias_mapping'
                        'add'
                    [Locals+Names]
                        'self'
                        'expr'
                        '__assert_armored__'
                        '_var_var_60'
                        '_var_var_62'
                        '_var_var_63'
                        '_var_var_31'
                        '_var_var_64'
                    [Constants]
                        None
                        '__pyarmor_assert_54841__'
                        '__pyarmor_enter_54842__'
                        b'<COAddr>\x03\x00\x00\x1a\x1c\t\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54843__'
                        0
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54842__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x1c\t\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: expr
                        30      LOAD_ATTR                       0: op
                        50      LOAD_GLOBAL                     2: ida_hexrays
                        60      LOAD_ATTR                       4: cot_asg
                        80      COMPARE_OP                      55 (!=)
                        84      POP_JUMP_IF_FALSE               11 (to 108)
                        86      NOP                             
                        88      LOAD_CONST                      5: 0
                        90      NOP                             
                        92      NOP                             
                        94      JUMP_FORWARD                    1144 (to 2386)
                        104     POP_TOP                         
                        106     RETURN_CONST                    5: 0
                        108     LOAD_FAST                       1: expr
                        110     LOAD_ATTR                       6: y
                        130     LOAD_ATTR                       0: op
                        150     LOAD_GLOBAL                     2: ida_hexrays
                        160     LOAD_ATTR                       8: cot_var
                        180     LOAD_GLOBAL                     2: ida_hexrays
                        190     LOAD_ATTR                       10: cot_ptr
                        210     LOAD_GLOBAL                     2: ida_hexrays
                        220     LOAD_ATTR                       12: cot_ref
                        240     LOAD_GLOBAL                     2: ida_hexrays
                        250     LOAD_ATTR                       14: cot_idx
                        270     LOAD_GLOBAL                     2: ida_hexrays
                        280     LOAD_ATTR                       16: cot_memptr
                        300     LOAD_GLOBAL                     2: ida_hexrays
                        310     LOAD_ATTR                       18: cot_memref
                        330     BUILD_TUPLE                     6
                        332     CONTAINS_OP                     0 (in)
                        334     POP_JUMP_IF_FALSE               470 (to 1278)
                        338     LOAD_GLOBAL                     21: NULL + get_final_x
                        348     LOAD_FAST                       1: expr
                        350     LOAD_ATTR                       6: y
                        370     CALL                            1
                        378     LOAD_ATTR                       0: op
                        398     LOAD_GLOBAL                     2: ida_hexrays
                        408     LOAD_ATTR                       8: cot_var
                        428     LOAD_GLOBAL                     2: ida_hexrays
                        438     LOAD_ATTR                       22: cot_obj
                        458     BUILD_TUPLE                     2
                        460     CONTAINS_OP                     0 (in)
                        462     POP_JUMP_IF_FALSE               406 (to 1278)
                        466     LOAD_GLOBAL                     21: NULL + get_final_x
                        476     LOAD_FAST                       1: expr
                        478     LOAD_ATTR                       6: y
                        498     CALL                            1
                        506     STORE_FAST                      3: _var_var_60
                        508     LOAD_FAST                       3: _var_var_60
                        510     LOAD_ATTR                       25: dstr
                        530     CALL                            0
                        538     STORE_FAST                      4: _var_var_62
                        540     LOAD_FAST                       3: _var_var_60
                        542     LOAD_ATTR                       0: op
                        562     LOAD_GLOBAL                     2: ida_hexrays
                        572     LOAD_ATTR                       8: cot_var
                        592     COMPARE_OP                      40 (==)
                        596     POP_JUMP_IF_FALSE               339 (to 1278)
                        600     LOAD_FAST                       4: _var_var_62
                        602     LOAD_FAST                       0: self
                        604     LOAD_ATTR                       26: tracked_vars
                        624     CONTAINS_OP                     0 (in)
                        626     POP_JUMP_IF_FALSE               324 (to 1278)
                        630     LOAD_FAST                       1: expr
                        632     LOAD_ATTR                       6: y
                        652     LOAD_ATTR                       25: dstr
                        672     CALL                            0
                        680     STORE_FAST                      5: _var_var_63
                        682     LOAD_FAST                       0: self
                        684     LOAD_ATTR                       29: _find_final_alias
                        704     LOAD_FAST                       4: _var_var_62
                        706     CALL                            1
                        714     STORE_FAST                      6: _var_var_31
                        716     LOAD_FAST                       6: _var_var_31
                        718     POP_JUMP_IF_FALSE               93 (to 906)
                        720     LOAD_FAST                       6: _var_var_31
                        722     LOAD_FAST                       4: _var_var_62
                        724     COMPARE_OP                      55 (!=)
                        728     POP_JUMP_IF_FALSE               88 (to 906)
                        730     LOAD_FAST                       6: _var_var_31
                        732     LOAD_FAST                       3: _var_var_60
                        734     LOAD_ATTR                       30: v
                        754     LOAD_ATTR                       33: getv
                        774     CALL                            0
                        782     STORE_ATTR                      17: name
                        792     LOAD_FAST                       1: expr
                        794     LOAD_ATTR                       6: y
                        814     LOAD_ATTR                       25: dstr
                        834     CALL                            0
                        842     STORE_FAST                      5: _var_var_63
                        844     LOAD_FAST                       4: _var_var_62
                        846     LOAD_FAST                       3: _var_var_60
                        848     LOAD_ATTR                       30: v
                        868     LOAD_ATTR                       33: getv
                        888     CALL                            0
                        896     STORE_ATTR                      17: name
                        906     LOAD_CONST                      0: None
                        908     STORE_FAST                      7: _var_var_64
                        910     LOAD_FAST                       1: expr
                        912     LOAD_ATTR                       36: x
                        932     LOAD_ATTR                       0: op
                        952     LOAD_GLOBAL                     2: ida_hexrays
                        962     LOAD_ATTR                       8: cot_var
                        982     LOAD_GLOBAL                     2: ida_hexrays
                        992     LOAD_ATTR                       10: cot_ptr
                        1012    LOAD_GLOBAL                     2: ida_hexrays
                        1022    LOAD_ATTR                       12: cot_ref
                        1042    LOAD_GLOBAL                     2: ida_hexrays
                        1052    LOAD_ATTR                       14: cot_idx
                        1072    LOAD_GLOBAL                     2: ida_hexrays
                        1082    LOAD_ATTR                       16: cot_memptr
                        1102    LOAD_GLOBAL                     2: ida_hexrays
                        1112    LOAD_ATTR                       18: cot_memref
                        1132    BUILD_TUPLE                     6
                        1134    CONTAINS_OP                     0 (in)
                        1136    POP_JUMP_IF_FALSE               26 (to 1190)
                        1138    LOAD_FAST                       1: expr
                        1140    LOAD_ATTR                       36: x
                        1160    LOAD_ATTR                       25: dstr
                        1180    CALL                            0
                        1188    STORE_FAST                      7: _var_var_64
                        1190    LOAD_FAST                       7: _var_var_64
                        1192    POP_JUMP_IF_FALSE               42 (to 1278)
                        1194    LOAD_FAST                       5: _var_var_63
                        1196    LOAD_FAST                       0: self
                        1198    LOAD_ATTR                       38: alias_mapping
                        1218    LOAD_FAST                       7: _var_var_64
                        1220    STORE_SUBSCR                    
                        1224    LOAD_FAST                       0: self
                        1226    LOAD_ATTR                       26: tracked_vars
                        1246    LOAD_ATTR                       41: add
                        1266    LOAD_FAST                       7: _var_var_64
                        1268    CALL                            1
                        1276    POP_TOP                         
                        1278    LOAD_FAST                       1: expr
                        1280    LOAD_ATTR                       36: x
                        1300    LOAD_ATTR                       0: op
                        1320    LOAD_GLOBAL                     2: ida_hexrays
                        1330    LOAD_ATTR                       8: cot_var
                        1350    LOAD_GLOBAL                     2: ida_hexrays
                        1360    LOAD_ATTR                       10: cot_ptr
                        1380    LOAD_GLOBAL                     2: ida_hexrays
                        1390    LOAD_ATTR                       12: cot_ref
                        1410    LOAD_GLOBAL                     2: ida_hexrays
                        1420    LOAD_ATTR                       14: cot_idx
                        1440    LOAD_GLOBAL                     2: ida_hexrays
                        1450    LOAD_ATTR                       16: cot_memptr
                        1470    LOAD_GLOBAL                     2: ida_hexrays
                        1480    LOAD_ATTR                       18: cot_memref
                        1500    BUILD_TUPLE                     6
                        1502    CONTAINS_OP                     0 (in)
                        1504    POP_JUMP_IF_FALSE               415 (to 2338)
                        1508    LOAD_GLOBAL                     21: NULL + get_final_x
                        1518    LOAD_FAST                       1: expr
                        1520    LOAD_ATTR                       36: x
                        1540    CALL                            1
                        1548    STORE_FAST                      3: _var_var_60
                        1550    LOAD_FAST                       3: _var_var_60
                        1552    LOAD_ATTR                       0: op
                        1572    LOAD_GLOBAL                     2: ida_hexrays
                        1582    LOAD_ATTR                       8: cot_var
                        1602    COMPARE_OP                      40 (==)
                        1606    POP_JUMP_IF_FALSE               364 (to 2338)
                        1610    LOAD_FAST                       3: _var_var_60
                        1612    LOAD_ATTR                       25: dstr
                        1632    CALL                            0
                        1640    LOAD_FAST                       0: self
                        1642    LOAD_ATTR                       26: tracked_vars
                        1662    CONTAINS_OP                     0 (in)
                        1664    POP_JUMP_IF_FALSE               335 (to 2338)
                        1668    LOAD_FAST                       3: _var_var_60
                        1670    LOAD_ATTR                       25: dstr
                        1690    CALL                            0
                        1698    STORE_FAST                      4: _var_var_62
                        1700    LOAD_FAST                       1: expr
                        1702    LOAD_ATTR                       36: x
                        1722    LOAD_ATTR                       25: dstr
                        1742    CALL                            0
                        1750    STORE_FAST                      7: _var_var_64
                        1752    LOAD_FAST                       0: self
                        1754    LOAD_ATTR                       29: _find_final_alias
                        1774    LOAD_FAST                       4: _var_var_62
                        1776    CALL                            1
                        1784    STORE_FAST                      6: _var_var_31
                        1786    LOAD_FAST                       6: _var_var_31
                        1788    POP_JUMP_IF_FALSE               88 (to 1966)
                        1790    LOAD_FAST                       6: _var_var_31
                        1792    LOAD_FAST                       3: _var_var_60
                        1794    LOAD_ATTR                       30: v
                        1814    LOAD_ATTR                       33: getv
                        1834    CALL                            0
                        1842    STORE_ATTR                      17: name
                        1852    LOAD_FAST                       1: expr
                        1854    LOAD_ATTR                       36: x
                        1874    LOAD_ATTR                       25: dstr
                        1894    CALL                            0
                        1902    STORE_FAST                      7: _var_var_64
                        1904    LOAD_FAST                       4: _var_var_62
                        1906    LOAD_FAST                       3: _var_var_60
                        1908    LOAD_ATTR                       30: v
                        1928    LOAD_ATTR                       33: getv
                        1948    CALL                            0
                        1956    STORE_ATTR                      17: name
                        1966    LOAD_CONST                      0: None
                        1968    STORE_FAST                      5: _var_var_63
                        1970    LOAD_FAST                       1: expr
                        1972    LOAD_ATTR                       6: y
                        1992    LOAD_ATTR                       0: op
                        2012    LOAD_GLOBAL                     2: ida_hexrays
                        2022    LOAD_ATTR                       8: cot_var
                        2042    LOAD_GLOBAL                     2: ida_hexrays
                        2052    LOAD_ATTR                       10: cot_ptr
                        2072    LOAD_GLOBAL                     2: ida_hexrays
                        2082    LOAD_ATTR                       12: cot_ref
                        2102    LOAD_GLOBAL                     2: ida_hexrays
                        2112    LOAD_ATTR                       14: cot_idx
                        2132    LOAD_GLOBAL                     2: ida_hexrays
                        2142    LOAD_ATTR                       16: cot_memptr
                        2162    LOAD_GLOBAL                     2: ida_hexrays
                        2172    LOAD_ATTR                       18: cot_memref
                        2192    BUILD_TUPLE                     6
                        2194    CONTAINS_OP                     0 (in)
                        2196    POP_JUMP_IF_FALSE               26 (to 2250)
                        2198    LOAD_FAST                       1: expr
                        2200    LOAD_ATTR                       6: y
                        2220    LOAD_ATTR                       25: dstr
                        2240    CALL                            0
                        2248    STORE_FAST                      5: _var_var_63
                        2250    LOAD_FAST                       5: _var_var_63
                        2252    POP_JUMP_IF_FALSE               42 (to 2338)
                        2254    LOAD_FAST                       7: _var_var_64
                        2256    LOAD_FAST                       0: self
                        2258    LOAD_ATTR                       38: alias_mapping
                        2278    LOAD_FAST                       5: _var_var_63
                        2280    STORE_SUBSCR                    
                        2284    LOAD_FAST                       0: self
                        2286    LOAD_ATTR                       26: tracked_vars
                        2306    LOAD_ATTR                       41: add
                        2326    LOAD_FAST                       5: _var_var_63
                        2328    CALL                            1
                        2336    POP_TOP                         
                        2338    LOAD_CONST                      5: 0
                        2340    NOP                             
                        2342    NOP                             
                        2344    NOP                             
                        2346    JUMP_FORWARD                    19 (to 2386)
                        2354    POP_TOP                         
                        2356    RETURN_CONST                    5: 0
                        2358    PUSH_EXC_INFO                   
                        2360    PUSH_NULL                       
                        2362    LOAD_CONST                      4: '__pyarmor_exit_54843__'
                        2364    NOP                             
                        2366    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x1c\t\x00\x00\x00\x00\x00\x00'
                        2368    CALL                            1
                        2376    POP_TOP                         
                        2378    RERAISE                         0
                        2380    COPY                            3
                        2382    POP_EXCEPT                      
                        2384    RERAISE                         1
                        2386    PUSH_NULL                       
                        2388    LOAD_CONST                      4: '__pyarmor_exit_54843__'
                        2390    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x1c\t\x00\x00\x00\x00\x00\x00'
                        2392    BUILD_TUPLE                     1
                        2394    CALL_FUNCTION_EX                0
                        2396    POP_TOP                         
                        2398    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: visit_expr
                    Qualified Name: DataFlowVisitor.visit_expr
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'not_trace_callee'
                        'op'
                        'ida_hexrays'
                        'cot_call'
                        'x'
                        'cot_obj'
                        '_track_var_in_callee'
                        'cot_asg'
                        '_track_var_in_asg'
                        'cot_var'
                        'cot_memptr'
                        'cot_memref'
                        'cot_idx'
                        'cot_ref'
                        'cot_ptr'
                        '_track_var_in_expr'
                    [Locals+Names]
                        'self'
                        'expr'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54844__'
                        '__pyarmor_enter_54845__'
                        b'<COAddr>\x03\x00\x00\x1a,\x02\x00\x00\x00\x00\x00\x00'
                        False
                        '__pyarmor_exit_54846__'
                        0
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54845__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a,\x02\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: not_trace_callee
                        50      LOAD_CONST                      4: False
                        52      COMPARE_OP                      40 (==)
                        56      POP_JUMP_IF_FALSE               85 (to 228)
                        58      LOAD_FAST                       1: expr
                        60      LOAD_ATTR                       2: op
                        80      LOAD_GLOBAL                     4: ida_hexrays
                        90      LOAD_ATTR                       6: cot_call
                        110     COMPARE_OP                      40 (==)
                        114     POP_JUMP_IF_FALSE               56 (to 228)
                        116     LOAD_FAST                       1: expr
                        118     LOAD_ATTR                       8: x
                        138     LOAD_ATTR                       2: op
                        158     LOAD_GLOBAL                     4: ida_hexrays
                        168     LOAD_ATTR                       10: cot_obj
                        188     COMPARE_OP                      40 (==)
                        192     POP_JUMP_IF_FALSE               17 (to 228)
                        194     LOAD_FAST                       0: self
                        196     LOAD_ATTR                       13: _track_var_in_callee
                        216     LOAD_FAST                       1: expr
                        218     CALL                            1
                        226     POP_TOP                         
                        228     LOAD_FAST                       1: expr
                        230     LOAD_ATTR                       2: op
                        250     LOAD_GLOBAL                     4: ida_hexrays
                        260     LOAD_ATTR                       14: cot_asg
                        280     COMPARE_OP                      40 (==)
                        284     POP_JUMP_IF_FALSE               17 (to 320)
                        286     LOAD_FAST                       0: self
                        288     LOAD_ATTR                       17: _track_var_in_asg
                        308     LOAD_FAST                       1: expr
                        310     CALL                            1
                        318     POP_TOP                         
                        320     LOAD_FAST                       1: expr
                        322     LOAD_ATTR                       2: op
                        342     LOAD_GLOBAL                     4: ida_hexrays
                        352     LOAD_ATTR                       18: cot_var
                        372     LOAD_GLOBAL                     4: ida_hexrays
                        382     LOAD_ATTR                       20: cot_memptr
                        402     LOAD_GLOBAL                     4: ida_hexrays
                        412     LOAD_ATTR                       22: cot_memref
                        432     LOAD_GLOBAL                     4: ida_hexrays
                        442     LOAD_ATTR                       24: cot_idx
                        462     LOAD_GLOBAL                     4: ida_hexrays
                        472     LOAD_ATTR                       26: cot_ref
                        492     LOAD_GLOBAL                     4: ida_hexrays
                        502     LOAD_ATTR                       28: cot_ptr
                        522     BUILD_TUPLE                     6
                        524     CONTAINS_OP                     0 (in)
                        526     POP_JUMP_IF_FALSE               17 (to 562)
                        528     LOAD_FAST                       0: self
                        530     LOAD_ATTR                       31: _track_var_in_expr
                        550     LOAD_FAST                       1: expr
                        552     CALL                            1
                        560     POP_TOP                         
                        562     LOAD_CONST                      6: 0
                        564     NOP                             
                        566     NOP                             
                        568     NOP                             
                        570     JUMP_FORWARD                    19 (to 610)
                        578     POP_TOP                         
                        580     RETURN_CONST                    6: 0
                        582     PUSH_EXC_INFO                   
                        584     PUSH_NULL                       
                        586     LOAD_CONST                      5: '__pyarmor_exit_54846__'
                        588     NOP                             
                        590     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a,\x02\x00\x00\x00\x00\x00\x00'
                        592     CALL                            1
                        600     POP_TOP                         
                        602     RERAISE                         0
                        604     COPY                            3
                        606     POP_EXCEPT                      
                        608     RERAISE                         1
                        610     PUSH_NULL                       
                        612     LOAD_CONST                      5: '__pyarmor_exit_54846__'
                        614     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a,\x02\x00\x00\x00\x00\x00\x00'
                        616     BUILD_TUPLE                     1
                        618     CALL_FUNCTION_EX                0
                        620     POP_TOP                         
                        622     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..data_flow>
                    Object Name: visit_insn
                    Qualified Name: DataFlowVisitor.visit_insn
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        'self'
                        'insn'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54847__'
                        '__pyarmor_enter_54848__'
                        b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54849__'
                        0
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54848__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_CONST                      5: 0
                        30      NOP                             
                        32      NOP                             
                        34      NOP                             
                        36      JUMP_FORWARD                    19 (to 76)
                        44      POP_TOP                         
                        46      RETURN_CONST                    5: 0
                        48      PUSH_EXC_INFO                   
                        50      PUSH_NULL                       
                        52      LOAD_CONST                      4: '__pyarmor_exit_54849__'
                        54      NOP                             
                        56      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        58      CALL                            1
                        66      POP_TOP                         
                        68      RERAISE                         0
                        70      COPY                            3
                        72      POP_EXCEPT                      
                        74      RERAISE                         1
                        76      PUSH_NULL                       
                        78      LOAD_CONST                      4: '__pyarmor_exit_54849__'
                        80      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        82      BUILD_TUPLE                     1
                        84      CALL_FUNCTION_EX                0
                        86      POP_TOP                         
                        88      RETURN_VALUE                    
                '__pyarmor_exit_54828__'
                (
                    None
                    False
                )
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'DataFlowVisitor'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_54827__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      17: (None, False)
                38      LOAD_CONST                      5: 'analyzer'
                40      LOAD_NAME                       4: DataFlowAnalyzer
                42      LOAD_CONST                      6: 'context'
                44      LOAD_NAME                       5: FunctionContext
                46      LOAD_CONST                      7: 'tracked_vars'
                48      LOAD_NAME                       6: set
                50      LOAD_CONST                      8: 'alias_mapping'
                52      LOAD_NAME                       7: dict
                54      BUILD_TUPLE                     8
                56      LOAD_CONST                      9: <CODE> __init__
                58      MAKE_FUNCTION                   5
                60      STORE_NAME                      8: __init__
                62      LOAD_CONST                      10: <CODE> _find_final_alias
                64      MAKE_FUNCTION                   0
                66      STORE_NAME                      9: _find_final_alias
                68      LOAD_CONST                      11: <CODE> _track_var_in_expr
                70      MAKE_FUNCTION                   0
                72      STORE_NAME                      10: _track_var_in_expr
                74      LOAD_CONST                      12: <CODE> _track_var_in_callee
                76      MAKE_FUNCTION                   0
                78      STORE_NAME                      11: _track_var_in_callee
                80      LOAD_CONST                      13: <CODE> _track_var_in_asg
                82      MAKE_FUNCTION                   0
                84      STORE_NAME                      12: _track_var_in_asg
                86      LOAD_CONST                      14: <CODE> visit_expr
                88      MAKE_FUNCTION                   0
                90      STORE_NAME                      13: visit_expr
                92      LOAD_CONST                      15: <CODE> visit_insn
                94      MAKE_FUNCTION                   0
                96      STORE_NAME                      14: visit_insn
                98      LOAD_CONST                      4: None
                100     NOP                             
                102     NOP                             
                104     NOP                             
                106     JUMP_FORWARD                    19 (to 146)
                114     POP_TOP                         
                116     RETURN_CONST                    4: None
                118     PUSH_EXC_INFO                   
                120     PUSH_NULL                       
                122     LOAD_CONST                      16: '__pyarmor_exit_54828__'
                124     NOP                             
                126     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                128     CALL                            1
                136     POP_TOP                         
                138     RERAISE                         0
                140     COPY                            3
                142     POP_EXCEPT                      
                144     RERAISE                         1
                146     PUSH_NULL                       
                148     LOAD_CONST                      16: '__pyarmor_exit_54828__'
                150     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"T\x00\x00\x00\x00\x00\x00\x00'
                152     BUILD_TUPLE                     1
                154     CALL_FUNCTION_EX                0
                156     POP_TOP                         
                158     RETURN_VALUE                    
        'DataFlowVisitor'
        '__pyarmor_exit_54741__'
        (
            False
        )
        (
            0
        )
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54740__'
        8       LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1aP\x01\x00\x00\x00\x00\x00\x00'
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
        30      IMPORT_NAME                     1: re
        32      STORE_NAME                      1: re
        34      LOAD_CONST                      3: 0
        36      LOAD_CONST                      4: None
        38      IMPORT_NAME                     2: idc
        40      STORE_NAME                      2: idc
        42      LOAD_CONST                      3: 0
        44      LOAD_CONST                      4: None
        46      IMPORT_NAME                     3: json
        48      STORE_NAME                      3: json
        50      LOAD_CONST                      3: 0
        52      LOAD_CONST                      4: None
        54      IMPORT_NAME                     4: ida_hexrays
        56      STORE_NAME                      4: ida_hexrays
        58      LOAD_CONST                      3: 0
        60      LOAD_CONST                      4: None
        62      IMPORT_NAME                     5: ida_funcs
        64      STORE_NAME                      5: ida_funcs
        66      LOAD_CONST                      3: 0
        68      LOAD_CONST                      4: None
        70      IMPORT_NAME                     6: ida_auto
        72      STORE_NAME                      6: ida_auto
        74      LOAD_CONST                      3: 0
        76      LOAD_CONST                      4: None
        78      IMPORT_NAME                     7: ida_name
        80      STORE_NAME                      7: ida_name
        82      LOAD_CONST                      3: 0
        84      LOAD_CONST                      4: None
        86      IMPORT_NAME                     8: ida_lines
        88      STORE_NAME                      8: ida_lines
        90      LOAD_CONST                      3: 0
        92      LOAD_CONST                      4: None
        94      IMPORT_NAME                     9: ida_idaapi
        96      STORE_NAME                      9: ida_idaapi
        98      LOAD_CONST                      3: 0
        100     LOAD_CONST                      4: None
        102     IMPORT_NAME                     10: ida_xref
        104     STORE_NAME                      10: ida_xref
        106     LOAD_CONST                      3: 0
        108     LOAD_CONST                      4: None
        110     IMPORT_NAME                     11: idaapi
        112     STORE_NAME                      11: idaapi
        114     LOAD_CONST                      3: 0
        116     LOAD_CONST                      4: None
        118     IMPORT_NAME                     12: idautils
        120     STORE_NAME                      12: idautils
        122     LOAD_CONST                      3: 0
        124     LOAD_CONST                      4: None
        126     IMPORT_NAME                     13: ida_segment
        128     STORE_NAME                      13: ida_segment
        130     LOAD_CONST                      3: 0
        132     LOAD_CONST                      5: ('defaultdict',)
        134     IMPORT_NAME                     14: collections
        136     IMPORT_FROM                     15: defaultdict
        138     STORE_NAME                      15: defaultdict
        140     POP_TOP                         
        142     LOAD_CONST                      3: 0
        144     LOAD_CONST                      6: ('colored',)
        146     IMPORT_NAME                     16: termcolor
        148     IMPORT_FROM                     17: colored
        150     STORE_NAME                      17: colored
        152     POP_TOP                         
        154     PUSH_NULL                       
        156     LOAD_NAME                       18: dict
        158     CALL                            0
        166     STORE_NAME                      19: IMPORT_FUNCS
        168     LOAD_CONST                      7: <CODE> collect_import_funcs
        170     MAKE_FUNCTION                   0
        172     STORE_NAME                      20: collect_import_funcs
        174     PUSH_NULL                       
        176     LOAD_NAME                       20: collect_import_funcs
        178     CALL                            0
        186     POP_TOP                         
        188     LOAD_CONST                      8: <CODE> is_thunk
        190     MAKE_FUNCTION                   0
        192     STORE_NAME                      21: is_thunk
        194     LOAD_CONST                      9: <CODE> is_thunk_func
        196     MAKE_FUNCTION                   0
        198     STORE_NAME                      22: is_thunk_func
        200     LOAD_CONST                      10: <CODE> is_import_name
        202     MAKE_FUNCTION                   0
        204     STORE_NAME                      23: is_import_name
        206     LOAD_CONST                      11: <CODE> get_import_name_info
        208     MAKE_FUNCTION                   0
        210     STORE_NAME                      24: get_import_name_info
        212     LOAD_CONST                      25: (False,)
        214     LOAD_CONST                      12: <CODE> find_var_declaration
        216     MAKE_FUNCTION                   1
        218     STORE_NAME                      25: find_var_declaration
        220     LOAD_CONST                      26: (0,)
        222     LOAD_CONST                      13: <CODE> demangle
        224     MAKE_FUNCTION                   1
        226     STORE_NAME                      26: demangle
        228     LOAD_CONST                      14: <CODE> get_final_x
        230     MAKE_FUNCTION                   0
        232     STORE_NAME                      27: get_final_x
        234     LOAD_CONST                      15: <CODE> clear_cast
        236     MAKE_FUNCTION                   0
        238     STORE_NAME                      28: clear_cast
        240     PUSH_NULL                       
        242     LOAD_BUILD_CLASS                
        244     LOAD_CONST                      16: <CODE> VarUsage
        246     MAKE_FUNCTION                   0
        248     LOAD_CONST                      17: 'VarUsage'
        250     CALL                            2
        258     STORE_NAME                      29: VarUsage
        260     PUSH_NULL                       
        262     LOAD_BUILD_CLASS                
        264     LOAD_CONST                      18: <CODE> FunctionContext
        266     MAKE_FUNCTION                   0
        268     LOAD_CONST                      19: 'FunctionContext'
        270     CALL                            2
        278     STORE_NAME                      30: FunctionContext
        280     PUSH_NULL                       
        282     LOAD_BUILD_CLASS                
        284     LOAD_CONST                      20: <CODE> DataFlowAnalyzer
        286     MAKE_FUNCTION                   0
        288     LOAD_CONST                      21: 'DataFlowAnalyzer'
        290     CALL                            2
        298     STORE_NAME                      31: DataFlowAnalyzer
        300     PUSH_NULL                       
        302     LOAD_BUILD_CLASS                
        304     LOAD_CONST                      22: <CODE> DataFlowVisitor
        306     MAKE_FUNCTION                   0
        308     LOAD_CONST                      23: 'DataFlowVisitor'
        310     LOAD_NAME                       4: ida_hexrays
        312     LOAD_ATTR                       64: ctree_visitor_t
        332     CALL                            3
        340     STORE_NAME                      33: DataFlowVisitor
        342     LOAD_CONST                      4: None
        344     NOP                             
        346     NOP                             
        348     NOP                             
        350     JUMP_FORWARD                    19 (to 390)
        358     POP_TOP                         
        360     RETURN_CONST                    4: None
        362     PUSH_EXC_INFO                   
        364     PUSH_NULL                       
        366     LOAD_CONST                      24: '__pyarmor_exit_54741__'
        368     NOP                             
        370     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1aP\x01\x00\x00\x00\x00\x00\x00'
        372     CALL                            1
        380     POP_TOP                         
        382     RERAISE                         0
        384     COPY                            3
        386     POP_EXCEPT                      
        388     RERAISE                         1
        390     PUSH_NULL                       
        392     LOAD_CONST                      24: '__pyarmor_exit_54741__'
        394     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1aP\x01\x00\x00\x00\x00\x00\x00'
        396     BUILD_TUPLE                     1
        398     CALL_FUNCTION_EX                0
        400     POP_TOP                         
        402     RETURN_VALUE                    
