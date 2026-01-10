checker.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..checker>
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
        'os'
        'json'
        'textwrap'
        'collections'
        'defaultdict'
        'ida_hexrays'
        'DecompilationFailure'
        'decompile'
        'drop_task_tag_in_output'
        'find_json_by_re'
        'find_output_by_re'
        'parse_model_response_json'
        'parse_model_response_str'
        'parse_var_pred'
        'vars_check_and_refine'
        'funcname_check_and_refine'
        'summary_check_and_refine'
        'list'
        'is_no_original_list'
        'get_func_args'
        'get_func_args_vars'
        'func_analysis_check_and_refine'
        'response_check_and_refine'
        'dict'
        'split_pred_to_var_arg'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54913__'
        '__pyarmor_enter_54914__'
        b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
        0
        None
        (
            'defaultdict'
        )
        (
            'DecompilationFailure'
            'decompile'
        )
        [Code]
            File Name: <frozen ..checker>
            Object Name: drop_task_tag_in_output
            Qualified Name: drop_task_tag_in_output
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'split'
                'index'
                'join'
            [Locals+Names]
                'output'
                '__assert_armored__'
                '_var_var_0'
            [Constants]
                None
                '__pyarmor_assert_54916__'
                '__pyarmor_enter_54917__'
                b'<COAddr>\x01\x00\x00\x1a\xc2\x00\x00\x00\x00\x00\x00\x00'
                '\n'
                -1
                '</'
                '__pyarmor_exit_54918__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54917__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc2\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: output
                30      LOAD_ATTR                       1: split
                50      LOAD_CONST                      4: '\n'
                52      CALL                            1
                60      LOAD_CONST                      5: -1
                62      BINARY_SUBSCR                   
                66      STORE_FAST                      2: _var_var_0
                68      LOAD_CONST                      6: '</'
                70      LOAD_FAST                       2: _var_var_0
                72      CONTAINS_OP                     0 (in)
                74      POP_JUMP_IF_FALSE               61 (to 198)
                76      LOAD_FAST                       2: _var_var_0
                78      LOAD_CONST                      0: None
                80      LOAD_FAST                       2: _var_var_0
                82      LOAD_ATTR                       3: index
                102     LOAD_CONST                      6: '</'
                104     CALL                            1
                112     BINARY_SLICE                    
                114     STORE_FAST                      2: _var_var_0
                116     LOAD_CONST                      4: '\n'
                118     LOAD_ATTR                       5: join
                138     LOAD_FAST                       0: output
                140     LOAD_ATTR                       1: split
                160     LOAD_CONST                      4: '\n'
                162     CALL                            1
                170     LOAD_CONST                      0: None
                172     LOAD_CONST                      5: -1
                174     BINARY_SLICE                    
                176     CALL                            1
                184     LOAD_CONST                      4: '\n'
                186     BINARY_OP                       0 (+)
                190     LOAD_FAST                       2: _var_var_0
                192     BINARY_OP                       0 (+)
                196     STORE_FAST                      0: output
                198     LOAD_FAST                       0: output
                200     NOP                             
                202     NOP                             
                204     NOP                             
                206     JUMP_FORWARD                    20 (to 248)
                208     CALL                            1
                216     POP_TOP                         
                218     RETURN_VALUE                    
                220     PUSH_EXC_INFO                   
                222     PUSH_NULL                       
                224     LOAD_CONST                      7: '__pyarmor_exit_54918__'
                226     NOP                             
                228     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc2\x00\x00\x00\x00\x00\x00\x00'
                230     CALL                            1
                238     POP_TOP                         
                240     RERAISE                         0
                242     COPY                            3
                244     POP_EXCEPT                      
                246     RERAISE                         1
                248     PUSH_NULL                       
                250     LOAD_CONST                      7: '__pyarmor_exit_54918__'
                252     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc2\x00\x00\x00\x00\x00\x00\x00'
                254     BUILD_TUPLE                     1
                256     CALL_FUNCTION_EX                0
                258     POP_TOP                         
                260     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: find_json_by_re
            Qualified Name: find_json_by_re
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                're'
                'findall'
                'DOTALL'
            [Locals+Names]
                'output'
                '__assert_armored__'
                '_var_var_1'
                '_var_var_2'
            [Constants]
                None
                '__pyarmor_assert_54919__'
                '__pyarmor_enter_54920__'
                b'<COAddr>\x01\x00\x00\x1a\x8a\x00\x00\x00\x00\x00\x00\x00'
                '```(json|JSON)?(.*?)```'
                -1
                1
                '__pyarmor_exit_54921__'
                ''
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54920__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8a\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '```(json|JSON)?(.*?)```'
                30      STORE_FAST                      2: _var_var_1
                32      LOAD_GLOBAL                     1: NULL + re
                42      LOAD_ATTR                       2: findall
                62      LOAD_FAST                       2: _var_var_1
                64      LOAD_FAST                       0: output
                66      LOAD_GLOBAL                     0: re
                76      LOAD_ATTR                       4: DOTALL
                96      CALL                            3
                104     STORE_FAST                      3: _var_var_2
                106     LOAD_FAST                       3: _var_var_2
                108     POP_JUMP_IF_FALSE               17 (to 144)
                110     LOAD_FAST                       3: _var_var_2
                112     LOAD_CONST                      5: -1
                114     BINARY_SUBSCR                   
                118     LOAD_CONST                      6: 1
                120     BINARY_SUBSCR                   
                124     NOP                             
                126     NOP                             
                128     NOP                             
                130     JUMP_FORWARD                    30 (to 192)
                132     CALL                            1
                140     POP_TOP                         
                142     RETURN_VALUE                    
                144     LOAD_CONST                      8: ''
                146     NOP                             
                148     NOP                             
                150     NOP                             
                152     JUMP_FORWARD                    19 (to 192)
                160     POP_TOP                         
                162     RETURN_CONST                    8: ''
                164     PUSH_EXC_INFO                   
                166     PUSH_NULL                       
                168     LOAD_CONST                      7: '__pyarmor_exit_54921__'
                170     NOP                             
                172     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8a\x00\x00\x00\x00\x00\x00\x00'
                174     CALL                            1
                182     POP_TOP                         
                184     RERAISE                         0
                186     COPY                            3
                188     POP_EXCEPT                      
                190     RERAISE                         1
                192     PUSH_NULL                       
                194     LOAD_CONST                      7: '__pyarmor_exit_54921__'
                196     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x8a\x00\x00\x00\x00\x00\x00\x00'
                198     BUILD_TUPLE                     1
                200     CALL_FUNCTION_EX                0
                202     POP_TOP                         
                204     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: find_output_by_re
            Qualified Name: find_output_by_re
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                're'
                'findall'
                'DOTALL'
            [Locals+Names]
                'output'
                '__assert_armored__'
                '_var_var_1'
                '_var_var_2'
            [Constants]
                None
                '__pyarmor_assert_54922__'
                '__pyarmor_enter_54923__'
                b'<COAddr>\x03\x00\x00\x1a\x84\x00\x00\x00\x00\x00\x00\x00'
                '<Output>(.*?)</Output>'
                -1
                '__pyarmor_exit_54924__'
                ''
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54923__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x84\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_CONST                      4: '<Output>(.*?)</Output>'
                30      STORE_FAST                      2: _var_var_1
                32      LOAD_GLOBAL                     1: NULL + re
                42      LOAD_ATTR                       2: findall
                62      LOAD_FAST                       2: _var_var_1
                64      LOAD_FAST                       0: output
                66      LOAD_GLOBAL                     0: re
                76      LOAD_ATTR                       4: DOTALL
                96      CALL                            3
                104     STORE_FAST                      3: _var_var_2
                106     LOAD_FAST                       3: _var_var_2
                108     POP_JUMP_IF_FALSE               14 (to 138)
                110     LOAD_FAST                       3: _var_var_2
                112     LOAD_CONST                      5: -1
                114     BINARY_SUBSCR                   
                118     NOP                             
                120     NOP                             
                122     NOP                             
                124     JUMP_FORWARD                    30 (to 186)
                126     CALL                            1
                134     POP_TOP                         
                136     RETURN_VALUE                    
                138     LOAD_CONST                      7: ''
                140     NOP                             
                142     NOP                             
                144     NOP                             
                146     JUMP_FORWARD                    19 (to 186)
                154     POP_TOP                         
                156     RETURN_CONST                    7: ''
                158     PUSH_EXC_INFO                   
                160     PUSH_NULL                       
                162     LOAD_CONST                      6: '__pyarmor_exit_54924__'
                164     NOP                             
                166     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x84\x00\x00\x00\x00\x00\x00\x00'
                168     CALL                            1
                176     POP_TOP                         
                178     RERAISE                         0
                180     COPY                            3
                182     POP_EXCEPT                      
                184     RERAISE                         1
                186     PUSH_NULL                       
                188     LOAD_CONST                      6: '__pyarmor_exit_54924__'
                190     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x84\x00\x00\x00\x00\x00\x00\x00'
                192     BUILD_TUPLE                     1
                194     CALL_FUNCTION_EX                0
                196     POP_TOP                         
                198     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: parse_model_response_json
            Qualified Name: parse_model_response_json
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'find_output_by_re'
                'strip'
                'drop_task_tag_in_output'
                'find_json_by_re'
                'startswith'
                'endswith'
                'json'
                'loads'
                'Exception'
            [Locals+Names]
                'json_str'
                '__assert_armored__'
                '_var_var_2'
                '_var_var_3'
            [Constants]
                None
                '__pyarmor_assert_54925__'
                '__pyarmor_enter_54926__'
                b'<COAddr>\x01\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                '[!] Empty model response'
                '__pyarmor_exit_54927__'
                '```json'
                7
                '```'
                -3
                '[!💥] parser json error'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54926__'
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
                28      LOAD_FAST                       0: json_str
                30      POP_JUMP_IF_TRUE                22 (to 76)
                32      LOAD_GLOBAL                     1: NULL + print
                42      LOAD_CONST                      4: '[!] Empty model response'
                44      CALL                            1
                52      POP_TOP                         
                54      NOP                             
                56      LOAD_CONST                      0: None
                58      NOP                             
                60      NOP                             
                62      NOP                             
                64      JUMP_FORWARD                    205 (to 476)
                72      POP_TOP                         
                74      RETURN_CONST                    0: None
                76      LOAD_GLOBAL                     3: NULL + find_output_by_re
                86      LOAD_FAST                       0: json_str
                88      CALL                            1
                96      LOAD_ATTR                       5: strip
                116     CALL                            0
                124     STORE_FAST                      0: json_str
                126     LOAD_GLOBAL                     7: NULL + drop_task_tag_in_output
                136     LOAD_FAST                       0: json_str
                138     CALL                            1
                146     STORE_FAST                      0: json_str
                148     LOAD_FAST                       0: json_str
                150     LOAD_ATTR                       5: strip
                170     CALL                            0
                178     STORE_FAST                      0: json_str
                180     LOAD_GLOBAL                     9: NULL + find_json_by_re
                190     LOAD_FAST                       0: json_str
                192     CALL                            1
                200     STORE_FAST                      2: _var_var_2
                202     LOAD_FAST                       2: _var_var_2
                204     POP_JUMP_IF_FALSE               2 (to 210)
                206     LOAD_FAST                       2: _var_var_2
                208     JUMP_FORWARD                    1 (to 212)
                210     LOAD_FAST                       0: json_str
                212     STORE_FAST                      0: json_str
                214     LOAD_FAST                       0: json_str
                216     LOAD_ATTR                       11: startswith
                236     LOAD_CONST                      6: '```json'
                238     CALL                            1
                246     POP_JUMP_IF_FALSE               5 (to 258)
                248     LOAD_FAST                       0: json_str
                250     LOAD_CONST                      7: 7
                252     LOAD_CONST                      0: None
                254     BINARY_SLICE                    
                256     STORE_FAST                      0: json_str
                258     LOAD_FAST                       0: json_str
                260     LOAD_ATTR                       13: endswith
                280     LOAD_CONST                      8: '```'
                282     CALL                            1
                290     POP_JUMP_IF_FALSE               5 (to 302)
                292     LOAD_FAST                       0: json_str
                294     LOAD_CONST                      0: None
                296     LOAD_CONST                      9: -3
                298     BINARY_SLICE                    
                300     STORE_FAST                      0: json_str
                302     NOP                             
                304     LOAD_GLOBAL                     15: NULL + json
                314     LOAD_ATTR                       16: loads
                334     LOAD_FAST                       0: json_str
                336     CALL                            1
                344     NOP                             
                346     NOP                             
                348     NOP                             
                350     JUMP_FORWARD                    62 (to 476)
                352     CALL                            1
                360     POP_TOP                         
                362     RETURN_VALUE                    
                364     PUSH_EXC_INFO                   
                366     LOAD_GLOBAL                     18: Exception
                376     CHECK_EXC_MATCH                 
                378     POP_JUMP_IF_FALSE               30 (to 440)
                380     STORE_FAST                      3: _var_var_3
                382     LOAD_GLOBAL                     1: NULL + print
                392     LOAD_CONST                      10: '[!💥] parser json error'
                394     CALL                            1
                402     POP_TOP                         
                404     POP_EXCEPT                      
                406     LOAD_CONST                      0: None
                408     STORE_FAST                      3: _var_var_3
                410     DELETE_FAST                     3: _var_var_3
                412     LOAD_CONST                      0: None
                414     NOP                             
                416     NOP                             
                418     NOP                             
                420     JUMP_FORWARD                    27 (to 476)
                428     POP_TOP                         
                430     RETURN_CONST                    0: None
                432     LOAD_CONST                      0: None
                434     STORE_FAST                      3: _var_var_3
                436     DELETE_FAST                     3: _var_var_3
                438     RERAISE                         1
                440     RERAISE                         0
                442     COPY                            3
                444     POP_EXCEPT                      
                446     RERAISE                         1
                448     PUSH_EXC_INFO                   
                450     PUSH_NULL                       
                452     LOAD_CONST                      5: '__pyarmor_exit_54927__'
                454     NOP                             
                456     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                458     CALL                            1
                466     POP_TOP                         
                468     RERAISE                         0
                470     COPY                            3
                472     POP_EXCEPT                      
                474     RERAISE                         1
                476     PUSH_NULL                       
                478     LOAD_CONST                      5: '__pyarmor_exit_54927__'
                480     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                482     BUILD_TUPLE                     1
                484     CALL_FUNCTION_EX                0
                486     POP_TOP                         
                488     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: parse_model_response_str
            Qualified Name: parse_model_response_str
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'find_output_by_re'
                'strip'
                'drop_task_tag_in_output'
                'startswith'
                'find'
                'endswith'
            [Locals+Names]
                'response'
                '__assert_armored__'
                '_var_var_4'
            [Constants]
                None
                '__pyarmor_assert_54928__'
                '__pyarmor_enter_54929__'
                b'<COAddr>\x03\x00\x00\x1a\\\x01\x00\x00\x00\x00\x00\x00'
                '[!] Empty model response'
                '__pyarmor_exit_54930__'
                '```'
                '\n'
                1
                -3
                '[!💥] not found <Output>...</Output>'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54929__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\\\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: response
                30      POP_JUMP_IF_TRUE                22 (to 76)
                32      LOAD_GLOBAL                     1: NULL + print
                42      LOAD_CONST                      4: '[!] Empty model response'
                44      CALL                            1
                52      POP_TOP                         
                54      NOP                             
                56      LOAD_CONST                      0: None
                58      NOP                             
                60      NOP                             
                62      NOP                             
                64      JUMP_FORWARD                    168 (to 402)
                72      POP_TOP                         
                74      RETURN_CONST                    0: None
                76      LOAD_GLOBAL                     3: NULL + find_output_by_re
                86      LOAD_FAST                       0: response
                88      CALL                            1
                96      LOAD_ATTR                       5: strip
                116     CALL                            0
                124     STORE_FAST                      2: _var_var_4
                126     LOAD_GLOBAL                     7: NULL + drop_task_tag_in_output
                136     LOAD_FAST                       2: _var_var_4
                138     CALL                            1
                146     STORE_FAST                      2: _var_var_4
                148     LOAD_FAST                       2: _var_var_4
                150     LOAD_ATTR                       5: strip
                170     CALL                            0
                178     STORE_FAST                      2: _var_var_4
                180     LOAD_FAST                       2: _var_var_4
                182     LOAD_ATTR                       9: startswith
                202     LOAD_CONST                      6: '```'
                204     CALL                            1
                212     POP_JUMP_IF_FALSE               23 (to 260)
                214     LOAD_FAST                       2: _var_var_4
                216     LOAD_FAST                       2: _var_var_4
                218     LOAD_ATTR                       11: find
                238     LOAD_CONST                      7: '\n'
                240     CALL                            1
                248     LOAD_CONST                      8: 1
                250     BINARY_OP                       0 (+)
                254     LOAD_CONST                      0: None
                256     BINARY_SLICE                    
                258     STORE_FAST                      2: _var_var_4
                260     LOAD_FAST                       2: _var_var_4
                262     LOAD_ATTR                       13: endswith
                282     LOAD_CONST                      6: '```'
                284     CALL                            1
                292     POP_JUMP_IF_FALSE               5 (to 304)
                294     LOAD_FAST                       2: _var_var_4
                296     LOAD_CONST                      0: None
                298     LOAD_CONST                      9: -3
                300     BINARY_SLICE                    
                302     STORE_FAST                      2: _var_var_4
                304     LOAD_FAST                       2: _var_var_4
                306     POP_JUMP_IF_FALSE               11 (to 330)
                308     LOAD_FAST                       2: _var_var_4
                310     NOP                             
                312     NOP                             
                314     NOP                             
                316     JUMP_FORWARD                    42 (to 402)
                318     CALL                            1
                326     POP_TOP                         
                328     RETURN_VALUE                    
                330     LOAD_GLOBAL                     1: NULL + print
                340     LOAD_CONST                      10: '[!💥] not found <Output>...</Output>'
                342     CALL                            1
                350     POP_TOP                         
                352     NOP                             
                354     LOAD_CONST                      0: None
                356     NOP                             
                358     NOP                             
                360     NOP                             
                362     JUMP_FORWARD                    19 (to 402)
                370     POP_TOP                         
                372     RETURN_CONST                    0: None
                374     PUSH_EXC_INFO                   
                376     PUSH_NULL                       
                378     LOAD_CONST                      5: '__pyarmor_exit_54930__'
                380     NOP                             
                382     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\\\x01\x00\x00\x00\x00\x00\x00'
                384     CALL                            1
                392     POP_TOP                         
                394     RERAISE                         0
                396     COPY                            3
                398     POP_EXCEPT                      
                400     RERAISE                         1
                402     PUSH_NULL                       
                404     LOAD_CONST                      5: '__pyarmor_exit_54930__'
                406     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\\\x01\x00\x00\x00\x00\x00\x00'
                408     BUILD_TUPLE                     1
                410     CALL_FUNCTION_EX                0
                412     POP_TOP                         
                414     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: parse_var_pred
            Qualified Name: parse_var_pred
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 8
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'isinstance'
                'list'
                'len'
                'append'
                'dict'
                'startswith'
                'replace'
                'strip'
                'values'
                'str'
                'split'
                'ord'
                'int'
                'keys'
                'isdigit'
            [Locals+Names]
                'var_pred'
                '__assert_armored__'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
                '_var_var_11'
                '_var_var_12'
                '_var_var_13'
                '_var_var_14'
                '_var_var_15'
                '_var_var_16'
            [Constants]
                None
                '__pyarmor_assert_54931__'
                '__pyarmor_enter_54932__'
                b'<COAddr>\x03\x00\x00\x1a0\x0e\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54933__'
                (
                    None
                    None
                    None
                    None
                )
                2
                ''
                3
                0
                'struct '
                'enum '
                1
                True
                'struct'
                False
                '*'
                'enum'
                '='
                "'"
                '"'
                4
                'array'
                ','
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54932__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a0\x0e\x00\x00\x00\x00\x00\x00'
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
                38      LOAD_FAST                       0: var_pred
                40      LOAD_GLOBAL                     2: list
                50      CALL                            2
                58      POP_JUMP_IF_TRUE                11 (to 82)
                60      NOP                             
                62      LOAD_CONST                      5: (None, None, None, None)
                64      NOP                             
                66      NOP                             
                68      JUMP_FORWARD                    1807 (to 3686)
                78      POP_TOP                         
                80      RETURN_CONST                    5: (None, None, None, None)
                82      LOAD_GLOBAL                     5: NULL + len
                92      LOAD_FAST                       0: var_pred
                94      CALL                            1
                102     LOAD_CONST                      6: 2
                104     COMPARE_OP                      2 (<)
                108     POP_JUMP_IF_FALSE               11 (to 132)
                110     NOP                             
                112     LOAD_CONST                      5: (None, None, None, None)
                114     NOP                             
                116     NOP                             
                118     JUMP_FORWARD                    1782 (to 3686)
                128     POP_TOP                         
                130     RETURN_CONST                    5: (None, None, None, None)
                132     LOAD_GLOBAL                     5: NULL + len
                142     LOAD_FAST                       0: var_pred
                144     CALL                            1
                152     LOAD_CONST                      6: 2
                154     COMPARE_OP                      40 (==)
                158     POP_JUMP_IF_FALSE               42 (to 244)
                160     LOAD_FAST                       0: var_pred
                162     LOAD_ATTR                       7: append
                182     LOAD_CONST                      7: ''
                184     CALL                            1
                192     POP_TOP                         
                194     LOAD_FAST                       0: var_pred
                196     LOAD_ATTR                       7: append
                216     LOAD_GLOBAL                     9: NULL + dict
                226     CALL                            0
                234     CALL                            1
                242     POP_TOP                         
                244     LOAD_GLOBAL                     5: NULL + len
                254     LOAD_FAST                       0: var_pred
                256     CALL                            1
                264     LOAD_CONST                      8: 3
                266     COMPARE_OP                      40 (==)
                270     POP_JUMP_IF_FALSE               25 (to 322)
                272     LOAD_FAST                       0: var_pred
                274     LOAD_ATTR                       7: append
                294     LOAD_GLOBAL                     9: NULL + dict
                304     CALL                            0
                312     CALL                            1
                320     POP_TOP                         
                322     LOAD_FAST                       0: var_pred
                324     LOAD_CONST                      9: 0
                326     BINARY_SUBSCR                   
                330     STORE_FAST                      2: _var_var_5
                332     LOAD_FAST                       2: _var_var_5
                334     LOAD_ATTR                       11: startswith
                354     LOAD_CONST                      10: 'struct '
                356     CALL                            1
                364     POP_JUMP_IF_FALSE               18 (to 402)
                366     LOAD_FAST                       2: _var_var_5
                368     LOAD_ATTR                       13: replace
                388     LOAD_CONST                      10: 'struct '
                390     LOAD_CONST                      7: ''
                392     CALL                            2
                400     STORE_FAST                      2: _var_var_5
                402     LOAD_FAST                       2: _var_var_5
                404     LOAD_ATTR                       11: startswith
                424     LOAD_CONST                      11: 'enum '
                426     CALL                            1
                434     POP_JUMP_IF_FALSE               18 (to 472)
                436     LOAD_FAST                       2: _var_var_5
                438     LOAD_ATTR                       13: replace
                458     LOAD_CONST                      11: 'enum '
                460     LOAD_CONST                      7: ''
                462     CALL                            2
                470     STORE_FAST                      2: _var_var_5
                472     LOAD_FAST                       0: var_pred
                474     LOAD_CONST                      12: 1
                476     BINARY_SUBSCR                   
                480     STORE_FAST                      3: _var_var_6
                482     LOAD_FAST                       0: var_pred
                484     LOAD_CONST                      6: 2
                486     BINARY_SUBSCR                   
                490     STORE_FAST                      4: _var_var_7
                492     LOAD_FAST                       0: var_pred
                494     LOAD_CONST                      8: 3
                496     BINARY_SUBSCR                   
                500     STORE_FAST                      5: _var_var_8
                502     LOAD_CONST                      13: True
                504     STORE_FAST                      6: _var_var_9
                506     LOAD_FAST                       4: _var_var_7
                508     LOAD_CONST                      7: ''
                510     COMPARE_OP                      40 (==)
                514     POP_JUMP_IF_FALSE               2 (to 520)
                516     JUMP_FORWARD                    1520 (to 3560)
                520     LOAD_FAST                       4: _var_var_7
                522     LOAD_CONST                      14: 'struct'
                524     COMPARE_OP                      40 (==)
                528     POP_JUMP_IF_FALSE               197 (to 924)
                530     LOAD_GLOBAL                     1: NULL + isinstance
                540     LOAD_FAST                       5: _var_var_8
                542     LOAD_GLOBAL                     2: list
                552     CALL                            2
                560     POP_JUMP_IF_FALSE               77 (to 716)
                562     LOAD_FAST                       5: _var_var_8
                564     GET_ITER                        
                566     FOR_ITER                        36 (to 640)
                570     STORE_FAST                      7: _var_var_10
                572     LOAD_GLOBAL                     1: NULL + isinstance
                582     LOAD_FAST                       7: _var_var_10
                584     LOAD_GLOBAL                     2: list
                594     CALL                            2
                602     POP_JUMP_IF_FALSE               15 (to 634)
                604     LOAD_GLOBAL                     5: NULL + len
                614     LOAD_FAST                       7: _var_var_10
                616     CALL                            1
                624     LOAD_CONST                      8: 3
                626     COMPARE_OP                      55 (!=)
                630     POP_JUMP_IF_TRUE                1 (to 634)
                632     JUMP_BACKWARD                   34 (to 566)
                634     LOAD_CONST                      15: False
                636     STORE_FAST                      6: _var_var_9
                638     POP_TOP                         
                640     JUMP_FORWARD                    1 (to 644)
                642     END_FOR                         
                644     LOAD_FAST                       2: _var_var_5
                646     LOAD_ATTR                       13: replace
                666     LOAD_CONST                      16: '*'
                668     LOAD_CONST                      7: ''
                670     CALL                            2
                678     LOAD_ATTR                       15: strip
                698     CALL                            0
                706     LOAD_FAST                       5: _var_var_8
                708     BUILD_MAP                       1
                710     STORE_FAST                      5: _var_var_8
                712     JUMP_FORWARD                    1422 (to 3560)
                716     LOAD_GLOBAL                     1: NULL + isinstance
                726     LOAD_FAST                       5: _var_var_8
                728     LOAD_GLOBAL                     8: dict
                738     CALL                            2
                746     POP_JUMP_IF_FALSE               84 (to 916)
                748     LOAD_GLOBAL                     5: NULL + len
                758     LOAD_FAST                       5: _var_var_8
                760     CALL                            1
                768     LOAD_CONST                      12: 1
                770     COMPARE_OP                      40 (==)
                774     POP_JUMP_IF_FALSE               70 (to 916)
                776     LOAD_GLOBAL                     3: NULL + list
                786     LOAD_FAST                       5: _var_var_8
                788     LOAD_ATTR                       17: values
                808     CALL                            0
                816     CALL                            1
                824     LOAD_CONST                      9: 0
                826     BINARY_SUBSCR                   
                830     GET_ITER                        
                832     FOR_ITER                        37 (to 908)
                836     STORE_FAST                      7: _var_var_10
                838     LOAD_GLOBAL                     1: NULL + isinstance
                848     LOAD_FAST                       7: _var_var_10
                850     LOAD_GLOBAL                     2: list
                860     CALL                            2
                868     POP_JUMP_IF_FALSE               15 (to 900)
                870     LOAD_GLOBAL                     5: NULL + len
                880     LOAD_FAST                       7: _var_var_10
                882     CALL                            1
                890     LOAD_CONST                      8: 3
                892     COMPARE_OP                      55 (!=)
                896     POP_JUMP_IF_TRUE                1 (to 900)
                898     JUMP_BACKWARD                   34 (to 832)
                900     LOAD_CONST                      15: False
                902     STORE_FAST                      6: _var_var_9
                904     POP_TOP                         
                906     JUMP_FORWARD                    1325 (to 3560)
                910     END_FOR                         
                912     JUMP_FORWARD                    1322 (to 3560)
                916     LOAD_CONST                      15: False
                918     STORE_FAST                      6: _var_var_9
                920     JUMP_FORWARD                    1318 (to 3560)
                924     LOAD_FAST                       4: _var_var_7
                926     LOAD_CONST                      17: 'enum'
                928     COMPARE_OP                      40 (==)
                932     POP_JUMP_IF_FALSE               1139 (to 3214)
                936     LOAD_GLOBAL                     1: NULL + isinstance
                946     LOAD_FAST                       5: _var_var_8
                948     LOAD_GLOBAL                     2: list
                958     CALL                            2
                966     POP_JUMP_IF_FALSE               489 (to 1948)
                970     BUILD_LIST                      0
                972     STORE_FAST                      8: _var_var_11
                974     LOAD_FAST                       5: _var_var_8
                976     GET_ITER                        
                978     FOR_ITER                        445 (to 1872)
                984     STORE_FAST                      7: _var_var_10
                986     LOAD_GLOBAL                     1: NULL + isinstance
                996     LOAD_FAST                       7: _var_var_10
                998     LOAD_GLOBAL                     18: str
                1008    CALL                            2
                1016    POP_JUMP_IF_FALSE               253 (to 1524)
                1018    LOAD_CONST                      18: '='
                1020    LOAD_FAST                       7: _var_var_10
                1022    CONTAINS_OP                     0 (in)
                1024    POP_JUMP_IF_FALSE               249 (to 1524)
                1026    NOP                             
                1028    LOAD_FAST                       7: _var_var_10
                1030    LOAD_ATTR                       21: split
                1050    LOAD_CONST                      18: '='
                1052    CALL                            1
                1060    STORE_FAST                      9: _var_var_12
                1062    LOAD_FAST                       9: _var_var_12
                1064    LOAD_CONST                      12: 1
                1066    BINARY_SUBSCR                   
                1070    LOAD_ATTR                       15: strip
                1090    CALL                            0
                1098    LOAD_FAST                       9: _var_var_12
                1100    LOAD_CONST                      12: 1
                1102    STORE_SUBSCR                    
                1106    LOAD_FAST                       9: _var_var_12
                1108    LOAD_CONST                      12: 1
                1110    BINARY_SUBSCR                   
                1114    LOAD_ATTR                       11: startswith
                1134    LOAD_CONST                      19: "'"
                1136    CALL                            1
                1144    POP_JUMP_IF_TRUE                20 (to 1186)
                1146    LOAD_FAST                       9: _var_var_12
                1148    LOAD_CONST                      12: 1
                1150    BINARY_SUBSCR                   
                1154    LOAD_ATTR                       11: startswith
                1174    LOAD_CONST                      20: '"'
                1176    CALL                            1
                1184    POP_JUMP_IF_FALSE               105 (to 1396)
                1186    LOAD_FAST                       9: _var_var_12
                1188    LOAD_CONST                      12: 1
                1190    BINARY_SUBSCR                   
                1194    LOAD_ATTR                       13: replace
                1214    LOAD_CONST                      19: "'"
                1216    LOAD_CONST                      7: ''
                1218    CALL                            2
                1226    LOAD_ATTR                       13: replace
                1246    LOAD_CONST                      20: '"'
                1248    LOAD_CONST                      7: ''
                1250    CALL                            2
                1258    LOAD_FAST                       9: _var_var_12
                1260    LOAD_CONST                      12: 1
                1262    STORE_SUBSCR                    
                1266    LOAD_GLOBAL                     5: NULL + len
                1276    LOAD_FAST                       9: _var_var_12
                1278    LOAD_CONST                      12: 1
                1280    BINARY_SUBSCR                   
                1284    CALL                            1
                1292    LOAD_CONST                      12: 1
                1294    COMPARE_OP                      40 (==)
                1298    POP_JUMP_IF_FALSE               48 (to 1396)
                1300    LOAD_FAST                       8: _var_var_11
                1302    LOAD_ATTR                       7: append
                1322    LOAD_FAST                       9: _var_var_12
                1324    LOAD_CONST                      9: 0
                1326    BINARY_SUBSCR                   
                1330    LOAD_ATTR                       15: strip
                1350    CALL                            0
                1358    LOAD_GLOBAL                     23: NULL + ord
                1368    LOAD_FAST                       9: _var_var_12
                1370    LOAD_CONST                      12: 1
                1372    BINARY_SUBSCR                   
                1376    CALL                            1
                1384    BUILD_LIST                      2
                1386    CALL                            1
                1394    POP_TOP                         
                1396    LOAD_FAST                       8: _var_var_11
                1398    LOAD_ATTR                       7: append
                1418    LOAD_FAST                       9: _var_var_12
                1420    LOAD_CONST                      9: 0
                1422    BINARY_SUBSCR                   
                1426    LOAD_ATTR                       15: strip
                1446    CALL                            0
                1454    LOAD_GLOBAL                     25: NULL + int
                1464    LOAD_FAST                       9: _var_var_12
                1466    LOAD_CONST                      12: 1
                1468    BINARY_SUBSCR                   
                1472    LOAD_ATTR                       15: strip
                1492    CALL                            0
                1500    CALL                            1
                1508    BUILD_LIST                      2
                1510    CALL                            1
                1518    POP_TOP                         
                1520    JUMP_BACKWARD                   273 (to 978)
                1524    LOAD_GLOBAL                     1: NULL + isinstance
                1534    LOAD_FAST                       7: _var_var_10
                1536    LOAD_GLOBAL                     2: list
                1546    CALL                            2
                1554    POP_JUMP_IF_FALSE               155 (to 1866)
                1556    LOAD_GLOBAL                     5: NULL + len
                1566    LOAD_FAST                       7: _var_var_10
                1568    CALL                            1
                1576    LOAD_CONST                      6: 2
                1578    COMPARE_OP                      92 (>=)
                1582    POP_JUMP_IF_FALSE               141 (to 1866)
                1584    LOAD_GLOBAL                     1: NULL + isinstance
                1594    LOAD_FAST                       7: _var_var_10
                1596    LOAD_CONST                      9: 0
                1598    BINARY_SUBSCR                   
                1602    LOAD_GLOBAL                     18: str
                1612    CALL                            2
                1620    POP_JUMP_IF_FALSE               122 (to 1866)
                1622    LOAD_GLOBAL                     1: NULL + isinstance
                1632    LOAD_FAST                       7: _var_var_10
                1634    LOAD_CONST                      12: 1
                1636    BINARY_SUBSCR                   
                1640    LOAD_GLOBAL                     24: int
                1650    CALL                            2
                1658    POP_JUMP_IF_FALSE               26 (to 1712)
                1660    LOAD_FAST                       8: _var_var_11
                1662    LOAD_ATTR                       7: append
                1682    LOAD_FAST                       7: _var_var_10
                1684    LOAD_CONST                      9: 0
                1686    BINARY_SUBSCR                   
                1690    LOAD_FAST                       7: _var_var_10
                1692    LOAD_CONST                      12: 1
                1694    BINARY_SUBSCR                   
                1698    BUILD_LIST                      2
                1700    CALL                            1
                1708    POP_TOP                         
                1710    JUMP_FORWARD                    75 (to 1862)
                1712    LOAD_GLOBAL                     1: NULL + isinstance
                1722    LOAD_FAST                       7: _var_var_10
                1724    LOAD_CONST                      12: 1
                1726    BINARY_SUBSCR                   
                1730    LOAD_GLOBAL                     18: str
                1740    CALL                            2
                1748    POP_JUMP_IF_FALSE               52 (to 1854)
                1750    LOAD_GLOBAL                     5: NULL + len
                1760    LOAD_FAST                       7: _var_var_10
                1762    LOAD_CONST                      12: 1
                1764    BINARY_SUBSCR                   
                1768    CALL                            1
                1776    LOAD_CONST                      12: 1
                1778    COMPARE_OP                      40 (==)
                1782    POP_JUMP_IF_FALSE               35 (to 1854)
                1784    LOAD_FAST                       8: _var_var_11
                1786    LOAD_ATTR                       7: append
                1806    LOAD_FAST                       7: _var_var_10
                1808    LOAD_CONST                      9: 0
                1810    BINARY_SUBSCR                   
                1814    LOAD_GLOBAL                     23: NULL + ord
                1824    LOAD_FAST                       7: _var_var_10
                1826    LOAD_CONST                      12: 1
                1828    BINARY_SUBSCR                   
                1832    CALL                            1
                1840    BUILD_LIST                      2
                1842    CALL                            1
                1850    POP_TOP                         
                1852    JUMP_FORWARD                    4 (to 1862)
                1854    LOAD_CONST                      15: False
                1856    STORE_FAST                      6: _var_var_9
                1858    POP_TOP                         
                1860    JUMP_FORWARD                    7 (to 1876)
                1862    JUMP_BACKWARD                   444 (to 978)
                1866    LOAD_CONST                      15: False
                1868    STORE_FAST                      6: _var_var_9
                1870    POP_TOP                         
                1872    JUMP_FORWARD                    1 (to 1876)
                1874    END_FOR                         
                1876    LOAD_FAST                       2: _var_var_5
                1878    LOAD_ATTR                       13: replace
                1898    LOAD_CONST                      16: '*'
                1900    LOAD_CONST                      7: ''
                1902    CALL                            2
                1910    LOAD_ATTR                       15: strip
                1930    CALL                            0
                1938    LOAD_FAST                       8: _var_var_11
                1940    BUILD_MAP                       1
                1942    STORE_FAST                      5: _var_var_8
                1944    JUMP_FORWARD                    806 (to 3560)
                1948    LOAD_GLOBAL                     1: NULL + isinstance
                1958    LOAD_FAST                       5: _var_var_8
                1960    LOAD_GLOBAL                     8: dict
                1970    CALL                            2
                1978    POP_JUMP_IF_FALSE               613 (to 3208)
                1982    LOAD_GLOBAL                     5: NULL + len
                1992    LOAD_FAST                       5: _var_var_8
                1994    CALL                            1
                2002    LOAD_CONST                      12: 1
                2004    COMPARE_OP                      40 (==)
                2008    POP_JUMP_IF_FALSE               598 (to 3208)
                2012    BUILD_LIST                      0
                2014    STORE_FAST                      8: _var_var_11
                2016    LOAD_CONST                      21: 4
                2018    STORE_FAST                      10: _var_var_13
                2020    LOAD_GLOBAL                     3: NULL + list
                2030    LOAD_FAST                       5: _var_var_8
                2032    LOAD_ATTR                       27: keys
                2052    CALL                            0
                2060    CALL                            1
                2068    LOAD_CONST                      9: 0
                2070    BINARY_SUBSCR                   
                2074    STORE_FAST                      11: _var_var_14
                2076    LOAD_GLOBAL                     3: NULL + list
                2086    LOAD_FAST                       5: _var_var_8
                2088    LOAD_ATTR                       17: values
                2108    CALL                            0
                2116    CALL                            1
                2124    LOAD_CONST                      9: 0
                2126    BINARY_SUBSCR                   
                2130    GET_ITER                        
                2132    FOR_ITER                        533 (to 3202)
                2138    STORE_FAST                      7: _var_var_10
                2140    LOAD_GLOBAL                     1: NULL + isinstance
                2150    LOAD_FAST                       7: _var_var_10
                2152    LOAD_GLOBAL                     18: str
                2162    CALL                            2
                2170    POP_JUMP_IF_FALSE               262 (to 2698)
                2174    LOAD_CONST                      18: '='
                2176    LOAD_FAST                       7: _var_var_10
                2178    CONTAINS_OP                     0 (in)
                2180    POP_JUMP_IF_FALSE               257 (to 2698)
                2184    NOP                             
                2186    LOAD_FAST                       7: _var_var_10
                2188    LOAD_ATTR                       21: split
                2208    LOAD_CONST                      18: '='
                2210    CALL                            1
                2218    STORE_FAST                      9: _var_var_12
                2220    LOAD_FAST                       9: _var_var_12
                2222    LOAD_CONST                      12: 1
                2224    BINARY_SUBSCR                   
                2228    LOAD_ATTR                       15: strip
                2248    CALL                            0
                2256    LOAD_FAST                       9: _var_var_12
                2258    LOAD_CONST                      12: 1
                2260    STORE_SUBSCR                    
                2264    LOAD_FAST                       9: _var_var_12
                2266    LOAD_CONST                      12: 1
                2268    BINARY_SUBSCR                   
                2272    LOAD_ATTR                       11: startswith
                2292    LOAD_CONST                      19: "'"
                2294    CALL                            1
                2302    POP_JUMP_IF_TRUE                20 (to 2344)
                2304    LOAD_FAST                       9: _var_var_12
                2306    LOAD_CONST                      12: 1
                2308    BINARY_SUBSCR                   
                2312    LOAD_ATTR                       11: startswith
                2332    LOAD_CONST                      20: '"'
                2334    CALL                            1
                2342    POP_JUMP_IF_FALSE               40 (to 2424)
                2344    LOAD_FAST                       9: _var_var_12
                2346    LOAD_CONST                      12: 1
                2348    BINARY_SUBSCR                   
                2352    LOAD_ATTR                       13: replace
                2372    LOAD_CONST                      19: "'"
                2374    LOAD_CONST                      7: ''
                2376    CALL                            2
                2384    LOAD_ATTR                       13: replace
                2404    LOAD_CONST                      20: '"'
                2406    LOAD_CONST                      7: ''
                2408    CALL                            2
                2416    LOAD_FAST                       9: _var_var_12
                2418    LOAD_CONST                      12: 1
                2420    STORE_SUBSCR                    
                2424    LOAD_GLOBAL                     5: NULL + len
                2434    LOAD_FAST                       9: _var_var_12
                2436    LOAD_CONST                      12: 1
                2438    BINARY_SUBSCR                   
                2442    CALL                            1
                2450    LOAD_CONST                      12: 1
                2452    COMPARE_OP                      40 (==)
                2456    POP_JUMP_IF_FALSE               118 (to 2694)
                2458    LOAD_FAST                       9: _var_var_12
                2460    LOAD_CONST                      12: 1
                2462    BINARY_SUBSCR                   
                2466    LOAD_ATTR                       29: isdigit
                2486    CALL                            0
                2494    POP_JUMP_IF_FALSE               50 (to 2596)
                2496    LOAD_FAST                       8: _var_var_11
                2498    LOAD_ATTR                       7: append
                2518    LOAD_FAST                       9: _var_var_12
                2520    LOAD_CONST                      9: 0
                2522    BINARY_SUBSCR                   
                2526    LOAD_ATTR                       15: strip
                2546    CALL                            0
                2554    LOAD_GLOBAL                     25: NULL + int
                2564    LOAD_FAST                       9: _var_var_12
                2566    LOAD_CONST                      12: 1
                2568    BINARY_SUBSCR                   
                2572    CALL                            1
                2580    LOAD_FAST                       10: _var_var_13
                2582    BUILD_LIST                      3
                2584    CALL                            1
                2592    POP_TOP                         
                2594    JUMP_FORWARD                    49 (to 2694)
                2596    LOAD_FAST                       8: _var_var_11
                2598    LOAD_ATTR                       7: append
                2618    LOAD_FAST                       9: _var_var_12
                2620    LOAD_CONST                      9: 0
                2622    BINARY_SUBSCR                   
                2626    LOAD_ATTR                       15: strip
                2646    CALL                            0
                2654    LOAD_GLOBAL                     23: NULL + ord
                2664    LOAD_FAST                       9: _var_var_12
                2666    LOAD_CONST                      12: 1
                2668    BINARY_SUBSCR                   
                2672    CALL                            1
                2680    LOAD_FAST                       10: _var_var_13
                2682    BUILD_LIST                      3
                2684    CALL                            1
                2692    POP_TOP                         
                2694    JUMP_BACKWARD                   283 (to 2132)
                2698    LOAD_GLOBAL                     1: NULL + isinstance
                2708    LOAD_FAST                       7: _var_var_10
                2710    LOAD_GLOBAL                     2: list
                2720    CALL                            2
                2728    POP_JUMP_IF_FALSE               233 (to 3196)
                2730    LOAD_GLOBAL                     5: NULL + len
                2740    LOAD_FAST                       7: _var_var_10
                2742    CALL                            1
                2750    LOAD_CONST                      6: 2
                2752    COMPARE_OP                      92 (>=)
                2756    POP_JUMP_IF_FALSE               219 (to 3196)
                2758    LOAD_GLOBAL                     1: NULL + isinstance
                2768    LOAD_FAST                       7: _var_var_10
                2770    LOAD_CONST                      9: 0
                2772    BINARY_SUBSCR                   
                2776    LOAD_GLOBAL                     18: str
                2786    CALL                            2
                2794    POP_JUMP_IF_FALSE               200 (to 3196)
                2796    LOAD_GLOBAL                     5: NULL + len
                2806    LOAD_FAST                       7: _var_var_10
                2808    CALL                            1
                2816    LOAD_CONST                      8: 3
                2818    COMPARE_OP                      2 (<)
                2822    POP_JUMP_IF_FALSE               2 (to 2828)
                2824    LOAD_FAST                       10: _var_var_13
                2826    JUMP_FORWARD                    4 (to 2836)
                2828    LOAD_FAST                       7: _var_var_10
                2830    LOAD_CONST                      6: 2
                2832    BINARY_SUBSCR                   
                2836    STORE_FAST                      12: _var_var_15
                2838    LOAD_GLOBAL                     1: NULL + isinstance
                2848    LOAD_FAST                       7: _var_var_10
                2850    LOAD_CONST                      12: 1
                2852    BINARY_SUBSCR                   
                2856    LOAD_GLOBAL                     24: int
                2866    CALL                            2
                2874    POP_JUMP_IF_FALSE               27 (to 2930)
                2876    LOAD_FAST                       8: _var_var_11
                2878    LOAD_ATTR                       7: append
                2898    LOAD_FAST                       7: _var_var_10
                2900    LOAD_CONST                      9: 0
                2902    BINARY_SUBSCR                   
                2906    LOAD_FAST                       7: _var_var_10
                2908    LOAD_CONST                      12: 1
                2910    BINARY_SUBSCR                   
                2914    LOAD_FAST                       12: _var_var_15
                2916    BUILD_LIST                      3
                2918    CALL                            1
                2926    POP_TOP                         
                2928    JUMP_FORWARD                    131 (to 3192)
                2930    LOAD_GLOBAL                     1: NULL + isinstance
                2940    LOAD_FAST                       7: _var_var_10
                2942    LOAD_CONST                      12: 1
                2944    BINARY_SUBSCR                   
                2948    LOAD_GLOBAL                     18: str
                2958    CALL                            2
                2966    POP_JUMP_IF_FALSE               108 (to 3184)
                2968    LOAD_GLOBAL                     5: NULL + len
                2978    LOAD_FAST                       7: _var_var_10
                2980    LOAD_CONST                      12: 1
                2982    BINARY_SUBSCR                   
                2986    CALL                            1
                2994    LOAD_CONST                      12: 1
                2996    COMPARE_OP                      40 (==)
                3000    POP_JUMP_IF_FALSE               91 (to 3184)
                3002    LOAD_FAST                       7: _var_var_10
                3004    LOAD_CONST                      12: 1
                3006    BINARY_SUBSCR                   
                3010    LOAD_ATTR                       29: isdigit
                3030    CALL                            0
                3038    POP_JUMP_IF_FALSE               36 (to 3112)
                3040    LOAD_FAST                       8: _var_var_11
                3042    LOAD_ATTR                       7: append
                3062    LOAD_FAST                       7: _var_var_10
                3064    LOAD_CONST                      9: 0
                3066    BINARY_SUBSCR                   
                3070    LOAD_GLOBAL                     25: NULL + int
                3080    LOAD_FAST                       7: _var_var_10
                3082    LOAD_CONST                      12: 1
                3084    BINARY_SUBSCR                   
                3088    CALL                            1
                3096    LOAD_FAST                       12: _var_var_15
                3098    BUILD_LIST                      3
                3100    CALL                            1
                3108    POP_TOP                         
                3110    JUMP_FORWARD                    40 (to 3192)
                3112    LOAD_FAST                       8: _var_var_11
                3114    LOAD_ATTR                       7: append
                3134    LOAD_FAST                       7: _var_var_10
                3136    LOAD_CONST                      9: 0
                3138    BINARY_SUBSCR                   
                3142    LOAD_GLOBAL                     23: NULL + ord
                3152    LOAD_FAST                       7: _var_var_10
                3154    LOAD_CONST                      12: 1
                3156    BINARY_SUBSCR                   
                3160    CALL                            1
                3168    LOAD_FAST                       12: _var_var_15
                3170    BUILD_LIST                      3
                3172    CALL                            1
                3180    POP_TOP                         
                3182    JUMP_FORWARD                    4 (to 3192)
                3184    LOAD_CONST                      15: False
                3186    STORE_FAST                      6: _var_var_9
                3188    POP_TOP                         
                3190    JUMP_FORWARD                    184 (to 3560)
                3192    JUMP_BACKWARD                   532 (to 2132)
                3196    LOAD_CONST                      15: False
                3198    STORE_FAST                      6: _var_var_9
                3200    JUMP_BACKWARD                   536 (to 2132)
                3204    END_FOR                         
                3206    JUMP_FORWARD                    176 (to 3560)
                3208    LOAD_CONST                      15: False
                3210    STORE_FAST                      6: _var_var_9
                3212    JUMP_FORWARD                    173 (to 3560)
                3214    LOAD_FAST                       4: _var_var_7
                3216    LOAD_CONST                      22: 'array'
                3218    COMPARE_OP                      40 (==)
                3222    POP_JUMP_IF_FALSE               166 (to 3556)
                3224    LOAD_GLOBAL                     1: NULL + isinstance
                3234    LOAD_FAST                       5: _var_var_8
                3236    LOAD_GLOBAL                     18: str
                3246    CALL                            2
                3254    POP_JUMP_IF_FALSE               103 (to 3462)
                3256    BUILD_LIST                      0
                3258    STORE_FAST                      8: _var_var_11
                3260    LOAD_FAST                       5: _var_var_8
                3262    LOAD_ATTR                       15: strip
                3282    CALL                            0
                3290    LOAD_ATTR                       21: split
                3310    LOAD_CONST                      23: ','
                3312    CALL                            1
                3320    GET_ITER                        
                3322    FOR_ITER                        64 (to 3452)
                3326    STORE_FAST                      13: _var_var_16
                3328    LOAD_FAST                       13: _var_var_16
                3330    LOAD_ATTR                       15: strip
                3350    CALL                            0
                3358    STORE_FAST                      13: _var_var_16
                3360    LOAD_FAST                       13: _var_var_16
                3362    LOAD_ATTR                       29: isdigit
                3382    CALL                            0
                3390    POP_JUMP_IF_FALSE               27 (to 3446)
                3392    LOAD_FAST                       8: _var_var_11
                3394    LOAD_ATTR                       7: append
                3414    LOAD_GLOBAL                     25: NULL + int
                3424    LOAD_FAST                       13: _var_var_16
                3426    CALL                            1
                3434    CALL                            1
                3442    POP_TOP                         
                3444    JUMP_BACKWARD                   62 (to 3322)
                3446    LOAD_CONST                      15: False
                3448    STORE_FAST                      6: _var_var_9
                3450    POP_TOP                         
                3452    JUMP_FORWARD                    1 (to 3456)
                3454    END_FOR                         
                3456    LOAD_FAST                       8: _var_var_11
                3458    STORE_FAST                      5: _var_var_8
                3460    JUMP_FORWARD                    49 (to 3560)
                3462    LOAD_GLOBAL                     1: NULL + isinstance
                3472    LOAD_FAST                       5: _var_var_8
                3474    LOAD_GLOBAL                     2: list
                3484    CALL                            2
                3492    POP_JUMP_IF_FALSE               28 (to 3550)
                3494    LOAD_FAST                       5: _var_var_8
                3496    GET_ITER                        
                3498    FOR_ITER                        22 (to 3544)
                3502    STORE_FAST                      13: _var_var_16
                3504    LOAD_GLOBAL                     1: NULL + isinstance
                3514    LOAD_FAST                       13: _var_var_16
                3516    LOAD_GLOBAL                     24: int
                3526    CALL                            2
                3534    POP_JUMP_IF_FALSE               1 (to 3538)
                3536    JUMP_BACKWARD                   20 (to 3498)
                3538    LOAD_CONST                      15: False
                3540    STORE_FAST                      6: _var_var_9
                3542    POP_TOP                         
                3544    JUMP_FORWARD                    7 (to 3560)
                3546    END_FOR                         
                3548    JUMP_FORWARD                    5 (to 3560)
                3550    LOAD_CONST                      15: False
                3552    STORE_FAST                      6: _var_var_9
                3554    JUMP_FORWARD                    2 (to 3560)
                3556    LOAD_CONST                      15: False
                3558    STORE_FAST                      6: _var_var_9
                3560    LOAD_FAST                       6: _var_var_9
                3562    POP_JUMP_IF_FALSE               15 (to 3594)
                3564    LOAD_FAST                       2: _var_var_5
                3566    LOAD_FAST                       3: _var_var_6
                3568    LOAD_FAST                       4: _var_var_7
                3570    LOAD_FAST                       5: _var_var_8
                3572    BUILD_TUPLE                     4
                3574    NOP                             
                3576    NOP                             
                3578    NOP                             
                3580    JUMP_FORWARD                    52 (to 3686)
                3582    CALL                            1
                3590    POP_TOP                         
                3592    RETURN_VALUE                    
                3594    NOP                             
                3596    LOAD_CONST                      5: (None, None, None, None)
                3598    NOP                             
                3600    NOP                             
                3602    NOP                             
                3604    JUMP_FORWARD                    40 (to 3686)
                3612    POP_TOP                         
                3614    RETURN_CONST                    5: (None, None, None, None)
                3616    PUSH_EXC_INFO                   
                3618    POP_TOP                         
                3620    LOAD_CONST                      15: False
                3622    STORE_FAST                      6: _var_var_9
                3624    POP_EXCEPT                      
                3626    POP_TOP                         
                3628    JUMP_BACKWARD                   878 (to 1876)
                3632    COPY                            3
                3634    POP_EXCEPT                      
                3636    RERAISE                         1
                3638    PUSH_EXC_INFO                   
                3640    POP_TOP                         
                3642    LOAD_CONST                      15: False
                3644    STORE_FAST                      6: _var_var_9
                3646    POP_EXCEPT                      
                3648    POP_TOP                         
                3650    JUMP_BACKWARD                   46 (to 3560)
                3652    COPY                            3
                3654    POP_EXCEPT                      
                3656    RERAISE                         1
                3658    PUSH_EXC_INFO                   
                3660    PUSH_NULL                       
                3662    LOAD_CONST                      4: '__pyarmor_exit_54933__'
                3664    NOP                             
                3666    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a0\x0e\x00\x00\x00\x00\x00\x00'
                3668    CALL                            1
                3676    POP_TOP                         
                3678    RERAISE                         0
                3680    COPY                            3
                3682    POP_EXCEPT                      
                3684    RERAISE                         1
                3686    PUSH_NULL                       
                3688    LOAD_CONST                      4: '__pyarmor_exit_54933__'
                3690    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a0\x0e\x00\x00\x00\x00\x00\x00'
                3692    BUILD_TUPLE                     1
                3694    CALL_FUNCTION_EX                0
                3696    POP_TOP                         
                3698    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: vars_check_and_refine
            Qualified Name: vars_check_and_refine
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 8
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'isinstance'
                'dict'
                'list'
                'get'
                'parse_var_pred'
                'len'
                'append'
            [Locals+Names]
                'var_pred_items'
                'return_type'
                '__assert_armored__'
                '_var_var_17'
                '_var_var_18'
                '_var_var_19'
                '_var_var_20'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_21'
            [Constants]
                "\n    var_pred_items: [ \n        {'original':[type, name], 'prediction':[type, name, is_complex_type, typedetails]}, \n        ... \n    ]\n    "
                '__pyarmor_assert_54934__'
                '__pyarmor_enter_54935__'
                b'<COAddr>\x03\x00\x00\x1a\x18\x02\x00\x00\x00\x00\x00\x00'
                'list'
                '__pyarmor_exit_54936__'
                'original'
                'prediction'
                2
                0
                1
                (
                    'original'
                    'prediction'
                )
                'dict'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54935__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x18\x02\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: var_pred_items
                30      POP_JUMP_IF_TRUE                19 (to 70)
                32      LOAD_FAST                       1: return_type
                34      LOAD_CONST                      4: 'list'
                36      COMPARE_OP                      40 (==)
                40      POP_JUMP_IF_FALSE               2 (to 46)
                42      BUILD_LIST                      0
                44      JUMP_FORWARD                    1 (to 48)
                46      BUILD_MAP                       0
                48      NOP                             
                50      NOP                             
                52      NOP                             
                54      JUMP_FORWARD                    266 (to 590)
                58      CALL                            1
                66      POP_TOP                         
                68      RETURN_VALUE                    
                70      LOAD_GLOBAL                     1: NULL + isinstance
                80      LOAD_FAST                       0: var_pred_items
                82      LOAD_GLOBAL                     2: dict
                92      CALL                            2
                100     POP_JUMP_IF_FALSE               3 (to 108)
                102     LOAD_FAST                       0: var_pred_items
                104     BUILD_LIST                      1
                106     STORE_FAST                      0: var_pred_items
                108     LOAD_GLOBAL                     1: NULL + isinstance
                118     LOAD_FAST                       0: var_pred_items
                120     LOAD_GLOBAL                     4: list
                130     CALL                            2
                138     POP_JUMP_IF_TRUE                19 (to 178)
                140     LOAD_FAST                       1: return_type
                142     LOAD_CONST                      4: 'list'
                144     COMPARE_OP                      40 (==)
                148     POP_JUMP_IF_FALSE               2 (to 154)
                150     BUILD_LIST                      0
                152     JUMP_FORWARD                    1 (to 156)
                154     BUILD_MAP                       0
                156     NOP                             
                158     NOP                             
                160     NOP                             
                162     NOP                             
                164     JUMP_FORWARD                    212 (to 590)
                166     CALL                            1
                174     POP_TOP                         
                176     RETURN_VALUE                    
                178     BUILD_LIST                      0
                180     STORE_FAST                      3: _var_var_17
                182     LOAD_FAST                       0: var_pred_items
                184     GET_ITER                        
                186     FOR_ITER                        129 (to 446)
                190     STORE_FAST                      4: _var_var_18
                192     LOAD_GLOBAL                     1: NULL + isinstance
                202     LOAD_FAST                       4: _var_var_18
                204     LOAD_GLOBAL                     2: dict
                214     CALL                            2
                222     POP_JUMP_IF_TRUE                1 (to 226)
                224     JUMP_BACKWARD                   20 (to 186)
                226     LOAD_FAST                       4: _var_var_18
                228     LOAD_ATTR                       7: get
                248     LOAD_CONST                      6: 'original'
                250     BUILD_LIST                      0
                252     CALL                            2
                260     STORE_FAST                      5: _var_var_19
                262     LOAD_FAST                       4: _var_var_18
                264     LOAD_ATTR                       7: get
                284     LOAD_CONST                      7: 'prediction'
                286     BUILD_LIST                      0
                288     CALL                            2
                296     STORE_FAST                      6: _var_var_20
                298     LOAD_GLOBAL                     9: NULL + parse_var_pred
                308     LOAD_FAST                       6: _var_var_20
                310     CALL                            1
                318     UNPACK_SEQUENCE                 4
                322     STORE_FAST                      7: _var_var_5
                324     STORE_FAST                      8: _var_var_6
                326     STORE_FAST                      9: _var_var_7
                328     STORE_FAST                      10: _var_var_8
                330     LOAD_GLOBAL                     11: NULL + len
                340     LOAD_FAST                       5: _var_var_19
                342     CALL                            1
                350     LOAD_CONST                      8: 2
                352     COMPARE_OP                      40 (==)
                356     POP_JUMP_IF_FALSE               17 (to 392)
                358     LOAD_FAST                       5: _var_var_19
                360     LOAD_CONST                      9: 0
                362     BINARY_SUBSCR                   
                366     LOAD_FAST                       7: _var_var_5
                368     COMPARE_OP                      40 (==)
                372     POP_JUMP_IF_FALSE               9 (to 392)
                374     LOAD_FAST                       5: _var_var_19
                376     LOAD_CONST                      10: 1
                378     BINARY_SUBSCR                   
                382     LOAD_FAST                       8: _var_var_6
                384     COMPARE_OP                      40 (==)
                388     POP_JUMP_IF_FALSE               1 (to 392)
                390     JUMP_BACKWARD                   103 (to 186)
                392     LOAD_FAST                       7: _var_var_5
                394     POP_JUMP_IF_TRUE                1 (to 398)
                396     JUMP_BACKWARD                   106 (to 186)
                398     LOAD_FAST                       3: _var_var_17
                400     LOAD_ATTR                       13: append
                420     LOAD_FAST                       5: _var_var_19
                422     LOAD_FAST                       7: _var_var_5
                424     LOAD_FAST                       8: _var_var_6
                426     LOAD_FAST                       9: _var_var_7
                428     LOAD_FAST                       10: _var_var_8
                430     BUILD_LIST                      4
                432     LOAD_CONST                      11: ('original', 'prediction')
                434     BUILD_CONST_KEY_MAP             2
                436     CALL                            1
                444     POP_TOP                         
                446     JUMP_BACKWARD                   131 (to 186)
                448     END_FOR                         
                450     LOAD_FAST                       1: return_type
                452     LOAD_CONST                      12: 'dict'
                454     COMPARE_OP                      40 (==)
                458     POP_JUMP_IF_FALSE               35 (to 530)
                460     LOAD_FAST                       3: _var_var_17
                462     GET_ITER                        
                464     LOAD_FAST_AND_CLEAR             11: _var_var_21
                466     SWAP                            2
                468     BUILD_MAP                       0
                470     SWAP                            2
                472     FOR_ITER                        14 (to 502)
                476     STORE_FAST                      11: _var_var_21
                478     LOAD_FAST                       11: _var_var_21
                480     LOAD_CONST                      6: 'original'
                482     BINARY_SUBSCR                   
                486     LOAD_CONST                      10: 1
                488     BINARY_SUBSCR                   
                492     LOAD_FAST                       11: _var_var_21
                494     LOAD_CONST                      7: 'prediction'
                496     BINARY_SUBSCR                   
                500     MAP_ADD                         2
                502     JUMP_BACKWARD                   16 (to 472)
                504     END_FOR                         
                506     SWAP                            2
                508     STORE_FAST                      11: _var_var_21
                510     NOP                             
                512     NOP                             
                514     NOP                             
                516     JUMP_FORWARD                    36 (to 590)
                518     CALL                            1
                526     POP_TOP                         
                528     RETURN_VALUE                    
                530     LOAD_FAST                       3: _var_var_17
                532     NOP                             
                534     NOP                             
                536     NOP                             
                538     JUMP_FORWARD                    25 (to 590)
                540     CALL                            1
                548     POP_TOP                         
                550     RETURN_VALUE                    
                552     SWAP                            2
                554     POP_TOP                         
                556     SWAP                            2
                558     STORE_FAST                      11: _var_var_21
                560     RERAISE                         0
                562     PUSH_EXC_INFO                   
                564     PUSH_NULL                       
                566     LOAD_CONST                      5: '__pyarmor_exit_54936__'
                568     NOP                             
                570     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x18\x02\x00\x00\x00\x00\x00\x00'
                572     CALL                            1
                580     POP_TOP                         
                582     RERAISE                         0
                584     COPY                            3
                586     POP_EXCEPT                      
                588     RERAISE                         1
                590     PUSH_NULL                       
                592     LOAD_CONST                      5: '__pyarmor_exit_54936__'
                594     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x18\x02\x00\x00\x00\x00\x00\x00'
                596     BUILD_TUPLE                     1
                598     CALL_FUNCTION_EX                0
                600     POP_TOP                         
                602     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: funcname_check_and_refine
            Qualified Name: funcname_check_and_refine
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'isinstance'
                'str'
                'strip'
                'endswith'
                'len'
                'dict'
                'list'
                'get'
                'append'
            [Locals+Names]
                'funcname_preds'
                '__assert_armored__'
                '_var_var_22'
                '_var_var_23'
                '_var_var_24'
            [Constants]
                None
                '__pyarmor_assert_54937__'
                '__pyarmor_enter_54938__'
                b'<COAddr>\x01\x00\x00\x1a0\x02\x00\x00\x00\x00\x00\x00'
                '<funcname>'
                '__pyarmor_exit_54939__'
                'original'
                ''
                'prediction'
                (
                    'original'
                    'prediction'
                )
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54938__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a0\x02\x00\x00\x00\x00\x00\x00'
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
                38      LOAD_FAST                       0: funcname_preds
                40      LOAD_GLOBAL                     2: str
                50      CALL                            2
                58      POP_JUMP_IF_FALSE               73 (to 206)
                60      LOAD_FAST                       0: funcname_preds
                62      LOAD_ATTR                       5: strip
                82      CALL                            0
                90      STORE_FAST                      0: funcname_preds
                92      LOAD_FAST                       0: funcname_preds
                94      LOAD_ATTR                       7: endswith
                114     LOAD_CONST                      4: '<funcname>'
                116     CALL                            1
                124     POP_JUMP_IF_FALSE               29 (to 184)
                126     LOAD_FAST                       0: funcname_preds
                128     LOAD_CONST                      0: None
                130     LOAD_GLOBAL                     9: NULL + len
                140     LOAD_CONST                      4: '<funcname>'
                142     CALL                            1
                150     UNARY_NEGATIVE                  
                152     BINARY_SLICE                    
                154     LOAD_ATTR                       5: strip
                174     CALL                            0
                182     STORE_FAST                      0: funcname_preds
                184     LOAD_FAST                       0: funcname_preds
                186     NOP                             
                188     NOP                             
                190     NOP                             
                192     JUMP_FORWARD                    210 (to 614)
                194     CALL                            1
                202     POP_TOP                         
                204     RETURN_VALUE                    
                206     LOAD_FAST                       0: funcname_preds
                208     POP_JUMP_IF_TRUE                11 (to 232)
                210     BUILD_LIST                      0
                212     NOP                             
                214     NOP                             
                216     NOP                             
                218     JUMP_FORWARD                    197 (to 614)
                220     CALL                            1
                228     POP_TOP                         
                230     RETURN_VALUE                    
                232     LOAD_GLOBAL                     1: NULL + isinstance
                242     LOAD_FAST                       0: funcname_preds
                244     LOAD_GLOBAL                     10: dict
                254     CALL                            2
                262     POP_JUMP_IF_FALSE               3 (to 270)
                264     LOAD_FAST                       0: funcname_preds
                266     BUILD_LIST                      1
                268     STORE_FAST                      0: funcname_preds
                270     LOAD_GLOBAL                     1: NULL + isinstance
                280     LOAD_FAST                       0: funcname_preds
                282     LOAD_GLOBAL                     12: list
                292     CALL                            2
                300     POP_JUMP_IF_TRUE                11 (to 324)
                302     BUILD_LIST                      0
                304     NOP                             
                306     NOP                             
                308     NOP                             
                310     JUMP_FORWARD                    151 (to 614)
                312     CALL                            1
                320     POP_TOP                         
                322     RETURN_VALUE                    
                324     BUILD_LIST                      0
                326     STORE_FAST                      2: _var_var_22
                328     LOAD_FAST                       0: funcname_preds
                330     GET_ITER                        
                332     FOR_ITER                        113 (to 560)
                336     STORE_FAST                      3: _var_var_23
                338     LOAD_GLOBAL                     1: NULL + isinstance
                348     LOAD_FAST                       3: _var_var_23
                350     LOAD_GLOBAL                     10: dict
                360     CALL                            2
                368     POP_JUMP_IF_TRUE                1 (to 372)
                370     JUMP_BACKWARD                   20 (to 332)
                372     LOAD_FAST                       3: _var_var_23
                374     LOAD_ATTR                       15: get
                394     LOAD_CONST                      6: 'original'
                396     LOAD_CONST                      7: ''
                398     CALL                            2
                406     STORE_FAST                      4: _var_var_24
                408     LOAD_FAST                       3: _var_var_23
                410     LOAD_ATTR                       15: get
                430     LOAD_CONST                      8: 'prediction'
                432     LOAD_CONST                      7: ''
                434     CALL                            2
                442     STORE_FAST                      3: _var_var_23
                444     LOAD_GLOBAL                     1: NULL + isinstance
                454     LOAD_FAST                       3: _var_var_23
                456     LOAD_GLOBAL                     2: str
                466     CALL                            2
                474     POP_JUMP_IF_FALSE               2 (to 480)
                476     LOAD_FAST                       3: _var_var_23
                478     POP_JUMP_IF_TRUE                1 (to 482)
                480     JUMP_BACKWARD                   75 (to 332)
                482     LOAD_GLOBAL                     1: NULL + isinstance
                492     LOAD_FAST                       4: _var_var_24
                494     LOAD_GLOBAL                     2: str
                504     CALL                            2
                512     POP_JUMP_IF_FALSE               2 (to 518)
                514     LOAD_FAST                       4: _var_var_24
                516     POP_JUMP_IF_TRUE                1 (to 520)
                518     JUMP_BACKWARD                   94 (to 332)
                520     LOAD_FAST                       2: _var_var_22
                522     LOAD_ATTR                       17: append
                542     LOAD_FAST                       4: _var_var_24
                544     LOAD_FAST                       3: _var_var_23
                546     LOAD_CONST                      9: ('original', 'prediction')
                548     BUILD_CONST_KEY_MAP             2
                550     CALL                            1
                558     POP_TOP                         
                560     JUMP_BACKWARD                   115 (to 332)
                562     END_FOR                         
                564     LOAD_FAST                       2: _var_var_22
                566     NOP                             
                568     NOP                             
                570     NOP                             
                572     JUMP_FORWARD                    20 (to 614)
                574     CALL                            1
                582     POP_TOP                         
                584     RETURN_VALUE                    
                586     PUSH_EXC_INFO                   
                588     PUSH_NULL                       
                590     LOAD_CONST                      5: '__pyarmor_exit_54939__'
                592     NOP                             
                594     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a0\x02\x00\x00\x00\x00\x00\x00'
                596     CALL                            1
                604     POP_TOP                         
                606     RERAISE                         0
                608     COPY                            3
                610     POP_EXCEPT                      
                612     RERAISE                         1
                614     PUSH_NULL                       
                616     LOAD_CONST                      5: '__pyarmor_exit_54939__'
                618     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a0\x02\x00\x00\x00\x00\x00\x00'
                620     BUILD_TUPLE                     1
                622     CALL_FUNCTION_EX                0
                624     POP_TOP                         
                626     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: summary_check_and_refine
            Qualified Name: summary_check_and_refine
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'dict'
                'isinstance'
                'str'
                'get'
                'items'
                'isdigit'
                'split'
                'textwrap'
                'fill'
            [Locals+Names]
                'summary'
                '__assert_armored__'
                '_var_var_25'
                '_var_var_26'
                '_var_var_27'
                '_var_var_28'
                '_var_var_29'
                '_var_var_30'
            [Constants]
                None
                '__pyarmor_assert_54940__'
                '__pyarmor_enter_54941__'
                b'<COAddr>\x01\x00\x00\x1a\xb6\x03\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54942__'
                'brief'
                ''
                'details'
                'params'
                'return'
                'category'
                'none'
                'algorithm'
                'inline_comment'
                '-'
                0
                70
                False
                (
                    'width'
                    'replace_whitespace'
                )
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54941__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb6\x03\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: summary
                30      POP_JUMP_IF_TRUE                19 (to 70)
                32      LOAD_GLOBAL                     1: NULL + dict
                42      CALL                            0
                50      NOP                             
                52      NOP                             
                54      JUMP_FORWARD                    473 (to 1004)
                58      CALL                            1
                66      POP_TOP                         
                68      RETURN_VALUE                    
                70      LOAD_GLOBAL                     3: NULL + isinstance
                80      LOAD_FAST                       0: summary
                82      LOAD_GLOBAL                     4: str
                92      CALL                            2
                100     POP_JUMP_IF_FALSE               11 (to 124)
                102     LOAD_FAST                       0: summary
                104     NOP                             
                106     NOP                             
                108     JUMP_FORWARD                    446 (to 1004)
                112     CALL                            1
                120     POP_TOP                         
                122     RETURN_VALUE                    
                124     BUILD_MAP                       0
                126     STORE_FAST                      2: _var_var_25
                128     LOAD_FAST                       0: summary
                130     LOAD_ATTR                       7: get
                150     LOAD_CONST                      5: 'brief'
                152     LOAD_CONST                      6: ''
                154     CALL                            2
                162     LOAD_FAST                       2: _var_var_25
                164     LOAD_CONST                      5: 'brief'
                166     STORE_SUBSCR                    
                170     LOAD_FAST                       0: summary
                172     LOAD_ATTR                       7: get
                192     LOAD_CONST                      7: 'details'
                194     LOAD_CONST                      6: ''
                196     CALL                            2
                204     LOAD_FAST                       2: _var_var_25
                206     LOAD_CONST                      7: 'details'
                208     STORE_SUBSCR                    
                212     LOAD_FAST                       0: summary
                214     LOAD_ATTR                       7: get
                234     LOAD_CONST                      8: 'params'
                236     BUILD_MAP                       0
                238     CALL                            2
                246     LOAD_FAST                       2: _var_var_25
                248     LOAD_CONST                      8: 'params'
                250     STORE_SUBSCR                    
                254     LOAD_FAST                       0: summary
                256     LOAD_ATTR                       7: get
                276     LOAD_CONST                      9: 'return'
                278     LOAD_CONST                      6: ''
                280     CALL                            2
                288     LOAD_FAST                       2: _var_var_25
                290     LOAD_CONST                      9: 'return'
                292     STORE_SUBSCR                    
                296     LOAD_FAST                       0: summary
                298     LOAD_ATTR                       7: get
                318     LOAD_CONST                      10: 'category'
                320     LOAD_CONST                      11: 'none'
                322     CALL                            2
                330     LOAD_FAST                       2: _var_var_25
                332     LOAD_CONST                      10: 'category'
                334     STORE_SUBSCR                    
                338     LOAD_FAST                       0: summary
                340     LOAD_ATTR                       7: get
                360     LOAD_CONST                      12: 'algorithm'
                362     LOAD_CONST                      11: 'none'
                364     CALL                            2
                372     LOAD_FAST                       2: _var_var_25
                374     LOAD_CONST                      12: 'algorithm'
                376     STORE_SUBSCR                    
                380     LOAD_FAST                       0: summary
                382     LOAD_ATTR                       7: get
                402     LOAD_CONST                      13: 'inline_comment'
                404     BUILD_MAP                       0
                406     CALL                            2
                414     STORE_FAST                      3: _var_var_26
                416     LOAD_GLOBAL                     3: NULL + isinstance
                426     LOAD_FAST                       3: _var_var_26
                428     LOAD_GLOBAL                     0: dict
                438     CALL                            2
                446     POP_JUMP_IF_FALSE               116 (to 680)
                448     BUILD_MAP                       0
                450     STORE_FAST                      4: _var_var_27
                452     LOAD_FAST                       3: _var_var_26
                454     LOAD_ATTR                       9: items
                474     CALL                            0
                482     GET_ITER                        
                484     FOR_ITER                        89 (to 664)
                488     UNPACK_SEQUENCE                 2
                492     STORE_FAST                      5: _var_var_28
                494     STORE_FAST                      6: _var_var_29
                496     LOAD_GLOBAL                     3: NULL + isinstance
                506     LOAD_FAST                       5: _var_var_28
                508     LOAD_GLOBAL                     4: str
                518     CALL                            2
                526     POP_JUMP_IF_TRUE                1 (to 530)
                528     JUMP_BACKWARD                   23 (to 484)
                530     LOAD_FAST                       5: _var_var_28
                532     LOAD_ATTR                       11: isdigit
                552     CALL                            0
                560     POP_JUMP_IF_FALSE               6 (to 574)
                562     LOAD_FAST                       6: _var_var_29
                564     LOAD_FAST                       4: _var_var_27
                566     LOAD_FAST                       5: _var_var_28
                568     STORE_SUBSCR                    
                572     JUMP_BACKWARD                   45 (to 484)
                574     LOAD_FAST                       5: _var_var_28
                576     LOAD_ATTR                       13: split
                596     LOAD_CONST                      14: '-'
                598     CALL                            1
                606     LOAD_CONST                      15: 0
                608     BINARY_SUBSCR                   
                612     STORE_FAST                      7: _var_var_30
                614     LOAD_FAST                       7: _var_var_30
                616     POP_JUMP_IF_TRUE                1 (to 620)
                618     JUMP_BACKWARD                   68 (to 484)
                620     LOAD_FAST                       7: _var_var_30
                622     LOAD_ATTR                       11: isdigit
                642     CALL                            0
                650     POP_JUMP_IF_TRUE                1 (to 654)
                652     JUMP_BACKWARD                   85 (to 484)
                654     LOAD_FAST                       6: _var_var_29
                656     LOAD_FAST                       4: _var_var_27
                658     LOAD_FAST                       7: _var_var_30
                660     STORE_SUBSCR                    
                664     JUMP_BACKWARD                   91 (to 484)
                666     END_FOR                         
                668     LOAD_FAST                       4: _var_var_27
                670     LOAD_FAST                       2: _var_var_25
                672     LOAD_CONST                      13: 'inline_comment'
                674     STORE_SUBSCR                    
                678     JUMP_FORWARD                    1 (to 682)
                680     NOP                             
                682     LOAD_GLOBAL                     15: NULL + textwrap
                692     LOAD_ATTR                       16: fill
                712     LOAD_FAST                       2: _var_var_25
                714     LOAD_CONST                      5: 'brief'
                716     BINARY_SUBSCR                   
                720     LOAD_CONST                      16: 70
                722     LOAD_CONST                      17: False
                724     KW_NAMES                        18: ('width', 'replace_whitespace')
                726     CALL                            3
                734     LOAD_FAST                       2: _var_var_25
                736     LOAD_CONST                      5: 'brief'
                738     STORE_SUBSCR                    
                742     LOAD_GLOBAL                     15: NULL + textwrap
                752     LOAD_ATTR                       16: fill
                772     LOAD_FAST                       2: _var_var_25
                774     LOAD_CONST                      7: 'details'
                776     BINARY_SUBSCR                   
                780     LOAD_CONST                      16: 70
                782     LOAD_CONST                      17: False
                784     KW_NAMES                        18: ('width', 'replace_whitespace')
                786     CALL                            3
                794     LOAD_FAST                       2: _var_var_25
                796     LOAD_CONST                      7: 'details'
                798     STORE_SUBSCR                    
                802     LOAD_GLOBAL                     15: NULL + textwrap
                812     LOAD_ATTR                       16: fill
                832     LOAD_FAST                       2: _var_var_25
                834     LOAD_CONST                      9: 'return'
                836     BINARY_SUBSCR                   
                840     LOAD_CONST                      16: 70
                842     LOAD_CONST                      17: False
                844     KW_NAMES                        18: ('width', 'replace_whitespace')
                846     CALL                            3
                854     LOAD_FAST                       2: _var_var_25
                856     LOAD_CONST                      9: 'return'
                858     STORE_SUBSCR                    
                862     LOAD_FAST                       2: _var_var_25
                864     LOAD_CONST                      8: 'params'
                866     BINARY_SUBSCR                   
                870     GET_ITER                        
                872     FOR_ITER                        38 (to 950)
                876     STORE_FAST                      5: _var_var_28
                878     LOAD_GLOBAL                     15: NULL + textwrap
                888     LOAD_ATTR                       16: fill
                908     LOAD_FAST                       2: _var_var_25
                910     LOAD_CONST                      8: 'params'
                912     BINARY_SUBSCR                   
                916     LOAD_FAST                       5: _var_var_28
                918     BINARY_SUBSCR                   
                922     LOAD_CONST                      16: 70
                924     LOAD_CONST                      17: False
                926     KW_NAMES                        18: ('width', 'replace_whitespace')
                928     CALL                            3
                936     LOAD_FAST                       2: _var_var_25
                938     LOAD_CONST                      8: 'params'
                940     BINARY_SUBSCR                   
                944     LOAD_FAST                       5: _var_var_28
                946     STORE_SUBSCR                    
                950     JUMP_BACKWARD                   40 (to 872)
                952     END_FOR                         
                954     LOAD_FAST                       2: _var_var_25
                956     NOP                             
                958     NOP                             
                960     NOP                             
                962     JUMP_FORWARD                    20 (to 1004)
                964     CALL                            1
                972     POP_TOP                         
                974     RETURN_VALUE                    
                976     PUSH_EXC_INFO                   
                978     PUSH_NULL                       
                980     LOAD_CONST                      4: '__pyarmor_exit_54942__'
                982     NOP                             
                984     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb6\x03\x00\x00\x00\x00\x00\x00'
                986     CALL                            1
                994     POP_TOP                         
                996     RERAISE                         0
                998     COPY                            3
                1000    POP_EXCEPT                      
                1002    RERAISE                         1
                1004    PUSH_NULL                       
                1006    LOAD_CONST                      4: '__pyarmor_exit_54942__'
                1008    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb6\x03\x00\x00\x00\x00\x00\x00'
                1010    BUILD_TUPLE                     1
                1012    CALL_FUNCTION_EX                0
                1014    POP_TOP                         
                1016    RETURN_VALUE                    
        'items'
        [Code]
            File Name: <frozen ..checker>
            Object Name: is_no_original_list
            Qualified Name: is_no_original_list
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'isinstance'
                'list'
                'len'
            [Locals+Names]
                'items'
                '__assert_armored__'
                '_var_var_16'
            [Constants]
                '\n    items: [pred_list_1, pred_list_2, ...]\n    pred_list_x: [type, name, is_complex_type, typedetails]\n    '
                '__pyarmor_assert_54943__'
                '__pyarmor_enter_54944__'
                b'<COAddr>\x03\x00\x00\x1a\x8c\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54945__'
                False
                2
                True
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54944__'
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
                28      LOAD_FAST                       0: items
                30      GET_ITER                        
                32      FOR_ITER                        54 (to 142)
                36      STORE_FAST                      2: _var_var_16
                38      LOAD_GLOBAL                     1: NULL + isinstance
                48      LOAD_FAST                       2: _var_var_16
                50      LOAD_GLOBAL                     2: list
                60      CALL                            2
                68      POP_JUMP_IF_TRUE                11 (to 92)
                70      POP_TOP                         
                72      LOAD_CONST                      5: False
                74      NOP                             
                76      NOP                             
                78      NOP                             
                80      JUMP_FORWARD                    56 (to 194)
                88      POP_TOP                         
                90      RETURN_CONST                    5: False
                92      LOAD_GLOBAL                     5: NULL + len
                102     LOAD_FAST                       2: _var_var_16
                104     CALL                            1
                112     LOAD_CONST                      6: 2
                114     COMPARE_OP                      26 (<=)
                118     POP_JUMP_IF_TRUE                1 (to 122)
                120     JUMP_BACKWARD                   45 (to 32)
                122     POP_TOP                         
                124     LOAD_CONST                      5: False
                126     NOP                             
                128     NOP                             
                130     NOP                             
                132     JUMP_FORWARD                    30 (to 194)
                140     POP_TOP                         
                142     RETURN_CONST                    5: False
                144     END_FOR                         
                146     LOAD_CONST                      7: True
                148     NOP                             
                150     NOP                             
                152     NOP                             
                154     JUMP_FORWARD                    19 (to 194)
                162     POP_TOP                         
                164     RETURN_CONST                    7: True
                166     PUSH_EXC_INFO                   
                168     PUSH_NULL                       
                170     LOAD_CONST                      4: '__pyarmor_exit_54945__'
                172     NOP                             
                174     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8c\x00\x00\x00\x00\x00\x00\x00'
                176     CALL                            1
                184     POP_TOP                         
                186     RERAISE                         0
                188     COPY                            3
                190     POP_EXCEPT                      
                192     RERAISE                         1
                194     PUSH_NULL                       
                196     LOAD_CONST                      4: '__pyarmor_exit_54945__'
                198     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8c\x00\x00\x00\x00\x00\x00\x00'
                200     BUILD_TUPLE                     1
                202     CALL_FUNCTION_EX                0
                204     POP_TOP                         
                206     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: get_func_args
            Qualified Name: get_func_args
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
            [Locals+Names]
                'func_ea'
                '__assert_armored__'
                '_var_var_31'
                '_var_var_16'
            [Constants]
                None
                '__pyarmor_assert_54946__'
                '__pyarmor_enter_54947__'
                b'<COAddr>\x01\x00\x00\x1a\x12\x01\x00\x00\x00\x00\x00\x00'
                '[!] Fail to decompile function at: '
                '__pyarmor_exit_54948__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54947__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x12\x01\x00\x00\x00\x00\x00\x00'
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
                50      STORE_FAST                      2: _var_var_31
                52      LOAD_FAST                       2: _var_var_31
                54      POP_JUMP_IF_TRUE                6 (to 68)
                56      LOAD_GLOBAL                     2: DecompilationFailure
                66      RAISE_VARARGS                   1
                68      NOP                             
                70      LOAD_FAST                       2: _var_var_31
                72      LOAD_ATTR                       8: arguments
                92      GET_ITER                        
                94      LOAD_FAST_AND_CLEAR             3: _var_var_16
                96      SWAP                            2
                98      BUILD_LIST                      0
                100     SWAP                            2
                102     FOR_ITER                        30 (to 164)
                106     STORE_FAST                      3: _var_var_16
                108     LOAD_FAST                       3: _var_var_16
                110     POP_JUMP_IF_TRUE                1 (to 114)
                112     JUMP_BACKWARD                   6 (to 102)
                114     LOAD_FAST                       3: _var_var_16
                116     LOAD_ATTR                       10: name
                136     POP_JUMP_IF_TRUE                1 (to 140)
                138     JUMP_BACKWARD                   19 (to 102)
                140     LOAD_FAST                       3: _var_var_16
                142     LOAD_ATTR                       10: name
                162     LIST_APPEND                     2
                164     JUMP_BACKWARD                   32 (to 102)
                166     END_FOR                         
                168     SWAP                            2
                170     STORE_FAST                      3: _var_var_16
                172     NOP                             
                174     NOP                             
                176     NOP                             
                178     JUMP_FORWARD                    74 (to 328)
                180     CALL                            1
                188     POP_TOP                         
                190     RETURN_VALUE                    
                192     PUSH_EXC_INFO                   
                194     LOAD_GLOBAL                     2: DecompilationFailure
                204     CHECK_EXC_MATCH                 
                206     POP_JUMP_IF_FALSE               37 (to 282)
                208     POP_TOP                         
                210     LOAD_GLOBAL                     5: NULL + print
                220     LOAD_CONST                      4: '[!] Fail to decompile function at: '
                222     LOAD_GLOBAL                     7: NULL + hex
                232     LOAD_FAST                       0: func_ea
                234     CALL                            1
                242     FORMAT_VALUE                    0 (FVC_NONE)
                244     BUILD_STRING                    2
                246     CALL                            1
                254     POP_TOP                         
                256     BUILD_LIST                      0
                258     SWAP                            2
                260     POP_EXCEPT                      
                262     NOP                             
                264     NOP                             
                266     NOP                             
                268     JUMP_FORWARD                    29 (to 328)
                270     CALL                            1
                278     POP_TOP                         
                280     RETURN_VALUE                    
                282     RERAISE                         0
                284     COPY                            3
                286     POP_EXCEPT                      
                288     RERAISE                         1
                290     SWAP                            2
                292     POP_TOP                         
                294     SWAP                            2
                296     STORE_FAST                      3: _var_var_16
                298     RERAISE                         0
                300     PUSH_EXC_INFO                   
                302     PUSH_NULL                       
                304     LOAD_CONST                      5: '__pyarmor_exit_54948__'
                306     NOP                             
                308     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x12\x01\x00\x00\x00\x00\x00\x00'
                310     CALL                            1
                318     POP_TOP                         
                320     RERAISE                         0
                322     COPY                            3
                324     POP_EXCEPT                      
                326     RERAISE                         1
                328     PUSH_NULL                       
                330     LOAD_CONST                      5: '__pyarmor_exit_54948__'
                332     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x12\x01\x00\x00\x00\x00\x00\x00'
                334     BUILD_TUPLE                     1
                336     CALL_FUNCTION_EX                0
                338     POP_TOP                         
                340     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: get_func_args_vars
            Qualified Name: get_func_args_vars
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
                'is_arg_var'
                'name'
                'arguments'
            [Locals+Names]
                'func_ea'
                '__assert_armored__'
                '_var_var_31'
                '_var_var_16'
                '_var_var_32'
                '_var_var_33'
            [Constants]
                None
                '__pyarmor_assert_54949__'
                '__pyarmor_enter_54950__'
                b'<COAddr>\x03\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                '[!] Fail to decompile function at: '
                '__pyarmor_exit_54951__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54950__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
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
                50      STORE_FAST                      2: _var_var_31
                52      LOAD_FAST                       2: _var_var_31
                54      POP_JUMP_IF_TRUE                6 (to 68)
                56      LOAD_GLOBAL                     2: DecompilationFailure
                66      RAISE_VARARGS                   1
                68      NOP                             
                70      LOAD_FAST                       2: _var_var_31
                72      LOAD_ATTR                       8: lvars
                92      GET_ITER                        
                94      LOAD_FAST_AND_CLEAR             3: _var_var_16
                96      SWAP                            2
                98      BUILD_LIST                      0
                100     SWAP                            2
                102     FOR_ITER                        43 (to 190)
                106     STORE_FAST                      3: _var_var_16
                108     LOAD_FAST                       3: _var_var_16
                110     POP_JUMP_IF_TRUE                1 (to 114)
                112     JUMP_BACKWARD                   6 (to 102)
                114     LOAD_FAST                       3: _var_var_16
                116     LOAD_ATTR                       10: is_arg_var
                136     POP_JUMP_IF_FALSE               1 (to 140)
                138     JUMP_BACKWARD                   19 (to 102)
                140     LOAD_FAST                       3: _var_var_16
                142     LOAD_ATTR                       12: name
                162     POP_JUMP_IF_TRUE                1 (to 166)
                164     JUMP_BACKWARD                   32 (to 102)
                166     LOAD_FAST                       3: _var_var_16
                168     LOAD_ATTR                       12: name
                188     LIST_APPEND                     2
                190     JUMP_BACKWARD                   45 (to 102)
                192     END_FOR                         
                194     STORE_FAST                      4: _var_var_32
                196     STORE_FAST                      3: _var_var_16
                198     LOAD_FAST                       2: _var_var_31
                200     LOAD_ATTR                       14: arguments
                220     GET_ITER                        
                222     LOAD_FAST_AND_CLEAR             3: _var_var_16
                224     SWAP                            2
                226     BUILD_LIST                      0
                228     SWAP                            2
                230     FOR_ITER                        30 (to 292)
                234     STORE_FAST                      3: _var_var_16
                236     LOAD_FAST                       3: _var_var_16
                238     POP_JUMP_IF_TRUE                1 (to 242)
                240     JUMP_BACKWARD                   6 (to 230)
                242     LOAD_FAST                       3: _var_var_16
                244     LOAD_ATTR                       12: name
                264     POP_JUMP_IF_TRUE                1 (to 268)
                266     JUMP_BACKWARD                   19 (to 230)
                268     LOAD_FAST                       3: _var_var_16
                270     LOAD_ATTR                       12: name
                290     LIST_APPEND                     2
                292     JUMP_BACKWARD                   32 (to 230)
                294     END_FOR                         
                296     STORE_FAST                      5: _var_var_33
                298     STORE_FAST                      3: _var_var_16
                300     LOAD_FAST                       5: _var_var_33
                302     LOAD_FAST                       4: _var_var_32
                304     BUILD_TUPLE                     2
                306     NOP                             
                308     NOP                             
                310     NOP                             
                312     JUMP_FORWARD                    81 (to 476)
                314     CALL                            1
                322     POP_TOP                         
                324     RETURN_VALUE                    
                326     PUSH_EXC_INFO                   
                328     LOAD_GLOBAL                     2: DecompilationFailure
                338     CHECK_EXC_MATCH                 
                340     POP_JUMP_IF_FALSE               39 (to 420)
                342     POP_TOP                         
                344     LOAD_GLOBAL                     5: NULL + print
                354     LOAD_CONST                      4: '[!] Fail to decompile function at: '
                356     LOAD_GLOBAL                     7: NULL + hex
                366     LOAD_FAST                       0: func_ea
                368     CALL                            1
                376     FORMAT_VALUE                    0 (FVC_NONE)
                378     BUILD_STRING                    2
                380     CALL                            1
                388     POP_TOP                         
                390     BUILD_LIST                      0
                392     BUILD_LIST                      0
                394     BUILD_TUPLE                     2
                396     SWAP                            2
                398     POP_EXCEPT                      
                400     NOP                             
                402     NOP                             
                404     NOP                             
                406     JUMP_FORWARD                    34 (to 476)
                408     CALL                            1
                416     POP_TOP                         
                418     RETURN_VALUE                    
                420     RERAISE                         0
                422     COPY                            3
                424     POP_EXCEPT                      
                426     RERAISE                         1
                428     SWAP                            2
                430     POP_TOP                         
                432     SWAP                            2
                434     STORE_FAST                      3: _var_var_16
                436     RERAISE                         0
                438     SWAP                            2
                440     POP_TOP                         
                442     SWAP                            2
                444     STORE_FAST                      3: _var_var_16
                446     RERAISE                         0
                448     PUSH_EXC_INFO                   
                450     PUSH_NULL                       
                452     LOAD_CONST                      5: '__pyarmor_exit_54951__'
                454     NOP                             
                456     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                458     CALL                            1
                466     POP_TOP                         
                468     RERAISE                         0
                470     COPY                            3
                472     POP_EXCEPT                      
                474     RERAISE                         1
                476     PUSH_NULL                       
                478     LOAD_CONST                      5: '__pyarmor_exit_54951__'
                480     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa6\x01\x00\x00\x00\x00\x00\x00'
                482     BUILD_TUPLE                     1
                484     CALL_FUNCTION_EX                0
                486     POP_TOP                         
                488     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: func_analysis_check_and_refine
            Qualified Name: func_analysis_check_and_refine
            Arg Count: 3
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 6
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'dict'
                'summary_check_and_refine'
                'funcname_check_and_refine'
                'get'
                'isinstance'
                'list'
                'print'
                'str'
                'items'
                'append'
                'vars_check_and_refine'
                'is_no_original_list'
                'enumerate'
                'len'
                'update'
            [Locals+Names]
                'func_analysis'
                'arg_names'
                'var_names'
                '__assert_armored__'
                '_var_var_34'
                '_var_var_35'
                '_var_var_36'
                '_var_var_37'
                '_var_var_38'
                '_var_var_39'
                '_var_var_40'
                '_var_var_41'
                '_var_var_42'
                '_var_var_43'
                '_var_var_44'
                '_var_var_45'
                '_var_var_46'
                '_var_var_47'
                '_var_var_48'
                '_var_var_49'
            [Constants]
                None
                '__pyarmor_assert_54952__'
                '__pyarmor_enter_54953__'
                b'<COAddr>\x01\x00\x00\x1a\xea\x04\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54954__'
                'funcname'
                ''
                'ret_type'
                'vars'
                '[!] found bad vars in prediction: '
                (
                    'original'
                    'prediction'
                )
                'prediction'
                'original'
                1
                'args'
                '[!] found bad args in prediction: '
                'a'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54953__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xea\x04\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       1: arg_names
                30      LOAD_CONST                      0: None
                32      COMPARE_OP                      40 (==)
                36      POP_JUMP_IF_FALSE               2 (to 42)
                38      BUILD_LIST                      0
                40      STORE_FAST                      1: arg_names
                42      LOAD_FAST                       2: var_names
                44      LOAD_CONST                      0: None
                46      COMPARE_OP                      40 (==)
                50      POP_JUMP_IF_FALSE               2 (to 56)
                52      BUILD_LIST                      0
                54      STORE_FAST                      2: var_names
                56      LOAD_FAST                       0: func_analysis
                58      POP_JUMP_IF_TRUE                19 (to 98)
                60      LOAD_GLOBAL                     1: NULL + dict
                70      CALL                            0
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    613 (to 1312)
                86      CALL                            1
                94      POP_TOP                         
                96      RETURN_VALUE                    
                98      BUILD_MAP                       0
                100     STORE_FAST                      4: _var_var_34
                102     LOAD_GLOBAL                     3: NULL + summary_check_and_refine
                112     LOAD_FAST                       0: func_analysis
                114     CALL                            1
                122     STORE_FAST                      5: _var_var_35
                124     LOAD_GLOBAL                     5: NULL + funcname_check_and_refine
                134     LOAD_FAST                       0: func_analysis
                136     LOAD_ATTR                       7: get
                156     LOAD_CONST                      5: 'funcname'
                158     LOAD_CONST                      6: ''
                160     CALL                            2
                168     CALL                            1
                176     LOAD_FAST                       4: _var_var_34
                178     LOAD_CONST                      5: 'funcname'
                180     STORE_SUBSCR                    
                184     LOAD_FAST                       0: func_analysis
                186     LOAD_ATTR                       7: get
                206     LOAD_CONST                      7: 'ret_type'
                208     LOAD_CONST                      6: ''
                210     CALL                            2
                218     LOAD_FAST                       4: _var_var_34
                220     LOAD_CONST                      7: 'ret_type'
                222     STORE_SUBSCR                    
                226     BUILD_LIST                      0
                228     STORE_FAST                      6: _var_var_36
                230     LOAD_FAST                       0: func_analysis
                232     LOAD_ATTR                       7: get
                252     LOAD_CONST                      8: 'vars'
                254     BUILD_MAP                       0
                256     CALL                            2
                264     STORE_FAST                      7: _var_var_37
                266     LOAD_GLOBAL                     9: NULL + isinstance
                276     LOAD_FAST                       7: _var_var_37
                278     LOAD_GLOBAL                     0: dict
                288     CALL                            2
                296     POP_JUMP_IF_TRUE                41 (to 380)
                298     LOAD_GLOBAL                     9: NULL + isinstance
                308     LOAD_FAST                       7: _var_var_37
                310     LOAD_GLOBAL                     10: list
                320     CALL                            2
                328     POP_JUMP_IF_TRUE                25 (to 380)
                330     LOAD_GLOBAL                     13: NULL + print
                340     LOAD_CONST                      9: '[!] found bad vars in prediction: '
                342     LOAD_GLOBAL                     15: NULL + str
                352     LOAD_FAST                       7: _var_var_37
                354     CALL                            1
                362     FORMAT_VALUE                    0 (FVC_NONE)
                364     BUILD_STRING                    2
                366     CALL                            1
                374     POP_TOP                         
                376     BUILD_MAP                       0
                378     STORE_FAST                      7: _var_var_37
                380     LOAD_GLOBAL                     9: NULL + isinstance
                390     LOAD_FAST                       7: _var_var_37
                392     LOAD_GLOBAL                     10: list
                402     CALL                            2
                410     POP_JUMP_IF_FALSE               3 (to 418)
                412     LOAD_FAST                       7: _var_var_37
                414     STORE_FAST                      6: _var_var_36
                416     JUMP_FORWARD                    67 (to 552)
                418     LOAD_GLOBAL                     9: NULL + isinstance
                428     LOAD_FAST                       7: _var_var_37
                430     LOAD_GLOBAL                     0: dict
                440     CALL                            2
                448     POP_JUMP_IF_FALSE               51 (to 552)
                450     LOAD_FAST                       7: _var_var_37
                452     LOAD_ATTR                       17: items
                472     CALL                            0
                480     GET_ITER                        
                482     FOR_ITER                        32 (to 548)
                486     UNPACK_SEQUENCE                 2
                490     STORE_FAST                      8: _var_var_38
                492     STORE_FAST                      9: _var_var_39
                494     LOAD_FAST                       8: _var_var_38
                496     LOAD_FAST                       2: var_names
                498     CONTAINS_OP                     0 (in)
                500     POP_JUMP_IF_TRUE                1 (to 504)
                502     JUMP_BACKWARD                   11 (to 482)
                504     LOAD_FAST                       6: _var_var_36
                506     LOAD_ATTR                       19: append
                526     LOAD_CONST                      6: ''
                528     LOAD_FAST                       8: _var_var_38
                530     BUILD_LIST                      2
                532     LOAD_FAST                       9: _var_var_39
                534     LOAD_CONST                      10: ('original', 'prediction')
                536     BUILD_CONST_KEY_MAP             2
                538     CALL                            1
                546     POP_TOP                         
                548     JUMP_BACKWARD                   34 (to 482)
                550     END_FOR                         
                552     LOAD_GLOBAL                     21: NULL + vars_check_and_refine
                562     LOAD_FAST                       6: _var_var_36
                564     CALL                            1
                572     STORE_FAST                      10: _var_var_40
                574     LOAD_GLOBAL                     1: NULL + dict
                584     CALL                            0
                592     STORE_FAST                      11: _var_var_41
                594     LOAD_FAST                       10: _var_var_40
                596     GET_ITER                        
                598     FOR_ITER                        16 (to 632)
                602     STORE_FAST                      12: _var_var_42
                604     LOAD_FAST                       12: _var_var_42
                606     LOAD_CONST                      11: 'prediction'
                608     BINARY_SUBSCR                   
                612     LOAD_FAST                       11: _var_var_41
                614     LOAD_FAST                       12: _var_var_42
                616     LOAD_CONST                      12: 'original'
                618     BINARY_SUBSCR                   
                622     LOAD_CONST                      13: 1
                624     BINARY_SUBSCR                   
                628     STORE_SUBSCR                    
                632     JUMP_BACKWARD                   18 (to 598)
                634     END_FOR                         
                636     LOAD_FAST                       11: _var_var_41
                638     LOAD_FAST                       4: _var_var_34
                640     LOAD_CONST                      8: 'vars'
                642     STORE_SUBSCR                    
                646     BUILD_LIST                      0
                648     STORE_FAST                      13: _var_var_43
                650     LOAD_FAST                       0: func_analysis
                652     LOAD_ATTR                       7: get
                672     LOAD_CONST                      14: 'args'
                674     BUILD_MAP                       0
                676     CALL                            2
                684     STORE_FAST                      14: _var_var_44
                686     LOAD_GLOBAL                     9: NULL + isinstance
                696     LOAD_FAST                       14: _var_var_44
                698     LOAD_GLOBAL                     0: dict
                708     CALL                            2
                716     POP_JUMP_IF_TRUE                41 (to 800)
                718     LOAD_GLOBAL                     9: NULL + isinstance
                728     LOAD_FAST                       14: _var_var_44
                730     LOAD_GLOBAL                     10: list
                740     CALL                            2
                748     POP_JUMP_IF_TRUE                25 (to 800)
                750     LOAD_GLOBAL                     13: NULL + print
                760     LOAD_CONST                      15: '[!] found bad args in prediction: '
                762     LOAD_GLOBAL                     15: NULL + str
                772     LOAD_FAST                       14: _var_var_44
                774     CALL                            1
                782     FORMAT_VALUE                    0 (FVC_NONE)
                784     BUILD_STRING                    2
                786     CALL                            1
                794     POP_TOP                         
                796     BUILD_MAP                       0
                798     STORE_FAST                      14: _var_var_44
                800     LOAD_GLOBAL                     9: NULL + isinstance
                810     LOAD_FAST                       14: _var_var_44
                812     LOAD_GLOBAL                     10: list
                822     CALL                            2
                830     POP_JUMP_IF_FALSE               84 (to 1000)
                832     LOAD_GLOBAL                     23: NULL + is_no_original_list
                842     LOAD_FAST                       14: _var_var_44
                844     CALL                            1
                852     POP_JUMP_IF_FALSE               70 (to 994)
                854     LOAD_GLOBAL                     25: NULL + enumerate
                864     LOAD_FAST                       14: _var_var_44
                866     LOAD_CONST                      13: 1
                868     CALL                            2
                876     GET_ITER                        
                878     FOR_ITER                        54 (to 988)
                882     UNPACK_SEQUENCE                 2
                886     STORE_FAST                      15: _var_var_45
                888     STORE_FAST                      9: _var_var_39
                890     LOAD_FAST                       15: _var_var_45
                892     LOAD_GLOBAL                     27: NULL + len
                902     LOAD_FAST                       1: arg_names
                904     CALL                            1
                912     COMPARE_OP                      26 (<=)
                916     POP_JUMP_IF_FALSE               8 (to 934)
                918     LOAD_FAST                       1: arg_names
                920     LOAD_FAST                       15: _var_var_45
                922     LOAD_CONST                      13: 1
                924     BINARY_OP                       10 (-)
                928     BINARY_SUBSCR                   
                932     JUMP_FORWARD                    4 (to 942)
                934     LOAD_CONST                      16: 'a'
                936     LOAD_FAST                       15: _var_var_45
                938     FORMAT_VALUE                    0 (FVC_NONE)
                940     BUILD_STRING                    2
                942     STORE_FAST                      16: _var_var_46
                944     LOAD_FAST                       13: _var_var_43
                946     LOAD_ATTR                       19: append
                966     LOAD_CONST                      6: ''
                968     LOAD_FAST                       16: _var_var_46
                970     BUILD_LIST                      2
                972     LOAD_FAST                       9: _var_var_39
                974     LOAD_CONST                      10: ('original', 'prediction')
                976     BUILD_CONST_KEY_MAP             2
                978     CALL                            1
                986     POP_TOP                         
                988     JUMP_BACKWARD                   56 (to 878)
                990     END_FOR                         
                992     JUMP_FORWARD                    70 (to 1134)
                994     LOAD_FAST                       14: _var_var_44
                996     STORE_FAST                      13: _var_var_43
                998     JUMP_FORWARD                    67 (to 1134)
                1000    LOAD_GLOBAL                     9: NULL + isinstance
                1010    LOAD_FAST                       14: _var_var_44
                1012    LOAD_GLOBAL                     0: dict
                1022    CALL                            2
                1030    POP_JUMP_IF_FALSE               51 (to 1134)
                1032    LOAD_FAST                       14: _var_var_44
                1034    LOAD_ATTR                       17: items
                1054    CALL                            0
                1062    GET_ITER                        
                1064    FOR_ITER                        32 (to 1130)
                1068    UNPACK_SEQUENCE                 2
                1072    STORE_FAST                      8: _var_var_38
                1074    STORE_FAST                      9: _var_var_39
                1076    LOAD_FAST                       8: _var_var_38
                1078    LOAD_FAST                       1: arg_names
                1080    CONTAINS_OP                     0 (in)
                1082    POP_JUMP_IF_TRUE                1 (to 1086)
                1084    JUMP_BACKWARD                   11 (to 1064)
                1086    LOAD_FAST                       13: _var_var_43
                1088    LOAD_ATTR                       19: append
                1108    LOAD_CONST                      6: ''
                1110    LOAD_FAST                       8: _var_var_38
                1112    BUILD_LIST                      2
                1114    LOAD_FAST                       9: _var_var_39
                1116    LOAD_CONST                      10: ('original', 'prediction')
                1118    BUILD_CONST_KEY_MAP             2
                1120    CALL                            1
                1128    POP_TOP                         
                1130    JUMP_BACKWARD                   34 (to 1064)
                1132    END_FOR                         
                1134    LOAD_GLOBAL                     21: NULL + vars_check_and_refine
                1144    LOAD_FAST                       13: _var_var_43
                1146    CALL                            1
                1154    STORE_FAST                      17: _var_var_47
                1156    LOAD_GLOBAL                     1: NULL + dict
                1166    CALL                            0
                1174    STORE_FAST                      18: _var_var_48
                1176    LOAD_FAST                       17: _var_var_47
                1178    GET_ITER                        
                1180    FOR_ITER                        16 (to 1214)
                1184    STORE_FAST                      19: _var_var_49
                1186    LOAD_FAST                       19: _var_var_49
                1188    LOAD_CONST                      11: 'prediction'
                1190    BINARY_SUBSCR                   
                1194    LOAD_FAST                       18: _var_var_48
                1196    LOAD_FAST                       19: _var_var_49
                1198    LOAD_CONST                      12: 'original'
                1200    BINARY_SUBSCR                   
                1204    LOAD_CONST                      13: 1
                1206    BINARY_SUBSCR                   
                1210    STORE_SUBSCR                    
                1214    JUMP_BACKWARD                   18 (to 1180)
                1216    END_FOR                         
                1218    LOAD_FAST                       18: _var_var_48
                1220    LOAD_FAST                       4: _var_var_34
                1222    LOAD_CONST                      14: 'args'
                1224    STORE_SUBSCR                    
                1228    LOAD_FAST                       4: _var_var_34
                1230    LOAD_ATTR                       29: update
                1250    LOAD_FAST                       5: _var_var_35
                1252    CALL                            1
                1260    POP_TOP                         
                1262    LOAD_FAST                       4: _var_var_34
                1264    NOP                             
                1266    NOP                             
                1268    NOP                             
                1270    JUMP_FORWARD                    20 (to 1312)
                1272    CALL                            1
                1280    POP_TOP                         
                1282    RETURN_VALUE                    
                1284    PUSH_EXC_INFO                   
                1286    PUSH_NULL                       
                1288    LOAD_CONST                      4: '__pyarmor_exit_54954__'
                1290    NOP                             
                1292    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xea\x04\x00\x00\x00\x00\x00\x00'
                1294    CALL                            1
                1302    POP_TOP                         
                1304    RERAISE                         0
                1306    COPY                            3
                1308    POP_EXCEPT                      
                1310    RERAISE                         1
                1312    PUSH_NULL                       
                1314    LOAD_CONST                      4: '__pyarmor_exit_54954__'
                1316    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xea\x04\x00\x00\x00\x00\x00\x00'
                1318    BUILD_TUPLE                     1
                1320    CALL_FUNCTION_EX                0
                1322    POP_TOP                         
                1324    RETURN_VALUE                    
        [Code]
            File Name: <frozen ..checker>
            Object Name: response_check_and_refine
            Qualified Name: response_check_and_refine
            Arg Count: 4
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'func_analysis_check_and_refine'
                'vars_check_and_refine'
                'funcname_check_and_refine'
                'summary_check_and_refine'
                'NotImplementedError'
            [Locals+Names]
                'response'
                'task_tag'
                'arg_names'
                'var_names'
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_54955__'
                '__pyarmor_enter_54956__'
                b'<COAddr>\x01\x00\x00\x1a\xac\x01\x00\x00\x00\x00\x00\x00'
                '[!] Empty model response'
                '__pyarmor_exit_54957__'
                '<func-analysis>'
                '[!] Error: need pass arg_names and var_names for checking response of func-analysis task'
                '<vars>'
                'dict'
                (
                    'return_type'
                )
                '<args>'
                '<specific-vars>'
                '<funcname>'
                '<summary>'
                'Not implemented task tag: '
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54956__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xac\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: response
                30      POP_JUMP_IF_TRUE                22 (to 76)
                32      LOAD_GLOBAL                     1: NULL + print
                42      LOAD_CONST                      4: '[!] Empty model response'
                44      CALL                            1
                52      POP_TOP                         
                54      NOP                             
                56      LOAD_CONST                      0: None
                58      NOP                             
                60      NOP                             
                62      NOP                             
                64      JUMP_FORWARD                    208 (to 482)
                72      POP_TOP                         
                74      RETURN_CONST                    0: None
                76      LOAD_FAST                       1: task_tag
                78      LOAD_CONST                      6: '<func-analysis>'
                80      COMPARE_OP                      40 (==)
                84      POP_JUMP_IF_FALSE               39 (to 164)
                86      LOAD_FAST                       2: arg_names
                88      LOAD_CONST                      0: None
                90      COMPARE_OP                      55 (!=)
                94      POP_JUMP_IF_FALSE               5 (to 106)
                96      LOAD_FAST                       3: var_names
                98      LOAD_CONST                      0: None
                100     COMPARE_OP                      55 (!=)
                104     POP_JUMP_IF_TRUE                7 (to 120)
                106     LOAD_ASSERTION_ERROR            
                108     LOAD_CONST                      7: '[!] Error: need pass arg_names and var_names for checking response of func-analysis task'
                110     CALL                            0
                118     RAISE_VARARGS                   1
                120     LOAD_GLOBAL                     3: NULL + func_analysis_check_and_refine
                130     LOAD_FAST                       0: response
                132     LOAD_FAST                       2: arg_names
                134     LOAD_FAST                       3: var_names
                136     CALL                            3
                144     NOP                             
                146     NOP                             
                148     NOP                             
                150     JUMP_FORWARD                    165 (to 482)
                152     CALL                            1
                160     POP_TOP                         
                162     RETURN_VALUE                    
                164     LOAD_FAST                       1: task_tag
                166     LOAD_CONST                      8: '<vars>'
                168     COMPARE_OP                      40 (==)
                172     POP_JUMP_IF_FALSE               22 (to 218)
                174     LOAD_GLOBAL                     5: NULL + vars_check_and_refine
                184     LOAD_FAST                       0: response
                186     LOAD_CONST                      9: 'dict'
                188     KW_NAMES                        10: ('return_type',)
                190     CALL                            2
                198     NOP                             
                200     NOP                             
                202     NOP                             
                204     JUMP_FORWARD                    138 (to 482)
                206     CALL                            1
                214     POP_TOP                         
                216     RETURN_VALUE                    
                218     LOAD_FAST                       1: task_tag
                220     LOAD_CONST                      11: '<args>'
                222     COMPARE_OP                      40 (==)
                226     POP_JUMP_IF_FALSE               22 (to 272)
                228     LOAD_GLOBAL                     5: NULL + vars_check_and_refine
                238     LOAD_FAST                       0: response
                240     LOAD_CONST                      9: 'dict'
                242     KW_NAMES                        10: ('return_type',)
                244     CALL                            2
                252     NOP                             
                254     NOP                             
                256     NOP                             
                258     JUMP_FORWARD                    111 (to 482)
                260     CALL                            1
                268     POP_TOP                         
                270     RETURN_VALUE                    
                272     LOAD_FAST                       1: task_tag
                274     LOAD_CONST                      12: '<specific-vars>'
                276     COMPARE_OP                      40 (==)
                280     POP_JUMP_IF_FALSE               22 (to 326)
                282     LOAD_GLOBAL                     5: NULL + vars_check_and_refine
                292     LOAD_FAST                       0: response
                294     LOAD_CONST                      9: 'dict'
                296     KW_NAMES                        10: ('return_type',)
                298     CALL                            2
                306     NOP                             
                308     NOP                             
                310     NOP                             
                312     JUMP_FORWARD                    84 (to 482)
                314     CALL                            1
                322     POP_TOP                         
                324     RETURN_VALUE                    
                326     LOAD_FAST                       1: task_tag
                328     LOAD_CONST                      13: '<funcname>'
                330     COMPARE_OP                      40 (==)
                334     POP_JUMP_IF_FALSE               20 (to 376)
                336     LOAD_GLOBAL                     7: NULL + funcname_check_and_refine
                346     LOAD_FAST                       0: response
                348     CALL                            1
                356     NOP                             
                358     NOP                             
                360     NOP                             
                362     JUMP_FORWARD                    59 (to 482)
                364     CALL                            1
                372     POP_TOP                         
                374     RETURN_VALUE                    
                376     LOAD_FAST                       1: task_tag
                378     LOAD_CONST                      14: '<summary>'
                380     COMPARE_OP                      40 (==)
                384     POP_JUMP_IF_FALSE               20 (to 426)
                386     LOAD_GLOBAL                     9: NULL + summary_check_and_refine
                396     LOAD_FAST                       0: response
                398     CALL                            1
                406     NOP                             
                408     NOP                             
                410     NOP                             
                412     JUMP_FORWARD                    34 (to 482)
                414     CALL                            1
                422     POP_TOP                         
                424     RETURN_VALUE                    
                426     LOAD_GLOBAL                     11: NULL + NotImplementedError
                436     LOAD_CONST                      15: 'Not implemented task tag: '
                438     LOAD_FAST                       1: task_tag
                440     FORMAT_VALUE                    0 (FVC_NONE)
                442     BUILD_STRING                    2
                444     CALL                            1
                452     RAISE_VARARGS                   1
                454     PUSH_EXC_INFO                   
                456     PUSH_NULL                       
                458     LOAD_CONST                      5: '__pyarmor_exit_54957__'
                460     NOP                             
                462     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xac\x01\x00\x00\x00\x00\x00\x00'
                464     CALL                            1
                472     POP_TOP                         
                474     RERAISE                         0
                476     COPY                            3
                478     POP_EXCEPT                      
                480     RERAISE                         1
                482     PUSH_NULL                       
                484     LOAD_CONST                      5: '__pyarmor_exit_54957__'
                486     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xac\x01\x00\x00\x00\x00\x00\x00'
                488     BUILD_TUPLE                     1
                490     CALL_FUNCTION_EX                0
                492     POP_TOP                         
                494     RETURN_VALUE                    
        'response'
        [Code]
            File Name: <frozen ..checker>
            Object Name: split_pred_to_var_arg
            Qualified Name: split_pred_to_var_arg
            Arg Count: 2
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
            [Locals+Names]
                'func_ea'
                'response'
                '__assert_armored__'
                '_var_var_50'
                '_var_var_31'
                '_var_var_42'
                '_var_var_38'
            [Constants]
                '\n    Split the response to vars and args\n    need run with ida_execute\n    '
                '__pyarmor_assert_54958__'
                '__pyarmor_enter_54959__'
                b'<COAddr>\x03\x00\x00\x1ax\x01\x00\x00\x00\x00\x00\x00'
                (
                    'vars'
                    'args'
                )
                '__pyarmor_exit_54960__'
                '[!] Fail to decompile function at: '
                'args'
                'vars'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54959__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x01\x00\x00\x00\x00\x00\x00'
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
                30      BUILD_MAP                       0
                32      LOAD_CONST                      4: ('vars', 'args')
                34      BUILD_CONST_KEY_MAP             2
                36      STORE_FAST                      3: _var_var_50
                38      LOAD_FAST                       1: response
                40      POP_JUMP_IF_TRUE                11 (to 64)
                42      LOAD_FAST                       3: _var_var_50
                44      NOP                             
                46      NOP                             
                48      NOP                             
                50      JUMP_FORWARD                    189 (to 430)
                52      CALL                            1
                60      POP_TOP                         
                62      RETURN_VALUE                    
                64      NOP                             
                66      LOAD_GLOBAL                     1: NULL + decompile
                76      LOAD_FAST                       0: func_ea
                78      CALL                            1
                86      STORE_FAST                      4: _var_var_31
                88      LOAD_FAST                       4: _var_var_31
                90      POP_JUMP_IF_TRUE                6 (to 104)
                92      LOAD_GLOBAL                     2: DecompilationFailure
                102     RAISE_VARARGS                   1
                104     NOP                             
                106     LOAD_FAST                       4: _var_var_31
                108     LOAD_ATTR                       8: lvars
                128     GET_ITER                        
                130     FOR_ITER                        73 (to 278)
                134     STORE_FAST                      5: _var_var_42
                136     LOAD_FAST                       5: _var_var_42
                138     LOAD_ATTR                       10: name
                158     POP_JUMP_IF_TRUE                1 (to 162)
                160     JUMP_BACKWARD                   16 (to 130)
                162     LOAD_FAST                       1: response
                164     GET_ITER                        
                166     FOR_ITER                        53 (to 274)
                170     STORE_FAST                      6: _var_var_38
                172     LOAD_FAST                       6: _var_var_38
                174     LOAD_FAST                       5: _var_var_42
                176     LOAD_ATTR                       10: name
                196     COMPARE_OP                      40 (==)
                200     POP_JUMP_IF_TRUE                1 (to 204)
                202     JUMP_BACKWARD                   19 (to 166)
                204     LOAD_FAST                       5: _var_var_42
                206     LOAD_ATTR                       12: is_arg_var
                226     POP_JUMP_IF_FALSE               12 (to 252)
                228     LOAD_FAST                       1: response
                230     LOAD_FAST                       6: _var_var_38
                232     BINARY_SUBSCR                   
                236     LOAD_FAST                       3: _var_var_50
                238     LOAD_CONST                      7: 'args'
                240     BINARY_SUBSCR                   
                244     LOAD_FAST                       6: _var_var_38
                246     STORE_SUBSCR                    
                250     JUMP_BACKWARD                   43 (to 166)
                252     LOAD_FAST                       1: response
                254     LOAD_FAST                       6: _var_var_38
                256     BINARY_SUBSCR                   
                260     LOAD_FAST                       3: _var_var_50
                262     LOAD_CONST                      8: 'vars'
                264     BINARY_SUBSCR                   
                268     LOAD_FAST                       6: _var_var_38
                270     STORE_SUBSCR                    
                274     JUMP_BACKWARD                   55 (to 166)
                276     END_FOR                         
                278     JUMP_BACKWARD                   75 (to 130)
                280     END_FOR                         
                282     LOAD_FAST                       3: _var_var_50
                284     NOP                             
                286     NOP                             
                288     NOP                             
                290     JUMP_FORWARD                    69 (to 430)
                292     CALL                            1
                300     POP_TOP                         
                302     RETURN_VALUE                    
                304     PUSH_EXC_INFO                   
                306     LOAD_GLOBAL                     2: DecompilationFailure
                316     CHECK_EXC_MATCH                 
                318     POP_JUMP_IF_FALSE               37 (to 394)
                320     POP_TOP                         
                322     LOAD_GLOBAL                     5: NULL + print
                332     LOAD_CONST                      6: '[!] Fail to decompile function at: '
                334     LOAD_GLOBAL                     7: NULL + hex
                344     LOAD_FAST                       0: func_ea
                346     CALL                            1
                354     FORMAT_VALUE                    0 (FVC_NONE)
                356     BUILD_STRING                    2
                358     CALL                            1
                366     POP_TOP                         
                368     LOAD_FAST                       3: _var_var_50
                370     SWAP                            2
                372     POP_EXCEPT                      
                374     NOP                             
                376     NOP                             
                378     NOP                             
                380     JUMP_FORWARD                    24 (to 430)
                382     CALL                            1
                390     POP_TOP                         
                392     RETURN_VALUE                    
                394     RERAISE                         0
                396     COPY                            3
                398     POP_EXCEPT                      
                400     RERAISE                         1
                402     PUSH_EXC_INFO                   
                404     PUSH_NULL                       
                406     LOAD_CONST                      5: '__pyarmor_exit_54960__'
                408     NOP                             
                410     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x01\x00\x00\x00\x00\x00\x00'
                412     CALL                            1
                420     POP_TOP                         
                422     RERAISE                         0
                424     COPY                            3
                426     POP_EXCEPT                      
                428     RERAISE                         1
                430     PUSH_NULL                       
                432     LOAD_CONST                      5: '__pyarmor_exit_54960__'
                434     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ax\x01\x00\x00\x00\x00\x00\x00'
                436     BUILD_TUPLE                     1
                438     CALL_FUNCTION_EX                0
                440     POP_TOP                         
                442     RETURN_VALUE                    
        '__pyarmor_exit_54915__'
        (
            'list'
        )
        (
            None
            None
        )
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54914__'
        8       LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
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
        38      IMPORT_NAME                     2: os
        40      STORE_NAME                      2: os
        42      LOAD_CONST                      3: 0
        44      LOAD_CONST                      4: None
        46      IMPORT_NAME                     3: json
        48      STORE_NAME                      3: json
        50      LOAD_CONST                      3: 0
        52      LOAD_CONST                      4: None
        54      IMPORT_NAME                     4: textwrap
        56      STORE_NAME                      4: textwrap
        58      LOAD_CONST                      3: 0
        60      LOAD_CONST                      5: ('defaultdict',)
        62      IMPORT_NAME                     5: collections
        64      IMPORT_FROM                     6: defaultdict
        66      STORE_NAME                      6: defaultdict
        68      POP_TOP                         
        70      LOAD_CONST                      3: 0
        72      LOAD_CONST                      6: ('DecompilationFailure', 'decompile')
        74      IMPORT_NAME                     7: ida_hexrays
        76      IMPORT_FROM                     8: DecompilationFailure
        78      STORE_NAME                      8: DecompilationFailure
        80      IMPORT_FROM                     9: decompile
        82      STORE_NAME                      9: decompile
        84      POP_TOP                         
        86      LOAD_CONST                      7: <CODE> drop_task_tag_in_output
        88      MAKE_FUNCTION                   0
        90      STORE_NAME                      10: drop_task_tag_in_output
        92      LOAD_CONST                      8: <CODE> find_json_by_re
        94      MAKE_FUNCTION                   0
        96      STORE_NAME                      11: find_json_by_re
        98      LOAD_CONST                      9: <CODE> find_output_by_re
        100     MAKE_FUNCTION                   0
        102     STORE_NAME                      12: find_output_by_re
        104     LOAD_CONST                      10: <CODE> parse_model_response_json
        106     MAKE_FUNCTION                   0
        108     STORE_NAME                      13: parse_model_response_json
        110     LOAD_CONST                      11: <CODE> parse_model_response_str
        112     MAKE_FUNCTION                   0
        114     STORE_NAME                      14: parse_model_response_str
        116     LOAD_CONST                      12: <CODE> parse_var_pred
        118     MAKE_FUNCTION                   0
        120     STORE_NAME                      15: parse_var_pred
        122     LOAD_CONST                      25: ('list',)
        124     LOAD_CONST                      13: <CODE> vars_check_and_refine
        126     MAKE_FUNCTION                   1
        128     STORE_NAME                      16: vars_check_and_refine
        130     LOAD_CONST                      14: <CODE> funcname_check_and_refine
        132     MAKE_FUNCTION                   0
        134     STORE_NAME                      17: funcname_check_and_refine
        136     LOAD_CONST                      15: <CODE> summary_check_and_refine
        138     MAKE_FUNCTION                   0
        140     STORE_NAME                      18: summary_check_and_refine
        142     LOAD_CONST                      16: 'items'
        144     LOAD_NAME                       19: list
        146     BUILD_TUPLE                     2
        148     LOAD_CONST                      17: <CODE> is_no_original_list
        150     MAKE_FUNCTION                   4
        152     STORE_NAME                      20: is_no_original_list
        154     LOAD_CONST                      18: <CODE> get_func_args
        156     MAKE_FUNCTION                   0
        158     STORE_NAME                      21: get_func_args
        160     LOAD_CONST                      19: <CODE> get_func_args_vars
        162     MAKE_FUNCTION                   0
        164     STORE_NAME                      22: get_func_args_vars
        166     LOAD_CONST                      20: <CODE> func_analysis_check_and_refine
        168     MAKE_FUNCTION                   0
        170     STORE_NAME                      23: func_analysis_check_and_refine
        172     LOAD_CONST                      26: (None, None)
        174     LOAD_CONST                      21: <CODE> response_check_and_refine
        176     MAKE_FUNCTION                   1
        178     STORE_NAME                      24: response_check_and_refine
        180     LOAD_CONST                      22: 'response'
        182     LOAD_NAME                       25: dict
        184     BUILD_TUPLE                     2
        186     LOAD_CONST                      23: <CODE> split_pred_to_var_arg
        188     MAKE_FUNCTION                   4
        190     STORE_NAME                      26: split_pred_to_var_arg
        192     LOAD_CONST                      4: None
        194     NOP                             
        196     NOP                             
        198     NOP                             
        200     JUMP_FORWARD                    19 (to 240)
        208     POP_TOP                         
        210     RETURN_CONST                    4: None
        212     PUSH_EXC_INFO                   
        214     PUSH_NULL                       
        216     LOAD_CONST                      24: '__pyarmor_exit_54915__'
        218     NOP                             
        220     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
        222     CALL                            1
        230     POP_TOP                         
        232     RERAISE                         0
        234     COPY                            3
        236     POP_EXCEPT                      
        238     RERAISE                         1
        240     PUSH_NULL                       
        242     LOAD_CONST                      24: '__pyarmor_exit_54915__'
        244     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\xba\x00\x00\x00\x00\x00\x00\x00'
        246     BUILD_TUPLE                     1
        248     CALL_FUNCTION_EX                0
        250     POP_TOP                         
        252     RETURN_VALUE                    
