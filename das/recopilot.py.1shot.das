recopilot.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..recopilot>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 5
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        'idaapi'
        'logging'
        'ida_idaapi'
        'ida_kernwin'
        'config'
        'settings_manager'
        'handler'
        'FuncAnalysisHandler'
        'DecompilationHandler'
        'ReCopilotSettingsHandler'
        'SpecificVariableAnalysisHandler'
        'AllVariableAnalysisHandler'
        'AllArgumentAnalysisHandler'
        'FuncNameAnalysisHandler'
        'SummaryAnalysisHandler'
        'getLogger'
        'setLevel'
        'ERROR'
        'INFO'
        'plugin_t'
        'ReCopilotPlugin'
        'UI_Hooks'
        'ContextMenuHooks'
        'PLUGIN_ENTRY'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54850__'
        '__pyarmor_enter_54851__'
        b'<COAddr>\x01\x00\x00\x1a\xc2\x01\x00\x00\x00\x00\x00\x00'
        0
        None
        (
            'settings_manager'
        )
        (
            'FuncAnalysisHandler'
            'DecompilationHandler'
            'ReCopilotSettingsHandler'
            'SpecificVariableAnalysisHandler'
            'AllVariableAnalysisHandler'
            'AllArgumentAnalysisHandler'
            'FuncNameAnalysisHandler'
            'SummaryAnalysisHandler'
        )
        'requests'
        'urllib3'
        [Code]
            File Name: <frozen ..recopilot>
            Object Name: ReCopilotPlugin
            Qualified Name: ReCopilotPlugin
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
                'func_analysis_name'
                'decompilation_name'
                'specific_vars_analysis_name'
                'vars_analysis_name'
                'args_analysis_name'
                'funcname_analysis_name'
                'summary_analysis_name'
                'wanted_name'
                'wanted_hotkey'
                'version'
                'comment'
                'help'
                'flags'
                'init'
                'term'
                'run'
            [Locals+Names]
            [Constants]
                'ReCopilotPlugin'
                '__pyarmor_assert_54853__'
                '__pyarmor_enter_54854__'
                b'<COAddr>\x01\x00\x00"\\\x00\x00\x00\x00\x00\x00\x00'
                'function overall analysis'
                'decompilation'
                'select variable analysis'
                'all variable analysis'
                'all argument analysis'
                'function name recovery'
                'summary analysis'
                'ReCopilot'
                ''
                'v0.1-beta'
                'ReCopilot: Reverse Engineering Copilot in Binary Analysis'
                'read README.md for help'
                0
                [Code]
                    File Name: <frozen ..recopilot>
                    Object Name: init
                    Qualified Name: ReCopilotPlugin.init
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 8
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'print'
                        'hooks'
                        'idaapi'
                        'action_desc_t'
                        'func_analysis_name'
                        'FuncAnalysisHandler'
                        'decompilation_name'
                        'DecompilationHandler'
                        'specific_vars_analysis_name'
                        'SpecificVariableAnalysisHandler'
                        'vars_analysis_name'
                        'AllVariableAnalysisHandler'
                        'args_analysis_name'
                        'AllArgumentAnalysisHandler'
                        'funcname_analysis_name'
                        'FuncNameAnalysisHandler'
                        'summary_analysis_name'
                        'SummaryAnalysisHandler'
                        'ReCopilotSettingsHandler'
                        'register_action'
                        'attach_action_to_menu'
                        'ContextMenuHooks'
                        'hook'
                        'ida_idaapi'
                        'PLUGIN_KEEP'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_0'
                        '_var_var_1'
                        '_var_var_2'
                        '_var_var_3'
                        '_var_var_4'
                        '_var_var_5'
                        '_var_var_6'
                        '_var_var_7'
                    [Constants]
                        None
                        '__pyarmor_assert_54856__'
                        '__pyarmor_enter_54857__'
                        b'<COAddr>\x01\x00\x00\x1av\x05\x00\x00\x00\x00\x00\x00'
                        '\n==== ReCopilot Plugin Init ===='
                        'Ctrl+Shift+Alt+F'
                        'Overall analysis for current function'
                        201
                        'Ctrl+Shift+Alt+D'
                        'Decompile function into source code'
                        'Ctrl+Shift+Alt+V'
                        'Analysis specific variables'
                        'Analysis all local variables and arguments'
                        'Analysis all arguments'
                        'Generate meaningful function name'
                        'Generate func summary and inline comments'
                        'recopilot:settings'
                        'Settings'
                        'Ctrl+Shift+Alt+S'
                        'Configure ReCopilot settings'
                        156
                        'Edit/ReCopilot/'
                        0
                        '[👏] ReCopilot init success'
                        '__pyarmor_exit_54858__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54857__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1av\x05\x00\x00\x00\x00\x00\x00'
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
                        38      LOAD_CONST                      4: '\n==== ReCopilot Plugin Init ===='
                        40      CALL                            1
                        48      POP_TOP                         
                        50      LOAD_CONST                      0: None
                        52      LOAD_FAST                       0: self
                        54      STORE_ATTR                      1: hooks
                        64      LOAD_GLOBAL                     5: NULL + idaapi
                        74      LOAD_ATTR                       6: action_desc_t
                        94      LOAD_FAST                       0: self
                        96      LOAD_ATTR                       8: func_analysis_name
                        116     LOAD_FAST                       0: self
                        118     LOAD_ATTR                       8: func_analysis_name
                        138     LOAD_GLOBAL                     11: NULL + FuncAnalysisHandler
                        148     CALL                            0
                        156     LOAD_CONST                      5: 'Ctrl+Shift+Alt+F'
                        158     LOAD_CONST                      6: 'Overall analysis for current function'
                        160     LOAD_CONST                      7: 201
                        162     CALL                            6
                        170     STORE_FAST                      2: _var_var_0
                        172     LOAD_GLOBAL                     5: NULL + idaapi
                        182     LOAD_ATTR                       6: action_desc_t
                        202     LOAD_FAST                       0: self
                        204     LOAD_ATTR                       12: decompilation_name
                        224     LOAD_FAST                       0: self
                        226     LOAD_ATTR                       12: decompilation_name
                        246     LOAD_GLOBAL                     15: NULL + DecompilationHandler
                        256     CALL                            0
                        264     LOAD_CONST                      8: 'Ctrl+Shift+Alt+D'
                        266     LOAD_CONST                      9: 'Decompile function into source code'
                        268     LOAD_CONST                      7: 201
                        270     CALL                            6
                        278     STORE_FAST                      3: _var_var_1
                        280     LOAD_GLOBAL                     5: NULL + idaapi
                        290     LOAD_ATTR                       6: action_desc_t
                        310     LOAD_FAST                       0: self
                        312     LOAD_ATTR                       16: specific_vars_analysis_name
                        332     LOAD_FAST                       0: self
                        334     LOAD_ATTR                       16: specific_vars_analysis_name
                        354     LOAD_GLOBAL                     19: NULL + SpecificVariableAnalysisHandler
                        364     CALL                            0
                        372     LOAD_CONST                      10: 'Ctrl+Shift+Alt+V'
                        374     LOAD_CONST                      11: 'Analysis specific variables'
                        376     LOAD_CONST                      7: 201
                        378     CALL                            6
                        386     STORE_FAST                      4: _var_var_2
                        388     LOAD_GLOBAL                     5: NULL + idaapi
                        398     LOAD_ATTR                       6: action_desc_t
                        418     LOAD_FAST                       0: self
                        420     LOAD_ATTR                       20: vars_analysis_name
                        440     LOAD_FAST                       0: self
                        442     LOAD_ATTR                       20: vars_analysis_name
                        462     LOAD_GLOBAL                     23: NULL + AllVariableAnalysisHandler
                        472     CALL                            0
                        480     LOAD_CONST                      0: None
                        482     LOAD_CONST                      12: 'Analysis all local variables and arguments'
                        484     LOAD_CONST                      7: 201
                        486     CALL                            6
                        494     STORE_FAST                      5: _var_var_3
                        496     LOAD_GLOBAL                     5: NULL + idaapi
                        506     LOAD_ATTR                       6: action_desc_t
                        526     LOAD_FAST                       0: self
                        528     LOAD_ATTR                       24: args_analysis_name
                        548     LOAD_FAST                       0: self
                        550     LOAD_ATTR                       24: args_analysis_name
                        570     LOAD_GLOBAL                     27: NULL + AllArgumentAnalysisHandler
                        580     CALL                            0
                        588     LOAD_CONST                      0: None
                        590     LOAD_CONST                      13: 'Analysis all arguments'
                        592     LOAD_CONST                      7: 201
                        594     CALL                            6
                        602     STORE_FAST                      6: _var_var_4
                        604     LOAD_GLOBAL                     5: NULL + idaapi
                        614     LOAD_ATTR                       6: action_desc_t
                        634     LOAD_FAST                       0: self
                        636     LOAD_ATTR                       28: funcname_analysis_name
                        656     LOAD_FAST                       0: self
                        658     LOAD_ATTR                       28: funcname_analysis_name
                        678     LOAD_GLOBAL                     31: NULL + FuncNameAnalysisHandler
                        688     CALL                            0
                        696     LOAD_CONST                      0: None
                        698     LOAD_CONST                      14: 'Generate meaningful function name'
                        700     LOAD_CONST                      7: 201
                        702     CALL                            6
                        710     STORE_FAST                      7: _var_var_5
                        712     LOAD_GLOBAL                     5: NULL + idaapi
                        722     LOAD_ATTR                       6: action_desc_t
                        742     LOAD_FAST                       0: self
                        744     LOAD_ATTR                       32: summary_analysis_name
                        764     LOAD_FAST                       0: self
                        766     LOAD_ATTR                       32: summary_analysis_name
                        786     LOAD_GLOBAL                     35: NULL + SummaryAnalysisHandler
                        796     CALL                            0
                        804     LOAD_CONST                      0: None
                        806     LOAD_CONST                      15: 'Generate func summary and inline comments'
                        808     LOAD_CONST                      7: 201
                        810     CALL                            6
                        818     STORE_FAST                      8: _var_var_6
                        820     LOAD_GLOBAL                     5: NULL + idaapi
                        830     LOAD_ATTR                       6: action_desc_t
                        850     LOAD_CONST                      16: 'recopilot:settings'
                        852     LOAD_CONST                      17: 'Settings'
                        854     LOAD_GLOBAL                     37: NULL + ReCopilotSettingsHandler
                        864     CALL                            0
                        872     LOAD_CONST                      18: 'Ctrl+Shift+Alt+S'
                        874     LOAD_CONST                      19: 'Configure ReCopilot settings'
                        876     LOAD_CONST                      20: 156
                        878     CALL                            6
                        886     STORE_FAST                      9: _var_var_7
                        888     LOAD_GLOBAL                     5: NULL + idaapi
                        898     LOAD_ATTR                       38: register_action
                        918     LOAD_FAST                       2: _var_var_0
                        920     CALL                            1
                        928     POP_TOP                         
                        930     LOAD_GLOBAL                     5: NULL + idaapi
                        940     LOAD_ATTR                       38: register_action
                        960     LOAD_FAST                       3: _var_var_1
                        962     CALL                            1
                        970     POP_TOP                         
                        972     LOAD_GLOBAL                     5: NULL + idaapi
                        982     LOAD_ATTR                       38: register_action
                        1002    LOAD_FAST                       4: _var_var_2
                        1004    CALL                            1
                        1012    POP_TOP                         
                        1014    LOAD_GLOBAL                     5: NULL + idaapi
                        1024    LOAD_ATTR                       38: register_action
                        1044    LOAD_FAST                       5: _var_var_3
                        1046    CALL                            1
                        1054    POP_TOP                         
                        1056    LOAD_GLOBAL                     5: NULL + idaapi
                        1066    LOAD_ATTR                       38: register_action
                        1086    LOAD_FAST                       6: _var_var_4
                        1088    CALL                            1
                        1096    POP_TOP                         
                        1098    LOAD_GLOBAL                     5: NULL + idaapi
                        1108    LOAD_ATTR                       38: register_action
                        1128    LOAD_FAST                       7: _var_var_5
                        1130    CALL                            1
                        1138    POP_TOP                         
                        1140    LOAD_GLOBAL                     5: NULL + idaapi
                        1150    LOAD_ATTR                       38: register_action
                        1170    LOAD_FAST                       8: _var_var_6
                        1172    CALL                            1
                        1180    POP_TOP                         
                        1182    LOAD_GLOBAL                     5: NULL + idaapi
                        1192    LOAD_ATTR                       38: register_action
                        1212    LOAD_FAST                       9: _var_var_7
                        1214    CALL                            1
                        1222    POP_TOP                         
                        1224    LOAD_GLOBAL                     5: NULL + idaapi
                        1234    LOAD_ATTR                       40: attach_action_to_menu
                        1254    LOAD_CONST                      21: 'Edit/ReCopilot/'
                        1256    LOAD_CONST                      16: 'recopilot:settings'
                        1258    LOAD_CONST                      22: 0
                        1260    CALL                            3
                        1268    POP_TOP                         
                        1270    LOAD_GLOBAL                     43: NULL + ContextMenuHooks
                        1280    CALL                            0
                        1288    LOAD_FAST                       0: self
                        1290    STORE_ATTR                      1: hooks
                        1300    LOAD_FAST                       0: self
                        1302    LOAD_ATTR                       2: hooks
                        1322    LOAD_ATTR                       45: hook
                        1342    CALL                            0
                        1350    POP_TOP                         
                        1352    LOAD_GLOBAL                     1: NULL + print
                        1362    LOAD_CONST                      23: '[👏] ReCopilot init success'
                        1364    CALL                            1
                        1372    POP_TOP                         
                        1374    LOAD_GLOBAL                     46: ida_idaapi
                        1384    LOAD_ATTR                       48: PLUGIN_KEEP
                        1404    NOP                             
                        1406    NOP                             
                        1408    NOP                             
                        1410    JUMP_FORWARD                    20 (to 1452)
                        1412    CALL                            1
                        1420    POP_TOP                         
                        1422    RETURN_VALUE                    
                        1424    PUSH_EXC_INFO                   
                        1426    PUSH_NULL                       
                        1428    LOAD_CONST                      24: '__pyarmor_exit_54858__'
                        1430    NOP                             
                        1432    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1av\x05\x00\x00\x00\x00\x00\x00'
                        1434    CALL                            1
                        1442    POP_TOP                         
                        1444    RERAISE                         0
                        1446    COPY                            3
                        1448    POP_EXCEPT                      
                        1450    RERAISE                         1
                        1452    PUSH_NULL                       
                        1454    LOAD_CONST                      24: '__pyarmor_exit_54858__'
                        1456    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1av\x05\x00\x00\x00\x00\x00\x00'
                        1458    BUILD_TUPLE                     1
                        1460    CALL_FUNCTION_EX                0
                        1462    POP_TOP                         
                        1464    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot>
                    Object Name: term
                    Qualified Name: ReCopilotPlugin.term
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54859__'
                        '__pyarmor_enter_54860__'
                        b'<COAddr>\x03\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54861__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54860__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_CONST                      0: None
                        30      NOP                             
                        32      NOP                             
                        34      NOP                             
                        36      JUMP_FORWARD                    19 (to 76)
                        44      POP_TOP                         
                        46      RETURN_CONST                    0: None
                        48      PUSH_EXC_INFO                   
                        50      PUSH_NULL                       
                        52      LOAD_CONST                      4: '__pyarmor_exit_54861__'
                        54      NOP                             
                        56      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        58      CALL                            1
                        66      POP_TOP                         
                        68      RERAISE                         0
                        70      COPY                            3
                        72      POP_EXCEPT                      
                        74      RERAISE                         1
                        76      PUSH_NULL                       
                        78      LOAD_CONST                      4: '__pyarmor_exit_54861__'
                        80      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        82      BUILD_TUPLE                     1
                        84      CALL_FUNCTION_EX                0
                        86      POP_TOP                         
                        88      RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot>
                    Object Name: run
                    Qualified Name: ReCopilotPlugin.run
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        'self'
                        'arg'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54862__'
                        '__pyarmor_enter_54863__'
                        b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54864__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54863__'
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
                        28      LOAD_CONST                      0: None
                        30      NOP                             
                        32      NOP                             
                        34      NOP                             
                        36      JUMP_FORWARD                    19 (to 76)
                        44      POP_TOP                         
                        46      RETURN_CONST                    0: None
                        48      PUSH_EXC_INFO                   
                        50      PUSH_NULL                       
                        52      LOAD_CONST                      4: '__pyarmor_exit_54864__'
                        54      NOP                             
                        56      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        58      CALL                            1
                        66      POP_TOP                         
                        68      RERAISE                         0
                        70      COPY                            3
                        72      POP_EXCEPT                      
                        74      RERAISE                         1
                        76      PUSH_NULL                       
                        78      LOAD_CONST                      4: '__pyarmor_exit_54864__'
                        80      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        82      BUILD_TUPLE                     1
                        84      CALL_FUNCTION_EX                0
                        86      POP_TOP                         
                        88      RETURN_VALUE                    
                '__pyarmor_exit_54855__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'ReCopilotPlugin'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_54854__'
                16      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"\\\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: 'function overall analysis'
                38      STORE_NAME                      4: func_analysis_name
                40      LOAD_CONST                      5: 'decompilation'
                42      STORE_NAME                      5: decompilation_name
                44      LOAD_CONST                      6: 'select variable analysis'
                46      STORE_NAME                      6: specific_vars_analysis_name
                48      LOAD_CONST                      7: 'all variable analysis'
                50      STORE_NAME                      7: vars_analysis_name
                52      LOAD_CONST                      8: 'all argument analysis'
                54      STORE_NAME                      8: args_analysis_name
                56      LOAD_CONST                      9: 'function name recovery'
                58      STORE_NAME                      9: funcname_analysis_name
                60      LOAD_CONST                      10: 'summary analysis'
                62      STORE_NAME                      10: summary_analysis_name
                64      LOAD_CONST                      11: 'ReCopilot'
                66      STORE_NAME                      11: wanted_name
                68      LOAD_CONST                      12: ''
                70      STORE_NAME                      12: wanted_hotkey
                72      LOAD_CONST                      13: 'v0.1-beta'
                74      STORE_NAME                      13: version
                76      LOAD_CONST                      14: 'ReCopilot: Reverse Engineering Copilot in Binary Analysis'
                78      STORE_NAME                      14: comment
                80      LOAD_CONST                      15: 'read README.md for help'
                82      STORE_NAME                      15: help
                84      LOAD_CONST                      16: 0
                86      STORE_NAME                      16: flags
                88      LOAD_CONST                      17: <CODE> init
                90      MAKE_FUNCTION                   0
                92      STORE_NAME                      17: init
                94      LOAD_CONST                      18: <CODE> term
                96      MAKE_FUNCTION                   0
                98      STORE_NAME                      18: term
                100     LOAD_CONST                      19: <CODE> run
                102     MAKE_FUNCTION                   0
                104     STORE_NAME                      19: run
                106     LOAD_CONST                      21: None
                108     NOP                             
                110     NOP                             
                112     NOP                             
                114     JUMP_FORWARD                    19 (to 154)
                122     POP_TOP                         
                124     RETURN_CONST                    21: None
                126     PUSH_EXC_INFO                   
                128     PUSH_NULL                       
                130     LOAD_CONST                      20: '__pyarmor_exit_54855__'
                132     NOP                             
                134     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"\\\x00\x00\x00\x00\x00\x00\x00'
                136     CALL                            1
                144     POP_TOP                         
                146     RERAISE                         0
                148     COPY                            3
                150     POP_EXCEPT                      
                152     RERAISE                         1
                154     PUSH_NULL                       
                156     LOAD_CONST                      20: '__pyarmor_exit_54855__'
                158     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00"\\\x00\x00\x00\x00\x00\x00\x00'
                160     BUILD_TUPLE                     1
                162     CALL_FUNCTION_EX                0
                164     POP_TOP                         
                166     RETURN_VALUE                    
        'ReCopilotPlugin'
        [Code]
            File Name: <frozen ..recopilot>
            Object Name: ContextMenuHooks
            Qualified Name: ContextMenuHooks
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
                'finish_populating_widget_popup'
            [Locals+Names]
            [Constants]
                'ContextMenuHooks'
                '__pyarmor_assert_54865__'
                '__pyarmor_enter_54866__'
                b'<COAddr>\x03\x00\x00"\x1c\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot>
                    Object Name: finish_populating_widget_popup
                    Qualified Name: ContextMenuHooks.finish_populating_widget_popup
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'ida_kernwin'
                        'get_widget_type'
                        'BWN_PSEUDOCODE'
                        'attach_action_to_popup'
                        'ReCopilotPlugin'
                        'func_analysis_name'
                        'decompilation_name'
                        'specific_vars_analysis_name'
                        'vars_analysis_name'
                        'args_analysis_name'
                        'funcname_analysis_name'
                        'summary_analysis_name'
                    [Locals+Names]
                        'self'
                        'widget'
                        'popup'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54868__'
                        '__pyarmor_enter_54869__'
                        b'<COAddr>\x01\x00\x00\x1a\xa8\x02\x00\x00\x00\x00\x00\x00'
                        'ReCopilot/'
                        'recopilot:settings'
                        '__pyarmor_exit_54870__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54869__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa8\x02\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + ida_kernwin
                        38      LOAD_ATTR                       2: get_widget_type
                        58      LOAD_FAST                       1: widget
                        60      CALL                            1
                        68      LOAD_GLOBAL                     0: ida_kernwin
                        78      LOAD_ATTR                       4: BWN_PSEUDOCODE
                        98      COMPARE_OP                      40 (==)
                        102     POP_JUMP_IF_FALSE               290 (to 686)
                        106     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        116     LOAD_ATTR                       6: attach_action_to_popup
                        136     LOAD_FAST                       1: widget
                        138     LOAD_FAST                       2: popup
                        140     LOAD_GLOBAL                     8: ReCopilotPlugin
                        150     LOAD_ATTR                       10: func_analysis_name
                        170     LOAD_CONST                      4: 'ReCopilot/'
                        172     CALL                            4
                        180     POP_TOP                         
                        182     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        192     LOAD_ATTR                       6: attach_action_to_popup
                        212     LOAD_FAST                       1: widget
                        214     LOAD_FAST                       2: popup
                        216     LOAD_GLOBAL                     8: ReCopilotPlugin
                        226     LOAD_ATTR                       12: decompilation_name
                        246     LOAD_CONST                      4: 'ReCopilot/'
                        248     CALL                            4
                        256     POP_TOP                         
                        258     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        268     LOAD_ATTR                       6: attach_action_to_popup
                        288     LOAD_FAST                       1: widget
                        290     LOAD_FAST                       2: popup
                        292     LOAD_GLOBAL                     8: ReCopilotPlugin
                        302     LOAD_ATTR                       14: specific_vars_analysis_name
                        322     LOAD_CONST                      4: 'ReCopilot/'
                        324     CALL                            4
                        332     POP_TOP                         
                        334     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        344     LOAD_ATTR                       6: attach_action_to_popup
                        364     LOAD_FAST                       1: widget
                        366     LOAD_FAST                       2: popup
                        368     LOAD_GLOBAL                     8: ReCopilotPlugin
                        378     LOAD_ATTR                       16: vars_analysis_name
                        398     LOAD_CONST                      4: 'ReCopilot/'
                        400     CALL                            4
                        408     POP_TOP                         
                        410     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        420     LOAD_ATTR                       6: attach_action_to_popup
                        440     LOAD_FAST                       1: widget
                        442     LOAD_FAST                       2: popup
                        444     LOAD_GLOBAL                     8: ReCopilotPlugin
                        454     LOAD_ATTR                       18: args_analysis_name
                        474     LOAD_CONST                      4: 'ReCopilot/'
                        476     CALL                            4
                        484     POP_TOP                         
                        486     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        496     LOAD_ATTR                       6: attach_action_to_popup
                        516     LOAD_FAST                       1: widget
                        518     LOAD_FAST                       2: popup
                        520     LOAD_GLOBAL                     8: ReCopilotPlugin
                        530     LOAD_ATTR                       20: funcname_analysis_name
                        550     LOAD_CONST                      4: 'ReCopilot/'
                        552     CALL                            4
                        560     POP_TOP                         
                        562     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        572     LOAD_ATTR                       6: attach_action_to_popup
                        592     LOAD_FAST                       1: widget
                        594     LOAD_FAST                       2: popup
                        596     LOAD_GLOBAL                     8: ReCopilotPlugin
                        606     LOAD_ATTR                       22: summary_analysis_name
                        626     LOAD_CONST                      4: 'ReCopilot/'
                        628     CALL                            4
                        636     POP_TOP                         
                        638     LOAD_GLOBAL                     1: NULL + ida_kernwin
                        648     LOAD_ATTR                       6: attach_action_to_popup
                        668     LOAD_FAST                       1: widget
                        670     LOAD_FAST                       2: popup
                        672     LOAD_CONST                      5: 'recopilot:settings'
                        674     LOAD_CONST                      4: 'ReCopilot/'
                        676     CALL                            4
                        684     POP_TOP                         
                        686     LOAD_CONST                      0: None
                        688     NOP                             
                        690     NOP                             
                        692     NOP                             
                        694     JUMP_FORWARD                    19 (to 734)
                        702     POP_TOP                         
                        704     RETURN_CONST                    0: None
                        706     PUSH_EXC_INFO                   
                        708     PUSH_NULL                       
                        710     LOAD_CONST                      6: '__pyarmor_exit_54870__'
                        712     NOP                             
                        714     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa8\x02\x00\x00\x00\x00\x00\x00'
                        716     CALL                            1
                        724     POP_TOP                         
                        726     RERAISE                         0
                        728     COPY                            3
                        730     POP_EXCEPT                      
                        732     RERAISE                         1
                        734     PUSH_NULL                       
                        736     LOAD_CONST                      6: '__pyarmor_exit_54870__'
                        738     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xa8\x02\x00\x00\x00\x00\x00\x00'
                        740     BUILD_TUPLE                     1
                        742     CALL_FUNCTION_EX                0
                        744     POP_TOP                         
                        746     RETURN_VALUE                    
                '__pyarmor_exit_54867__'
                None
            [Disassembly]
                0       NOP                             
                2       LOAD_NAME                       0: __name__
                4       STORE_NAME                      1: __module__
                6       LOAD_CONST                      0: 'ContextMenuHooks'
                8       STORE_NAME                      2: __qualname__
                10      NOP                             
                12      PUSH_NULL                       
                14      LOAD_CONST                      2: '__pyarmor_enter_54866__'
                16      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"\x1c\x00\x00\x00\x00\x00\x00\x00'
                18      BUILD_TUPLE                     1
                20      CALL_FUNCTION_EX                0
                22      POP_TOP                         
                24      RESUME                          0
                26      NOP                             
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      LOAD_CONST                      4: <CODE> finish_populating_widget_popup
                38      MAKE_FUNCTION                   0
                40      STORE_NAME                      4: finish_populating_widget_popup
                42      LOAD_CONST                      6: None
                44      NOP                             
                46      NOP                             
                48      NOP                             
                50      JUMP_FORWARD                    19 (to 90)
                58      POP_TOP                         
                60      RETURN_CONST                    6: None
                62      PUSH_EXC_INFO                   
                64      PUSH_NULL                       
                66      LOAD_CONST                      5: '__pyarmor_exit_54867__'
                68      NOP                             
                70      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"\x1c\x00\x00\x00\x00\x00\x00\x00'
                72      CALL                            1
                80      POP_TOP                         
                82      RERAISE                         0
                84      COPY                            3
                86      POP_EXCEPT                      
                88      RERAISE                         1
                90      PUSH_NULL                       
                92      LOAD_CONST                      5: '__pyarmor_exit_54867__'
                94      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00"\x1c\x00\x00\x00\x00\x00\x00\x00'
                96      BUILD_TUPLE                     1
                98      CALL_FUNCTION_EX                0
                100     POP_TOP                         
                102     RETURN_VALUE                    
        'ContextMenuHooks'
        [Code]
            File Name: <frozen ..recopilot>
            Object Name: PLUGIN_ENTRY
            Qualified Name: PLUGIN_ENTRY
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ReCopilotPlugin'
            [Locals+Names]
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_54871__'
                '__pyarmor_enter_54872__'
                b'<COAddr>\x01\x00\x00\x1a(\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54873__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54872__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + ReCopilotPlugin
                38      CALL                            0
                46      NOP                             
                48      NOP                             
                50      NOP                             
                52      JUMP_FORWARD                    20 (to 94)
                54      CALL                            1
                62      POP_TOP                         
                64      RETURN_VALUE                    
                66      PUSH_EXC_INFO                   
                68      PUSH_NULL                       
                70      LOAD_CONST                      4: '__pyarmor_exit_54873__'
                72      NOP                             
                74      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x00\x00\x00\x00\x00\x00\x00'
                76      CALL                            1
                84      POP_TOP                         
                86      RERAISE                         0
                88      COPY                            3
                90      POP_EXCEPT                      
                92      RERAISE                         1
                94      PUSH_NULL                       
                96      LOAD_CONST                      4: '__pyarmor_exit_54873__'
                98      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x00\x00\x00\x00\x00\x00\x00'
                100     BUILD_TUPLE                     1
                102     CALL_FUNCTION_EX                0
                104     POP_TOP                         
                106     RETURN_VALUE                    
        '__pyarmor_exit_54852__'
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54851__'
        8       LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\xc2\x01\x00\x00\x00\x00\x00\x00'
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
        30      IMPORT_NAME                     1: idaapi
        32      STORE_NAME                      1: idaapi
        34      LOAD_CONST                      3: 0
        36      LOAD_CONST                      4: None
        38      IMPORT_NAME                     2: logging
        40      STORE_NAME                      2: logging
        42      LOAD_CONST                      3: 0
        44      LOAD_CONST                      4: None
        46      IMPORT_NAME                     3: ida_idaapi
        48      STORE_NAME                      3: ida_idaapi
        50      LOAD_CONST                      3: 0
        52      LOAD_CONST                      4: None
        54      IMPORT_NAME                     4: ida_kernwin
        56      STORE_NAME                      4: ida_kernwin
        58      LOAD_CONST                      3: 0
        60      LOAD_CONST                      5: ('settings_manager',)
        62      IMPORT_NAME                     5: config
        64      IMPORT_FROM                     6: settings_manager
        66      STORE_NAME                      6: settings_manager
        68      POP_TOP                         
        70      LOAD_CONST                      3: 0
        72      LOAD_CONST                      6: ('FuncAnalysisHandler', 'DecompilationHandler', 'ReCopilotSettingsHandler', 'SpecificVariableAnalysisHandler', 'AllVariableAnalysisHandler', 'AllArgumentAnalysisHandler', 'FuncNameAnalysisHandler', 'SummaryAnalysisHandler')
        74      IMPORT_NAME                     7: handler
        76      IMPORT_FROM                     8: FuncAnalysisHandler
        78      STORE_NAME                      8: FuncAnalysisHandler
        80      IMPORT_FROM                     9: DecompilationHandler
        82      STORE_NAME                      9: DecompilationHandler
        84      IMPORT_FROM                     10: ReCopilotSettingsHandler
        86      STORE_NAME                      10: ReCopilotSettingsHandler
        88      IMPORT_FROM                     11: SpecificVariableAnalysisHandler
        90      STORE_NAME                      11: SpecificVariableAnalysisHandler
        92      IMPORT_FROM                     12: AllVariableAnalysisHandler
        94      STORE_NAME                      12: AllVariableAnalysisHandler
        96      IMPORT_FROM                     13: AllArgumentAnalysisHandler
        98      STORE_NAME                      13: AllArgumentAnalysisHandler
        100     IMPORT_FROM                     14: FuncNameAnalysisHandler
        102     STORE_NAME                      14: FuncNameAnalysisHandler
        104     IMPORT_FROM                     15: SummaryAnalysisHandler
        106     STORE_NAME                      15: SummaryAnalysisHandler
        108     POP_TOP                         
        110     PUSH_NULL                       
        112     LOAD_NAME                       2: logging
        114     LOAD_ATTR                       32: getLogger
        134     LOAD_CONST                      7: 'requests'
        136     CALL                            1
        144     LOAD_ATTR                       35: setLevel
        164     LOAD_NAME                       2: logging
        166     LOAD_ATTR                       36: ERROR
        186     CALL                            1
        194     POP_TOP                         
        196     PUSH_NULL                       
        198     LOAD_NAME                       2: logging
        200     LOAD_ATTR                       32: getLogger
        220     LOAD_CONST                      8: 'urllib3'
        222     CALL                            1
        230     LOAD_ATTR                       35: setLevel
        250     LOAD_NAME                       2: logging
        252     LOAD_ATTR                       36: ERROR
        272     CALL                            1
        280     POP_TOP                         
        282     PUSH_NULL                       
        284     LOAD_NAME                       2: logging
        286     LOAD_ATTR                       32: getLogger
        306     CALL                            0
        314     LOAD_ATTR                       35: setLevel
        334     LOAD_NAME                       2: logging
        336     LOAD_ATTR                       38: INFO
        356     CALL                            1
        364     POP_TOP                         
        366     PUSH_NULL                       
        368     LOAD_BUILD_CLASS                
        370     LOAD_CONST                      9: <CODE> ReCopilotPlugin
        372     MAKE_FUNCTION                   0
        374     LOAD_CONST                      10: 'ReCopilotPlugin'
        376     LOAD_NAME                       1: idaapi
        378     LOAD_ATTR                       40: plugin_t
        398     CALL                            3
        406     STORE_NAME                      21: ReCopilotPlugin
        408     PUSH_NULL                       
        410     LOAD_BUILD_CLASS                
        412     LOAD_CONST                      11: <CODE> ContextMenuHooks
        414     MAKE_FUNCTION                   0
        416     LOAD_CONST                      12: 'ContextMenuHooks'
        418     LOAD_NAME                       4: ida_kernwin
        420     LOAD_ATTR                       44: UI_Hooks
        440     CALL                            3
        448     STORE_NAME                      23: ContextMenuHooks
        450     LOAD_CONST                      13: <CODE> PLUGIN_ENTRY
        452     MAKE_FUNCTION                   0
        454     STORE_NAME                      24: PLUGIN_ENTRY
        456     LOAD_CONST                      4: None
        458     NOP                             
        460     NOP                             
        462     NOP                             
        464     JUMP_FORWARD                    19 (to 504)
        472     POP_TOP                         
        474     RETURN_CONST                    4: None
        476     PUSH_EXC_INFO                   
        478     PUSH_NULL                       
        480     LOAD_CONST                      14: '__pyarmor_exit_54852__'
        482     NOP                             
        484     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\xc2\x01\x00\x00\x00\x00\x00\x00'
        486     CALL                            1
        494     POP_TOP                         
        496     RERAISE                         0
        498     COPY                            3
        500     POP_EXCEPT                      
        502     RERAISE                         1
        504     PUSH_NULL                       
        506     LOAD_CONST                      14: '__pyarmor_exit_54852__'
        508     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\xc2\x01\x00\x00\x00\x00\x00\x00'
        510     BUILD_TUPLE                     1
        512     CALL_FUNCTION_EX                0
        514     POP_TOP                         
        516     RETURN_VALUE                    
