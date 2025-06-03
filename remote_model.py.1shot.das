remote_model.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..remote_model>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 5
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        'openai'
        'OpenAI'
        'time'
        'config'
        'settings_manager'
        'PROMPT_TEMPLATE'
        'task_guides'
        'TASK_GUIDES'
        'TASK_OUTPUT_FORMATS'
        'get_mock_response'
        'OpenAIModel'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54895__'
        '__pyarmor_enter_54896__'
        b'<COAddr>\x03\x00\x00\x1a`\x00\x00\x00\x00\x00\x00\x00'
        0
        (
            'OpenAI'
        )
        None
        (
            'settings_manager'
            'PROMPT_TEMPLATE'
        )
        (
            'TASK_GUIDES'
            'TASK_OUTPUT_FORMATS'
            'get_mock_response'
        )
        [Code]
            File Name: <frozen ..remote_model>
            Object Name: OpenAIModel
            Qualified Name: OpenAIModel
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
                'cancel'
                'call_model'
                'call_model_mock'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'OpenAIModel'
                '__pyarmor_assert_54898__'
                '__pyarmor_enter_54899__'
                b'<COAddr>\x01\x00\x00$<\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..remote_model>
                    Object Name: __init__
                    Qualified Name: OpenAIModel.__init__
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        '__init__'
                        '_current_completion'
                        '_cancelled'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54901__'
                        '__pyarmor_enter_54902__'
                        b'<COAddr>\x03\x00\x00\x1cN\x00\x00\x00\x00\x00\x00\x00'
                        False
                        '__pyarmor_exit_54903__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54902__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cN\x00\x00\x00\x00\x00\x00\x00'
                        12      BUILD_TUPLE                     1
                        14      CALL_FUNCTION_EX                0
                        16      POP_TOP                         
                        18      RESUME                          0
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      LOAD_GLOBAL                     0: super
                        40      LOAD_DEREF                      2: __class__
                        42      LOAD_FAST                       0: self
                        44      LOAD_SUPER_ATTR                 5: __init__
                        48      CALL                            0
                        56      POP_TOP                         
                        58      LOAD_CONST                      0: None
                        60      LOAD_FAST                       0: self
                        62      STORE_ATTR                      2: _current_completion
                        72      LOAD_CONST                      4: False
                        74      LOAD_FAST                       0: self
                        76      STORE_ATTR                      3: _cancelled
                        86      LOAD_CONST                      0: None
                        88      NOP                             
                        90      NOP                             
                        92      NOP                             
                        94      JUMP_FORWARD                    19 (to 134)
                        102     POP_TOP                         
                        104     RETURN_CONST                    0: None
                        106     PUSH_EXC_INFO                   
                        108     PUSH_NULL                       
                        110     LOAD_CONST                      5: '__pyarmor_exit_54903__'
                        112     NOP                             
                        114     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cN\x00\x00\x00\x00\x00\x00\x00'
                        116     CALL                            1
                        124     POP_TOP                         
                        126     RERAISE                         0
                        128     COPY                            3
                        130     POP_EXCEPT                      
                        132     RERAISE                         1
                        134     PUSH_NULL                       
                        136     LOAD_CONST                      5: '__pyarmor_exit_54903__'
                        138     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cN\x00\x00\x00\x00\x00\x00\x00'
                        140     BUILD_TUPLE                     1
                        142     CALL_FUNCTION_EX                0
                        144     POP_TOP                         
                        146     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..remote_model>
                    Object Name: cancel
                    Qualified Name: OpenAIModel.cancel
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        '_cancelled'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        'Cancel the current model call'
                        '__pyarmor_assert_54904__'
                        '__pyarmor_enter_54905__'
                        b'<COAddr>\x03\x00\x00\x1a$\x00\x00\x00\x00\x00\x00\x00'
                        True
                        '__pyarmor_exit_54906__'
                        None
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54905__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a$\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_CONST                      4: True
                        30      LOAD_FAST                       0: self
                        32      STORE_ATTR                      0: _cancelled
                        42      LOAD_CONST                      6: None
                        44      NOP                             
                        46      NOP                             
                        48      NOP                             
                        50      JUMP_FORWARD                    19 (to 90)
                        58      POP_TOP                         
                        60      RETURN_CONST                    6: None
                        62      PUSH_EXC_INFO                   
                        64      PUSH_NULL                       
                        66      LOAD_CONST                      5: '__pyarmor_exit_54906__'
                        68      NOP                             
                        70      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a$\x00\x00\x00\x00\x00\x00\x00'
                        72      CALL                            1
                        80      POP_TOP                         
                        82      RERAISE                         0
                        84      COPY                            3
                        86      POP_EXCEPT                      
                        88      RERAISE                         1
                        90      PUSH_NULL                       
                        92      LOAD_CONST                      5: '__pyarmor_exit_54906__'
                        94      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a$\x00\x00\x00\x00\x00\x00\x00'
                        96      BUILD_TUPLE                     1
                        98      CALL_FUNCTION_EX                0
                        100     POP_TOP                         
                        102     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..remote_model>
                    Object Name: call_model
                    Qualified Name: OpenAIModel.call_model
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 9
                    Flags: 0x20000083 (CO_OPTIMIZED | CO_NEWLOCALS | CO_COROUTINE | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        '_cancelled'
                        'settings_manager'
                        'settings'
                        'PROMPT_TEMPLATE'
                        'endswith'
                        'replace'
                        'TASK_OUTPUT_FORMATS'
                        'TASK_GUIDES'
                        'print'
                        'join'
                        'split'
                        'len'
                        'OpenAI'
                        'chat'
                        'completions'
                        'create'
                        '_current_completion'
                        'close'
                        'hasattr'
                        'choices'
                        'delta'
                        'reasoning_content'
                        'content'
                        'append'
                        'TimeoutError'
                        'Exception'
                        'traceback'
                        'print_exc'
                        'str'
                    [Locals+Names]
                        'self'
                        'prompt'
                        'task_tag'
                        'timeout'
                        '__assert_armored__'
                        '_var_var_0'
                        '_var_var_1'
                        '_var_var_2'
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
                        '__pyarmor_assert_54907__'
                        '__pyarmor_enter_54908__'
                        b'<COAddr>\x03\x00\x00\x1eB\x06\x00\x00\x00\x00\x00\x00'
                        False
                        'prompt_template'
                        '_wo_guide'
                        '{format}'
                        '{guide}'
                        '{input}'
                        '\n[DEBUG🐛] '
                        '\n'
                        'model_name'
                        '[🔗] OpenAIModel.call_model: model_name='
                        ', timeout='
                        's'
                        '[🔗] OpenAIModel.call_model: send '
                        ' chars prompt'
                        'base_url'
                        'api_key'
                        (
                            'base_url'
                            'api_key'
                        )
                        0.6
                        True
                        'max_output_tokens'
                        'user'
                        (
                            'role'
                            'content'
                        )
                        (
                            'model'
                            'temperature'
                            'stream'
                            'max_tokens'
                            'messages'
                            'timeout'
                        )
                        '\n[!💥] Analysis cancelled by user'
                        '<Cancelled>Analysis cancelled by user'
                        '__pyarmor_exit_54909__'
                        0
                        'reasoning_content'
                        ''
                        (
                            'end'
                        )
                        '<RequestException>Request timed out'
                        '[!💥] Error:'
                        '<RequestException>'
                    [Disassembly]
                        0       RETURN_GENERATOR                
                        2       POP_TOP                         
                        4       NOP                             
                        6       NOP                             
                        8       PUSH_NULL                       
                        10      LOAD_CONST                      2: '__pyarmor_enter_54908__'
                        12      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1eB\x06\x00\x00\x00\x00\x00\x00'
                        14      BUILD_TUPLE                     1
                        16      CALL_FUNCTION_EX                0
                        18      POP_TOP                         
                        20      RESUME                          0
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      NOP                             
                        32      NOP                             
                        34      LOAD_CONST                      4: False
                        36      LOAD_FAST                       0: self
                        38      STORE_ATTR                      0: _cancelled
                        48      LOAD_GLOBAL                     2: settings_manager
                        58      LOAD_ATTR                       4: settings
                        78      LOAD_CONST                      5: 'prompt_template'
                        80      BINARY_SUBSCR                   
                        84      STORE_FAST                      5: _var_var_0
                        86      LOAD_GLOBAL                     6: PROMPT_TEMPLATE
                        96      LOAD_FAST                       5: _var_var_0
                        98      BINARY_SUBSCR                   
                        102     STORE_FAST                      6: _var_var_1
                        104     LOAD_FAST                       5: _var_var_0
                        106     LOAD_ATTR                       9: endswith
                        126     LOAD_CONST                      6: '_wo_guide'
                        128     CALL                            1
                        136     POP_JUMP_IF_FALSE               26 (to 190)
                        138     LOAD_FAST                       6: _var_var_1
                        140     LOAD_ATTR                       11: replace
                        160     LOAD_CONST                      7: '{format}'
                        162     LOAD_GLOBAL                     12: TASK_OUTPUT_FORMATS
                        172     LOAD_FAST                       2: task_tag
                        174     BINARY_SUBSCR                   
                        178     CALL                            2
                        186     STORE_FAST                      6: _var_var_1
                        188     JUMP_FORWARD                    25 (to 240)
                        190     LOAD_FAST                       6: _var_var_1
                        192     LOAD_ATTR                       11: replace
                        212     LOAD_CONST                      8: '{guide}'
                        214     LOAD_GLOBAL                     14: TASK_GUIDES
                        224     LOAD_FAST                       2: task_tag
                        226     BINARY_SUBSCR                   
                        230     CALL                            2
                        238     STORE_FAST                      6: _var_var_1
                        240     LOAD_FAST                       6: _var_var_1
                        242     LOAD_ATTR                       11: replace
                        262     LOAD_CONST                      9: '{input}'
                        264     LOAD_FAST                       1: prompt
                        266     CALL                            2
                        274     STORE_FAST                      1: prompt
                        276     LOAD_GLOBAL                     17: NULL + print
                        286     LOAD_CONST                      10: '\n[DEBUG🐛] '
                        288     LOAD_ATTR                       19: join
                        308     LOAD_FAST                       1: prompt
                        310     LOAD_ATTR                       21: split
                        330     LOAD_CONST                      11: '\n'
                        332     CALL                            1
                        340     CALL                            1
                        348     CALL                            1
                        356     POP_TOP                         
                        358     LOAD_GLOBAL                     2: settings_manager
                        368     LOAD_ATTR                       4: settings
                        388     LOAD_CONST                      12: 'model_name'
                        390     BINARY_SUBSCR                   
                        394     STORE_FAST                      7: _var_var_2
                        396     LOAD_GLOBAL                     17: NULL + print
                        406     LOAD_CONST                      13: '[🔗] OpenAIModel.call_model: model_name='
                        408     LOAD_FAST                       7: _var_var_2
                        410     FORMAT_VALUE                    0 (FVC_NONE)
                        412     LOAD_CONST                      14: ', timeout='
                        414     LOAD_FAST                       3: timeout
                        416     FORMAT_VALUE                    0 (FVC_NONE)
                        418     LOAD_CONST                      15: 's'
                        420     BUILD_STRING                    5
                        422     CALL                            1
                        430     POP_TOP                         
                        432     LOAD_GLOBAL                     17: NULL + print
                        442     LOAD_CONST                      16: '[🔗] OpenAIModel.call_model: send '
                        444     LOAD_GLOBAL                     23: NULL + len
                        454     LOAD_FAST                       1: prompt
                        456     CALL                            1
                        464     FORMAT_VALUE                    0 (FVC_NONE)
                        466     LOAD_CONST                      17: ' chars prompt'
                        468     BUILD_STRING                    3
                        470     CALL                            1
                        478     POP_TOP                         
                        480     LOAD_GLOBAL                     25: NULL + OpenAI
                        490     LOAD_GLOBAL                     2: settings_manager
                        500     LOAD_ATTR                       4: settings
                        520     LOAD_CONST                      18: 'base_url'
                        522     BINARY_SUBSCR                   
                        526     LOAD_GLOBAL                     2: settings_manager
                        536     LOAD_ATTR                       4: settings
                        556     LOAD_CONST                      19: 'api_key'
                        558     BINARY_SUBSCR                   
                        562     KW_NAMES                        20: ('base_url', 'api_key')
                        564     CALL                            2
                        572     STORE_FAST                      8: _var_var_3
                        574     LOAD_FAST                       8: _var_var_3
                        576     LOAD_ATTR                       26: chat
                        596     LOAD_ATTR                       28: completions
                        616     LOAD_ATTR                       31: create
                        636     LOAD_FAST                       7: _var_var_2
                        638     LOAD_CONST                      21: 0.6
                        640     LOAD_CONST                      22: True
                        642     LOAD_GLOBAL                     2: settings_manager
                        652     LOAD_ATTR                       4: settings
                        672     LOAD_CONST                      23: 'max_output_tokens'
                        674     BINARY_SUBSCR                   
                        678     LOAD_CONST                      24: 'user'
                        680     LOAD_FAST                       1: prompt
                        682     LOAD_CONST                      25: ('role', 'content')
                        684     BUILD_CONST_KEY_MAP             2
                        686     BUILD_LIST                      1
                        688     LOAD_FAST                       3: timeout
                        690     KW_NAMES                        26: ('model', 'temperature', 'stream', 'max_tokens', 'messages', 'timeout')
                        692     CALL                            6
                        700     LOAD_FAST                       0: self
                        702     STORE_ATTR                      16: _current_completion
                        712     BUILD_LIST                      0
                        714     STORE_FAST                      9: _var_var_4
                        716     LOAD_FAST                       0: self
                        718     LOAD_ATTR                       32: _current_completion
                        738     GET_ITER                        
                        740     FOR_ITER                        250 (to 1242)
                        744     STORE_FAST                      10: _var_var_5
                        746     LOAD_FAST                       0: self
                        748     LOAD_ATTR                       0: _cancelled
                        768     POP_JUMP_IF_FALSE               59 (to 888)
                        770     LOAD_GLOBAL                     17: NULL + print
                        780     LOAD_CONST                      27: '\n[!💥] Analysis cancelled by user'
                        782     CALL                            1
                        790     POP_TOP                         
                        792     LOAD_FAST                       0: self
                        794     LOAD_ATTR                       32: _current_completion
                        814     LOAD_ATTR                       35: close
                        834     CALL                            0
                        842     POP_TOP                         
                        844     LOAD_CONST                      28: '<Cancelled>Analysis cancelled by user'
                        846     LOAD_FAST                       1: prompt
                        848     BUILD_TUPLE                     2
                        850     SWAP                            2
                        852     POP_TOP                         
                        854     LOAD_CONST                      0: None
                        856     LOAD_FAST                       0: self
                        858     STORE_ATTR                      16: _current_completion
                        868     NOP                             
                        870     NOP                             
                        872     JUMP_FORWARD                    394 (to 1664)
                        876     CALL                            1
                        884     POP_TOP                         
                        886     RETURN_VALUE                    
                        888     LOAD_GLOBAL                     37: NULL + hasattr
                        898     LOAD_FAST                       10: _var_var_5
                        900     LOAD_ATTR                       38: choices
                        920     LOAD_CONST                      30: 0
                        922     BINARY_SUBSCR                   
                        926     LOAD_ATTR                       40: delta
                        946     LOAD_CONST                      31: 'reasoning_content'
                        948     CALL                            2
                        956     POP_JUMP_IF_FALSE               71 (to 1100)
                        958     LOAD_FAST                       10: _var_var_5
                        960     LOAD_ATTR                       38: choices
                        980     LOAD_CONST                      30: 0
                        982     BINARY_SUBSCR                   
                        986     LOAD_ATTR                       40: delta
                        1006    LOAD_ATTR                       42: reasoning_content
                        1026    POP_JUMP_IF_FALSE               36 (to 1100)
                        1028    LOAD_FAST                       10: _var_var_5
                        1030    LOAD_ATTR                       38: choices
                        1050    LOAD_CONST                      30: 0
                        1052    BINARY_SUBSCR                   
                        1056    LOAD_ATTR                       40: delta
                        1076    LOAD_ATTR                       42: reasoning_content
                        1096    STORE_FAST                      11: _var_var_6
                        1098    JUMP_FORWARD                    35 (to 1170)
                        1100    LOAD_FAST                       10: _var_var_5
                        1102    LOAD_ATTR                       38: choices
                        1122    LOAD_CONST                      30: 0
                        1124    BINARY_SUBSCR                   
                        1128    LOAD_ATTR                       40: delta
                        1148    LOAD_ATTR                       44: content
                        1168    STORE_FAST                      11: _var_var_6
                        1170    LOAD_FAST                       11: _var_var_6
                        1172    LOAD_CONST                      0: None
                        1174    COMPARE_OP                      40 (==)
                        1178    POP_JUMP_IF_FALSE               1 (to 1182)
                        1180    JUMP_BACKWARD                   221 (to 740)
                        1182    LOAD_GLOBAL                     17: NULL + print
                        1192    LOAD_FAST                       11: _var_var_6
                        1194    LOAD_CONST                      32: ''
                        1196    KW_NAMES                        33: ('end',)
                        1198    CALL                            2
                        1206    POP_TOP                         
                        1208    LOAD_FAST                       9: _var_var_4
                        1210    LOAD_ATTR                       47: append
                        1230    LOAD_FAST                       11: _var_var_6
                        1232    CALL                            1
                        1240    POP_TOP                         
                        1242    JUMP_BACKWARD                   252 (to 740)
                        1244    END_FOR                         
                        1246    LOAD_GLOBAL                     17: NULL + print
                        1256    LOAD_CONST                      32: ''
                        1258    CALL                            1
                        1266    POP_TOP                         
                        1268    LOAD_CONST                      32: ''
                        1270    LOAD_ATTR                       19: join
                        1290    LOAD_FAST                       9: _var_var_4
                        1292    CALL                            1
                        1300    STORE_FAST                      12: _var_var_7
                        1302    NOP                             
                        1304    LOAD_CONST                      0: None
                        1306    LOAD_FAST                       0: self
                        1308    STORE_ATTR                      16: _current_completion
                        1318    LOAD_FAST                       12: _var_var_7
                        1320    LOAD_FAST                       1: prompt
                        1322    BUILD_TUPLE                     2
                        1324    NOP                             
                        1326    NOP                             
                        1328    NOP                             
                        1330    JUMP_FORWARD                    166 (to 1664)
                        1332    CALL                            1
                        1340    POP_TOP                         
                        1342    RETURN_VALUE                    
                        1344    PUSH_EXC_INFO                   
                        1346    LOAD_GLOBAL                     48: TimeoutError
                        1356    CHECK_EXC_MATCH                 
                        1358    POP_JUMP_IF_FALSE               37 (to 1434)
                        1360    POP_TOP                         
                        1362    LOAD_CONST                      34: '<RequestException>Request timed out'
                        1364    STORE_FAST                      13: _var_var_8
                        1366    LOAD_GLOBAL                     17: NULL + print
                        1376    LOAD_CONST                      35: '[!💥] Error:'
                        1378    LOAD_FAST                       13: _var_var_8
                        1380    CALL                            2
                        1388    POP_TOP                         
                        1390    LOAD_FAST                       13: _var_var_8
                        1392    LOAD_FAST                       1: prompt
                        1394    BUILD_TUPLE                     2
                        1396    SWAP                            2
                        1398    POP_EXCEPT                      
                        1400    LOAD_CONST                      0: None
                        1402    LOAD_FAST                       0: self
                        1404    STORE_ATTR                      16: _current_completion
                        1414    NOP                             
                        1416    NOP                             
                        1418    NOP                             
                        1420    JUMP_FORWARD                    121 (to 1664)
                        1422    CALL                            1
                        1430    POP_TOP                         
                        1432    RETURN_VALUE                    
                        1434    LOAD_GLOBAL                     50: Exception
                        1444    CHECK_EXC_MATCH                 
                        1446    POP_JUMP_IF_FALSE               76 (to 1600)
                        1448    STORE_FAST                      14: _var_var_9
                        1450    LOAD_CONST                      30: 0
                        1452    LOAD_CONST                      0: None
                        1454    IMPORT_NAME                     26: traceback
                        1456    STORE_FAST                      15: _var_var_10
                        1458    LOAD_FAST                       15: _var_var_10
                        1460    LOAD_ATTR                       55: print_exc
                        1480    CALL                            0
                        1488    POP_TOP                         
                        1490    LOAD_CONST                      36: '<RequestException>'
                        1492    LOAD_GLOBAL                     57: NULL + str
                        1502    LOAD_FAST                       14: _var_var_9
                        1504    CALL                            1
                        1512    BINARY_OP                       0 (+)
                        1516    STORE_FAST                      13: _var_var_8
                        1518    LOAD_GLOBAL                     17: NULL + print
                        1528    LOAD_CONST                      35: '[!💥] Error:'
                        1530    LOAD_FAST                       13: _var_var_8
                        1532    CALL                            2
                        1540    POP_TOP                         
                        1542    LOAD_FAST                       13: _var_var_8
                        1544    LOAD_FAST                       1: prompt
                        1546    BUILD_TUPLE                     2
                        1548    SWAP                            2
                        1550    POP_EXCEPT                      
                        1552    LOAD_CONST                      0: None
                        1554    STORE_FAST                      14: _var_var_9
                        1556    DELETE_FAST                     14: _var_var_9
                        1558    LOAD_CONST                      0: None
                        1560    LOAD_FAST                       0: self
                        1562    STORE_ATTR                      16: _current_completion
                        1572    NOP                             
                        1574    NOP                             
                        1576    NOP                             
                        1578    JUMP_FORWARD                    42 (to 1664)
                        1580    CALL                            1
                        1588    POP_TOP                         
                        1590    RETURN_VALUE                    
                        1592    LOAD_CONST                      0: None
                        1594    STORE_FAST                      14: _var_var_9
                        1596    DELETE_FAST                     14: _var_var_9
                        1598    RERAISE                         1
                        1600    RERAISE                         0
                        1602    COPY                            3
                        1604    POP_EXCEPT                      
                        1606    RERAISE                         1
                        1608    PUSH_EXC_INFO                   
                        1610    LOAD_CONST                      0: None
                        1612    LOAD_FAST                       0: self
                        1614    STORE_ATTR                      16: _current_completion
                        1624    RERAISE                         0
                        1626    COPY                            3
                        1628    POP_EXCEPT                      
                        1630    RERAISE                         1
                        1632    PUSH_EXC_INFO                   
                        1634    PUSH_NULL                       
                        1636    LOAD_CONST                      29: '__pyarmor_exit_54909__'
                        1638    NOP                             
                        1640    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1eB\x06\x00\x00\x00\x00\x00\x00'
                        1642    CALL                            1
                        1650    POP_TOP                         
                        1652    RERAISE                         0
                        1654    COPY                            3
                        1656    POP_EXCEPT                      
                        1658    RERAISE                         1
                        1660    CALL_INTRINSIC_1                3 (INTRINSIC_STOPITERATION_ERROR)
                        1662    RERAISE                         1
                        1664    PUSH_NULL                       
                        1666    LOAD_CONST                      29: '__pyarmor_exit_54909__'
                        1668    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1eB\x06\x00\x00\x00\x00\x00\x00'
                        1670    BUILD_TUPLE                     1
                        1672    CALL_FUNCTION_EX                0
                        1674    POP_TOP                         
                        1676    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..remote_model>
                    Object Name: call_model_mock
                    Qualified Name: OpenAIModel.call_model_mock
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 11
                    Flags: 0x20000083 (CO_OPTIMIZED | CO_NEWLOCALS | CO_COROUTINE | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        '_cancelled'
                        'settings_manager'
                        'settings'
                        'PROMPT_TEMPLATE'
                        'endswith'
                        'replace'
                        'TASK_OUTPUT_FORMATS'
                        'TASK_GUIDES'
                        'print'
                        'join'
                        'split'
                        'len'
                        'get_mock_response'
                        'time'
                        'sleep'
                    [Locals+Names]
                        'self'
                        'prompt'
                        'task_tag'
                        'timeout'
                        '__assert_armored__'
                        '_var_var_0'
                        '_var_var_1'
                        '_var_var_11'
                        '_var_var_12'
                        '_var_var_2'
                        '_var_var_13'
                        '_var_var_14'
                    [Constants]
                        None
                        '__pyarmor_assert_54910__'
                        '__pyarmor_enter_54911__'
                        b'<COAddr>\x03\x00\x00\x1e0\x03\x00\x00\x00\x00\x00\x00'
                        False
                        'prompt_template'
                        '_wo_guide'
                        '{format}'
                        '{guide}'
                        '{input}'
                        '\n[DEBUG🐛] '
                        '\n'
                        'base_url'
                        'api_key'
                        'model_name'
                        '[DEBUG🐛] OpenAIModel.call_model_mock: base_url='
                        ', api_key='
                        ', model_name='
                        ', timeout='
                        's'
                        '[DEBUG🐛] OpenAIModel.call_model_mock: recv '
                        ' chars prompt'
                        1.5
                        '[DEBUG🐛] '
                        0.1
                        '\n[!💥] Analysis cancelled by user'
                        '<Cancelled>Analysis cancelled by user'
                        '__pyarmor_exit_54912__'
                    [Disassembly]
                        0       RETURN_GENERATOR                
                        2       POP_TOP                         
                        4       NOP                             
                        6       NOP                             
                        8       PUSH_NULL                       
                        10      LOAD_CONST                      2: '__pyarmor_enter_54911__'
                        12      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1e0\x03\x00\x00\x00\x00\x00\x00'
                        14      BUILD_TUPLE                     1
                        16      CALL_FUNCTION_EX                0
                        18      POP_TOP                         
                        20      RESUME                          0
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      NOP                             
                        32      LOAD_CONST                      4: False
                        34      LOAD_FAST                       0: self
                        36      STORE_ATTR                      0: _cancelled
                        46      LOAD_GLOBAL                     2: settings_manager
                        56      LOAD_ATTR                       4: settings
                        76      LOAD_CONST                      5: 'prompt_template'
                        78      BINARY_SUBSCR                   
                        82      STORE_FAST                      5: _var_var_0
                        84      LOAD_GLOBAL                     6: PROMPT_TEMPLATE
                        94      LOAD_FAST                       5: _var_var_0
                        96      BINARY_SUBSCR                   
                        100     STORE_FAST                      6: _var_var_1
                        102     LOAD_FAST                       5: _var_var_0
                        104     LOAD_ATTR                       9: endswith
                        124     LOAD_CONST                      6: '_wo_guide'
                        126     CALL                            1
                        134     POP_JUMP_IF_FALSE               26 (to 188)
                        136     LOAD_FAST                       6: _var_var_1
                        138     LOAD_ATTR                       11: replace
                        158     LOAD_CONST                      7: '{format}'
                        160     LOAD_GLOBAL                     12: TASK_OUTPUT_FORMATS
                        170     LOAD_FAST                       2: task_tag
                        172     BINARY_SUBSCR                   
                        176     CALL                            2
                        184     STORE_FAST                      6: _var_var_1
                        186     JUMP_FORWARD                    25 (to 238)
                        188     LOAD_FAST                       6: _var_var_1
                        190     LOAD_ATTR                       11: replace
                        210     LOAD_CONST                      8: '{guide}'
                        212     LOAD_GLOBAL                     14: TASK_GUIDES
                        222     LOAD_FAST                       2: task_tag
                        224     BINARY_SUBSCR                   
                        228     CALL                            2
                        236     STORE_FAST                      6: _var_var_1
                        238     LOAD_FAST                       6: _var_var_1
                        240     LOAD_ATTR                       11: replace
                        260     LOAD_CONST                      9: '{input}'
                        262     LOAD_FAST                       1: prompt
                        264     CALL                            2
                        272     STORE_FAST                      1: prompt
                        274     LOAD_GLOBAL                     17: NULL + print
                        284     LOAD_CONST                      10: '\n[DEBUG🐛] '
                        286     LOAD_ATTR                       19: join
                        306     LOAD_FAST                       1: prompt
                        308     LOAD_ATTR                       21: split
                        328     LOAD_CONST                      11: '\n'
                        330     CALL                            1
                        338     CALL                            1
                        346     CALL                            1
                        354     POP_TOP                         
                        356     LOAD_GLOBAL                     2: settings_manager
                        366     LOAD_ATTR                       4: settings
                        386     LOAD_CONST                      12: 'base_url'
                        388     BINARY_SUBSCR                   
                        392     STORE_FAST                      7: _var_var_11
                        394     LOAD_GLOBAL                     2: settings_manager
                        404     LOAD_ATTR                       4: settings
                        424     LOAD_CONST                      13: 'api_key'
                        426     BINARY_SUBSCR                   
                        430     STORE_FAST                      8: _var_var_12
                        432     LOAD_GLOBAL                     2: settings_manager
                        442     LOAD_ATTR                       4: settings
                        462     LOAD_CONST                      14: 'model_name'
                        464     BINARY_SUBSCR                   
                        468     STORE_FAST                      9: _var_var_2
                        470     LOAD_GLOBAL                     17: NULL + print
                        480     LOAD_CONST                      15: '[DEBUG🐛] OpenAIModel.call_model_mock: base_url='
                        482     LOAD_FAST                       7: _var_var_11
                        484     FORMAT_VALUE                    0 (FVC_NONE)
                        486     LOAD_CONST                      16: ', api_key='
                        488     LOAD_FAST                       8: _var_var_12
                        490     FORMAT_VALUE                    0 (FVC_NONE)
                        492     LOAD_CONST                      17: ', model_name='
                        494     LOAD_FAST                       9: _var_var_2
                        496     FORMAT_VALUE                    0 (FVC_NONE)
                        498     LOAD_CONST                      18: ', timeout='
                        500     LOAD_FAST                       3: timeout
                        502     FORMAT_VALUE                    0 (FVC_NONE)
                        504     LOAD_CONST                      19: 's'
                        506     BUILD_STRING                    9
                        508     CALL                            1
                        516     POP_TOP                         
                        518     LOAD_GLOBAL                     17: NULL + print
                        528     LOAD_CONST                      20: '[DEBUG🐛] OpenAIModel.call_model_mock: recv '
                        530     LOAD_GLOBAL                     23: NULL + len
                        540     LOAD_FAST                       1: prompt
                        542     CALL                            1
                        550     FORMAT_VALUE                    0 (FVC_NONE)
                        552     LOAD_CONST                      21: ' chars prompt'
                        554     BUILD_STRING                    3
                        556     CALL                            1
                        564     POP_TOP                         
                        566     LOAD_GLOBAL                     25: NULL + get_mock_response
                        576     LOAD_FAST                       2: task_tag
                        578     CALL                            1
                        586     STORE_FAST                      10: _var_var_13
                        588     LOAD_GLOBAL                     27: NULL + time
                        598     LOAD_ATTR                       28: sleep
                        618     LOAD_CONST                      22: 1.5
                        620     CALL                            1
                        628     POP_TOP                         
                        630     LOAD_FAST                       10: _var_var_13
                        632     LOAD_ATTR                       21: split
                        652     LOAD_CONST                      11: '\n'
                        654     CALL                            1
                        662     GET_ITER                        
                        664     FOR_ITER                        75 (to 816)
                        668     STORE_FAST                      11: _var_var_14
                        670     LOAD_GLOBAL                     17: NULL + print
                        680     LOAD_CONST                      23: '[DEBUG🐛] '
                        682     LOAD_FAST                       11: _var_var_14
                        684     BINARY_OP                       0 (+)
                        688     CALL                            1
                        696     POP_TOP                         
                        698     LOAD_GLOBAL                     27: NULL + time
                        708     LOAD_ATTR                       28: sleep
                        728     LOAD_CONST                      24: 0.1
                        730     CALL                            1
                        738     POP_TOP                         
                        740     LOAD_FAST                       0: self
                        742     LOAD_ATTR                       0: _cancelled
                        762     POP_JUMP_IF_TRUE                1 (to 766)
                        764     JUMP_BACKWARD                   51 (to 664)
                        766     LOAD_GLOBAL                     17: NULL + print
                        776     LOAD_CONST                      25: '\n[!💥] Analysis cancelled by user'
                        778     CALL                            1
                        786     POP_TOP                         
                        788     LOAD_CONST                      26: '<Cancelled>Analysis cancelled by user'
                        790     LOAD_FAST                       1: prompt
                        792     BUILD_TUPLE                     2
                        794     SWAP                            2
                        796     POP_TOP                         
                        798     NOP                             
                        800     NOP                             
                        802     NOP                             
                        804     JUMP_FORWARD                    36 (to 878)
                        806     CALL                            1
                        814     POP_TOP                         
                        816     RETURN_VALUE                    
                        818     END_FOR                         
                        820     LOAD_FAST                       10: _var_var_13
                        822     LOAD_FAST                       1: prompt
                        824     BUILD_TUPLE                     2
                        826     NOP                             
                        828     NOP                             
                        830     NOP                             
                        832     JUMP_FORWARD                    22 (to 878)
                        834     CALL                            1
                        842     POP_TOP                         
                        844     RETURN_VALUE                    
                        846     PUSH_EXC_INFO                   
                        848     PUSH_NULL                       
                        850     LOAD_CONST                      27: '__pyarmor_exit_54912__'
                        852     NOP                             
                        854     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1e0\x03\x00\x00\x00\x00\x00\x00'
                        856     CALL                            1
                        864     POP_TOP                         
                        866     RERAISE                         0
                        868     COPY                            3
                        870     POP_EXCEPT                      
                        872     RERAISE                         1
                        874     CALL_INTRINSIC_1                3 (INTRINSIC_STOPITERATION_ERROR)
                        876     RERAISE                         1
                        878     PUSH_NULL                       
                        880     LOAD_CONST                      27: '__pyarmor_exit_54912__'
                        882     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1e0\x03\x00\x00\x00\x00\x00\x00'
                        884     BUILD_TUPLE                     1
                        886     CALL_FUNCTION_EX                0
                        888     POP_TOP                         
                        890     RETURN_VALUE                    
                '__pyarmor_exit_54900__'
                (
                    600
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'OpenAIModel'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54899__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$<\x00\x00\x00\x00\x00\x00\x00'
                20      BUILD_TUPLE                     1
                22      CALL_FUNCTION_EX                0
                24      POP_TOP                         
                26      RESUME                          0
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      LOAD_CLOSURE                    0: __class__
                40      BUILD_TUPLE                     1
                42      LOAD_CONST                      4: <CODE> __init__
                44      MAKE_FUNCTION                   8
                46      STORE_NAME                      4: __init__
                48      LOAD_CONST                      5: <CODE> cancel
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      5: cancel
                54      LOAD_CONST                      9: (600,)
                56      LOAD_CONST                      6: <CODE> call_model
                58      MAKE_FUNCTION                   1
                60      STORE_NAME                      6: call_model
                62      LOAD_CONST                      9: (600,)
                64      LOAD_CONST                      7: <CODE> call_model_mock
                66      MAKE_FUNCTION                   1
                68      STORE_NAME                      7: call_model_mock
                70      LOAD_CLOSURE                    0: __class__
                72      COPY                            1
                74      STORE_NAME                      8: __classcell__
                76      NOP                             
                78      NOP                             
                80      NOP                             
                82      JUMP_FORWARD                    20 (to 124)
                86      POP_TOP                         
                88      LOAD_CLOSURE                    0: __class__
                90      COPY                            1
                92      STORE_NAME                      8: __classcell__
                94      RETURN_VALUE                    
                96      PUSH_EXC_INFO                   
                98      PUSH_NULL                       
                100     LOAD_CONST                      8: '__pyarmor_exit_54900__'
                102     NOP                             
                104     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$<\x00\x00\x00\x00\x00\x00\x00'
                106     CALL                            1
                114     POP_TOP                         
                116     RERAISE                         0
                118     COPY                            3
                120     POP_EXCEPT                      
                122     RERAISE                         1
                124     PUSH_NULL                       
                126     LOAD_CONST                      8: '__pyarmor_exit_54900__'
                128     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$<\x00\x00\x00\x00\x00\x00\x00'
                130     BUILD_TUPLE                     1
                132     CALL_FUNCTION_EX                0
                134     POP_TOP                         
                136     RETURN_VALUE                    
        'OpenAIModel'
        '__pyarmor_exit_54897__'
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54896__'
        8       LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a`\x00\x00\x00\x00\x00\x00\x00'
        10      BUILD_TUPLE                     1
        12      CALL_FUNCTION_EX                0
        14      POP_TOP                         
        16      RESUME                          0
        18      NOP                             
        20      NOP                             
        22      NOP                             
        24      NOP                             
        26      LOAD_CONST                      3: 0
        28      LOAD_CONST                      4: ('OpenAI',)
        30      IMPORT_NAME                     1: openai
        32      IMPORT_FROM                     2: OpenAI
        34      STORE_NAME                      2: OpenAI
        36      POP_TOP                         
        38      LOAD_CONST                      3: 0
        40      LOAD_CONST                      5: None
        42      IMPORT_NAME                     3: time
        44      STORE_NAME                      3: time
        46      LOAD_CONST                      3: 0
        48      LOAD_CONST                      6: ('settings_manager', 'PROMPT_TEMPLATE')
        50      IMPORT_NAME                     4: config
        52      IMPORT_FROM                     5: settings_manager
        54      STORE_NAME                      5: settings_manager
        56      IMPORT_FROM                     6: PROMPT_TEMPLATE
        58      STORE_NAME                      6: PROMPT_TEMPLATE
        60      POP_TOP                         
        62      LOAD_CONST                      3: 0
        64      LOAD_CONST                      7: ('TASK_GUIDES', 'TASK_OUTPUT_FORMATS', 'get_mock_response')
        66      IMPORT_NAME                     7: task_guides
        68      IMPORT_FROM                     8: TASK_GUIDES
        70      STORE_NAME                      8: TASK_GUIDES
        72      IMPORT_FROM                     9: TASK_OUTPUT_FORMATS
        74      STORE_NAME                      9: TASK_OUTPUT_FORMATS
        76      IMPORT_FROM                     10: get_mock_response
        78      STORE_NAME                      10: get_mock_response
        80      POP_TOP                         
        82      PUSH_NULL                       
        84      LOAD_BUILD_CLASS                
        86      LOAD_CONST                      8: <CODE> OpenAIModel
        88      MAKE_FUNCTION                   0
        90      LOAD_CONST                      9: 'OpenAIModel'
        92      CALL                            2
        100     STORE_NAME                      11: OpenAIModel
        102     LOAD_CONST                      5: None
        104     NOP                             
        106     NOP                             
        108     NOP                             
        110     JUMP_FORWARD                    19 (to 150)
        118     POP_TOP                         
        120     RETURN_CONST                    5: None
        122     PUSH_EXC_INFO                   
        124     PUSH_NULL                       
        126     LOAD_CONST                      10: '__pyarmor_exit_54897__'
        128     NOP                             
        130     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a`\x00\x00\x00\x00\x00\x00\x00'
        132     CALL                            1
        140     POP_TOP                         
        142     RERAISE                         0
        144     COPY                            3
        146     POP_EXCEPT                      
        148     RERAISE                         1
        150     PUSH_NULL                       
        152     LOAD_CONST                      10: '__pyarmor_exit_54897__'
        154     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a`\x00\x00\x00\x00\x00\x00\x00'
        156     BUILD_TUPLE                     1
        158     CALL_FUNCTION_EX                0
        160     POP_TOP                         
        162     RETURN_VALUE                    
