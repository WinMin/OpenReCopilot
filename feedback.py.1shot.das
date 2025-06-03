feedback.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..feedback>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 6
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        'requests'
        'json'
        'config'
        'settings_manager'
        'uuid'
        'time'
        'os'
        'sys'
        'platform'
        'hashlib'
        'threading'
        'traceback'
        'path'
        'join'
        'dirname'
        '__file__'
        '_fp'
        'open'
        'f'
        'load'
        'data'
        'get'
        'PLUGIN_VERSION'
        'get_machine_id'
        'is_debug_mode'
        '_send_feedback_thread'
        'send_feedback'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54874__'
        '__pyarmor_enter_54875__'
        b'<COAddr>\x01\x00\x00\x1a\x9e\x01\x00\x00\x00\x00\x00\x00'
        0
        None
        (
            'settings_manager'
        )
        'ida-plugin.json'
        'r'
        'plugin'
        'version'
        [Code]
            File Name: <frozen ..feedback>
            Object Name: get_machine_id
            Qualified Name: get_machine_id
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'platform'
                'node'
                'machine'
                'processor'
                'str'
                'uuid'
                'getnode'
                'system'
                'version'
                'join'
                'hashlib'
                'sha256'
                'encode'
                'hexdigest'
            [Locals+Names]
                '__assert_armored__'
                '_var_var_0'
                '_var_var_1'
                '_var_var_2'
            [Constants]
                None
                '__pyarmor_assert_54877__'
                '__pyarmor_enter_54878__'
                b'<COAddr>\x03\x00\x00\x1a\x96\x01\x00\x00\x00\x00\x00\x00'
                ''
                '__pyarmor_exit_54879__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54878__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x96\x01\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + platform
                38      LOAD_ATTR                       2: node
                58      CALL                            0
                66      LOAD_GLOBAL                     1: NULL + platform
                76      LOAD_ATTR                       4: machine
                96      CALL                            0
                104     LOAD_GLOBAL                     1: NULL + platform
                114     LOAD_ATTR                       6: processor
                134     CALL                            0
                142     LOAD_GLOBAL                     9: NULL + str
                152     LOAD_GLOBAL                     11: NULL + uuid
                162     LOAD_ATTR                       12: getnode
                182     CALL                            0
                190     CALL                            1
                198     LOAD_GLOBAL                     1: NULL + platform
                208     LOAD_ATTR                       14: system
                228     CALL                            0
                236     LOAD_GLOBAL                     1: NULL + platform
                246     LOAD_ATTR                       16: version
                266     CALL                            0
                274     BUILD_LIST                      6
                276     STORE_FAST                      1: _var_var_0
                278     LOAD_CONST                      4: ''
                280     LOAD_ATTR                       19: join
                300     LOAD_FAST                       1: _var_var_0
                302     CALL                            1
                310     STORE_FAST                      2: _var_var_1
                312     LOAD_GLOBAL                     21: NULL + hashlib
                322     LOAD_ATTR                       22: sha256
                342     LOAD_FAST                       2: _var_var_1
                344     LOAD_ATTR                       25: encode
                364     CALL                            0
                372     CALL                            1
                380     LOAD_ATTR                       27: hexdigest
                400     CALL                            0
                408     STORE_FAST                      3: _var_var_2
                410     LOAD_FAST                       3: _var_var_2
                412     NOP                             
                414     NOP                             
                416     NOP                             
                418     JUMP_FORWARD                    20 (to 460)
                420     CALL                            1
                428     POP_TOP                         
                430     RETURN_VALUE                    
                432     PUSH_EXC_INFO                   
                434     PUSH_NULL                       
                436     LOAD_CONST                      5: '__pyarmor_exit_54879__'
                438     NOP                             
                440     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x96\x01\x00\x00\x00\x00\x00\x00'
                442     CALL                            1
                450     POP_TOP                         
                452     RERAISE                         0
                454     COPY                            3
                456     POP_EXCEPT                      
                458     RERAISE                         1
                460     PUSH_NULL                       
                462     LOAD_CONST                      5: '__pyarmor_exit_54879__'
                464     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x96\x01\x00\x00\x00\x00\x00\x00'
                466     BUILD_TUPLE                     1
                468     CALL_FUNCTION_EX                0
                470     POP_TOP                         
                472     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..feedback>
            Object Name: is_debug_mode
            Qualified Name: is_debug_mode
            Arg Count: 0
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'settings_manager'
                'settings'
            [Locals+Names]
                '__assert_armored__'
            [Constants]
                None
                '__pyarmor_assert_54880__'
                '__pyarmor_enter_54881__'
                b'<COAddr>\x01\x00\x00\x1a:\x00\x00\x00\x00\x00\x00\x00'
                'debug_mode'
                '__pyarmor_exit_54882__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54881__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a:\x00\x00\x00\x00\x00\x00\x00'
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
                58      LOAD_CONST                      4: 'debug_mode'
                60      BINARY_SUBSCR                   
                64      NOP                             
                66      NOP                             
                68      NOP                             
                70      JUMP_FORWARD                    20 (to 112)
                72      CALL                            1
                80      POP_TOP                         
                82      RETURN_VALUE                    
                84      PUSH_EXC_INFO                   
                86      PUSH_NULL                       
                88      LOAD_CONST                      5: '__pyarmor_exit_54882__'
                90      NOP                             
                92      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a:\x00\x00\x00\x00\x00\x00\x00'
                94      CALL                            1
                102     POP_TOP                         
                104     RERAISE                         0
                106     COPY                            3
                108     POP_EXCEPT                      
                110     RERAISE                         1
                112     PUSH_NULL                       
                114     LOAD_CONST                      5: '__pyarmor_exit_54882__'
                116     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a:\x00\x00\x00\x00\x00\x00\x00'
                118     BUILD_TUPLE                     1
                120     CALL_FUNCTION_EX                0
                122     POP_TOP                         
                124     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..feedback>
            Object Name: _send_feedback_thread
            Qualified Name: _send_feedback_thread
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'is_debug_mode'
                'print'
                'requests'
                'post'
                'status_code'
                'Exception'
                'traceback'
                'print_exc'
                'str'
            [Locals+Names]
                'feedback_data'
                '__assert_armored__'
                '_var_var_3'
                '_var_var_4'
                '_var_var_5'
                '_var_var_6'
            [Constants]
                None
                '__pyarmor_assert_54883__'
                '__pyarmor_enter_54884__'
                b'<COAddr>\x03\x00\x00\x1a\xb0\x01\x00\x00\x00\x00\x00\x00'
                '[DEBUG🐛] invoke send_feedback'
                'https://recopilot-feedback.qianxin.com/api/feedback'
                'application/json'
                (
                    'accept'
                    'Content-Type'
                )
                3
                (
                    'json'
                    'headers'
                    'timeout'
                )
                200
                299
                '[🔗] Feedback send successfully'
                '[!🔗] Failed to send feedback: status_code='
                '[!🔗] Unexpected error in sending feedback: '
                '__pyarmor_exit_54885__'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54884__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xb0\x01\x00\x00\x00\x00\x00\x00'
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
                30      LOAD_GLOBAL                     1: NULL + is_debug_mode
                40      CALL                            0
                48      POP_JUMP_IF_FALSE               11 (to 72)
                50      LOAD_GLOBAL                     3: NULL + print
                60      LOAD_CONST                      4: '[DEBUG🐛] invoke send_feedback'
                62      CALL                            1
                70      POP_TOP                         
                72      LOAD_CONST                      5: 'https://recopilot-feedback.qianxin.com/api/feedback'
                74      STORE_FAST                      2: _var_var_3
                76      LOAD_CONST                      6: 'application/json'
                78      LOAD_CONST                      6: 'application/json'
                80      LOAD_CONST                      7: ('accept', 'Content-Type')
                82      BUILD_CONST_KEY_MAP             2
                84      STORE_FAST                      3: _var_var_4
                86      LOAD_GLOBAL                     5: NULL + requests
                96      LOAD_ATTR                       6: post
                116     LOAD_FAST                       2: _var_var_3
                118     LOAD_FAST                       0: feedback_data
                120     LOAD_FAST                       3: _var_var_4
                122     LOAD_CONST                      8: 3
                124     KW_NAMES                        9: ('json', 'headers', 'timeout')
                126     CALL                            4
                134     STORE_FAST                      4: _var_var_5
                136     LOAD_GLOBAL                     1: NULL + is_debug_mode
                146     CALL                            0
                154     POP_JUMP_IF_FALSE               66 (to 288)
                156     LOAD_FAST                       4: _var_var_5
                158     LOAD_ATTR                       8: status_code
                178     LOAD_CONST                      10: 200
                180     COMPARE_OP                      92 (>=)
                184     POP_JUMP_IF_FALSE               27 (to 240)
                186     LOAD_FAST                       4: _var_var_5
                188     LOAD_ATTR                       8: status_code
                208     LOAD_CONST                      11: 299
                210     COMPARE_OP                      26 (<=)
                214     POP_JUMP_IF_FALSE               12 (to 240)
                216     LOAD_GLOBAL                     3: NULL + print
                226     LOAD_CONST                      12: '[🔗] Feedback send successfully'
                228     CALL                            1
                236     POP_TOP                         
                238     JUMP_FORWARD                    24 (to 288)
                240     LOAD_GLOBAL                     3: NULL + print
                250     LOAD_CONST                      13: '[!🔗] Failed to send feedback: status_code='
                252     LOAD_FAST                       4: _var_var_5
                254     LOAD_ATTR                       8: status_code
                274     FORMAT_VALUE                    0 (FVC_NONE)
                276     BUILD_STRING                    2
                278     CALL                            1
                286     POP_TOP                         
                288     LOAD_CONST                      0: None
                290     NOP                             
                292     NOP                             
                294     NOP                             
                296     JUMP_FORWARD                    94 (to 486)
                304     POP_TOP                         
                306     RETURN_CONST                    0: None
                308     PUSH_EXC_INFO                   
                310     LOAD_GLOBAL                     10: Exception
                320     CHECK_EXC_MATCH                 
                322     POP_JUMP_IF_FALSE               63 (to 450)
                324     STORE_FAST                      5: _var_var_6
                326     LOAD_GLOBAL                     1: NULL + is_debug_mode
                336     CALL                            0
                344     POP_JUMP_IF_FALSE               43 (to 432)
                346     LOAD_GLOBAL                     13: NULL + traceback
                356     LOAD_ATTR                       14: print_exc
                376     CALL                            0
                384     POP_TOP                         
                386     LOAD_GLOBAL                     3: NULL + print
                396     LOAD_CONST                      14: '[!🔗] Unexpected error in sending feedback: '
                398     LOAD_GLOBAL                     17: NULL + str
                408     LOAD_FAST                       5: _var_var_6
                410     CALL                            1
                418     FORMAT_VALUE                    0 (FVC_NONE)
                420     BUILD_STRING                    2
                422     CALL                            1
                430     POP_TOP                         
                432     POP_EXCEPT                      
                434     LOAD_CONST                      0: None
                436     STORE_FAST                      5: _var_var_6
                438     DELETE_FAST                     5: _var_var_6
                440     JUMP_BACKWARD                   77 (to 288)
                442     LOAD_CONST                      0: None
                444     STORE_FAST                      5: _var_var_6
                446     DELETE_FAST                     5: _var_var_6
                448     RERAISE                         1
                450     RERAISE                         0
                452     COPY                            3
                454     POP_EXCEPT                      
                456     RERAISE                         1
                458     PUSH_EXC_INFO                   
                460     PUSH_NULL                       
                462     LOAD_CONST                      15: '__pyarmor_exit_54885__'
                464     NOP                             
                466     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xb0\x01\x00\x00\x00\x00\x00\x00'
                468     CALL                            1
                476     POP_TOP                         
                478     RERAISE                         0
                480     COPY                            3
                482     POP_EXCEPT                      
                484     RERAISE                         1
                486     PUSH_NULL                       
                488     LOAD_CONST                      15: '__pyarmor_exit_54885__'
                490     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xb0\x01\x00\x00\x00\x00\x00\x00'
                492     BUILD_TUPLE                     1
                494     CALL_FUNCTION_EX                0
                496     POP_TOP                         
                498     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..feedback>
            Object Name: send_feedback
            Qualified Name: send_feedback
            Arg Count: 4
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 10
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'settings_manager'
                'settings'
                'get_machine_id'
                'time'
                'json'
                'dumps'
                'PLUGIN_VERSION'
                'threading'
                'Thread'
                '_send_feedback_thread'
                'daemon'
                'start'
                'Exception'
                'is_debug_mode'
                'traceback'
                'print_exc'
                'print'
                'str'
            [Locals+Names]
                'prompt'
                'model_response'
                'accept_response'
                'task_tag'
                '__assert_armored__'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
                '_var_var_10'
                '_var_var_6'
            [Constants]
                '\n    Send feedback data to the server asynchronously.\n    \n    Args:\n        model_response: The original response from the model\n        accept_response: The response that was accepted/modified by the user\n        task_tag: The type of analysis task performed\n    \n    Returns:\n        bool: True if feedback was sent successfully, False otherwise\n    '
                '__pyarmor_assert_54886__'
                '__pyarmor_enter_54887__'
                b'<COAddr>\x01\x00\x00\x1a\xee\x01\x00\x00\x00\x00\x00\x00'
                'base_url'
                'model_name'
                (
                    'machine_id'
                    'timestamp'
                    'base_url'
                    'model_name'
                    'task_tag'
                    'prompt'
                    'model_response'
                    'accept_response'
                    'plugin_version'
                )
                (
                    'target'
                    'args'
                )
                True
                '__pyarmor_exit_54888__'
                '[!🔗] Error preparing feedback data: '
                None
                False
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54887__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xee\x01\x00\x00\x00\x00\x00\x00'
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
                30      LOAD_GLOBAL                     0: settings_manager
                40      LOAD_ATTR                       2: settings
                60      LOAD_CONST                      4: 'base_url'
                62      BINARY_SUBSCR                   
                66      STORE_FAST                      5: _var_var_7
                68      LOAD_GLOBAL                     0: settings_manager
                78      LOAD_ATTR                       2: settings
                98      LOAD_CONST                      5: 'model_name'
                100     BINARY_SUBSCR                   
                104     STORE_FAST                      6: _var_var_8
                106     LOAD_GLOBAL                     5: NULL + get_machine_id
                116     CALL                            0
                124     LOAD_GLOBAL                     7: NULL + time
                134     LOAD_ATTR                       6: time
                154     CALL                            0
                162     LOAD_FAST                       5: _var_var_7
                164     LOAD_FAST                       6: _var_var_8
                166     LOAD_FAST                       3: task_tag
                168     LOAD_FAST                       0: prompt
                170     LOAD_FAST                       1: model_response
                172     LOAD_GLOBAL                     9: NULL + json
                182     LOAD_ATTR                       10: dumps
                202     LOAD_FAST                       2: accept_response
                204     CALL                            1
                212     LOAD_GLOBAL                     12: PLUGIN_VERSION
                222     LOAD_CONST                      6: ('machine_id', 'timestamp', 'base_url', 'model_name', 'task_tag', 'prompt', 'model_response', 'accept_response', 'plugin_version')
                224     BUILD_CONST_KEY_MAP             9
                226     STORE_FAST                      7: _var_var_9
                228     LOAD_GLOBAL                     15: NULL + threading
                238     LOAD_ATTR                       16: Thread
                258     LOAD_GLOBAL                     18: _send_feedback_thread
                268     LOAD_FAST                       7: _var_var_9
                270     BUILD_TUPLE                     1
                272     KW_NAMES                        7: ('target', 'args')
                274     CALL                            2
                282     STORE_FAST                      8: _var_var_10
                284     LOAD_CONST                      8: True
                286     LOAD_FAST                       8: _var_var_10
                288     STORE_ATTR                      10: daemon
                298     LOAD_FAST                       8: _var_var_10
                300     LOAD_ATTR                       23: start
                320     CALL                            0
                328     POP_TOP                         
                330     NOP                             
                332     LOAD_CONST                      8: True
                334     NOP                             
                336     NOP                             
                338     NOP                             
                340     JUMP_FORWARD                    103 (to 548)
                348     POP_TOP                         
                350     RETURN_CONST                    8: True
                352     PUSH_EXC_INFO                   
                354     LOAD_GLOBAL                     24: Exception
                364     CHECK_EXC_MATCH                 
                366     POP_JUMP_IF_FALSE               72 (to 512)
                368     STORE_FAST                      9: _var_var_6
                370     LOAD_GLOBAL                     27: NULL + is_debug_mode
                380     CALL                            0
                388     POP_JUMP_IF_FALSE               43 (to 476)
                390     LOAD_GLOBAL                     29: NULL + traceback
                400     LOAD_ATTR                       30: print_exc
                420     CALL                            0
                428     POP_TOP                         
                430     LOAD_GLOBAL                     33: NULL + print
                440     LOAD_CONST                      10: '[!🔗] Error preparing feedback data: '
                442     LOAD_GLOBAL                     35: NULL + str
                452     LOAD_FAST                       9: _var_var_6
                454     CALL                            1
                462     FORMAT_VALUE                    0 (FVC_NONE)
                464     BUILD_STRING                    2
                466     CALL                            1
                474     POP_TOP                         
                476     POP_EXCEPT                      
                478     LOAD_CONST                      11: None
                480     STORE_FAST                      9: _var_var_6
                482     DELETE_FAST                     9: _var_var_6
                484     LOAD_CONST                      12: False
                486     NOP                             
                488     NOP                             
                490     NOP                             
                492     JUMP_FORWARD                    27 (to 548)
                500     POP_TOP                         
                502     RETURN_CONST                    12: False
                504     LOAD_CONST                      11: None
                506     STORE_FAST                      9: _var_var_6
                508     DELETE_FAST                     9: _var_var_6
                510     RERAISE                         1
                512     RERAISE                         0
                514     COPY                            3
                516     POP_EXCEPT                      
                518     RERAISE                         1
                520     PUSH_EXC_INFO                   
                522     PUSH_NULL                       
                524     LOAD_CONST                      9: '__pyarmor_exit_54888__'
                526     NOP                             
                528     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xee\x01\x00\x00\x00\x00\x00\x00'
                530     CALL                            1
                538     POP_TOP                         
                540     RERAISE                         0
                542     COPY                            3
                544     POP_EXCEPT                      
                546     RERAISE                         1
                548     PUSH_NULL                       
                550     LOAD_CONST                      9: '__pyarmor_exit_54888__'
                552     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xee\x01\x00\x00\x00\x00\x00\x00'
                554     BUILD_TUPLE                     1
                556     CALL_FUNCTION_EX                0
                558     POP_TOP                         
                560     RETURN_VALUE                    
        '__pyarmor_exit_54876__'
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54875__'
        8       LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\x9e\x01\x00\x00\x00\x00\x00\x00'
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
        30      IMPORT_NAME                     1: requests
        32      STORE_NAME                      1: requests
        34      LOAD_CONST                      3: 0
        36      LOAD_CONST                      4: None
        38      IMPORT_NAME                     2: json
        40      STORE_NAME                      2: json
        42      LOAD_CONST                      3: 0
        44      LOAD_CONST                      5: ('settings_manager',)
        46      IMPORT_NAME                     3: config
        48      IMPORT_FROM                     4: settings_manager
        50      STORE_NAME                      4: settings_manager
        52      POP_TOP                         
        54      LOAD_CONST                      3: 0
        56      LOAD_CONST                      4: None
        58      IMPORT_NAME                     5: uuid
        60      STORE_NAME                      5: uuid
        62      LOAD_CONST                      3: 0
        64      LOAD_CONST                      4: None
        66      IMPORT_NAME                     6: time
        68      STORE_NAME                      6: time
        70      LOAD_CONST                      3: 0
        72      LOAD_CONST                      4: None
        74      IMPORT_NAME                     7: os
        76      STORE_NAME                      7: os
        78      LOAD_CONST                      3: 0
        80      LOAD_CONST                      4: None
        82      IMPORT_NAME                     8: sys
        84      STORE_NAME                      8: sys
        86      LOAD_CONST                      3: 0
        88      LOAD_CONST                      4: None
        90      IMPORT_NAME                     9: platform
        92      STORE_NAME                      9: platform
        94      LOAD_CONST                      3: 0
        96      LOAD_CONST                      4: None
        98      IMPORT_NAME                     10: hashlib
        100     STORE_NAME                      10: hashlib
        102     LOAD_CONST                      3: 0
        104     LOAD_CONST                      4: None
        106     IMPORT_NAME                     11: threading
        108     STORE_NAME                      11: threading
        110     LOAD_CONST                      3: 0
        112     LOAD_CONST                      4: None
        114     IMPORT_NAME                     12: traceback
        116     STORE_NAME                      12: traceback
        118     LOAD_CONST                      3: 0
        120     LOAD_CONST                      4: None
        122     IMPORT_NAME                     2: json
        124     STORE_NAME                      2: json
        126     LOAD_NAME                       7: os
        128     LOAD_ATTR                       26: path
        148     LOAD_ATTR                       29: join
        168     LOAD_NAME                       7: os
        170     LOAD_ATTR                       26: path
        190     LOAD_ATTR                       31: dirname
        210     LOAD_NAME                       16: __file__
        212     CALL                            1
        220     LOAD_CONST                      6: 'ida-plugin.json'
        222     CALL                            2
        230     STORE_NAME                      17: _fp
        232     PUSH_NULL                       
        234     LOAD_NAME                       18: open
        236     LOAD_NAME                       17: _fp
        238     LOAD_CONST                      7: 'r'
        240     CALL                            2
        248     BEFORE_WITH                     
        250     STORE_NAME                      19: f
        252     PUSH_NULL                       
        254     LOAD_NAME                       2: json
        256     LOAD_ATTR                       40: load
        276     LOAD_NAME                       19: f
        278     CALL                            1
        286     STORE_NAME                      21: data
        288     LOAD_CONST                      4: None
        290     LOAD_CONST                      4: None
        292     LOAD_CONST                      4: None
        294     CALL                            2
        302     POP_TOP                         
        304     LOAD_NAME                       21: data
        306     LOAD_ATTR                       45: get
        326     LOAD_CONST                      8: 'plugin'
        328     BUILD_MAP                       0
        330     CALL                            2
        338     LOAD_ATTR                       45: get
        358     LOAD_CONST                      9: 'version'
        360     LOAD_CONST                      4: None
        362     CALL                            2
        370     STORE_NAME                      23: PLUGIN_VERSION
        372     LOAD_CONST                      10: <CODE> get_machine_id
        374     MAKE_FUNCTION                   0
        376     STORE_NAME                      24: get_machine_id
        378     LOAD_CONST                      11: <CODE> is_debug_mode
        380     MAKE_FUNCTION                   0
        382     STORE_NAME                      25: is_debug_mode
        384     LOAD_CONST                      12: <CODE> _send_feedback_thread
        386     MAKE_FUNCTION                   0
        388     STORE_NAME                      26: _send_feedback_thread
        390     LOAD_CONST                      13: <CODE> send_feedback
        392     MAKE_FUNCTION                   0
        394     STORE_NAME                      27: send_feedback
        396     LOAD_CONST                      4: None
        398     NOP                             
        400     NOP                             
        402     NOP                             
        404     JUMP_FORWARD                    31 (to 468)
        412     POP_TOP                         
        414     RETURN_CONST                    4: None
        416     PUSH_EXC_INFO                   
        418     WITH_EXCEPT_START               
        420     POP_JUMP_IF_TRUE                1 (to 424)
        422     RERAISE                         2
        424     POP_TOP                         
        426     POP_EXCEPT                      
        428     POP_TOP                         
        430     POP_TOP                         
        432     JUMP_BACKWARD                   65 (to 304)
        434     COPY                            3
        436     POP_EXCEPT                      
        438     RERAISE                         1
        440     PUSH_EXC_INFO                   
        442     PUSH_NULL                       
        444     LOAD_CONST                      14: '__pyarmor_exit_54876__'
        446     NOP                             
        448     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\x9e\x01\x00\x00\x00\x00\x00\x00'
        450     CALL                            1
        458     POP_TOP                         
        460     RERAISE                         0
        462     COPY                            3
        464     POP_EXCEPT                      
        466     RERAISE                         1
        468     PUSH_NULL                       
        470     LOAD_CONST                      14: '__pyarmor_exit_54876__'
        472     LOAD_CONST                      2: b'<COAddr>\x01\x00\x00\x1a\x9e\x01\x00\x00\x00\x00\x00\x00'
        474     BUILD_TUPLE                     1
        476     CALL_FUNCTION_EX                0
        478     POP_TOP                         
        480     RETURN_VALUE                    
