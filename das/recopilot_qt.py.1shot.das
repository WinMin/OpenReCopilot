recopilot_qt.py.1shot.seq (Python 3.12)
[Code]
    File Name: <frozen ..recopilot_qt>
    Object Name: <module>
    Qualified Name: <module>
    Arg Count: 0
    Pos Only Arg Count: 0
    KW Only Arg Count: 0
    Stack Size: 5
    Flags: 0x20000000 (CO_PYARMOR_OBFUSCATED)
    [Names]
        '__assert_armored__'
        'idc'
        'idaapi'
        'ida_funcs'
        'ida_hexrays'
        'ida_name'
        'ida_bytes'
        'ida_kernwin'
        'pygments'
        'highlight'
        'pygments.lexers'
        'CppLexer'
        'pygments.token'
        'Token'
        'pygments.formatters'
        'HtmlFormatter'
        'PyQt5'
        'QtWidgets'
        'QtCore'
        'QtGui'
        'PyQt5.QtWidgets'
        'QDialog'
        'QVBoxLayout'
        'QHBoxLayout'
        'QPushButton'
        'QLabel'
        'QWidget'
        'QLineEdit'
        'QGroupBox'
        'QGridLayout'
        'QMessageBox'
        'QSpinBox'
        'QCheckBox'
        'QComboBox'
        'ext_info'
        'apply_prediction'
        'config'
        'settings_manager'
        'PROMPT_TEMPLATE'
        'feedback'
        'send_feedback'
        'remote_model'
        'OpenAIModel'
        'PluginForm'
        'DecompilationViewPluginForm'
        'create_decompilation_view'
        'EditablePredictionWidget'
        'NameTypeWidget'
        'StructFieldWidget'
        'EnumFieldWidget'
        'ComplexTypeWidget'
        'UserConfirmForm'
        'create_user_confirm_view'
        'UserConfirmFormForFuncName'
        'create_user_confirm_view_for_funcname'
        'VariableSelectionWidget'
        'VariableSelectionForm'
        'create_variable_selection_view'
        'ReCopilotSettingsDialog'
        'OutputWindowButton'
        'add_cancel_button'
        'remove_cancel_button'
    [Locals+Names]
    [Constants]
        '__pyarmor_assert_54478__'
        '__pyarmor_enter_54479__'
        b'<COAddr>\x03\x00\x00\x1a|\x02\x00\x00\x00\x00\x00\x00'
        0
        None
        (
            'highlight'
        )
        (
            'CppLexer'
        )
        (
            'Token'
        )
        (
            'HtmlFormatter'
        )
        (
            'QtWidgets'
            'QtCore'
            'QtGui'
        )
        (
            'QDialog'
            'QVBoxLayout'
            'QHBoxLayout'
            'QPushButton'
            'QLabel'
            'QWidget'
            'QLineEdit'
            'QGroupBox'
            'QGridLayout'
            'QMessageBox'
            'QSpinBox'
            'QCheckBox'
            'QComboBox'
        )
        (
            'apply_prediction'
        )
        (
            'settings_manager'
            'PROMPT_TEMPLATE'
        )
        (
            'send_feedback'
        )
        (
            'OpenAIModel'
        )
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: DecompilationViewPluginForm
            Qualified Name: DecompilationViewPluginForm
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
                'OnCreate'
                'set_content'
                'OnClose'
                'Show'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'DecompilationViewPluginForm'
                '__pyarmor_assert_54481__'
                '__pyarmor_enter_54482__'
                b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: DecompilationViewPluginForm.__init__
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'DecompilationViewPluginForm'
                        '__init__'
                        'title'
                        'initial_content'
                        'parent_widget'
                        'code_browser'
                        'ida_kernwin'
                        'find_widget'
                        'print'
                        'close_widget'
                    [Locals+Names]
                        'self'
                        'title'
                        'content'
                        '__assert_armored__'
                        '_var_var_0'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54484__'
                        '__pyarmor_enter_54485__'
                        b'<COAddr>\x01\x00\x00\x1c\xea\x00\x00\x00\x00\x00\x00\x00'
                        "[*] Found existing widget with title '"
                        "'. Closing it before recreating."
                        0
                        '__pyarmor_exit_54486__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54485__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xea\x00\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: DecompilationViewPluginForm
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_FAST                       1: title
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: title
                        80      LOAD_FAST                       2: content
                        82      LOAD_FAST                       0: self
                        84      STORE_ATTR                      4: initial_content
                        94      LOAD_CONST                      0: None
                        96      LOAD_FAST                       0: self
                        98      STORE_ATTR                      5: parent_widget
                        108     LOAD_CONST                      0: None
                        110     LOAD_FAST                       0: self
                        112     STORE_ATTR                      6: code_browser
                        122     LOAD_GLOBAL                     15: NULL + ida_kernwin
                        132     LOAD_ATTR                       16: find_widget
                        152     LOAD_FAST                       1: title
                        154     CALL                            1
                        162     STORE_FAST                      4: _var_var_0
                        164     LOAD_FAST                       4: _var_var_0
                        166     POP_JUMP_IF_FALSE               37 (to 242)
                        168     LOAD_GLOBAL                     19: NULL + print
                        178     LOAD_CONST                      4: "[*] Found existing widget with title '"
                        180     LOAD_FAST                       1: title
                        182     FORMAT_VALUE                    0 (FVC_NONE)
                        184     LOAD_CONST                      5: "'. Closing it before recreating."
                        186     BUILD_STRING                    3
                        188     CALL                            1
                        196     POP_TOP                         
                        198     LOAD_GLOBAL                     15: NULL + ida_kernwin
                        208     LOAD_ATTR                       20: close_widget
                        228     LOAD_FAST                       4: _var_var_0
                        230     LOAD_CONST                      6: 0
                        232     CALL                            2
                        240     POP_TOP                         
                        242     LOAD_CONST                      0: None
                        244     NOP                             
                        246     NOP                             
                        248     NOP                             
                        250     JUMP_FORWARD                    19 (to 290)
                        258     POP_TOP                         
                        260     RETURN_CONST                    0: None
                        262     PUSH_EXC_INFO                   
                        264     PUSH_NULL                       
                        266     LOAD_CONST                      7: '__pyarmor_exit_54486__'
                        268     NOP                             
                        270     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xea\x00\x00\x00\x00\x00\x00\x00'
                        272     CALL                            1
                        280     POP_TOP                         
                        282     RERAISE                         0
                        284     COPY                            3
                        286     POP_EXCEPT                      
                        288     RERAISE                         1
                        290     PUSH_NULL                       
                        292     LOAD_CONST                      7: '__pyarmor_exit_54486__'
                        294     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xea\x00\x00\x00\x00\x00\x00\x00'
                        296     BUILD_TUPLE                     1
                        298     CALL_FUNCTION_EX                0
                        300     POP_TOP                         
                        302     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: OnCreate
                    Qualified Name: DecompilationViewPluginForm.OnCreate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'FormToPyQtWidget'
                        'parent_widget'
                        'QtWidgets'
                        'QVBoxLayout'
                        'QTextBrowser'
                        'code_browser'
                        'setOpenExternalLinks'
                        'setFontFamily'
                        'setStyleSheet'
                        'addWidget'
                        'setLayout'
                        'initial_content'
                        'set_content'
                    [Locals+Names]
                        'self'
                        'form'
                        '__assert_armored__'
                        '_var_var_1'
                    [Constants]
                        None
                        '__pyarmor_assert_54487__'
                        '__pyarmor_enter_54488__'
                        b'<COAddr>\x01\x00\x00\x1a\xf8\x01\x00\x00\x00\x00\x00\x00'
                        False
                        'Consolas'
                        'font-size: 12px;'
                        '__pyarmor_exit_54489__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54488__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf8\x01\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: FormToPyQtWidget
                        50      LOAD_FAST                       1: form
                        52      CALL                            1
                        60      LOAD_FAST                       0: self
                        62      STORE_ATTR                      1: parent_widget
                        72      LOAD_GLOBAL                     5: NULL + QtWidgets
                        82      LOAD_ATTR                       6: QVBoxLayout
                        102     CALL                            0
                        110     STORE_FAST                      3: _var_var_1
                        112     LOAD_GLOBAL                     5: NULL + QtWidgets
                        122     LOAD_ATTR                       8: QTextBrowser
                        142     CALL                            0
                        150     LOAD_FAST                       0: self
                        152     STORE_ATTR                      5: code_browser
                        162     LOAD_FAST                       0: self
                        164     LOAD_ATTR                       10: code_browser
                        184     LOAD_ATTR                       13: setOpenExternalLinks
                        204     LOAD_CONST                      4: False
                        206     CALL                            1
                        214     POP_TOP                         
                        216     LOAD_FAST                       0: self
                        218     LOAD_ATTR                       10: code_browser
                        238     LOAD_ATTR                       15: setFontFamily
                        258     LOAD_CONST                      5: 'Consolas'
                        260     CALL                            1
                        268     POP_TOP                         
                        270     LOAD_FAST                       0: self
                        272     LOAD_ATTR                       10: code_browser
                        292     LOAD_ATTR                       17: setStyleSheet
                        312     LOAD_CONST                      6: 'font-size: 12px;'
                        314     CALL                            1
                        322     POP_TOP                         
                        324     LOAD_FAST                       3: _var_var_1
                        326     LOAD_ATTR                       19: addWidget
                        346     LOAD_FAST                       0: self
                        348     LOAD_ATTR                       10: code_browser
                        368     CALL                            1
                        376     POP_TOP                         
                        378     LOAD_FAST                       0: self
                        380     LOAD_ATTR                       2: parent_widget
                        400     LOAD_ATTR                       21: setLayout
                        420     LOAD_FAST                       3: _var_var_1
                        422     CALL                            1
                        430     POP_TOP                         
                        432     LOAD_FAST                       0: self
                        434     LOAD_ATTR                       22: initial_content
                        454     POP_JUMP_IF_FALSE               27 (to 510)
                        456     LOAD_FAST                       0: self
                        458     LOAD_ATTR                       25: set_content
                        478     LOAD_FAST                       0: self
                        480     LOAD_ATTR                       22: initial_content
                        500     CALL                            1
                        508     POP_TOP                         
                        510     LOAD_CONST                      0: None
                        512     NOP                             
                        514     NOP                             
                        516     NOP                             
                        518     JUMP_FORWARD                    19 (to 558)
                        526     POP_TOP                         
                        528     RETURN_CONST                    0: None
                        530     PUSH_EXC_INFO                   
                        532     PUSH_NULL                       
                        534     LOAD_CONST                      7: '__pyarmor_exit_54489__'
                        536     NOP                             
                        538     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf8\x01\x00\x00\x00\x00\x00\x00'
                        540     CALL                            1
                        548     POP_TOP                         
                        550     RERAISE                         0
                        552     COPY                            3
                        554     POP_EXCEPT                      
                        556     RERAISE                         1
                        558     PUSH_NULL                       
                        560     LOAD_CONST                      7: '__pyarmor_exit_54489__'
                        562     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xf8\x01\x00\x00\x00\x00\x00\x00'
                        564     BUILD_TUPLE                     1
                        566     CALL_FUNCTION_EX                0
                        568     POP_TOP                         
                        570     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: set_content
                    Qualified Name: DecompilationViewPluginForm.set_content
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'code_browser'
                        'CppLexer'
                        'HtmlFormatter'
                        'highlight'
                        'setHtml'
                    [Locals+Names]
                        'self'
                        'code'
                        '__assert_armored__'
                        '_var_var_2'
                        '_var_var_3'
                        '_var_var_4'
                    [Constants]
                        None
                        '__pyarmor_assert_54490__'
                        '__pyarmor_enter_54491__'
                        b'<COAddr>\x01\x00\x00\x1a\xac\x00\x00\x00\x00\x00\x00\x00'
                        'vs'
                        True
                        (
                            'style'
                            'noclasses'
                        )
                        '__pyarmor_exit_54492__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54491__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xac\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: code_browser
                        50      POP_JUMP_IF_FALSE               63 (to 178)
                        52      LOAD_GLOBAL                     3: NULL + CppLexer
                        62      CALL                            0
                        70      STORE_FAST                      3: _var_var_2
                        72      LOAD_GLOBAL                     5: NULL + HtmlFormatter
                        82      LOAD_CONST                      4: 'vs'
                        84      LOAD_CONST                      5: True
                        86      KW_NAMES                        6: ('style', 'noclasses')
                        88      CALL                            2
                        96      STORE_FAST                      4: _var_var_3
                        98      LOAD_GLOBAL                     7: NULL + highlight
                        108     LOAD_FAST                       1: code
                        110     LOAD_FAST                       3: _var_var_2
                        112     LOAD_FAST                       4: _var_var_3
                        114     CALL                            3
                        122     STORE_FAST                      5: _var_var_4
                        124     LOAD_FAST                       0: self
                        126     LOAD_ATTR                       0: code_browser
                        146     LOAD_ATTR                       9: setHtml
                        166     LOAD_FAST                       5: _var_var_4
                        168     CALL                            1
                        176     POP_TOP                         
                        178     LOAD_CONST                      0: None
                        180     NOP                             
                        182     NOP                             
                        184     NOP                             
                        186     JUMP_FORWARD                    19 (to 226)
                        194     POP_TOP                         
                        196     RETURN_CONST                    0: None
                        198     PUSH_EXC_INFO                   
                        200     PUSH_NULL                       
                        202     LOAD_CONST                      7: '__pyarmor_exit_54492__'
                        204     NOP                             
                        206     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xac\x00\x00\x00\x00\x00\x00\x00'
                        208     CALL                            1
                        216     POP_TOP                         
                        218     RERAISE                         0
                        220     COPY                            3
                        222     POP_EXCEPT                      
                        224     RERAISE                         1
                        226     PUSH_NULL                       
                        228     LOAD_CONST                      7: '__pyarmor_exit_54492__'
                        230     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xac\x00\x00\x00\x00\x00\x00\x00'
                        232     BUILD_TUPLE                     1
                        234     CALL_FUNCTION_EX                0
                        236     POP_TOP                         
                        238     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: OnClose
                    Qualified Name: DecompilationViewPluginForm.OnClose
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        'self'
                        'form'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54493__'
                        '__pyarmor_enter_54494__'
                        b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54495__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54494__'
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
                        52      LOAD_CONST                      4: '__pyarmor_exit_54495__'
                        54      NOP                             
                        56      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        58      CALL                            1
                        66      POP_TOP                         
                        68      RERAISE                         0
                        70      COPY                            3
                        72      POP_EXCEPT                      
                        74      RERAISE                         1
                        76      PUSH_NULL                       
                        78      LOAD_CONST                      4: '__pyarmor_exit_54495__'
                        80      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x16\x00\x00\x00\x00\x00\x00\x00'
                        82      BUILD_TUPLE                     1
                        84      CALL_FUNCTION_EX                0
                        86      POP_TOP                         
                        88      RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: Show
                    Qualified Name: DecompilationViewPluginForm.Show
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'DecompilationViewPluginForm'
                        'Show'
                        'title'
                        'ida_kernwin'
                        'PluginForm'
                        'WOPN_TAB'
                        'WOPN_PERSIST'
                        'WOPN_RESTORE'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54496__'
                        '__pyarmor_enter_54497__'
                        b'<COAddr>\x01\x00\x00\x1c\xee\x00\x00\x00\x00\x00\x00\x00'
                        (
                            'options'
                        )
                        '__pyarmor_exit_54498__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54497__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xee\x00\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: DecompilationViewPluginForm
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: Show
                        56      LOAD_FAST                       0: self
                        58      LOAD_ATTR                       6: title
                        78      LOAD_GLOBAL                     8: ida_kernwin
                        88      LOAD_ATTR                       10: PluginForm
                        108     LOAD_ATTR                       12: WOPN_TAB
                        128     LOAD_GLOBAL                     8: ida_kernwin
                        138     LOAD_ATTR                       10: PluginForm
                        158     LOAD_ATTR                       14: WOPN_PERSIST
                        178     BINARY_OP                       7 (|)
                        182     LOAD_GLOBAL                     8: ida_kernwin
                        192     LOAD_ATTR                       10: PluginForm
                        212     LOAD_ATTR                       16: WOPN_RESTORE
                        232     BINARY_OP                       7 (|)
                        236     KW_NAMES                        4: ('options',)
                        238     CALL                            2
                        246     NOP                             
                        248     NOP                             
                        250     NOP                             
                        252     JUMP_FORWARD                    20 (to 294)
                        254     CALL                            1
                        262     POP_TOP                         
                        264     RETURN_VALUE                    
                        266     PUSH_EXC_INFO                   
                        268     PUSH_NULL                       
                        270     LOAD_CONST                      5: '__pyarmor_exit_54498__'
                        272     NOP                             
                        274     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xee\x00\x00\x00\x00\x00\x00\x00'
                        276     CALL                            1
                        284     POP_TOP                         
                        286     RERAISE                         0
                        288     COPY                            3
                        290     POP_EXCEPT                      
                        292     RERAISE                         1
                        294     PUSH_NULL                       
                        296     LOAD_CONST                      5: '__pyarmor_exit_54498__'
                        298     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xee\x00\x00\x00\x00\x00\x00\x00'
                        300     BUILD_TUPLE                     1
                        302     CALL_FUNCTION_EX                0
                        304     POP_TOP                         
                        306     RETURN_VALUE                    
                '__pyarmor_exit_54483__'
                (
                    ''
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'DecompilationViewPluginForm'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54482__'
                18      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                20      BUILD_TUPLE                     1
                22      CALL_FUNCTION_EX                0
                24      POP_TOP                         
                26      RESUME                          0
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      LOAD_CONST                      10: ('',)
                40      LOAD_CLOSURE                    0: __class__
                42      BUILD_TUPLE                     1
                44      LOAD_CONST                      4: <CODE> __init__
                46      MAKE_FUNCTION                   9
                48      STORE_NAME                      4: __init__
                50      LOAD_CONST                      5: <CODE> OnCreate
                52      MAKE_FUNCTION                   0
                54      STORE_NAME                      5: OnCreate
                56      LOAD_CONST                      6: <CODE> set_content
                58      MAKE_FUNCTION                   0
                60      STORE_NAME                      6: set_content
                62      LOAD_CONST                      7: <CODE> OnClose
                64      MAKE_FUNCTION                   0
                66      STORE_NAME                      7: OnClose
                68      LOAD_CLOSURE                    0: __class__
                70      BUILD_TUPLE                     1
                72      LOAD_CONST                      8: <CODE> Show
                74      MAKE_FUNCTION                   8
                76      STORE_NAME                      8: Show
                78      LOAD_CLOSURE                    0: __class__
                80      COPY                            1
                82      STORE_NAME                      9: __classcell__
                84      NOP                             
                86      NOP                             
                88      NOP                             
                90      JUMP_FORWARD                    20 (to 132)
                94      POP_TOP                         
                96      LOAD_CLOSURE                    0: __class__
                98      COPY                            1
                100     STORE_NAME                      9: __classcell__
                102     RETURN_VALUE                    
                104     PUSH_EXC_INFO                   
                106     PUSH_NULL                       
                108     LOAD_CONST                      9: '__pyarmor_exit_54483__'
                110     NOP                             
                112     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                114     CALL                            1
                122     POP_TOP                         
                124     RERAISE                         0
                126     COPY                            3
                128     POP_EXCEPT                      
                130     RERAISE                         1
                132     PUSH_NULL                       
                134     LOAD_CONST                      9: '__pyarmor_exit_54483__'
                136     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                138     BUILD_TUPLE                     1
                140     CALL_FUNCTION_EX                0
                142     POP_TOP                         
                144     RETURN_VALUE                    
        'DecompilationViewPluginForm'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: create_decompilation_view
            Qualified Name: create_decompilation_view
            Arg Count: 2
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'print'
                'idc'
                'get_func_name'
                'DecompilationViewPluginForm'
                'Show'
                'ida_kernwin'
                'find_widget'
                'Exception'
                'str'
                'traceback'
                'print_exc'
            [Locals+Names]
                'ea'
                'content'
                '__assert_armored__'
                '_var_var_5'
                '_var_var_6'
                '_var_var_7'
                '_var_var_8'
                '_var_var_9'
            [Constants]
                '\n    在IDA主线程中创建反编译视图 (使用PluginForm)\n    \n    Args:\n        ea: func addr\n        content: view content\n        \n    Returns:\n        bool: True if success, False otherwise\n    '
                '__pyarmor_assert_54499__'
                '__pyarmor_enter_54500__'
                b'<COAddr>\x01\x00\x00\x1a\xaa\x01\x00\x00\x00\x00\x00\x00'
                '[*] Try to create ReCopilot decompilation view using PluginForm'
                'ReCopilot Decompilation - '
                '[+] Successfully created/shown decompilation view with PluginForm, title: '
                '__pyarmor_exit_54501__'
                True
                '[!] Failed to verify creation/showing of decompilation view with PluginForm, title: '
                '.'
                False
                '[!] Error creating decompilation view with PluginForm: '
                0
                None
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54500__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x01\x00\x00\x00\x00\x00\x00'
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
                30      LOAD_GLOBAL                     1: NULL + print
                40      LOAD_CONST                      4: '[*] Try to create ReCopilot decompilation view using PluginForm'
                42      CALL                            1
                50      POP_TOP                         
                52      LOAD_GLOBAL                     3: NULL + idc
                62      LOAD_ATTR                       4: get_func_name
                82      LOAD_FAST                       0: ea
                84      CALL                            1
                92      STORE_FAST                      3: _var_var_5
                94      LOAD_CONST                      5: 'ReCopilot Decompilation - '
                96      LOAD_FAST                       3: _var_var_5
                98      FORMAT_VALUE                    0 (FVC_NONE)
                100     BUILD_STRING                    2
                102     STORE_FAST                      4: _var_var_6
                104     LOAD_GLOBAL                     7: NULL + DecompilationViewPluginForm
                114     LOAD_FAST                       4: _var_var_6
                116     LOAD_FAST                       1: content
                118     CALL                            2
                126     STORE_FAST                      5: _var_var_7
                128     LOAD_FAST                       5: _var_var_7
                130     LOAD_ATTR                       9: Show
                150     CALL                            0
                158     POP_TOP                         
                160     LOAD_GLOBAL                     11: NULL + ida_kernwin
                170     LOAD_ATTR                       12: find_widget
                190     LOAD_FAST                       4: _var_var_6
                192     CALL                            1
                200     POP_JUMP_IF_FALSE               25 (to 252)
                202     LOAD_GLOBAL                     1: NULL + print
                212     LOAD_CONST                      6: '[+] Successfully created/shown decompilation view with PluginForm, title: '
                214     LOAD_FAST                       4: _var_var_6
                216     FORMAT_VALUE                    0 (FVC_NONE)
                218     BUILD_STRING                    2
                220     CALL                            1
                228     POP_TOP                         
                230     NOP                             
                232     LOAD_CONST                      8: True
                234     NOP                             
                236     NOP                             
                238     NOP                             
                240     JUMP_FORWARD                    119 (to 480)
                248     POP_TOP                         
                250     RETURN_CONST                    8: True
                252     LOAD_GLOBAL                     1: NULL + print
                262     LOAD_CONST                      9: '[!] Failed to verify creation/showing of decompilation view with PluginForm, title: '
                264     LOAD_FAST                       4: _var_var_6
                266     FORMAT_VALUE                    0 (FVC_NONE)
                268     LOAD_CONST                      10: '.'
                270     BUILD_STRING                    3
                272     CALL                            1
                280     POP_TOP                         
                282     NOP                             
                284     LOAD_CONST                      11: False
                286     NOP                             
                288     NOP                             
                290     NOP                             
                292     JUMP_FORWARD                    93 (to 480)
                300     POP_TOP                         
                302     RETURN_CONST                    11: False
                304     PUSH_EXC_INFO                   
                306     LOAD_GLOBAL                     14: Exception
                316     CHECK_EXC_MATCH                 
                318     POP_JUMP_IF_FALSE               62 (to 444)
                320     STORE_FAST                      6: _var_var_8
                322     LOAD_GLOBAL                     1: NULL + print
                332     LOAD_CONST                      12: '[!] Error creating decompilation view with PluginForm: '
                334     LOAD_GLOBAL                     17: NULL + str
                344     LOAD_FAST                       6: _var_var_8
                346     CALL                            1
                354     FORMAT_VALUE                    0 (FVC_NONE)
                356     BUILD_STRING                    2
                358     CALL                            1
                366     POP_TOP                         
                368     LOAD_CONST                      13: 0
                370     LOAD_CONST                      14: None
                372     IMPORT_NAME                     9: traceback
                374     STORE_FAST                      7: _var_var_9
                376     LOAD_FAST                       7: _var_var_9
                378     LOAD_ATTR                       21: print_exc
                398     CALL                            0
                406     POP_TOP                         
                408     POP_EXCEPT                      
                410     LOAD_CONST                      14: None
                412     STORE_FAST                      6: _var_var_8
                414     DELETE_FAST                     6: _var_var_8
                416     LOAD_CONST                      11: False
                418     NOP                             
                420     NOP                             
                422     NOP                             
                424     JUMP_FORWARD                    27 (to 480)
                432     POP_TOP                         
                434     RETURN_CONST                    11: False
                436     LOAD_CONST                      14: None
                438     STORE_FAST                      6: _var_var_8
                440     DELETE_FAST                     6: _var_var_8
                442     RERAISE                         1
                444     RERAISE                         0
                446     COPY                            3
                448     POP_EXCEPT                      
                450     RERAISE                         1
                452     PUSH_EXC_INFO                   
                454     PUSH_NULL                       
                456     LOAD_CONST                      7: '__pyarmor_exit_54501__'
                458     NOP                             
                460     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x01\x00\x00\x00\x00\x00\x00'
                462     CALL                            1
                470     POP_TOP                         
                472     RERAISE                         0
                474     COPY                            3
                476     POP_EXCEPT                      
                478     RERAISE                         1
                480     PUSH_NULL                       
                482     LOAD_CONST                      7: '__pyarmor_exit_54501__'
                484     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xaa\x01\x00\x00\x00\x00\x00\x00'
                486     BUILD_TUPLE                     1
                488     CALL_FUNCTION_EX                0
                490     POP_TOP                         
                492     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: EditablePredictionWidget
            Qualified Name: EditablePredictionWidget
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
                'accepted_state_change'
                'get_content'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'EditablePredictionWidget'
                '__pyarmor_assert_54502__'
                '__pyarmor_enter_54503__'
                b'<COAddr>\x03\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: EditablePredictionWidget.__init__
                    Arg Count: 6
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'EditablePredictionWidget'
                        '__init__'
                        'accepted'
                        'QtWidgets'
                        'QVBoxLayout'
                        'setAlignment'
                        'QtCore'
                        'Qt'
                        'AlignLeft'
                        'AlignVCenter'
                        'QGroupBox'
                        'QHBoxLayout'
                        'setSpacing'
                        'QCheckBox'
                        'checkbox'
                        'setCheckState'
                        'Checked'
                        'stateChanged'
                        'connect'
                        'accepted_state_change'
                        'QTextEdit'
                        'content_edit'
                        'setMinimumWidth'
                        'setMinimumHeight'
                        'min'
                        'QLineEdit'
                        'setText'
                        'addWidget'
                        'setLayout'
                    [Locals+Names]
                        'self'
                        'title'
                        'content'
                        'is_multiline'
                        'line_count'
                        'force_single_line'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_10'
                        '_var_var_11'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54505__'
                        '__pyarmor_enter_54506__'
                        b'<COAddr>\x01\x00\x00\x1cn\x05\x00\x00\x00\x00\x00\x00'
                        True
                        10
                        '\n'
                        False
                        1
                        500
                        20
                        300
                        100
                        '__pyarmor_exit_54507__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54506__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1cn\x05\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: EditablePredictionWidget
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_CONST                      4: True
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: accepted
                        80      LOAD_GLOBAL                     9: NULL + QtWidgets
                        90      LOAD_ATTR                       10: QVBoxLayout
                        110     CALL                            0
                        118     STORE_FAST                      7: _var_var_1
                        120     LOAD_FAST                       7: _var_var_1
                        122     LOAD_ATTR                       13: setAlignment
                        142     LOAD_GLOBAL                     14: QtCore
                        152     LOAD_ATTR                       16: Qt
                        172     LOAD_ATTR                       18: AlignLeft
                        192     LOAD_GLOBAL                     14: QtCore
                        202     LOAD_ATTR                       16: Qt
                        222     LOAD_ATTR                       20: AlignVCenter
                        242     BINARY_OP                       7 (|)
                        246     CALL                            1
                        254     POP_TOP                         
                        256     LOAD_GLOBAL                     9: NULL + QtWidgets
                        266     LOAD_ATTR                       22: QGroupBox
                        286     LOAD_FAST                       1: title
                        288     CALL                            1
                        296     STORE_FAST                      8: _var_var_10
                        298     LOAD_GLOBAL                     9: NULL + QtWidgets
                        308     LOAD_ATTR                       24: QHBoxLayout
                        328     CALL                            0
                        336     STORE_FAST                      9: _var_var_11
                        338     LOAD_FAST                       9: _var_var_11
                        340     LOAD_ATTR                       13: setAlignment
                        360     LOAD_GLOBAL                     14: QtCore
                        370     LOAD_ATTR                       16: Qt
                        390     LOAD_ATTR                       18: AlignLeft
                        410     LOAD_GLOBAL                     14: QtCore
                        420     LOAD_ATTR                       16: Qt
                        440     LOAD_ATTR                       20: AlignVCenter
                        460     BINARY_OP                       7 (|)
                        464     CALL                            1
                        472     POP_TOP                         
                        474     LOAD_FAST                       9: _var_var_11
                        476     LOAD_ATTR                       27: setSpacing
                        496     LOAD_CONST                      5: 10
                        498     CALL                            1
                        506     POP_TOP                         
                        508     LOAD_GLOBAL                     9: NULL + QtWidgets
                        518     LOAD_ATTR                       28: QCheckBox
                        538     CALL                            0
                        546     LOAD_FAST                       0: self
                        548     STORE_ATTR                      15: checkbox
                        558     LOAD_FAST                       0: self
                        560     LOAD_ATTR                       30: checkbox
                        580     LOAD_ATTR                       33: setCheckState
                        600     LOAD_GLOBAL                     14: QtCore
                        610     LOAD_ATTR                       16: Qt
                        630     LOAD_ATTR                       34: Checked
                        650     CALL                            1
                        658     POP_TOP                         
                        660     LOAD_FAST                       0: self
                        662     LOAD_ATTR                       30: checkbox
                        682     LOAD_ATTR                       36: stateChanged
                        702     LOAD_ATTR                       39: connect
                        722     LOAD_FAST                       0: self
                        724     LOAD_ATTR                       40: accepted_state_change
                        744     CALL                            1
                        752     POP_TOP                         
                        754     LOAD_FAST                       5: force_single_line
                        756     POP_JUMP_IF_FALSE               8 (to 774)
                        758     LOAD_CONST                      6: '\n'
                        760     LOAD_FAST                       2: content
                        762     CONTAINS_OP                     1 (not in)
                        764     POP_JUMP_IF_FALSE               4 (to 774)
                        766     LOAD_CONST                      7: False
                        768     STORE_FAST                      3: is_multiline
                        770     LOAD_CONST                      8: 1
                        772     STORE_FAST                      4: line_count
                        774     LOAD_FAST                       3: is_multiline
                        776     POP_JUMP_IF_FALSE               126 (to 1030)
                        778     LOAD_GLOBAL                     9: NULL + QtWidgets
                        788     LOAD_ATTR                       42: QTextEdit
                        808     CALL                            0
                        816     LOAD_FAST                       0: self
                        818     STORE_ATTR                      22: content_edit
                        828     LOAD_FAST                       0: self
                        830     LOAD_ATTR                       44: content_edit
                        850     LOAD_ATTR                       47: setMinimumWidth
                        870     LOAD_CONST                      9: 500
                        872     CALL                            1
                        880     POP_TOP                         
                        882     LOAD_FAST                       4: line_count
                        884     POP_JUMP_IF_FALSE               44 (to 974)
                        886     LOAD_FAST                       0: self
                        888     LOAD_ATTR                       44: content_edit
                        908     LOAD_ATTR                       49: setMinimumHeight
                        928     LOAD_GLOBAL                     51: NULL + min
                        938     LOAD_CONST                      10: 20
                        940     LOAD_FAST                       4: line_count
                        942     BINARY_OP                       5 (*)
                        946     LOAD_CONST                      5: 10
                        948     BINARY_OP                       0 (+)
                        952     LOAD_CONST                      11: 300
                        954     CALL                            2
                        962     CALL                            1
                        970     POP_TOP                         
                        972     JUMP_FORWARD                    80 (to 1134)
                        974     LOAD_FAST                       0: self
                        976     LOAD_ATTR                       44: content_edit
                        996     LOAD_ATTR                       49: setMinimumHeight
                        1016    LOAD_CONST                      12: 100
                        1018    CALL                            1
                        1026    POP_TOP                         
                        1028    JUMP_FORWARD                    52 (to 1134)
                        1030    LOAD_GLOBAL                     9: NULL + QtWidgets
                        1040    LOAD_ATTR                       52: QLineEdit
                        1060    CALL                            0
                        1068    LOAD_FAST                       0: self
                        1070    STORE_ATTR                      22: content_edit
                        1080    LOAD_FAST                       0: self
                        1082    LOAD_ATTR                       44: content_edit
                        1102    LOAD_ATTR                       47: setMinimumWidth
                        1122    LOAD_CONST                      9: 500
                        1124    CALL                            1
                        1132    POP_TOP                         
                        1134    LOAD_FAST                       0: self
                        1136    LOAD_ATTR                       44: content_edit
                        1156    LOAD_ATTR                       55: setText
                        1176    LOAD_FAST                       2: content
                        1178    CALL                            1
                        1186    POP_TOP                         
                        1188    LOAD_FAST                       9: _var_var_11
                        1190    LOAD_ATTR                       57: addWidget
                        1210    LOAD_FAST                       0: self
                        1212    LOAD_ATTR                       30: checkbox
                        1232    CALL                            1
                        1240    POP_TOP                         
                        1242    LOAD_FAST                       9: _var_var_11
                        1244    LOAD_ATTR                       57: addWidget
                        1264    LOAD_FAST                       0: self
                        1266    LOAD_ATTR                       44: content_edit
                        1286    CALL                            1
                        1294    POP_TOP                         
                        1296    LOAD_FAST                       8: _var_var_10
                        1298    LOAD_ATTR                       59: setLayout
                        1318    LOAD_FAST                       9: _var_var_11
                        1320    CALL                            1
                        1328    POP_TOP                         
                        1330    LOAD_FAST                       7: _var_var_1
                        1332    LOAD_ATTR                       57: addWidget
                        1352    LOAD_FAST                       8: _var_var_10
                        1354    CALL                            1
                        1362    POP_TOP                         
                        1364    LOAD_FAST                       0: self
                        1366    LOAD_ATTR                       59: setLayout
                        1386    LOAD_FAST                       7: _var_var_1
                        1388    CALL                            1
                        1396    POP_TOP                         
                        1398    LOAD_CONST                      0: None
                        1400    NOP                             
                        1402    NOP                             
                        1404    NOP                             
                        1406    JUMP_FORWARD                    19 (to 1446)
                        1414    POP_TOP                         
                        1416    RETURN_CONST                    0: None
                        1418    PUSH_EXC_INFO                   
                        1420    PUSH_NULL                       
                        1422    LOAD_CONST                      13: '__pyarmor_exit_54507__'
                        1424    NOP                             
                        1426    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1cn\x05\x00\x00\x00\x00\x00\x00'
                        1428    CALL                            1
                        1436    POP_TOP                         
                        1438    RERAISE                         0
                        1440    COPY                            3
                        1442    POP_EXCEPT                      
                        1444    RERAISE                         1
                        1446    PUSH_NULL                       
                        1448    LOAD_CONST                      13: '__pyarmor_exit_54507__'
                        1450    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1cn\x05\x00\x00\x00\x00\x00\x00'
                        1452    BUILD_TUPLE                     1
                        1454    CALL_FUNCTION_EX                0
                        1456    POP_TOP                         
                        1458    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: accepted_state_change
                    Qualified Name: EditablePredictionWidget.accepted_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted'
                        'content_edit'
                        'setEnabled'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54508__'
                        '__pyarmor_enter_54509__'
                        b'<COAddr>\x03\x00\x00\x1a\xa4\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54510__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54509__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa4\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: content_edit
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       6: accepted
                        160     CALL                            1
                        168     POP_TOP                         
                        170     LOAD_CONST                      0: None
                        172     NOP                             
                        174     NOP                             
                        176     NOP                             
                        178     JUMP_FORWARD                    19 (to 218)
                        186     POP_TOP                         
                        188     RETURN_CONST                    0: None
                        190     PUSH_EXC_INFO                   
                        192     PUSH_NULL                       
                        194     LOAD_CONST                      4: '__pyarmor_exit_54510__'
                        196     NOP                             
                        198     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa4\x00\x00\x00\x00\x00\x00\x00'
                        200     CALL                            1
                        208     POP_TOP                         
                        210     RERAISE                         0
                        212     COPY                            3
                        214     POP_EXCEPT                      
                        216     RERAISE                         1
                        218     PUSH_NULL                       
                        220     LOAD_CONST                      4: '__pyarmor_exit_54510__'
                        222     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa4\x00\x00\x00\x00\x00\x00\x00'
                        224     BUILD_TUPLE                     1
                        226     CALL_FUNCTION_EX                0
                        228     POP_TOP                         
                        230     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: get_content
                    Qualified Name: EditablePredictionWidget.get_content
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'isinstance'
                        'content_edit'
                        'QtWidgets'
                        'QTextEdit'
                        'toPlainText'
                        'text'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54511__'
                        '__pyarmor_enter_54512__'
                        b'<COAddr>\x01\x00\x00\x1a\xc4\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54513__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54512__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc4\x00\x00\x00\x00\x00\x00\x00'
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
                        38      LOAD_FAST                       0: self
                        40      LOAD_ATTR                       2: content_edit
                        60      LOAD_GLOBAL                     4: QtWidgets
                        70      LOAD_ATTR                       6: QTextEdit
                        90      CALL                            2
                        98      POP_JUMP_IF_FALSE               26 (to 152)
                        100     LOAD_FAST                       0: self
                        102     LOAD_ATTR                       2: content_edit
                        122     LOAD_ATTR                       9: toPlainText
                        142     CALL                            0
                        150     JUMP_FORWARD                    25 (to 202)
                        152     LOAD_FAST                       0: self
                        154     LOAD_ATTR                       2: content_edit
                        174     LOAD_ATTR                       11: text
                        194     CALL                            0
                        202     NOP                             
                        204     NOP                             
                        206     NOP                             
                        208     JUMP_FORWARD                    20 (to 250)
                        210     CALL                            1
                        218     POP_TOP                         
                        220     RETURN_VALUE                    
                        222     PUSH_EXC_INFO                   
                        224     PUSH_NULL                       
                        226     LOAD_CONST                      4: '__pyarmor_exit_54513__'
                        228     NOP                             
                        230     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc4\x00\x00\x00\x00\x00\x00\x00'
                        232     CALL                            1
                        240     POP_TOP                         
                        242     RERAISE                         0
                        244     COPY                            3
                        246     POP_EXCEPT                      
                        248     RERAISE                         1
                        250     PUSH_NULL                       
                        252     LOAD_CONST                      4: '__pyarmor_exit_54513__'
                        254     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc4\x00\x00\x00\x00\x00\x00\x00'
                        256     BUILD_TUPLE                     1
                        258     CALL_FUNCTION_EX                0
                        260     POP_TOP                         
                        262     RETURN_VALUE                    
                '__pyarmor_exit_54504__'
                (
                    ''
                    False
                    None
                    False
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'EditablePredictionWidget'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54503__'
                18      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                20      BUILD_TUPLE                     1
                22      CALL_FUNCTION_EX                0
                24      POP_TOP                         
                26      RESUME                          0
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      LOAD_CONST                      8: ('', False, None, False)
                40      LOAD_CLOSURE                    0: __class__
                42      BUILD_TUPLE                     1
                44      LOAD_CONST                      4: <CODE> __init__
                46      MAKE_FUNCTION                   9
                48      STORE_NAME                      4: __init__
                50      LOAD_CONST                      5: <CODE> accepted_state_change
                52      MAKE_FUNCTION                   0
                54      STORE_NAME                      5: accepted_state_change
                56      LOAD_CONST                      6: <CODE> get_content
                58      MAKE_FUNCTION                   0
                60      STORE_NAME                      6: get_content
                62      LOAD_CLOSURE                    0: __class__
                64      COPY                            1
                66      STORE_NAME                      7: __classcell__
                68      NOP                             
                70      NOP                             
                72      NOP                             
                74      JUMP_FORWARD                    20 (to 116)
                78      POP_TOP                         
                80      LOAD_CLOSURE                    0: __class__
                82      COPY                            1
                84      STORE_NAME                      7: __classcell__
                86      RETURN_VALUE                    
                88      PUSH_EXC_INFO                   
                90      PUSH_NULL                       
                92      LOAD_CONST                      7: '__pyarmor_exit_54504__'
                94      NOP                             
                96      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                98      CALL                            1
                106     POP_TOP                         
                108     RERAISE                         0
                110     COPY                            3
                112     POP_EXCEPT                      
                114     RERAISE                         1
                116     PUSH_NULL                       
                118     LOAD_CONST                      7: '__pyarmor_exit_54504__'
                120     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                122     BUILD_TUPLE                     1
                124     CALL_FUNCTION_EX                0
                126     POP_TOP                         
                128     RETURN_VALUE                    
        'EditablePredictionWidget'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: NameTypeWidget
            Qualified Name: NameTypeWidget
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
                'QtCore'
                'pyqtSignal'
                'field_added'
                'QWidget'
                'field_removed'
                '__init__'
                'accepted_state_change'
                'name_state_change'
                'type_state_change'
                'size_state_change'
                'get_content'
                'validate'
                'on_add_clicked'
                'on_remove_clicked'
                'setEnabled'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'NameTypeWidget'
                '__pyarmor_assert_54514__'
                '__pyarmor_enter_54515__'
                b'<COAddr>\x01\x00\x00$\xa8\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: NameTypeWidget.__init__
                    Arg Count: 6
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'NameTypeWidget'
                        '__init__'
                        'accepted'
                        'accepted_name'
                        'accepted_type'
                        'accepted_size'
                        'is_enum'
                        'QtWidgets'
                        'QVBoxLayout'
                        'setAlignment'
                        'QtCore'
                        'Qt'
                        'AlignLeft'
                        'AlignVCenter'
                        'QGroupBox'
                        'QHBoxLayout'
                        'setSpacing'
                        'QCheckBox'
                        'name_checkbox'
                        'setCheckState'
                        'Checked'
                        'stateChanged'
                        'connect'
                        'name_state_change'
                        'QLineEdit'
                        'name_edit'
                        'setMinimumWidth'
                        'addWidget'
                        'type_checkbox'
                        'type_state_change'
                        'type_edit'
                        'addLayout'
                        'size_checkbox'
                        'size_state_change'
                        'str'
                        'size_edit'
                        'QPushButton'
                        'add_button'
                        'setMaximumWidth'
                        'clicked'
                        'on_add_clicked'
                        'remove_button'
                        'on_remove_clicked'
                        'addStretch'
                        'setLayout'
                    [Locals+Names]
                        'self'
                        'title'
                        'name'
                        'type_str'
                        'size'
                        'is_enum'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_10'
                        '_var_var_11'
                        '_var_var_12'
                        '_var_var_13'
                        '_var_var_14'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54517__'
                        '__pyarmor_enter_54518__'
                        b'<COAddr>\x01\x00\x00\x1c\x1a\x0b\x00\x00\x00\x00\x00\x00'
                        True
                        10
                        'Name'
                        200
                        'Value'
                        'Type'
                        'Size'
                        80
                        '+'
                        30
                        '-'
                        '__pyarmor_exit_54519__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54518__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x1a\x0b\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: NameTypeWidget
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_CONST                      4: True
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: accepted
                        80      LOAD_CONST                      4: True
                        82      LOAD_FAST                       0: self
                        84      STORE_ATTR                      4: accepted_name
                        94      LOAD_CONST                      4: True
                        96      LOAD_FAST                       0: self
                        98      STORE_ATTR                      5: accepted_type
                        108     LOAD_CONST                      4: True
                        110     LOAD_FAST                       0: self
                        112     STORE_ATTR                      6: accepted_size
                        122     LOAD_FAST                       5: is_enum
                        124     LOAD_FAST                       0: self
                        126     STORE_ATTR                      7: is_enum
                        136     LOAD_GLOBAL                     17: NULL + QtWidgets
                        146     LOAD_ATTR                       18: QVBoxLayout
                        166     CALL                            0
                        174     STORE_FAST                      7: _var_var_1
                        176     LOAD_FAST                       7: _var_var_1
                        178     LOAD_ATTR                       21: setAlignment
                        198     LOAD_GLOBAL                     22: QtCore
                        208     LOAD_ATTR                       24: Qt
                        228     LOAD_ATTR                       26: AlignLeft
                        248     LOAD_GLOBAL                     22: QtCore
                        258     LOAD_ATTR                       24: Qt
                        278     LOAD_ATTR                       28: AlignVCenter
                        298     BINARY_OP                       7 (|)
                        302     CALL                            1
                        310     POP_TOP                         
                        312     LOAD_GLOBAL                     17: NULL + QtWidgets
                        322     LOAD_ATTR                       30: QGroupBox
                        342     LOAD_FAST                       1: title
                        344     CALL                            1
                        352     STORE_FAST                      8: _var_var_10
                        354     LOAD_GLOBAL                     17: NULL + QtWidgets
                        364     LOAD_ATTR                       32: QHBoxLayout
                        384     CALL                            0
                        392     STORE_FAST                      9: _var_var_11
                        394     LOAD_FAST                       9: _var_var_11
                        396     LOAD_ATTR                       21: setAlignment
                        416     LOAD_GLOBAL                     22: QtCore
                        426     LOAD_ATTR                       24: Qt
                        446     LOAD_ATTR                       26: AlignLeft
                        466     LOAD_GLOBAL                     22: QtCore
                        476     LOAD_ATTR                       24: Qt
                        496     LOAD_ATTR                       28: AlignVCenter
                        516     BINARY_OP                       7 (|)
                        520     CALL                            1
                        528     POP_TOP                         
                        530     LOAD_FAST                       9: _var_var_11
                        532     LOAD_ATTR                       35: setSpacing
                        552     LOAD_CONST                      5: 10
                        554     CALL                            1
                        562     POP_TOP                         
                        564     LOAD_GLOBAL                     17: NULL + QtWidgets
                        574     LOAD_ATTR                       32: QHBoxLayout
                        594     CALL                            0
                        602     STORE_FAST                      10: _var_var_12
                        604     LOAD_GLOBAL                     17: NULL + QtWidgets
                        614     LOAD_ATTR                       36: QCheckBox
                        634     LOAD_CONST                      6: 'Name'
                        636     CALL                            1
                        644     LOAD_FAST                       0: self
                        646     STORE_ATTR                      19: name_checkbox
                        656     LOAD_FAST                       0: self
                        658     LOAD_ATTR                       38: name_checkbox
                        678     LOAD_ATTR                       41: setCheckState
                        698     LOAD_GLOBAL                     22: QtCore
                        708     LOAD_ATTR                       24: Qt
                        728     LOAD_ATTR                       42: Checked
                        748     CALL                            1
                        756     POP_TOP                         
                        758     LOAD_FAST                       0: self
                        760     LOAD_ATTR                       38: name_checkbox
                        780     LOAD_ATTR                       44: stateChanged
                        800     LOAD_ATTR                       47: connect
                        820     LOAD_FAST                       0: self
                        822     LOAD_ATTR                       48: name_state_change
                        842     CALL                            1
                        850     POP_TOP                         
                        852     LOAD_GLOBAL                     17: NULL + QtWidgets
                        862     LOAD_ATTR                       50: QLineEdit
                        882     LOAD_FAST                       2: name
                        884     CALL                            1
                        892     LOAD_FAST                       0: self
                        894     STORE_ATTR                      26: name_edit
                        904     LOAD_FAST                       0: self
                        906     LOAD_ATTR                       52: name_edit
                        926     LOAD_ATTR                       55: setMinimumWidth
                        946     LOAD_CONST                      7: 200
                        948     CALL                            1
                        956     POP_TOP                         
                        958     LOAD_FAST                       10: _var_var_12
                        960     LOAD_ATTR                       57: addWidget
                        980     LOAD_FAST                       0: self
                        982     LOAD_ATTR                       38: name_checkbox
                        1002    CALL                            1
                        1010    POP_TOP                         
                        1012    LOAD_FAST                       10: _var_var_12
                        1014    LOAD_ATTR                       57: addWidget
                        1034    LOAD_FAST                       0: self
                        1036    LOAD_ATTR                       52: name_edit
                        1056    CALL                            1
                        1064    POP_TOP                         
                        1066    LOAD_GLOBAL                     17: NULL + QtWidgets
                        1076    LOAD_ATTR                       32: QHBoxLayout
                        1096    CALL                            0
                        1104    STORE_FAST                      11: _var_var_13
                        1106    LOAD_GLOBAL                     17: NULL + QtWidgets
                        1116    LOAD_ATTR                       36: QCheckBox
                        1136    LOAD_FAST                       5: is_enum
                        1138    POP_JUMP_IF_FALSE               2 (to 1144)
                        1140    LOAD_CONST                      8: 'Value'
                        1142    JUMP_FORWARD                    1 (to 1146)
                        1144    LOAD_CONST                      9: 'Type'
                        1146    CALL                            1
                        1154    LOAD_FAST                       0: self
                        1156    STORE_ATTR                      29: type_checkbox
                        1166    LOAD_FAST                       0: self
                        1168    LOAD_ATTR                       58: type_checkbox
                        1188    LOAD_ATTR                       41: setCheckState
                        1208    LOAD_GLOBAL                     22: QtCore
                        1218    LOAD_ATTR                       24: Qt
                        1238    LOAD_ATTR                       42: Checked
                        1258    CALL                            1
                        1266    POP_TOP                         
                        1268    LOAD_FAST                       0: self
                        1270    LOAD_ATTR                       58: type_checkbox
                        1290    LOAD_ATTR                       44: stateChanged
                        1310    LOAD_ATTR                       47: connect
                        1330    LOAD_FAST                       0: self
                        1332    LOAD_ATTR                       60: type_state_change
                        1352    CALL                            1
                        1360    POP_TOP                         
                        1362    LOAD_GLOBAL                     17: NULL + QtWidgets
                        1372    LOAD_ATTR                       50: QLineEdit
                        1392    LOAD_FAST                       3: type_str
                        1394    CALL                            1
                        1402    LOAD_FAST                       0: self
                        1404    STORE_ATTR                      31: type_edit
                        1414    LOAD_FAST                       0: self
                        1416    LOAD_ATTR                       62: type_edit
                        1436    LOAD_ATTR                       55: setMinimumWidth
                        1456    LOAD_CONST                      7: 200
                        1458    CALL                            1
                        1466    POP_TOP                         
                        1468    LOAD_FAST                       11: _var_var_13
                        1470    LOAD_ATTR                       57: addWidget
                        1490    LOAD_FAST                       0: self
                        1492    LOAD_ATTR                       58: type_checkbox
                        1512    CALL                            1
                        1520    POP_TOP                         
                        1522    LOAD_FAST                       11: _var_var_13
                        1524    LOAD_ATTR                       57: addWidget
                        1544    LOAD_FAST                       0: self
                        1546    LOAD_ATTR                       62: type_edit
                        1566    CALL                            1
                        1574    POP_TOP                         
                        1576    LOAD_FAST                       9: _var_var_11
                        1578    LOAD_ATTR                       65: addLayout
                        1598    LOAD_FAST                       10: _var_var_12
                        1600    CALL                            1
                        1608    POP_TOP                         
                        1610    LOAD_FAST                       9: _var_var_11
                        1612    LOAD_ATTR                       65: addLayout
                        1632    LOAD_FAST                       11: _var_var_13
                        1634    CALL                            1
                        1642    POP_TOP                         
                        1644    LOAD_FAST                       5: is_enum
                        1646    POP_JUMP_IF_FALSE               277 (to 2204)
                        1650    LOAD_GLOBAL                     17: NULL + QtWidgets
                        1660    LOAD_ATTR                       32: QHBoxLayout
                        1680    CALL                            0
                        1688    STORE_FAST                      12: _var_var_14
                        1690    LOAD_GLOBAL                     17: NULL + QtWidgets
                        1700    LOAD_ATTR                       36: QCheckBox
                        1720    LOAD_CONST                      10: 'Size'
                        1722    CALL                            1
                        1730    LOAD_FAST                       0: self
                        1732    STORE_ATTR                      33: size_checkbox
                        1742    LOAD_FAST                       0: self
                        1744    LOAD_ATTR                       66: size_checkbox
                        1764    LOAD_ATTR                       41: setCheckState
                        1784    LOAD_GLOBAL                     22: QtCore
                        1794    LOAD_ATTR                       24: Qt
                        1814    LOAD_ATTR                       42: Checked
                        1834    CALL                            1
                        1842    POP_TOP                         
                        1844    LOAD_FAST                       0: self
                        1846    LOAD_ATTR                       66: size_checkbox
                        1866    LOAD_ATTR                       44: stateChanged
                        1886    LOAD_ATTR                       47: connect
                        1906    LOAD_FAST                       0: self
                        1908    LOAD_ATTR                       68: size_state_change
                        1928    CALL                            1
                        1936    POP_TOP                         
                        1938    LOAD_GLOBAL                     17: NULL + QtWidgets
                        1948    LOAD_ATTR                       50: QLineEdit
                        1968    LOAD_GLOBAL                     71: NULL + str
                        1978    LOAD_FAST                       4: size
                        1980    CALL                            1
                        1988    CALL                            1
                        1996    LOAD_FAST                       0: self
                        1998    STORE_ATTR                      36: size_edit
                        2008    LOAD_FAST                       0: self
                        2010    LOAD_ATTR                       72: size_edit
                        2030    LOAD_ATTR                       55: setMinimumWidth
                        2050    LOAD_CONST                      11: 80
                        2052    CALL                            1
                        2060    POP_TOP                         
                        2062    LOAD_FAST                       12: _var_var_14
                        2064    LOAD_ATTR                       57: addWidget
                        2084    LOAD_FAST                       0: self
                        2086    LOAD_ATTR                       66: size_checkbox
                        2106    CALL                            1
                        2114    POP_TOP                         
                        2116    LOAD_FAST                       12: _var_var_14
                        2118    LOAD_ATTR                       57: addWidget
                        2138    LOAD_FAST                       0: self
                        2140    LOAD_ATTR                       72: size_edit
                        2160    CALL                            1
                        2168    POP_TOP                         
                        2170    LOAD_FAST                       9: _var_var_11
                        2172    LOAD_ATTR                       65: addLayout
                        2192    LOAD_FAST                       12: _var_var_14
                        2194    CALL                            1
                        2202    POP_TOP                         
                        2204    LOAD_FAST                       5: is_enum
                        2206    POP_JUMP_IF_FALSE               254 (to 2716)
                        2208    LOAD_GLOBAL                     17: NULL + QtWidgets
                        2218    LOAD_ATTR                       74: QPushButton
                        2238    LOAD_CONST                      12: '+'
                        2240    CALL                            1
                        2248    LOAD_FAST                       0: self
                        2250    STORE_ATTR                      38: add_button
                        2260    LOAD_FAST                       0: self
                        2262    LOAD_ATTR                       76: add_button
                        2282    LOAD_ATTR                       79: setMaximumWidth
                        2302    LOAD_CONST                      13: 30
                        2304    CALL                            1
                        2312    POP_TOP                         
                        2314    LOAD_FAST                       0: self
                        2316    LOAD_ATTR                       76: add_button
                        2336    LOAD_ATTR                       80: clicked
                        2356    LOAD_ATTR                       47: connect
                        2376    LOAD_FAST                       0: self
                        2378    LOAD_ATTR                       82: on_add_clicked
                        2398    CALL                            1
                        2406    POP_TOP                         
                        2408    LOAD_GLOBAL                     17: NULL + QtWidgets
                        2418    LOAD_ATTR                       74: QPushButton
                        2438    LOAD_CONST                      14: '-'
                        2440    CALL                            1
                        2448    LOAD_FAST                       0: self
                        2450    STORE_ATTR                      42: remove_button
                        2460    LOAD_FAST                       0: self
                        2462    LOAD_ATTR                       84: remove_button
                        2482    LOAD_ATTR                       79: setMaximumWidth
                        2502    LOAD_CONST                      13: 30
                        2504    CALL                            1
                        2512    POP_TOP                         
                        2514    LOAD_FAST                       0: self
                        2516    LOAD_ATTR                       84: remove_button
                        2536    LOAD_ATTR                       80: clicked
                        2556    LOAD_ATTR                       47: connect
                        2576    LOAD_FAST                       0: self
                        2578    LOAD_ATTR                       86: on_remove_clicked
                        2598    CALL                            1
                        2606    POP_TOP                         
                        2608    LOAD_FAST                       9: _var_var_11
                        2610    LOAD_ATTR                       57: addWidget
                        2630    LOAD_FAST                       0: self
                        2632    LOAD_ATTR                       76: add_button
                        2652    CALL                            1
                        2660    POP_TOP                         
                        2662    LOAD_FAST                       9: _var_var_11
                        2664    LOAD_ATTR                       57: addWidget
                        2684    LOAD_FAST                       0: self
                        2686    LOAD_ATTR                       84: remove_button
                        2706    CALL                            1
                        2714    POP_TOP                         
                        2716    LOAD_FAST                       9: _var_var_11
                        2718    LOAD_ATTR                       89: addStretch
                        2738    CALL                            0
                        2746    POP_TOP                         
                        2748    LOAD_FAST                       8: _var_var_10
                        2750    LOAD_ATTR                       91: setLayout
                        2770    LOAD_FAST                       9: _var_var_11
                        2772    CALL                            1
                        2780    POP_TOP                         
                        2782    LOAD_FAST                       7: _var_var_1
                        2784    LOAD_ATTR                       57: addWidget
                        2804    LOAD_FAST                       8: _var_var_10
                        2806    CALL                            1
                        2814    POP_TOP                         
                        2816    LOAD_FAST                       0: self
                        2818    LOAD_ATTR                       91: setLayout
                        2838    LOAD_FAST                       7: _var_var_1
                        2840    CALL                            1
                        2848    POP_TOP                         
                        2850    LOAD_CONST                      0: None
                        2852    NOP                             
                        2854    NOP                             
                        2856    NOP                             
                        2858    JUMP_FORWARD                    19 (to 2898)
                        2866    POP_TOP                         
                        2868    RETURN_CONST                    0: None
                        2870    PUSH_EXC_INFO                   
                        2872    PUSH_NULL                       
                        2874    LOAD_CONST                      15: '__pyarmor_exit_54519__'
                        2876    NOP                             
                        2878    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x1a\x0b\x00\x00\x00\x00\x00\x00'
                        2880    CALL                            1
                        2888    POP_TOP                         
                        2890    RERAISE                         0
                        2892    COPY                            3
                        2894    POP_EXCEPT                      
                        2896    RERAISE                         1
                        2898    PUSH_NULL                       
                        2900    LOAD_CONST                      15: '__pyarmor_exit_54519__'
                        2902    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x1a\x0b\x00\x00\x00\x00\x00\x00'
                        2904    BUILD_TUPLE                     1
                        2906    CALL_FUNCTION_EX                0
                        2908    POP_TOP                         
                        2910    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: accepted_state_change
                    Qualified Name: NameTypeWidget.accepted_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted'
                        'name_checkbox'
                        'setEnabled'
                        'type_checkbox'
                        'name_edit'
                        'accepted_name'
                        'type_edit'
                        'accepted_type'
                        'is_enum'
                        'size_checkbox'
                        'size_edit'
                        'accepted_size'
                        'add_button'
                        'remove_button'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54520__'
                        '__pyarmor_enter_54521__'
                        b'<COAddr>\x03\x00\x00\x1a\x16\x03\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54522__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54521__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x16\x03\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: name_checkbox
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       6: accepted
                        160     CALL                            1
                        168     POP_TOP                         
                        170     LOAD_FAST                       0: self
                        172     LOAD_ATTR                       12: type_checkbox
                        192     LOAD_ATTR                       11: setEnabled
                        212     LOAD_FAST                       0: self
                        214     LOAD_ATTR                       6: accepted
                        234     CALL                            1
                        242     POP_TOP                         
                        244     LOAD_FAST                       0: self
                        246     LOAD_ATTR                       14: name_edit
                        266     LOAD_ATTR                       11: setEnabled
                        286     LOAD_FAST                       0: self
                        288     LOAD_ATTR                       6: accepted
                        308     COPY                            1
                        310     POP_JUMP_IF_FALSE               12 (to 336)
                        312     POP_TOP                         
                        314     LOAD_FAST                       0: self
                        316     LOAD_ATTR                       16: accepted_name
                        336     CALL                            1
                        344     POP_TOP                         
                        346     LOAD_FAST                       0: self
                        348     LOAD_ATTR                       18: type_edit
                        368     LOAD_ATTR                       11: setEnabled
                        388     LOAD_FAST                       0: self
                        390     LOAD_ATTR                       6: accepted
                        410     COPY                            1
                        412     POP_JUMP_IF_FALSE               12 (to 438)
                        414     POP_TOP                         
                        416     LOAD_FAST                       0: self
                        418     LOAD_ATTR                       20: accepted_type
                        438     CALL                            1
                        446     POP_TOP                         
                        448     LOAD_FAST                       0: self
                        450     LOAD_ATTR                       22: is_enum
                        470     POP_JUMP_IF_FALSE               162 (to 796)
                        472     LOAD_FAST                       0: self
                        474     LOAD_ATTR                       24: size_checkbox
                        494     LOAD_ATTR                       11: setEnabled
                        514     LOAD_FAST                       0: self
                        516     LOAD_ATTR                       6: accepted
                        536     CALL                            1
                        544     POP_TOP                         
                        546     LOAD_FAST                       0: self
                        548     LOAD_ATTR                       26: size_edit
                        568     LOAD_ATTR                       11: setEnabled
                        588     LOAD_FAST                       0: self
                        590     LOAD_ATTR                       6: accepted
                        610     COPY                            1
                        612     POP_JUMP_IF_FALSE               12 (to 638)
                        614     POP_TOP                         
                        616     LOAD_FAST                       0: self
                        618     LOAD_ATTR                       28: accepted_size
                        638     CALL                            1
                        646     POP_TOP                         
                        648     LOAD_FAST                       0: self
                        650     LOAD_ATTR                       30: add_button
                        670     LOAD_ATTR                       11: setEnabled
                        690     LOAD_FAST                       0: self
                        692     LOAD_ATTR                       6: accepted
                        712     CALL                            1
                        720     POP_TOP                         
                        722     LOAD_FAST                       0: self
                        724     LOAD_ATTR                       32: remove_button
                        744     LOAD_ATTR                       11: setEnabled
                        764     LOAD_FAST                       0: self
                        766     LOAD_ATTR                       6: accepted
                        786     CALL                            1
                        794     POP_TOP                         
                        796     LOAD_CONST                      0: None
                        798     NOP                             
                        800     NOP                             
                        802     NOP                             
                        804     JUMP_FORWARD                    19 (to 844)
                        812     POP_TOP                         
                        814     RETURN_CONST                    0: None
                        816     PUSH_EXC_INFO                   
                        818     PUSH_NULL                       
                        820     LOAD_CONST                      4: '__pyarmor_exit_54522__'
                        822     NOP                             
                        824     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x16\x03\x00\x00\x00\x00\x00\x00'
                        826     CALL                            1
                        834     POP_TOP                         
                        836     RERAISE                         0
                        838     COPY                            3
                        840     POP_EXCEPT                      
                        842     RERAISE                         1
                        844     PUSH_NULL                       
                        846     LOAD_CONST                      4: '__pyarmor_exit_54522__'
                        848     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x16\x03\x00\x00\x00\x00\x00\x00'
                        850     BUILD_TUPLE                     1
                        852     CALL_FUNCTION_EX                0
                        854     POP_TOP                         
                        856     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: name_state_change
                    Qualified Name: NameTypeWidget.name_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted_name'
                        'name_edit'
                        'setEnabled'
                        'accepted'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54523__'
                        '__pyarmor_enter_54524__'
                        b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54525__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54524__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted_name
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: name_edit
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       12: accepted
                        160     COPY                            1
                        162     POP_JUMP_IF_FALSE               12 (to 188)
                        164     POP_TOP                         
                        166     LOAD_FAST                       0: self
                        168     LOAD_ATTR                       6: accepted_name
                        188     CALL                            1
                        196     POP_TOP                         
                        198     LOAD_CONST                      0: None
                        200     NOP                             
                        202     NOP                             
                        204     NOP                             
                        206     JUMP_FORWARD                    19 (to 246)
                        214     POP_TOP                         
                        216     RETURN_CONST                    0: None
                        218     PUSH_EXC_INFO                   
                        220     PUSH_NULL                       
                        222     LOAD_CONST                      4: '__pyarmor_exit_54525__'
                        224     NOP                             
                        226     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        228     CALL                            1
                        236     POP_TOP                         
                        238     RERAISE                         0
                        240     COPY                            3
                        242     POP_EXCEPT                      
                        244     RERAISE                         1
                        246     PUSH_NULL                       
                        248     LOAD_CONST                      4: '__pyarmor_exit_54525__'
                        250     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        252     BUILD_TUPLE                     1
                        254     CALL_FUNCTION_EX                0
                        256     POP_TOP                         
                        258     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: type_state_change
                    Qualified Name: NameTypeWidget.type_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted_type'
                        'type_edit'
                        'setEnabled'
                        'accepted'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54526__'
                        '__pyarmor_enter_54527__'
                        b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54528__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54527__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted_type
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: type_edit
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       12: accepted
                        160     COPY                            1
                        162     POP_JUMP_IF_FALSE               12 (to 188)
                        164     POP_TOP                         
                        166     LOAD_FAST                       0: self
                        168     LOAD_ATTR                       6: accepted_type
                        188     CALL                            1
                        196     POP_TOP                         
                        198     LOAD_CONST                      0: None
                        200     NOP                             
                        202     NOP                             
                        204     NOP                             
                        206     JUMP_FORWARD                    19 (to 246)
                        214     POP_TOP                         
                        216     RETURN_CONST                    0: None
                        218     PUSH_EXC_INFO                   
                        220     PUSH_NULL                       
                        222     LOAD_CONST                      4: '__pyarmor_exit_54528__'
                        224     NOP                             
                        226     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        228     CALL                            1
                        236     POP_TOP                         
                        238     RERAISE                         0
                        240     COPY                            3
                        242     POP_EXCEPT                      
                        244     RERAISE                         1
                        246     PUSH_NULL                       
                        248     LOAD_CONST                      4: '__pyarmor_exit_54528__'
                        250     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        252     BUILD_TUPLE                     1
                        254     CALL_FUNCTION_EX                0
                        256     POP_TOP                         
                        258     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: size_state_change
                    Qualified Name: NameTypeWidget.size_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted_size'
                        'size_edit'
                        'setEnabled'
                        'accepted'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54529__'
                        '__pyarmor_enter_54530__'
                        b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54531__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54530__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted_size
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: size_edit
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       12: accepted
                        160     COPY                            1
                        162     POP_JUMP_IF_FALSE               12 (to 188)
                        164     POP_TOP                         
                        166     LOAD_FAST                       0: self
                        168     LOAD_ATTR                       6: accepted_size
                        188     CALL                            1
                        196     POP_TOP                         
                        198     LOAD_CONST                      0: None
                        200     NOP                             
                        202     NOP                             
                        204     NOP                             
                        206     JUMP_FORWARD                    19 (to 246)
                        214     POP_TOP                         
                        216     RETURN_CONST                    0: None
                        218     PUSH_EXC_INFO                   
                        220     PUSH_NULL                       
                        222     LOAD_CONST                      4: '__pyarmor_exit_54531__'
                        224     NOP                             
                        226     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        228     CALL                            1
                        236     POP_TOP                         
                        238     RERAISE                         0
                        240     COPY                            3
                        242     POP_EXCEPT                      
                        244     RERAISE                         1
                        246     PUSH_NULL                       
                        248     LOAD_CONST                      4: '__pyarmor_exit_54531__'
                        250     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        252     BUILD_TUPLE                     1
                        254     CALL_FUNCTION_EX                0
                        256     POP_TOP                         
                        258     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: get_content
                    Qualified Name: NameTypeWidget.get_content
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'is_enum'
                        'accepted'
                        'accepted_size'
                        'int'
                        'size_edit'
                        'text'
                        'ValueError'
                        'accepted_name'
                        'name_edit'
                        'accepted_type'
                        'type_edit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_15'
                    [Constants]
                        None
                        '__pyarmor_assert_54532__'
                        '__pyarmor_enter_54533__'
                        b'<COAddr>\x01\x00\x00\x1a~\x02\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54534__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54533__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a~\x02\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: is_enum
                        50      POP_JUMP_IF_FALSE               176 (to 404)
                        52      NOP                             
                        54      LOAD_FAST                       0: self
                        56      LOAD_ATTR                       2: accepted
                        76      POP_JUMP_IF_FALSE               47 (to 172)
                        78      LOAD_FAST                       0: self
                        80      LOAD_ATTR                       4: accepted_size
                        100     POP_JUMP_IF_FALSE               35 (to 172)
                        102     LOAD_GLOBAL                     7: NULL + int
                        112     LOAD_FAST                       0: self
                        114     LOAD_ATTR                       8: size_edit
                        134     LOAD_ATTR                       11: text
                        154     CALL                            0
                        162     CALL                            1
                        170     JUMP_FORWARD                    1 (to 174)
                        172     LOAD_CONST                      0: None
                        174     STORE_FAST                      2: _var_var_15
                        176     LOAD_FAST                       0: self
                        178     LOAD_ATTR                       2: accepted
                        198     POP_JUMP_IF_FALSE               38 (to 276)
                        200     LOAD_FAST                       0: self
                        202     LOAD_ATTR                       14: accepted_name
                        222     POP_JUMP_IF_FALSE               26 (to 276)
                        224     LOAD_FAST                       0: self
                        226     LOAD_ATTR                       16: name_edit
                        246     LOAD_ATTR                       11: text
                        266     CALL                            0
                        274     JUMP_FORWARD                    1 (to 278)
                        276     LOAD_CONST                      0: None
                        278     LOAD_FAST                       0: self
                        280     LOAD_ATTR                       2: accepted
                        300     POP_JUMP_IF_FALSE               38 (to 378)
                        302     LOAD_FAST                       0: self
                        304     LOAD_ATTR                       18: accepted_type
                        324     POP_JUMP_IF_FALSE               26 (to 378)
                        326     LOAD_FAST                       0: self
                        328     LOAD_ATTR                       20: type_edit
                        348     LOAD_ATTR                       11: text
                        368     CALL                            0
                        376     JUMP_FORWARD                    1 (to 380)
                        378     LOAD_CONST                      0: None
                        380     LOAD_FAST                       2: _var_var_15
                        382     BUILD_LIST                      3
                        384     NOP                             
                        386     NOP                             
                        388     NOP                             
                        390     JUMP_FORWARD                    150 (to 692)
                        392     CALL                            1
                        400     POP_TOP                         
                        402     RETURN_VALUE                    
                        404     LOAD_FAST                       0: self
                        406     LOAD_ATTR                       2: accepted
                        426     POP_JUMP_IF_FALSE               38 (to 504)
                        428     LOAD_FAST                       0: self
                        430     LOAD_ATTR                       14: accepted_name
                        450     POP_JUMP_IF_FALSE               26 (to 504)
                        452     LOAD_FAST                       0: self
                        454     LOAD_ATTR                       16: name_edit
                        474     LOAD_ATTR                       11: text
                        494     CALL                            0
                        502     JUMP_FORWARD                    1 (to 506)
                        504     LOAD_CONST                      0: None
                        506     LOAD_FAST                       0: self
                        508     LOAD_ATTR                       2: accepted
                        528     POP_JUMP_IF_FALSE               38 (to 606)
                        530     LOAD_FAST                       0: self
                        532     LOAD_ATTR                       18: accepted_type
                        552     POP_JUMP_IF_FALSE               26 (to 606)
                        554     LOAD_FAST                       0: self
                        556     LOAD_ATTR                       20: type_edit
                        576     LOAD_ATTR                       11: text
                        596     CALL                            0
                        604     JUMP_FORWARD                    1 (to 608)
                        606     LOAD_CONST                      0: None
                        608     BUILD_LIST                      2
                        610     NOP                             
                        612     NOP                             
                        614     NOP                             
                        616     JUMP_FORWARD                    37 (to 692)
                        618     CALL                            1
                        626     POP_TOP                         
                        628     RETURN_VALUE                    
                        630     PUSH_EXC_INFO                   
                        632     LOAD_GLOBAL                     12: ValueError
                        642     CHECK_EXC_MATCH                 
                        644     POP_JUMP_IF_FALSE               5 (to 656)
                        646     POP_TOP                         
                        648     LOAD_CONST                      0: None
                        650     STORE_FAST                      2: _var_var_15
                        652     POP_EXCEPT                      
                        654     JUMP_BACKWARD                   240 (to 176)
                        656     RERAISE                         0
                        658     COPY                            3
                        660     POP_EXCEPT                      
                        662     RERAISE                         1
                        664     PUSH_EXC_INFO                   
                        666     PUSH_NULL                       
                        668     LOAD_CONST                      4: '__pyarmor_exit_54534__'
                        670     NOP                             
                        672     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a~\x02\x00\x00\x00\x00\x00\x00'
                        674     CALL                            1
                        682     POP_TOP                         
                        684     RERAISE                         0
                        686     COPY                            3
                        688     POP_EXCEPT                      
                        690     RERAISE                         1
                        692     PUSH_NULL                       
                        694     LOAD_CONST                      4: '__pyarmor_exit_54534__'
                        696     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a~\x02\x00\x00\x00\x00\x00\x00'
                        698     BUILD_TUPLE                     1
                        700     CALL_FUNCTION_EX                0
                        702     POP_TOP                         
                        704     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: validate
                    Qualified Name: NameTypeWidget.validate
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'accepted'
                        'accepted_name'
                        'name_edit'
                        'text'
                        'strip'
                        'accepted_type'
                        'type_edit'
                        'is_enum'
                        'accepted_size'
                        'int'
                        'size_edit'
                        'ValueError'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_15'
                    [Constants]
                        None
                        '__pyarmor_assert_54535__'
                        '__pyarmor_enter_54536__'
                        b'<COAddr>\x03\x00\x00\x1a&\x02\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54537__'
                        True
                        False
                        0
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54536__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a&\x02\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: accepted
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      5: True
                        56      NOP                             
                        58      NOP                             
                        60      JUMP_FORWARD                    270 (to 604)
                        70      POP_TOP                         
                        72      RETURN_CONST                    5: True
                        74      LOAD_FAST                       0: self
                        76      LOAD_ATTR                       2: accepted_name
                        96      POP_JUMP_IF_FALSE               51 (to 200)
                        98      LOAD_FAST                       0: self
                        100     LOAD_ATTR                       4: name_edit
                        120     LOAD_ATTR                       7: text
                        140     CALL                            0
                        148     LOAD_ATTR                       9: strip
                        168     CALL                            0
                        176     POP_JUMP_IF_TRUE                11 (to 200)
                        178     NOP                             
                        180     LOAD_CONST                      6: False
                        182     NOP                             
                        184     NOP                             
                        186     NOP                             
                        188     JUMP_FORWARD                    207 (to 604)
                        196     POP_TOP                         
                        198     RETURN_CONST                    6: False
                        200     LOAD_FAST                       0: self
                        202     LOAD_ATTR                       10: accepted_type
                        222     POP_JUMP_IF_FALSE               51 (to 326)
                        224     LOAD_FAST                       0: self
                        226     LOAD_ATTR                       12: type_edit
                        246     LOAD_ATTR                       7: text
                        266     CALL                            0
                        274     LOAD_ATTR                       9: strip
                        294     CALL                            0
                        302     POP_JUMP_IF_TRUE                11 (to 326)
                        304     NOP                             
                        306     LOAD_CONST                      6: False
                        308     NOP                             
                        310     NOP                             
                        312     NOP                             
                        314     JUMP_FORWARD                    144 (to 604)
                        322     POP_TOP                         
                        324     RETURN_CONST                    6: False
                        326     LOAD_FAST                       0: self
                        328     LOAD_ATTR                       14: is_enum
                        348     POP_JUMP_IF_FALSE               79 (to 508)
                        350     LOAD_FAST                       0: self
                        352     LOAD_ATTR                       16: accepted_size
                        372     POP_JUMP_IF_FALSE               67 (to 508)
                        374     NOP                             
                        376     LOAD_GLOBAL                     19: NULL + int
                        386     LOAD_FAST                       0: self
                        388     LOAD_ATTR                       20: size_edit
                        408     LOAD_ATTR                       7: text
                        428     CALL                            0
                        436     LOAD_ATTR                       9: strip
                        456     CALL                            0
                        464     CALL                            1
                        472     STORE_FAST                      2: _var_var_15
                        474     LOAD_FAST                       2: _var_var_15
                        476     LOAD_CONST                      7: 0
                        478     COMPARE_OP                      26 (<=)
                        482     POP_JUMP_IF_FALSE               11 (to 506)
                        484     NOP                             
                        486     LOAD_CONST                      6: False
                        488     NOP                             
                        490     NOP                             
                        492     NOP                             
                        494     JUMP_FORWARD                    54 (to 604)
                        502     POP_TOP                         
                        504     RETURN_CONST                    6: False
                        506     NOP                             
                        508     LOAD_CONST                      5: True
                        510     NOP                             
                        512     NOP                             
                        514     NOP                             
                        516     JUMP_FORWARD                    43 (to 604)
                        524     POP_TOP                         
                        526     RETURN_CONST                    5: True
                        528     PUSH_EXC_INFO                   
                        530     LOAD_GLOBAL                     22: ValueError
                        540     CHECK_EXC_MATCH                 
                        542     POP_JUMP_IF_FALSE               12 (to 568)
                        544     POP_TOP                         
                        546     POP_EXCEPT                      
                        548     LOAD_CONST                      6: False
                        550     NOP                             
                        552     NOP                             
                        554     NOP                             
                        556     JUMP_FORWARD                    23 (to 604)
                        564     POP_TOP                         
                        566     RETURN_CONST                    6: False
                        568     RERAISE                         0
                        570     COPY                            3
                        572     POP_EXCEPT                      
                        574     RERAISE                         1
                        576     PUSH_EXC_INFO                   
                        578     PUSH_NULL                       
                        580     LOAD_CONST                      4: '__pyarmor_exit_54537__'
                        582     NOP                             
                        584     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a&\x02\x00\x00\x00\x00\x00\x00'
                        586     CALL                            1
                        594     POP_TOP                         
                        596     RERAISE                         0
                        598     COPY                            3
                        600     POP_EXCEPT                      
                        602     RERAISE                         1
                        604     PUSH_NULL                       
                        606     LOAD_CONST                      4: '__pyarmor_exit_54537__'
                        608     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a&\x02\x00\x00\x00\x00\x00\x00'
                        610     BUILD_TUPLE                     1
                        612     CALL_FUNCTION_EX                0
                        614     POP_TOP                         
                        616     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_add_clicked
                    Qualified Name: NameTypeWidget.on_add_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'field_added'
                        'emit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54538__'
                        '__pyarmor_enter_54539__'
                        b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54540__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54539__'
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
                        28      LOAD_FAST                       0: self
                        30      LOAD_ATTR                       0: field_added
                        50      LOAD_ATTR                       3: emit
                        70      CALL                            0
                        78      POP_TOP                         
                        80      LOAD_CONST                      0: None
                        82      NOP                             
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    19 (to 128)
                        96      POP_TOP                         
                        98      RETURN_CONST                    0: None
                        100     PUSH_EXC_INFO                   
                        102     PUSH_NULL                       
                        104     LOAD_CONST                      4: '__pyarmor_exit_54540__'
                        106     NOP                             
                        108     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        110     CALL                            1
                        118     POP_TOP                         
                        120     RERAISE                         0
                        122     COPY                            3
                        124     POP_EXCEPT                      
                        126     RERAISE                         1
                        128     PUSH_NULL                       
                        130     LOAD_CONST                      4: '__pyarmor_exit_54540__'
                        132     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        134     BUILD_TUPLE                     1
                        136     CALL_FUNCTION_EX                0
                        138     POP_TOP                         
                        140     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_remove_clicked
                    Qualified Name: NameTypeWidget.on_remove_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'field_removed'
                        'emit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54541__'
                        '__pyarmor_enter_54542__'
                        b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54543__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54542__'
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
                        30      LOAD_ATTR                       0: field_removed
                        50      LOAD_ATTR                       3: emit
                        70      LOAD_FAST                       0: self
                        72      CALL                            1
                        80      POP_TOP                         
                        82      LOAD_CONST                      0: None
                        84      NOP                             
                        86      NOP                             
                        88      NOP                             
                        90      JUMP_FORWARD                    19 (to 130)
                        98      POP_TOP                         
                        100     RETURN_CONST                    0: None
                        102     PUSH_EXC_INFO                   
                        104     PUSH_NULL                       
                        106     LOAD_CONST                      4: '__pyarmor_exit_54543__'
                        108     NOP                             
                        110     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        112     CALL                            1
                        120     POP_TOP                         
                        122     RERAISE                         0
                        124     COPY                            3
                        126     POP_EXCEPT                      
                        128     RERAISE                         1
                        130     PUSH_NULL                       
                        132     LOAD_CONST                      4: '__pyarmor_exit_54543__'
                        134     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        136     BUILD_TUPLE                     1
                        138     CALL_FUNCTION_EX                0
                        140     POP_TOP                         
                        142     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: setEnabled
                    Qualified Name: NameTypeWidget.setEnabled
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'setEnabled'
                        'name_checkbox'
                        'accepted'
                        'type_checkbox'
                        'name_edit'
                        'accepted_name'
                        'type_edit'
                        'accepted_type'
                        'is_enum'
                        'size_checkbox'
                        'size_edit'
                        'accepted_size'
                        'add_button'
                        'remove_button'
                    [Locals+Names]
                        'self'
                        'enabled'
                        '__assert_armored__'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54544__'
                        '__pyarmor_enter_54545__'
                        b'<COAddr>\x03\x00\x00\x1c0\x03\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54546__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54545__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c0\x03\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_DEREF                      3: __class__
                        42      LOAD_FAST                       0: self
                        44      LOAD_SUPER_ATTR                 5: setEnabled
                        48      LOAD_FAST                       1: enabled
                        50      CALL                            1
                        58      POP_TOP                         
                        60      LOAD_FAST                       0: self
                        62      LOAD_ATTR                       4: name_checkbox
                        82      LOAD_ATTR                       3: setEnabled
                        102     LOAD_FAST                       1: enabled
                        104     COPY                            1
                        106     POP_JUMP_IF_FALSE               12 (to 132)
                        108     POP_TOP                         
                        110     LOAD_FAST                       0: self
                        112     LOAD_ATTR                       6: accepted
                        132     CALL                            1
                        140     POP_TOP                         
                        142     LOAD_FAST                       0: self
                        144     LOAD_ATTR                       8: type_checkbox
                        164     LOAD_ATTR                       3: setEnabled
                        184     LOAD_FAST                       1: enabled
                        186     COPY                            1
                        188     POP_JUMP_IF_FALSE               12 (to 214)
                        190     POP_TOP                         
                        192     LOAD_FAST                       0: self
                        194     LOAD_ATTR                       6: accepted
                        214     CALL                            1
                        222     POP_TOP                         
                        224     LOAD_FAST                       0: self
                        226     LOAD_ATTR                       10: name_edit
                        246     LOAD_ATTR                       3: setEnabled
                        266     LOAD_FAST                       1: enabled
                        268     COPY                            1
                        270     POP_JUMP_IF_FALSE               26 (to 324)
                        272     POP_TOP                         
                        274     LOAD_FAST                       0: self
                        276     LOAD_ATTR                       6: accepted
                        296     COPY                            1
                        298     POP_JUMP_IF_FALSE               12 (to 324)
                        300     POP_TOP                         
                        302     LOAD_FAST                       0: self
                        304     LOAD_ATTR                       12: accepted_name
                        324     CALL                            1
                        332     POP_TOP                         
                        334     LOAD_FAST                       0: self
                        336     LOAD_ATTR                       14: type_edit
                        356     LOAD_ATTR                       3: setEnabled
                        376     LOAD_FAST                       1: enabled
                        378     COPY                            1
                        380     POP_JUMP_IF_FALSE               26 (to 434)
                        382     POP_TOP                         
                        384     LOAD_FAST                       0: self
                        386     LOAD_ATTR                       6: accepted
                        406     COPY                            1
                        408     POP_JUMP_IF_FALSE               12 (to 434)
                        410     POP_TOP                         
                        412     LOAD_FAST                       0: self
                        414     LOAD_ATTR                       16: accepted_type
                        434     CALL                            1
                        442     POP_TOP                         
                        444     LOAD_FAST                       0: self
                        446     LOAD_ATTR                       18: is_enum
                        466     POP_JUMP_IF_FALSE               178 (to 824)
                        468     LOAD_FAST                       0: self
                        470     LOAD_ATTR                       20: size_checkbox
                        490     LOAD_ATTR                       3: setEnabled
                        510     LOAD_FAST                       1: enabled
                        512     COPY                            1
                        514     POP_JUMP_IF_FALSE               12 (to 540)
                        516     POP_TOP                         
                        518     LOAD_FAST                       0: self
                        520     LOAD_ATTR                       6: accepted
                        540     CALL                            1
                        548     POP_TOP                         
                        550     LOAD_FAST                       0: self
                        552     LOAD_ATTR                       22: size_edit
                        572     LOAD_ATTR                       3: setEnabled
                        592     LOAD_FAST                       1: enabled
                        594     COPY                            1
                        596     POP_JUMP_IF_FALSE               26 (to 650)
                        598     POP_TOP                         
                        600     LOAD_FAST                       0: self
                        602     LOAD_ATTR                       6: accepted
                        622     COPY                            1
                        624     POP_JUMP_IF_FALSE               12 (to 650)
                        626     POP_TOP                         
                        628     LOAD_FAST                       0: self
                        630     LOAD_ATTR                       24: accepted_size
                        650     CALL                            1
                        658     POP_TOP                         
                        660     LOAD_FAST                       0: self
                        662     LOAD_ATTR                       26: add_button
                        682     LOAD_ATTR                       3: setEnabled
                        702     LOAD_FAST                       1: enabled
                        704     COPY                            1
                        706     POP_JUMP_IF_FALSE               12 (to 732)
                        708     POP_TOP                         
                        710     LOAD_FAST                       0: self
                        712     LOAD_ATTR                       6: accepted
                        732     CALL                            1
                        740     POP_TOP                         
                        742     LOAD_FAST                       0: self
                        744     LOAD_ATTR                       28: remove_button
                        764     LOAD_ATTR                       3: setEnabled
                        784     LOAD_FAST                       1: enabled
                        786     COPY                            1
                        788     POP_JUMP_IF_FALSE               12 (to 814)
                        790     POP_TOP                         
                        792     LOAD_FAST                       0: self
                        794     LOAD_ATTR                       6: accepted
                        814     CALL                            1
                        822     POP_TOP                         
                        824     LOAD_CONST                      0: None
                        826     NOP                             
                        828     NOP                             
                        830     NOP                             
                        832     JUMP_FORWARD                    19 (to 872)
                        840     POP_TOP                         
                        842     RETURN_CONST                    0: None
                        844     PUSH_EXC_INFO                   
                        846     PUSH_NULL                       
                        848     LOAD_CONST                      4: '__pyarmor_exit_54546__'
                        850     NOP                             
                        852     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c0\x03\x00\x00\x00\x00\x00\x00'
                        854     CALL                            1
                        862     POP_TOP                         
                        864     RERAISE                         0
                        866     COPY                            3
                        868     POP_EXCEPT                      
                        870     RERAISE                         1
                        872     PUSH_NULL                       
                        874     LOAD_CONST                      4: '__pyarmor_exit_54546__'
                        876     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c0\x03\x00\x00\x00\x00\x00\x00'
                        878     BUILD_TUPLE                     1
                        880     CALL_FUNCTION_EX                0
                        882     POP_TOP                         
                        884     RETURN_VALUE                    
                '__pyarmor_exit_54516__'
                (
                    ''
                    ''
                    ''
                    False
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'NameTypeWidget'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54515__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\xa8\x00\x00\x00\x00\x00\x00\x00'
                20      BUILD_TUPLE                     1
                22      CALL_FUNCTION_EX                0
                24      POP_TOP                         
                26      RESUME                          0
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      PUSH_NULL                       
                40      LOAD_NAME                       4: QtCore
                42      LOAD_ATTR                       10: pyqtSignal
                62      CALL                            0
                70      STORE_NAME                      6: field_added
                72      PUSH_NULL                       
                74      LOAD_NAME                       4: QtCore
                76      LOAD_ATTR                       10: pyqtSignal
                96      LOAD_NAME                       7: QWidget
                98      CALL                            1
                106     STORE_NAME                      8: field_removed
                108     LOAD_CONST                      15: ('', '', '', False)
                110     LOAD_CLOSURE                    0: __class__
                112     BUILD_TUPLE                     1
                114     LOAD_CONST                      4: <CODE> __init__
                116     MAKE_FUNCTION                   9
                118     STORE_NAME                      9: __init__
                120     LOAD_CONST                      5: <CODE> accepted_state_change
                122     MAKE_FUNCTION                   0
                124     STORE_NAME                      10: accepted_state_change
                126     LOAD_CONST                      6: <CODE> name_state_change
                128     MAKE_FUNCTION                   0
                130     STORE_NAME                      11: name_state_change
                132     LOAD_CONST                      7: <CODE> type_state_change
                134     MAKE_FUNCTION                   0
                136     STORE_NAME                      12: type_state_change
                138     LOAD_CONST                      8: <CODE> size_state_change
                140     MAKE_FUNCTION                   0
                142     STORE_NAME                      13: size_state_change
                144     LOAD_CONST                      9: <CODE> get_content
                146     MAKE_FUNCTION                   0
                148     STORE_NAME                      14: get_content
                150     LOAD_CONST                      10: <CODE> validate
                152     MAKE_FUNCTION                   0
                154     STORE_NAME                      15: validate
                156     LOAD_CONST                      11: <CODE> on_add_clicked
                158     MAKE_FUNCTION                   0
                160     STORE_NAME                      16: on_add_clicked
                162     LOAD_CONST                      12: <CODE> on_remove_clicked
                164     MAKE_FUNCTION                   0
                166     STORE_NAME                      17: on_remove_clicked
                168     LOAD_CLOSURE                    0: __class__
                170     BUILD_TUPLE                     1
                172     LOAD_CONST                      13: <CODE> setEnabled
                174     MAKE_FUNCTION                   8
                176     STORE_NAME                      18: setEnabled
                178     LOAD_CLOSURE                    0: __class__
                180     COPY                            1
                182     STORE_NAME                      19: __classcell__
                184     NOP                             
                186     NOP                             
                188     NOP                             
                190     JUMP_FORWARD                    20 (to 232)
                194     POP_TOP                         
                196     LOAD_CLOSURE                    0: __class__
                198     COPY                            1
                200     STORE_NAME                      19: __classcell__
                202     RETURN_VALUE                    
                204     PUSH_EXC_INFO                   
                206     PUSH_NULL                       
                208     LOAD_CONST                      14: '__pyarmor_exit_54516__'
                210     NOP                             
                212     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\xa8\x00\x00\x00\x00\x00\x00\x00'
                214     CALL                            1
                222     POP_TOP                         
                224     RERAISE                         0
                226     COPY                            3
                228     POP_EXCEPT                      
                230     RERAISE                         1
                232     PUSH_NULL                       
                234     LOAD_CONST                      14: '__pyarmor_exit_54516__'
                236     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\xa8\x00\x00\x00\x00\x00\x00\x00'
                238     BUILD_TUPLE                     1
                240     CALL_FUNCTION_EX                0
                242     POP_TOP                         
                244     RETURN_VALUE                    
        'NameTypeWidget'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: StructFieldWidget
            Qualified Name: StructFieldWidget
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
                'QtCore'
                'pyqtSignal'
                'field_added'
                'QWidget'
                'field_removed'
                '__init__'
                'accepted_state_change'
                'get_content'
                'validate'
                'on_add_clicked'
                'on_remove_clicked'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'StructFieldWidget'
                '__pyarmor_assert_54547__'
                '__pyarmor_enter_54548__'
                b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: StructFieldWidget.__init__
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'StructFieldWidget'
                        '__init__'
                        'accepted'
                        'QtWidgets'
                        'QHBoxLayout'
                        'setAlignment'
                        'QtCore'
                        'Qt'
                        'AlignLeft'
                        'AlignVCenter'
                        'setSpacing'
                        'QCheckBox'
                        'checkbox'
                        'setCheckState'
                        'Checked'
                        'stateChanged'
                        'connect'
                        'accepted_state_change'
                        'QLineEdit'
                        'type_edit'
                        'setMinimumWidth'
                        'setPlaceholderText'
                        'name_edit'
                        'str'
                        'size_edit'
                        'QPushButton'
                        'add_button'
                        'setMaximumWidth'
                        'clicked'
                        'on_add_clicked'
                        'remove_button'
                        'on_remove_clicked'
                        'addWidget'
                        'addStretch'
                        'setLayout'
                    [Locals+Names]
                        'self'
                        'type_str'
                        'name'
                        'size'
                        '__assert_armored__'
                        '_var_var_1'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54550__'
                        '__pyarmor_enter_54551__'
                        b'<COAddr>\x01\x00\x00\x1c\x18\x07\x00\x00\x00\x00\x00\x00'
                        True
                        10
                        150
                        'Type'
                        'Name'
                        80
                        'Size'
                        '+'
                        30
                        '-'
                        '__pyarmor_exit_54552__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54551__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x18\x07\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: StructFieldWidget
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_CONST                      4: True
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: accepted
                        80      LOAD_GLOBAL                     9: NULL + QtWidgets
                        90      LOAD_ATTR                       10: QHBoxLayout
                        110     CALL                            0
                        118     STORE_FAST                      5: _var_var_1
                        120     LOAD_FAST                       5: _var_var_1
                        122     LOAD_ATTR                       13: setAlignment
                        142     LOAD_GLOBAL                     14: QtCore
                        152     LOAD_ATTR                       16: Qt
                        172     LOAD_ATTR                       18: AlignLeft
                        192     LOAD_GLOBAL                     14: QtCore
                        202     LOAD_ATTR                       16: Qt
                        222     LOAD_ATTR                       20: AlignVCenter
                        242     BINARY_OP                       7 (|)
                        246     CALL                            1
                        254     POP_TOP                         
                        256     LOAD_FAST                       5: _var_var_1
                        258     LOAD_ATTR                       23: setSpacing
                        278     LOAD_CONST                      5: 10
                        280     CALL                            1
                        288     POP_TOP                         
                        290     LOAD_GLOBAL                     9: NULL + QtWidgets
                        300     LOAD_ATTR                       24: QCheckBox
                        320     CALL                            0
                        328     LOAD_FAST                       0: self
                        330     STORE_ATTR                      13: checkbox
                        340     LOAD_FAST                       0: self
                        342     LOAD_ATTR                       26: checkbox
                        362     LOAD_ATTR                       29: setCheckState
                        382     LOAD_GLOBAL                     14: QtCore
                        392     LOAD_ATTR                       16: Qt
                        412     LOAD_ATTR                       30: Checked
                        432     CALL                            1
                        440     POP_TOP                         
                        442     LOAD_FAST                       0: self
                        444     LOAD_ATTR                       26: checkbox
                        464     LOAD_ATTR                       32: stateChanged
                        484     LOAD_ATTR                       35: connect
                        504     LOAD_FAST                       0: self
                        506     LOAD_ATTR                       36: accepted_state_change
                        526     CALL                            1
                        534     POP_TOP                         
                        536     LOAD_GLOBAL                     9: NULL + QtWidgets
                        546     LOAD_ATTR                       38: QLineEdit
                        566     LOAD_FAST                       1: type_str
                        568     CALL                            1
                        576     LOAD_FAST                       0: self
                        578     STORE_ATTR                      20: type_edit
                        588     LOAD_FAST                       0: self
                        590     LOAD_ATTR                       40: type_edit
                        610     LOAD_ATTR                       43: setMinimumWidth
                        630     LOAD_CONST                      6: 150
                        632     CALL                            1
                        640     POP_TOP                         
                        642     LOAD_FAST                       0: self
                        644     LOAD_ATTR                       40: type_edit
                        664     LOAD_ATTR                       45: setPlaceholderText
                        684     LOAD_CONST                      7: 'Type'
                        686     CALL                            1
                        694     POP_TOP                         
                        696     LOAD_GLOBAL                     9: NULL + QtWidgets
                        706     LOAD_ATTR                       38: QLineEdit
                        726     LOAD_FAST                       2: name
                        728     CALL                            1
                        736     LOAD_FAST                       0: self
                        738     STORE_ATTR                      23: name_edit
                        748     LOAD_FAST                       0: self
                        750     LOAD_ATTR                       46: name_edit
                        770     LOAD_ATTR                       43: setMinimumWidth
                        790     LOAD_CONST                      6: 150
                        792     CALL                            1
                        800     POP_TOP                         
                        802     LOAD_FAST                       0: self
                        804     LOAD_ATTR                       46: name_edit
                        824     LOAD_ATTR                       45: setPlaceholderText
                        844     LOAD_CONST                      8: 'Name'
                        846     CALL                            1
                        854     POP_TOP                         
                        856     LOAD_GLOBAL                     9: NULL + QtWidgets
                        866     LOAD_ATTR                       38: QLineEdit
                        886     LOAD_GLOBAL                     49: NULL + str
                        896     LOAD_FAST                       3: size
                        898     CALL                            1
                        906     CALL                            1
                        914     LOAD_FAST                       0: self
                        916     STORE_ATTR                      25: size_edit
                        926     LOAD_FAST                       0: self
                        928     LOAD_ATTR                       50: size_edit
                        948     LOAD_ATTR                       43: setMinimumWidth
                        968     LOAD_CONST                      9: 80
                        970     CALL                            1
                        978     POP_TOP                         
                        980     LOAD_FAST                       0: self
                        982     LOAD_ATTR                       50: size_edit
                        1002    LOAD_ATTR                       45: setPlaceholderText
                        1022    LOAD_CONST                      10: 'Size'
                        1024    CALL                            1
                        1032    POP_TOP                         
                        1034    LOAD_GLOBAL                     9: NULL + QtWidgets
                        1044    LOAD_ATTR                       52: QPushButton
                        1064    LOAD_CONST                      11: '+'
                        1066    CALL                            1
                        1074    LOAD_FAST                       0: self
                        1076    STORE_ATTR                      27: add_button
                        1086    LOAD_FAST                       0: self
                        1088    LOAD_ATTR                       54: add_button
                        1108    LOAD_ATTR                       57: setMaximumWidth
                        1128    LOAD_CONST                      12: 30
                        1130    CALL                            1
                        1138    POP_TOP                         
                        1140    LOAD_FAST                       0: self
                        1142    LOAD_ATTR                       54: add_button
                        1162    LOAD_ATTR                       58: clicked
                        1182    LOAD_ATTR                       35: connect
                        1202    LOAD_FAST                       0: self
                        1204    LOAD_ATTR                       60: on_add_clicked
                        1224    CALL                            1
                        1232    POP_TOP                         
                        1234    LOAD_GLOBAL                     9: NULL + QtWidgets
                        1244    LOAD_ATTR                       52: QPushButton
                        1264    LOAD_CONST                      13: '-'
                        1266    CALL                            1
                        1274    LOAD_FAST                       0: self
                        1276    STORE_ATTR                      31: remove_button
                        1286    LOAD_FAST                       0: self
                        1288    LOAD_ATTR                       62: remove_button
                        1308    LOAD_ATTR                       57: setMaximumWidth
                        1328    LOAD_CONST                      12: 30
                        1330    CALL                            1
                        1338    POP_TOP                         
                        1340    LOAD_FAST                       0: self
                        1342    LOAD_ATTR                       62: remove_button
                        1362    LOAD_ATTR                       58: clicked
                        1382    LOAD_ATTR                       35: connect
                        1402    LOAD_FAST                       0: self
                        1404    LOAD_ATTR                       64: on_remove_clicked
                        1424    CALL                            1
                        1432    POP_TOP                         
                        1434    LOAD_FAST                       5: _var_var_1
                        1436    LOAD_ATTR                       67: addWidget
                        1456    LOAD_FAST                       0: self
                        1458    LOAD_ATTR                       26: checkbox
                        1478    CALL                            1
                        1486    POP_TOP                         
                        1488    LOAD_FAST                       5: _var_var_1
                        1490    LOAD_ATTR                       67: addWidget
                        1510    LOAD_FAST                       0: self
                        1512    LOAD_ATTR                       40: type_edit
                        1532    CALL                            1
                        1540    POP_TOP                         
                        1542    LOAD_FAST                       5: _var_var_1
                        1544    LOAD_ATTR                       67: addWidget
                        1564    LOAD_FAST                       0: self
                        1566    LOAD_ATTR                       46: name_edit
                        1586    CALL                            1
                        1594    POP_TOP                         
                        1596    LOAD_FAST                       5: _var_var_1
                        1598    LOAD_ATTR                       67: addWidget
                        1618    LOAD_FAST                       0: self
                        1620    LOAD_ATTR                       50: size_edit
                        1640    CALL                            1
                        1648    POP_TOP                         
                        1650    LOAD_FAST                       5: _var_var_1
                        1652    LOAD_ATTR                       67: addWidget
                        1672    LOAD_FAST                       0: self
                        1674    LOAD_ATTR                       54: add_button
                        1694    CALL                            1
                        1702    POP_TOP                         
                        1704    LOAD_FAST                       5: _var_var_1
                        1706    LOAD_ATTR                       67: addWidget
                        1726    LOAD_FAST                       0: self
                        1728    LOAD_ATTR                       62: remove_button
                        1748    CALL                            1
                        1756    POP_TOP                         
                        1758    LOAD_FAST                       5: _var_var_1
                        1760    LOAD_ATTR                       69: addStretch
                        1780    CALL                            0
                        1788    POP_TOP                         
                        1790    LOAD_FAST                       0: self
                        1792    LOAD_ATTR                       71: setLayout
                        1812    LOAD_FAST                       5: _var_var_1
                        1814    CALL                            1
                        1822    POP_TOP                         
                        1824    LOAD_CONST                      0: None
                        1826    NOP                             
                        1828    NOP                             
                        1830    NOP                             
                        1832    JUMP_FORWARD                    19 (to 1872)
                        1840    POP_TOP                         
                        1842    RETURN_CONST                    0: None
                        1844    PUSH_EXC_INFO                   
                        1846    PUSH_NULL                       
                        1848    LOAD_CONST                      14: '__pyarmor_exit_54552__'
                        1850    NOP                             
                        1852    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x18\x07\x00\x00\x00\x00\x00\x00'
                        1854    CALL                            1
                        1862    POP_TOP                         
                        1864    RERAISE                         0
                        1866    COPY                            3
                        1868    POP_EXCEPT                      
                        1870    RERAISE                         1
                        1872    PUSH_NULL                       
                        1874    LOAD_CONST                      14: '__pyarmor_exit_54552__'
                        1876    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x18\x07\x00\x00\x00\x00\x00\x00'
                        1878    BUILD_TUPLE                     1
                        1880    CALL_FUNCTION_EX                0
                        1882    POP_TOP                         
                        1884    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: accepted_state_change
                    Qualified Name: StructFieldWidget.accepted_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted'
                        'type_edit'
                        'setEnabled'
                        'name_edit'
                        'size_edit'
                        'add_button'
                        'remove_button'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54553__'
                        '__pyarmor_enter_54554__'
                        b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54555__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54554__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: type_edit
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       6: accepted
                        160     CALL                            1
                        168     POP_TOP                         
                        170     LOAD_FAST                       0: self
                        172     LOAD_ATTR                       12: name_edit
                        192     LOAD_ATTR                       11: setEnabled
                        212     LOAD_FAST                       0: self
                        214     LOAD_ATTR                       6: accepted
                        234     CALL                            1
                        242     POP_TOP                         
                        244     LOAD_FAST                       0: self
                        246     LOAD_ATTR                       14: size_edit
                        266     LOAD_ATTR                       11: setEnabled
                        286     LOAD_FAST                       0: self
                        288     LOAD_ATTR                       6: accepted
                        308     CALL                            1
                        316     POP_TOP                         
                        318     LOAD_FAST                       0: self
                        320     LOAD_ATTR                       16: add_button
                        340     LOAD_ATTR                       11: setEnabled
                        360     LOAD_FAST                       0: self
                        362     LOAD_ATTR                       6: accepted
                        382     CALL                            1
                        390     POP_TOP                         
                        392     LOAD_FAST                       0: self
                        394     LOAD_ATTR                       18: remove_button
                        414     LOAD_ATTR                       11: setEnabled
                        434     LOAD_FAST                       0: self
                        436     LOAD_ATTR                       6: accepted
                        456     CALL                            1
                        464     POP_TOP                         
                        466     LOAD_CONST                      0: None
                        468     NOP                             
                        470     NOP                             
                        472     NOP                             
                        474     JUMP_FORWARD                    19 (to 514)
                        482     POP_TOP                         
                        484     RETURN_CONST                    0: None
                        486     PUSH_EXC_INFO                   
                        488     PUSH_NULL                       
                        490     LOAD_CONST                      4: '__pyarmor_exit_54555__'
                        492     NOP                             
                        494     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        496     CALL                            1
                        504     POP_TOP                         
                        506     RERAISE                         0
                        508     COPY                            3
                        510     POP_EXCEPT                      
                        512     RERAISE                         1
                        514     PUSH_NULL                       
                        516     LOAD_CONST                      4: '__pyarmor_exit_54555__'
                        518     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        520     BUILD_TUPLE                     1
                        522     CALL_FUNCTION_EX                0
                        524     POP_TOP                         
                        526     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: get_content
                    Qualified Name: StructFieldWidget.get_content
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'accepted'
                        'type_edit'
                        'text'
                        'name_edit'
                        'int'
                        'size_edit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54556__'
                        '__pyarmor_enter_54557__'
                        b'<COAddr>\x03\x00\x00\x1a\xee\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54558__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54557__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xee\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: accepted
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      0: None
                        56      NOP                             
                        58      NOP                             
                        60      NOP                             
                        62      JUMP_FORWARD                    114 (to 292)
                        70      POP_TOP                         
                        72      RETURN_CONST                    0: None
                        74      LOAD_FAST                       0: self
                        76      LOAD_ATTR                       2: type_edit
                        96      LOAD_ATTR                       5: text
                        116     CALL                            0
                        124     LOAD_FAST                       0: self
                        126     LOAD_ATTR                       6: name_edit
                        146     LOAD_ATTR                       5: text
                        166     CALL                            0
                        174     LOAD_GLOBAL                     9: NULL + int
                        184     LOAD_FAST                       0: self
                        186     LOAD_ATTR                       10: size_edit
                        206     LOAD_ATTR                       5: text
                        226     CALL                            0
                        234     CALL                            1
                        242     BUILD_LIST                      3
                        244     NOP                             
                        246     NOP                             
                        248     NOP                             
                        250     JUMP_FORWARD                    20 (to 292)
                        252     CALL                            1
                        260     POP_TOP                         
                        262     RETURN_VALUE                    
                        264     PUSH_EXC_INFO                   
                        266     PUSH_NULL                       
                        268     LOAD_CONST                      4: '__pyarmor_exit_54558__'
                        270     NOP                             
                        272     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xee\x00\x00\x00\x00\x00\x00\x00'
                        274     CALL                            1
                        282     POP_TOP                         
                        284     RERAISE                         0
                        286     COPY                            3
                        288     POP_EXCEPT                      
                        290     RERAISE                         1
                        292     PUSH_NULL                       
                        294     LOAD_CONST                      4: '__pyarmor_exit_54558__'
                        296     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xee\x00\x00\x00\x00\x00\x00\x00'
                        298     BUILD_TUPLE                     1
                        300     CALL_FUNCTION_EX                0
                        302     POP_TOP                         
                        304     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: validate
                    Qualified Name: StructFieldWidget.validate
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'accepted'
                        'type_edit'
                        'text'
                        'strip'
                        'name_edit'
                        'size_edit'
                        'int'
                        'ValueError'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_16'
                        '_var_var_15'
                    [Constants]
                        None
                        '__pyarmor_assert_54559__'
                        '__pyarmor_enter_54560__'
                        b'<COAddr>\x01\x00\x00\x1a\xe4\x01\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54561__'
                        True
                        False
                        0
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54560__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x01\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: accepted
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      5: True
                        56      NOP                             
                        58      NOP                             
                        60      NOP                             
                        62      JUMP_FORWARD                    237 (to 538)
                        70      POP_TOP                         
                        72      RETURN_CONST                    5: True
                        74      LOAD_FAST                       0: self
                        76      LOAD_ATTR                       2: type_edit
                        96      LOAD_ATTR                       5: text
                        116     CALL                            0
                        124     LOAD_ATTR                       7: strip
                        144     CALL                            0
                        152     POP_JUMP_IF_TRUE                11 (to 176)
                        154     NOP                             
                        156     LOAD_CONST                      6: False
                        158     NOP                             
                        160     NOP                             
                        162     NOP                             
                        164     JUMP_FORWARD                    186 (to 538)
                        172     POP_TOP                         
                        174     RETURN_CONST                    6: False
                        176     LOAD_FAST                       0: self
                        178     LOAD_ATTR                       8: name_edit
                        198     LOAD_ATTR                       5: text
                        218     CALL                            0
                        226     LOAD_ATTR                       7: strip
                        246     CALL                            0
                        254     POP_JUMP_IF_TRUE                11 (to 278)
                        256     NOP                             
                        258     LOAD_CONST                      6: False
                        260     NOP                             
                        262     NOP                             
                        264     NOP                             
                        266     JUMP_FORWARD                    135 (to 538)
                        274     POP_TOP                         
                        276     RETURN_CONST                    6: False
                        278     NOP                             
                        280     LOAD_FAST                       0: self
                        282     LOAD_ATTR                       10: size_edit
                        302     LOAD_ATTR                       5: text
                        322     CALL                            0
                        330     LOAD_ATTR                       7: strip
                        350     CALL                            0
                        358     STORE_FAST                      2: _var_var_16
                        360     LOAD_FAST                       2: _var_var_16
                        362     POP_JUMP_IF_TRUE                11 (to 386)
                        364     NOP                             
                        366     LOAD_CONST                      6: False
                        368     NOP                             
                        370     NOP                             
                        372     NOP                             
                        374     JUMP_FORWARD                    81 (to 538)
                        382     POP_TOP                         
                        384     RETURN_CONST                    6: False
                        386     LOAD_GLOBAL                     13: NULL + int
                        396     LOAD_FAST                       2: _var_var_16
                        398     CALL                            1
                        406     STORE_FAST                      3: _var_var_15
                        408     LOAD_FAST                       3: _var_var_15
                        410     LOAD_CONST                      7: 0
                        412     COMPARE_OP                      26 (<=)
                        416     POP_JUMP_IF_FALSE               11 (to 440)
                        418     NOP                             
                        420     LOAD_CONST                      6: False
                        422     NOP                             
                        424     NOP                             
                        426     NOP                             
                        428     JUMP_FORWARD                    54 (to 538)
                        436     POP_TOP                         
                        438     RETURN_CONST                    6: False
                        440     NOP                             
                        442     LOAD_CONST                      5: True
                        444     NOP                             
                        446     NOP                             
                        448     NOP                             
                        450     JUMP_FORWARD                    43 (to 538)
                        458     POP_TOP                         
                        460     RETURN_CONST                    5: True
                        462     PUSH_EXC_INFO                   
                        464     LOAD_GLOBAL                     14: ValueError
                        474     CHECK_EXC_MATCH                 
                        476     POP_JUMP_IF_FALSE               12 (to 502)
                        478     POP_TOP                         
                        480     POP_EXCEPT                      
                        482     LOAD_CONST                      6: False
                        484     NOP                             
                        486     NOP                             
                        488     NOP                             
                        490     JUMP_FORWARD                    23 (to 538)
                        498     POP_TOP                         
                        500     RETURN_CONST                    6: False
                        502     RERAISE                         0
                        504     COPY                            3
                        506     POP_EXCEPT                      
                        508     RERAISE                         1
                        510     PUSH_EXC_INFO                   
                        512     PUSH_NULL                       
                        514     LOAD_CONST                      4: '__pyarmor_exit_54561__'
                        516     NOP                             
                        518     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x01\x00\x00\x00\x00\x00\x00'
                        520     CALL                            1
                        528     POP_TOP                         
                        530     RERAISE                         0
                        532     COPY                            3
                        534     POP_EXCEPT                      
                        536     RERAISE                         1
                        538     PUSH_NULL                       
                        540     LOAD_CONST                      4: '__pyarmor_exit_54561__'
                        542     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x01\x00\x00\x00\x00\x00\x00'
                        544     BUILD_TUPLE                     1
                        546     CALL_FUNCTION_EX                0
                        548     POP_TOP                         
                        550     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_add_clicked
                    Qualified Name: StructFieldWidget.on_add_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'field_added'
                        'emit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54562__'
                        '__pyarmor_enter_54563__'
                        b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54564__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54563__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: field_added
                        50      LOAD_ATTR                       3: emit
                        70      CALL                            0
                        78      POP_TOP                         
                        80      LOAD_CONST                      0: None
                        82      NOP                             
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    19 (to 128)
                        96      POP_TOP                         
                        98      RETURN_CONST                    0: None
                        100     PUSH_EXC_INFO                   
                        102     PUSH_NULL                       
                        104     LOAD_CONST                      4: '__pyarmor_exit_54564__'
                        106     NOP                             
                        108     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        110     CALL                            1
                        118     POP_TOP                         
                        120     RERAISE                         0
                        122     COPY                            3
                        124     POP_EXCEPT                      
                        126     RERAISE                         1
                        128     PUSH_NULL                       
                        130     LOAD_CONST                      4: '__pyarmor_exit_54564__'
                        132     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        134     BUILD_TUPLE                     1
                        136     CALL_FUNCTION_EX                0
                        138     POP_TOP                         
                        140     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_remove_clicked
                    Qualified Name: StructFieldWidget.on_remove_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'field_removed'
                        'emit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54565__'
                        '__pyarmor_enter_54566__'
                        b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54567__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54566__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: field_removed
                        50      LOAD_ATTR                       3: emit
                        70      LOAD_FAST                       0: self
                        72      CALL                            1
                        80      POP_TOP                         
                        82      LOAD_CONST                      0: None
                        84      NOP                             
                        86      NOP                             
                        88      NOP                             
                        90      JUMP_FORWARD                    19 (to 130)
                        98      POP_TOP                         
                        100     RETURN_CONST                    0: None
                        102     PUSH_EXC_INFO                   
                        104     PUSH_NULL                       
                        106     LOAD_CONST                      4: '__pyarmor_exit_54567__'
                        108     NOP                             
                        110     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        112     CALL                            1
                        120     POP_TOP                         
                        122     RERAISE                         0
                        124     COPY                            3
                        126     POP_EXCEPT                      
                        128     RERAISE                         1
                        130     PUSH_NULL                       
                        132     LOAD_CONST                      4: '__pyarmor_exit_54567__'
                        134     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        136     BUILD_TUPLE                     1
                        138     CALL_FUNCTION_EX                0
                        140     POP_TOP                         
                        142     RETURN_VALUE                    
                '__pyarmor_exit_54549__'
                (
                    ''
                    ''
                    ''
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'StructFieldWidget'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54548__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                20      BUILD_TUPLE                     1
                22      CALL_FUNCTION_EX                0
                24      POP_TOP                         
                26      RESUME                          0
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      PUSH_NULL                       
                40      LOAD_NAME                       4: QtCore
                42      LOAD_ATTR                       10: pyqtSignal
                62      CALL                            0
                70      STORE_NAME                      6: field_added
                72      PUSH_NULL                       
                74      LOAD_NAME                       4: QtCore
                76      LOAD_ATTR                       10: pyqtSignal
                96      LOAD_NAME                       7: QWidget
                98      CALL                            1
                106     STORE_NAME                      8: field_removed
                108     LOAD_CONST                      11: ('', '', '')
                110     LOAD_CLOSURE                    0: __class__
                112     BUILD_TUPLE                     1
                114     LOAD_CONST                      4: <CODE> __init__
                116     MAKE_FUNCTION                   9
                118     STORE_NAME                      9: __init__
                120     LOAD_CONST                      5: <CODE> accepted_state_change
                122     MAKE_FUNCTION                   0
                124     STORE_NAME                      10: accepted_state_change
                126     LOAD_CONST                      6: <CODE> get_content
                128     MAKE_FUNCTION                   0
                130     STORE_NAME                      11: get_content
                132     LOAD_CONST                      7: <CODE> validate
                134     MAKE_FUNCTION                   0
                136     STORE_NAME                      12: validate
                138     LOAD_CONST                      8: <CODE> on_add_clicked
                140     MAKE_FUNCTION                   0
                142     STORE_NAME                      13: on_add_clicked
                144     LOAD_CONST                      9: <CODE> on_remove_clicked
                146     MAKE_FUNCTION                   0
                148     STORE_NAME                      14: on_remove_clicked
                150     LOAD_CLOSURE                    0: __class__
                152     COPY                            1
                154     STORE_NAME                      15: __classcell__
                156     NOP                             
                158     NOP                             
                160     NOP                             
                162     JUMP_FORWARD                    20 (to 204)
                166     POP_TOP                         
                168     LOAD_CLOSURE                    0: __class__
                170     COPY                            1
                172     STORE_NAME                      15: __classcell__
                174     RETURN_VALUE                    
                176     PUSH_EXC_INFO                   
                178     PUSH_NULL                       
                180     LOAD_CONST                      10: '__pyarmor_exit_54549__'
                182     NOP                             
                184     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                186     CALL                            1
                194     POP_TOP                         
                196     RERAISE                         0
                198     COPY                            3
                200     POP_EXCEPT                      
                202     RERAISE                         1
                204     PUSH_NULL                       
                206     LOAD_CONST                      10: '__pyarmor_exit_54549__'
                208     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                210     BUILD_TUPLE                     1
                212     CALL_FUNCTION_EX                0
                214     POP_TOP                         
                216     RETURN_VALUE                    
        'StructFieldWidget'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: EnumFieldWidget
            Qualified Name: EnumFieldWidget
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
                'QtCore'
                'pyqtSignal'
                'field_added'
                'QWidget'
                'field_removed'
                '__init__'
                'accepted_state_change'
                'get_content'
                'validate'
                'on_add_clicked'
                'on_remove_clicked'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'EnumFieldWidget'
                '__pyarmor_assert_54568__'
                '__pyarmor_enter_54569__'
                b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: EnumFieldWidget.__init__
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'EnumFieldWidget'
                        '__init__'
                        'accepted'
                        'QtWidgets'
                        'QHBoxLayout'
                        'setAlignment'
                        'QtCore'
                        'Qt'
                        'AlignLeft'
                        'AlignVCenter'
                        'setSpacing'
                        'QCheckBox'
                        'checkbox'
                        'setCheckState'
                        'Checked'
                        'stateChanged'
                        'connect'
                        'accepted_state_change'
                        'QLineEdit'
                        'name_edit'
                        'setMinimumWidth'
                        'setPlaceholderText'
                        'str'
                        'value_edit'
                        'size_edit'
                        'QPushButton'
                        'add_button'
                        'setMaximumWidth'
                        'clicked'
                        'on_add_clicked'
                        'remove_button'
                        'on_remove_clicked'
                        'addWidget'
                        'addStretch'
                        'setLayout'
                    [Locals+Names]
                        'self'
                        'name'
                        'value'
                        'size'
                        '__assert_armored__'
                        '_var_var_1'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54571__'
                        '__pyarmor_enter_54572__'
                        b'<COAddr>\x01\x00\x00\x1c*\x07\x00\x00\x00\x00\x00\x00'
                        True
                        10
                        200
                        'Name'
                        'Value'
                        80
                        'Size'
                        '+'
                        30
                        '-'
                        '__pyarmor_exit_54573__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54572__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c*\x07\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: EnumFieldWidget
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_CONST                      4: True
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: accepted
                        80      LOAD_GLOBAL                     9: NULL + QtWidgets
                        90      LOAD_ATTR                       10: QHBoxLayout
                        110     CALL                            0
                        118     STORE_FAST                      5: _var_var_1
                        120     LOAD_FAST                       5: _var_var_1
                        122     LOAD_ATTR                       13: setAlignment
                        142     LOAD_GLOBAL                     14: QtCore
                        152     LOAD_ATTR                       16: Qt
                        172     LOAD_ATTR                       18: AlignLeft
                        192     LOAD_GLOBAL                     14: QtCore
                        202     LOAD_ATTR                       16: Qt
                        222     LOAD_ATTR                       20: AlignVCenter
                        242     BINARY_OP                       7 (|)
                        246     CALL                            1
                        254     POP_TOP                         
                        256     LOAD_FAST                       5: _var_var_1
                        258     LOAD_ATTR                       23: setSpacing
                        278     LOAD_CONST                      5: 10
                        280     CALL                            1
                        288     POP_TOP                         
                        290     LOAD_GLOBAL                     9: NULL + QtWidgets
                        300     LOAD_ATTR                       24: QCheckBox
                        320     CALL                            0
                        328     LOAD_FAST                       0: self
                        330     STORE_ATTR                      13: checkbox
                        340     LOAD_FAST                       0: self
                        342     LOAD_ATTR                       26: checkbox
                        362     LOAD_ATTR                       29: setCheckState
                        382     LOAD_GLOBAL                     14: QtCore
                        392     LOAD_ATTR                       16: Qt
                        412     LOAD_ATTR                       30: Checked
                        432     CALL                            1
                        440     POP_TOP                         
                        442     LOAD_FAST                       0: self
                        444     LOAD_ATTR                       26: checkbox
                        464     LOAD_ATTR                       32: stateChanged
                        484     LOAD_ATTR                       35: connect
                        504     LOAD_FAST                       0: self
                        506     LOAD_ATTR                       36: accepted_state_change
                        526     CALL                            1
                        534     POP_TOP                         
                        536     LOAD_GLOBAL                     9: NULL + QtWidgets
                        546     LOAD_ATTR                       38: QLineEdit
                        566     LOAD_FAST                       1: name
                        568     CALL                            1
                        576     LOAD_FAST                       0: self
                        578     STORE_ATTR                      20: name_edit
                        588     LOAD_FAST                       0: self
                        590     LOAD_ATTR                       40: name_edit
                        610     LOAD_ATTR                       43: setMinimumWidth
                        630     LOAD_CONST                      6: 200
                        632     CALL                            1
                        640     POP_TOP                         
                        642     LOAD_FAST                       0: self
                        644     LOAD_ATTR                       40: name_edit
                        664     LOAD_ATTR                       45: setPlaceholderText
                        684     LOAD_CONST                      7: 'Name'
                        686     CALL                            1
                        694     POP_TOP                         
                        696     LOAD_GLOBAL                     9: NULL + QtWidgets
                        706     LOAD_ATTR                       38: QLineEdit
                        726     LOAD_GLOBAL                     47: NULL + str
                        736     LOAD_FAST                       2: value
                        738     CALL                            1
                        746     CALL                            1
                        754     LOAD_FAST                       0: self
                        756     STORE_ATTR                      24: value_edit
                        766     LOAD_FAST                       0: self
                        768     LOAD_ATTR                       48: value_edit
                        788     LOAD_ATTR                       43: setMinimumWidth
                        808     LOAD_CONST                      6: 200
                        810     CALL                            1
                        818     POP_TOP                         
                        820     LOAD_FAST                       0: self
                        822     LOAD_ATTR                       48: value_edit
                        842     LOAD_ATTR                       45: setPlaceholderText
                        862     LOAD_CONST                      8: 'Value'
                        864     CALL                            1
                        872     POP_TOP                         
                        874     LOAD_GLOBAL                     9: NULL + QtWidgets
                        884     LOAD_ATTR                       38: QLineEdit
                        904     LOAD_GLOBAL                     47: NULL + str
                        914     LOAD_FAST                       3: size
                        916     CALL                            1
                        924     CALL                            1
                        932     LOAD_FAST                       0: self
                        934     STORE_ATTR                      25: size_edit
                        944     LOAD_FAST                       0: self
                        946     LOAD_ATTR                       50: size_edit
                        966     LOAD_ATTR                       43: setMinimumWidth
                        986     LOAD_CONST                      9: 80
                        988     CALL                            1
                        996     POP_TOP                         
                        998     LOAD_FAST                       0: self
                        1000    LOAD_ATTR                       50: size_edit
                        1020    LOAD_ATTR                       45: setPlaceholderText
                        1040    LOAD_CONST                      10: 'Size'
                        1042    CALL                            1
                        1050    POP_TOP                         
                        1052    LOAD_GLOBAL                     9: NULL + QtWidgets
                        1062    LOAD_ATTR                       52: QPushButton
                        1082    LOAD_CONST                      11: '+'
                        1084    CALL                            1
                        1092    LOAD_FAST                       0: self
                        1094    STORE_ATTR                      27: add_button
                        1104    LOAD_FAST                       0: self
                        1106    LOAD_ATTR                       54: add_button
                        1126    LOAD_ATTR                       57: setMaximumWidth
                        1146    LOAD_CONST                      12: 30
                        1148    CALL                            1
                        1156    POP_TOP                         
                        1158    LOAD_FAST                       0: self
                        1160    LOAD_ATTR                       54: add_button
                        1180    LOAD_ATTR                       58: clicked
                        1200    LOAD_ATTR                       35: connect
                        1220    LOAD_FAST                       0: self
                        1222    LOAD_ATTR                       60: on_add_clicked
                        1242    CALL                            1
                        1250    POP_TOP                         
                        1252    LOAD_GLOBAL                     9: NULL + QtWidgets
                        1262    LOAD_ATTR                       52: QPushButton
                        1282    LOAD_CONST                      13: '-'
                        1284    CALL                            1
                        1292    LOAD_FAST                       0: self
                        1294    STORE_ATTR                      31: remove_button
                        1304    LOAD_FAST                       0: self
                        1306    LOAD_ATTR                       62: remove_button
                        1326    LOAD_ATTR                       57: setMaximumWidth
                        1346    LOAD_CONST                      12: 30
                        1348    CALL                            1
                        1356    POP_TOP                         
                        1358    LOAD_FAST                       0: self
                        1360    LOAD_ATTR                       62: remove_button
                        1380    LOAD_ATTR                       58: clicked
                        1400    LOAD_ATTR                       35: connect
                        1420    LOAD_FAST                       0: self
                        1422    LOAD_ATTR                       64: on_remove_clicked
                        1442    CALL                            1
                        1450    POP_TOP                         
                        1452    LOAD_FAST                       5: _var_var_1
                        1454    LOAD_ATTR                       67: addWidget
                        1474    LOAD_FAST                       0: self
                        1476    LOAD_ATTR                       26: checkbox
                        1496    CALL                            1
                        1504    POP_TOP                         
                        1506    LOAD_FAST                       5: _var_var_1
                        1508    LOAD_ATTR                       67: addWidget
                        1528    LOAD_FAST                       0: self
                        1530    LOAD_ATTR                       40: name_edit
                        1550    CALL                            1
                        1558    POP_TOP                         
                        1560    LOAD_FAST                       5: _var_var_1
                        1562    LOAD_ATTR                       67: addWidget
                        1582    LOAD_FAST                       0: self
                        1584    LOAD_ATTR                       48: value_edit
                        1604    CALL                            1
                        1612    POP_TOP                         
                        1614    LOAD_FAST                       5: _var_var_1
                        1616    LOAD_ATTR                       67: addWidget
                        1636    LOAD_FAST                       0: self
                        1638    LOAD_ATTR                       50: size_edit
                        1658    CALL                            1
                        1666    POP_TOP                         
                        1668    LOAD_FAST                       5: _var_var_1
                        1670    LOAD_ATTR                       67: addWidget
                        1690    LOAD_FAST                       0: self
                        1692    LOAD_ATTR                       54: add_button
                        1712    CALL                            1
                        1720    POP_TOP                         
                        1722    LOAD_FAST                       5: _var_var_1
                        1724    LOAD_ATTR                       67: addWidget
                        1744    LOAD_FAST                       0: self
                        1746    LOAD_ATTR                       62: remove_button
                        1766    CALL                            1
                        1774    POP_TOP                         
                        1776    LOAD_FAST                       5: _var_var_1
                        1778    LOAD_ATTR                       69: addStretch
                        1798    CALL                            0
                        1806    POP_TOP                         
                        1808    LOAD_FAST                       0: self
                        1810    LOAD_ATTR                       71: setLayout
                        1830    LOAD_FAST                       5: _var_var_1
                        1832    CALL                            1
                        1840    POP_TOP                         
                        1842    LOAD_CONST                      0: None
                        1844    NOP                             
                        1846    NOP                             
                        1848    NOP                             
                        1850    JUMP_FORWARD                    19 (to 1890)
                        1858    POP_TOP                         
                        1860    RETURN_CONST                    0: None
                        1862    PUSH_EXC_INFO                   
                        1864    PUSH_NULL                       
                        1866    LOAD_CONST                      14: '__pyarmor_exit_54573__'
                        1868    NOP                             
                        1870    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c*\x07\x00\x00\x00\x00\x00\x00'
                        1872    CALL                            1
                        1880    POP_TOP                         
                        1882    RERAISE                         0
                        1884    COPY                            3
                        1886    POP_EXCEPT                      
                        1888    RERAISE                         1
                        1890    PUSH_NULL                       
                        1892    LOAD_CONST                      14: '__pyarmor_exit_54573__'
                        1894    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c*\x07\x00\x00\x00\x00\x00\x00'
                        1896    BUILD_TUPLE                     1
                        1898    CALL_FUNCTION_EX                0
                        1900    POP_TOP                         
                        1902    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: accepted_state_change
                    Qualified Name: EnumFieldWidget.accepted_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted'
                        'name_edit'
                        'setEnabled'
                        'value_edit'
                        'size_edit'
                        'add_button'
                        'remove_button'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54574__'
                        '__pyarmor_enter_54575__'
                        b'<COAddr>\x03\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54576__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54575__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: name_edit
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       6: accepted
                        160     CALL                            1
                        168     POP_TOP                         
                        170     LOAD_FAST                       0: self
                        172     LOAD_ATTR                       12: value_edit
                        192     LOAD_ATTR                       11: setEnabled
                        212     LOAD_FAST                       0: self
                        214     LOAD_ATTR                       6: accepted
                        234     CALL                            1
                        242     POP_TOP                         
                        244     LOAD_FAST                       0: self
                        246     LOAD_ATTR                       14: size_edit
                        266     LOAD_ATTR                       11: setEnabled
                        286     LOAD_FAST                       0: self
                        288     LOAD_ATTR                       6: accepted
                        308     CALL                            1
                        316     POP_TOP                         
                        318     LOAD_FAST                       0: self
                        320     LOAD_ATTR                       16: add_button
                        340     LOAD_ATTR                       11: setEnabled
                        360     LOAD_FAST                       0: self
                        362     LOAD_ATTR                       6: accepted
                        382     CALL                            1
                        390     POP_TOP                         
                        392     LOAD_FAST                       0: self
                        394     LOAD_ATTR                       18: remove_button
                        414     LOAD_ATTR                       11: setEnabled
                        434     LOAD_FAST                       0: self
                        436     LOAD_ATTR                       6: accepted
                        456     CALL                            1
                        464     POP_TOP                         
                        466     LOAD_CONST                      0: None
                        468     NOP                             
                        470     NOP                             
                        472     NOP                             
                        474     JUMP_FORWARD                    19 (to 514)
                        482     POP_TOP                         
                        484     RETURN_CONST                    0: None
                        486     PUSH_EXC_INFO                   
                        488     PUSH_NULL                       
                        490     LOAD_CONST                      4: '__pyarmor_exit_54576__'
                        492     NOP                             
                        494     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        496     CALL                            1
                        504     POP_TOP                         
                        506     RERAISE                         0
                        508     COPY                            3
                        510     POP_EXCEPT                      
                        512     RERAISE                         1
                        514     PUSH_NULL                       
                        516     LOAD_CONST                      4: '__pyarmor_exit_54576__'
                        518     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        520     BUILD_TUPLE                     1
                        522     CALL_FUNCTION_EX                0
                        524     POP_TOP                         
                        526     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: get_content
                    Qualified Name: EnumFieldWidget.get_content
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'accepted'
                        'size_edit'
                        'text'
                        'strip'
                        'int'
                        'ValueError'
                        'value_edit'
                        'isdigit'
                        'name_edit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_15'
                        '_var_var_17'
                    [Constants]
                        None
                        '__pyarmor_assert_54577__'
                        '__pyarmor_enter_54578__'
                        b'<COAddr>\x03\x00\x00\x1a\xa4\x01\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54579__'
                        4
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54578__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa4\x01\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: accepted
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      0: None
                        56      NOP                             
                        58      NOP                             
                        60      NOP                             
                        62      JUMP_FORWARD                    205 (to 474)
                        70      POP_TOP                         
                        72      RETURN_CONST                    0: None
                        74      NOP                             
                        76      LOAD_FAST                       0: self
                        78      LOAD_ATTR                       2: size_edit
                        98      LOAD_ATTR                       5: text
                        118     CALL                            0
                        126     LOAD_ATTR                       7: strip
                        146     CALL                            0
                        154     POP_JUMP_IF_FALSE               35 (to 226)
                        156     LOAD_GLOBAL                     9: NULL + int
                        166     LOAD_FAST                       0: self
                        168     LOAD_ATTR                       2: size_edit
                        188     LOAD_ATTR                       5: text
                        208     CALL                            0
                        216     CALL                            1
                        224     JUMP_FORWARD                    1 (to 228)
                        226     LOAD_CONST                      5: 4
                        228     STORE_FAST                      2: _var_var_15
                        230     LOAD_FAST                       0: self
                        232     LOAD_ATTR                       12: value_edit
                        252     LOAD_ATTR                       5: text
                        272     CALL                            0
                        280     STORE_FAST                      3: _var_var_17
                        282     LOAD_FAST                       3: _var_var_17
                        284     LOAD_ATTR                       15: isdigit
                        304     CALL                            0
                        312     POP_JUMP_IF_FALSE               11 (to 336)
                        314     LOAD_GLOBAL                     9: NULL + int
                        324     LOAD_FAST                       3: _var_var_17
                        326     CALL                            1
                        334     STORE_FAST                      3: _var_var_17
                        336     LOAD_FAST                       0: self
                        338     LOAD_ATTR                       16: name_edit
                        358     LOAD_ATTR                       5: text
                        378     CALL                            0
                        386     LOAD_FAST                       3: _var_var_17
                        388     LOAD_FAST                       2: _var_var_15
                        390     BUILD_LIST                      3
                        392     NOP                             
                        394     NOP                             
                        396     NOP                             
                        398     JUMP_FORWARD                    37 (to 474)
                        400     CALL                            1
                        408     POP_TOP                         
                        410     RETURN_VALUE                    
                        412     PUSH_EXC_INFO                   
                        414     LOAD_GLOBAL                     10: ValueError
                        424     CHECK_EXC_MATCH                 
                        426     POP_JUMP_IF_FALSE               5 (to 438)
                        428     POP_TOP                         
                        430     LOAD_CONST                      5: 4
                        432     STORE_FAST                      2: _var_var_15
                        434     POP_EXCEPT                      
                        436     JUMP_BACKWARD                   104 (to 230)
                        438     RERAISE                         0
                        440     COPY                            3
                        442     POP_EXCEPT                      
                        444     RERAISE                         1
                        446     PUSH_EXC_INFO                   
                        448     PUSH_NULL                       
                        450     LOAD_CONST                      4: '__pyarmor_exit_54579__'
                        452     NOP                             
                        454     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa4\x01\x00\x00\x00\x00\x00\x00'
                        456     CALL                            1
                        464     POP_TOP                         
                        466     RERAISE                         0
                        468     COPY                            3
                        470     POP_EXCEPT                      
                        472     RERAISE                         1
                        474     PUSH_NULL                       
                        476     LOAD_CONST                      4: '__pyarmor_exit_54579__'
                        478     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xa4\x01\x00\x00\x00\x00\x00\x00'
                        480     BUILD_TUPLE                     1
                        482     CALL_FUNCTION_EX                0
                        484     POP_TOP                         
                        486     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: validate
                    Qualified Name: EnumFieldWidget.validate
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'accepted'
                        'name_edit'
                        'text'
                        'strip'
                        'value_edit'
                        'size_edit'
                        'int'
                        'ValueError'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_16'
                        '_var_var_15'
                    [Constants]
                        None
                        '__pyarmor_assert_54580__'
                        '__pyarmor_enter_54581__'
                        b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54582__'
                        True
                        False
                        0
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54581__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: accepted
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      5: True
                        56      NOP                             
                        58      NOP                             
                        60      NOP                             
                        62      JUMP_FORWARD                    225 (to 514)
                        70      POP_TOP                         
                        72      RETURN_CONST                    5: True
                        74      LOAD_FAST                       0: self
                        76      LOAD_ATTR                       2: name_edit
                        96      LOAD_ATTR                       5: text
                        116     CALL                            0
                        124     LOAD_ATTR                       7: strip
                        144     CALL                            0
                        152     POP_JUMP_IF_TRUE                11 (to 176)
                        154     NOP                             
                        156     LOAD_CONST                      6: False
                        158     NOP                             
                        160     NOP                             
                        162     NOP                             
                        164     JUMP_FORWARD                    174 (to 514)
                        172     POP_TOP                         
                        174     RETURN_CONST                    6: False
                        176     LOAD_FAST                       0: self
                        178     LOAD_ATTR                       8: value_edit
                        198     LOAD_ATTR                       5: text
                        218     CALL                            0
                        226     LOAD_ATTR                       7: strip
                        246     CALL                            0
                        254     POP_JUMP_IF_TRUE                11 (to 278)
                        256     NOP                             
                        258     LOAD_CONST                      6: False
                        260     NOP                             
                        262     NOP                             
                        264     NOP                             
                        266     JUMP_FORWARD                    123 (to 514)
                        274     POP_TOP                         
                        276     RETURN_CONST                    6: False
                        278     NOP                             
                        280     LOAD_FAST                       0: self
                        282     LOAD_ATTR                       10: size_edit
                        302     LOAD_ATTR                       5: text
                        322     CALL                            0
                        330     LOAD_ATTR                       7: strip
                        350     CALL                            0
                        358     STORE_FAST                      2: _var_var_16
                        360     LOAD_FAST                       2: _var_var_16
                        362     POP_JUMP_IF_FALSE               27 (to 418)
                        364     LOAD_GLOBAL                     13: NULL + int
                        374     LOAD_FAST                       2: _var_var_16
                        376     CALL                            1
                        384     STORE_FAST                      3: _var_var_15
                        386     LOAD_FAST                       3: _var_var_15
                        388     LOAD_CONST                      7: 0
                        390     COMPARE_OP                      26 (<=)
                        394     POP_JUMP_IF_FALSE               11 (to 418)
                        396     NOP                             
                        398     LOAD_CONST                      6: False
                        400     NOP                             
                        402     NOP                             
                        404     NOP                             
                        406     JUMP_FORWARD                    53 (to 514)
                        414     POP_TOP                         
                        416     RETURN_CONST                    6: False
                        418     LOAD_CONST                      5: True
                        420     NOP                             
                        422     NOP                             
                        424     NOP                             
                        426     JUMP_FORWARD                    43 (to 514)
                        434     POP_TOP                         
                        436     RETURN_CONST                    5: True
                        438     PUSH_EXC_INFO                   
                        440     LOAD_GLOBAL                     14: ValueError
                        450     CHECK_EXC_MATCH                 
                        452     POP_JUMP_IF_FALSE               12 (to 478)
                        454     POP_TOP                         
                        456     POP_EXCEPT                      
                        458     LOAD_CONST                      6: False
                        460     NOP                             
                        462     NOP                             
                        464     NOP                             
                        466     JUMP_FORWARD                    23 (to 514)
                        474     POP_TOP                         
                        476     RETURN_CONST                    6: False
                        478     RERAISE                         0
                        480     COPY                            3
                        482     POP_EXCEPT                      
                        484     RERAISE                         1
                        486     PUSH_EXC_INFO                   
                        488     PUSH_NULL                       
                        490     LOAD_CONST                      4: '__pyarmor_exit_54582__'
                        492     NOP                             
                        494     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        496     CALL                            1
                        504     POP_TOP                         
                        506     RERAISE                         0
                        508     COPY                            3
                        510     POP_EXCEPT                      
                        512     RERAISE                         1
                        514     PUSH_NULL                       
                        516     LOAD_CONST                      4: '__pyarmor_exit_54582__'
                        518     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xcc\x01\x00\x00\x00\x00\x00\x00'
                        520     BUILD_TUPLE                     1
                        522     CALL_FUNCTION_EX                0
                        524     POP_TOP                         
                        526     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_add_clicked
                    Qualified Name: EnumFieldWidget.on_add_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'field_added'
                        'emit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54583__'
                        '__pyarmor_enter_54584__'
                        b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54585__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54584__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: field_added
                        50      LOAD_ATTR                       3: emit
                        70      CALL                            0
                        78      POP_TOP                         
                        80      LOAD_CONST                      0: None
                        82      NOP                             
                        84      NOP                             
                        86      NOP                             
                        88      JUMP_FORWARD                    19 (to 128)
                        96      POP_TOP                         
                        98      RETURN_CONST                    0: None
                        100     PUSH_EXC_INFO                   
                        102     PUSH_NULL                       
                        104     LOAD_CONST                      4: '__pyarmor_exit_54585__'
                        106     NOP                             
                        108     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        110     CALL                            1
                        118     POP_TOP                         
                        120     RERAISE                         0
                        122     COPY                            3
                        124     POP_EXCEPT                      
                        126     RERAISE                         1
                        128     PUSH_NULL                       
                        130     LOAD_CONST                      4: '__pyarmor_exit_54585__'
                        132     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aJ\x00\x00\x00\x00\x00\x00\x00'
                        134     BUILD_TUPLE                     1
                        136     CALL_FUNCTION_EX                0
                        138     POP_TOP                         
                        140     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_remove_clicked
                    Qualified Name: EnumFieldWidget.on_remove_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'field_removed'
                        'emit'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54586__'
                        '__pyarmor_enter_54587__'
                        b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54588__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54587__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: field_removed
                        50      LOAD_ATTR                       3: emit
                        70      LOAD_FAST                       0: self
                        72      CALL                            1
                        80      POP_TOP                         
                        82      LOAD_CONST                      0: None
                        84      NOP                             
                        86      NOP                             
                        88      NOP                             
                        90      JUMP_FORWARD                    19 (to 130)
                        98      POP_TOP                         
                        100     RETURN_CONST                    0: None
                        102     PUSH_EXC_INFO                   
                        104     PUSH_NULL                       
                        106     LOAD_CONST                      4: '__pyarmor_exit_54588__'
                        108     NOP                             
                        110     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        112     CALL                            1
                        120     POP_TOP                         
                        122     RERAISE                         0
                        124     COPY                            3
                        126     POP_EXCEPT                      
                        128     RERAISE                         1
                        130     PUSH_NULL                       
                        132     LOAD_CONST                      4: '__pyarmor_exit_54588__'
                        134     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aL\x00\x00\x00\x00\x00\x00\x00'
                        136     BUILD_TUPLE                     1
                        138     CALL_FUNCTION_EX                0
                        140     POP_TOP                         
                        142     RETURN_VALUE                    
                '__pyarmor_exit_54570__'
                (
                    ''
                    ''
                    ''
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'EnumFieldWidget'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54569__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                20      BUILD_TUPLE                     1
                22      CALL_FUNCTION_EX                0
                24      POP_TOP                         
                26      RESUME                          0
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      PUSH_NULL                       
                40      LOAD_NAME                       4: QtCore
                42      LOAD_ATTR                       10: pyqtSignal
                62      CALL                            0
                70      STORE_NAME                      6: field_added
                72      PUSH_NULL                       
                74      LOAD_NAME                       4: QtCore
                76      LOAD_ATTR                       10: pyqtSignal
                96      LOAD_NAME                       7: QWidget
                98      CALL                            1
                106     STORE_NAME                      8: field_removed
                108     LOAD_CONST                      11: ('', '', '')
                110     LOAD_CLOSURE                    0: __class__
                112     BUILD_TUPLE                     1
                114     LOAD_CONST                      4: <CODE> __init__
                116     MAKE_FUNCTION                   9
                118     STORE_NAME                      9: __init__
                120     LOAD_CONST                      5: <CODE> accepted_state_change
                122     MAKE_FUNCTION                   0
                124     STORE_NAME                      10: accepted_state_change
                126     LOAD_CONST                      6: <CODE> get_content
                128     MAKE_FUNCTION                   0
                130     STORE_NAME                      11: get_content
                132     LOAD_CONST                      7: <CODE> validate
                134     MAKE_FUNCTION                   0
                136     STORE_NAME                      12: validate
                138     LOAD_CONST                      8: <CODE> on_add_clicked
                140     MAKE_FUNCTION                   0
                142     STORE_NAME                      13: on_add_clicked
                144     LOAD_CONST                      9: <CODE> on_remove_clicked
                146     MAKE_FUNCTION                   0
                148     STORE_NAME                      14: on_remove_clicked
                150     LOAD_CLOSURE                    0: __class__
                152     COPY                            1
                154     STORE_NAME                      15: __classcell__
                156     NOP                             
                158     NOP                             
                160     NOP                             
                162     JUMP_FORWARD                    20 (to 204)
                166     POP_TOP                         
                168     LOAD_CLOSURE                    0: __class__
                170     COPY                            1
                172     STORE_NAME                      15: __classcell__
                174     RETURN_VALUE                    
                176     PUSH_EXC_INFO                   
                178     PUSH_NULL                       
                180     LOAD_CONST                      10: '__pyarmor_exit_54570__'
                182     NOP                             
                184     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                186     CALL                            1
                194     POP_TOP                         
                196     RERAISE                         0
                198     COPY                            3
                200     POP_EXCEPT                      
                202     RERAISE                         1
                204     PUSH_NULL                       
                206     LOAD_CONST                      10: '__pyarmor_exit_54570__'
                208     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$\x8c\x00\x00\x00\x00\x00\x00\x00'
                210     BUILD_TUPLE                     1
                212     CALL_FUNCTION_EX                0
                214     POP_TOP                         
                216     RETURN_VALUE                    
        'EnumFieldWidget'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: ComplexTypeWidget
            Qualified Name: ComplexTypeWidget
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
                'add_struct_field'
                'add_enum_field'
                'remove_struct_field'
                'remove_enum_field'
                'validate'
                'accepted_state_change'
                'get_type_info'
                '_create_add_enum_callback'
                '_create_add_struct_callback'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'ComplexTypeWidget'
                '__pyarmor_assert_54589__'
                '__pyarmor_enter_54590__'
                b'<COAddr>\x03\x00\x00$`\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: ComplexTypeWidget.__init__
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'ComplexTypeWidget'
                        '__init__'
                        'accepted'
                        'type_info'
                        'field_widgets'
                        'QtWidgets'
                        'QVBoxLayout'
                        'setAlignment'
                        'QtCore'
                        'Qt'
                        'AlignLeft'
                        'AlignVCenter'
                        'QGroupBox'
                        'QHBoxLayout'
                        'QCheckBox'
                        'checkbox'
                        'setCheckState'
                        'Checked'
                        'stateChanged'
                        'connect'
                        'accepted_state_change'
                        'NameTypeWidget'
                        'name_type_widget'
                        'addWidget'
                        'addLayout'
                        'fields_group'
                        'QLabel'
                        'QLineEdit'
                        'struct_name_edit'
                        'list'
                        'keys'
                        'replace'
                        'strip'
                        'setText'
                        'fields_layout'
                        'get'
                        'isinstance'
                        'tuple'
                        'len'
                        'add_struct_field'
                        'setLayout'
                        'enum_name_edit'
                        'dict'
                        'str'
                        'EnumFieldWidget'
                        'field_added'
                        '_create_add_enum_callback'
                        'field_removed'
                        'remove_enum_field'
                        'append'
                        'add_enum_field'
                        'join'
                        'map'
                        'array_edit'
                        'setPlaceholderText'
                    [Locals+Names]
                        'self'
                        'title'
                        'type_info'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_10'
                        '_var_var_11'
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
                        '_var_var_15'
                        '_var_var_29'
                        '_var_var_30'
                        '_var_var_31'
                        '_var_var_32'
                        '_var_var_33'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54592__'
                        '__pyarmor_enter_54593__'
                        b'<COAddr>\x01\x00\x00\x1c*\x0e\x00\x00\x00\x00\x00\x00'
                        True
                        ''
                        1
                        0
                        False
                        2
                        'struct'
                        'Struct Fields'
                        'Struct Name:'
                        3
                        ' *'
                        'enum'
                        'Enum Fields'
                        'Enum Name:'
                        '0'
                        4
                        'array'
                        'Array Dimensions'
                        ','
                        'Enter dimensions separated by commas'
                        '__pyarmor_exit_54594__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54593__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c*\x0e\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: ComplexTypeWidget
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_CONST                      4: True
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: accepted
                        80      LOAD_FAST                       2: type_info
                        82      LOAD_FAST                       0: self
                        84      STORE_ATTR                      4: type_info
                        94      BUILD_LIST                      0
                        96      LOAD_FAST                       0: self
                        98      STORE_ATTR                      5: field_widgets
                        108     LOAD_GLOBAL                     13: NULL + QtWidgets
                        118     LOAD_ATTR                       14: QVBoxLayout
                        138     CALL                            0
                        146     STORE_FAST                      4: _var_var_1
                        148     LOAD_FAST                       4: _var_var_1
                        150     LOAD_ATTR                       17: setAlignment
                        170     LOAD_GLOBAL                     18: QtCore
                        180     LOAD_ATTR                       20: Qt
                        200     LOAD_ATTR                       22: AlignLeft
                        220     LOAD_GLOBAL                     18: QtCore
                        230     LOAD_ATTR                       20: Qt
                        250     LOAD_ATTR                       24: AlignVCenter
                        270     BINARY_OP                       7 (|)
                        274     CALL                            1
                        282     POP_TOP                         
                        284     LOAD_GLOBAL                     13: NULL + QtWidgets
                        294     LOAD_ATTR                       26: QGroupBox
                        314     LOAD_FAST                       1: title
                        316     CALL                            1
                        324     STORE_FAST                      5: _var_var_10
                        326     LOAD_GLOBAL                     13: NULL + QtWidgets
                        336     LOAD_ATTR                       14: QVBoxLayout
                        356     CALL                            0
                        364     STORE_FAST                      6: _var_var_11
                        366     LOAD_GLOBAL                     13: NULL + QtWidgets
                        376     LOAD_ATTR                       28: QHBoxLayout
                        396     CALL                            0
                        404     STORE_FAST                      7: _var_var_18
                        406     LOAD_GLOBAL                     13: NULL + QtWidgets
                        416     LOAD_ATTR                       30: QCheckBox
                        436     CALL                            0
                        444     LOAD_FAST                       0: self
                        446     STORE_ATTR                      16: checkbox
                        456     LOAD_FAST                       0: self
                        458     LOAD_ATTR                       32: checkbox
                        478     LOAD_ATTR                       35: setCheckState
                        498     LOAD_GLOBAL                     18: QtCore
                        508     LOAD_ATTR                       20: Qt
                        528     LOAD_ATTR                       36: Checked
                        548     CALL                            1
                        556     POP_TOP                         
                        558     LOAD_FAST                       0: self
                        560     LOAD_ATTR                       32: checkbox
                        580     LOAD_ATTR                       38: stateChanged
                        600     LOAD_ATTR                       41: connect
                        620     LOAD_FAST                       0: self
                        622     LOAD_ATTR                       42: accepted_state_change
                        642     CALL                            1
                        650     POP_TOP                         
                        652     LOAD_GLOBAL                     45: NULL + NameTypeWidget
                        662     LOAD_CONST                      5: ''
                        664     LOAD_FAST                       2: type_info
                        666     LOAD_CONST                      6: 1
                        668     BINARY_SUBSCR                   
                        672     LOAD_FAST                       2: type_info
                        674     LOAD_CONST                      7: 0
                        676     BINARY_SUBSCR                   
                        680     LOAD_CONST                      5: ''
                        682     LOAD_CONST                      8: False
                        684     CALL                            5
                        692     LOAD_FAST                       0: self
                        694     STORE_ATTR                      23: name_type_widget
                        704     LOAD_FAST                       7: _var_var_18
                        706     LOAD_ATTR                       49: addWidget
                        726     LOAD_FAST                       0: self
                        728     LOAD_ATTR                       32: checkbox
                        748     CALL                            1
                        756     POP_TOP                         
                        758     LOAD_FAST                       7: _var_var_18
                        760     LOAD_ATTR                       49: addWidget
                        780     LOAD_FAST                       0: self
                        782     LOAD_ATTR                       46: name_type_widget
                        802     CALL                            1
                        810     POP_TOP                         
                        812     LOAD_FAST                       6: _var_var_11
                        814     LOAD_ATTR                       51: addLayout
                        834     LOAD_FAST                       7: _var_var_18
                        836     CALL                            1
                        844     POP_TOP                         
                        846     LOAD_FAST                       2: type_info
                        848     LOAD_CONST                      9: 2
                        850     BINARY_SUBSCR                   
                        854     POP_JUMP_IF_FALSE               1337 (to 3532)
                        858     LOAD_FAST                       2: type_info
                        860     LOAD_CONST                      9: 2
                        862     BINARY_SUBSCR                   
                        866     LOAD_CONST                      10: 'struct'
                        868     COMPARE_OP                      40 (==)
                        872     POP_JUMP_IF_FALSE               444 (to 1764)
                        876     LOAD_GLOBAL                     13: NULL + QtWidgets
                        886     LOAD_ATTR                       26: QGroupBox
                        906     LOAD_CONST                      11: 'Struct Fields'
                        908     CALL                            1
                        916     LOAD_FAST                       0: self
                        918     STORE_ATTR                      26: fields_group
                        928     LOAD_GLOBAL                     13: NULL + QtWidgets
                        938     LOAD_ATTR                       28: QHBoxLayout
                        958     CALL                            0
                        966     STORE_FAST                      8: _var_var_19
                        968     LOAD_FAST                       8: _var_var_19
                        970     LOAD_ATTR                       49: addWidget
                        990     LOAD_GLOBAL                     13: NULL + QtWidgets
                        1000    LOAD_ATTR                       54: QLabel
                        1020    LOAD_CONST                      12: 'Struct Name:'
                        1022    CALL                            1
                        1030    CALL                            1
                        1038    POP_TOP                         
                        1040    LOAD_GLOBAL                     13: NULL + QtWidgets
                        1050    LOAD_ATTR                       56: QLineEdit
                        1070    CALL                            0
                        1078    LOAD_FAST                       0: self
                        1080    STORE_ATTR                      29: struct_name_edit
                        1090    LOAD_FAST                       2: type_info
                        1092    LOAD_CONST                      13: 3
                        1094    BINARY_SUBSCR                   
                        1098    POP_JUMP_IF_FALSE               31 (to 1162)
                        1100    LOAD_GLOBAL                     61: NULL + list
                        1110    LOAD_FAST                       2: type_info
                        1112    LOAD_CONST                      13: 3
                        1114    BINARY_SUBSCR                   
                        1118    LOAD_ATTR                       63: keys
                        1138    CALL                            0
                        1146    CALL                            1
                        1154    LOAD_CONST                      7: 0
                        1156    BINARY_SUBSCR                   
                        1160    JUMP_FORWARD                    34 (to 1230)
                        1162    LOAD_FAST                       2: type_info
                        1164    LOAD_CONST                      7: 0
                        1166    BINARY_SUBSCR                   
                        1170    LOAD_ATTR                       65: replace
                        1190    LOAD_CONST                      14: ' *'
                        1192    LOAD_CONST                      5: ''
                        1194    CALL                            2
                        1202    LOAD_ATTR                       67: strip
                        1222    CALL                            0
                        1230    STORE_FAST                      9: _var_var_20
                        1232    LOAD_FAST                       0: self
                        1234    LOAD_ATTR                       58: struct_name_edit
                        1254    LOAD_ATTR                       69: setText
                        1274    LOAD_FAST                       9: _var_var_20
                        1276    CALL                            1
                        1284    POP_TOP                         
                        1286    LOAD_FAST                       8: _var_var_19
                        1288    LOAD_ATTR                       49: addWidget
                        1308    LOAD_FAST                       0: self
                        1310    LOAD_ATTR                       58: struct_name_edit
                        1330    CALL                            1
                        1338    POP_TOP                         
                        1340    LOAD_GLOBAL                     13: NULL + QtWidgets
                        1350    LOAD_ATTR                       14: QVBoxLayout
                        1370    CALL                            0
                        1378    LOAD_FAST                       0: self
                        1380    STORE_ATTR                      35: fields_layout
                        1390    LOAD_FAST                       0: self
                        1392    LOAD_ATTR                       70: fields_layout
                        1412    LOAD_ATTR                       51: addLayout
                        1432    LOAD_FAST                       8: _var_var_19
                        1434    CALL                            1
                        1442    POP_TOP                         
                        1444    LOAD_FAST                       2: type_info
                        1446    LOAD_CONST                      13: 3
                        1448    BINARY_SUBSCR                   
                        1452    LOAD_ATTR                       73: get
                        1472    LOAD_FAST                       9: _var_var_20
                        1474    BUILD_LIST                      0
                        1476    CALL                            2
                        1484    STORE_FAST                      10: _var_var_21
                        1486    LOAD_FAST                       10: _var_var_21
                        1488    GET_ITER                        
                        1490    FOR_ITER                        68 (to 1628)
                        1494    STORE_FAST                      11: _var_var_22
                        1496    LOAD_GLOBAL                     75: NULL + isinstance
                        1506    LOAD_FAST                       11: _var_var_22
                        1508    LOAD_GLOBAL                     60: list
                        1518    LOAD_GLOBAL                     76: tuple
                        1528    BUILD_TUPLE                     2
                        1530    CALL                            2
                        1538    POP_JUMP_IF_TRUE                1 (to 1542)
                        1540    JUMP_BACKWARD                   26 (to 1490)
                        1542    LOAD_GLOBAL                     79: NULL + len
                        1552    LOAD_FAST                       11: _var_var_22
                        1554    CALL                            1
                        1562    LOAD_CONST                      13: 3
                        1564    COMPARE_OP                      92 (>=)
                        1568    POP_JUMP_IF_TRUE                1 (to 1572)
                        1570    JUMP_BACKWARD                   41 (to 1490)
                        1572    LOAD_FAST                       0: self
                        1574    LOAD_ATTR                       81: add_struct_field
                        1594    LOAD_FAST                       11: _var_var_22
                        1596    LOAD_CONST                      7: 0
                        1598    BINARY_SUBSCR                   
                        1602    LOAD_FAST                       11: _var_var_22
                        1604    LOAD_CONST                      6: 1
                        1606    BINARY_SUBSCR                   
                        1610    LOAD_FAST                       11: _var_var_22
                        1612    LOAD_CONST                      9: 2
                        1614    BINARY_SUBSCR                   
                        1618    CALL                            3
                        1626    POP_TOP                         
                        1628    JUMP_BACKWARD                   70 (to 1490)
                        1630    END_FOR                         
                        1632    LOAD_FAST                       0: self
                        1634    LOAD_ATTR                       52: fields_group
                        1654    LOAD_ATTR                       83: setLayout
                        1674    LOAD_FAST                       0: self
                        1676    LOAD_ATTR                       70: fields_layout
                        1696    CALL                            1
                        1704    POP_TOP                         
                        1706    LOAD_FAST                       6: _var_var_11
                        1708    LOAD_ATTR                       49: addWidget
                        1728    LOAD_FAST                       0: self
                        1730    LOAD_ATTR                       52: fields_group
                        1750    CALL                            1
                        1758    POP_TOP                         
                        1760    JUMP_FORWARD                    884 (to 3532)
                        1764    LOAD_FAST                       2: type_info
                        1766    LOAD_CONST                      9: 2
                        1768    BINARY_SUBSCR                   
                        1772    LOAD_CONST                      15: 'enum'
                        1774    COMPARE_OP                      40 (==)
                        1778    POP_JUMP_IF_FALSE               649 (to 3080)
                        1782    LOAD_GLOBAL                     13: NULL + QtWidgets
                        1792    LOAD_ATTR                       26: QGroupBox
                        1812    LOAD_CONST                      16: 'Enum Fields'
                        1814    CALL                            1
                        1822    STORE_FAST                      12: _var_var_23
                        1824    LOAD_GLOBAL                     13: NULL + QtWidgets
                        1834    LOAD_ATTR                       28: QHBoxLayout
                        1854    CALL                            0
                        1862    STORE_FAST                      8: _var_var_19
                        1864    LOAD_FAST                       8: _var_var_19
                        1866    LOAD_ATTR                       49: addWidget
                        1886    LOAD_GLOBAL                     13: NULL + QtWidgets
                        1896    LOAD_ATTR                       54: QLabel
                        1916    LOAD_CONST                      17: 'Enum Name:'
                        1918    CALL                            1
                        1926    CALL                            1
                        1934    POP_TOP                         
                        1936    LOAD_GLOBAL                     13: NULL + QtWidgets
                        1946    LOAD_ATTR                       56: QLineEdit
                        1966    CALL                            0
                        1974    LOAD_FAST                       0: self
                        1976    STORE_ATTR                      42: enum_name_edit
                        1986    LOAD_FAST                       2: type_info
                        1988    LOAD_CONST                      13: 3
                        1990    BINARY_SUBSCR                   
                        1994    POP_JUMP_IF_FALSE               50 (to 2096)
                        1996    LOAD_GLOBAL                     75: NULL + isinstance
                        2006    LOAD_FAST                       2: type_info
                        2008    LOAD_CONST                      13: 3
                        2010    BINARY_SUBSCR                   
                        2014    LOAD_GLOBAL                     86: dict
                        2024    CALL                            2
                        2032    POP_JUMP_IF_FALSE               31 (to 2096)
                        2034    LOAD_GLOBAL                     61: NULL + list
                        2044    LOAD_FAST                       2: type_info
                        2046    LOAD_CONST                      13: 3
                        2048    BINARY_SUBSCR                   
                        2052    LOAD_ATTR                       63: keys
                        2072    CALL                            0
                        2080    CALL                            1
                        2088    LOAD_CONST                      7: 0
                        2090    BINARY_SUBSCR                   
                        2094    JUMP_FORWARD                    18 (to 2132)
                        2096    LOAD_FAST                       2: type_info
                        2098    LOAD_CONST                      7: 0
                        2100    BINARY_SUBSCR                   
                        2104    LOAD_ATTR                       67: strip
                        2124    CALL                            0
                        2132    STORE_FAST                      13: _var_var_24
                        2134    LOAD_FAST                       0: self
                        2136    LOAD_ATTR                       84: enum_name_edit
                        2156    LOAD_ATTR                       69: setText
                        2176    LOAD_FAST                       13: _var_var_24
                        2178    CALL                            1
                        2186    POP_TOP                         
                        2188    LOAD_FAST                       8: _var_var_19
                        2190    LOAD_ATTR                       49: addWidget
                        2210    LOAD_FAST                       0: self
                        2212    LOAD_ATTR                       84: enum_name_edit
                        2232    CALL                            1
                        2240    POP_TOP                         
                        2242    LOAD_GLOBAL                     13: NULL + QtWidgets
                        2252    LOAD_ATTR                       14: QVBoxLayout
                        2272    CALL                            0
                        2280    LOAD_FAST                       0: self
                        2282    STORE_ATTR                      35: fields_layout
                        2292    LOAD_FAST                       0: self
                        2294    LOAD_ATTR                       70: fields_layout
                        2314    LOAD_ATTR                       51: addLayout
                        2334    LOAD_FAST                       8: _var_var_19
                        2336    CALL                            1
                        2344    POP_TOP                         
                        2346    LOAD_GLOBAL                     75: NULL + isinstance
                        2356    LOAD_FAST                       2: type_info
                        2358    LOAD_CONST                      13: 3
                        2360    BINARY_SUBSCR                   
                        2364    LOAD_GLOBAL                     86: dict
                        2374    CALL                            2
                        2382    POP_JUMP_IF_FALSE               21 (to 2426)
                        2384    LOAD_FAST                       2: type_info
                        2386    LOAD_CONST                      13: 3
                        2388    BINARY_SUBSCR                   
                        2392    LOAD_ATTR                       73: get
                        2412    LOAD_FAST                       13: _var_var_24
                        2414    BUILD_LIST                      0
                        2416    CALL                            2
                        2424    JUMP_FORWARD                    1 (to 2428)
                        2426    BUILD_LIST                      0
                        2428    STORE_FAST                      14: _var_var_25
                        2430    LOAD_FAST                       14: _var_var_25
                        2432    POP_JUMP_IF_FALSE               261 (to 2958)
                        2436    LOAD_FAST                       14: _var_var_25
                        2438    GET_ITER                        
                        2440    FOR_ITER                        255 (to 2952)
                        2444    STORE_FAST                      15: _var_var_26
                        2446    LOAD_GLOBAL                     75: NULL + isinstance
                        2456    LOAD_FAST                       15: _var_var_26
                        2458    LOAD_GLOBAL                     60: list
                        2468    LOAD_GLOBAL                     76: tuple
                        2478    BUILD_TUPLE                     2
                        2480    CALL                            2
                        2488    POP_JUMP_IF_TRUE                1 (to 2492)
                        2490    JUMP_BACKWARD                   26 (to 2440)
                        2492    LOAD_GLOBAL                     79: NULL + len
                        2502    LOAD_FAST                       15: _var_var_26
                        2504    CALL                            1
                        2512    LOAD_CONST                      9: 2
                        2514    COMPARE_OP                      92 (>=)
                        2518    POP_JUMP_IF_TRUE                1 (to 2522)
                        2520    JUMP_BACKWARD                   41 (to 2440)
                        2522    LOAD_FAST                       15: _var_var_26
                        2524    LOAD_CONST                      7: 0
                        2526    BINARY_SUBSCR                   
                        2530    POP_JUMP_IF_NONE                14 (to 2560)
                        2532    LOAD_GLOBAL                     89: NULL + str
                        2542    LOAD_FAST                       15: _var_var_26
                        2544    LOAD_CONST                      7: 0
                        2546    BINARY_SUBSCR                   
                        2550    CALL                            1
                        2558    JUMP_FORWARD                    1 (to 2562)
                        2560    LOAD_CONST                      5: ''
                        2562    STORE_FAST                      16: _var_var_27
                        2564    LOAD_FAST                       15: _var_var_26
                        2566    LOAD_CONST                      6: 1
                        2568    BINARY_SUBSCR                   
                        2572    POP_JUMP_IF_NONE                14 (to 2602)
                        2574    LOAD_GLOBAL                     89: NULL + str
                        2584    LOAD_FAST                       15: _var_var_26
                        2586    LOAD_CONST                      6: 1
                        2588    BINARY_SUBSCR                   
                        2592    CALL                            1
                        2600    JUMP_FORWARD                    1 (to 2604)
                        2602    LOAD_CONST                      18: '0'
                        2604    STORE_FAST                      17: _var_var_28
                        2606    LOAD_GLOBAL                     79: NULL + len
                        2616    LOAD_FAST                       15: _var_var_26
                        2618    CALL                            1
                        2626    LOAD_CONST                      9: 2
                        2628    COMPARE_OP                      68 (>)
                        2632    POP_JUMP_IF_FALSE               10 (to 2654)
                        2634    LOAD_FAST                       15: _var_var_26
                        2636    LOAD_CONST                      9: 2
                        2638    BINARY_SUBSCR                   
                        2642    POP_JUMP_IF_NONE                5 (to 2654)
                        2644    LOAD_FAST                       15: _var_var_26
                        2646    LOAD_CONST                      9: 2
                        2648    BINARY_SUBSCR                   
                        2652    JUMP_FORWARD                    1 (to 2656)
                        2654    LOAD_CONST                      19: 4
                        2656    STORE_FAST                      18: _var_var_15
                        2658    LOAD_GLOBAL                     91: NULL + EnumFieldWidget
                        2668    LOAD_FAST                       16: _var_var_27
                        2670    LOAD_FAST                       17: _var_var_28
                        2672    LOAD_FAST                       18: _var_var_15
                        2674    CALL                            3
                        2682    STORE_FAST                      19: _var_var_29
                        2684    LOAD_FAST                       19: _var_var_29
                        2686    LOAD_ATTR                       92: field_added
                        2706    LOAD_ATTR                       41: connect
                        2726    LOAD_FAST                       0: self
                        2728    LOAD_ATTR                       95: _create_add_enum_callback
                        2748    LOAD_FAST                       19: _var_var_29
                        2750    CALL                            1
                        2758    CALL                            1
                        2766    POP_TOP                         
                        2768    LOAD_FAST                       19: _var_var_29
                        2770    LOAD_ATTR                       96: field_removed
                        2790    LOAD_ATTR                       41: connect
                        2810    LOAD_FAST                       0: self
                        2812    LOAD_ATTR                       98: remove_enum_field
                        2832    CALL                            1
                        2840    POP_TOP                         
                        2842    LOAD_FAST                       0: self
                        2844    LOAD_ATTR                       10: field_widgets
                        2864    LOAD_ATTR                       101: append
                        2884    LOAD_FAST                       19: _var_var_29
                        2886    CALL                            1
                        2894    POP_TOP                         
                        2896    LOAD_FAST                       0: self
                        2898    LOAD_ATTR                       70: fields_layout
                        2918    LOAD_ATTR                       49: addWidget
                        2938    LOAD_FAST                       19: _var_var_29
                        2940    CALL                            1
                        2948    POP_TOP                         
                        2950    JUMP_BACKWARD                   257 (to 2440)
                        2954    END_FOR                         
                        2956    JUMP_FORWARD                    16 (to 2990)
                        2958    LOAD_FAST                       0: self
                        2960    LOAD_ATTR                       103: add_enum_field
                        2980    CALL                            0
                        2988    POP_TOP                         
                        2990    LOAD_FAST                       12: _var_var_23
                        2992    LOAD_ATTR                       83: setLayout
                        3012    LOAD_FAST                       0: self
                        3014    LOAD_ATTR                       70: fields_layout
                        3034    CALL                            1
                        3042    POP_TOP                         
                        3044    LOAD_FAST                       6: _var_var_11
                        3046    LOAD_ATTR                       49: addWidget
                        3066    LOAD_FAST                       12: _var_var_23
                        3068    CALL                            1
                        3076    POP_TOP                         
                        3078    JUMP_FORWARD                    226 (to 3532)
                        3080    LOAD_FAST                       2: type_info
                        3082    LOAD_CONST                      9: 2
                        3084    BINARY_SUBSCR                   
                        3088    LOAD_CONST                      20: 'array'
                        3090    COMPARE_OP                      40 (==)
                        3094    POP_JUMP_IF_FALSE               218 (to 3532)
                        3096    LOAD_GLOBAL                     13: NULL + QtWidgets
                        3106    LOAD_ATTR                       26: QGroupBox
                        3126    LOAD_CONST                      21: 'Array Dimensions'
                        3128    CALL                            1
                        3136    STORE_FAST                      20: _var_var_30
                        3138    LOAD_GLOBAL                     13: NULL + QtWidgets
                        3148    LOAD_ATTR                       28: QHBoxLayout
                        3168    CALL                            0
                        3176    STORE_FAST                      21: _var_var_31
                        3178    LOAD_GLOBAL                     75: NULL + isinstance
                        3188    LOAD_FAST                       2: type_info
                        3190    LOAD_CONST                      13: 3
                        3192    BINARY_SUBSCR                   
                        3196    LOAD_GLOBAL                     60: list
                        3206    LOAD_GLOBAL                     76: tuple
                        3216    BUILD_TUPLE                     2
                        3218    CALL                            2
                        3226    POP_JUMP_IF_FALSE               5 (to 3238)
                        3228    LOAD_FAST                       2: type_info
                        3230    LOAD_CONST                      13: 3
                        3232    BINARY_SUBSCR                   
                        3236    JUMP_FORWARD                    1 (to 3240)
                        3238    BUILD_LIST                      0
                        3240    STORE_FAST                      22: _var_var_32
                        3242    LOAD_CONST                      22: ','
                        3244    LOAD_ATTR                       105: join
                        3264    LOAD_GLOBAL                     107: NULL + map
                        3274    LOAD_GLOBAL                     88: str
                        3284    LOAD_FAST                       22: _var_var_32
                        3286    CALL                            2
                        3294    CALL                            1
                        3302    STORE_FAST                      23: _var_var_33
                        3304    LOAD_GLOBAL                     13: NULL + QtWidgets
                        3314    LOAD_ATTR                       56: QLineEdit
                        3334    LOAD_FAST                       23: _var_var_33
                        3336    CALL                            1
                        3344    LOAD_FAST                       0: self
                        3346    STORE_ATTR                      54: array_edit
                        3356    LOAD_FAST                       0: self
                        3358    LOAD_ATTR                       108: array_edit
                        3378    LOAD_ATTR                       111: setPlaceholderText
                        3398    LOAD_CONST                      23: 'Enter dimensions separated by commas'
                        3400    CALL                            1
                        3408    POP_TOP                         
                        3410    LOAD_FAST                       21: _var_var_31
                        3412    LOAD_ATTR                       49: addWidget
                        3432    LOAD_FAST                       0: self
                        3434    LOAD_ATTR                       108: array_edit
                        3454    CALL                            1
                        3462    POP_TOP                         
                        3464    LOAD_FAST                       20: _var_var_30
                        3466    LOAD_ATTR                       83: setLayout
                        3486    LOAD_FAST                       21: _var_var_31
                        3488    CALL                            1
                        3496    POP_TOP                         
                        3498    LOAD_FAST                       6: _var_var_11
                        3500    LOAD_ATTR                       49: addWidget
                        3520    LOAD_FAST                       20: _var_var_30
                        3522    CALL                            1
                        3530    POP_TOP                         
                        3532    LOAD_FAST                       5: _var_var_10
                        3534    LOAD_ATTR                       83: setLayout
                        3554    LOAD_FAST                       6: _var_var_11
                        3556    CALL                            1
                        3564    POP_TOP                         
                        3566    LOAD_FAST                       4: _var_var_1
                        3568    LOAD_ATTR                       49: addWidget
                        3588    LOAD_FAST                       5: _var_var_10
                        3590    CALL                            1
                        3598    POP_TOP                         
                        3600    LOAD_FAST                       0: self
                        3602    LOAD_ATTR                       83: setLayout
                        3622    LOAD_FAST                       4: _var_var_1
                        3624    CALL                            1
                        3632    POP_TOP                         
                        3634    LOAD_CONST                      0: None
                        3636    NOP                             
                        3638    NOP                             
                        3640    NOP                             
                        3642    JUMP_FORWARD                    19 (to 3682)
                        3650    POP_TOP                         
                        3652    RETURN_CONST                    0: None
                        3654    PUSH_EXC_INFO                   
                        3656    PUSH_NULL                       
                        3658    LOAD_CONST                      24: '__pyarmor_exit_54594__'
                        3660    NOP                             
                        3662    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c*\x0e\x00\x00\x00\x00\x00\x00'
                        3664    CALL                            1
                        3672    POP_TOP                         
                        3674    RERAISE                         0
                        3676    COPY                            3
                        3678    POP_EXCEPT                      
                        3680    RERAISE                         1
                        3682    PUSH_NULL                       
                        3684    LOAD_CONST                      24: '__pyarmor_exit_54594__'
                        3686    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c*\x0e\x00\x00\x00\x00\x00\x00'
                        3688    BUILD_TUPLE                     1
                        3690    CALL_FUNCTION_EX                0
                        3692    POP_TOP                         
                        3694    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: add_struct_field
                    Qualified Name: ComplexTypeWidget.add_struct_field
                    Arg Count: 5
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'StructFieldWidget'
                        'field_added'
                        'connect'
                        '_create_add_struct_callback'
                        'field_removed'
                        'remove_struct_field'
                        'field_widgets'
                        'index'
                        'insert'
                        'fields_layout'
                        'insertWidget'
                        'append'
                        'addWidget'
                    [Locals+Names]
                        'self'
                        'type_str'
                        'name'
                        'size'
                        'after_widget'
                        '__assert_armored__'
                        '_var_var_29'
                        '_var_var_34'
                    [Constants]
                        None
                        '__pyarmor_assert_54595__'
                        '__pyarmor_enter_54596__'
                        b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        1
                        '__pyarmor_exit_54597__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54596__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + StructFieldWidget
                        38      LOAD_FAST                       1: type_str
                        40      LOAD_FAST                       2: name
                        42      LOAD_FAST                       3: size
                        44      CALL                            3
                        52      STORE_FAST                      6: _var_var_29
                        54      LOAD_FAST                       6: _var_var_29
                        56      LOAD_ATTR                       2: field_added
                        76      LOAD_ATTR                       5: connect
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       7: _create_add_struct_callback
                        118     LOAD_FAST                       6: _var_var_29
                        120     CALL                            1
                        128     CALL                            1
                        136     POP_TOP                         
                        138     LOAD_FAST                       6: _var_var_29
                        140     LOAD_ATTR                       8: field_removed
                        160     LOAD_ATTR                       5: connect
                        180     LOAD_FAST                       0: self
                        182     LOAD_ATTR                       10: remove_struct_field
                        202     CALL                            1
                        210     POP_TOP                         
                        212     LOAD_FAST                       4: after_widget
                        214     POP_JUMP_IF_FALSE               90 (to 396)
                        216     LOAD_FAST                       0: self
                        218     LOAD_ATTR                       12: field_widgets
                        238     LOAD_ATTR                       15: index
                        258     LOAD_FAST                       4: after_widget
                        260     CALL                            1
                        268     LOAD_CONST                      4: 1
                        270     BINARY_OP                       0 (+)
                        274     STORE_FAST                      7: _var_var_34
                        276     LOAD_FAST                       0: self
                        278     LOAD_ATTR                       12: field_widgets
                        298     LOAD_ATTR                       17: insert
                        318     LOAD_FAST                       7: _var_var_34
                        320     LOAD_FAST                       6: _var_var_29
                        322     CALL                            2
                        330     POP_TOP                         
                        332     LOAD_FAST                       0: self
                        334     LOAD_ATTR                       18: fields_layout
                        354     LOAD_ATTR                       21: insertWidget
                        374     LOAD_FAST                       7: _var_var_34
                        376     LOAD_CONST                      4: 1
                        378     BINARY_OP                       0 (+)
                        382     LOAD_FAST                       6: _var_var_29
                        384     CALL                            2
                        392     POP_TOP                         
                        394     JUMP_FORWARD                    54 (to 504)
                        396     LOAD_FAST                       0: self
                        398     LOAD_ATTR                       12: field_widgets
                        418     LOAD_ATTR                       23: append
                        438     LOAD_FAST                       6: _var_var_29
                        440     CALL                            1
                        448     POP_TOP                         
                        450     LOAD_FAST                       0: self
                        452     LOAD_ATTR                       18: fields_layout
                        472     LOAD_ATTR                       25: addWidget
                        492     LOAD_FAST                       6: _var_var_29
                        494     CALL                            1
                        502     POP_TOP                         
                        504     LOAD_CONST                      0: None
                        506     NOP                             
                        508     NOP                             
                        510     NOP                             
                        512     JUMP_FORWARD                    19 (to 552)
                        520     POP_TOP                         
                        522     RETURN_CONST                    0: None
                        524     PUSH_EXC_INFO                   
                        526     PUSH_NULL                       
                        528     LOAD_CONST                      5: '__pyarmor_exit_54597__'
                        530     NOP                             
                        532     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        534     CALL                            1
                        542     POP_TOP                         
                        544     RERAISE                         0
                        546     COPY                            3
                        548     POP_EXCEPT                      
                        550     RERAISE                         1
                        552     PUSH_NULL                       
                        554     LOAD_CONST                      5: '__pyarmor_exit_54597__'
                        556     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        558     BUILD_TUPLE                     1
                        560     CALL_FUNCTION_EX                0
                        562     POP_TOP                         
                        564     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: add_enum_field
                    Qualified Name: ComplexTypeWidget.add_enum_field
                    Arg Count: 5
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'EnumFieldWidget'
                        'field_added'
                        'connect'
                        '_create_add_enum_callback'
                        'field_removed'
                        'remove_enum_field'
                        'field_widgets'
                        'index'
                        'insert'
                        'fields_layout'
                        'insertWidget'
                        'append'
                        'addWidget'
                    [Locals+Names]
                        'self'
                        'name'
                        'value'
                        'size'
                        'after_widget'
                        '__assert_armored__'
                        '_var_var_29'
                        '_var_var_34'
                    [Constants]
                        None
                        '__pyarmor_assert_54598__'
                        '__pyarmor_enter_54599__'
                        b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        1
                        '__pyarmor_exit_54600__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54599__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + EnumFieldWidget
                        38      LOAD_FAST                       1: name
                        40      LOAD_FAST                       2: value
                        42      LOAD_FAST                       3: size
                        44      CALL                            3
                        52      STORE_FAST                      6: _var_var_29
                        54      LOAD_FAST                       6: _var_var_29
                        56      LOAD_ATTR                       2: field_added
                        76      LOAD_ATTR                       5: connect
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       7: _create_add_enum_callback
                        118     LOAD_FAST                       6: _var_var_29
                        120     CALL                            1
                        128     CALL                            1
                        136     POP_TOP                         
                        138     LOAD_FAST                       6: _var_var_29
                        140     LOAD_ATTR                       8: field_removed
                        160     LOAD_ATTR                       5: connect
                        180     LOAD_FAST                       0: self
                        182     LOAD_ATTR                       10: remove_enum_field
                        202     CALL                            1
                        210     POP_TOP                         
                        212     LOAD_FAST                       4: after_widget
                        214     POP_JUMP_IF_FALSE               90 (to 396)
                        216     LOAD_FAST                       0: self
                        218     LOAD_ATTR                       12: field_widgets
                        238     LOAD_ATTR                       15: index
                        258     LOAD_FAST                       4: after_widget
                        260     CALL                            1
                        268     LOAD_CONST                      4: 1
                        270     BINARY_OP                       0 (+)
                        274     STORE_FAST                      7: _var_var_34
                        276     LOAD_FAST                       0: self
                        278     LOAD_ATTR                       12: field_widgets
                        298     LOAD_ATTR                       17: insert
                        318     LOAD_FAST                       7: _var_var_34
                        320     LOAD_FAST                       6: _var_var_29
                        322     CALL                            2
                        330     POP_TOP                         
                        332     LOAD_FAST                       0: self
                        334     LOAD_ATTR                       18: fields_layout
                        354     LOAD_ATTR                       21: insertWidget
                        374     LOAD_FAST                       7: _var_var_34
                        376     LOAD_CONST                      4: 1
                        378     BINARY_OP                       0 (+)
                        382     LOAD_FAST                       6: _var_var_29
                        384     CALL                            2
                        392     POP_TOP                         
                        394     JUMP_FORWARD                    54 (to 504)
                        396     LOAD_FAST                       0: self
                        398     LOAD_ATTR                       12: field_widgets
                        418     LOAD_ATTR                       23: append
                        438     LOAD_FAST                       6: _var_var_29
                        440     CALL                            1
                        448     POP_TOP                         
                        450     LOAD_FAST                       0: self
                        452     LOAD_ATTR                       18: fields_layout
                        472     LOAD_ATTR                       25: addWidget
                        492     LOAD_FAST                       6: _var_var_29
                        494     CALL                            1
                        502     POP_TOP                         
                        504     LOAD_CONST                      0: None
                        506     NOP                             
                        508     NOP                             
                        510     NOP                             
                        512     JUMP_FORWARD                    19 (to 552)
                        520     POP_TOP                         
                        522     RETURN_CONST                    0: None
                        524     PUSH_EXC_INFO                   
                        526     PUSH_NULL                       
                        528     LOAD_CONST                      5: '__pyarmor_exit_54600__'
                        530     NOP                             
                        532     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        534     CALL                            1
                        542     POP_TOP                         
                        544     RERAISE                         0
                        546     COPY                            3
                        548     POP_EXCEPT                      
                        550     RERAISE                         1
                        552     PUSH_NULL                       
                        554     LOAD_CONST                      5: '__pyarmor_exit_54600__'
                        556     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xf2\x01\x00\x00\x00\x00\x00\x00'
                        558     BUILD_TUPLE                     1
                        560     CALL_FUNCTION_EX                0
                        562     POP_TOP                         
                        564     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: remove_struct_field
                    Qualified Name: ComplexTypeWidget.remove_struct_field
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'len'
                        'field_widgets'
                        'fields_layout'
                        'removeWidget'
                        'remove'
                        'deleteLater'
                    [Locals+Names]
                        'self'
                        'widget'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54601__'
                        '__pyarmor_enter_54602__'
                        b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        1
                        '__pyarmor_exit_54603__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54602__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + len
                        38      LOAD_FAST                       0: self
                        40      LOAD_ATTR                       2: field_widgets
                        60      CALL                            1
                        68      LOAD_CONST                      4: 1
                        70      COMPARE_OP                      68 (>)
                        74      POP_JUMP_IF_FALSE               70 (to 216)
                        76      LOAD_FAST                       0: self
                        78      LOAD_ATTR                       4: fields_layout
                        98      LOAD_ATTR                       7: removeWidget
                        118     LOAD_FAST                       1: widget
                        120     CALL                            1
                        128     POP_TOP                         
                        130     LOAD_FAST                       0: self
                        132     LOAD_ATTR                       2: field_widgets
                        152     LOAD_ATTR                       9: remove
                        172     LOAD_FAST                       1: widget
                        174     CALL                            1
                        182     POP_TOP                         
                        184     LOAD_FAST                       1: widget
                        186     LOAD_ATTR                       11: deleteLater
                        206     CALL                            0
                        214     POP_TOP                         
                        216     LOAD_CONST                      0: None
                        218     NOP                             
                        220     NOP                             
                        222     NOP                             
                        224     JUMP_FORWARD                    19 (to 264)
                        232     POP_TOP                         
                        234     RETURN_CONST                    0: None
                        236     PUSH_EXC_INFO                   
                        238     PUSH_NULL                       
                        240     LOAD_CONST                      5: '__pyarmor_exit_54603__'
                        242     NOP                             
                        244     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        246     CALL                            1
                        254     POP_TOP                         
                        256     RERAISE                         0
                        258     COPY                            3
                        260     POP_EXCEPT                      
                        262     RERAISE                         1
                        264     PUSH_NULL                       
                        266     LOAD_CONST                      5: '__pyarmor_exit_54603__'
                        268     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        270     BUILD_TUPLE                     1
                        272     CALL_FUNCTION_EX                0
                        274     POP_TOP                         
                        276     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: remove_enum_field
                    Qualified Name: ComplexTypeWidget.remove_enum_field
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'len'
                        'field_widgets'
                        'fields_layout'
                        'removeWidget'
                        'remove'
                        'deleteLater'
                    [Locals+Names]
                        'self'
                        'widget'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54604__'
                        '__pyarmor_enter_54605__'
                        b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        1
                        '__pyarmor_exit_54606__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54605__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + len
                        38      LOAD_FAST                       0: self
                        40      LOAD_ATTR                       2: field_widgets
                        60      CALL                            1
                        68      LOAD_CONST                      4: 1
                        70      COMPARE_OP                      68 (>)
                        74      POP_JUMP_IF_FALSE               70 (to 216)
                        76      LOAD_FAST                       0: self
                        78      LOAD_ATTR                       4: fields_layout
                        98      LOAD_ATTR                       7: removeWidget
                        118     LOAD_FAST                       1: widget
                        120     CALL                            1
                        128     POP_TOP                         
                        130     LOAD_FAST                       0: self
                        132     LOAD_ATTR                       2: field_widgets
                        152     LOAD_ATTR                       9: remove
                        172     LOAD_FAST                       1: widget
                        174     CALL                            1
                        182     POP_TOP                         
                        184     LOAD_FAST                       1: widget
                        186     LOAD_ATTR                       11: deleteLater
                        206     CALL                            0
                        214     POP_TOP                         
                        216     LOAD_CONST                      0: None
                        218     NOP                             
                        220     NOP                             
                        222     NOP                             
                        224     JUMP_FORWARD                    19 (to 264)
                        232     POP_TOP                         
                        234     RETURN_CONST                    0: None
                        236     PUSH_EXC_INFO                   
                        238     PUSH_NULL                       
                        240     LOAD_CONST                      5: '__pyarmor_exit_54606__'
                        242     NOP                             
                        244     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        246     CALL                            1
                        254     POP_TOP                         
                        256     RERAISE                         0
                        258     COPY                            3
                        260     POP_EXCEPT                      
                        262     RERAISE                         1
                        264     PUSH_NULL                       
                        266     LOAD_CONST                      5: '__pyarmor_exit_54606__'
                        268     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd2\x00\x00\x00\x00\x00\x00\x00'
                        270     BUILD_TUPLE                     1
                        272     CALL_FUNCTION_EX                0
                        274     POP_TOP                         
                        276     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: validate
                    Qualified Name: ComplexTypeWidget.validate
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'accepted'
                        'name_type_widget'
                        'validate'
                        'type_info'
                        'struct_name_edit'
                        'text'
                        'strip'
                        'enum_name_edit'
                        'field_widgets'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_35'
                    [Constants]
                        None
                        '__pyarmor_assert_54607__'
                        '__pyarmor_enter_54608__'
                        b'<COAddr>\x01\x00\x00\x1a\xfa\x01\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54609__'
                        True
                        False
                        2
                        'struct'
                        'enum'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54608__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xfa\x01\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: accepted
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      5: True
                        56      NOP                             
                        58      NOP                             
                        60      NOP                             
                        62      JUMP_FORWARD                    248 (to 560)
                        70      POP_TOP                         
                        72      RETURN_CONST                    5: True
                        74      LOAD_FAST                       0: self
                        76      LOAD_ATTR                       2: name_type_widget
                        96      LOAD_ATTR                       5: validate
                        116     CALL                            0
                        124     POP_JUMP_IF_TRUE                11 (to 148)
                        126     NOP                             
                        128     LOAD_CONST                      6: False
                        130     NOP                             
                        132     NOP                             
                        134     NOP                             
                        136     JUMP_FORWARD                    211 (to 560)
                        144     POP_TOP                         
                        146     RETURN_CONST                    6: False
                        148     LOAD_FAST                       0: self
                        150     LOAD_ATTR                       6: type_info
                        170     LOAD_CONST                      7: 2
                        172     BINARY_SUBSCR                   
                        176     LOAD_CONST                      8: 'struct'
                        178     COMPARE_OP                      40 (==)
                        182     POP_JUMP_IF_FALSE               51 (to 286)
                        184     LOAD_FAST                       0: self
                        186     LOAD_ATTR                       8: struct_name_edit
                        206     LOAD_ATTR                       11: text
                        226     CALL                            0
                        234     LOAD_ATTR                       13: strip
                        254     CALL                            0
                        262     POP_JUMP_IF_TRUE                80 (to 424)
                        264     NOP                             
                        266     LOAD_CONST                      6: False
                        268     NOP                             
                        270     NOP                             
                        272     NOP                             
                        274     JUMP_FORWARD                    142 (to 560)
                        282     POP_TOP                         
                        284     RETURN_CONST                    6: False
                        286     LOAD_FAST                       0: self
                        288     LOAD_ATTR                       6: type_info
                        308     LOAD_CONST                      7: 2
                        310     BINARY_SUBSCR                   
                        314     LOAD_CONST                      9: 'enum'
                        316     COMPARE_OP                      40 (==)
                        320     POP_JUMP_IF_FALSE               51 (to 424)
                        322     LOAD_FAST                       0: self
                        324     LOAD_ATTR                       14: enum_name_edit
                        344     LOAD_ATTR                       11: text
                        364     CALL                            0
                        372     LOAD_ATTR                       13: strip
                        392     CALL                            0
                        400     POP_JUMP_IF_TRUE                11 (to 424)
                        402     NOP                             
                        404     LOAD_CONST                      6: False
                        406     NOP                             
                        408     NOP                             
                        410     NOP                             
                        412     JUMP_FORWARD                    73 (to 560)
                        420     POP_TOP                         
                        422     RETURN_CONST                    6: False
                        424     LOAD_FAST                       0: self
                        426     LOAD_ATTR                       16: field_widgets
                        446     GET_ITER                        
                        448     FOR_ITER                        29 (to 508)
                        452     STORE_FAST                      2: _var_var_35
                        454     LOAD_FAST                       2: _var_var_35
                        456     LOAD_ATTR                       5: validate
                        476     CALL                            0
                        484     POP_JUMP_IF_FALSE               1 (to 488)
                        486     JUMP_BACKWARD                   20 (to 448)
                        488     POP_TOP                         
                        490     LOAD_CONST                      6: False
                        492     NOP                             
                        494     NOP                             
                        496     NOP                             
                        498     JUMP_FORWARD                    30 (to 560)
                        506     POP_TOP                         
                        508     RETURN_CONST                    6: False
                        510     END_FOR                         
                        512     LOAD_CONST                      5: True
                        514     NOP                             
                        516     NOP                             
                        518     NOP                             
                        520     JUMP_FORWARD                    19 (to 560)
                        528     POP_TOP                         
                        530     RETURN_CONST                    5: True
                        532     PUSH_EXC_INFO                   
                        534     PUSH_NULL                       
                        536     LOAD_CONST                      4: '__pyarmor_exit_54609__'
                        538     NOP                             
                        540     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xfa\x01\x00\x00\x00\x00\x00\x00'
                        542     CALL                            1
                        550     POP_TOP                         
                        552     RERAISE                         0
                        554     COPY                            3
                        556     POP_EXCEPT                      
                        558     RERAISE                         1
                        560     PUSH_NULL                       
                        562     LOAD_CONST                      4: '__pyarmor_exit_54609__'
                        564     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xfa\x01\x00\x00\x00\x00\x00\x00'
                        566     BUILD_TUPLE                     1
                        568     CALL_FUNCTION_EX                0
                        570     POP_TOP                         
                        572     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: accepted_state_change
                    Qualified Name: ComplexTypeWidget.accepted_state_change
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtCore'
                        'Qt'
                        'Checked'
                        'accepted'
                        'name_type_widget'
                        'setEnabled'
                        'field_widgets'
                        'hasattr'
                        'array_edit'
                        'struct_name_edit'
                        'enum_name_edit'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                        '_var_var_35'
                    [Constants]
                        None
                        '__pyarmor_assert_54610__'
                        '__pyarmor_enter_54611__'
                        b'<COAddr>\x01\x00\x00\x1a"\x02\x00\x00\x00\x00\x00\x00'
                        'array_edit'
                        'struct_name_edit'
                        'enum_name_edit'
                        '__pyarmor_exit_54612__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54611__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a"\x02\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_FAST                       1: state
                        30      LOAD_GLOBAL                     0: QtCore
                        40      LOAD_ATTR                       2: Qt
                        60      LOAD_ATTR                       4: Checked
                        80      COMPARE_OP                      40 (==)
                        84      LOAD_FAST                       0: self
                        86      STORE_ATTR                      3: accepted
                        96      LOAD_FAST                       0: self
                        98      LOAD_ATTR                       8: name_type_widget
                        118     LOAD_ATTR                       11: setEnabled
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       6: accepted
                        160     CALL                            1
                        168     POP_TOP                         
                        170     LOAD_FAST                       0: self
                        172     LOAD_ATTR                       12: field_widgets
                        192     GET_ITER                        
                        194     FOR_ITER                        29 (to 254)
                        198     STORE_FAST                      3: _var_var_35
                        200     LOAD_FAST                       3: _var_var_35
                        202     LOAD_ATTR                       11: setEnabled
                        222     LOAD_FAST                       0: self
                        224     LOAD_ATTR                       6: accepted
                        244     CALL                            1
                        252     POP_TOP                         
                        254     JUMP_BACKWARD                   31 (to 194)
                        256     END_FOR                         
                        258     LOAD_GLOBAL                     15: NULL + hasattr
                        268     LOAD_FAST                       0: self
                        270     LOAD_CONST                      4: 'array_edit'
                        272     CALL                            2
                        280     POP_JUMP_IF_FALSE               37 (to 356)
                        282     LOAD_FAST                       0: self
                        284     LOAD_ATTR                       16: array_edit
                        304     LOAD_ATTR                       11: setEnabled
                        324     LOAD_FAST                       0: self
                        326     LOAD_ATTR                       6: accepted
                        346     CALL                            1
                        354     POP_TOP                         
                        356     LOAD_GLOBAL                     15: NULL + hasattr
                        366     LOAD_FAST                       0: self
                        368     LOAD_CONST                      5: 'struct_name_edit'
                        370     CALL                            2
                        378     POP_JUMP_IF_FALSE               37 (to 454)
                        380     LOAD_FAST                       0: self
                        382     LOAD_ATTR                       18: struct_name_edit
                        402     LOAD_ATTR                       11: setEnabled
                        422     LOAD_FAST                       0: self
                        424     LOAD_ATTR                       6: accepted
                        444     CALL                            1
                        452     POP_TOP                         
                        454     LOAD_GLOBAL                     15: NULL + hasattr
                        464     LOAD_FAST                       0: self
                        466     LOAD_CONST                      6: 'enum_name_edit'
                        468     CALL                            2
                        476     POP_JUMP_IF_FALSE               37 (to 552)
                        478     LOAD_FAST                       0: self
                        480     LOAD_ATTR                       20: enum_name_edit
                        500     LOAD_ATTR                       11: setEnabled
                        520     LOAD_FAST                       0: self
                        522     LOAD_ATTR                       6: accepted
                        542     CALL                            1
                        550     POP_TOP                         
                        552     LOAD_CONST                      0: None
                        554     NOP                             
                        556     NOP                             
                        558     NOP                             
                        560     JUMP_FORWARD                    19 (to 600)
                        568     POP_TOP                         
                        570     RETURN_CONST                    0: None
                        572     PUSH_EXC_INFO                   
                        574     PUSH_NULL                       
                        576     LOAD_CONST                      7: '__pyarmor_exit_54612__'
                        578     NOP                             
                        580     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a"\x02\x00\x00\x00\x00\x00\x00'
                        582     CALL                            1
                        590     POP_TOP                         
                        592     RERAISE                         0
                        594     COPY                            3
                        596     POP_EXCEPT                      
                        598     RERAISE                         1
                        600     PUSH_NULL                       
                        602     LOAD_CONST                      7: '__pyarmor_exit_54612__'
                        604     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a"\x02\x00\x00\x00\x00\x00\x00'
                        606     BUILD_TUPLE                     1
                        608     CALL_FUNCTION_EX                0
                        610     POP_TOP                         
                        612     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: get_type_info
                    Qualified Name: ComplexTypeWidget.get_type_info
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'accepted'
                        'name_type_widget'
                        'get_content'
                        'type_info'
                        'struct_name_edit'
                        'text'
                        'strip'
                        'field_widgets'
                        'enum_name_edit'
                        'append'
                        'array_edit'
                        'split'
                        'int'
                        'ValueError'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_27'
                        '_var_var_36'
                        '_var_var_37'
                        '_var_var_20'
                        '_var_var_22'
                        '_var_var_38'
                        '_var_var_24'
                        '_var_var_39'
                        '_var_var_40'
                        '_var_var_28'
                        '_var_var_15'
                        '_var_var_41'
                        '_var_var_32'
                    [Constants]
                        None
                        '__pyarmor_assert_54613__'
                        '__pyarmor_enter_54614__'
                        b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54615__'
                        ''
                        1
                        2
                        'struct'
                        3
                        'enum'
                        'array'
                        ','
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54614__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: accepted
                        50      POP_JUMP_IF_TRUE                11 (to 74)
                        52      NOP                             
                        54      LOAD_CONST                      0: None
                        56      NOP                             
                        58      NOP                             
                        60      JUMP_FORWARD                    497 (to 1058)
                        70      POP_TOP                         
                        72      RETURN_CONST                    0: None
                        74      LOAD_FAST                       0: self
                        76      LOAD_ATTR                       2: name_type_widget
                        96      LOAD_ATTR                       5: get_content
                        116     CALL                            0
                        124     UNPACK_SEQUENCE                 2
                        128     STORE_FAST                      2: _var_var_27
                        130     STORE_FAST                      3: _var_var_36
                        132     LOAD_FAST                       3: _var_var_36
                        134     POP_JUMP_IF_NONE                2 (to 140)
                        136     LOAD_FAST                       3: _var_var_36
                        138     JUMP_FORWARD                    1 (to 142)
                        140     LOAD_CONST                      5: ''
                        142     LOAD_FAST                       2: _var_var_27
                        144     POP_JUMP_IF_NONE                2 (to 150)
                        146     LOAD_FAST                       2: _var_var_27
                        148     JUMP_FORWARD                    14 (to 178)
                        150     LOAD_FAST                       0: self
                        152     LOAD_ATTR                       6: type_info
                        172     LOAD_CONST                      6: 1
                        174     BINARY_SUBSCR                   
                        178     LOAD_FAST                       0: self
                        180     LOAD_ATTR                       6: type_info
                        200     LOAD_CONST                      7: 2
                        202     BINARY_SUBSCR                   
                        206     BUILD_MAP                       0
                        208     BUILD_LIST                      4
                        210     STORE_FAST                      4: _var_var_37
                        212     LOAD_FAST                       0: self
                        214     LOAD_ATTR                       6: type_info
                        234     LOAD_CONST                      7: 2
                        236     BINARY_SUBSCR                   
                        240     LOAD_CONST                      8: 'struct'
                        242     COMPARE_OP                      40 (==)
                        246     POP_JUMP_IF_FALSE               104 (to 456)
                        248     LOAD_FAST                       0: self
                        250     LOAD_ATTR                       8: struct_name_edit
                        270     LOAD_ATTR                       11: text
                        290     CALL                            0
                        298     LOAD_ATTR                       13: strip
                        318     CALL                            0
                        326     STORE_FAST                      5: _var_var_20
                        328     LOAD_FAST                       0: self
                        330     LOAD_ATTR                       14: field_widgets
                        350     GET_ITER                        
                        352     LOAD_FAST_AND_CLEAR             6: _var_var_22
                        354     SWAP                            2
                        356     BUILD_LIST                      0
                        358     SWAP                            2
                        360     FOR_ITER                        35 (to 432)
                        364     STORE_FAST                      6: _var_var_22
                        366     LOAD_FAST                       6: _var_var_22
                        368     LOAD_ATTR                       5: get_content
                        388     CALL                            0
                        396     POP_JUMP_IF_TRUE                1 (to 400)
                        398     JUMP_BACKWARD                   20 (to 360)
                        400     LOAD_FAST                       6: _var_var_22
                        402     LOAD_ATTR                       5: get_content
                        422     CALL                            0
                        430     LIST_APPEND                     2
                        432     JUMP_BACKWARD                   37 (to 360)
                        434     END_FOR                         
                        436     STORE_FAST                      7: _var_var_38
                        438     STORE_FAST                      6: _var_var_22
                        440     LOAD_FAST                       5: _var_var_20
                        442     LOAD_FAST                       7: _var_var_38
                        444     BUILD_MAP                       1
                        446     LOAD_FAST                       4: _var_var_37
                        448     LOAD_CONST                      9: 3
                        450     STORE_SUBSCR                    
                        454     JUMP_FORWARD                    233 (to 922)
                        456     LOAD_FAST                       0: self
                        458     LOAD_ATTR                       6: type_info
                        478     LOAD_CONST                      7: 2
                        480     BINARY_SUBSCR                   
                        484     LOAD_CONST                      10: 'enum'
                        486     COMPARE_OP                      40 (==)
                        490     POP_JUMP_IF_FALSE               114 (to 720)
                        492     LOAD_FAST                       0: self
                        494     LOAD_ATTR                       16: enum_name_edit
                        514     LOAD_ATTR                       11: text
                        534     CALL                            0
                        542     LOAD_ATTR                       13: strip
                        562     CALL                            0
                        570     STORE_FAST                      8: _var_var_24
                        572     BUILD_LIST                      0
                        574     STORE_FAST                      9: _var_var_39
                        576     LOAD_FAST                       0: self
                        578     LOAD_ATTR                       14: field_widgets
                        598     GET_ITER                        
                        600     FOR_ITER                        47 (to 696)
                        604     STORE_FAST                      6: _var_var_22
                        606     LOAD_FAST                       6: _var_var_22
                        608     LOAD_ATTR                       5: get_content
                        628     CALL                            0
                        636     STORE_FAST                      10: _var_var_40
                        638     LOAD_FAST                       10: _var_var_40
                        640     POP_JUMP_IF_TRUE                1 (to 644)
                        642     JUMP_BACKWARD                   22 (to 600)
                        644     LOAD_FAST                       10: _var_var_40
                        646     UNPACK_SEQUENCE                 3
                        650     STORE_FAST                      2: _var_var_27
                        652     STORE_FAST                      11: _var_var_28
                        654     STORE_FAST                      12: _var_var_15
                        656     LOAD_FAST                       9: _var_var_39
                        658     LOAD_ATTR                       19: append
                        678     LOAD_FAST                       2: _var_var_27
                        680     LOAD_FAST                       11: _var_var_28
                        682     LOAD_FAST                       12: _var_var_15
                        684     BUILD_LIST                      3
                        686     CALL                            1
                        694     POP_TOP                         
                        696     JUMP_BACKWARD                   49 (to 600)
                        698     END_FOR                         
                        700     LOAD_FAST                       9: _var_var_39
                        702     POP_JUMP_IF_FALSE               109 (to 922)
                        704     LOAD_FAST                       8: _var_var_24
                        706     LOAD_FAST                       9: _var_var_39
                        708     BUILD_MAP                       1
                        710     LOAD_FAST                       4: _var_var_37
                        712     LOAD_CONST                      9: 3
                        714     STORE_SUBSCR                    
                        718     JUMP_FORWARD                    101 (to 922)
                        720     LOAD_FAST                       0: self
                        722     LOAD_ATTR                       6: type_info
                        742     LOAD_CONST                      7: 2
                        744     BINARY_SUBSCR                   
                        748     LOAD_CONST                      11: 'array'
                        750     COMPARE_OP                      40 (==)
                        754     POP_JUMP_IF_FALSE               83 (to 922)
                        756     NOP                             
                        758     LOAD_FAST                       0: self
                        760     LOAD_ATTR                       20: array_edit
                        780     LOAD_ATTR                       11: text
                        800     CALL                            0
                        808     LOAD_ATTR                       23: split
                        828     LOAD_CONST                      12: ','
                        830     CALL                            1
                        838     GET_ITER                        
                        840     LOAD_FAST_AND_CLEAR             13: _var_var_41
                        842     SWAP                            2
                        844     BUILD_LIST                      0
                        846     SWAP                            2
                        848     FOR_ITER                        27 (to 904)
                        852     STORE_FAST                      13: _var_var_41
                        854     LOAD_GLOBAL                     25: NULL + int
                        864     LOAD_FAST                       13: _var_var_41
                        866     LOAD_ATTR                       13: strip
                        886     CALL                            0
                        894     CALL                            1
                        902     LIST_APPEND                     2
                        904     JUMP_BACKWARD                   29 (to 848)
                        906     END_FOR                         
                        908     STORE_FAST                      14: _var_var_32
                        910     STORE_FAST                      13: _var_var_41
                        912     LOAD_FAST                       14: _var_var_32
                        914     LOAD_FAST                       4: _var_var_37
                        916     LOAD_CONST                      9: 3
                        918     STORE_SUBSCR                    
                        922     LOAD_FAST                       4: _var_var_37
                        924     NOP                             
                        926     NOP                             
                        928     NOP                             
                        930     JUMP_FORWARD                    63 (to 1058)
                        932     CALL                            1
                        940     POP_TOP                         
                        942     RETURN_VALUE                    
                        944     SWAP                            2
                        946     POP_TOP                         
                        948     SWAP                            2
                        950     STORE_FAST                      6: _var_var_22
                        952     RERAISE                         0
                        954     SWAP                            2
                        956     POP_TOP                         
                        958     SWAP                            2
                        960     STORE_FAST                      13: _var_var_41
                        962     RERAISE                         0
                        964     PUSH_EXC_INFO                   
                        966     LOAD_GLOBAL                     26: ValueError
                        976     CHECK_EXC_MATCH                 
                        978     POP_JUMP_IF_FALSE               21 (to 1022)
                        980     POP_TOP                         
                        982     LOAD_FAST                       0: self
                        984     LOAD_ATTR                       6: type_info
                        1004    LOAD_CONST                      9: 3
                        1006    BINARY_SUBSCR                   
                        1010    LOAD_FAST                       4: _var_var_37
                        1012    LOAD_CONST                      9: 3
                        1014    STORE_SUBSCR                    
                        1018    POP_EXCEPT                      
                        1020    JUMP_BACKWARD                   50 (to 922)
                        1022    RERAISE                         0
                        1024    COPY                            3
                        1026    POP_EXCEPT                      
                        1028    RERAISE                         1
                        1030    PUSH_EXC_INFO                   
                        1032    PUSH_NULL                       
                        1034    LOAD_CONST                      4: '__pyarmor_exit_54615__'
                        1036    NOP                             
                        1038    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
                        1040    CALL                            1
                        1048    POP_TOP                         
                        1050    RERAISE                         0
                        1052    COPY                            3
                        1054    POP_EXCEPT                      
                        1056    RERAISE                         1
                        1058    PUSH_NULL                       
                        1060    LOAD_CONST                      4: '__pyarmor_exit_54615__'
                        1062    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
                        1064    BUILD_TUPLE                     1
                        1066    CALL_FUNCTION_EX                0
                        1068    POP_TOP                         
                        1070    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: _create_add_enum_callback
                    Qualified Name: ComplexTypeWidget._create_add_enum_callback
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        'self'
                        'widget'
                        '__assert_armored__'
                        '_var_var_42'
                    [Constants]
                        'Create a callback function for adding an enum field after the specified widget'
                        '__pyarmor_assert_54616__'
                        '__pyarmor_enter_54617__'
                        b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        [Code]
                            File Name: <frozen ..recopilot_qt>
                            Object Name: callback
                            Qualified Name: ComplexTypeWidget._create_add_enum_callback.<locals>.callback
                            Arg Count: 0
                            Pos Only Arg Count: 0
                            KW Only Arg Count: 0
                            Stack Size: 5
                            Flags: 0x20000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_PYARMOR_OBFUSCATED)
                            [Names]
                                'add_enum_field'
                            [Locals+Names]
                                '__assert_armored__'
                                'self'
                                'widget'
                            [Constants]
                                None
                                '__pyarmor_assert_54619__'
                                '__pyarmor_enter_54620__'
                                b'<COAddr>\x01\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                (
                                    'after_widget'
                                )
                                '__pyarmor_exit_54621__'
                            [Disassembly]
                                0       COPY_FREE_VARS                  2
                                2       NOP                             
                                4       NOP                             
                                6       PUSH_NULL                       
                                8       LOAD_CONST                      2: '__pyarmor_enter_54620__'
                                10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                12      BUILD_TUPLE                     1
                                14      CALL_FUNCTION_EX                0
                                16      POP_TOP                         
                                18      RESUME                          0
                                20      NOP                             
                                22      NOP                             
                                24      NOP                             
                                26      NOP                             
                                28      NOP                             
                                30      LOAD_DEREF                      1: self
                                32      LOAD_ATTR                       1: add_enum_field
                                52      LOAD_DEREF                      2: widget
                                54      KW_NAMES                        4: ('after_widget',)
                                56      CALL                            1
                                64      POP_TOP                         
                                66      LOAD_CONST                      0: None
                                68      NOP                             
                                70      NOP                             
                                72      NOP                             
                                74      JUMP_FORWARD                    19 (to 114)
                                82      POP_TOP                         
                                84      RETURN_CONST                    0: None
                                86      PUSH_EXC_INFO                   
                                88      PUSH_NULL                       
                                90      LOAD_CONST                      5: '__pyarmor_exit_54621__'
                                92      NOP                             
                                94      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                96      CALL                            1
                                104     POP_TOP                         
                                106     RERAISE                         0
                                108     COPY                            3
                                110     POP_EXCEPT                      
                                112     RERAISE                         1
                                114     PUSH_NULL                       
                                116     LOAD_CONST                      5: '__pyarmor_exit_54621__'
                                118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                120     BUILD_TUPLE                     1
                                122     CALL_FUNCTION_EX                0
                                124     POP_TOP                         
                                126     RETURN_VALUE                    
                        '__pyarmor_exit_54618__'
                    [Disassembly]
                        0       MAKE_CELL                       0: self
                        2       MAKE_CELL                       1: widget
                        4       NOP                             
                        6       NOP                             
                        8       PUSH_NULL                       
                        10      LOAD_CONST                      2: '__pyarmor_enter_54617__'
                        12      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        14      BUILD_TUPLE                     1
                        16      CALL_FUNCTION_EX                0
                        18      POP_TOP                         
                        20      RESUME                          0
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      NOP                             
                        32      LOAD_CLOSURE                    0: self
                        34      LOAD_CLOSURE                    1: widget
                        36      BUILD_TUPLE                     2
                        38      LOAD_CONST                      4: <CODE> callback
                        40      MAKE_FUNCTION                   8
                        42      STORE_FAST                      3: _var_var_42
                        44      LOAD_FAST                       3: _var_var_42
                        46      NOP                             
                        48      NOP                             
                        50      NOP                             
                        52      JUMP_FORWARD                    20 (to 94)
                        54      CALL                            1
                        62      POP_TOP                         
                        64      RETURN_VALUE                    
                        66      PUSH_EXC_INFO                   
                        68      PUSH_NULL                       
                        70      LOAD_CONST                      5: '__pyarmor_exit_54618__'
                        72      NOP                             
                        74      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        76      CALL                            1
                        84      POP_TOP                         
                        86      RERAISE                         0
                        88      COPY                            3
                        90      POP_EXCEPT                      
                        92      RERAISE                         1
                        94      PUSH_NULL                       
                        96      LOAD_CONST                      5: '__pyarmor_exit_54618__'
                        98      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        100     BUILD_TUPLE                     1
                        102     CALL_FUNCTION_EX                0
                        104     POP_TOP                         
                        106     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: _create_add_struct_callback
                    Qualified Name: ComplexTypeWidget._create_add_struct_callback
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                    [Locals+Names]
                        'self'
                        'widget'
                        '__assert_armored__'
                        '_var_var_42'
                    [Constants]
                        'Create a callback function for adding a struct field after the specified widget'
                        '__pyarmor_assert_54622__'
                        '__pyarmor_enter_54623__'
                        b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        [Code]
                            File Name: <frozen ..recopilot_qt>
                            Object Name: callback
                            Qualified Name: ComplexTypeWidget._create_add_struct_callback.<locals>.callback
                            Arg Count: 0
                            Pos Only Arg Count: 0
                            KW Only Arg Count: 0
                            Stack Size: 5
                            Flags: 0x20000013 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_PYARMOR_OBFUSCATED)
                            [Names]
                                'add_struct_field'
                            [Locals+Names]
                                '__assert_armored__'
                                'self'
                                'widget'
                            [Constants]
                                None
                                '__pyarmor_assert_54625__'
                                '__pyarmor_enter_54626__'
                                b'<COAddr>\x03\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                (
                                    'after_widget'
                                )
                                '__pyarmor_exit_54627__'
                            [Disassembly]
                                0       COPY_FREE_VARS                  2
                                2       NOP                             
                                4       NOP                             
                                6       PUSH_NULL                       
                                8       LOAD_CONST                      2: '__pyarmor_enter_54626__'
                                10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                12      BUILD_TUPLE                     1
                                14      CALL_FUNCTION_EX                0
                                16      POP_TOP                         
                                18      RESUME                          0
                                20      NOP                             
                                22      NOP                             
                                24      NOP                             
                                26      NOP                             
                                28      NOP                             
                                30      LOAD_DEREF                      1: self
                                32      LOAD_ATTR                       1: add_struct_field
                                52      LOAD_DEREF                      2: widget
                                54      KW_NAMES                        4: ('after_widget',)
                                56      CALL                            1
                                64      POP_TOP                         
                                66      LOAD_CONST                      0: None
                                68      NOP                             
                                70      NOP                             
                                72      NOP                             
                                74      JUMP_FORWARD                    19 (to 114)
                                82      POP_TOP                         
                                84      RETURN_CONST                    0: None
                                86      PUSH_EXC_INFO                   
                                88      PUSH_NULL                       
                                90      LOAD_CONST                      5: '__pyarmor_exit_54627__'
                                92      NOP                             
                                94      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                96      CALL                            1
                                104     POP_TOP                         
                                106     RERAISE                         0
                                108     COPY                            3
                                110     POP_EXCEPT                      
                                112     RERAISE                         1
                                114     PUSH_NULL                       
                                116     LOAD_CONST                      5: '__pyarmor_exit_54627__'
                                118     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c:\x00\x00\x00\x00\x00\x00\x00'
                                120     BUILD_TUPLE                     1
                                122     CALL_FUNCTION_EX                0
                                124     POP_TOP                         
                                126     RETURN_VALUE                    
                        '__pyarmor_exit_54624__'
                    [Disassembly]
                        0       MAKE_CELL                       0: self
                        2       MAKE_CELL                       1: widget
                        4       NOP                             
                        6       NOP                             
                        8       PUSH_NULL                       
                        10      LOAD_CONST                      2: '__pyarmor_enter_54623__'
                        12      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        14      BUILD_TUPLE                     1
                        16      CALL_FUNCTION_EX                0
                        18      POP_TOP                         
                        20      RESUME                          0
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      NOP                             
                        32      LOAD_CLOSURE                    0: self
                        34      LOAD_CLOSURE                    1: widget
                        36      BUILD_TUPLE                     2
                        38      LOAD_CONST                      4: <CODE> callback
                        40      MAKE_FUNCTION                   8
                        42      STORE_FAST                      3: _var_var_42
                        44      LOAD_FAST                       3: _var_var_42
                        46      NOP                             
                        48      NOP                             
                        50      NOP                             
                        52      JUMP_FORWARD                    20 (to 94)
                        54      CALL                            1
                        62      POP_TOP                         
                        64      RETURN_VALUE                    
                        66      PUSH_EXC_INFO                   
                        68      PUSH_NULL                       
                        70      LOAD_CONST                      5: '__pyarmor_exit_54624__'
                        72      NOP                             
                        74      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        76      CALL                            1
                        84      POP_TOP                         
                        86      RERAISE                         0
                        88      COPY                            3
                        90      POP_EXCEPT                      
                        92      RERAISE                         1
                        94      PUSH_NULL                       
                        96      LOAD_CONST                      5: '__pyarmor_exit_54624__'
                        98      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1e$\x00\x00\x00\x00\x00\x00\x00'
                        100     BUILD_TUPLE                     1
                        102     CALL_FUNCTION_EX                0
                        104     POP_TOP                         
                        106     RETURN_VALUE                    
                '__pyarmor_exit_54591__'
                (
                    ''
                    ''
                    ''
                    None
                )
                (
                    ''
                    ''
                    4
                    None
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'ComplexTypeWidget'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54590__'
                18      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$`\x00\x00\x00\x00\x00\x00\x00'
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
                48      LOAD_CONST                      15: ('', '', '', None)
                50      LOAD_CONST                      5: <CODE> add_struct_field
                52      MAKE_FUNCTION                   1
                54      STORE_NAME                      5: add_struct_field
                56      LOAD_CONST                      16: ('', '', 4, None)
                58      LOAD_CONST                      6: <CODE> add_enum_field
                60      MAKE_FUNCTION                   1
                62      STORE_NAME                      6: add_enum_field
                64      LOAD_CONST                      7: <CODE> remove_struct_field
                66      MAKE_FUNCTION                   0
                68      STORE_NAME                      7: remove_struct_field
                70      LOAD_CONST                      8: <CODE> remove_enum_field
                72      MAKE_FUNCTION                   0
                74      STORE_NAME                      8: remove_enum_field
                76      LOAD_CONST                      9: <CODE> validate
                78      MAKE_FUNCTION                   0
                80      STORE_NAME                      9: validate
                82      LOAD_CONST                      10: <CODE> accepted_state_change
                84      MAKE_FUNCTION                   0
                86      STORE_NAME                      10: accepted_state_change
                88      LOAD_CONST                      11: <CODE> get_type_info
                90      MAKE_FUNCTION                   0
                92      STORE_NAME                      11: get_type_info
                94      LOAD_CONST                      12: <CODE> _create_add_enum_callback
                96      MAKE_FUNCTION                   0
                98      STORE_NAME                      12: _create_add_enum_callback
                100     LOAD_CONST                      13: <CODE> _create_add_struct_callback
                102     MAKE_FUNCTION                   0
                104     STORE_NAME                      13: _create_add_struct_callback
                106     LOAD_CLOSURE                    0: __class__
                108     COPY                            1
                110     STORE_NAME                      14: __classcell__
                112     NOP                             
                114     NOP                             
                116     NOP                             
                118     JUMP_FORWARD                    20 (to 160)
                122     POP_TOP                         
                124     LOAD_CLOSURE                    0: __class__
                126     COPY                            1
                128     STORE_NAME                      14: __classcell__
                130     RETURN_VALUE                    
                132     PUSH_EXC_INFO                   
                134     PUSH_NULL                       
                136     LOAD_CONST                      14: '__pyarmor_exit_54591__'
                138     NOP                             
                140     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$`\x00\x00\x00\x00\x00\x00\x00'
                142     CALL                            1
                150     POP_TOP                         
                152     RERAISE                         0
                154     COPY                            3
                156     POP_EXCEPT                      
                158     RERAISE                         1
                160     PUSH_NULL                       
                162     LOAD_CONST                      14: '__pyarmor_exit_54591__'
                164     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$`\x00\x00\x00\x00\x00\x00\x00'
                166     BUILD_TUPLE                     1
                168     CALL_FUNCTION_EX                0
                170     POP_TOP                         
                172     RETURN_VALUE                    
        'ComplexTypeWidget'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: UserConfirmForm
            Qualified Name: UserConfirmForm
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
                'OnCreate'
                'PopulateForm'
                'validate_fields'
                'on_accept_clicked'
                'on_cancel_clicked'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'UserConfirmForm'
                '__pyarmor_assert_54628__'
                '__pyarmor_enter_54629__'
                b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: UserConfirmForm.__init__
                    Arg Count: 6
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'UserConfirmForm'
                        '__init__'
                        'ea'
                        'task_tag'
                        'prompt'
                        'response_raw'
                        'response'
                        'widgets'
                    [Locals+Names]
                        'self'
                        'ea'
                        'task_tag'
                        'prompt'
                        'response_raw'
                        'response'
                        '__assert_armored__'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54631__'
                        '__pyarmor_enter_54632__'
                        b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54633__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54632__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: UserConfirmForm
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_FAST                       1: ea
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: ea
                        80      LOAD_FAST                       2: task_tag
                        82      LOAD_FAST                       0: self
                        84      STORE_ATTR                      4: task_tag
                        94      LOAD_FAST                       3: prompt
                        96      LOAD_FAST                       0: self
                        98      STORE_ATTR                      5: prompt
                        108     LOAD_FAST                       4: response_raw
                        110     LOAD_FAST                       0: self
                        112     STORE_ATTR                      6: response_raw
                        122     LOAD_FAST                       5: response
                        124     LOAD_FAST                       0: self
                        126     STORE_ATTR                      7: response
                        136     BUILD_MAP                       0
                        138     LOAD_FAST                       0: self
                        140     STORE_ATTR                      8: widgets
                        150     LOAD_CONST                      0: None
                        152     NOP                             
                        154     NOP                             
                        156     NOP                             
                        158     JUMP_FORWARD                    19 (to 198)
                        166     POP_TOP                         
                        168     RETURN_CONST                    0: None
                        170     PUSH_EXC_INFO                   
                        172     PUSH_NULL                       
                        174     LOAD_CONST                      4: '__pyarmor_exit_54633__'
                        176     NOP                             
                        178     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
                        180     CALL                            1
                        188     POP_TOP                         
                        190     RERAISE                         0
                        192     COPY                            3
                        194     POP_EXCEPT                      
                        196     RERAISE                         1
                        198     PUSH_NULL                       
                        200     LOAD_CONST                      4: '__pyarmor_exit_54633__'
                        202     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
                        204     BUILD_TUPLE                     1
                        206     CALL_FUNCTION_EX                0
                        208     POP_TOP                         
                        210     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: OnCreate
                    Qualified Name: UserConfirmForm.OnCreate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'FormToPyQtWidget'
                        'parent'
                        'PopulateForm'
                    [Locals+Names]
                        'self'
                        'form'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54634__'
                        '__pyarmor_enter_54635__'
                        b'<COAddr>\x01\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54636__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54635__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: FormToPyQtWidget
                        50      LOAD_FAST                       1: form
                        52      CALL                            1
                        60      LOAD_FAST                       0: self
                        62      STORE_ATTR                      1: parent
                        72      LOAD_FAST                       0: self
                        74      LOAD_ATTR                       5: PopulateForm
                        94      CALL                            0
                        102     POP_TOP                         
                        104     LOAD_CONST                      0: None
                        106     NOP                             
                        108     NOP                             
                        110     NOP                             
                        112     JUMP_FORWARD                    19 (to 152)
                        120     POP_TOP                         
                        122     RETURN_CONST                    0: None
                        124     PUSH_EXC_INFO                   
                        126     PUSH_NULL                       
                        128     LOAD_CONST                      4: '__pyarmor_exit_54636__'
                        130     NOP                             
                        132     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
                        134     CALL                            1
                        142     POP_TOP                         
                        144     RERAISE                         0
                        146     COPY                            3
                        148     POP_EXCEPT                      
                        150     RERAISE                         1
                        152     PUSH_NULL                       
                        154     LOAD_CONST                      4: '__pyarmor_exit_54636__'
                        156     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
                        158     BUILD_TUPLE                     1
                        160     CALL_FUNCTION_EX                0
                        162     POP_TOP                         
                        164     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: PopulateForm
                    Qualified Name: UserConfirmForm.PopulateForm
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtWidgets'
                        'QVBoxLayout'
                        'setAlignment'
                        'QtCore'
                        'Qt'
                        'AlignTop'
                        'AlignLeft'
                        'response'
                        'EditablePredictionWidget'
                        'widgets'
                        'addWidget'
                        'QGroupBox'
                        'items'
                        'ComplexTypeWidget'
                        'setLayout'
                        'any'
                        'len'
                        'split'
                        'QHBoxLayout'
                        'QPushButton'
                        'clicked'
                        'connect'
                        'on_accept_clicked'
                        'on_cancel_clicked'
                        'addLayout'
                        'QScrollArea'
                        'setWidgetResizable'
                        'QWidget'
                        'setWidget'
                        'parent'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_43'
                        '_var_var_44'
                        '_var_var_45'
                        '_var_var_46'
                        '_var_var_35'
                        '_var_var_47'
                        '_var_var_48'
                        '_var_var_49'
                        '_var_var_50'
                        '_var_var_51'
                        '_var_var_52'
                        '_var_var_53'
                        '_var_var_54'
                        '_var_var_6'
                        '_var_var_55'
                        '_var_var_56'
                        '_var_var_57'
                        '_var_var_58'
                        '_var_var_59'
                        '_var_var_60'
                        '_var_var_61'
                        '_var_var_62'
                        '_var_var_63'
                        '_var_var_64'
                        '_var_var_65'
                        '_var_var_66'
                        '_var_var_67'
                        '_var_var_68'
                        '_var_var_69'
                        '_var_var_70'
                        '_var_var_71'
                    [Constants]
                        None
                        '__pyarmor_assert_54637__'
                        '__pyarmor_enter_54638__'
                        b'<COAddr>\x01\x00\x00\x1c\x80\x0c\x00\x00\x00\x00\x00\x00'
                        'funcname'
                        'Function Name'
                        'ret_type'
                        'Return Type'
                        'args'
                        'Function Arguments'
                        'vars'
                        'Local Variables'
                        (
                            'Brief Description'
                            True
                            True
                        )
                        (
                            'Detailed Description'
                            True
                            False
                        )
                        (
                            'Return Description'
                            True
                            True
                        )
                        (
                            'Category'
                            False
                            True
                        )
                        (
                            'Algorithm'
                            False
                            False
                        )
                        (
                            'brief'
                            'details'
                            'return'
                            'category'
                            'algorithm'
                        )
                        [Code]
                            File Name: <frozen ..recopilot_qt>
                            Object Name: <genexpr>
                            Qualified Name: UserConfirmForm.PopulateForm.<locals>.<genexpr>
                            Arg Count: 1
                            Pos Only Arg Count: 0
                            KW Only Arg Count: 0
                            Stack Size: 3
                            Flags: 0x00000033 (CO_OPTIMIZED | CO_NEWLOCALS | CO_NESTED | CO_GENERATOR)
                            [Names]
                                'response'
                            [Locals+Names]
                                '.0'
                                '_var_var_54'
                                'self'
                            [Constants]
                                None
                            [Disassembly]
                                0       COPY_FREE_VARS                  1
                                2       RETURN_GENERATOR                
                                4       POP_TOP                         
                                6       RESUME                          0
                                8       LOAD_FAST                       0: .0
                                10      FOR_ITER                        18 (to 48)
                                14      STORE_FAST                      1: _var_var_54
                                16      LOAD_FAST                       1: _var_var_54
                                18      LOAD_DEREF                      2: self
                                20      LOAD_ATTR                       0: response
                                40      CONTAINS_OP                     0 (in)
                                42      YIELD_VALUE                     1
                                44      RESUME                          1
                                46      POP_TOP                         
                                48      JUMP_BACKWARD                   20 (to 10)
                                50      END_FOR                         
                                52      RETURN_CONST                    0: None
                                54      CALL_INTRINSIC_1                3 (INTRINSIC_STOPITERATION_ERROR)
                                56      RERAISE                         1
                        'Function Documentation'
                        (
                            'force_single_line'
                        )
                        'params'
                        'Parameter Documentation'
                        'Parameter: '
                        True
                        'inline_comment'
                        'Inline Comments'
                        '\n'
                        'Line '
                        'Accept Selected'
                        'Cancel'
                        '__pyarmor_exit_54639__'
                    [Disassembly]
                        0       MAKE_CELL                       0: self
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54638__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x80\x0c\x00\x00\x00\x00\x00\x00'
                        12      BUILD_TUPLE                     1
                        14      CALL_FUNCTION_EX                0
                        16      POP_TOP                         
                        18      RESUME                          0
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      NOP                             
                        30      LOAD_GLOBAL                     1: NULL + QtWidgets
                        40      LOAD_ATTR                       2: QVBoxLayout
                        60      CALL                            0
                        68      STORE_FAST                      2: _var_var_1
                        70      LOAD_FAST                       2: _var_var_1
                        72      LOAD_ATTR                       5: setAlignment
                        92      LOAD_GLOBAL                     6: QtCore
                        102     LOAD_ATTR                       8: Qt
                        122     LOAD_ATTR                       10: AlignTop
                        142     LOAD_GLOBAL                     6: QtCore
                        152     LOAD_ATTR                       8: Qt
                        172     LOAD_ATTR                       12: AlignLeft
                        192     BINARY_OP                       7 (|)
                        196     CALL                            1
                        204     POP_TOP                         
                        206     LOAD_CONST                      4: 'funcname'
                        208     LOAD_DEREF                      0: self
                        210     LOAD_ATTR                       14: response
                        230     CONTAINS_OP                     0 (in)
                        232     POP_JUMP_IF_FALSE               68 (to 370)
                        234     LOAD_GLOBAL                     17: NULL + EditablePredictionWidget
                        244     LOAD_CONST                      5: 'Function Name'
                        246     LOAD_DEREF                      0: self
                        248     LOAD_ATTR                       14: response
                        268     LOAD_CONST                      4: 'funcname'
                        270     BINARY_SUBSCR                   
                        274     CALL                            2
                        282     LOAD_DEREF                      0: self
                        284     LOAD_ATTR                       18: widgets
                        304     LOAD_CONST                      4: 'funcname'
                        306     STORE_SUBSCR                    
                        310     LOAD_FAST                       2: _var_var_1
                        312     LOAD_ATTR                       21: addWidget
                        332     LOAD_DEREF                      0: self
                        334     LOAD_ATTR                       18: widgets
                        354     LOAD_CONST                      4: 'funcname'
                        356     BINARY_SUBSCR                   
                        360     CALL                            1
                        368     POP_TOP                         
                        370     LOAD_CONST                      6: 'ret_type'
                        372     LOAD_DEREF                      0: self
                        374     LOAD_ATTR                       14: response
                        394     CONTAINS_OP                     0 (in)
                        396     POP_JUMP_IF_FALSE               68 (to 534)
                        398     LOAD_GLOBAL                     17: NULL + EditablePredictionWidget
                        408     LOAD_CONST                      7: 'Return Type'
                        410     LOAD_DEREF                      0: self
                        412     LOAD_ATTR                       14: response
                        432     LOAD_CONST                      6: 'ret_type'
                        434     BINARY_SUBSCR                   
                        438     CALL                            2
                        446     LOAD_DEREF                      0: self
                        448     LOAD_ATTR                       18: widgets
                        468     LOAD_CONST                      6: 'ret_type'
                        470     STORE_SUBSCR                    
                        474     LOAD_FAST                       2: _var_var_1
                        476     LOAD_ATTR                       21: addWidget
                        496     LOAD_DEREF                      0: self
                        498     LOAD_ATTR                       18: widgets
                        518     LOAD_CONST                      6: 'ret_type'
                        520     BINARY_SUBSCR                   
                        524     CALL                            1
                        532     POP_TOP                         
                        534     LOAD_CONST                      8: 'args'
                        536     LOAD_DEREF                      0: self
                        538     LOAD_ATTR                       14: response
                        558     CONTAINS_OP                     0 (in)
                        560     POP_JUMP_IF_FALSE               174 (to 910)
                        562     LOAD_GLOBAL                     1: NULL + QtWidgets
                        572     LOAD_ATTR                       22: QGroupBox
                        592     LOAD_CONST                      9: 'Function Arguments'
                        594     CALL                            1
                        602     STORE_FAST                      3: _var_var_43
                        604     LOAD_GLOBAL                     1: NULL + QtWidgets
                        614     LOAD_ATTR                       2: QVBoxLayout
                        634     CALL                            0
                        642     STORE_FAST                      4: _var_var_44
                        644     BUILD_MAP                       0
                        646     LOAD_DEREF                      0: self
                        648     LOAD_ATTR                       18: widgets
                        668     LOAD_CONST                      8: 'args'
                        670     STORE_SUBSCR                    
                        674     LOAD_DEREF                      0: self
                        676     LOAD_ATTR                       14: response
                        696     LOAD_CONST                      8: 'args'
                        698     BINARY_SUBSCR                   
                        702     LOAD_ATTR                       25: items
                        722     CALL                            0
                        730     GET_ITER                        
                        732     FOR_ITER                        52 (to 838)
                        736     UNPACK_SEQUENCE                 2
                        740     STORE_FAST                      5: _var_var_45
                        742     STORE_FAST                      6: _var_var_46
                        744     LOAD_GLOBAL                     27: NULL + ComplexTypeWidget
                        754     LOAD_FAST                       5: _var_var_45
                        756     LOAD_FAST                       6: _var_var_46
                        758     CALL                            2
                        766     STORE_FAST                      7: _var_var_35
                        768     LOAD_FAST                       7: _var_var_35
                        770     LOAD_DEREF                      0: self
                        772     LOAD_ATTR                       18: widgets
                        792     LOAD_CONST                      8: 'args'
                        794     BINARY_SUBSCR                   
                        798     LOAD_FAST                       5: _var_var_45
                        800     STORE_SUBSCR                    
                        804     LOAD_FAST                       4: _var_var_44
                        806     LOAD_ATTR                       21: addWidget
                        826     LOAD_FAST                       7: _var_var_35
                        828     CALL                            1
                        836     POP_TOP                         
                        838     JUMP_BACKWARD                   54 (to 732)
                        840     END_FOR                         
                        842     LOAD_FAST                       3: _var_var_43
                        844     LOAD_ATTR                       29: setLayout
                        864     LOAD_FAST                       4: _var_var_44
                        866     CALL                            1
                        874     POP_TOP                         
                        876     LOAD_FAST                       2: _var_var_1
                        878     LOAD_ATTR                       21: addWidget
                        898     LOAD_FAST                       3: _var_var_43
                        900     CALL                            1
                        908     POP_TOP                         
                        910     LOAD_CONST                      10: 'vars'
                        912     LOAD_DEREF                      0: self
                        914     LOAD_ATTR                       14: response
                        934     CONTAINS_OP                     0 (in)
                        936     POP_JUMP_IF_FALSE               174 (to 1286)
                        938     LOAD_GLOBAL                     1: NULL + QtWidgets
                        948     LOAD_ATTR                       22: QGroupBox
                        968     LOAD_CONST                      11: 'Local Variables'
                        970     CALL                            1
                        978     STORE_FAST                      8: _var_var_47
                        980     LOAD_GLOBAL                     1: NULL + QtWidgets
                        990     LOAD_ATTR                       2: QVBoxLayout
                        1010    CALL                            0
                        1018    STORE_FAST                      9: _var_var_48
                        1020    BUILD_MAP                       0
                        1022    LOAD_DEREF                      0: self
                        1024    LOAD_ATTR                       18: widgets
                        1044    LOAD_CONST                      10: 'vars'
                        1046    STORE_SUBSCR                    
                        1050    LOAD_DEREF                      0: self
                        1052    LOAD_ATTR                       14: response
                        1072    LOAD_CONST                      10: 'vars'
                        1074    BINARY_SUBSCR                   
                        1078    LOAD_ATTR                       25: items
                        1098    CALL                            0
                        1106    GET_ITER                        
                        1108    FOR_ITER                        52 (to 1214)
                        1112    UNPACK_SEQUENCE                 2
                        1116    STORE_FAST                      10: _var_var_49
                        1118    STORE_FAST                      11: _var_var_50
                        1120    LOAD_GLOBAL                     27: NULL + ComplexTypeWidget
                        1130    LOAD_FAST                       10: _var_var_49
                        1132    LOAD_FAST                       11: _var_var_50
                        1134    CALL                            2
                        1142    STORE_FAST                      7: _var_var_35
                        1144    LOAD_FAST                       7: _var_var_35
                        1146    LOAD_DEREF                      0: self
                        1148    LOAD_ATTR                       18: widgets
                        1168    LOAD_CONST                      10: 'vars'
                        1170    BINARY_SUBSCR                   
                        1174    LOAD_FAST                       10: _var_var_49
                        1176    STORE_SUBSCR                    
                        1180    LOAD_FAST                       9: _var_var_48
                        1182    LOAD_ATTR                       21: addWidget
                        1202    LOAD_FAST                       7: _var_var_35
                        1204    CALL                            1
                        1212    POP_TOP                         
                        1214    JUMP_BACKWARD                   54 (to 1108)
                        1216    END_FOR                         
                        1218    LOAD_FAST                       8: _var_var_47
                        1220    LOAD_ATTR                       29: setLayout
                        1240    LOAD_FAST                       9: _var_var_48
                        1242    CALL                            1
                        1250    POP_TOP                         
                        1252    LOAD_FAST                       2: _var_var_1
                        1254    LOAD_ATTR                       21: addWidget
                        1274    LOAD_FAST                       8: _var_var_47
                        1276    CALL                            1
                        1284    POP_TOP                         
                        1286    LOAD_CONST                      12: ('Brief Description', True, True)
                        1288    LOAD_CONST                      13: ('Detailed Description', True, False)
                        1290    LOAD_CONST                      14: ('Return Description', True, True)
                        1292    LOAD_CONST                      15: ('Category', False, True)
                        1294    LOAD_CONST                      16: ('Algorithm', False, False)
                        1296    LOAD_CONST                      17: ('brief', 'details', 'return', 'category', 'algorithm')
                        1298    BUILD_CONST_KEY_MAP             5
                        1300    STORE_FAST                      12: _var_var_51
                        1302    LOAD_GLOBAL                     31: NULL + any
                        1312    LOAD_CLOSURE                    0: self
                        1314    BUILD_TUPLE                     1
                        1316    LOAD_CONST                      18: <CODE> <genexpr>
                        1318    MAKE_FUNCTION                   8
                        1320    LOAD_FAST                       12: _var_var_51
                        1322    GET_ITER                        
                        1324    CALL                            0
                        1332    CALL                            1
                        1340    POP_JUMP_IF_FALSE               144 (to 1630)
                        1342    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1352    LOAD_ATTR                       22: QGroupBox
                        1372    LOAD_CONST                      19: 'Function Documentation'
                        1374    CALL                            1
                        1382    STORE_FAST                      13: _var_var_52
                        1384    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1394    LOAD_ATTR                       2: QVBoxLayout
                        1414    CALL                            0
                        1422    STORE_FAST                      14: _var_var_53
                        1424    LOAD_FAST                       12: _var_var_51
                        1426    LOAD_ATTR                       25: items
                        1446    CALL                            0
                        1454    GET_ITER                        
                        1456    FOR_ITER                        84 (to 1626)
                        1460    UNPACK_SEQUENCE                 2
                        1464    STORE_FAST                      15: _var_var_54
                        1466    UNPACK_SEQUENCE                 3
                        1470    STORE_FAST                      16: _var_var_6
                        1472    STORE_FAST                      17: _var_var_55
                        1474    STORE_FAST                      18: _var_var_56
                        1476    LOAD_FAST                       15: _var_var_54
                        1478    LOAD_DEREF                      0: self
                        1480    LOAD_ATTR                       14: response
                        1500    CONTAINS_OP                     0 (in)
                        1502    POP_JUMP_IF_TRUE                1 (to 1506)
                        1504    JUMP_BACKWARD                   25 (to 1456)
                        1506    LOAD_GLOBAL                     17: NULL + EditablePredictionWidget
                        1516    LOAD_FAST                       16: _var_var_6
                        1518    LOAD_DEREF                      0: self
                        1520    LOAD_ATTR                       14: response
                        1540    LOAD_FAST                       15: _var_var_54
                        1542    BINARY_SUBSCR                   
                        1546    LOAD_FAST                       17: _var_var_55
                        1548    LOAD_FAST                       18: _var_var_56
                        1550    KW_NAMES                        20: ('force_single_line',)
                        1552    CALL                            4
                        1560    STORE_FAST                      7: _var_var_35
                        1562    LOAD_FAST                       7: _var_var_35
                        1564    LOAD_DEREF                      0: self
                        1566    LOAD_ATTR                       18: widgets
                        1586    LOAD_FAST                       15: _var_var_54
                        1588    STORE_SUBSCR                    
                        1592    LOAD_FAST                       14: _var_var_53
                        1594    LOAD_ATTR                       21: addWidget
                        1614    LOAD_FAST                       7: _var_var_35
                        1616    CALL                            1
                        1624    POP_TOP                         
                        1626    JUMP_BACKWARD                   86 (to 1456)
                        1628    END_FOR                         
                        1630    LOAD_CONST                      21: 'params'
                        1632    LOAD_DEREF                      0: self
                        1634    LOAD_ATTR                       14: response
                        1654    CONTAINS_OP                     0 (in)
                        1656    POP_JUMP_IF_FALSE               214 (to 2086)
                        1658    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1668    LOAD_ATTR                       22: QGroupBox
                        1688    LOAD_CONST                      22: 'Parameter Documentation'
                        1690    CALL                            1
                        1698    STORE_FAST                      19: _var_var_57
                        1700    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1710    LOAD_ATTR                       2: QVBoxLayout
                        1730    CALL                            0
                        1738    STORE_FAST                      20: _var_var_58
                        1740    BUILD_MAP                       0
                        1742    LOAD_DEREF                      0: self
                        1744    LOAD_ATTR                       18: widgets
                        1764    LOAD_CONST                      21: 'params'
                        1766    STORE_SUBSCR                    
                        1770    LOAD_DEREF                      0: self
                        1772    LOAD_ATTR                       14: response
                        1792    LOAD_CONST                      21: 'params'
                        1794    BINARY_SUBSCR                   
                        1798    LOAD_ATTR                       25: items
                        1818    CALL                            0
                        1826    GET_ITER                        
                        1828    FOR_ITER                        58 (to 1946)
                        1832    UNPACK_SEQUENCE                 2
                        1836    STORE_FAST                      21: _var_var_59
                        1838    STORE_FAST                      22: _var_var_60
                        1840    LOAD_GLOBAL                     17: NULL + EditablePredictionWidget
                        1850    LOAD_CONST                      23: 'Parameter: '
                        1852    LOAD_FAST                       21: _var_var_59
                        1854    FORMAT_VALUE                    0 (FVC_NONE)
                        1856    BUILD_STRING                    2
                        1858    LOAD_FAST                       22: _var_var_60
                        1860    LOAD_CONST                      24: True
                        1862    LOAD_CONST                      24: True
                        1864    KW_NAMES                        20: ('force_single_line',)
                        1866    CALL                            4
                        1874    STORE_FAST                      7: _var_var_35
                        1876    LOAD_FAST                       7: _var_var_35
                        1878    LOAD_DEREF                      0: self
                        1880    LOAD_ATTR                       18: widgets
                        1900    LOAD_CONST                      21: 'params'
                        1902    BINARY_SUBSCR                   
                        1906    LOAD_FAST                       21: _var_var_59
                        1908    STORE_SUBSCR                    
                        1912    LOAD_FAST                       20: _var_var_58
                        1914    LOAD_ATTR                       21: addWidget
                        1934    LOAD_FAST                       7: _var_var_35
                        1936    CALL                            1
                        1944    POP_TOP                         
                        1946    JUMP_BACKWARD                   60 (to 1828)
                        1948    END_FOR                         
                        1950    LOAD_FAST                       19: _var_var_57
                        1952    LOAD_ATTR                       29: setLayout
                        1972    LOAD_FAST                       20: _var_var_58
                        1974    CALL                            1
                        1982    POP_TOP                         
                        1984    LOAD_FAST_CHECK                 14: _var_var_53
                        1986    LOAD_ATTR                       21: addWidget
                        2006    LOAD_FAST                       19: _var_var_57
                        2008    CALL                            1
                        2016    POP_TOP                         
                        2018    LOAD_FAST_CHECK                 13: _var_var_52
                        2020    LOAD_ATTR                       29: setLayout
                        2040    LOAD_FAST                       14: _var_var_53
                        2042    CALL                            1
                        2050    POP_TOP                         
                        2052    LOAD_FAST                       2: _var_var_1
                        2054    LOAD_ATTR                       21: addWidget
                        2074    LOAD_FAST                       13: _var_var_52
                        2076    CALL                            1
                        2084    POP_TOP                         
                        2086    LOAD_CONST                      25: 'inline_comment'
                        2088    LOAD_DEREF                      0: self
                        2090    LOAD_ATTR                       14: response
                        2110    CONTAINS_OP                     0 (in)
                        2112    POP_JUMP_IF_FALSE               205 (to 2524)
                        2114    LOAD_GLOBAL                     1: NULL + QtWidgets
                        2124    LOAD_ATTR                       22: QGroupBox
                        2144    LOAD_CONST                      26: 'Inline Comments'
                        2146    CALL                            1
                        2154    STORE_FAST                      23: _var_var_61
                        2156    LOAD_GLOBAL                     1: NULL + QtWidgets
                        2166    LOAD_ATTR                       2: QVBoxLayout
                        2186    CALL                            0
                        2194    STORE_FAST                      24: _var_var_62
                        2196    BUILD_MAP                       0
                        2198    LOAD_DEREF                      0: self
                        2200    LOAD_ATTR                       18: widgets
                        2220    LOAD_CONST                      25: 'inline_comment'
                        2222    STORE_SUBSCR                    
                        2226    LOAD_DEREF                      0: self
                        2228    LOAD_ATTR                       14: response
                        2248    LOAD_CONST                      25: 'inline_comment'
                        2250    BINARY_SUBSCR                   
                        2254    LOAD_ATTR                       25: items
                        2274    CALL                            0
                        2282    GET_ITER                        
                        2284    FOR_ITER                        83 (to 2452)
                        2288    UNPACK_SEQUENCE                 2
                        2292    STORE_FAST                      25: _var_var_63
                        2294    STORE_FAST                      26: _var_var_64
                        2296    LOAD_GLOBAL                     33: NULL + len
                        2306    LOAD_FAST                       26: _var_var_64
                        2308    LOAD_ATTR                       35: split
                        2328    LOAD_CONST                      27: '\n'
                        2330    CALL                            1
                        2338    CALL                            1
                        2346    STORE_FAST                      27: _var_var_65
                        2348    LOAD_GLOBAL                     17: NULL + EditablePredictionWidget
                        2358    LOAD_CONST                      28: 'Line '
                        2360    LOAD_FAST                       25: _var_var_63
                        2362    FORMAT_VALUE                    0 (FVC_NONE)
                        2364    BUILD_STRING                    2
                        2366    LOAD_FAST                       26: _var_var_64
                        2368    LOAD_CONST                      24: True
                        2370    LOAD_FAST                       27: _var_var_65
                        2372    CALL                            4
                        2380    STORE_FAST                      7: _var_var_35
                        2382    LOAD_FAST                       7: _var_var_35
                        2384    LOAD_DEREF                      0: self
                        2386    LOAD_ATTR                       18: widgets
                        2406    LOAD_CONST                      25: 'inline_comment'
                        2408    BINARY_SUBSCR                   
                        2412    LOAD_FAST                       25: _var_var_63
                        2414    STORE_SUBSCR                    
                        2418    LOAD_FAST                       24: _var_var_62
                        2420    LOAD_ATTR                       21: addWidget
                        2440    LOAD_FAST                       7: _var_var_35
                        2442    CALL                            1
                        2450    POP_TOP                         
                        2452    JUMP_BACKWARD                   85 (to 2284)
                        2454    END_FOR                         
                        2456    LOAD_FAST                       23: _var_var_61
                        2458    LOAD_ATTR                       29: setLayout
                        2478    LOAD_FAST                       24: _var_var_62
                        2480    CALL                            1
                        2488    POP_TOP                         
                        2490    LOAD_FAST                       2: _var_var_1
                        2492    LOAD_ATTR                       21: addWidget
                        2512    LOAD_FAST                       23: _var_var_61
                        2514    CALL                            1
                        2522    POP_TOP                         
                        2524    LOAD_GLOBAL                     1: NULL + QtWidgets
                        2534    LOAD_ATTR                       36: QHBoxLayout
                        2554    CALL                            0
                        2562    STORE_FAST                      28: _var_var_66
                        2564    LOAD_GLOBAL                     1: NULL + QtWidgets
                        2574    LOAD_ATTR                       38: QPushButton
                        2594    LOAD_CONST                      29: 'Accept Selected'
                        2596    CALL                            1
                        2604    STORE_FAST                      29: _var_var_67
                        2606    LOAD_GLOBAL                     1: NULL + QtWidgets
                        2616    LOAD_ATTR                       38: QPushButton
                        2636    LOAD_CONST                      30: 'Cancel'
                        2638    CALL                            1
                        2646    STORE_FAST                      30: _var_var_68
                        2648    LOAD_FAST                       29: _var_var_67
                        2650    LOAD_ATTR                       40: clicked
                        2670    LOAD_ATTR                       43: connect
                        2690    LOAD_DEREF                      0: self
                        2692    LOAD_ATTR                       44: on_accept_clicked
                        2712    CALL                            1
                        2720    POP_TOP                         
                        2722    LOAD_FAST                       30: _var_var_68
                        2724    LOAD_ATTR                       40: clicked
                        2744    LOAD_ATTR                       43: connect
                        2764    LOAD_DEREF                      0: self
                        2766    LOAD_ATTR                       46: on_cancel_clicked
                        2786    CALL                            1
                        2794    POP_TOP                         
                        2796    LOAD_FAST                       28: _var_var_66
                        2798    LOAD_ATTR                       21: addWidget
                        2818    LOAD_FAST                       29: _var_var_67
                        2820    CALL                            1
                        2828    POP_TOP                         
                        2830    LOAD_FAST                       28: _var_var_66
                        2832    LOAD_ATTR                       21: addWidget
                        2852    LOAD_FAST                       30: _var_var_68
                        2854    CALL                            1
                        2862    POP_TOP                         
                        2864    LOAD_FAST                       2: _var_var_1
                        2866    LOAD_ATTR                       49: addLayout
                        2886    LOAD_FAST                       28: _var_var_66
                        2888    CALL                            1
                        2896    POP_TOP                         
                        2898    LOAD_GLOBAL                     1: NULL + QtWidgets
                        2908    LOAD_ATTR                       50: QScrollArea
                        2928    CALL                            0
                        2936    STORE_FAST                      31: _var_var_69
                        2938    LOAD_FAST                       31: _var_var_69
                        2940    LOAD_ATTR                       53: setWidgetResizable
                        2960    LOAD_CONST                      24: True
                        2962    CALL                            1
                        2970    POP_TOP                         
                        2972    LOAD_GLOBAL                     1: NULL + QtWidgets
                        2982    LOAD_ATTR                       54: QWidget
                        3002    CALL                            0
                        3010    STORE_FAST                      32: _var_var_70
                        3012    LOAD_FAST                       32: _var_var_70
                        3014    LOAD_ATTR                       29: setLayout
                        3034    LOAD_FAST                       2: _var_var_1
                        3036    CALL                            1
                        3044    POP_TOP                         
                        3046    LOAD_FAST                       31: _var_var_69
                        3048    LOAD_ATTR                       57: setWidget
                        3068    LOAD_FAST                       32: _var_var_70
                        3070    CALL                            1
                        3078    POP_TOP                         
                        3080    LOAD_GLOBAL                     1: NULL + QtWidgets
                        3090    LOAD_ATTR                       2: QVBoxLayout
                        3110    CALL                            0
                        3118    STORE_FAST                      33: _var_var_71
                        3120    LOAD_FAST                       33: _var_var_71
                        3122    LOAD_ATTR                       21: addWidget
                        3142    LOAD_FAST                       31: _var_var_69
                        3144    CALL                            1
                        3152    POP_TOP                         
                        3154    LOAD_DEREF                      0: self
                        3156    LOAD_ATTR                       58: parent
                        3176    LOAD_ATTR                       29: setLayout
                        3196    LOAD_FAST                       33: _var_var_71
                        3198    CALL                            1
                        3206    POP_TOP                         
                        3208    LOAD_CONST                      0: None
                        3210    NOP                             
                        3212    NOP                             
                        3214    NOP                             
                        3216    JUMP_FORWARD                    19 (to 3256)
                        3224    POP_TOP                         
                        3226    RETURN_CONST                    0: None
                        3228    PUSH_EXC_INFO                   
                        3230    PUSH_NULL                       
                        3232    LOAD_CONST                      31: '__pyarmor_exit_54639__'
                        3234    NOP                             
                        3236    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x80\x0c\x00\x00\x00\x00\x00\x00'
                        3238    CALL                            1
                        3246    POP_TOP                         
                        3248    RERAISE                         0
                        3250    COPY                            3
                        3252    POP_EXCEPT                      
                        3254    RERAISE                         1
                        3256    PUSH_NULL                       
                        3258    LOAD_CONST                      31: '__pyarmor_exit_54639__'
                        3260    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x80\x0c\x00\x00\x00\x00\x00\x00'
                        3262    BUILD_TUPLE                     1
                        3264    CALL_FUNCTION_EX                0
                        3266    POP_TOP                         
                        3268    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: validate_fields
                    Qualified Name: UserConfirmForm.validate_fields
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 7
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widgets'
                        'accepted'
                        'get_content'
                        'strip'
                        'items'
                        'validate'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_54'
                        '_var_var_72'
                        '_var_var_27'
                        '_var_var_35'
                    [Constants]
                        '验证所有字段是否都已正确填写'
                        '__pyarmor_assert_54640__'
                        '__pyarmor_enter_54641__'
                        b'<COAddr>\x01\x00\x00\x1a\xb6\x01\x00\x00\x00\x00\x00\x00'
                        (
                            'funcname'
                            'ret_type'
                        )
                        False
                        'Please fill in the '
                        ' field'
                        '__pyarmor_exit_54642__'
                        (
                            'args'
                            'vars'
                        )
                        'Please fill in all fields in '
                        ': '
                        (
                            True
                            ''
                        )
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54641__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb6\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_CONST                      4: ('funcname', 'ret_type')
                        30      GET_ITER                        
                        32      FOR_ITER                        105 (to 244)
                        36      STORE_FAST                      2: _var_var_54
                        38      LOAD_FAST                       2: _var_var_54
                        40      LOAD_FAST                       0: self
                        42      LOAD_ATTR                       0: widgets
                        62      CONTAINS_OP                     0 (in)
                        64      POP_JUMP_IF_TRUE                1 (to 68)
                        66      JUMP_BACKWARD                   18 (to 32)
                        68      LOAD_FAST                       0: self
                        70      LOAD_ATTR                       0: widgets
                        90      LOAD_FAST                       2: _var_var_54
                        92      BINARY_SUBSCR                   
                        96      LOAD_ATTR                       2: accepted
                        116     POP_JUMP_IF_TRUE                1 (to 120)
                        118     JUMP_BACKWARD                   44 (to 32)
                        120     LOAD_FAST                       0: self
                        122     LOAD_ATTR                       0: widgets
                        142     LOAD_FAST                       2: _var_var_54
                        144     BINARY_SUBSCR                   
                        148     LOAD_ATTR                       5: get_content
                        168     CALL                            0
                        176     LOAD_ATTR                       7: strip
                        196     CALL                            0
                        204     POP_JUMP_IF_FALSE               1 (to 208)
                        206     JUMP_BACKWARD                   88 (to 32)
                        208     LOAD_CONST                      5: False
                        210     LOAD_CONST                      6: 'Please fill in the '
                        212     LOAD_FAST                       2: _var_var_54
                        214     FORMAT_VALUE                    0 (FVC_NONE)
                        216     LOAD_CONST                      7: ' field'
                        218     BUILD_STRING                    3
                        220     BUILD_TUPLE                     2
                        222     SWAP                            2
                        224     POP_TOP                         
                        226     NOP                             
                        228     NOP                             
                        230     NOP                             
                        232     JUMP_FORWARD                    129 (to 492)
                        234     CALL                            1
                        242     POP_TOP                         
                        244     RETURN_VALUE                    
                        246     END_FOR                         
                        248     LOAD_CONST                      9: ('args', 'vars')
                        250     GET_ITER                        
                        252     FOR_ITER                        93 (to 440)
                        256     STORE_FAST                      3: _var_var_72
                        258     LOAD_FAST                       3: _var_var_72
                        260     LOAD_FAST                       0: self
                        262     LOAD_ATTR                       0: widgets
                        282     CONTAINS_OP                     0 (in)
                        284     POP_JUMP_IF_TRUE                1 (to 288)
                        286     JUMP_BACKWARD                   18 (to 252)
                        288     LOAD_FAST                       0: self
                        290     LOAD_ATTR                       0: widgets
                        310     LOAD_FAST                       3: _var_var_72
                        312     BINARY_SUBSCR                   
                        316     LOAD_ATTR                       9: items
                        336     CALL                            0
                        344     GET_ITER                        
                        346     FOR_ITER                        44 (to 436)
                        350     UNPACK_SEQUENCE                 2
                        354     STORE_FAST                      4: _var_var_27
                        356     STORE_FAST                      5: _var_var_35
                        358     LOAD_FAST                       5: _var_var_35
                        360     LOAD_ATTR                       11: validate
                        380     CALL                            0
                        388     POP_JUMP_IF_FALSE               1 (to 392)
                        390     JUMP_BACKWARD                   23 (to 346)
                        392     LOAD_CONST                      5: False
                        394     LOAD_CONST                      10: 'Please fill in all fields in '
                        396     LOAD_FAST                       3: _var_var_72
                        398     FORMAT_VALUE                    0 (FVC_NONE)
                        400     LOAD_CONST                      11: ': '
                        402     LOAD_FAST                       4: _var_var_27
                        404     FORMAT_VALUE                    0 (FVC_NONE)
                        406     BUILD_STRING                    4
                        408     BUILD_TUPLE                     2
                        410     SWAP                            2
                        412     POP_TOP                         
                        414     SWAP                            2
                        416     POP_TOP                         
                        418     NOP                             
                        420     NOP                             
                        422     NOP                             
                        424     JUMP_FORWARD                    33 (to 492)
                        426     CALL                            1
                        434     POP_TOP                         
                        436     RETURN_VALUE                    
                        438     END_FOR                         
                        440     JUMP_BACKWARD                   95 (to 252)
                        442     END_FOR                         
                        444     LOAD_CONST                      12: (True, '')
                        446     NOP                             
                        448     NOP                             
                        450     NOP                             
                        452     JUMP_FORWARD                    19 (to 492)
                        460     POP_TOP                         
                        462     RETURN_CONST                    12: (True, '')
                        464     PUSH_EXC_INFO                   
                        466     PUSH_NULL                       
                        468     LOAD_CONST                      8: '__pyarmor_exit_54642__'
                        470     NOP                             
                        472     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb6\x01\x00\x00\x00\x00\x00\x00'
                        474     CALL                            1
                        482     POP_TOP                         
                        484     RERAISE                         0
                        486     COPY                            3
                        488     POP_EXCEPT                      
                        490     RERAISE                         1
                        492     PUSH_NULL                       
                        494     LOAD_CONST                      8: '__pyarmor_exit_54642__'
                        496     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xb6\x01\x00\x00\x00\x00\x00\x00'
                        498     BUILD_TUPLE                     1
                        500     CALL_FUNCTION_EX                0
                        502     POP_TOP                         
                        504     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_accept_clicked
                    Qualified Name: UserConfirmForm.on_accept_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'validate_fields'
                        'QtWidgets'
                        'QMessageBox'
                        'warning'
                        'parent'
                        'widgets'
                        'accepted'
                        'get_content'
                        'items'
                        'get_type_info'
                        'settings_manager'
                        'settings'
                        'send_feedback'
                        'prompt'
                        'response_raw'
                        'task_tag'
                        'apply_prediction'
                        'ea'
                        'Close'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_73'
                        '_var_var_74'
                        '_var_var_75'
                        '_var_var_54'
                        '_var_var_76'
                        '_var_var_45'
                        '_var_var_35'
                        '_var_var_77'
                        '_var_var_78'
                        '_var_var_49'
                        '_var_var_79'
                        '_var_var_59'
                        '_var_var_80'
                        '_var_var_63'
                    [Constants]
                        None
                        '__pyarmor_assert_54643__'
                        '__pyarmor_enter_54644__'
                        b'<COAddr>\x01\x00\x00\x1a\xd0\x05\x00\x00\x00\x00\x00\x00'
                        'Validation Error'
                        '\nPlease fill in all selected fields before applying, otherwise unselect it.'
                        '__pyarmor_exit_54645__'
                        (
                            'funcname'
                            'ret_type'
                        )
                        'args'
                        'vars'
                        (
                            'brief'
                            'details'
                            'return'
                            'category'
                            'algorithm'
                        )
                        'params'
                        'inline_comment'
                        'feedback'
                        0
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54644__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd0\x05\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: validate_fields
                        50      CALL                            0
                        58      UNPACK_SEQUENCE                 2
                        62      STORE_FAST                      2: _var_var_73
                        64      STORE_FAST                      3: _var_var_74
                        66      LOAD_FAST                       2: _var_var_73
                        68      POP_JUMP_IF_TRUE                57 (to 184)
                        70      LOAD_GLOBAL                     2: QtWidgets
                        80      LOAD_ATTR                       4: QMessageBox
                        100     LOAD_ATTR                       7: warning
                        120     LOAD_FAST                       0: self
                        122     LOAD_ATTR                       8: parent
                        142     LOAD_CONST                      4: 'Validation Error'
                        144     LOAD_FAST                       3: _var_var_74
                        146     FORMAT_VALUE                    0 (FVC_NONE)
                        148     LOAD_CONST                      5: '\nPlease fill in all selected fields before applying, otherwise unselect it.'
                        150     BUILD_STRING                    2
                        152     CALL                            3
                        160     POP_TOP                         
                        162     NOP                             
                        164     LOAD_CONST                      0: None
                        166     NOP                             
                        168     NOP                             
                        170     JUMP_FORWARD                    684 (to 1542)
                        180     POP_TOP                         
                        182     RETURN_CONST                    0: None
                        184     BUILD_MAP                       0
                        186     STORE_FAST                      4: _var_var_75
                        188     LOAD_CONST                      7: ('funcname', 'ret_type')
                        190     GET_ITER                        
                        192     FOR_ITER                        75 (to 344)
                        196     STORE_FAST                      5: _var_var_54
                        198     LOAD_FAST                       5: _var_var_54
                        200     LOAD_FAST                       0: self
                        202     LOAD_ATTR                       10: widgets
                        222     CONTAINS_OP                     0 (in)
                        224     POP_JUMP_IF_TRUE                1 (to 228)
                        226     JUMP_BACKWARD                   18 (to 192)
                        228     LOAD_FAST                       0: self
                        230     LOAD_ATTR                       10: widgets
                        250     LOAD_FAST                       5: _var_var_54
                        252     BINARY_SUBSCR                   
                        256     LOAD_ATTR                       12: accepted
                        276     POP_JUMP_IF_TRUE                1 (to 280)
                        278     JUMP_BACKWARD                   44 (to 192)
                        280     LOAD_FAST                       0: self
                        282     LOAD_ATTR                       10: widgets
                        302     LOAD_FAST                       5: _var_var_54
                        304     BINARY_SUBSCR                   
                        308     LOAD_ATTR                       15: get_content
                        328     CALL                            0
                        336     LOAD_FAST                       4: _var_var_75
                        338     LOAD_FAST                       5: _var_var_54
                        340     STORE_SUBSCR                    
                        344     JUMP_BACKWARD                   77 (to 192)
                        346     END_FOR                         
                        348     LOAD_CONST                      8: 'args'
                        350     LOAD_FAST                       0: self
                        352     LOAD_ATTR                       10: widgets
                        372     CONTAINS_OP                     0 (in)
                        374     POP_JUMP_IF_FALSE               83 (to 542)
                        376     BUILD_MAP                       0
                        378     STORE_FAST                      6: _var_var_76
                        380     LOAD_FAST                       0: self
                        382     LOAD_ATTR                       10: widgets
                        402     LOAD_CONST                      8: 'args'
                        404     BINARY_SUBSCR                   
                        408     LOAD_ATTR                       17: items
                        428     CALL                            0
                        436     GET_ITER                        
                        438     FOR_ITER                        42 (to 524)
                        442     UNPACK_SEQUENCE                 2
                        446     STORE_FAST                      7: _var_var_45
                        448     STORE_FAST                      8: _var_var_35
                        450     LOAD_FAST                       8: _var_var_35
                        452     LOAD_ATTR                       12: accepted
                        472     POP_JUMP_IF_TRUE                1 (to 476)
                        474     JUMP_BACKWARD                   19 (to 438)
                        476     LOAD_FAST                       8: _var_var_35
                        478     LOAD_ATTR                       19: get_type_info
                        498     CALL                            0
                        506     STORE_FAST                      9: _var_var_77
                        508     LOAD_FAST                       9: _var_var_77
                        510     POP_JUMP_IF_TRUE                1 (to 514)
                        512     JUMP_BACKWARD                   38 (to 438)
                        514     LOAD_FAST                       9: _var_var_77
                        516     LOAD_FAST                       6: _var_var_76
                        518     LOAD_FAST                       7: _var_var_45
                        520     STORE_SUBSCR                    
                        524     JUMP_BACKWARD                   44 (to 438)
                        526     END_FOR                         
                        528     LOAD_FAST                       6: _var_var_76
                        530     POP_JUMP_IF_FALSE               5 (to 542)
                        532     LOAD_FAST                       6: _var_var_76
                        534     LOAD_FAST                       4: _var_var_75
                        536     LOAD_CONST                      8: 'args'
                        538     STORE_SUBSCR                    
                        542     LOAD_CONST                      9: 'vars'
                        544     LOAD_FAST                       0: self
                        546     LOAD_ATTR                       10: widgets
                        566     CONTAINS_OP                     0 (in)
                        568     POP_JUMP_IF_FALSE               83 (to 736)
                        570     BUILD_MAP                       0
                        572     STORE_FAST                      10: _var_var_78
                        574     LOAD_FAST                       0: self
                        576     LOAD_ATTR                       10: widgets
                        596     LOAD_CONST                      9: 'vars'
                        598     BINARY_SUBSCR                   
                        602     LOAD_ATTR                       17: items
                        622     CALL                            0
                        630     GET_ITER                        
                        632     FOR_ITER                        42 (to 718)
                        636     UNPACK_SEQUENCE                 2
                        640     STORE_FAST                      11: _var_var_49
                        642     STORE_FAST                      8: _var_var_35
                        644     LOAD_FAST                       8: _var_var_35
                        646     LOAD_ATTR                       12: accepted
                        666     POP_JUMP_IF_TRUE                1 (to 670)
                        668     JUMP_BACKWARD                   19 (to 632)
                        670     LOAD_FAST                       8: _var_var_35
                        672     LOAD_ATTR                       19: get_type_info
                        692     CALL                            0
                        700     STORE_FAST                      9: _var_var_77
                        702     LOAD_FAST                       9: _var_var_77
                        704     POP_JUMP_IF_TRUE                1 (to 708)
                        706     JUMP_BACKWARD                   38 (to 632)
                        708     LOAD_FAST                       9: _var_var_77
                        710     LOAD_FAST                       10: _var_var_78
                        712     LOAD_FAST                       11: _var_var_49
                        714     STORE_SUBSCR                    
                        718     JUMP_BACKWARD                   44 (to 632)
                        720     END_FOR                         
                        722     LOAD_FAST                       10: _var_var_78
                        724     POP_JUMP_IF_FALSE               5 (to 736)
                        726     LOAD_FAST                       10: _var_var_78
                        728     LOAD_FAST                       4: _var_var_75
                        730     LOAD_CONST                      9: 'vars'
                        732     STORE_SUBSCR                    
                        736     LOAD_CONST                      10: ('brief', 'details', 'return', 'category', 'algorithm')
                        738     GET_ITER                        
                        740     FOR_ITER                        75 (to 892)
                        744     STORE_FAST                      5: _var_var_54
                        746     LOAD_FAST                       5: _var_var_54
                        748     LOAD_FAST                       0: self
                        750     LOAD_ATTR                       10: widgets
                        770     CONTAINS_OP                     0 (in)
                        772     POP_JUMP_IF_TRUE                1 (to 776)
                        774     JUMP_BACKWARD                   18 (to 740)
                        776     LOAD_FAST                       0: self
                        778     LOAD_ATTR                       10: widgets
                        798     LOAD_FAST                       5: _var_var_54
                        800     BINARY_SUBSCR                   
                        804     LOAD_ATTR                       12: accepted
                        824     POP_JUMP_IF_TRUE                1 (to 828)
                        826     JUMP_BACKWARD                   44 (to 740)
                        828     LOAD_FAST                       0: self
                        830     LOAD_ATTR                       10: widgets
                        850     LOAD_FAST                       5: _var_var_54
                        852     BINARY_SUBSCR                   
                        856     LOAD_ATTR                       15: get_content
                        876     CALL                            0
                        884     LOAD_FAST                       4: _var_var_75
                        886     LOAD_FAST                       5: _var_var_54
                        888     STORE_SUBSCR                    
                        892     JUMP_BACKWARD                   77 (to 740)
                        894     END_FOR                         
                        896     LOAD_CONST                      11: 'params'
                        898     LOAD_FAST                       0: self
                        900     LOAD_ATTR                       10: widgets
                        920     CONTAINS_OP                     0 (in)
                        922     POP_JUMP_IF_FALSE               78 (to 1080)
                        924     BUILD_MAP                       0
                        926     STORE_FAST                      12: _var_var_79
                        928     LOAD_FAST                       0: self
                        930     LOAD_ATTR                       10: widgets
                        950     LOAD_CONST                      11: 'params'
                        952     BINARY_SUBSCR                   
                        956     LOAD_ATTR                       17: items
                        976     CALL                            0
                        984     GET_ITER                        
                        986     FOR_ITER                        37 (to 1062)
                        990     UNPACK_SEQUENCE                 2
                        994     STORE_FAST                      13: _var_var_59
                        996     STORE_FAST                      8: _var_var_35
                        998     LOAD_FAST                       8: _var_var_35
                        1000    LOAD_ATTR                       12: accepted
                        1020    POP_JUMP_IF_TRUE                1 (to 1024)
                        1022    JUMP_BACKWARD                   19 (to 986)
                        1024    LOAD_FAST                       8: _var_var_35
                        1026    LOAD_ATTR                       15: get_content
                        1046    CALL                            0
                        1054    LOAD_FAST                       12: _var_var_79
                        1056    LOAD_FAST                       13: _var_var_59
                        1058    STORE_SUBSCR                    
                        1062    JUMP_BACKWARD                   39 (to 986)
                        1064    END_FOR                         
                        1066    LOAD_FAST                       12: _var_var_79
                        1068    POP_JUMP_IF_FALSE               5 (to 1080)
                        1070    LOAD_FAST                       12: _var_var_79
                        1072    LOAD_FAST                       4: _var_var_75
                        1074    LOAD_CONST                      11: 'params'
                        1076    STORE_SUBSCR                    
                        1080    LOAD_CONST                      12: 'inline_comment'
                        1082    LOAD_FAST                       0: self
                        1084    LOAD_ATTR                       10: widgets
                        1104    CONTAINS_OP                     0 (in)
                        1106    POP_JUMP_IF_FALSE               78 (to 1264)
                        1108    BUILD_MAP                       0
                        1110    STORE_FAST                      14: _var_var_80
                        1112    LOAD_FAST                       0: self
                        1114    LOAD_ATTR                       10: widgets
                        1134    LOAD_CONST                      12: 'inline_comment'
                        1136    BINARY_SUBSCR                   
                        1140    LOAD_ATTR                       17: items
                        1160    CALL                            0
                        1168    GET_ITER                        
                        1170    FOR_ITER                        37 (to 1246)
                        1174    UNPACK_SEQUENCE                 2
                        1178    STORE_FAST                      15: _var_var_63
                        1180    STORE_FAST                      8: _var_var_35
                        1182    LOAD_FAST                       8: _var_var_35
                        1184    LOAD_ATTR                       12: accepted
                        1204    POP_JUMP_IF_TRUE                1 (to 1208)
                        1206    JUMP_BACKWARD                   19 (to 1170)
                        1208    LOAD_FAST                       8: _var_var_35
                        1210    LOAD_ATTR                       15: get_content
                        1230    CALL                            0
                        1238    LOAD_FAST                       14: _var_var_80
                        1240    LOAD_FAST                       15: _var_var_63
                        1242    STORE_SUBSCR                    
                        1246    JUMP_BACKWARD                   39 (to 1170)
                        1248    END_FOR                         
                        1250    LOAD_FAST                       14: _var_var_80
                        1252    POP_JUMP_IF_FALSE               5 (to 1264)
                        1254    LOAD_FAST                       14: _var_var_80
                        1256    LOAD_FAST                       4: _var_var_75
                        1258    LOAD_CONST                      12: 'inline_comment'
                        1260    STORE_SUBSCR                    
                        1264    LOAD_FAST                       4: _var_var_75
                        1266    POP_JUMP_IF_FALSE               96 (to 1460)
                        1268    LOAD_GLOBAL                     20: settings_manager
                        1278    LOAD_ATTR                       22: settings
                        1298    LOAD_CONST                      13: 'feedback'
                        1300    BINARY_SUBSCR                   
                        1304    POP_JUMP_IF_FALSE               44 (to 1394)
                        1306    LOAD_GLOBAL                     25: NULL + send_feedback
                        1316    LOAD_FAST                       0: self
                        1318    LOAD_ATTR                       26: prompt
                        1338    LOAD_FAST                       0: self
                        1340    LOAD_ATTR                       28: response_raw
                        1360    LOAD_FAST                       4: _var_var_75
                        1362    LOAD_FAST                       0: self
                        1364    LOAD_ATTR                       30: task_tag
                        1384    CALL                            4
                        1392    POP_TOP                         
                        1394    LOAD_GLOBAL                     33: NULL + apply_prediction
                        1404    LOAD_FAST                       0: self
                        1406    LOAD_ATTR                       34: ea
                        1426    LOAD_FAST                       0: self
                        1428    LOAD_ATTR                       30: task_tag
                        1448    LOAD_FAST                       4: _var_var_75
                        1450    CALL                            3
                        1458    POP_TOP                         
                        1460    LOAD_FAST                       0: self
                        1462    LOAD_ATTR                       37: Close
                        1482    LOAD_CONST                      14: 0
                        1484    CALL                            1
                        1492    POP_TOP                         
                        1494    LOAD_CONST                      0: None
                        1496    NOP                             
                        1498    NOP                             
                        1500    NOP                             
                        1502    JUMP_FORWARD                    19 (to 1542)
                        1510    POP_TOP                         
                        1512    RETURN_CONST                    0: None
                        1514    PUSH_EXC_INFO                   
                        1516    PUSH_NULL                       
                        1518    LOAD_CONST                      6: '__pyarmor_exit_54645__'
                        1520    NOP                             
                        1522    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd0\x05\x00\x00\x00\x00\x00\x00'
                        1524    CALL                            1
                        1532    POP_TOP                         
                        1534    RERAISE                         0
                        1536    COPY                            3
                        1538    POP_EXCEPT                      
                        1540    RERAISE                         1
                        1542    PUSH_NULL                       
                        1544    LOAD_CONST                      6: '__pyarmor_exit_54645__'
                        1546    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd0\x05\x00\x00\x00\x00\x00\x00'
                        1548    BUILD_TUPLE                     1
                        1550    CALL_FUNCTION_EX                0
                        1552    POP_TOP                         
                        1554    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_cancel_clicked
                    Qualified Name: UserConfirmForm.on_cancel_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'Close'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54646__'
                        '__pyarmor_enter_54647__'
                        b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        0
                        '__pyarmor_exit_54648__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54647__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: Close
                        50      LOAD_CONST                      4: 0
                        52      CALL                            1
                        60      POP_TOP                         
                        62      LOAD_CONST                      0: None
                        64      NOP                             
                        66      NOP                             
                        68      NOP                             
                        70      JUMP_FORWARD                    19 (to 110)
                        78      POP_TOP                         
                        80      RETURN_CONST                    0: None
                        82      PUSH_EXC_INFO                   
                        84      PUSH_NULL                       
                        86      LOAD_CONST                      5: '__pyarmor_exit_54648__'
                        88      NOP                             
                        90      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        92      CALL                            1
                        100     POP_TOP                         
                        102     RERAISE                         0
                        104     COPY                            3
                        106     POP_EXCEPT                      
                        108     RERAISE                         1
                        110     PUSH_NULL                       
                        112     LOAD_CONST                      5: '__pyarmor_exit_54648__'
                        114     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        116     BUILD_TUPLE                     1
                        118     CALL_FUNCTION_EX                0
                        120     POP_TOP                         
                        122     RETURN_VALUE                    
                '__pyarmor_exit_54630__'
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'UserConfirmForm'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54629__'
                18      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
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
                48      LOAD_CONST                      5: <CODE> OnCreate
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      5: OnCreate
                54      LOAD_CONST                      6: <CODE> PopulateForm
                56      MAKE_FUNCTION                   0
                58      STORE_NAME                      6: PopulateForm
                60      LOAD_CONST                      7: <CODE> validate_fields
                62      MAKE_FUNCTION                   0
                64      STORE_NAME                      7: validate_fields
                66      LOAD_CONST                      8: <CODE> on_accept_clicked
                68      MAKE_FUNCTION                   0
                70      STORE_NAME                      8: on_accept_clicked
                72      LOAD_CONST                      9: <CODE> on_cancel_clicked
                74      MAKE_FUNCTION                   0
                76      STORE_NAME                      9: on_cancel_clicked
                78      LOAD_CLOSURE                    0: __class__
                80      COPY                            1
                82      STORE_NAME                      10: __classcell__
                84      NOP                             
                86      NOP                             
                88      NOP                             
                90      JUMP_FORWARD                    20 (to 132)
                94      POP_TOP                         
                96      LOAD_CLOSURE                    0: __class__
                98      COPY                            1
                100     STORE_NAME                      10: __classcell__
                102     RETURN_VALUE                    
                104     PUSH_EXC_INFO                   
                106     PUSH_NULL                       
                108     LOAD_CONST                      10: '__pyarmor_exit_54630__'
                110     NOP                             
                112     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                114     CALL                            1
                122     POP_TOP                         
                124     RERAISE                         0
                126     COPY                            3
                128     POP_EXCEPT                      
                130     RERAISE                         1
                132     PUSH_NULL                       
                134     LOAD_CONST                      10: '__pyarmor_exit_54630__'
                136     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                138     BUILD_TUPLE                     1
                140     CALL_FUNCTION_EX                0
                142     POP_TOP                         
                144     RETURN_VALUE                    
        'UserConfirmForm'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: create_user_confirm_view
            Qualified Name: create_user_confirm_view
            Arg Count: 5
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'UserConfirmForm'
                'Show'
                'hex'
            [Locals+Names]
                'ea'
                'task_tag'
                'prompt'
                'response_raw'
                'response'
                '__assert_armored__'
                '_var_var_7'
            [Constants]
                None
                '__pyarmor_assert_54649__'
                '__pyarmor_enter_54650__'
                b'<COAddr>\x03\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                'ReCopilot Predictions - '
                '__pyarmor_exit_54651__'
                True
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54650__'
                8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + UserConfirmForm
                38      LOAD_FAST                       0: ea
                40      LOAD_FAST                       1: task_tag
                42      LOAD_FAST                       2: prompt
                44      LOAD_FAST                       3: response_raw
                46      LOAD_FAST                       4: response
                48      CALL                            5
                56      STORE_FAST                      6: _var_var_7
                58      LOAD_FAST                       6: _var_var_7
                60      LOAD_ATTR                       3: Show
                80      LOAD_CONST                      4: 'ReCopilot Predictions - '
                82      LOAD_GLOBAL                     5: NULL + hex
                92      LOAD_FAST                       0: ea
                94      CALL                            1
                102     FORMAT_VALUE                    0 (FVC_NONE)
                104     BUILD_STRING                    2
                106     CALL                            1
                114     POP_TOP                         
                116     LOAD_CONST                      6: True
                118     NOP                             
                120     NOP                             
                122     NOP                             
                124     JUMP_FORWARD                    19 (to 164)
                132     POP_TOP                         
                134     RETURN_CONST                    6: True
                136     PUSH_EXC_INFO                   
                138     PUSH_NULL                       
                140     LOAD_CONST                      5: '__pyarmor_exit_54651__'
                142     NOP                             
                144     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                146     CALL                            1
                154     POP_TOP                         
                156     RERAISE                         0
                158     COPY                            3
                160     POP_EXCEPT                      
                162     RERAISE                         1
                164     PUSH_NULL                       
                166     LOAD_CONST                      5: '__pyarmor_exit_54651__'
                168     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                170     BUILD_TUPLE                     1
                172     CALL_FUNCTION_EX                0
                174     POP_TOP                         
                176     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: UserConfirmFormForFuncName
            Qualified Name: UserConfirmFormForFuncName
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
                'OnCreate'
                'PopulateForm'
                'validate_fields'
                'on_accept_clicked'
                'on_cancel_clicked'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'UserConfirmFormForFuncName'
                '__pyarmor_assert_54652__'
                '__pyarmor_enter_54653__'
                b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: UserConfirmFormForFuncName.__init__
                    Arg Count: 6
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'UserConfirmFormForFuncName'
                        '__init__'
                        'ea'
                        'task_tag'
                        'prompt'
                        'response_raw'
                        'response'
                        'widgets'
                    [Locals+Names]
                        'self'
                        'ea'
                        'task_tag'
                        'prompt'
                        'response_raw'
                        'response'
                        '__assert_armored__'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54655__'
                        '__pyarmor_enter_54656__'
                        b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54657__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54656__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: UserConfirmFormForFuncName
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_FAST                       1: ea
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: ea
                        80      LOAD_FAST                       2: task_tag
                        82      LOAD_FAST                       0: self
                        84      STORE_ATTR                      4: task_tag
                        94      LOAD_FAST                       3: prompt
                        96      LOAD_FAST                       0: self
                        98      STORE_ATTR                      5: prompt
                        108     LOAD_FAST                       4: response_raw
                        110     LOAD_FAST                       0: self
                        112     STORE_ATTR                      6: response_raw
                        122     LOAD_FAST                       5: response
                        124     LOAD_FAST                       0: self
                        126     STORE_ATTR                      7: response
                        136     BUILD_LIST                      0
                        138     LOAD_FAST                       0: self
                        140     STORE_ATTR                      8: widgets
                        150     LOAD_CONST                      0: None
                        152     NOP                             
                        154     NOP                             
                        156     NOP                             
                        158     JUMP_FORWARD                    19 (to 198)
                        166     POP_TOP                         
                        168     RETURN_CONST                    0: None
                        170     PUSH_EXC_INFO                   
                        172     PUSH_NULL                       
                        174     LOAD_CONST                      4: '__pyarmor_exit_54657__'
                        176     NOP                             
                        178     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
                        180     CALL                            1
                        188     POP_TOP                         
                        190     RERAISE                         0
                        192     COPY                            3
                        194     POP_EXCEPT                      
                        196     RERAISE                         1
                        198     PUSH_NULL                       
                        200     LOAD_CONST                      4: '__pyarmor_exit_54657__'
                        202     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\x8e\x00\x00\x00\x00\x00\x00\x00'
                        204     BUILD_TUPLE                     1
                        206     CALL_FUNCTION_EX                0
                        208     POP_TOP                         
                        210     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: OnCreate
                    Qualified Name: UserConfirmFormForFuncName.OnCreate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'FormToPyQtWidget'
                        'parent'
                        'PopulateForm'
                    [Locals+Names]
                        'self'
                        'form'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54658__'
                        '__pyarmor_enter_54659__'
                        b'<COAddr>\x03\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54660__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54659__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: FormToPyQtWidget
                        50      LOAD_FAST                       1: form
                        52      CALL                            1
                        60      LOAD_FAST                       0: self
                        62      STORE_ATTR                      1: parent
                        72      LOAD_FAST                       0: self
                        74      LOAD_ATTR                       5: PopulateForm
                        94      CALL                            0
                        102     POP_TOP                         
                        104     LOAD_CONST                      0: None
                        106     NOP                             
                        108     NOP                             
                        110     NOP                             
                        112     JUMP_FORWARD                    19 (to 152)
                        120     POP_TOP                         
                        122     RETURN_CONST                    0: None
                        124     PUSH_EXC_INFO                   
                        126     PUSH_NULL                       
                        128     LOAD_CONST                      4: '__pyarmor_exit_54660__'
                        130     NOP                             
                        132     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
                        134     CALL                            1
                        142     POP_TOP                         
                        144     RERAISE                         0
                        146     COPY                            3
                        148     POP_EXCEPT                      
                        150     RERAISE                         1
                        152     PUSH_NULL                       
                        154     LOAD_CONST                      4: '__pyarmor_exit_54660__'
                        156     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1ab\x00\x00\x00\x00\x00\x00\x00'
                        158     BUILD_TUPLE                     1
                        160     CALL_FUNCTION_EX                0
                        162     POP_TOP                         
                        164     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: PopulateForm
                    Qualified Name: UserConfirmFormForFuncName.PopulateForm
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtWidgets'
                        'QVBoxLayout'
                        'setAlignment'
                        'QtCore'
                        'Qt'
                        'AlignTop'
                        'AlignLeft'
                        'isinstance'
                        'response'
                        'str'
                        'EditablePredictionWidget'
                        'idc'
                        'get_func_name'
                        'ea'
                        'widgets'
                        'append'
                        'addWidget'
                        'dict'
                        'get'
                        'list'
                        'QHBoxLayout'
                        'QPushButton'
                        'clicked'
                        'connect'
                        'on_accept_clicked'
                        'on_cancel_clicked'
                        'addLayout'
                        'QScrollArea'
                        'setWidgetResizable'
                        'QWidget'
                        'setLayout'
                        'setWidget'
                        'parent'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_35'
                        '_var_var_81'
                        '_var_var_82'
                        '_var_var_83'
                        '_var_var_66'
                        '_var_var_67'
                        '_var_var_68'
                        '_var_var_69'
                        '_var_var_70'
                        '_var_var_71'
                    [Constants]
                        None
                        '__pyarmor_assert_54661__'
                        '__pyarmor_enter_54662__'
                        b'<COAddr>\x01\x00\x00\x1a\xd8\x06\x00\x00\x00\x00\x00\x00'
                        'Function Name (Current: '
                        ')'
                        (
                            'widget'
                            'original'
                        )
                        'original'
                        ''
                        'prediction'
                        'Function Name (Original: '
                        'Accept Selected'
                        'Cancel'
                        True
                        '__pyarmor_exit_54663__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54662__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd8\x06\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + QtWidgets
                        38      LOAD_ATTR                       2: QVBoxLayout
                        58      CALL                            0
                        66      STORE_FAST                      2: _var_var_1
                        68      LOAD_FAST                       2: _var_var_1
                        70      LOAD_ATTR                       5: setAlignment
                        90      LOAD_GLOBAL                     6: QtCore
                        100     LOAD_ATTR                       8: Qt
                        120     LOAD_ATTR                       10: AlignTop
                        140     LOAD_GLOBAL                     6: QtCore
                        150     LOAD_ATTR                       8: Qt
                        170     LOAD_ATTR                       12: AlignLeft
                        190     BINARY_OP                       7 (|)
                        194     CALL                            1
                        202     POP_TOP                         
                        204     LOAD_GLOBAL                     15: NULL + isinstance
                        214     LOAD_FAST                       0: self
                        216     LOAD_ATTR                       16: response
                        236     LOAD_GLOBAL                     18: str
                        246     CALL                            2
                        254     POP_JUMP_IF_FALSE               104 (to 464)
                        256     LOAD_GLOBAL                     21: NULL + EditablePredictionWidget
                        266     LOAD_CONST                      4: 'Function Name (Current: '
                        268     LOAD_GLOBAL                     23: NULL + idc
                        278     LOAD_ATTR                       24: get_func_name
                        298     LOAD_FAST                       0: self
                        300     LOAD_ATTR                       26: ea
                        320     CALL                            1
                        328     FORMAT_VALUE                    0 (FVC_NONE)
                        330     LOAD_CONST                      5: ')'
                        332     BUILD_STRING                    3
                        334     LOAD_FAST                       0: self
                        336     LOAD_ATTR                       16: response
                        356     CALL                            2
                        364     STORE_FAST                      3: _var_var_35
                        366     LOAD_FAST                       0: self
                        368     LOAD_ATTR                       28: widgets
                        388     LOAD_ATTR                       31: append
                        408     LOAD_FAST                       3: _var_var_35
                        410     LOAD_CONST                      0: None
                        412     LOAD_CONST                      6: ('widget', 'original')
                        414     BUILD_CONST_KEY_MAP             2
                        416     CALL                            1
                        424     POP_TOP                         
                        426     LOAD_FAST                       2: _var_var_1
                        428     LOAD_ATTR                       33: addWidget
                        448     LOAD_FAST                       3: _var_var_35
                        450     CALL                            1
                        458     POP_TOP                         
                        460     JUMP_FORWARD                    305 (to 1074)
                        464     LOAD_GLOBAL                     15: NULL + isinstance
                        474     LOAD_FAST                       0: self
                        476     LOAD_ATTR                       16: response
                        496     LOAD_GLOBAL                     34: dict
                        506     CALL                            2
                        514     POP_JUMP_IF_FALSE               120 (to 756)
                        516     LOAD_FAST                       0: self
                        518     LOAD_ATTR                       16: response
                        538     LOAD_ATTR                       37: get
                        558     LOAD_CONST                      7: 'original'
                        560     LOAD_CONST                      8: ''
                        562     CALL                            2
                        570     STORE_FAST                      4: _var_var_81
                        572     LOAD_FAST                       0: self
                        574     LOAD_ATTR                       16: response
                        594     LOAD_ATTR                       37: get
                        614     LOAD_CONST                      9: 'prediction'
                        616     LOAD_CONST                      8: ''
                        618     CALL                            2
                        626     STORE_FAST                      5: _var_var_82
                        628     LOAD_GLOBAL                     21: NULL + EditablePredictionWidget
                        638     LOAD_CONST                      10: 'Function Name (Original: '
                        640     LOAD_FAST                       4: _var_var_81
                        642     FORMAT_VALUE                    0 (FVC_NONE)
                        644     LOAD_CONST                      5: ')'
                        646     BUILD_STRING                    3
                        648     LOAD_FAST                       5: _var_var_82
                        650     CALL                            2
                        658     STORE_FAST                      3: _var_var_35
                        660     LOAD_FAST                       0: self
                        662     LOAD_ATTR                       28: widgets
                        682     LOAD_ATTR                       31: append
                        702     LOAD_FAST                       3: _var_var_35
                        704     LOAD_FAST                       4: _var_var_81
                        706     LOAD_CONST                      6: ('widget', 'original')
                        708     BUILD_CONST_KEY_MAP             2
                        710     CALL                            1
                        718     POP_TOP                         
                        720     LOAD_FAST                       2: _var_var_1
                        722     LOAD_ATTR                       33: addWidget
                        742     LOAD_FAST                       3: _var_var_35
                        744     CALL                            1
                        752     POP_TOP                         
                        754     JUMP_FORWARD                    159 (to 1074)
                        756     LOAD_GLOBAL                     15: NULL + isinstance
                        766     LOAD_FAST                       0: self
                        768     LOAD_ATTR                       16: response
                        788     LOAD_GLOBAL                     38: list
                        798     CALL                            2
                        806     POP_JUMP_IF_FALSE               133 (to 1074)
                        808     LOAD_FAST                       0: self
                        810     LOAD_ATTR                       16: response
                        830     GET_ITER                        
                        832     FOR_ITER                        118 (to 1070)
                        836     STORE_FAST                      6: _var_var_83
                        838     LOAD_GLOBAL                     15: NULL + isinstance
                        848     LOAD_FAST                       6: _var_var_83
                        850     LOAD_GLOBAL                     34: dict
                        860     CALL                            2
                        868     POP_JUMP_IF_TRUE                1 (to 872)
                        870     JUMP_BACKWARD                   20 (to 832)
                        872     LOAD_FAST                       6: _var_var_83
                        874     LOAD_ATTR                       37: get
                        894     LOAD_CONST                      7: 'original'
                        896     LOAD_CONST                      8: ''
                        898     CALL                            2
                        906     STORE_FAST                      4: _var_var_81
                        908     LOAD_FAST                       6: _var_var_83
                        910     LOAD_ATTR                       37: get
                        930     LOAD_CONST                      9: 'prediction'
                        932     LOAD_CONST                      8: ''
                        934     CALL                            2
                        942     STORE_FAST                      5: _var_var_82
                        944     LOAD_GLOBAL                     21: NULL + EditablePredictionWidget
                        954     LOAD_CONST                      10: 'Function Name (Original: '
                        956     LOAD_FAST                       4: _var_var_81
                        958     FORMAT_VALUE                    0 (FVC_NONE)
                        960     LOAD_CONST                      5: ')'
                        962     BUILD_STRING                    3
                        964     LOAD_FAST                       5: _var_var_82
                        966     CALL                            2
                        974     STORE_FAST                      3: _var_var_35
                        976     LOAD_FAST                       0: self
                        978     LOAD_ATTR                       28: widgets
                        998     LOAD_ATTR                       31: append
                        1018    LOAD_FAST                       3: _var_var_35
                        1020    LOAD_FAST                       4: _var_var_81
                        1022    LOAD_CONST                      6: ('widget', 'original')
                        1024    BUILD_CONST_KEY_MAP             2
                        1026    CALL                            1
                        1034    POP_TOP                         
                        1036    LOAD_FAST                       2: _var_var_1
                        1038    LOAD_ATTR                       33: addWidget
                        1058    LOAD_FAST                       3: _var_var_35
                        1060    CALL                            1
                        1068    POP_TOP                         
                        1070    JUMP_BACKWARD                   120 (to 832)
                        1072    END_FOR                         
                        1074    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1084    LOAD_ATTR                       40: QHBoxLayout
                        1104    CALL                            0
                        1112    STORE_FAST                      7: _var_var_66
                        1114    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1124    LOAD_ATTR                       42: QPushButton
                        1144    LOAD_CONST                      11: 'Accept Selected'
                        1146    CALL                            1
                        1154    STORE_FAST                      8: _var_var_67
                        1156    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1166    LOAD_ATTR                       42: QPushButton
                        1186    LOAD_CONST                      12: 'Cancel'
                        1188    CALL                            1
                        1196    STORE_FAST                      9: _var_var_68
                        1198    LOAD_FAST                       8: _var_var_67
                        1200    LOAD_ATTR                       44: clicked
                        1220    LOAD_ATTR                       47: connect
                        1240    LOAD_FAST                       0: self
                        1242    LOAD_ATTR                       48: on_accept_clicked
                        1262    CALL                            1
                        1270    POP_TOP                         
                        1272    LOAD_FAST                       9: _var_var_68
                        1274    LOAD_ATTR                       44: clicked
                        1294    LOAD_ATTR                       47: connect
                        1314    LOAD_FAST                       0: self
                        1316    LOAD_ATTR                       50: on_cancel_clicked
                        1336    CALL                            1
                        1344    POP_TOP                         
                        1346    LOAD_FAST                       7: _var_var_66
                        1348    LOAD_ATTR                       33: addWidget
                        1368    LOAD_FAST                       8: _var_var_67
                        1370    CALL                            1
                        1378    POP_TOP                         
                        1380    LOAD_FAST                       7: _var_var_66
                        1382    LOAD_ATTR                       33: addWidget
                        1402    LOAD_FAST                       9: _var_var_68
                        1404    CALL                            1
                        1412    POP_TOP                         
                        1414    LOAD_FAST                       2: _var_var_1
                        1416    LOAD_ATTR                       53: addLayout
                        1436    LOAD_FAST                       7: _var_var_66
                        1438    CALL                            1
                        1446    POP_TOP                         
                        1448    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1458    LOAD_ATTR                       54: QScrollArea
                        1478    CALL                            0
                        1486    STORE_FAST                      10: _var_var_69
                        1488    LOAD_FAST                       10: _var_var_69
                        1490    LOAD_ATTR                       57: setWidgetResizable
                        1510    LOAD_CONST                      13: True
                        1512    CALL                            1
                        1520    POP_TOP                         
                        1522    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1532    LOAD_ATTR                       58: QWidget
                        1552    CALL                            0
                        1560    STORE_FAST                      11: _var_var_70
                        1562    LOAD_FAST                       11: _var_var_70
                        1564    LOAD_ATTR                       61: setLayout
                        1584    LOAD_FAST                       2: _var_var_1
                        1586    CALL                            1
                        1594    POP_TOP                         
                        1596    LOAD_FAST                       10: _var_var_69
                        1598    LOAD_ATTR                       63: setWidget
                        1618    LOAD_FAST                       11: _var_var_70
                        1620    CALL                            1
                        1628    POP_TOP                         
                        1630    LOAD_GLOBAL                     1: NULL + QtWidgets
                        1640    LOAD_ATTR                       2: QVBoxLayout
                        1660    CALL                            0
                        1668    STORE_FAST                      12: _var_var_71
                        1670    LOAD_FAST                       12: _var_var_71
                        1672    LOAD_ATTR                       33: addWidget
                        1692    LOAD_FAST                       10: _var_var_69
                        1694    CALL                            1
                        1702    POP_TOP                         
                        1704    LOAD_FAST                       0: self
                        1706    LOAD_ATTR                       64: parent
                        1726    LOAD_ATTR                       61: setLayout
                        1746    LOAD_FAST                       12: _var_var_71
                        1748    CALL                            1
                        1756    POP_TOP                         
                        1758    LOAD_CONST                      0: None
                        1760    NOP                             
                        1762    NOP                             
                        1764    NOP                             
                        1766    JUMP_FORWARD                    19 (to 1806)
                        1774    POP_TOP                         
                        1776    RETURN_CONST                    0: None
                        1778    PUSH_EXC_INFO                   
                        1780    PUSH_NULL                       
                        1782    LOAD_CONST                      14: '__pyarmor_exit_54663__'
                        1784    NOP                             
                        1786    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd8\x06\x00\x00\x00\x00\x00\x00'
                        1788    CALL                            1
                        1796    POP_TOP                         
                        1798    RERAISE                         0
                        1800    COPY                            3
                        1802    POP_EXCEPT                      
                        1804    RERAISE                         1
                        1806    PUSH_NULL                       
                        1808    LOAD_CONST                      14: '__pyarmor_exit_54663__'
                        1810    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xd8\x06\x00\x00\x00\x00\x00\x00'
                        1812    BUILD_TUPLE                     1
                        1814    CALL_FUNCTION_EX                0
                        1816    POP_TOP                         
                        1818    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: validate_fields
                    Qualified Name: UserConfirmFormForFuncName.validate_fields
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'widgets'
                        'accepted'
                        'get_content'
                        'strip'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_84'
                        '_var_var_35'
                    [Constants]
                        '验证所有字段是否都已正确填写'
                        '__pyarmor_assert_54664__'
                        '__pyarmor_enter_54665__'
                        b'<COAddr>\x01\x00\x00\x1a\xae\x00\x00\x00\x00\x00\x00\x00'
                        'widget'
                        '__pyarmor_exit_54666__'
                        (
                            False
                            'Please fill in all selected function names'
                        )
                        (
                            True
                            ''
                        )
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54665__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xae\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: widgets
                        50      GET_ITER                        
                        52      FOR_ITER                        61 (to 176)
                        56      STORE_FAST                      2: _var_var_84
                        58      LOAD_FAST                       2: _var_var_84
                        60      LOAD_CONST                      4: 'widget'
                        62      BINARY_SUBSCR                   
                        66      STORE_FAST                      3: _var_var_35
                        68      LOAD_FAST                       3: _var_var_35
                        70      LOAD_ATTR                       2: accepted
                        90      POP_JUMP_IF_TRUE                1 (to 94)
                        92      JUMP_BACKWARD                   21 (to 52)
                        94      LOAD_FAST                       3: _var_var_35
                        96      LOAD_ATTR                       5: get_content
                        116     CALL                            0
                        124     LOAD_ATTR                       7: strip
                        144     CALL                            0
                        152     POP_JUMP_IF_FALSE               1 (to 156)
                        154     JUMP_BACKWARD                   52 (to 52)
                        156     POP_TOP                         
                        158     LOAD_CONST                      6: (False, 'Please fill in all selected function names')
                        160     NOP                             
                        162     NOP                             
                        164     NOP                             
                        166     JUMP_FORWARD                    30 (to 228)
                        174     POP_TOP                         
                        176     RETURN_CONST                    6: (False, 'Please fill in all selected function names')
                        178     END_FOR                         
                        180     LOAD_CONST                      7: (True, '')
                        182     NOP                             
                        184     NOP                             
                        186     NOP                             
                        188     JUMP_FORWARD                    19 (to 228)
                        196     POP_TOP                         
                        198     RETURN_CONST                    7: (True, '')
                        200     PUSH_EXC_INFO                   
                        202     PUSH_NULL                       
                        204     LOAD_CONST                      5: '__pyarmor_exit_54666__'
                        206     NOP                             
                        208     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xae\x00\x00\x00\x00\x00\x00\x00'
                        210     CALL                            1
                        218     POP_TOP                         
                        220     RERAISE                         0
                        222     COPY                            3
                        224     POP_EXCEPT                      
                        226     RERAISE                         1
                        228     PUSH_NULL                       
                        230     LOAD_CONST                      5: '__pyarmor_exit_54666__'
                        232     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xae\x00\x00\x00\x00\x00\x00\x00'
                        234     BUILD_TUPLE                     1
                        236     CALL_FUNCTION_EX                0
                        238     POP_TOP                         
                        240     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_accept_clicked
                    Qualified Name: UserConfirmFormForFuncName.on_accept_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'validate_fields'
                        'QtWidgets'
                        'QMessageBox'
                        'warning'
                        'parent'
                        'isinstance'
                        'response'
                        'str'
                        'widgets'
                        'accepted'
                        'get_content'
                        'dict'
                        'list'
                        'append'
                        'settings_manager'
                        'settings'
                        'send_feedback'
                        'prompt'
                        'response_raw'
                        'task_tag'
                        'apply_prediction'
                        'ea'
                        'Close'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_73'
                        '_var_var_74'
                        '_var_var_75'
                        '_var_var_84'
                        '_var_var_35'
                    [Constants]
                        None
                        '__pyarmor_assert_54667__'
                        '__pyarmor_enter_54668__'
                        b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
                        'Validation Error'
                        '\nPlease fill in all selected fields before applying, otherwise unselect it.'
                        '__pyarmor_exit_54669__'
                        0
                        'widget'
                        'funcname'
                        'original'
                        (
                            'original'
                            'prediction'
                        )
                        'feedback'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54668__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: validate_fields
                        50      CALL                            0
                        58      UNPACK_SEQUENCE                 2
                        62      STORE_FAST                      2: _var_var_73
                        64      STORE_FAST                      3: _var_var_74
                        66      LOAD_FAST                       2: _var_var_73
                        68      POP_JUMP_IF_TRUE                57 (to 184)
                        70      LOAD_GLOBAL                     2: QtWidgets
                        80      LOAD_ATTR                       4: QMessageBox
                        100     LOAD_ATTR                       7: warning
                        120     LOAD_FAST                       0: self
                        122     LOAD_ATTR                       8: parent
                        142     LOAD_CONST                      4: 'Validation Error'
                        144     LOAD_FAST                       3: _var_var_74
                        146     FORMAT_VALUE                    0 (FVC_NONE)
                        148     LOAD_CONST                      5: '\nPlease fill in all selected fields before applying, otherwise unselect it.'
                        150     BUILD_STRING                    2
                        152     CALL                            3
                        160     POP_TOP                         
                        162     NOP                             
                        164     LOAD_CONST                      0: None
                        166     NOP                             
                        168     NOP                             
                        170     JUMP_FORWARD                    442 (to 1058)
                        180     POP_TOP                         
                        182     RETURN_CONST                    0: None
                        184     BUILD_MAP                       0
                        186     STORE_FAST                      4: _var_var_75
                        188     LOAD_GLOBAL                     11: NULL + isinstance
                        198     LOAD_FAST                       0: self
                        200     LOAD_ATTR                       12: response
                        220     LOAD_GLOBAL                     14: str
                        230     CALL                            2
                        238     POP_JUMP_IF_FALSE               64 (to 368)
                        240     LOAD_FAST                       0: self
                        242     LOAD_ATTR                       16: widgets
                        262     LOAD_CONST                      7: 0
                        264     BINARY_SUBSCR                   
                        268     LOAD_CONST                      8: 'widget'
                        270     BINARY_SUBSCR                   
                        274     LOAD_ATTR                       18: accepted
                        294     POP_JUMP_IF_FALSE               242 (to 780)
                        296     LOAD_FAST                       0: self
                        298     LOAD_ATTR                       16: widgets
                        318     LOAD_CONST                      7: 0
                        320     BINARY_SUBSCR                   
                        324     LOAD_CONST                      8: 'widget'
                        326     BINARY_SUBSCR                   
                        330     LOAD_ATTR                       21: get_content
                        350     CALL                            0
                        358     LOAD_FAST                       4: _var_var_75
                        360     LOAD_CONST                      9: 'funcname'
                        362     STORE_SUBSCR                    
                        366     JUMP_FORWARD                    206 (to 780)
                        368     LOAD_GLOBAL                     11: NULL + isinstance
                        378     LOAD_FAST                       0: self
                        380     LOAD_ATTR                       12: response
                        400     LOAD_GLOBAL                     22: dict
                        410     CALL                            2
                        418     POP_JUMP_IF_FALSE               80 (to 580)
                        420     LOAD_FAST                       0: self
                        422     LOAD_ATTR                       16: widgets
                        442     LOAD_CONST                      7: 0
                        444     BINARY_SUBSCR                   
                        448     LOAD_CONST                      8: 'widget'
                        450     BINARY_SUBSCR                   
                        454     LOAD_ATTR                       18: accepted
                        474     POP_JUMP_IF_FALSE               152 (to 780)
                        476     LOAD_FAST                       0: self
                        478     LOAD_ATTR                       16: widgets
                        498     LOAD_CONST                      7: 0
                        500     BINARY_SUBSCR                   
                        504     LOAD_CONST                      10: 'original'
                        506     BINARY_SUBSCR                   
                        510     LOAD_FAST                       0: self
                        512     LOAD_ATTR                       16: widgets
                        532     LOAD_CONST                      7: 0
                        534     BINARY_SUBSCR                   
                        538     LOAD_CONST                      8: 'widget'
                        540     BINARY_SUBSCR                   
                        544     LOAD_ATTR                       21: get_content
                        564     CALL                            0
                        572     LOAD_CONST                      11: ('original', 'prediction')
                        574     BUILD_CONST_KEY_MAP             2
                        576     STORE_FAST                      4: _var_var_75
                        578     JUMP_FORWARD                    100 (to 780)
                        580     LOAD_GLOBAL                     11: NULL + isinstance
                        590     LOAD_FAST                       0: self
                        592     LOAD_ATTR                       12: response
                        612     LOAD_GLOBAL                     24: list
                        622     CALL                            2
                        630     POP_JUMP_IF_FALSE               74 (to 780)
                        632     BUILD_LIST                      0
                        634     STORE_FAST                      4: _var_var_75
                        636     LOAD_FAST                       0: self
                        638     LOAD_ATTR                       16: widgets
                        658     GET_ITER                        
                        660     FOR_ITER                        57 (to 776)
                        664     STORE_FAST                      5: _var_var_84
                        666     LOAD_FAST                       5: _var_var_84
                        668     LOAD_CONST                      8: 'widget'
                        670     BINARY_SUBSCR                   
                        674     STORE_FAST                      6: _var_var_35
                        676     LOAD_FAST                       6: _var_var_35
                        678     LOAD_ATTR                       18: accepted
                        698     POP_JUMP_IF_TRUE                1 (to 702)
                        700     JUMP_BACKWARD                   21 (to 660)
                        702     LOAD_FAST                       4: _var_var_75
                        704     LOAD_ATTR                       27: append
                        724     LOAD_FAST                       5: _var_var_84
                        726     LOAD_CONST                      10: 'original'
                        728     BINARY_SUBSCR                   
                        732     LOAD_FAST                       6: _var_var_35
                        734     LOAD_ATTR                       21: get_content
                        754     CALL                            0
                        762     LOAD_CONST                      11: ('original', 'prediction')
                        764     BUILD_CONST_KEY_MAP             2
                        766     CALL                            1
                        774     POP_TOP                         
                        776     JUMP_BACKWARD                   59 (to 660)
                        778     END_FOR                         
                        780     LOAD_FAST                       4: _var_var_75
                        782     POP_JUMP_IF_FALSE               96 (to 976)
                        784     LOAD_GLOBAL                     28: settings_manager
                        794     LOAD_ATTR                       30: settings
                        814     LOAD_CONST                      12: 'feedback'
                        816     BINARY_SUBSCR                   
                        820     POP_JUMP_IF_FALSE               44 (to 910)
                        822     LOAD_GLOBAL                     33: NULL + send_feedback
                        832     LOAD_FAST                       0: self
                        834     LOAD_ATTR                       34: prompt
                        854     LOAD_FAST                       0: self
                        856     LOAD_ATTR                       36: response_raw
                        876     LOAD_FAST                       4: _var_var_75
                        878     LOAD_FAST                       0: self
                        880     LOAD_ATTR                       38: task_tag
                        900     CALL                            4
                        908     POP_TOP                         
                        910     LOAD_GLOBAL                     41: NULL + apply_prediction
                        920     LOAD_FAST                       0: self
                        922     LOAD_ATTR                       42: ea
                        942     LOAD_FAST                       0: self
                        944     LOAD_ATTR                       38: task_tag
                        964     LOAD_FAST                       4: _var_var_75
                        966     CALL                            3
                        974     POP_TOP                         
                        976     LOAD_FAST                       0: self
                        978     LOAD_ATTR                       45: Close
                        998     LOAD_CONST                      7: 0
                        1000    CALL                            1
                        1008    POP_TOP                         
                        1010    LOAD_CONST                      0: None
                        1012    NOP                             
                        1014    NOP                             
                        1016    NOP                             
                        1018    JUMP_FORWARD                    19 (to 1058)
                        1026    POP_TOP                         
                        1028    RETURN_CONST                    0: None
                        1030    PUSH_EXC_INFO                   
                        1032    PUSH_NULL                       
                        1034    LOAD_CONST                      6: '__pyarmor_exit_54669__'
                        1036    NOP                             
                        1038    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
                        1040    CALL                            1
                        1048    POP_TOP                         
                        1050    RERAISE                         0
                        1052    COPY                            3
                        1054    POP_EXCEPT                      
                        1056    RERAISE                         1
                        1058    PUSH_NULL                       
                        1060    LOAD_CONST                      6: '__pyarmor_exit_54669__'
                        1062    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xec\x03\x00\x00\x00\x00\x00\x00'
                        1064    BUILD_TUPLE                     1
                        1066    CALL_FUNCTION_EX                0
                        1068    POP_TOP                         
                        1070    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_cancel_clicked
                    Qualified Name: UserConfirmFormForFuncName.on_cancel_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'Close'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54670__'
                        '__pyarmor_enter_54671__'
                        b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        0
                        '__pyarmor_exit_54672__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54671__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: Close
                        50      LOAD_CONST                      4: 0
                        52      CALL                            1
                        60      POP_TOP                         
                        62      LOAD_CONST                      0: None
                        64      NOP                             
                        66      NOP                             
                        68      NOP                             
                        70      JUMP_FORWARD                    19 (to 110)
                        78      POP_TOP                         
                        80      RETURN_CONST                    0: None
                        82      PUSH_EXC_INFO                   
                        84      PUSH_NULL                       
                        86      LOAD_CONST                      5: '__pyarmor_exit_54672__'
                        88      NOP                             
                        90      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        92      CALL                            1
                        100     POP_TOP                         
                        102     RERAISE                         0
                        104     COPY                            3
                        106     POP_EXCEPT                      
                        108     RERAISE                         1
                        110     PUSH_NULL                       
                        112     LOAD_CONST                      5: '__pyarmor_exit_54672__'
                        114     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        116     BUILD_TUPLE                     1
                        118     CALL_FUNCTION_EX                0
                        120     POP_TOP                         
                        122     RETURN_VALUE                    
                '__pyarmor_exit_54654__'
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'UserConfirmFormForFuncName'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54653__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
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
                48      LOAD_CONST                      5: <CODE> OnCreate
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      5: OnCreate
                54      LOAD_CONST                      6: <CODE> PopulateForm
                56      MAKE_FUNCTION                   0
                58      STORE_NAME                      6: PopulateForm
                60      LOAD_CONST                      7: <CODE> validate_fields
                62      MAKE_FUNCTION                   0
                64      STORE_NAME                      7: validate_fields
                66      LOAD_CONST                      8: <CODE> on_accept_clicked
                68      MAKE_FUNCTION                   0
                70      STORE_NAME                      8: on_accept_clicked
                72      LOAD_CONST                      9: <CODE> on_cancel_clicked
                74      MAKE_FUNCTION                   0
                76      STORE_NAME                      9: on_cancel_clicked
                78      LOAD_CLOSURE                    0: __class__
                80      COPY                            1
                82      STORE_NAME                      10: __classcell__
                84      NOP                             
                86      NOP                             
                88      NOP                             
                90      JUMP_FORWARD                    20 (to 132)
                94      POP_TOP                         
                96      LOAD_CLOSURE                    0: __class__
                98      COPY                            1
                100     STORE_NAME                      10: __classcell__
                102     RETURN_VALUE                    
                104     PUSH_EXC_INFO                   
                106     PUSH_NULL                       
                108     LOAD_CONST                      10: '__pyarmor_exit_54654__'
                110     NOP                             
                112     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                114     CALL                            1
                122     POP_TOP                         
                124     RERAISE                         0
                126     COPY                            3
                128     POP_EXCEPT                      
                130     RERAISE                         1
                132     PUSH_NULL                       
                134     LOAD_CONST                      10: '__pyarmor_exit_54654__'
                136     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                138     BUILD_TUPLE                     1
                140     CALL_FUNCTION_EX                0
                142     POP_TOP                         
                144     RETURN_VALUE                    
        'UserConfirmFormForFuncName'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: create_user_confirm_view_for_funcname
            Qualified Name: create_user_confirm_view_for_funcname
            Arg Count: 5
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 7
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'UserConfirmFormForFuncName'
                'Show'
                'hex'
            [Locals+Names]
                'ea'
                'task_tag'
                'prompt'
                'response_raw'
                'response'
                '__assert_armored__'
                '_var_var_7'
            [Constants]
                None
                '__pyarmor_assert_54673__'
                '__pyarmor_enter_54674__'
                b'<COAddr>\x01\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                'ReCopilot Predictions - '
                '__pyarmor_exit_54675__'
                True
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54674__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_GLOBAL                     1: NULL + UserConfirmFormForFuncName
                38      LOAD_FAST                       0: ea
                40      LOAD_FAST                       1: task_tag
                42      LOAD_FAST                       2: prompt
                44      LOAD_FAST                       3: response_raw
                46      LOAD_FAST                       4: response
                48      CALL                            5
                56      STORE_FAST                      6: _var_var_7
                58      LOAD_FAST                       6: _var_var_7
                60      LOAD_ATTR                       3: Show
                80      LOAD_CONST                      4: 'ReCopilot Predictions - '
                82      LOAD_GLOBAL                     5: NULL + hex
                92      LOAD_FAST                       0: ea
                94      CALL                            1
                102     FORMAT_VALUE                    0 (FVC_NONE)
                104     BUILD_STRING                    2
                106     CALL                            1
                114     POP_TOP                         
                116     LOAD_CONST                      6: True
                118     NOP                             
                120     NOP                             
                122     NOP                             
                124     JUMP_FORWARD                    19 (to 164)
                132     POP_TOP                         
                134     RETURN_CONST                    6: True
                136     PUSH_EXC_INFO                   
                138     PUSH_NULL                       
                140     LOAD_CONST                      5: '__pyarmor_exit_54675__'
                142     NOP                             
                144     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                146     CALL                            1
                154     POP_TOP                         
                156     RERAISE                         0
                158     COPY                            3
                160     POP_EXCEPT                      
                162     RERAISE                         1
                164     PUSH_NULL                       
                166     LOAD_CONST                      5: '__pyarmor_exit_54675__'
                168     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1an\x00\x00\x00\x00\x00\x00\x00'
                170     BUILD_TUPLE                     1
                172     CALL_FUNCTION_EX                0
                174     POP_TOP                         
                176     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: VariableSelectionWidget
            Qualified Name: VariableSelectionWidget
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
                'on_select_all'
                'get_selected_variables'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'VariableSelectionWidget'
                '__pyarmor_assert_54676__'
                '__pyarmor_enter_54677__'
                b'<COAddr>\x01\x00\x00$2\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: VariableSelectionWidget.__init__
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'VariableSelectionWidget'
                        '__init__'
                        'variables'
                        'checkboxes'
                        'QtWidgets'
                        'QVBoxLayout'
                        'QHBoxLayout'
                        'addWidget'
                        'QLabel'
                        'QCheckBox'
                        'select_all_checkbox'
                        'setChecked'
                        'stateChanged'
                        'connect'
                        'on_select_all'
                        'addStretch'
                        'addLayout'
                        'append'
                        'setLayout'
                    [Locals+Names]
                        'self'
                        'title'
                        'variables'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_18'
                        '_var_var_49'
                        '_var_var_85'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54679__'
                        '__pyarmor_enter_54680__'
                        b'<COAddr>\x03\x00\x00\x1c\x02\x03\x00\x00\x00\x00\x00\x00'
                        'Select All'
                        True
                        '__pyarmor_exit_54681__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54680__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\x02\x03\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: VariableSelectionWidget
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_FAST                       2: variables
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: variables
                        80      BUILD_LIST                      0
                        82      LOAD_FAST                       0: self
                        84      STORE_ATTR                      4: checkboxes
                        94      LOAD_GLOBAL                     11: NULL + QtWidgets
                        104     LOAD_ATTR                       12: QVBoxLayout
                        124     CALL                            0
                        132     STORE_FAST                      4: _var_var_1
                        134     LOAD_GLOBAL                     11: NULL + QtWidgets
                        144     LOAD_ATTR                       14: QHBoxLayout
                        164     CALL                            0
                        172     STORE_FAST                      5: _var_var_18
                        174     LOAD_FAST                       5: _var_var_18
                        176     LOAD_ATTR                       17: addWidget
                        196     LOAD_GLOBAL                     11: NULL + QtWidgets
                        206     LOAD_ATTR                       18: QLabel
                        226     LOAD_FAST                       1: title
                        228     CALL                            1
                        236     CALL                            1
                        244     POP_TOP                         
                        246     LOAD_GLOBAL                     11: NULL + QtWidgets
                        256     LOAD_ATTR                       20: QCheckBox
                        276     LOAD_CONST                      4: 'Select All'
                        278     CALL                            1
                        286     LOAD_FAST                       0: self
                        288     STORE_ATTR                      11: select_all_checkbox
                        298     LOAD_FAST                       0: self
                        300     LOAD_ATTR                       22: select_all_checkbox
                        320     LOAD_ATTR                       25: setChecked
                        340     LOAD_CONST                      5: True
                        342     CALL                            1
                        350     POP_TOP                         
                        352     LOAD_FAST                       0: self
                        354     LOAD_ATTR                       22: select_all_checkbox
                        374     LOAD_ATTR                       26: stateChanged
                        394     LOAD_ATTR                       29: connect
                        414     LOAD_FAST                       0: self
                        416     LOAD_ATTR                       30: on_select_all
                        436     CALL                            1
                        444     POP_TOP                         
                        446     LOAD_FAST                       5: _var_var_18
                        448     LOAD_ATTR                       17: addWidget
                        468     LOAD_FAST                       0: self
                        470     LOAD_ATTR                       22: select_all_checkbox
                        490     CALL                            1
                        498     POP_TOP                         
                        500     LOAD_FAST                       5: _var_var_18
                        502     LOAD_ATTR                       33: addStretch
                        522     CALL                            0
                        530     POP_TOP                         
                        532     LOAD_FAST                       4: _var_var_1
                        534     LOAD_ATTR                       35: addLayout
                        554     LOAD_FAST                       5: _var_var_18
                        556     CALL                            1
                        564     POP_TOP                         
                        566     LOAD_FAST                       2: variables
                        568     GET_ITER                        
                        570     FOR_ITER                        84 (to 740)
                        574     STORE_FAST                      6: _var_var_49
                        576     LOAD_GLOBAL                     11: NULL + QtWidgets
                        586     LOAD_ATTR                       20: QCheckBox
                        606     LOAD_FAST                       6: _var_var_49
                        608     CALL                            1
                        616     STORE_FAST                      7: _var_var_85
                        618     LOAD_FAST                       7: _var_var_85
                        620     LOAD_ATTR                       25: setChecked
                        640     LOAD_CONST                      5: True
                        642     CALL                            1
                        650     POP_TOP                         
                        652     LOAD_FAST                       0: self
                        654     LOAD_ATTR                       8: checkboxes
                        674     LOAD_ATTR                       37: append
                        694     LOAD_FAST                       7: _var_var_85
                        696     CALL                            1
                        704     POP_TOP                         
                        706     LOAD_FAST                       4: _var_var_1
                        708     LOAD_ATTR                       17: addWidget
                        728     LOAD_FAST                       7: _var_var_85
                        730     CALL                            1
                        738     POP_TOP                         
                        740     JUMP_BACKWARD                   86 (to 570)
                        742     END_FOR                         
                        744     LOAD_FAST                       0: self
                        746     LOAD_ATTR                       39: setLayout
                        766     LOAD_FAST                       4: _var_var_1
                        768     CALL                            1
                        776     POP_TOP                         
                        778     LOAD_CONST                      0: None
                        780     NOP                             
                        782     NOP                             
                        784     NOP                             
                        786     JUMP_FORWARD                    19 (to 826)
                        794     POP_TOP                         
                        796     RETURN_CONST                    0: None
                        798     PUSH_EXC_INFO                   
                        800     PUSH_NULL                       
                        802     LOAD_CONST                      6: '__pyarmor_exit_54681__'
                        804     NOP                             
                        806     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\x02\x03\x00\x00\x00\x00\x00\x00'
                        808     CALL                            1
                        816     POP_TOP                         
                        818     RERAISE                         0
                        820     COPY                            3
                        822     POP_EXCEPT                      
                        824     RERAISE                         1
                        826     PUSH_NULL                       
                        828     LOAD_CONST                      6: '__pyarmor_exit_54681__'
                        830     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\x02\x03\x00\x00\x00\x00\x00\x00'
                        832     BUILD_TUPLE                     1
                        834     CALL_FUNCTION_EX                0
                        836     POP_TOP                         
                        838     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_select_all
                    Qualified Name: VariableSelectionWidget.on_select_all
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'checkboxes'
                        'setChecked'
                        'QtCore'
                        'Qt'
                        'Checked'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                        '_var_var_85'
                    [Constants]
                        None
                        '__pyarmor_assert_54682__'
                        '__pyarmor_enter_54683__'
                        b'<COAddr>\x03\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54684__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54683__'
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
                        28      LOAD_FAST                       0: self
                        30      LOAD_ATTR                       0: checkboxes
                        50      GET_ITER                        
                        52      FOR_ITER                        46 (to 146)
                        56      STORE_FAST                      3: _var_var_85
                        58      LOAD_FAST                       3: _var_var_85
                        60      LOAD_ATTR                       3: setChecked
                        80      LOAD_FAST                       1: state
                        82      LOAD_GLOBAL                     4: QtCore
                        92      LOAD_ATTR                       6: Qt
                        112     LOAD_ATTR                       8: Checked
                        132     COMPARE_OP                      40 (==)
                        136     CALL                            1
                        144     POP_TOP                         
                        146     JUMP_BACKWARD                   48 (to 52)
                        148     END_FOR                         
                        150     LOAD_CONST                      0: None
                        152     NOP                             
                        154     NOP                             
                        156     NOP                             
                        158     JUMP_FORWARD                    19 (to 198)
                        166     POP_TOP                         
                        168     RETURN_CONST                    0: None
                        170     PUSH_EXC_INFO                   
                        172     PUSH_NULL                       
                        174     LOAD_CONST                      4: '__pyarmor_exit_54684__'
                        176     NOP                             
                        178     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        180     CALL                            1
                        188     POP_TOP                         
                        190     RERAISE                         0
                        192     COPY                            3
                        194     POP_EXCEPT                      
                        196     RERAISE                         1
                        198     PUSH_NULL                       
                        200     LOAD_CONST                      4: '__pyarmor_exit_54684__'
                        202     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        204     BUILD_TUPLE                     1
                        206     CALL_FUNCTION_EX                0
                        208     POP_TOP                         
                        210     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: get_selected_variables
                    Qualified Name: VariableSelectionWidget.get_selected_variables
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'checkboxes'
                        'isChecked'
                        'text'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_86'
                    [Constants]
                        None
                        '__pyarmor_assert_54685__'
                        '__pyarmor_enter_54686__'
                        b'<COAddr>\x01\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54687__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54686__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: checkboxes
                        50      GET_ITER                        
                        52      LOAD_FAST_AND_CLEAR             2: _var_var_86
                        54      SWAP                            2
                        56      BUILD_LIST                      0
                        58      SWAP                            2
                        60      FOR_ITER                        35 (to 132)
                        64      STORE_FAST                      2: _var_var_86
                        66      LOAD_FAST                       2: _var_var_86
                        68      LOAD_ATTR                       3: isChecked
                        88      CALL                            0
                        96      POP_JUMP_IF_TRUE                1 (to 100)
                        98      JUMP_BACKWARD                   20 (to 60)
                        100     LOAD_FAST                       2: _var_var_86
                        102     LOAD_ATTR                       5: text
                        122     CALL                            0
                        130     LIST_APPEND                     2
                        132     JUMP_BACKWARD                   37 (to 60)
                        134     END_FOR                         
                        136     SWAP                            2
                        138     STORE_FAST                      2: _var_var_86
                        140     NOP                             
                        142     NOP                             
                        144     NOP                             
                        146     JUMP_FORWARD                    25 (to 198)
                        148     CALL                            1
                        156     POP_TOP                         
                        158     RETURN_VALUE                    
                        160     SWAP                            2
                        162     POP_TOP                         
                        164     SWAP                            2
                        166     STORE_FAST                      2: _var_var_86
                        168     RERAISE                         0
                        170     PUSH_EXC_INFO                   
                        172     PUSH_NULL                       
                        174     LOAD_CONST                      4: '__pyarmor_exit_54687__'
                        176     NOP                             
                        178     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        180     CALL                            1
                        188     POP_TOP                         
                        190     RERAISE                         0
                        192     COPY                            3
                        194     POP_EXCEPT                      
                        196     RERAISE                         1
                        198     PUSH_NULL                       
                        200     LOAD_CONST                      4: '__pyarmor_exit_54687__'
                        202     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\x90\x00\x00\x00\x00\x00\x00\x00'
                        204     BUILD_TUPLE                     1
                        206     CALL_FUNCTION_EX                0
                        208     POP_TOP                         
                        210     RETURN_VALUE                    
                '__pyarmor_exit_54678__'
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'VariableSelectionWidget'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54677__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$2\x00\x00\x00\x00\x00\x00\x00'
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
                48      LOAD_CONST                      5: <CODE> on_select_all
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      5: on_select_all
                54      LOAD_CONST                      6: <CODE> get_selected_variables
                56      MAKE_FUNCTION                   0
                58      STORE_NAME                      6: get_selected_variables
                60      LOAD_CLOSURE                    0: __class__
                62      COPY                            1
                64      STORE_NAME                      7: __classcell__
                66      NOP                             
                68      NOP                             
                70      NOP                             
                72      JUMP_FORWARD                    20 (to 114)
                76      POP_TOP                         
                78      LOAD_CLOSURE                    0: __class__
                80      COPY                            1
                82      STORE_NAME                      7: __classcell__
                84      RETURN_VALUE                    
                86      PUSH_EXC_INFO                   
                88      PUSH_NULL                       
                90      LOAD_CONST                      7: '__pyarmor_exit_54678__'
                92      NOP                             
                94      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$2\x00\x00\x00\x00\x00\x00\x00'
                96      CALL                            1
                104     POP_TOP                         
                106     RERAISE                         0
                108     COPY                            3
                110     POP_EXCEPT                      
                112     RERAISE                         1
                114     PUSH_NULL                       
                116     LOAD_CONST                      7: '__pyarmor_exit_54678__'
                118     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$2\x00\x00\x00\x00\x00\x00\x00'
                120     BUILD_TUPLE                     1
                122     CALL_FUNCTION_EX                0
                124     POP_TOP                         
                126     RETURN_VALUE                    
        'VariableSelectionWidget'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: VariableSelectionForm
            Qualified Name: VariableSelectionForm
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
                'OnCreate'
                'PopulateForm'
                'on_main_select_all'
                'on_analyze_clicked'
                'on_cancel_clicked'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'VariableSelectionForm'
                '__pyarmor_assert_54688__'
                '__pyarmor_enter_54689__'
                b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: VariableSelectionForm.__init__
                    Arg Count: 4
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'VariableSelectionForm'
                        '__init__'
                        'ea'
                        'args'
                        'vars'
                        'selected_args'
                        'selected_vars'
                        'hex'
                        'title'
                    [Locals+Names]
                        'self'
                        'ea'
                        'args'
                        'vars'
                        '__assert_armored__'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54691__'
                        '__pyarmor_enter_54692__'
                        b'<COAddr>\x03\x00\x00\x1c\xa6\x00\x00\x00\x00\x00\x00\x00'
                        'Select Variables to Analyze - '
                        '__pyarmor_exit_54693__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54692__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xa6\x00\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: VariableSelectionForm
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      CALL                            0
                        64      POP_TOP                         
                        66      LOAD_FAST                       1: ea
                        68      LOAD_FAST                       0: self
                        70      STORE_ATTR                      3: ea
                        80      LOAD_FAST                       2: args
                        82      LOAD_FAST                       0: self
                        84      STORE_ATTR                      4: args
                        94      LOAD_FAST                       3: vars
                        96      LOAD_FAST                       0: self
                        98      STORE_ATTR                      5: vars
                        108     BUILD_LIST                      0
                        110     LOAD_FAST                       0: self
                        112     STORE_ATTR                      6: selected_args
                        122     BUILD_LIST                      0
                        124     LOAD_FAST                       0: self
                        126     STORE_ATTR                      7: selected_vars
                        136     LOAD_CONST                      4: 'Select Variables to Analyze - '
                        138     LOAD_GLOBAL                     17: NULL + hex
                        148     LOAD_FAST                       1: ea
                        150     CALL                            1
                        158     FORMAT_VALUE                    0 (FVC_NONE)
                        160     BUILD_STRING                    2
                        162     LOAD_FAST                       0: self
                        164     STORE_ATTR                      9: title
                        174     LOAD_CONST                      0: None
                        176     NOP                             
                        178     NOP                             
                        180     NOP                             
                        182     JUMP_FORWARD                    19 (to 222)
                        190     POP_TOP                         
                        192     RETURN_CONST                    0: None
                        194     PUSH_EXC_INFO                   
                        196     PUSH_NULL                       
                        198     LOAD_CONST                      5: '__pyarmor_exit_54693__'
                        200     NOP                             
                        202     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xa6\x00\x00\x00\x00\x00\x00\x00'
                        204     CALL                            1
                        212     POP_TOP                         
                        214     RERAISE                         0
                        216     COPY                            3
                        218     POP_EXCEPT                      
                        220     RERAISE                         1
                        222     PUSH_NULL                       
                        224     LOAD_CONST                      5: '__pyarmor_exit_54693__'
                        226     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1c\xa6\x00\x00\x00\x00\x00\x00\x00'
                        228     BUILD_TUPLE                     1
                        230     CALL_FUNCTION_EX                0
                        232     POP_TOP                         
                        234     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: OnCreate
                    Qualified Name: VariableSelectionForm.OnCreate
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'FormToPyQtWidget'
                        'parent'
                        'PopulateForm'
                        'ida_kernwin'
                        'set_dock_pos'
                        'title'
                        'DP_RIGHT'
                    [Locals+Names]
                        'self'
                        'form'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54694__'
                        '__pyarmor_enter_54695__'
                        b'<COAddr>\x03\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        'Output window'
                        '__pyarmor_exit_54696__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54695__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: FormToPyQtWidget
                        50      LOAD_FAST                       1: form
                        52      CALL                            1
                        60      LOAD_FAST                       0: self
                        62      STORE_ATTR                      1: parent
                        72      LOAD_FAST                       0: self
                        74      LOAD_ATTR                       5: PopulateForm
                        94      CALL                            0
                        102     POP_TOP                         
                        104     LOAD_GLOBAL                     7: NULL + ida_kernwin
                        114     LOAD_ATTR                       8: set_dock_pos
                        134     LOAD_FAST                       0: self
                        136     LOAD_ATTR                       10: title
                        156     LOAD_CONST                      4: 'Output window'
                        158     LOAD_GLOBAL                     6: ida_kernwin
                        168     LOAD_ATTR                       12: DP_RIGHT
                        188     CALL                            3
                        196     POP_TOP                         
                        198     LOAD_CONST                      0: None
                        200     NOP                             
                        202     NOP                             
                        204     NOP                             
                        206     JUMP_FORWARD                    19 (to 246)
                        214     POP_TOP                         
                        216     RETURN_CONST                    0: None
                        218     PUSH_EXC_INFO                   
                        220     PUSH_NULL                       
                        222     LOAD_CONST                      5: '__pyarmor_exit_54696__'
                        224     NOP                             
                        226     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        228     CALL                            1
                        236     POP_TOP                         
                        238     RERAISE                         0
                        240     COPY                            3
                        242     POP_EXCEPT                      
                        244     RERAISE                         1
                        246     PUSH_NULL                       
                        248     LOAD_CONST                      5: '__pyarmor_exit_54696__'
                        250     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\xc0\x00\x00\x00\x00\x00\x00\x00'
                        252     BUILD_TUPLE                     1
                        254     CALL_FUNCTION_EX                0
                        256     POP_TOP                         
                        258     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: PopulateForm
                    Qualified Name: VariableSelectionForm.PopulateForm
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'QtWidgets'
                        'QVBoxLayout'
                        'QHBoxLayout'
                        'QCheckBox'
                        'main_select_all'
                        'setChecked'
                        'stateChanged'
                        'connect'
                        'on_main_select_all'
                        'addWidget'
                        'addStretch'
                        'addLayout'
                        'args'
                        'VariableSelectionWidget'
                        'args_widget'
                        'vars'
                        'vars_widget'
                        'QPushButton'
                        'clicked'
                        'on_analyze_clicked'
                        'on_cancel_clicked'
                        'parent'
                        'setLayout'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_87'
                        '_var_var_66'
                        '_var_var_88'
                        '_var_var_68'
                    [Constants]
                        None
                        '__pyarmor_assert_54697__'
                        '__pyarmor_enter_54698__'
                        b'<COAddr>\x03\x00\x00\x1aZ\x04\x00\x00\x00\x00\x00\x00'
                        'Select All Variables'
                        True
                        'Function Arguments'
                        'Local Variables'
                        'Analyze Selected'
                        'Cancel'
                        '__pyarmor_exit_54699__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54698__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aZ\x04\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + QtWidgets
                        38      LOAD_ATTR                       2: QVBoxLayout
                        58      CALL                            0
                        66      STORE_FAST                      2: _var_var_1
                        68      LOAD_GLOBAL                     1: NULL + QtWidgets
                        78      LOAD_ATTR                       4: QHBoxLayout
                        98      CALL                            0
                        106     STORE_FAST                      3: _var_var_87
                        108     LOAD_GLOBAL                     1: NULL + QtWidgets
                        118     LOAD_ATTR                       6: QCheckBox
                        138     LOAD_CONST                      4: 'Select All Variables'
                        140     CALL                            1
                        148     LOAD_FAST                       0: self
                        150     STORE_ATTR                      4: main_select_all
                        160     LOAD_FAST                       0: self
                        162     LOAD_ATTR                       8: main_select_all
                        182     LOAD_ATTR                       11: setChecked
                        202     LOAD_CONST                      5: True
                        204     CALL                            1
                        212     POP_TOP                         
                        214     LOAD_FAST                       0: self
                        216     LOAD_ATTR                       8: main_select_all
                        236     LOAD_ATTR                       12: stateChanged
                        256     LOAD_ATTR                       15: connect
                        276     LOAD_FAST                       0: self
                        278     LOAD_ATTR                       16: on_main_select_all
                        298     CALL                            1
                        306     POP_TOP                         
                        308     LOAD_FAST                       3: _var_var_87
                        310     LOAD_ATTR                       19: addWidget
                        330     LOAD_FAST                       0: self
                        332     LOAD_ATTR                       8: main_select_all
                        352     CALL                            1
                        360     POP_TOP                         
                        362     LOAD_FAST                       3: _var_var_87
                        364     LOAD_ATTR                       21: addStretch
                        384     CALL                            0
                        392     POP_TOP                         
                        394     LOAD_FAST                       2: _var_var_1
                        396     LOAD_ATTR                       23: addLayout
                        416     LOAD_FAST                       3: _var_var_87
                        418     CALL                            1
                        426     POP_TOP                         
                        428     LOAD_FAST                       0: self
                        430     LOAD_ATTR                       24: args
                        450     POP_JUMP_IF_FALSE               54 (to 560)
                        452     LOAD_GLOBAL                     27: NULL + VariableSelectionWidget
                        462     LOAD_CONST                      6: 'Function Arguments'
                        464     LOAD_FAST                       0: self
                        466     LOAD_ATTR                       24: args
                        486     CALL                            2
                        494     LOAD_FAST                       0: self
                        496     STORE_ATTR                      14: args_widget
                        506     LOAD_FAST                       2: _var_var_1
                        508     LOAD_ATTR                       19: addWidget
                        528     LOAD_FAST                       0: self
                        530     LOAD_ATTR                       28: args_widget
                        550     CALL                            1
                        558     POP_TOP                         
                        560     LOAD_FAST                       0: self
                        562     LOAD_ATTR                       30: vars
                        582     POP_JUMP_IF_FALSE               54 (to 692)
                        584     LOAD_GLOBAL                     27: NULL + VariableSelectionWidget
                        594     LOAD_CONST                      7: 'Local Variables'
                        596     LOAD_FAST                       0: self
                        598     LOAD_ATTR                       30: vars
                        618     CALL                            2
                        626     LOAD_FAST                       0: self
                        628     STORE_ATTR                      16: vars_widget
                        638     LOAD_FAST                       2: _var_var_1
                        640     LOAD_ATTR                       19: addWidget
                        660     LOAD_FAST                       0: self
                        662     LOAD_ATTR                       32: vars_widget
                        682     CALL                            1
                        690     POP_TOP                         
                        692     LOAD_GLOBAL                     1: NULL + QtWidgets
                        702     LOAD_ATTR                       4: QHBoxLayout
                        722     CALL                            0
                        730     STORE_FAST                      4: _var_var_66
                        732     LOAD_GLOBAL                     1: NULL + QtWidgets
                        742     LOAD_ATTR                       34: QPushButton
                        762     LOAD_CONST                      8: 'Analyze Selected'
                        764     CALL                            1
                        772     STORE_FAST                      5: _var_var_88
                        774     LOAD_GLOBAL                     1: NULL + QtWidgets
                        784     LOAD_ATTR                       34: QPushButton
                        804     LOAD_CONST                      9: 'Cancel'
                        806     CALL                            1
                        814     STORE_FAST                      6: _var_var_68
                        816     LOAD_FAST                       5: _var_var_88
                        818     LOAD_ATTR                       36: clicked
                        838     LOAD_ATTR                       15: connect
                        858     LOAD_FAST                       0: self
                        860     LOAD_ATTR                       38: on_analyze_clicked
                        880     CALL                            1
                        888     POP_TOP                         
                        890     LOAD_FAST                       6: _var_var_68
                        892     LOAD_ATTR                       36: clicked
                        912     LOAD_ATTR                       15: connect
                        932     LOAD_FAST                       0: self
                        934     LOAD_ATTR                       40: on_cancel_clicked
                        954     CALL                            1
                        962     POP_TOP                         
                        964     LOAD_FAST                       4: _var_var_66
                        966     LOAD_ATTR                       19: addWidget
                        986     LOAD_FAST                       5: _var_var_88
                        988     CALL                            1
                        996     POP_TOP                         
                        998     LOAD_FAST                       4: _var_var_66
                        1000    LOAD_ATTR                       19: addWidget
                        1020    LOAD_FAST                       6: _var_var_68
                        1022    CALL                            1
                        1030    POP_TOP                         
                        1032    LOAD_FAST                       2: _var_var_1
                        1034    LOAD_ATTR                       23: addLayout
                        1054    LOAD_FAST                       4: _var_var_66
                        1056    CALL                            1
                        1064    POP_TOP                         
                        1066    LOAD_FAST                       0: self
                        1068    LOAD_ATTR                       42: parent
                        1088    LOAD_ATTR                       45: setLayout
                        1108    LOAD_FAST                       2: _var_var_1
                        1110    CALL                            1
                        1118    POP_TOP                         
                        1120    LOAD_CONST                      0: None
                        1122    NOP                             
                        1124    NOP                             
                        1126    NOP                             
                        1128    JUMP_FORWARD                    19 (to 1168)
                        1136    POP_TOP                         
                        1138    RETURN_CONST                    0: None
                        1140    PUSH_EXC_INFO                   
                        1142    PUSH_NULL                       
                        1144    LOAD_CONST                      10: '__pyarmor_exit_54699__'
                        1146    NOP                             
                        1148    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aZ\x04\x00\x00\x00\x00\x00\x00'
                        1150    CALL                            1
                        1158    POP_TOP                         
                        1160    RERAISE                         0
                        1162    COPY                            3
                        1164    POP_EXCEPT                      
                        1166    RERAISE                         1
                        1168    PUSH_NULL                       
                        1170    LOAD_CONST                      10: '__pyarmor_exit_54699__'
                        1172    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1aZ\x04\x00\x00\x00\x00\x00\x00'
                        1174    BUILD_TUPLE                     1
                        1176    CALL_FUNCTION_EX                0
                        1178    POP_TOP                         
                        1180    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_main_select_all
                    Qualified Name: VariableSelectionForm.on_main_select_all
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'hasattr'
                        'args_widget'
                        'select_all_checkbox'
                        'setChecked'
                        'QtCore'
                        'Qt'
                        'Checked'
                        'vars_widget'
                    [Locals+Names]
                        'self'
                        'state'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54700__'
                        '__pyarmor_enter_54701__'
                        b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                        'args_widget'
                        'vars_widget'
                        '__pyarmor_exit_54702__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54701__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + hasattr
                        38      LOAD_FAST                       0: self
                        40      LOAD_CONST                      4: 'args_widget'
                        42      CALL                            2
                        50      POP_JUMP_IF_FALSE               64 (to 180)
                        52      LOAD_FAST                       0: self
                        54      LOAD_ATTR                       2: args_widget
                        74      LOAD_ATTR                       4: select_all_checkbox
                        94      LOAD_ATTR                       7: setChecked
                        114     LOAD_FAST                       1: state
                        116     LOAD_GLOBAL                     8: QtCore
                        126     LOAD_ATTR                       10: Qt
                        146     LOAD_ATTR                       12: Checked
                        166     COMPARE_OP                      40 (==)
                        170     CALL                            1
                        178     POP_TOP                         
                        180     LOAD_GLOBAL                     1: NULL + hasattr
                        190     LOAD_FAST                       0: self
                        192     LOAD_CONST                      5: 'vars_widget'
                        194     CALL                            2
                        202     POP_JUMP_IF_FALSE               64 (to 332)
                        204     LOAD_FAST                       0: self
                        206     LOAD_ATTR                       14: vars_widget
                        226     LOAD_ATTR                       4: select_all_checkbox
                        246     LOAD_ATTR                       7: setChecked
                        266     LOAD_FAST                       1: state
                        268     LOAD_GLOBAL                     8: QtCore
                        278     LOAD_ATTR                       10: Qt
                        298     LOAD_ATTR                       12: Checked
                        318     COMPARE_OP                      40 (==)
                        322     CALL                            1
                        330     POP_TOP                         
                        332     LOAD_CONST                      0: None
                        334     NOP                             
                        336     NOP                             
                        338     NOP                             
                        340     JUMP_FORWARD                    19 (to 380)
                        348     POP_TOP                         
                        350     RETURN_CONST                    0: None
                        352     PUSH_EXC_INFO                   
                        354     PUSH_NULL                       
                        356     LOAD_CONST                      6: '__pyarmor_exit_54702__'
                        358     NOP                             
                        360     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                        362     CALL                            1
                        370     POP_TOP                         
                        372     RERAISE                         0
                        374     COPY                            3
                        376     POP_EXCEPT                      
                        378     RERAISE                         1
                        380     PUSH_NULL                       
                        382     LOAD_CONST                      6: '__pyarmor_exit_54702__'
                        384     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                        386     BUILD_TUPLE                     1
                        388     CALL_FUNCTION_EX                0
                        390     POP_TOP                         
                        392     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_analyze_clicked
                    Qualified Name: VariableSelectionForm.on_analyze_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'hasattr'
                        'args_widget'
                        'get_selected_variables'
                        'selected_args'
                        'vars_widget'
                        'selected_vars'
                        'Close'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54703__'
                        '__pyarmor_enter_54704__'
                        b'<COAddr>\x01\x00\x00\x1a\xe4\x00\x00\x00\x00\x00\x00\x00'
                        'args_widget'
                        'vars_widget'
                        1
                        '__pyarmor_exit_54705__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54704__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x00\x00\x00\x00\x00\x00\x00'
                        10      BUILD_TUPLE                     1
                        12      CALL_FUNCTION_EX                0
                        14      POP_TOP                         
                        16      RESUME                          0
                        18      NOP                             
                        20      NOP                             
                        22      NOP                             
                        24      NOP                             
                        26      NOP                             
                        28      LOAD_GLOBAL                     1: NULL + hasattr
                        38      LOAD_FAST                       0: self
                        40      LOAD_CONST                      4: 'args_widget'
                        42      CALL                            2
                        50      POP_JUMP_IF_FALSE               31 (to 114)
                        52      LOAD_FAST                       0: self
                        54      LOAD_ATTR                       2: args_widget
                        74      LOAD_ATTR                       5: get_selected_variables
                        94      CALL                            0
                        102     LOAD_FAST                       0: self
                        104     STORE_ATTR                      3: selected_args
                        114     LOAD_GLOBAL                     1: NULL + hasattr
                        124     LOAD_FAST                       0: self
                        126     LOAD_CONST                      5: 'vars_widget'
                        128     CALL                            2
                        136     POP_JUMP_IF_FALSE               31 (to 200)
                        138     LOAD_FAST                       0: self
                        140     LOAD_ATTR                       8: vars_widget
                        160     LOAD_ATTR                       5: get_selected_variables
                        180     CALL                            0
                        188     LOAD_FAST                       0: self
                        190     STORE_ATTR                      5: selected_vars
                        200     LOAD_FAST                       0: self
                        202     LOAD_ATTR                       13: Close
                        222     LOAD_CONST                      6: 1
                        224     CALL                            1
                        232     POP_TOP                         
                        234     LOAD_CONST                      0: None
                        236     NOP                             
                        238     NOP                             
                        240     NOP                             
                        242     JUMP_FORWARD                    19 (to 282)
                        250     POP_TOP                         
                        252     RETURN_CONST                    0: None
                        254     PUSH_EXC_INFO                   
                        256     PUSH_NULL                       
                        258     LOAD_CONST                      7: '__pyarmor_exit_54705__'
                        260     NOP                             
                        262     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x00\x00\x00\x00\x00\x00\x00'
                        264     CALL                            1
                        272     POP_TOP                         
                        274     RERAISE                         0
                        276     COPY                            3
                        278     POP_EXCEPT                      
                        280     RERAISE                         1
                        282     PUSH_NULL                       
                        284     LOAD_CONST                      7: '__pyarmor_exit_54705__'
                        286     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x00\x00\x00\x00\x00\x00\x00'
                        288     BUILD_TUPLE                     1
                        290     CALL_FUNCTION_EX                0
                        292     POP_TOP                         
                        294     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_cancel_clicked
                    Qualified Name: VariableSelectionForm.on_cancel_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'Close'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54706__'
                        '__pyarmor_enter_54707__'
                        b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        0
                        '__pyarmor_exit_54708__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54707__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: Close
                        50      LOAD_CONST                      4: 0
                        52      CALL                            1
                        60      POP_TOP                         
                        62      LOAD_CONST                      0: None
                        64      NOP                             
                        66      NOP                             
                        68      NOP                             
                        70      JUMP_FORWARD                    19 (to 110)
                        78      POP_TOP                         
                        80      RETURN_CONST                    0: None
                        82      PUSH_EXC_INFO                   
                        84      PUSH_NULL                       
                        86      LOAD_CONST                      5: '__pyarmor_exit_54708__'
                        88      NOP                             
                        90      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        92      CALL                            1
                        100     POP_TOP                         
                        102     RERAISE                         0
                        104     COPY                            3
                        106     POP_EXCEPT                      
                        108     RERAISE                         1
                        110     PUSH_NULL                       
                        112     LOAD_CONST                      5: '__pyarmor_exit_54708__'
                        114     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a8\x00\x00\x00\x00\x00\x00\x00'
                        116     BUILD_TUPLE                     1
                        118     CALL_FUNCTION_EX                0
                        120     POP_TOP                         
                        122     RETURN_VALUE                    
                '__pyarmor_exit_54690__'
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'VariableSelectionForm'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54689__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
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
                48      LOAD_CONST                      5: <CODE> OnCreate
                50      MAKE_FUNCTION                   0
                52      STORE_NAME                      5: OnCreate
                54      LOAD_CONST                      6: <CODE> PopulateForm
                56      MAKE_FUNCTION                   0
                58      STORE_NAME                      6: PopulateForm
                60      LOAD_CONST                      7: <CODE> on_main_select_all
                62      MAKE_FUNCTION                   0
                64      STORE_NAME                      7: on_main_select_all
                66      LOAD_CONST                      8: <CODE> on_analyze_clicked
                68      MAKE_FUNCTION                   0
                70      STORE_NAME                      8: on_analyze_clicked
                72      LOAD_CONST                      9: <CODE> on_cancel_clicked
                74      MAKE_FUNCTION                   0
                76      STORE_NAME                      9: on_cancel_clicked
                78      LOAD_CLOSURE                    0: __class__
                80      COPY                            1
                82      STORE_NAME                      10: __classcell__
                84      NOP                             
                86      NOP                             
                88      NOP                             
                90      JUMP_FORWARD                    20 (to 132)
                94      POP_TOP                         
                96      LOAD_CLOSURE                    0: __class__
                98      COPY                            1
                100     STORE_NAME                      10: __classcell__
                102     RETURN_VALUE                    
                104     PUSH_EXC_INFO                   
                106     PUSH_NULL                       
                108     LOAD_CONST                      10: '__pyarmor_exit_54690__'
                110     NOP                             
                112     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                114     CALL                            1
                122     POP_TOP                         
                124     RERAISE                         0
                126     COPY                            3
                128     POP_EXCEPT                      
                130     RERAISE                         1
                132     PUSH_NULL                       
                134     LOAD_CONST                      10: '__pyarmor_exit_54690__'
                136     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$D\x00\x00\x00\x00\x00\x00\x00'
                138     BUILD_TUPLE                     1
                140     CALL_FUNCTION_EX                0
                142     POP_TOP                         
                144     RETURN_VALUE                    
        'VariableSelectionForm'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: create_variable_selection_view
            Qualified Name: create_variable_selection_view
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'idaapi'
                'get_func'
                'print'
                'ida_hexrays'
                'decompile'
                'lvars'
                'name'
                'is_arg_var'
                'append'
                'VariableSelectionForm'
                'Show'
                'title'
            [Locals+Names]
                'ea'
                '__assert_armored__'
                '_var_var_89'
                '_var_var_90'
                '_var_var_91'
                '_var_var_92'
                '_var_var_93'
                '_var_var_7'
            [Constants]
                '\n    创建变量选择视图\n    \n    Args:\n        ea: 函数地址\n        \n    Returns:\n        VariableSelectionForm: 变量选择表单实例\n    '
                '__pyarmor_assert_54709__'
                '__pyarmor_enter_54710__'
                b'<COAddr>\x01\x00\x00\x1a(\x02\x00\x00\x00\x00\x00\x00'
                '[!] No function found at this address'
                '__pyarmor_exit_54711__'
                None
                '[!] Failed to decompile function'
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54710__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x02\x00\x00\x00\x00\x00\x00'
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
                38      LOAD_ATTR                       2: get_func
                58      LOAD_FAST                       0: ea
                60      CALL                            1
                68      STORE_FAST                      2: _var_var_89
                70      LOAD_FAST                       2: _var_var_89
                72      POP_JUMP_IF_TRUE                22 (to 118)
                74      LOAD_GLOBAL                     5: NULL + print
                84      LOAD_CONST                      4: '[!] No function found at this address'
                86      CALL                            1
                94      POP_TOP                         
                96      NOP                             
                98      LOAD_CONST                      6: None
                100     NOP                             
                102     NOP                             
                104     NOP                             
                106     JUMP_FORWARD                    249 (to 606)
                114     POP_TOP                         
                116     RETURN_CONST                    6: None
                118     LOAD_CONST                      6: None
                120     STORE_FAST                      3: _var_var_90
                122     NOP                             
                124     LOAD_GLOBAL                     7: NULL + ida_hexrays
                134     LOAD_ATTR                       8: decompile
                154     LOAD_FAST                       2: _var_var_89
                156     CALL                            1
                164     STORE_FAST                      3: _var_var_90
                166     LOAD_FAST                       3: _var_var_90
                168     POP_JUMP_IF_TRUE                22 (to 214)
                170     LOAD_GLOBAL                     5: NULL + print
                180     LOAD_CONST                      7: '[!] Failed to decompile function'
                182     CALL                            1
                190     POP_TOP                         
                192     NOP                             
                194     LOAD_CONST                      6: None
                196     NOP                             
                198     NOP                             
                200     NOP                             
                202     JUMP_FORWARD                    201 (to 606)
                210     POP_TOP                         
                212     RETURN_CONST                    6: None
                214     BUILD_LIST                      0
                216     STORE_FAST                      4: _var_var_91
                218     BUILD_LIST                      0
                220     STORE_FAST                      5: _var_var_92
                222     LOAD_FAST                       3: _var_var_90
                224     LOAD_ATTR                       10: lvars
                244     GET_ITER                        
                246     FOR_ITER                        85 (to 418)
                250     STORE_FAST                      6: _var_var_93
                252     LOAD_FAST                       6: _var_var_93
                254     POP_JUMP_IF_TRUE                1 (to 258)
                256     JUMP_BACKWARD                   6 (to 246)
                258     LOAD_FAST                       6: _var_var_93
                260     LOAD_ATTR                       12: name
                280     POP_JUMP_IF_TRUE                1 (to 284)
                282     JUMP_BACKWARD                   19 (to 246)
                284     LOAD_FAST                       6: _var_var_93
                286     LOAD_ATTR                       14: is_arg_var
                306     POP_JUMP_IF_FALSE               28 (to 364)
                308     LOAD_FAST                       4: _var_var_91
                310     LOAD_ATTR                       17: append
                330     LOAD_FAST                       6: _var_var_93
                332     LOAD_ATTR                       12: name
                352     CALL                            1
                360     POP_TOP                         
                362     JUMP_BACKWARD                   59 (to 246)
                364     LOAD_FAST                       5: _var_var_92
                366     LOAD_ATTR                       17: append
                386     LOAD_FAST                       6: _var_var_93
                388     LOAD_ATTR                       12: name
                408     CALL                            1
                416     POP_TOP                         
                418     JUMP_BACKWARD                   87 (to 246)
                420     END_FOR                         
                422     LOAD_GLOBAL                     19: NULL + VariableSelectionForm
                432     LOAD_FAST                       0: ea
                434     LOAD_FAST                       4: _var_var_91
                436     LOAD_FAST                       5: _var_var_92
                438     CALL                            3
                446     STORE_FAST                      7: _var_var_7
                448     LOAD_FAST                       7: _var_var_7
                450     LOAD_ATTR                       21: Show
                470     LOAD_FAST                       7: _var_var_7
                472     LOAD_ATTR                       22: title
                492     CALL                            1
                500     POP_TOP                         
                502     LOAD_FAST                       7: _var_var_7
                504     NOP                             
                506     NOP                             
                508     NOP                             
                510     JUMP_FORWARD                    47 (to 606)
                512     CALL                            1
                520     POP_TOP                         
                522     RETURN_VALUE                    
                524     PUSH_EXC_INFO                   
                526     POP_TOP                         
                528     LOAD_GLOBAL                     5: NULL + print
                538     LOAD_CONST                      7: '[!] Failed to decompile function'
                540     CALL                            1
                548     POP_TOP                         
                550     POP_EXCEPT                      
                552     LOAD_CONST                      6: None
                554     NOP                             
                556     NOP                             
                558     NOP                             
                560     JUMP_FORWARD                    22 (to 606)
                568     POP_TOP                         
                570     RETURN_CONST                    6: None
                572     COPY                            3
                574     POP_EXCEPT                      
                576     RERAISE                         1
                578     PUSH_EXC_INFO                   
                580     PUSH_NULL                       
                582     LOAD_CONST                      5: '__pyarmor_exit_54711__'
                584     NOP                             
                586     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x02\x00\x00\x00\x00\x00\x00'
                588     CALL                            1
                596     POP_TOP                         
                598     RERAISE                         0
                600     COPY                            3
                602     POP_EXCEPT                      
                604     RERAISE                         1
                606     PUSH_NULL                       
                608     LOAD_CONST                      5: '__pyarmor_exit_54711__'
                610     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a(\x02\x00\x00\x00\x00\x00\x00'
                612     BUILD_TUPLE                     1
                614     CALL_FUNCTION_EX                0
                616     POP_TOP                         
                618     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: ReCopilotSettingsDialog
            Qualified Name: ReCopilotSettingsDialog
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
                'initUI'
                'save_settings'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'ReCopilotSettingsDialog'
                '\n    Dialog for configuring ReCopilot settings.\n    '
                '__pyarmor_assert_54712__'
                '__pyarmor_enter_54713__'
                b'<COAddr>\x01\x00\x00(4\x00\x00\x00\x00\x00\x00\x00'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: ReCopilotSettingsDialog.__init__
                    Arg Count: 2
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        '__init__'
                        'initUI'
                    [Locals+Names]
                        'self'
                        'parent'
                        '__assert_armored__'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54715__'
                        '__pyarmor_enter_54716__'
                        b'<COAddr>\x03\x00\x00\x1cT\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54717__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54716__'
                        10      LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cT\x00\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_DEREF                      3: __class__
                        42      LOAD_FAST                       0: self
                        44      LOAD_SUPER_ATTR                 5: __init__
                        48      LOAD_FAST                       1: parent
                        50      CALL                            1
                        58      POP_TOP                         
                        60      LOAD_FAST                       0: self
                        62      LOAD_ATTR                       5: initUI
                        82      CALL                            0
                        90      POP_TOP                         
                        92      LOAD_CONST                      0: None
                        94      NOP                             
                        96      NOP                             
                        98      NOP                             
                        100     JUMP_FORWARD                    19 (to 140)
                        108     POP_TOP                         
                        110     RETURN_CONST                    0: None
                        112     PUSH_EXC_INFO                   
                        114     PUSH_NULL                       
                        116     LOAD_CONST                      4: '__pyarmor_exit_54717__'
                        118     NOP                             
                        120     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cT\x00\x00\x00\x00\x00\x00\x00'
                        122     CALL                            1
                        130     POP_TOP                         
                        132     RERAISE                         0
                        134     COPY                            3
                        136     POP_EXCEPT                      
                        138     RERAISE                         1
                        140     PUSH_NULL                       
                        142     LOAD_CONST                      4: '__pyarmor_exit_54717__'
                        144     LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1cT\x00\x00\x00\x00\x00\x00\x00'
                        146     BUILD_TUPLE                     1
                        148     CALL_FUNCTION_EX                0
                        150     POP_TOP                         
                        152     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: initUI
                    Qualified Name: ReCopilotSettingsDialog.initUI
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'setWindowTitle'
                        'QVBoxLayout'
                        'QGroupBox'
                        'QGridLayout'
                        'addWidget'
                        'QLabel'
                        'QLineEdit'
                        'settings_manager'
                        'settings'
                        'model_name_edit'
                        'base_url_edit'
                        'api_key_edit'
                        'setEchoMode'
                        'Password'
                        'QComboBox'
                        'prompt_template_combo'
                        'addItems'
                        'list'
                        'PROMPT_TEMPLATE'
                        'keys'
                        'setCurrentText'
                        'setToolTip'
                        'QSpinBox'
                        'max_output_tokens_spin'
                        'setRange'
                        'setValue'
                        'caller_depth_spin'
                        'callee_depth_spin'
                        'context_func_spin'
                        'QCheckBox'
                        'data_flow_switch'
                        'setChecked'
                        'measure_info_score_switch'
                        'need_confirm_switch'
                        'debug_mode_switch'
                        'feedback_switch'
                        'QHBoxLayout'
                        'QPushButton'
                        'clicked'
                        'connect'
                        'save_settings'
                        'reject'
                        'addLayout'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_1'
                        '_var_var_94'
                        '_var_var_95'
                        '_var_var_96'
                        '_var_var_97'
                        '_var_var_98'
                        '_var_var_99'
                        '_var_var_100'
                        '_var_var_101'
                        '_var_var_102'
                        '_var_var_103'
                        '_var_var_104'
                        '_var_var_105'
                        '_var_var_66'
                        '_var_var_106'
                        '_var_var_68'
                    [Constants]
                        'Initialize the dialog UI.'
                        '__pyarmor_assert_54718__'
                        '__pyarmor_enter_54719__'
                        b'<COAddr>\x03\x00\x00\x1a\x8a\x10\x00\x00\x00\x00\x00\x00'
                        'Configure ReCopilot'
                        'Model Settings'
                        'Model Name:'
                        0
                        'model_name'
                        1
                        'Base URL:'
                        'base_url'
                        'API Key:'
                        2
                        'api_key'
                        'Prompt Template:'
                        3
                        'prompt_template'
                        'Select the prompt template to query the model'
                        'Max Output Tokens:'
                        4
                        2147483647
                        'max_output_tokens'
                        'Maximum number of tokens to generate in the output (1-2147483647)'
                        'Analysis Settings'
                        'Max Trace Caller Depth:'
                        'Maximum depth when tracing function callers (0-10)'
                        10
                        'max_trace_caller_depth'
                        'Max Trace Callee Depth:'
                        'Maximum depth when tracing function callees (0-10)'
                        'max_trace_callee_depth'
                        'Max Context Functions:'
                        'Maximum number of functions to include in context (-1 for no limit)'
                        -1
                        100
                        'max_context_func_num'
                        'Data Flow Analysis Enable:'
                        'Enable/Disable Data Flow Analysis'
                        'data_flow_analysis'
                        'Measure Info Score:'
                        'Enable/disable information score measurement'
                        'measure_info_score'
                        'Need User Confirm:'
                        'Enable/disable user confirm before send request to LLM'
                        5
                        'need_confirm'
                        'Mock Mode (Developer Only):'
                        'Enable/disable mock mode for debug'
                        6
                        'debug_mode'
                        'Feedback Enable:'
                        'Enable/Disable Send Feedback'
                        7
                        'feedback'
                        'Save Settings'
                        'Cancel'
                        '__pyarmor_exit_54720__'
                        None
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54719__'
                        8       LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8a\x10\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       1: setWindowTitle
                        50      LOAD_CONST                      4: 'Configure ReCopilot'
                        52      CALL                            1
                        60      POP_TOP                         
                        62      LOAD_GLOBAL                     3: NULL + QVBoxLayout
                        72      LOAD_FAST                       0: self
                        74      CALL                            1
                        82      STORE_FAST                      2: _var_var_1
                        84      LOAD_GLOBAL                     5: NULL + QGroupBox
                        94      LOAD_CONST                      5: 'Model Settings'
                        96      CALL                            1
                        104     STORE_FAST                      3: _var_var_94
                        106     LOAD_GLOBAL                     7: NULL + QGridLayout
                        116     LOAD_FAST                       3: _var_var_94
                        118     CALL                            1
                        126     STORE_FAST                      4: _var_var_95
                        128     LOAD_FAST                       4: _var_var_95
                        130     LOAD_ATTR                       9: addWidget
                        150     LOAD_GLOBAL                     11: NULL + QLabel
                        160     LOAD_CONST                      6: 'Model Name:'
                        162     CALL                            1
                        170     LOAD_CONST                      7: 0
                        172     LOAD_CONST                      7: 0
                        174     CALL                            3
                        182     POP_TOP                         
                        184     LOAD_GLOBAL                     13: NULL + QLineEdit
                        194     LOAD_GLOBAL                     14: settings_manager
                        204     LOAD_ATTR                       16: settings
                        224     LOAD_CONST                      8: 'model_name'
                        226     BINARY_SUBSCR                   
                        230     CALL                            1
                        238     LOAD_FAST                       0: self
                        240     STORE_ATTR                      9: model_name_edit
                        250     LOAD_FAST                       4: _var_var_95
                        252     LOAD_ATTR                       9: addWidget
                        272     LOAD_FAST                       0: self
                        274     LOAD_ATTR                       18: model_name_edit
                        294     LOAD_CONST                      7: 0
                        296     LOAD_CONST                      9: 1
                        298     CALL                            3
                        306     POP_TOP                         
                        308     LOAD_FAST                       4: _var_var_95
                        310     LOAD_ATTR                       9: addWidget
                        330     LOAD_GLOBAL                     11: NULL + QLabel
                        340     LOAD_CONST                      10: 'Base URL:'
                        342     CALL                            1
                        350     LOAD_CONST                      9: 1
                        352     LOAD_CONST                      7: 0
                        354     CALL                            3
                        362     POP_TOP                         
                        364     LOAD_GLOBAL                     13: NULL + QLineEdit
                        374     LOAD_GLOBAL                     14: settings_manager
                        384     LOAD_ATTR                       16: settings
                        404     LOAD_CONST                      11: 'base_url'
                        406     BINARY_SUBSCR                   
                        410     CALL                            1
                        418     LOAD_FAST                       0: self
                        420     STORE_ATTR                      10: base_url_edit
                        430     LOAD_FAST                       4: _var_var_95
                        432     LOAD_ATTR                       9: addWidget
                        452     LOAD_FAST                       0: self
                        454     LOAD_ATTR                       20: base_url_edit
                        474     LOAD_CONST                      9: 1
                        476     LOAD_CONST                      9: 1
                        478     CALL                            3
                        486     POP_TOP                         
                        488     LOAD_FAST                       4: _var_var_95
                        490     LOAD_ATTR                       9: addWidget
                        510     LOAD_GLOBAL                     11: NULL + QLabel
                        520     LOAD_CONST                      12: 'API Key:'
                        522     CALL                            1
                        530     LOAD_CONST                      13: 2
                        532     LOAD_CONST                      7: 0
                        534     CALL                            3
                        542     POP_TOP                         
                        544     LOAD_GLOBAL                     13: NULL + QLineEdit
                        554     LOAD_GLOBAL                     14: settings_manager
                        564     LOAD_ATTR                       16: settings
                        584     LOAD_CONST                      14: 'api_key'
                        586     BINARY_SUBSCR                   
                        590     CALL                            1
                        598     LOAD_FAST                       0: self
                        600     STORE_ATTR                      11: api_key_edit
                        610     LOAD_FAST                       0: self
                        612     LOAD_ATTR                       22: api_key_edit
                        632     LOAD_ATTR                       25: setEchoMode
                        652     LOAD_GLOBAL                     12: QLineEdit
                        662     LOAD_ATTR                       26: Password
                        682     CALL                            1
                        690     POP_TOP                         
                        692     LOAD_FAST                       4: _var_var_95
                        694     LOAD_ATTR                       9: addWidget
                        714     LOAD_FAST                       0: self
                        716     LOAD_ATTR                       22: api_key_edit
                        736     LOAD_CONST                      13: 2
                        738     LOAD_CONST                      9: 1
                        740     CALL                            3
                        748     POP_TOP                         
                        750     LOAD_FAST                       4: _var_var_95
                        752     LOAD_ATTR                       9: addWidget
                        772     LOAD_GLOBAL                     11: NULL + QLabel
                        782     LOAD_CONST                      15: 'Prompt Template:'
                        784     CALL                            1
                        792     LOAD_CONST                      16: 3
                        794     LOAD_CONST                      7: 0
                        796     CALL                            3
                        804     POP_TOP                         
                        806     LOAD_GLOBAL                     29: NULL + QComboBox
                        816     CALL                            0
                        824     LOAD_FAST                       0: self
                        826     STORE_ATTR                      15: prompt_template_combo
                        836     LOAD_FAST                       0: self
                        838     LOAD_ATTR                       30: prompt_template_combo
                        858     LOAD_ATTR                       33: addItems
                        878     LOAD_GLOBAL                     35: NULL + list
                        888     LOAD_GLOBAL                     37: NULL + PROMPT_TEMPLATE
                        898     LOAD_ATTR                       38: keys
                        918     CALL                            0
                        926     CALL                            1
                        934     CALL                            1
                        942     POP_TOP                         
                        944     LOAD_FAST                       0: self
                        946     LOAD_ATTR                       30: prompt_template_combo
                        966     LOAD_ATTR                       41: setCurrentText
                        986     LOAD_GLOBAL                     14: settings_manager
                        996     LOAD_ATTR                       16: settings
                        1016    LOAD_CONST                      17: 'prompt_template'
                        1018    BINARY_SUBSCR                   
                        1022    CALL                            1
                        1030    POP_TOP                         
                        1032    LOAD_FAST                       0: self
                        1034    LOAD_ATTR                       30: prompt_template_combo
                        1054    LOAD_ATTR                       43: setToolTip
                        1074    LOAD_CONST                      18: 'Select the prompt template to query the model'
                        1076    CALL                            1
                        1084    POP_TOP                         
                        1086    LOAD_FAST                       4: _var_var_95
                        1088    LOAD_ATTR                       9: addWidget
                        1108    LOAD_FAST                       0: self
                        1110    LOAD_ATTR                       30: prompt_template_combo
                        1130    LOAD_CONST                      16: 3
                        1132    LOAD_CONST                      9: 1
                        1134    CALL                            3
                        1142    POP_TOP                         
                        1144    LOAD_FAST                       4: _var_var_95
                        1146    LOAD_ATTR                       9: addWidget
                        1166    LOAD_GLOBAL                     11: NULL + QLabel
                        1176    LOAD_CONST                      19: 'Max Output Tokens:'
                        1178    CALL                            1
                        1186    LOAD_CONST                      20: 4
                        1188    LOAD_CONST                      7: 0
                        1190    CALL                            3
                        1198    POP_TOP                         
                        1200    LOAD_GLOBAL                     45: NULL + QSpinBox
                        1210    CALL                            0
                        1218    LOAD_FAST                       0: self
                        1220    STORE_ATTR                      23: max_output_tokens_spin
                        1230    LOAD_FAST                       0: self
                        1232    LOAD_ATTR                       46: max_output_tokens_spin
                        1252    LOAD_ATTR                       49: setRange
                        1272    LOAD_CONST                      9: 1
                        1274    LOAD_CONST                      21: 2147483647
                        1276    CALL                            2
                        1284    POP_TOP                         
                        1286    LOAD_FAST                       0: self
                        1288    LOAD_ATTR                       46: max_output_tokens_spin
                        1308    LOAD_ATTR                       51: setValue
                        1328    LOAD_GLOBAL                     14: settings_manager
                        1338    LOAD_ATTR                       16: settings
                        1358    LOAD_CONST                      22: 'max_output_tokens'
                        1360    BINARY_SUBSCR                   
                        1364    CALL                            1
                        1372    POP_TOP                         
                        1374    LOAD_FAST                       0: self
                        1376    LOAD_ATTR                       46: max_output_tokens_spin
                        1396    LOAD_ATTR                       43: setToolTip
                        1416    LOAD_CONST                      23: 'Maximum number of tokens to generate in the output (1-2147483647)'
                        1418    CALL                            1
                        1426    POP_TOP                         
                        1428    LOAD_FAST                       4: _var_var_95
                        1430    LOAD_ATTR                       9: addWidget
                        1450    LOAD_FAST                       0: self
                        1452    LOAD_ATTR                       46: max_output_tokens_spin
                        1472    LOAD_CONST                      20: 4
                        1474    LOAD_CONST                      9: 1
                        1476    CALL                            3
                        1484    POP_TOP                         
                        1486    LOAD_FAST                       2: _var_var_1
                        1488    LOAD_ATTR                       9: addWidget
                        1508    LOAD_FAST                       3: _var_var_94
                        1510    CALL                            1
                        1518    POP_TOP                         
                        1520    LOAD_GLOBAL                     5: NULL + QGroupBox
                        1530    LOAD_CONST                      24: 'Analysis Settings'
                        1532    CALL                            1
                        1540    STORE_FAST                      5: _var_var_96
                        1542    LOAD_GLOBAL                     7: NULL + QGridLayout
                        1552    LOAD_FAST                       5: _var_var_96
                        1554    CALL                            1
                        1562    STORE_FAST                      6: _var_var_97
                        1564    LOAD_GLOBAL                     11: NULL + QLabel
                        1574    LOAD_CONST                      25: 'Max Trace Caller Depth:'
                        1576    CALL                            1
                        1584    STORE_FAST                      7: _var_var_98
                        1586    LOAD_FAST                       7: _var_var_98
                        1588    LOAD_ATTR                       43: setToolTip
                        1608    LOAD_CONST                      26: 'Maximum depth when tracing function callers (0-10)'
                        1610    CALL                            1
                        1618    POP_TOP                         
                        1620    LOAD_FAST                       6: _var_var_97
                        1622    LOAD_ATTR                       9: addWidget
                        1642    LOAD_FAST                       7: _var_var_98
                        1644    LOAD_CONST                      7: 0
                        1646    LOAD_CONST                      7: 0
                        1648    CALL                            3
                        1656    POP_TOP                         
                        1658    LOAD_GLOBAL                     45: NULL + QSpinBox
                        1668    CALL                            0
                        1676    LOAD_FAST                       0: self
                        1678    STORE_ATTR                      26: caller_depth_spin
                        1688    LOAD_FAST                       0: self
                        1690    LOAD_ATTR                       52: caller_depth_spin
                        1710    LOAD_ATTR                       49: setRange
                        1730    LOAD_CONST                      7: 0
                        1732    LOAD_CONST                      27: 10
                        1734    CALL                            2
                        1742    POP_TOP                         
                        1744    LOAD_FAST                       0: self
                        1746    LOAD_ATTR                       52: caller_depth_spin
                        1766    LOAD_ATTR                       51: setValue
                        1786    LOAD_GLOBAL                     14: settings_manager
                        1796    LOAD_ATTR                       16: settings
                        1816    LOAD_CONST                      28: 'max_trace_caller_depth'
                        1818    BINARY_SUBSCR                   
                        1822    CALL                            1
                        1830    POP_TOP                         
                        1832    LOAD_FAST                       6: _var_var_97
                        1834    LOAD_ATTR                       9: addWidget
                        1854    LOAD_FAST                       0: self
                        1856    LOAD_ATTR                       52: caller_depth_spin
                        1876    LOAD_CONST                      7: 0
                        1878    LOAD_CONST                      9: 1
                        1880    CALL                            3
                        1888    POP_TOP                         
                        1890    LOAD_GLOBAL                     11: NULL + QLabel
                        1900    LOAD_CONST                      29: 'Max Trace Callee Depth:'
                        1902    CALL                            1
                        1910    STORE_FAST                      8: _var_var_99
                        1912    LOAD_FAST                       8: _var_var_99
                        1914    LOAD_ATTR                       43: setToolTip
                        1934    LOAD_CONST                      30: 'Maximum depth when tracing function callees (0-10)'
                        1936    CALL                            1
                        1944    POP_TOP                         
                        1946    LOAD_FAST                       6: _var_var_97
                        1948    LOAD_ATTR                       9: addWidget
                        1968    LOAD_FAST                       8: _var_var_99
                        1970    LOAD_CONST                      9: 1
                        1972    LOAD_CONST                      7: 0
                        1974    CALL                            3
                        1982    POP_TOP                         
                        1984    LOAD_GLOBAL                     45: NULL + QSpinBox
                        1994    CALL                            0
                        2002    LOAD_FAST                       0: self
                        2004    STORE_ATTR                      27: callee_depth_spin
                        2014    LOAD_FAST                       0: self
                        2016    LOAD_ATTR                       54: callee_depth_spin
                        2036    LOAD_ATTR                       49: setRange
                        2056    LOAD_CONST                      7: 0
                        2058    LOAD_CONST                      27: 10
                        2060    CALL                            2
                        2068    POP_TOP                         
                        2070    LOAD_FAST                       0: self
                        2072    LOAD_ATTR                       54: callee_depth_spin
                        2092    LOAD_ATTR                       51: setValue
                        2112    LOAD_GLOBAL                     14: settings_manager
                        2122    LOAD_ATTR                       16: settings
                        2142    LOAD_CONST                      31: 'max_trace_callee_depth'
                        2144    BINARY_SUBSCR                   
                        2148    CALL                            1
                        2156    POP_TOP                         
                        2158    LOAD_FAST                       6: _var_var_97
                        2160    LOAD_ATTR                       9: addWidget
                        2180    LOAD_FAST                       0: self
                        2182    LOAD_ATTR                       54: callee_depth_spin
                        2202    LOAD_CONST                      9: 1
                        2204    LOAD_CONST                      9: 1
                        2206    CALL                            3
                        2214    POP_TOP                         
                        2216    LOAD_GLOBAL                     11: NULL + QLabel
                        2226    LOAD_CONST                      32: 'Max Context Functions:'
                        2228    CALL                            1
                        2236    STORE_FAST                      9: _var_var_100
                        2238    LOAD_FAST                       9: _var_var_100
                        2240    LOAD_ATTR                       43: setToolTip
                        2260    LOAD_CONST                      33: 'Maximum number of functions to include in context (-1 for no limit)'
                        2262    CALL                            1
                        2270    POP_TOP                         
                        2272    LOAD_FAST                       6: _var_var_97
                        2274    LOAD_ATTR                       9: addWidget
                        2294    LOAD_FAST                       9: _var_var_100
                        2296    LOAD_CONST                      13: 2
                        2298    LOAD_CONST                      7: 0
                        2300    CALL                            3
                        2308    POP_TOP                         
                        2310    LOAD_GLOBAL                     45: NULL + QSpinBox
                        2320    CALL                            0
                        2328    LOAD_FAST                       0: self
                        2330    STORE_ATTR                      28: context_func_spin
                        2340    LOAD_FAST                       0: self
                        2342    LOAD_ATTR                       56: context_func_spin
                        2362    LOAD_ATTR                       49: setRange
                        2382    LOAD_CONST                      34: -1
                        2384    LOAD_CONST                      35: 100
                        2386    CALL                            2
                        2394    POP_TOP                         
                        2396    LOAD_FAST                       0: self
                        2398    LOAD_ATTR                       56: context_func_spin
                        2418    LOAD_ATTR                       51: setValue
                        2438    LOAD_GLOBAL                     14: settings_manager
                        2448    LOAD_ATTR                       16: settings
                        2468    LOAD_CONST                      36: 'max_context_func_num'
                        2470    BINARY_SUBSCR                   
                        2474    CALL                            1
                        2482    POP_TOP                         
                        2484    LOAD_FAST                       6: _var_var_97
                        2486    LOAD_ATTR                       9: addWidget
                        2506    LOAD_FAST                       0: self
                        2508    LOAD_ATTR                       56: context_func_spin
                        2528    LOAD_CONST                      13: 2
                        2530    LOAD_CONST                      9: 1
                        2532    CALL                            3
                        2540    POP_TOP                         
                        2542    LOAD_GLOBAL                     11: NULL + QLabel
                        2552    LOAD_CONST                      37: 'Data Flow Analysis Enable:'
                        2554    CALL                            1
                        2562    STORE_FAST                      10: _var_var_101
                        2564    LOAD_FAST                       10: _var_var_101
                        2566    LOAD_ATTR                       43: setToolTip
                        2586    LOAD_CONST                      38: 'Enable/Disable Data Flow Analysis'
                        2588    CALL                            1
                        2596    POP_TOP                         
                        2598    LOAD_FAST                       6: _var_var_97
                        2600    LOAD_ATTR                       9: addWidget
                        2620    LOAD_FAST                       10: _var_var_101
                        2622    LOAD_CONST                      16: 3
                        2624    LOAD_CONST                      7: 0
                        2626    CALL                            3
                        2634    POP_TOP                         
                        2636    LOAD_GLOBAL                     59: NULL + QCheckBox
                        2646    CALL                            0
                        2654    LOAD_FAST                       0: self
                        2656    STORE_ATTR                      30: data_flow_switch
                        2666    LOAD_FAST                       0: self
                        2668    LOAD_ATTR                       60: data_flow_switch
                        2688    LOAD_ATTR                       63: setChecked
                        2708    LOAD_GLOBAL                     14: settings_manager
                        2718    LOAD_ATTR                       16: settings
                        2738    LOAD_CONST                      39: 'data_flow_analysis'
                        2740    BINARY_SUBSCR                   
                        2744    CALL                            1
                        2752    POP_TOP                         
                        2754    LOAD_FAST                       6: _var_var_97
                        2756    LOAD_ATTR                       9: addWidget
                        2776    LOAD_FAST                       0: self
                        2778    LOAD_ATTR                       60: data_flow_switch
                        2798    LOAD_CONST                      16: 3
                        2800    LOAD_CONST                      9: 1
                        2802    CALL                            3
                        2810    POP_TOP                         
                        2812    LOAD_GLOBAL                     11: NULL + QLabel
                        2822    LOAD_CONST                      40: 'Measure Info Score:'
                        2824    CALL                            1
                        2832    STORE_FAST                      11: _var_var_102
                        2834    LOAD_FAST                       11: _var_var_102
                        2836    LOAD_ATTR                       43: setToolTip
                        2856    LOAD_CONST                      41: 'Enable/disable information score measurement'
                        2858    CALL                            1
                        2866    POP_TOP                         
                        2868    LOAD_FAST                       6: _var_var_97
                        2870    LOAD_ATTR                       9: addWidget
                        2890    LOAD_FAST                       11: _var_var_102
                        2892    LOAD_CONST                      20: 4
                        2894    LOAD_CONST                      7: 0
                        2896    CALL                            3
                        2904    POP_TOP                         
                        2906    LOAD_GLOBAL                     59: NULL + QCheckBox
                        2916    CALL                            0
                        2924    LOAD_FAST                       0: self
                        2926    STORE_ATTR                      32: measure_info_score_switch
                        2936    LOAD_FAST                       0: self
                        2938    LOAD_ATTR                       64: measure_info_score_switch
                        2958    LOAD_ATTR                       63: setChecked
                        2978    LOAD_GLOBAL                     14: settings_manager
                        2988    LOAD_ATTR                       16: settings
                        3008    LOAD_CONST                      42: 'measure_info_score'
                        3010    BINARY_SUBSCR                   
                        3014    CALL                            1
                        3022    POP_TOP                         
                        3024    LOAD_FAST                       6: _var_var_97
                        3026    LOAD_ATTR                       9: addWidget
                        3046    LOAD_FAST                       0: self
                        3048    LOAD_ATTR                       64: measure_info_score_switch
                        3068    LOAD_CONST                      20: 4
                        3070    LOAD_CONST                      9: 1
                        3072    CALL                            3
                        3080    POP_TOP                         
                        3082    LOAD_GLOBAL                     11: NULL + QLabel
                        3092    LOAD_CONST                      43: 'Need User Confirm:'
                        3094    CALL                            1
                        3102    STORE_FAST                      12: _var_var_103
                        3104    LOAD_FAST                       12: _var_var_103
                        3106    LOAD_ATTR                       43: setToolTip
                        3126    LOAD_CONST                      44: 'Enable/disable user confirm before send request to LLM'
                        3128    CALL                            1
                        3136    POP_TOP                         
                        3138    LOAD_FAST                       6: _var_var_97
                        3140    LOAD_ATTR                       9: addWidget
                        3160    LOAD_FAST                       12: _var_var_103
                        3162    LOAD_CONST                      45: 5
                        3164    LOAD_CONST                      7: 0
                        3166    CALL                            3
                        3174    POP_TOP                         
                        3176    LOAD_GLOBAL                     59: NULL + QCheckBox
                        3186    CALL                            0
                        3194    LOAD_FAST                       0: self
                        3196    STORE_ATTR                      33: need_confirm_switch
                        3206    LOAD_FAST                       0: self
                        3208    LOAD_ATTR                       66: need_confirm_switch
                        3228    LOAD_ATTR                       63: setChecked
                        3248    LOAD_GLOBAL                     14: settings_manager
                        3258    LOAD_ATTR                       16: settings
                        3278    LOAD_CONST                      46: 'need_confirm'
                        3280    BINARY_SUBSCR                   
                        3284    CALL                            1
                        3292    POP_TOP                         
                        3294    LOAD_FAST                       6: _var_var_97
                        3296    LOAD_ATTR                       9: addWidget
                        3316    LOAD_FAST                       0: self
                        3318    LOAD_ATTR                       66: need_confirm_switch
                        3338    LOAD_CONST                      45: 5
                        3340    LOAD_CONST                      9: 1
                        3342    CALL                            3
                        3350    POP_TOP                         
                        3352    LOAD_GLOBAL                     11: NULL + QLabel
                        3362    LOAD_CONST                      47: 'Mock Mode (Developer Only):'
                        3364    CALL                            1
                        3372    STORE_FAST                      13: _var_var_104
                        3374    LOAD_FAST                       13: _var_var_104
                        3376    LOAD_ATTR                       43: setToolTip
                        3396    LOAD_CONST                      48: 'Enable/disable mock mode for debug'
                        3398    CALL                            1
                        3406    POP_TOP                         
                        3408    LOAD_FAST                       6: _var_var_97
                        3410    LOAD_ATTR                       9: addWidget
                        3430    LOAD_FAST                       13: _var_var_104
                        3432    LOAD_CONST                      49: 6
                        3434    LOAD_CONST                      7: 0
                        3436    CALL                            3
                        3444    POP_TOP                         
                        3446    LOAD_GLOBAL                     59: NULL + QCheckBox
                        3456    CALL                            0
                        3464    LOAD_FAST                       0: self
                        3466    STORE_ATTR                      34: debug_mode_switch
                        3476    LOAD_FAST                       0: self
                        3478    LOAD_ATTR                       68: debug_mode_switch
                        3498    LOAD_ATTR                       63: setChecked
                        3518    LOAD_GLOBAL                     14: settings_manager
                        3528    LOAD_ATTR                       16: settings
                        3548    LOAD_CONST                      50: 'debug_mode'
                        3550    BINARY_SUBSCR                   
                        3554    CALL                            1
                        3562    POP_TOP                         
                        3564    LOAD_FAST                       6: _var_var_97
                        3566    LOAD_ATTR                       9: addWidget
                        3586    LOAD_FAST                       0: self
                        3588    LOAD_ATTR                       68: debug_mode_switch
                        3608    LOAD_CONST                      49: 6
                        3610    LOAD_CONST                      9: 1
                        3612    CALL                            3
                        3620    POP_TOP                         
                        3622    LOAD_GLOBAL                     11: NULL + QLabel
                        3632    LOAD_CONST                      51: 'Feedback Enable:'
                        3634    CALL                            1
                        3642    STORE_FAST                      14: _var_var_105
                        3644    LOAD_FAST                       14: _var_var_105
                        3646    LOAD_ATTR                       43: setToolTip
                        3666    LOAD_CONST                      52: 'Enable/Disable Send Feedback'
                        3668    CALL                            1
                        3676    POP_TOP                         
                        3678    LOAD_FAST                       6: _var_var_97
                        3680    LOAD_ATTR                       9: addWidget
                        3700    LOAD_FAST                       14: _var_var_105
                        3702    LOAD_CONST                      53: 7
                        3704    LOAD_CONST                      7: 0
                        3706    CALL                            3
                        3714    POP_TOP                         
                        3716    LOAD_GLOBAL                     59: NULL + QCheckBox
                        3726    CALL                            0
                        3734    LOAD_FAST                       0: self
                        3736    STORE_ATTR                      35: feedback_switch
                        3746    LOAD_FAST                       0: self
                        3748    LOAD_ATTR                       70: feedback_switch
                        3768    LOAD_ATTR                       63: setChecked
                        3788    LOAD_GLOBAL                     14: settings_manager
                        3798    LOAD_ATTR                       16: settings
                        3818    LOAD_CONST                      54: 'feedback'
                        3820    BINARY_SUBSCR                   
                        3824    CALL                            1
                        3832    POP_TOP                         
                        3834    LOAD_FAST                       6: _var_var_97
                        3836    LOAD_ATTR                       9: addWidget
                        3856    LOAD_FAST                       0: self
                        3858    LOAD_ATTR                       70: feedback_switch
                        3878    LOAD_CONST                      53: 7
                        3880    LOAD_CONST                      9: 1
                        3882    CALL                            3
                        3890    POP_TOP                         
                        3892    LOAD_FAST                       2: _var_var_1
                        3894    LOAD_ATTR                       9: addWidget
                        3914    LOAD_FAST                       5: _var_var_96
                        3916    CALL                            1
                        3924    POP_TOP                         
                        3926    LOAD_GLOBAL                     73: NULL + QHBoxLayout
                        3936    CALL                            0
                        3944    STORE_FAST                      15: _var_var_66
                        3946    LOAD_GLOBAL                     75: NULL + QPushButton
                        3956    LOAD_CONST                      55: 'Save Settings'
                        3958    CALL                            1
                        3966    STORE_FAST                      16: _var_var_106
                        3968    LOAD_FAST                       16: _var_var_106
                        3970    LOAD_ATTR                       76: clicked
                        3990    LOAD_ATTR                       79: connect
                        4010    LOAD_FAST                       0: self
                        4012    LOAD_ATTR                       80: save_settings
                        4032    CALL                            1
                        4040    POP_TOP                         
                        4042    LOAD_GLOBAL                     75: NULL + QPushButton
                        4052    LOAD_CONST                      56: 'Cancel'
                        4054    CALL                            1
                        4062    STORE_FAST                      17: _var_var_68
                        4064    LOAD_FAST                       17: _var_var_68
                        4066    LOAD_ATTR                       76: clicked
                        4086    LOAD_ATTR                       79: connect
                        4106    LOAD_FAST                       0: self
                        4108    LOAD_ATTR                       82: reject
                        4128    CALL                            1
                        4136    POP_TOP                         
                        4138    LOAD_FAST                       15: _var_var_66
                        4140    LOAD_ATTR                       9: addWidget
                        4160    LOAD_FAST                       16: _var_var_106
                        4162    CALL                            1
                        4170    POP_TOP                         
                        4172    LOAD_FAST                       15: _var_var_66
                        4174    LOAD_ATTR                       9: addWidget
                        4194    LOAD_FAST                       17: _var_var_68
                        4196    CALL                            1
                        4204    POP_TOP                         
                        4206    LOAD_FAST                       2: _var_var_1
                        4208    LOAD_ATTR                       85: addLayout
                        4228    LOAD_FAST                       15: _var_var_66
                        4230    CALL                            1
                        4238    POP_TOP                         
                        4240    LOAD_CONST                      58: None
                        4242    NOP                             
                        4244    NOP                             
                        4246    NOP                             
                        4248    JUMP_FORWARD                    19 (to 4288)
                        4256    POP_TOP                         
                        4258    RETURN_CONST                    58: None
                        4260    PUSH_EXC_INFO                   
                        4262    PUSH_NULL                       
                        4264    LOAD_CONST                      57: '__pyarmor_exit_54720__'
                        4266    NOP                             
                        4268    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8a\x10\x00\x00\x00\x00\x00\x00'
                        4270    CALL                            1
                        4278    POP_TOP                         
                        4280    RERAISE                         0
                        4282    COPY                            3
                        4284    POP_EXCEPT                      
                        4286    RERAISE                         1
                        4288    PUSH_NULL                       
                        4290    LOAD_CONST                      57: '__pyarmor_exit_54720__'
                        4292    LOAD_CONST                      3: b'<COAddr>\x03\x00\x00\x1a\x8a\x10\x00\x00\x00\x00\x00\x00'
                        4294    BUILD_TUPLE                     1
                        4296    CALL_FUNCTION_EX                0
                        4298    POP_TOP                         
                        4300    RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: save_settings
                    Qualified Name: ReCopilotSettingsDialog.save_settings
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 14
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'model_name_edit'
                        'text'
                        'strip'
                        'prompt_template_combo'
                        'currentText'
                        'startswith'
                        'QMessageBox'
                        'warning'
                        'base_url_edit'
                        'api_key_edit'
                        'max_output_tokens_spin'
                        'value'
                        'caller_depth_spin'
                        'callee_depth_spin'
                        'context_func_spin'
                        'data_flow_switch'
                        'isChecked'
                        'measure_info_score_switch'
                        'need_confirm_switch'
                        'debug_mode_switch'
                        'feedback_switch'
                        'settings_manager'
                        'save_settings'
                        'information'
                        'accept'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                        '_var_var_107'
                        '_var_var_108'
                        '_var_var_109'
                    [Constants]
                        'Save current settings and close dialog.'
                        '__pyarmor_assert_54721__'
                        '__pyarmor_enter_54722__'
                        b'<COAddr>\x01\x00\x00\x1a\xe4\x04\x00\x00\x00\x00\x00\x00'
                        'recopilot'
                        'general'
                        'Invalid Configuration (无效配置)'
                        'General LLMs must use general* prompt template.\n(通用模型必须使用 general* 提示词模版)'
                        '__pyarmor_exit_54723__'
                        None
                        'ReCopilot models must use recopilot* prompt template.\n(ReCopilot 模型必须使用 recopilot* 提示词模版)'
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
                        'Success'
                        'Settings saved successfully!'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54722__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x04\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: model_name_edit
                        50      LOAD_ATTR                       3: text
                        70      CALL                            0
                        78      LOAD_ATTR                       5: strip
                        98      CALL                            0
                        106     STORE_FAST                      2: _var_var_107
                        108     LOAD_FAST                       0: self
                        110     LOAD_ATTR                       6: prompt_template_combo
                        130     LOAD_ATTR                       9: currentText
                        150     CALL                            0
                        158     STORE_FAST                      3: _var_var_108
                        160     LOAD_FAST                       2: _var_var_107
                        162     LOAD_ATTR                       11: startswith
                        182     LOAD_CONST                      4: 'recopilot'
                        184     CALL                            1
                        192     POP_JUMP_IF_TRUE                51 (to 296)
                        194     LOAD_FAST                       3: _var_var_108
                        196     LOAD_ATTR                       11: startswith
                        216     LOAD_CONST                      5: 'general'
                        218     CALL                            1
                        226     POP_JUMP_IF_TRUE                85 (to 398)
                        228     LOAD_GLOBAL                     13: NULL + QMessageBox
                        238     LOAD_ATTR                       14: warning
                        258     LOAD_FAST                       0: self
                        260     LOAD_CONST                      6: 'Invalid Configuration (无效配置)'
                        262     LOAD_CONST                      7: 'General LLMs must use general* prompt template.\n(通用模型必须使用 general* 提示词模版)'
                        264     CALL                            3
                        272     POP_TOP                         
                        274     NOP                             
                        276     LOAD_CONST                      9: None
                        278     NOP                             
                        280     NOP                             
                        282     JUMP_FORWARD                    510 (to 1306)
                        292     POP_TOP                         
                        294     RETURN_CONST                    9: None
                        296     LOAD_FAST                       3: _var_var_108
                        298     LOAD_ATTR                       11: startswith
                        318     LOAD_CONST                      4: 'recopilot'
                        320     CALL                            1
                        328     POP_JUMP_IF_TRUE                34 (to 398)
                        330     LOAD_GLOBAL                     13: NULL + QMessageBox
                        340     LOAD_ATTR                       14: warning
                        360     LOAD_FAST                       0: self
                        362     LOAD_CONST                      6: 'Invalid Configuration (无效配置)'
                        364     LOAD_CONST                      10: 'ReCopilot models must use recopilot* prompt template.\n(ReCopilot 模型必须使用 recopilot* 提示词模版)'
                        366     CALL                            3
                        374     POP_TOP                         
                        376     NOP                             
                        378     LOAD_CONST                      9: None
                        380     NOP                             
                        382     NOP                             
                        384     JUMP_FORWARD                    459 (to 1306)
                        394     POP_TOP                         
                        396     RETURN_CONST                    9: None
                        398     LOAD_FAST                       0: self
                        400     LOAD_ATTR                       0: model_name_edit
                        420     LOAD_ATTR                       3: text
                        440     CALL                            0
                        448     LOAD_ATTR                       5: strip
                        468     CALL                            0
                        476     LOAD_FAST                       0: self
                        478     LOAD_ATTR                       16: base_url_edit
                        498     LOAD_ATTR                       3: text
                        518     CALL                            0
                        526     LOAD_ATTR                       5: strip
                        546     CALL                            0
                        554     LOAD_FAST                       0: self
                        556     LOAD_ATTR                       18: api_key_edit
                        576     LOAD_ATTR                       3: text
                        596     CALL                            0
                        604     LOAD_ATTR                       5: strip
                        624     CALL                            0
                        632     LOAD_FAST                       0: self
                        634     LOAD_ATTR                       6: prompt_template_combo
                        654     LOAD_ATTR                       9: currentText
                        674     CALL                            0
                        682     LOAD_FAST                       0: self
                        684     LOAD_ATTR                       20: max_output_tokens_spin
                        704     LOAD_ATTR                       23: value
                        724     CALL                            0
                        732     LOAD_FAST                       0: self
                        734     LOAD_ATTR                       24: caller_depth_spin
                        754     LOAD_ATTR                       23: value
                        774     CALL                            0
                        782     LOAD_FAST                       0: self
                        784     LOAD_ATTR                       26: callee_depth_spin
                        804     LOAD_ATTR                       23: value
                        824     CALL                            0
                        832     LOAD_FAST                       0: self
                        834     LOAD_ATTR                       28: context_func_spin
                        854     LOAD_ATTR                       23: value
                        874     CALL                            0
                        882     LOAD_FAST                       0: self
                        884     LOAD_ATTR                       30: data_flow_switch
                        904     LOAD_ATTR                       33: isChecked
                        924     CALL                            0
                        932     LOAD_FAST                       0: self
                        934     LOAD_ATTR                       34: measure_info_score_switch
                        954     LOAD_ATTR                       33: isChecked
                        974     CALL                            0
                        982     LOAD_FAST                       0: self
                        984     LOAD_ATTR                       36: need_confirm_switch
                        1004    LOAD_ATTR                       33: isChecked
                        1024    CALL                            0
                        1032    LOAD_FAST                       0: self
                        1034    LOAD_ATTR                       38: debug_mode_switch
                        1054    LOAD_ATTR                       33: isChecked
                        1074    CALL                            0
                        1082    LOAD_FAST                       0: self
                        1084    LOAD_ATTR                       40: feedback_switch
                        1104    LOAD_ATTR                       33: isChecked
                        1124    CALL                            0
                        1132    LOAD_CONST                      11: ('model_name', 'base_url', 'api_key', 'prompt_template', 'max_output_tokens', 'max_trace_caller_depth', 'max_trace_callee_depth', 'max_context_func_num', 'data_flow_analysis', 'measure_info_score', 'need_confirm', 'debug_mode', 'feedback')
                        1134    BUILD_CONST_KEY_MAP             13
                        1136    STORE_FAST                      4: _var_var_109
                        1138    LOAD_GLOBAL                     43: NULL + settings_manager
                        1148    LOAD_ATTR                       44: save_settings
                        1168    LOAD_FAST                       4: _var_var_109
                        1170    CALL                            1
                        1178    POP_TOP                         
                        1180    LOAD_GLOBAL                     13: NULL + QMessageBox
                        1190    LOAD_ATTR                       46: information
                        1210    LOAD_FAST                       0: self
                        1212    LOAD_CONST                      12: 'Success'
                        1214    LOAD_CONST                      13: 'Settings saved successfully!'
                        1216    CALL                            3
                        1224    POP_TOP                         
                        1226    LOAD_FAST                       0: self
                        1228    LOAD_ATTR                       49: accept
                        1248    CALL                            0
                        1256    POP_TOP                         
                        1258    LOAD_CONST                      9: None
                        1260    NOP                             
                        1262    NOP                             
                        1264    NOP                             
                        1266    JUMP_FORWARD                    19 (to 1306)
                        1274    POP_TOP                         
                        1276    RETURN_CONST                    9: None
                        1278    PUSH_EXC_INFO                   
                        1280    PUSH_NULL                       
                        1282    LOAD_CONST                      8: '__pyarmor_exit_54723__'
                        1284    NOP                             
                        1286    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x04\x00\x00\x00\x00\x00\x00'
                        1288    CALL                            1
                        1296    POP_TOP                         
                        1298    RERAISE                         0
                        1300    COPY                            3
                        1302    POP_EXCEPT                      
                        1304    RERAISE                         1
                        1306    PUSH_NULL                       
                        1308    LOAD_CONST                      8: '__pyarmor_exit_54723__'
                        1310    LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1a\xe4\x04\x00\x00\x00\x00\x00\x00'
                        1312    BUILD_TUPLE                     1
                        1314    CALL_FUNCTION_EX                0
                        1316    POP_TOP                         
                        1318    RETURN_VALUE                    
                '__pyarmor_exit_54714__'
                (
                    None
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'ReCopilotSettingsDialog'
                10      STORE_NAME                      2: __qualname__
                12      LOAD_CONST                      1: '\n    Dialog for configuring ReCopilot settings.\n    '
                14      STORE_NAME                      3: __doc__
                16      NOP                             
                18      PUSH_NULL                       
                20      LOAD_CONST                      3: '__pyarmor_enter_54713__'
                22      LOAD_CONST                      4: b'<COAddr>\x01\x00\x00(4\x00\x00\x00\x00\x00\x00\x00'
                24      BUILD_TUPLE                     1
                26      CALL_FUNCTION_EX                0
                28      POP_TOP                         
                30      RESUME                          0
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      NOP                             
                40      NOP                             
                42      LOAD_CONST                      9: (None,)
                44      LOAD_CLOSURE                    0: __class__
                46      BUILD_TUPLE                     1
                48      LOAD_CONST                      5: <CODE> __init__
                50      MAKE_FUNCTION                   9
                52      STORE_NAME                      5: __init__
                54      LOAD_CONST                      6: <CODE> initUI
                56      MAKE_FUNCTION                   0
                58      STORE_NAME                      6: initUI
                60      LOAD_CONST                      7: <CODE> save_settings
                62      MAKE_FUNCTION                   0
                64      STORE_NAME                      7: save_settings
                66      LOAD_CLOSURE                    0: __class__
                68      COPY                            1
                70      STORE_NAME                      8: __classcell__
                72      NOP                             
                74      NOP                             
                76      NOP                             
                78      JUMP_FORWARD                    20 (to 120)
                82      POP_TOP                         
                84      LOAD_CLOSURE                    0: __class__
                86      COPY                            1
                88      STORE_NAME                      8: __classcell__
                90      RETURN_VALUE                    
                92      PUSH_EXC_INFO                   
                94      PUSH_NULL                       
                96      LOAD_CONST                      8: '__pyarmor_exit_54714__'
                98      NOP                             
                100     LOAD_CONST                      4: b'<COAddr>\x01\x00\x00(4\x00\x00\x00\x00\x00\x00\x00'
                102     CALL                            1
                110     POP_TOP                         
                112     RERAISE                         0
                114     COPY                            3
                116     POP_EXCEPT                      
                118     RERAISE                         1
                120     PUSH_NULL                       
                122     LOAD_CONST                      8: '__pyarmor_exit_54714__'
                124     LOAD_CONST                      4: b'<COAddr>\x01\x00\x00(4\x00\x00\x00\x00\x00\x00\x00'
                126     BUILD_TUPLE                     1
                128     CALL_FUNCTION_EX                0
                130     POP_TOP                         
                132     RETURN_VALUE                    
        'ReCopilotSettingsDialog'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: OutputWindowButton
            Qualified Name: OutputWindowButton
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
                'OpenAIModel'
                '__init__'
                'on_cancel_clicked'
                '__classcell__'
            [Locals+Names]
                '__class__'
            [Constants]
                'OutputWindowButton'
                '__pyarmor_assert_54724__'
                '__pyarmor_enter_54725__'
                b'<COAddr>\x01\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                'model'
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: __init__
                    Qualified Name: OutputWindowButton.__init__
                    Arg Count: 3
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 6
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'super'
                        'OutputWindowButton'
                        '__init__'
                        'model'
                        'setFixedHeight'
                        'QHBoxLayout'
                        'setContentsMargins'
                        'setSpacing'
                        'addStretch'
                        'QPushButton'
                        'button'
                        'setStyleSheet'
                        'clicked'
                        'connect'
                        'on_cancel_clicked'
                        'addWidget'
                    [Locals+Names]
                        'self'
                        'model'
                        'parent'
                        '__assert_armored__'
                        '_var_var_1'
                        '__class__'
                    [Constants]
                        None
                        '__pyarmor_assert_54727__'
                        '__pyarmor_enter_54728__'
                        b'<COAddr>\x01\x00\x00\x1c\xd8\x01\x00\x00\x00\x00\x00\x00'
                        30
                        5
                        0
                        15
                        'Cancel Analysis'
                        '\n            QPushButton {\n                background-color: #823432;\n                color: white;\n                border: none;\n                border-radius: 3px;\n                padding: 5px 10px;\n                font-weight: bold;\n                min-width: 100px;\n            }\n            QPushButton:hover {\n                background-color: #9a3f3d;\n            }\n            QPushButton:pressed {\n                background-color: #6b2a29;\n            }\n        '
                        '__pyarmor_exit_54729__'
                    [Disassembly]
                        0       COPY_FREE_VARS                  1
                        2       NOP                             
                        4       NOP                             
                        6       PUSH_NULL                       
                        8       LOAD_CONST                      2: '__pyarmor_enter_54728__'
                        10      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xd8\x01\x00\x00\x00\x00\x00\x00'
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
                        40      LOAD_GLOBAL                     2: OutputWindowButton
                        50      LOAD_FAST                       0: self
                        52      LOAD_SUPER_ATTR                 11: __init__
                        56      LOAD_FAST                       2: parent
                        58      CALL                            1
                        66      POP_TOP                         
                        68      LOAD_FAST                       1: model
                        70      LOAD_FAST                       0: self
                        72      STORE_ATTR                      3: model
                        82      LOAD_FAST                       0: self
                        84      LOAD_ATTR                       9: setFixedHeight
                        104     LOAD_CONST                      4: 30
                        106     CALL                            1
                        114     POP_TOP                         
                        116     LOAD_GLOBAL                     11: NULL + QHBoxLayout
                        126     LOAD_FAST                       0: self
                        128     CALL                            1
                        136     STORE_FAST                      4: _var_var_1
                        138     LOAD_FAST                       4: _var_var_1
                        140     LOAD_ATTR                       13: setContentsMargins
                        160     LOAD_CONST                      5: 5
                        162     LOAD_CONST                      6: 0
                        164     LOAD_CONST                      7: 15
                        166     LOAD_CONST                      6: 0
                        168     CALL                            4
                        176     POP_TOP                         
                        178     LOAD_FAST                       4: _var_var_1
                        180     LOAD_ATTR                       15: setSpacing
                        200     LOAD_CONST                      5: 5
                        202     CALL                            1
                        210     POP_TOP                         
                        212     LOAD_FAST                       4: _var_var_1
                        214     LOAD_ATTR                       17: addStretch
                        234     CALL                            0
                        242     POP_TOP                         
                        244     LOAD_GLOBAL                     19: NULL + QPushButton
                        254     LOAD_CONST                      8: 'Cancel Analysis'
                        256     LOAD_FAST                       0: self
                        258     CALL                            2
                        266     LOAD_FAST                       0: self
                        268     STORE_ATTR                      10: button
                        278     LOAD_FAST                       0: self
                        280     LOAD_ATTR                       20: button
                        300     LOAD_ATTR                       23: setStyleSheet
                        320     LOAD_CONST                      9: '\n            QPushButton {\n                background-color: #823432;\n                color: white;\n                border: none;\n                border-radius: 3px;\n                padding: 5px 10px;\n                font-weight: bold;\n                min-width: 100px;\n            }\n            QPushButton:hover {\n                background-color: #9a3f3d;\n            }\n            QPushButton:pressed {\n                background-color: #6b2a29;\n            }\n        '
                        322     CALL                            1
                        330     POP_TOP                         
                        332     LOAD_FAST                       0: self
                        334     LOAD_ATTR                       20: button
                        354     LOAD_ATTR                       24: clicked
                        374     LOAD_ATTR                       27: connect
                        394     LOAD_FAST                       0: self
                        396     LOAD_ATTR                       28: on_cancel_clicked
                        416     CALL                            1
                        424     POP_TOP                         
                        426     LOAD_FAST                       4: _var_var_1
                        428     LOAD_ATTR                       31: addWidget
                        448     LOAD_FAST                       0: self
                        450     LOAD_ATTR                       20: button
                        470     CALL                            1
                        478     POP_TOP                         
                        480     LOAD_CONST                      0: None
                        482     NOP                             
                        484     NOP                             
                        486     NOP                             
                        488     JUMP_FORWARD                    19 (to 528)
                        496     POP_TOP                         
                        498     RETURN_CONST                    0: None
                        500     PUSH_EXC_INFO                   
                        502     PUSH_NULL                       
                        504     LOAD_CONST                      10: '__pyarmor_exit_54729__'
                        506     NOP                             
                        508     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xd8\x01\x00\x00\x00\x00\x00\x00'
                        510     CALL                            1
                        518     POP_TOP                         
                        520     RERAISE                         0
                        522     COPY                            3
                        524     POP_EXCEPT                      
                        526     RERAISE                         1
                        528     PUSH_NULL                       
                        530     LOAD_CONST                      10: '__pyarmor_exit_54729__'
                        532     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1c\xd8\x01\x00\x00\x00\x00\x00\x00'
                        534     BUILD_TUPLE                     1
                        536     CALL_FUNCTION_EX                0
                        538     POP_TOP                         
                        540     RETURN_VALUE                    
                [Code]
                    File Name: <frozen ..recopilot_qt>
                    Object Name: on_cancel_clicked
                    Qualified Name: OutputWindowButton.on_cancel_clicked
                    Arg Count: 1
                    Pos Only Arg Count: 0
                    KW Only Arg Count: 0
                    Stack Size: 5
                    Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
                    [Names]
                        'model'
                        'cancel'
                        'hide'
                    [Locals+Names]
                        'self'
                        '__assert_armored__'
                    [Constants]
                        None
                        '__pyarmor_assert_54730__'
                        '__pyarmor_enter_54731__'
                        b'<COAddr>\x01\x00\x00\x1aj\x00\x00\x00\x00\x00\x00\x00'
                        '__pyarmor_exit_54732__'
                    [Disassembly]
                        0       NOP                             
                        2       NOP                             
                        4       PUSH_NULL                       
                        6       LOAD_CONST                      2: '__pyarmor_enter_54731__'
                        8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aj\x00\x00\x00\x00\x00\x00\x00'
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
                        30      LOAD_ATTR                       0: model
                        50      LOAD_ATTR                       3: cancel
                        70      CALL                            0
                        78      POP_TOP                         
                        80      LOAD_FAST                       0: self
                        82      LOAD_ATTR                       5: hide
                        102     CALL                            0
                        110     POP_TOP                         
                        112     LOAD_CONST                      0: None
                        114     NOP                             
                        116     NOP                             
                        118     NOP                             
                        120     JUMP_FORWARD                    19 (to 160)
                        128     POP_TOP                         
                        130     RETURN_CONST                    0: None
                        132     PUSH_EXC_INFO                   
                        134     PUSH_NULL                       
                        136     LOAD_CONST                      4: '__pyarmor_exit_54732__'
                        138     NOP                             
                        140     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aj\x00\x00\x00\x00\x00\x00\x00'
                        142     CALL                            1
                        150     POP_TOP                         
                        152     RERAISE                         0
                        154     COPY                            3
                        156     POP_EXCEPT                      
                        158     RERAISE                         1
                        160     PUSH_NULL                       
                        162     LOAD_CONST                      4: '__pyarmor_exit_54732__'
                        164     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aj\x00\x00\x00\x00\x00\x00\x00'
                        166     BUILD_TUPLE                     1
                        168     CALL_FUNCTION_EX                0
                        170     POP_TOP                         
                        172     RETURN_VALUE                    
                '__pyarmor_exit_54726__'
                (
                    None
                )
            [Disassembly]
                0       MAKE_CELL                       0: __class__
                2       NOP                             
                4       LOAD_NAME                       0: __name__
                6       STORE_NAME                      1: __module__
                8       LOAD_CONST                      0: 'OutputWindowButton'
                10      STORE_NAME                      2: __qualname__
                12      NOP                             
                14      PUSH_NULL                       
                16      LOAD_CONST                      2: '__pyarmor_enter_54725__'
                18      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                20      BUILD_TUPLE                     1
                22      CALL_FUNCTION_EX                0
                24      POP_TOP                         
                26      RESUME                          0
                28      NOP                             
                30      NOP                             
                32      NOP                             
                34      NOP                             
                36      NOP                             
                38      LOAD_CONST                      8: (None,)
                40      LOAD_CONST                      4: 'model'
                42      LOAD_NAME                       4: OpenAIModel
                44      BUILD_TUPLE                     2
                46      LOAD_CLOSURE                    0: __class__
                48      BUILD_TUPLE                     1
                50      LOAD_CONST                      5: <CODE> __init__
                52      MAKE_FUNCTION                   13
                54      STORE_NAME                      5: __init__
                56      LOAD_CONST                      6: <CODE> on_cancel_clicked
                58      MAKE_FUNCTION                   0
                60      STORE_NAME                      6: on_cancel_clicked
                62      LOAD_CLOSURE                    0: __class__
                64      COPY                            1
                66      STORE_NAME                      7: __classcell__
                68      NOP                             
                70      NOP                             
                72      NOP                             
                74      JUMP_FORWARD                    20 (to 116)
                78      POP_TOP                         
                80      LOAD_CLOSURE                    0: __class__
                82      COPY                            1
                84      STORE_NAME                      7: __classcell__
                86      RETURN_VALUE                    
                88      PUSH_EXC_INFO                   
                90      PUSH_NULL                       
                92      LOAD_CONST                      7: '__pyarmor_exit_54726__'
                94      NOP                             
                96      LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                98      CALL                            1
                106     POP_TOP                         
                108     RERAISE                         0
                110     COPY                            3
                112     POP_EXCEPT                      
                114     RERAISE                         1
                116     PUSH_NULL                       
                118     LOAD_CONST                      7: '__pyarmor_exit_54726__'
                120     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00$4\x00\x00\x00\x00\x00\x00\x00'
                122     BUILD_TUPLE                     1
                124     CALL_FUNCTION_EX                0
                126     POP_TOP                         
                128     RETURN_VALUE                    
        'OutputWindowButton'
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: add_cancel_button
            Qualified Name: add_cancel_button
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'ida_kernwin'
                'find_widget'
                'PluginForm'
                'FormToPyQtWidget'
                'OutputWindowButton'
                'layout'
                'addWidget'
                'show'
            [Locals+Names]
                'model'
                '__assert_armored__'
                '_var_var_110'
                '_var_var_111'
                '_var_var_112'
            [Constants]
                'Add a cancel button to the bottom of the Output window'
                '__pyarmor_assert_54733__'
                '__pyarmor_enter_54734__'
                b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                'Output window'
                '__pyarmor_exit_54735__'
                None
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54734__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
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
                38      LOAD_ATTR                       2: find_widget
                58      LOAD_CONST                      4: 'Output window'
                60      CALL                            1
                68      STORE_FAST                      2: _var_var_110
                70      LOAD_FAST                       2: _var_var_110
                72      POP_JUMP_IF_TRUE                11 (to 96)
                74      NOP                             
                76      LOAD_CONST                      6: None
                78      NOP                             
                80      NOP                             
                82      NOP                             
                84      JUMP_FORWARD                    147 (to 380)
                92      POP_TOP                         
                94      RETURN_CONST                    6: None
                96      LOAD_GLOBAL                     0: ida_kernwin
                106     LOAD_ATTR                       4: PluginForm
                126     LOAD_ATTR                       7: FormToPyQtWidget
                146     LOAD_FAST                       2: _var_var_110
                148     CALL                            1
                156     STORE_FAST                      2: _var_var_110
                158     LOAD_FAST                       2: _var_var_110
                160     POP_JUMP_IF_TRUE                11 (to 184)
                162     NOP                             
                164     LOAD_CONST                      6: None
                166     NOP                             
                168     NOP                             
                170     NOP                             
                172     JUMP_FORWARD                    103 (to 380)
                180     POP_TOP                         
                182     RETURN_CONST                    6: None
                184     LOAD_GLOBAL                     9: NULL + OutputWindowButton
                194     LOAD_FAST                       0: model
                196     LOAD_FAST                       2: _var_var_110
                198     CALL                            2
                206     STORE_FAST                      3: _var_var_111
                208     LOAD_FAST                       2: _var_var_110
                210     LOAD_ATTR                       11: layout
                230     CALL                            0
                238     STORE_FAST                      4: _var_var_112
                240     LOAD_FAST                       4: _var_var_112
                242     POP_JUMP_IF_FALSE               44 (to 332)
                244     LOAD_FAST                       4: _var_var_112
                246     LOAD_ATTR                       13: addWidget
                266     LOAD_FAST                       3: _var_var_111
                268     CALL                            1
                276     POP_TOP                         
                278     LOAD_FAST                       3: _var_var_111
                280     LOAD_ATTR                       15: show
                300     CALL                            0
                308     POP_TOP                         
                310     LOAD_FAST                       3: _var_var_111
                312     NOP                             
                314     NOP                             
                316     NOP                             
                318     JUMP_FORWARD                    30 (to 380)
                320     CALL                            1
                328     POP_TOP                         
                330     RETURN_VALUE                    
                332     LOAD_CONST                      6: None
                334     NOP                             
                336     NOP                             
                338     NOP                             
                340     JUMP_FORWARD                    19 (to 380)
                348     POP_TOP                         
                350     RETURN_CONST                    6: None
                352     PUSH_EXC_INFO                   
                354     PUSH_NULL                       
                356     LOAD_CONST                      5: '__pyarmor_exit_54735__'
                358     NOP                             
                360     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                362     CALL                            1
                370     POP_TOP                         
                372     RERAISE                         0
                374     COPY                            3
                376     POP_EXCEPT                      
                378     RERAISE                         1
                380     PUSH_NULL                       
                382     LOAD_CONST                      5: '__pyarmor_exit_54735__'
                384     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aF\x01\x00\x00\x00\x00\x00\x00'
                386     BUILD_TUPLE                     1
                388     CALL_FUNCTION_EX                0
                390     POP_TOP                         
                392     RETURN_VALUE                    
        [Code]
            File Name: <frozen ..recopilot_qt>
            Object Name: remove_cancel_button
            Qualified Name: remove_cancel_button
            Arg Count: 1
            Pos Only Arg Count: 0
            KW Only Arg Count: 0
            Stack Size: 5
            Flags: 0x20000003 (CO_OPTIMIZED | CO_NEWLOCALS | CO_PYARMOR_OBFUSCATED)
            [Names]
                'hide'
                'deleteLater'
            [Locals+Names]
                'button_widget'
                '__assert_armored__'
            [Constants]
                'Remove the cancel button'
                '__pyarmor_assert_54736__'
                '__pyarmor_enter_54737__'
                b'<COAddr>\x01\x00\x00\x1aZ\x00\x00\x00\x00\x00\x00\x00'
                '__pyarmor_exit_54738__'
                None
            [Disassembly]
                0       NOP                             
                2       NOP                             
                4       PUSH_NULL                       
                6       LOAD_CONST                      2: '__pyarmor_enter_54737__'
                8       LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x00\x00\x00\x00\x00\x00\x00'
                10      BUILD_TUPLE                     1
                12      CALL_FUNCTION_EX                0
                14      POP_TOP                         
                16      RESUME                          0
                18      NOP                             
                20      NOP                             
                22      NOP                             
                24      NOP                             
                26      NOP                             
                28      LOAD_FAST                       0: button_widget
                30      POP_JUMP_IF_FALSE               32 (to 96)
                32      LOAD_FAST                       0: button_widget
                34      LOAD_ATTR                       1: hide
                54      CALL                            0
                62      POP_TOP                         
                64      LOAD_FAST                       0: button_widget
                66      LOAD_ATTR                       3: deleteLater
                86      CALL                            0
                94      POP_TOP                         
                96      LOAD_CONST                      5: None
                98      NOP                             
                100     NOP                             
                102     NOP                             
                104     JUMP_FORWARD                    19 (to 144)
                112     POP_TOP                         
                114     RETURN_CONST                    5: None
                116     PUSH_EXC_INFO                   
                118     PUSH_NULL                       
                120     LOAD_CONST                      4: '__pyarmor_exit_54738__'
                122     NOP                             
                124     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x00\x00\x00\x00\x00\x00\x00'
                126     CALL                            1
                134     POP_TOP                         
                136     RERAISE                         0
                138     COPY                            3
                140     POP_EXCEPT                      
                142     RERAISE                         1
                144     PUSH_NULL                       
                146     LOAD_CONST                      4: '__pyarmor_exit_54738__'
                148     LOAD_CONST                      3: b'<COAddr>\x01\x00\x00\x1aZ\x00\x00\x00\x00\x00\x00\x00'
                150     BUILD_TUPLE                     1
                152     CALL_FUNCTION_EX                0
                154     POP_TOP                         
                156     RETURN_VALUE                    
        '__pyarmor_exit_54480__'
    [Disassembly]
        0       NOP                             
        2       NOP                             
        4       PUSH_NULL                       
        6       LOAD_CONST                      1: '__pyarmor_enter_54479__'
        8       LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a|\x02\x00\x00\x00\x00\x00\x00'
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
        30      IMPORT_NAME                     1: idc
        32      STORE_NAME                      1: idc
        34      LOAD_CONST                      3: 0
        36      LOAD_CONST                      4: None
        38      IMPORT_NAME                     2: idaapi
        40      STORE_NAME                      2: idaapi
        42      LOAD_CONST                      3: 0
        44      LOAD_CONST                      4: None
        46      IMPORT_NAME                     3: ida_funcs
        48      STORE_NAME                      3: ida_funcs
        50      LOAD_CONST                      3: 0
        52      LOAD_CONST                      4: None
        54      IMPORT_NAME                     4: ida_hexrays
        56      STORE_NAME                      4: ida_hexrays
        58      LOAD_CONST                      3: 0
        60      LOAD_CONST                      4: None
        62      IMPORT_NAME                     5: ida_name
        64      STORE_NAME                      5: ida_name
        66      LOAD_CONST                      3: 0
        68      LOAD_CONST                      4: None
        70      IMPORT_NAME                     6: ida_bytes
        72      STORE_NAME                      6: ida_bytes
        74      LOAD_CONST                      3: 0
        76      LOAD_CONST                      4: None
        78      IMPORT_NAME                     7: ida_kernwin
        80      STORE_NAME                      7: ida_kernwin
        82      LOAD_CONST                      3: 0
        84      LOAD_CONST                      5: ('highlight',)
        86      IMPORT_NAME                     8: pygments
        88      IMPORT_FROM                     9: highlight
        90      STORE_NAME                      9: highlight
        92      POP_TOP                         
        94      LOAD_CONST                      3: 0
        96      LOAD_CONST                      6: ('CppLexer',)
        98      IMPORT_NAME                     10: pygments.lexers
        100     IMPORT_FROM                     11: CppLexer
        102     STORE_NAME                      11: CppLexer
        104     POP_TOP                         
        106     LOAD_CONST                      3: 0
        108     LOAD_CONST                      7: ('Token',)
        110     IMPORT_NAME                     12: pygments.token
        112     IMPORT_FROM                     13: Token
        114     STORE_NAME                      13: Token
        116     POP_TOP                         
        118     LOAD_CONST                      3: 0
        120     LOAD_CONST                      8: ('HtmlFormatter',)
        122     IMPORT_NAME                     14: pygments.formatters
        124     IMPORT_FROM                     15: HtmlFormatter
        126     STORE_NAME                      15: HtmlFormatter
        128     POP_TOP                         
        130     LOAD_CONST                      3: 0
        132     LOAD_CONST                      9: ('QtWidgets', 'QtCore', 'QtGui')
        134     IMPORT_NAME                     16: PyQt5
        136     IMPORT_FROM                     17: QtWidgets
        138     STORE_NAME                      17: QtWidgets
        140     IMPORT_FROM                     18: QtCore
        142     STORE_NAME                      18: QtCore
        144     IMPORT_FROM                     19: QtGui
        146     STORE_NAME                      19: QtGui
        148     POP_TOP                         
        150     LOAD_CONST                      3: 0
        152     LOAD_CONST                      10: ('QDialog', 'QVBoxLayout', 'QHBoxLayout', 'QPushButton', 'QLabel', 'QWidget', 'QLineEdit', 'QGroupBox', 'QGridLayout', 'QMessageBox', 'QSpinBox', 'QCheckBox', 'QComboBox')
        154     IMPORT_NAME                     20: PyQt5.QtWidgets
        156     IMPORT_FROM                     21: QDialog
        158     STORE_NAME                      21: QDialog
        160     IMPORT_FROM                     22: QVBoxLayout
        162     STORE_NAME                      22: QVBoxLayout
        164     IMPORT_FROM                     23: QHBoxLayout
        166     STORE_NAME                      23: QHBoxLayout
        168     IMPORT_FROM                     24: QPushButton
        170     STORE_NAME                      24: QPushButton
        172     IMPORT_FROM                     25: QLabel
        174     STORE_NAME                      25: QLabel
        176     IMPORT_FROM                     26: QWidget
        178     STORE_NAME                      26: QWidget
        180     IMPORT_FROM                     27: QLineEdit
        182     STORE_NAME                      27: QLineEdit
        184     IMPORT_FROM                     28: QGroupBox
        186     STORE_NAME                      28: QGroupBox
        188     IMPORT_FROM                     29: QGridLayout
        190     STORE_NAME                      29: QGridLayout
        192     IMPORT_FROM                     30: QMessageBox
        194     STORE_NAME                      30: QMessageBox
        196     IMPORT_FROM                     31: QSpinBox
        198     STORE_NAME                      31: QSpinBox
        200     IMPORT_FROM                     32: QCheckBox
        202     STORE_NAME                      32: QCheckBox
        204     IMPORT_FROM                     33: QComboBox
        206     STORE_NAME                      33: QComboBox
        208     POP_TOP                         
        210     LOAD_CONST                      3: 0
        212     LOAD_CONST                      11: ('apply_prediction',)
        214     IMPORT_NAME                     34: ext_info
        216     IMPORT_FROM                     35: apply_prediction
        218     STORE_NAME                      35: apply_prediction
        220     POP_TOP                         
        222     LOAD_CONST                      3: 0
        224     LOAD_CONST                      12: ('settings_manager', 'PROMPT_TEMPLATE')
        226     IMPORT_NAME                     36: config
        228     IMPORT_FROM                     37: settings_manager
        230     STORE_NAME                      37: settings_manager
        232     IMPORT_FROM                     38: PROMPT_TEMPLATE
        234     STORE_NAME                      38: PROMPT_TEMPLATE
        236     POP_TOP                         
        238     LOAD_CONST                      3: 0
        240     LOAD_CONST                      13: ('send_feedback',)
        242     IMPORT_NAME                     39: feedback
        244     IMPORT_FROM                     40: send_feedback
        246     STORE_NAME                      40: send_feedback
        248     POP_TOP                         
        250     LOAD_CONST                      3: 0
        252     LOAD_CONST                      14: ('OpenAIModel',)
        254     IMPORT_NAME                     41: remote_model
        256     IMPORT_FROM                     42: OpenAIModel
        258     STORE_NAME                      42: OpenAIModel
        260     POP_TOP                         
        262     PUSH_NULL                       
        264     LOAD_BUILD_CLASS                
        266     LOAD_CONST                      15: <CODE> DecompilationViewPluginForm
        268     MAKE_FUNCTION                   0
        270     LOAD_CONST                      16: 'DecompilationViewPluginForm'
        272     LOAD_NAME                       7: ida_kernwin
        274     LOAD_ATTR                       86: PluginForm
        294     CALL                            3
        302     STORE_NAME                      44: DecompilationViewPluginForm
        304     LOAD_CONST                      17: <CODE> create_decompilation_view
        306     MAKE_FUNCTION                   0
        308     STORE_NAME                      45: create_decompilation_view
        310     PUSH_NULL                       
        312     LOAD_BUILD_CLASS                
        314     LOAD_CONST                      18: <CODE> EditablePredictionWidget
        316     MAKE_FUNCTION                   0
        318     LOAD_CONST                      19: 'EditablePredictionWidget'
        320     LOAD_NAME                       26: QWidget
        322     CALL                            3
        330     STORE_NAME                      46: EditablePredictionWidget
        332     PUSH_NULL                       
        334     LOAD_BUILD_CLASS                
        336     LOAD_CONST                      20: <CODE> NameTypeWidget
        338     MAKE_FUNCTION                   0
        340     LOAD_CONST                      21: 'NameTypeWidget'
        342     LOAD_NAME                       26: QWidget
        344     CALL                            3
        352     STORE_NAME                      47: NameTypeWidget
        354     PUSH_NULL                       
        356     LOAD_BUILD_CLASS                
        358     LOAD_CONST                      22: <CODE> StructFieldWidget
        360     MAKE_FUNCTION                   0
        362     LOAD_CONST                      23: 'StructFieldWidget'
        364     LOAD_NAME                       26: QWidget
        366     CALL                            3
        374     STORE_NAME                      48: StructFieldWidget
        376     PUSH_NULL                       
        378     LOAD_BUILD_CLASS                
        380     LOAD_CONST                      24: <CODE> EnumFieldWidget
        382     MAKE_FUNCTION                   0
        384     LOAD_CONST                      25: 'EnumFieldWidget'
        386     LOAD_NAME                       26: QWidget
        388     CALL                            3
        396     STORE_NAME                      49: EnumFieldWidget
        398     PUSH_NULL                       
        400     LOAD_BUILD_CLASS                
        402     LOAD_CONST                      26: <CODE> ComplexTypeWidget
        404     MAKE_FUNCTION                   0
        406     LOAD_CONST                      27: 'ComplexTypeWidget'
        408     LOAD_NAME                       26: QWidget
        410     CALL                            3
        418     STORE_NAME                      50: ComplexTypeWidget
        420     PUSH_NULL                       
        422     LOAD_BUILD_CLASS                
        424     LOAD_CONST                      28: <CODE> UserConfirmForm
        426     MAKE_FUNCTION                   0
        428     LOAD_CONST                      29: 'UserConfirmForm'
        430     LOAD_NAME                       7: ida_kernwin
        432     LOAD_ATTR                       86: PluginForm
        452     CALL                            3
        460     STORE_NAME                      51: UserConfirmForm
        462     LOAD_CONST                      30: <CODE> create_user_confirm_view
        464     MAKE_FUNCTION                   0
        466     STORE_NAME                      52: create_user_confirm_view
        468     PUSH_NULL                       
        470     LOAD_BUILD_CLASS                
        472     LOAD_CONST                      31: <CODE> UserConfirmFormForFuncName
        474     MAKE_FUNCTION                   0
        476     LOAD_CONST                      32: 'UserConfirmFormForFuncName'
        478     LOAD_NAME                       7: ida_kernwin
        480     LOAD_ATTR                       86: PluginForm
        500     CALL                            3
        508     STORE_NAME                      53: UserConfirmFormForFuncName
        510     LOAD_CONST                      33: <CODE> create_user_confirm_view_for_funcname
        512     MAKE_FUNCTION                   0
        514     STORE_NAME                      54: create_user_confirm_view_for_funcname
        516     PUSH_NULL                       
        518     LOAD_BUILD_CLASS                
        520     LOAD_CONST                      34: <CODE> VariableSelectionWidget
        522     MAKE_FUNCTION                   0
        524     LOAD_CONST                      35: 'VariableSelectionWidget'
        526     LOAD_NAME                       26: QWidget
        528     CALL                            3
        536     STORE_NAME                      55: VariableSelectionWidget
        538     PUSH_NULL                       
        540     LOAD_BUILD_CLASS                
        542     LOAD_CONST                      36: <CODE> VariableSelectionForm
        544     MAKE_FUNCTION                   0
        546     LOAD_CONST                      37: 'VariableSelectionForm'
        548     LOAD_NAME                       7: ida_kernwin
        550     LOAD_ATTR                       86: PluginForm
        570     CALL                            3
        578     STORE_NAME                      56: VariableSelectionForm
        580     LOAD_CONST                      38: <CODE> create_variable_selection_view
        582     MAKE_FUNCTION                   0
        584     STORE_NAME                      57: create_variable_selection_view
        586     PUSH_NULL                       
        588     LOAD_BUILD_CLASS                
        590     LOAD_CONST                      39: <CODE> ReCopilotSettingsDialog
        592     MAKE_FUNCTION                   0
        594     LOAD_CONST                      40: 'ReCopilotSettingsDialog'
        596     LOAD_NAME                       21: QDialog
        598     CALL                            3
        606     STORE_NAME                      58: ReCopilotSettingsDialog
        608     PUSH_NULL                       
        610     LOAD_BUILD_CLASS                
        612     LOAD_CONST                      41: <CODE> OutputWindowButton
        614     MAKE_FUNCTION                   0
        616     LOAD_CONST                      42: 'OutputWindowButton'
        618     LOAD_NAME                       26: QWidget
        620     CALL                            3
        628     STORE_NAME                      59: OutputWindowButton
        630     LOAD_CONST                      43: <CODE> add_cancel_button
        632     MAKE_FUNCTION                   0
        634     STORE_NAME                      60: add_cancel_button
        636     LOAD_CONST                      44: <CODE> remove_cancel_button
        638     MAKE_FUNCTION                   0
        640     STORE_NAME                      61: remove_cancel_button
        642     LOAD_CONST                      4: None
        644     NOP                             
        646     NOP                             
        648     NOP                             
        650     JUMP_FORWARD                    19 (to 690)
        658     POP_TOP                         
        660     RETURN_CONST                    4: None
        662     PUSH_EXC_INFO                   
        664     PUSH_NULL                       
        666     LOAD_CONST                      45: '__pyarmor_exit_54480__'
        668     NOP                             
        670     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a|\x02\x00\x00\x00\x00\x00\x00'
        672     CALL                            1
        680     POP_TOP                         
        682     RERAISE                         0
        684     COPY                            3
        686     POP_EXCEPT                      
        688     RERAISE                         1
        690     PUSH_NULL                       
        692     LOAD_CONST                      45: '__pyarmor_exit_54480__'
        694     LOAD_CONST                      2: b'<COAddr>\x03\x00\x00\x1a|\x02\x00\x00\x00\x00\x00\x00'
        696     BUILD_TUPLE                     1
        698     CALL_FUNCTION_EX                0
        700     POP_TOP                         
        702     RETURN_VALUE                    
