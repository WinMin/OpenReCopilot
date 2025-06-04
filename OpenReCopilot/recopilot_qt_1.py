# Imports (推断自 [Names])
import idc
import idaapi
import ida_funcs
import ida_hexrays
import ida_name
import ida_bytes
import ida_kernwin
import traceback # (推断自 create_decompilation_view 常量)

from pygments import highlight
from pygments.lexers import CppLexer
from pygments.token import Token
from pygments.formatters import HtmlFormatter

from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QWidget,
    QLineEdit, QGroupBox, QGridLayout, QMessageBox, QSpinBox, QCheckBox,
    QComboBox, QTextEdit # QTextEdit 推断自 EditablePredictionWidget.__init__
)

# 自定义模块导入 (推断)
# from . import ext_info # (假设在同一目录下)
# from . import config
# from . import feedback
# from . import remote_model

# --- 全局常量 (推断自 config) ---
# PROMPT_TEMPLATE = ... (来自 config 模块)
# settings_manager = ... (来自 config 模块)


# --- 类定义 ---

class DecompilationViewPluginForm(ida_kernwin.PluginForm):
    def __init__(self, title, content):
        # __pyarmor_enter_...
        super(DecompilationViewPluginForm, self).__init__()
        self.title = title
        self.initial_content = content
        self.parent_widget = None
        self.code_browser = None

        existing_widget = ida_kernwin.find_widget(title)
        if existing_widget:
            print(f"[*] Found existing widget with title '{title}'. Closing it before recreating.")
            ida_kernwin.close_widget(existing_widget, 0)
        # __pyarmor_exit_...

    def OnCreate(self, form):
        # __pyarmor_enter_...
        self.parent_widget = self.FormToPyQtWidget(form)
        layout = QtWidgets.QVBoxLayout()
        self.code_browser = QtWidgets.QTextBrowser() # 或自定义的 EditablePredictionWidget
        self.code_browser.setOpenExternalLinks(False) # 常量 4: False
        self.code_browser.setFontFamily("Consolas") # 常量 5: 'Consolas'
        self.code_browser.setStyleSheet("font-size: 12px;") # 常量 6: 'font-size: 12px;'
        layout.addWidget(self.code_browser)
        self.parent_widget.setLayout(layout)
        if self.initial_content:
            self.set_content(self.initial_content)
        # __pyarmor_exit_...
        return self.parent_widget # 推断，通常 OnCreate 返回创建的 widget

    def set_content(self, code):
        # __pyarmor_enter_...
        if self.code_browser:
            lexer = CppLexer() # 全局名称 CppLexer
            formatter = HtmlFormatter(style='vs', noclasses=True) # 全局名称 HtmlFormatter, 常量 'vs', True
            html_code = highlight(code, lexer, formatter) # 全局名称 highlight
            self.code_browser.setHtml(html_code)
        # __pyarmor_exit_...

    def OnClose(self, form):
        # __pyarmor_enter_...
        # 清理操作
        # __pyarmor_exit_...
        pass

    def Show(self):
        # __pyarmor_enter_...
        options = (ida_kernwin.PluginForm.WOPN_TAB |
                   ida_kernwin.PluginForm.WOPN_PERSIST |
                   ida_kernwin.PluginForm.WOPN_RESTORE)
        super(DecompilationViewPluginForm, self).Show(self.title, options=options)
        # __pyarmor_exit_...
        return # Show 通常不返回重要内容，或者返回成功/失败状态

def create_decompilation_view(ea, content):
    """
    在IDA主线程中创建反编译视图 (使用PluginForm)
    Args:
        ea: func addr
        content: view content
    Returns:
        bool: True if success, False otherwise
    """
    # __pyarmor_enter_...
    print("[*] Try to create ReCopilot decompilation view using PluginForm")
    func_name = idc.get_func_name(ea)
    title = f"ReCopilot Decompilation - {func_name}" # 常量 'ReCopilot Decompilation - '
    try:
        form_instance = DecompilationViewPluginForm(title, content)
        form_instance.Show()
        if ida_kernwin.find_widget(title):
            print(f"[+] Successfully created/shown decompilation view with PluginForm, title: {title}")
            return True
        else:
            print(f"[!] Failed to verify creation/showing of decompilation view with PluginForm, title: {title}.")
            return False
    except Exception as e:
        print(f"[!] Error creating decompilation view with PluginForm: {str(e)}")
        traceback.print_exc() # 推断，常见错误处理
        return False
    # __pyarmor_exit_...


class EditablePredictionWidget(QWidget): # 基类是 QWidget
    def __init__(self, title='', content='', is_multiline=False, line_count=None, force_single_line=False, parent=None): # 参数推断
        # __pyarmor_enter_...
        super(EditablePredictionWidget, self).__init__(parent) # 假设 parent 传递给 super
        self.accepted = True
        # ... UI 初始化代码，包括 QGroupBox, QVBoxLayout, QHBoxLayout, QCheckBox, QTextEdit/QLineEdit
        # self.checkbox = QCheckBox()
        # self.checkbox.setCheckState(QtCore.Qt.Checked)
        # self.checkbox.stateChanged.connect(self.accepted_state_change)
        # if is_multiline and not force_single_line (or similar logic):
        # self.content_edit = QTextEdit()
        # self.content_edit.setMinimumWidth(500)
        # if line_count:
        # self.content_edit.setMinimumHeight(min(20 * line_count + 10, 300))
        # else:
        # self.content_edit.setMinimumHeight(100)
        # else:
        # self.content_edit = QLineEdit()
        # self.content_edit.setMinimumWidth(500)
        # self.content_edit.setText(content)
        # ...
        # __pyarmor_exit_...

    def accepted_state_change(self, state):
        # __pyarmor_enter_...
        self.accepted = (state == QtCore.Qt.Checked)
        self.content_edit.setEnabled(self.accepted)
        # __pyarmor_exit_...

    def get_content(self):
        # __pyarmor_enter_...
        if isinstance(self.content_edit, QtWidgets.QTextEdit): # 推断
            return self.content_edit.toPlainText()
        else: # QLineEdit
            return self.content_edit.text()
        # __pyarmor_exit_...

# ... 类似地，可以为 NameTypeWidget, StructFieldWidget, EnumFieldWidget, ComplexTypeWidget, UserConfirmForm, UserConfirmFormForFuncName, VariableSelectionWidget, VariableSelectionForm, ReCopilotSettingsDialog, OutputWindowButton 勾勒出大致结构。

# 例如 UserConfirmForm.PopulateForm
class UserConfirmForm(ida_kernwin.PluginForm):
    # ... __init__ 等 ...
    def PopulateForm(self):
        # __pyarmor_enter_...
        main_layout = QtWidgets.QVBoxLayout(self.parent) # self.parent 是 OnCreate 中设置的
        # ...
        # 根据 self.response 中的键（如 'funcname', 'ret_type', 'args', 'vars', 'brief', 'details', etc.）
        # 动态创建 EditablePredictionWidget 或 ComplexTypeWidget
        # 并将它们添加到 main_layout 或嵌套的 QGroupBox 中。

        # Example for 'funcname':
        if 'funcname' in self.response:
            # current_func_name = idc.get_func_name(self.ea) # 假设 ea 在 self 中
            # title = f"Function Name (Current: {current_func_name})"
            # widget = EditablePredictionWidget(title, self.response['funcname'])
            # self.widgets['funcname'] = widget
            # main_layout.addWidget(widget)

        # Example for complex types like 'args' or 'vars':
        if 'args' in self.response and isinstance(self.response['args'], dict):
            # args_group = QtWidgets.QGroupBox("Function Arguments")
            # args_layout = QtWidgets.QVBoxLayout()
            # self.widgets['args'] = {}
            # for arg_name, arg_info in self.response['args'].items():
            #     widget = ComplexTypeWidget(arg_name, arg_info) # ComplexTypeWidget处理更复杂的嵌套结构
            #     self.widgets['args'][arg_name] = widget
            #     args_layout.addWidget(widget)
            # args_group.setLayout(args_layout)
            # main_layout.addWidget(args_group)
            pass

        # ... 其他字段 ...

        # Buttons
        # buttons_layout = QtWidgets.QHBoxLayout()
        # accept_button = QtWidgets.QPushButton("Accept Selected")
        # accept_button.clicked.connect(self.on_accept_clicked)
        # cancel_button = QtWidgets.QPushButton("Cancel")
        # cancel_button.clicked.connect(self.on_cancel_clicked)
        # buttons_layout.addWidget(accept_button)
        # buttons_layout.addWidget(cancel_button)
        # main_layout.addLayout(buttons_layout)

        # Scroll Area (可能)
        # scroll_content_widget = QtWidgets.QWidget()
        # scroll_content_widget.setLayout(main_layout)
        # scroll_area = QtWidgets.QScrollArea()
        # scroll_area.setWidgetResizable(True)
        # scroll_area.setWidget(scroll_content_widget)
        #
        # final_layout = QtWidgets.QVBoxLayout(self.parent) # self.parent 是IDA的form widget
        # final_layout.addWidget(scroll_area)
        # self.parent.setLayout(final_layout)
        # __pyarmor_exit_...
        pass

    def on_accept_clicked(self):
        # __pyarmor_enter_...
        # is_valid, error_msg = self.validate_fields()
        # if not is_valid:
        # QtWidgets.QMessageBox.warning(self.parent, "Validation Error", error_msg + "\nPlease fill in all selected fields...")
        # return

        # processed_response = {}
        # for key, widget_info in self.widgets.items():
        # if isinstance(widget_info, dict): # For 'args', 'vars' etc.
        # processed_response[key] = {}
        # for sub_key, sub_widget in widget_info.items():
        # if sub_widget.accepted:
        # processed_response[key][sub_key] = sub_widget.get_type_info() # or get_content()
        # else: # Single widget
        # if widget_info.accepted:
        # processed_response[key] = widget_info.get_content()

        # if settings_manager.settings['feedback']:
        #     send_feedback(self.prompt, self.response_raw, processed_response, self.task_tag)

        # apply_prediction(self.ea, self.task_tag, processed_response)
        # self.Close(0)
        # __pyarmor_exit_...
        pass

# ... etc. ...

class OutputWindowButton(QtWidgets.QWidget):
    def __init__(self, model: OpenAIModel, parent=None): # OpenAIModel 是类型提示
        # __pyarmor_enter_...
        super(OutputWindowButton, self).__init__(parent)
        self.model = model
        self.setFixedHeight(30)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(5, 0, 15, 0)
        layout.setSpacing(5)
        layout.addStretch()
        self.button = QtWidgets.QPushButton("Cancel Analysis", self)
        self.button.setStyleSheet("...") # CSS from constants
        self.button.clicked.connect(self.on_cancel_clicked)
        layout.addWidget(self.button)
        # __pyarmor_exit_...

    def on_cancel_clicked(self):
        # __pyarmor_enter_...
        if self.model:
            self.model.cancel()
        self.hide()
        # __pyarmor_exit_...

# 全局变量 cancel_button_instance (可能)
# cancel_button_instance = None

def add_cancel_button(model: OpenAIModel):
    # __pyarmor_enter_...
    # global cancel_button_instance
    output_window_form = ida_kernwin.find_widget("Output window")
    if not output_window_form:
        return None # Or False

    output_window_widget = ida_kernwin.PluginForm.FormToPyQtWidget(output_window_form)
    if not output_window_widget:
        return None

    # cancel_button_instance = OutputWindowButton(model, output_window_widget)
    # output_layout = output_window_widget.layout()
    # if output_layout:
    #     output_layout.addWidget(cancel_button_instance)
    #     cancel_button_instance.show()
    # return cancel_button_instance
    # __pyarmor_exit_...
    pass


def remove_cancel_button(button_widget): # button_widget is the instance from add_cancel_button
    # __pyarmor_enter_...
    # if button_widget:
    #     button_widget.hide()
    #     button_widget.deleteLater()
    # __pyarmor_exit_...
    pass