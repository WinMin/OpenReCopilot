import idc
import idaapi
import ida_funcs
import ida_hexrays
import ida_name
import ida_bytes
import ida_kernwin
from pygments import highlight
from pygments.lexers import CppLexer
from pygments.token import Token
from pygments.formatters import HtmlFormatter
from PyQt5 import QtWidgets, QtCore, QtGui
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QWidget, QLineEdit,
    QGroupBox, QGridLayout, QMessageBox, QSpinBox, QCheckBox, QComboBox
)
from ext_info import apply_prediction
from config import settings_manager, PROMPT_TEMPLATE
from remote_model import OpenAIModel

def create_variable_selection_view(ea):
    """Creates a variable selection view."""
    try:
        f = idaapi.get_func(ea)
        if not f:
            print("[!] No function found at this address")
            return None

        df = ida_hexrays.decompile(f)
        if not df:
            print("[!] Failed to decompile function")
            return None

        args = []
        vars = []
        for var in df.lvars:
            if var.is_arg_var:
                args.append(var.name)
            else:
                vars.append(var.name)

        form = VariableSelectionForm(ea, args, vars)
        form.Show(form.title)
        return form
    except Exception as e:
        print(f"Error creating variable selection view: {e}")
        return None
class DecompilationViewPluginForm(ida_kernwin.PluginForm):
    def __init__(self, title, initial_content):
        super(DecompilationViewPluginForm, self).__init__()
        self.title = title
        self.initial_content = initial_content
        self.parent_widget = None
        self.code_browser = None

        # Check and close existing widget if it exists
        existing_widget = ida_kernwin.find_widget(title)
        if existing_widget:
            print(f"[*] Found existing widget with title '{title}'. Closing it before recreating.")
            ida_kernwin.close_widget(existing_widget, 0)

    def OnCreate(self, form):
        self.parent_widget = self.FormToPyQtWidget(form)
        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        self.code_browser = QtWidgets.QTextBrowser()
        self.code_browser.setOpenExternalLinks(False)
        self.code_browser.setFontFamily('Consolas')
        self.code_browser.setStyleSheet('font-size: 12px;')
        layout.addWidget(self.code_browser)
        self.parent_widget.setLayout(layout)

        if self.initial_content:
            self.set_content(self.initial_content)

    def set_content(self, code):
        if self.code_browser:
            lexer = CppLexer()
            formatter = HtmlFormatter(style='vs', noclasses=True)
            highlighted_code = highlight(code, lexer, formatter)
            self.code_browser.setHtml(highlighted_code)

    def OnClose(self, form):
        pass

    def Show(self):
        super(DecompilationViewPluginForm, self).Show(
            self.title,
            options=ida_kernwin.PluginForm.WOPN_TAB | ida_kernwin.PluginForm.WOPN_PERSIST | ida_kernwin.PluginForm.WOPN_RESTORE
        )


def create_decompilation_view(ea, task_tag, prompt, response_raw, response):
    """
    在IDA主线程中创建反编译视图 (使用PluginForm)

    Args:
        ea: func addr
        task_tag: task tag (unused but kept for consistent signature)
        prompt: prompt for feedback (unused but kept for consistent signature)
        response_raw: raw response (unused but kept for consistent signature)
        response: processed response - the decompiled code content

    Returns:
        bool: True if success, False otherwise
    """
    print('[*] Try to create ReCopilot decompilation view using PluginForm')
    func_name = idc.get_func_name(ea)
    title = f'ReCopilot Decompilation - {func_name}'
    # 对于反编译视图，使用 response 作为内容（已解析的响应）
    content = response if response else response_raw
    try:
        form = DecompilationViewPluginForm(title, content)
        form.Show()  # Show() already uses self.title internally
        if ida_kernwin.find_widget(title):
            print(f'[+] Successfully created/shown decompilation view with PluginForm, title: {title}')
            return True
        else:
            print(f'[!] Failed to verify creation/showing of decompilation view with PluginForm, title: {title}.')
            return False
    except Exception as e:
        print(f'[!] Error creating decompilation view with PluginForm: {str(e)}')
        import traceback
        traceback.print_exc(0)
        return False


class EditablePredictionWidget(QWidget):
    def __init__(self, title, content="", is_multiline=False, line_count=None, force_single_line=False):
        super(EditablePredictionWidget, self).__init__()
        self.accepted = True
        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        group_box = QGroupBox(title)
        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setSpacing(10)

        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)
        
        if force_single_line or ('\n' not in content and not force_single_line):
            self.is_multiline = False
            self.line_count = 1
        else:
            self.is_multiline = is_multiline
            self.line_count = line_count

        if self.is_multiline:
            self.content_edit = QtWidgets.QTextEdit()
            self.content_edit.setMinimumWidth(500)
            if self.line_count:
                self.content_edit.setMinimumHeight(min(20 * self.line_count + 10, 300))
            else:
                self.content_edit.setMinimumHeight(100)
        else:
            self.content_edit = QLineEdit()
            self.content_edit.setMinimumWidth(500)

        self.content_edit.setText(content)
        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.content_edit)
        group_box.setLayout(h_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.content_edit.setEnabled(self.accepted)

    def get_content(self):
        if isinstance(self.content_edit, QtWidgets.QTextEdit):
            return self.content_edit.toPlainText()
        else:
            return self.content_edit.text()


class NameTypeWidget(QWidget):
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)

    def __init__(self, title="", name="", type_str="", size="", is_enum=False):
        super(NameTypeWidget, self).__init__()
        self.accepted = True
        self.accepted_name = True
        self.accepted_type = True
        self.accepted_size = True
        self.is_enum = is_enum

        layout = QVBoxLayout()
        layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        group_box = QGroupBox(title)
        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setSpacing(10)

        # Name field
        name_layout = QHBoxLayout()
        self.name_checkbox = QCheckBox('Name')
        self.name_checkbox.setCheckState(QtCore.Qt.Checked)
        self.name_checkbox.stateChanged.connect(self.name_state_change)
        self.name_edit = QLineEdit(name)
        self.name_edit.setMinimumWidth(200)
        name_layout.addWidget(self.name_checkbox)
        name_layout.addWidget(self.name_edit)

        # Type field
        type_layout = QHBoxLayout()
        self.type_checkbox = QCheckBox('Value' if is_enum else 'Type')
        self.type_checkbox.setCheckState(QtCore.Qt.Checked)
        self.type_checkbox.stateChanged.connect(self.type_state_change)
        self.type_edit = QLineEdit(type_str)
        self.type_edit.setMinimumWidth(200)
        type_layout.addWidget(self.type_checkbox)
        type_layout.addWidget(self.type_edit)

        # Size field (only for enum members and struct fields)
        if is_enum:
            size_layout = QHBoxLayout()
            self.size_checkbox = QCheckBox('Size')
            self.size_checkbox.setCheckState(QtCore.Qt.Checked)
            self.size_checkbox.stateChanged.connect(self.size_state_change)
            self.size_edit = QLineEdit(str(size))
            self.size_edit.setMinimumWidth(80)
            size_layout.addWidget(self.size_checkbox)
            size_layout.addWidget(self.size_edit)

            h_layout.addLayout(size_layout)

        # Add/Remove buttons for enum and struct fields
        if is_enum:
            add_button = QPushButton('+')
            add_button.setMaximumWidth(30)
            add_button.clicked.connect(self.on_add_clicked)
            remove_button = QPushButton('-')
            remove_button.setMaximumWidth(30)
            remove_button.clicked.connect(self.on_remove_clicked)
            h_layout.addWidget(add_button)
            h_layout.addWidget(remove_button)

        h_layout.addStretch() # Push widgets to the left
        group_box.setLayout(h_layout)
        layout.addWidget(group_box)
        self.setLayout(layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.name_checkbox.setEnabled(self.accepted)
        self.type_checkbox.setEnabled(self.accepted)
        self.name_edit.setEnabled(self.accepted and self.accepted_name)
        self.type_edit.setEnabled(self.accepted and self.accepted_type)
        if self.is_enum:
            self.size_checkbox.setEnabled(self.accepted)
            self.size_edit.setEnabled(self.accepted and self.accepted_size)
            self.add_button.setEnabled(self.accepted)
            self.remove_button.setEnabled(self.accepted)

    def name_state_change(self, state):
        self.accepted_name = (state == QtCore.Qt.Checked)
        self.name_edit.setEnabled(self.accepted and self.accepted_name)

    def type_state_change(self, state):
        self.accepted_type = (state == QtCore.Qt.Checked)
        self.type_edit.setEnabled(self.accepted and self.accepted_type)

    def size_state_change(self, state):
        self.accepted_size = (state == QtCore.Qt.Checked)
        self.size_edit.setEnabled(self.accepted and self.accepted_size)

    def get_content(self):
        # Returns a list: [name, type_str, size] for enum fields, or [name, type_str] for others
        size_val = None
        if self.is_enum:
            if self.accepted and self.accepted_size:
                try:
                    size_val = int(self.size_edit.text())
                except ValueError:
                    size_val = None # Handle invalid integer input
        
        name_val = self.name_edit.text().strip() if self.accepted and self.accepted_name else None
        type_val = self.type_edit.text().strip() if self.accepted and self.accepted_type else None

        if self.is_enum:
            return [name_val, type_val, size_val]
        else:
            return [name_val, type_val]


    def validate(self):
        if not self.accepted:
            return True # If not accepted, validation passes as it's not applied

        if self.accepted_name and not self.name_edit.text().strip():
            return False
        if self.accepted_type and not self.type_edit.text().strip():
            return False
        if self.is_enum and self.accepted_size:
            try:
                size_val = int(self.size_edit.text().strip())
                if size_val <= 0:
                    return False
            except ValueError:
                return False
        return True

    def on_add_clicked(self):
        self.field_added.emit()

    def on_remove_clicked(self):
        self.field_removed.emit(self) # Emit the widget itself for removal

def create_user_confirm_view_for_funcname(ea, task_tag, prompt, response_raw, response):
    form = UserConfirmFormForFuncName(ea, task_tag, prompt, response_raw, response)
    title = f'ReCopilot - Function Name Analysis - {hex(ea)}'
    form.Show(title)
    return True

def create_user_confirm_view(ea, task_tag, prompt, response_raw, response):
    form = UserConfirmForm(ea, task_tag, prompt, response_raw, response)
    title = f'ReCopilot - {task_tag} - {hex(ea)}'
    form.Show(title)
    return True
class StructFieldWidget(NameTypeWidget):
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)

    def __init__(self, type_str="", name="", size="", parent=None):
        super(StructFieldWidget, self).__init__("Struct Field", name, type_str, size, parent=parent)
        self.accepted = True

        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(5)

        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)

        self.type_edit = QLineEdit(type_str)
        self.type_edit.setMinimumWidth(150)
        self.type_edit.setPlaceholderText('Type')

        self.name_edit = QLineEdit(name)
        self.name_edit.setMinimumWidth(150)
        self.name_edit.setPlaceholderText('Name')

        self.size_edit = QLineEdit(str(size))
        self.size_edit.setMinimumWidth(80)
        self.size_edit.setPlaceholderText('Size')

        add_button = QPushButton('+')
        add_button.setMaximumWidth(30)
        add_button.clicked.connect(self.on_add_clicked)
        remove_button = QPushButton('-')
        remove_button.setMaximumWidth(30)
        remove_button.clicked.connect(self.on_remove_clicked)

        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.type_edit)
        h_layout.addWidget(self.name_edit)
        h_layout.addWidget(self.size_edit)
        h_layout.addWidget(add_button)
        h_layout.addWidget(remove_button)
        h_layout.addStretch()
        self.setLayout(h_layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.type_edit.setEnabled(self.accepted)
        self.name_edit.setEnabled(self.accepted)
        self.size_edit.setEnabled(self.accepted)
        self.add_button.setEnabled(self.accepted)
        self.remove_button.setEnabled(self.accepted)

    def get_content(self):
        if not self.accepted:
            return None
        type_val = self.type_edit.text().strip()
        name_val = self.name_edit.text().strip()
        try:
            size_val = int(self.size_edit.text().strip())
        except ValueError:
            size_val = None # Handle invalid integer input
        return [type_val, name_val, size_val]

    def validate(self):
        if not self.accepted:
            return True
        if not self.type_edit.text().strip():
            return False
        if not self.name_edit.text().strip():
            return False
        try:
            size_val = int(self.size_edit.text().strip())
            if size_val <= 0:
                return False
        except ValueError:
            return False
        return True

    def on_add_clicked(self):
        self.field_added.emit()

    def on_remove_clicked(self):
        self.field_removed.emit(self)


class EnumFieldWidget(NameTypeWidget):
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)

    def __init__(self, name="", value="", size="", parent=None):
        super(EnumFieldWidget, self).__init__("Enum Field", name, value, size, parent=parent)
        self.accepted = True

        h_layout = QHBoxLayout()
        h_layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(5)

        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)

        self.name_edit = QLineEdit(name)
        self.name_edit.setMinimumWidth(200)
        self.name_edit.setPlaceholderText('Name')

        self.value_edit = QLineEdit(str(value))
        self.value_edit.setMinimumWidth(200)
        self.value_edit.setPlaceholderText('Value')

        self.size_edit = QLineEdit(str(size))
        self.size_edit.setMinimumWidth(80)
        self.size_edit.setPlaceholderText('Size')

        add_button = QPushButton('+')
        add_button.setMaximumWidth(30)
        add_button.clicked.connect(self.on_add_clicked)
        remove_button = QPushButton('-')
        remove_button.setMaximumWidth(30)
        remove_button.clicked.connect(self.on_remove_clicked)

        h_layout.addWidget(self.checkbox)
        h_layout.addWidget(self.name_edit)
        h_layout.addWidget(self.value_edit)
        h_layout.addWidget(self.size_edit)
        h_layout.addWidget(add_button)
        h_layout.addWidget(remove_button)
        h_layout.addStretch()
        self.setLayout(h_layout)

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.name_edit.setEnabled(self.accepted)
        self.value_edit.setEnabled(self.accepted)
        self.size_edit.setEnabled(self.accepted)
        self.add_button.setEnabled(self.accepted)
        self.remove_button.setEnabled(self.accepted)

    def get_content(self):
        if not self.accepted:
            return None
        size_val = 4 # Default size if not provided or invalid
        if self.size_edit.text().strip():
            try:
                size_val = int(self.size_edit.text().strip())
            except ValueError:
                pass # Keep default size_val if parsing fails
        
        name_val = self.name_edit.text().strip()
        value_val = self.value_edit.text().strip()
        if value_val.isdigit(): # Check if value is a valid integer string
            value_val = int(value_val)

        return [name_val, value_val, size_val]

    def validate(self):
        if not self.accepted:
            return True
        if not self.name_edit.text().strip():
            return False
        if not self.value_edit.text().strip():
            return False
        try:
            if self.size_edit.text().strip():
                size_val = int(self.size_edit.text().strip())
                if size_val <= 0:
                    return False
        except ValueError:
            return False
        return True

    def on_add_clicked(self):
        self.field_added.emit()

    def on_remove_clicked(self):
        self.field_removed.emit(self)


class ComplexTypeWidget(QWidget):
    def __init__(self, title, type_info=None, parent=None):
        super(ComplexTypeWidget, self).__init__(parent)
        self.accepted = True
        self.type_info = type_info if type_info is not None else ["", "", "", []]
        self.field_widgets = []

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        group_box = QGroupBox(title, self)
        group_box_layout = QVBoxLayout(group_box)

        # Main name and type fields
        name_type_layout = QHBoxLayout()
        self.checkbox = QCheckBox()
        self.checkbox.setCheckState(QtCore.Qt.Checked)
        self.checkbox.stateChanged.connect(self.accepted_state_change)
        name_type_layout.addWidget(self.checkbox)
        
        self.name_type_widget = NameTypeWidget(
            "",
            self.type_info[1], # Name
            self.type_info[0], # Type string
            "", # Size (not directly used here for type declaration itself)
            is_enum=(self.type_info[2] == "enum")
        )
        name_type_layout.addWidget(self.name_type_widget)
        group_box_layout.addLayout(name_type_layout)

        # Fields section for structs and enums
        if self.type_info[2] == "struct":
            fields_group = QGroupBox("Struct Fields")
            self.fields_layout = QVBoxLayout(fields_group)
            
            # Struct name edit
            struct_name_layout = QHBoxLayout()
            struct_name_layout.addWidget(QLabel("Struct Name:"))
            struct_name_value = self.type_info[3].keys()[0] if self.type_info[3] else ""
            self.struct_name_edit = QLineEdit(struct_name_value.replace(" *", "").strip())
            struct_name_layout.addWidget(self.struct_name_edit)
            self.fields_layout.addLayout(struct_name_layout)

            # Add existing struct fields
            if isinstance(self.type_info[3], dict) and self.type_info[3].get(struct_name_value):
                for field_type, field_name, field_size in self.type_info[3][struct_name_value]:
                    self.add_struct_field(field_type, field_name, field_size)

        elif self.type_info[2] == "enum":
            fields_group = QGroupBox("Enum Fields")
            self.fields_layout = QVBoxLayout(fields_group)

            # Enum name edit
            enum_name_layout = QHBoxLayout()
            enum_name_layout.addWidget(QLabel("Enum Name:"))
            enum_name_value = list(self.type_info[3].keys())[0] if self.type_info[3] else ""
            self.enum_name_edit = QLineEdit(enum_name_value.strip())
            enum_name_layout.addWidget(self.enum_name_edit)
            self.fields_layout.addLayout(enum_name_layout)

            # Add existing enum fields
            if isinstance(self.type_info[3], dict) and self.type_info[3].get(enum_name_value):
                for member_name, member_value, member_size in self.type_info[3][enum_name_value]:
                    self.add_enum_field(member_name, member_value, member_size)
            else:
                self.add_enum_field() # Add at least one empty field if none exist

        elif self.type_info[2] == "array":
            fields_group = QGroupBox("Array Dimensions")
            self.fields_layout = QHBoxLayout(fields_group)
            
            # Array dimensions edit
            dimensions_str = ",".join(map(str, self.type_info[3] if self.type_info[3] else []))
            self.array_edit = QLineEdit(dimensions_str)
            self.array_edit.setPlaceholderText('Enter dimensions separated by commas')
            self.fields_layout.addWidget(self.array_edit)

        group_box_layout.addWidget(fields_group)
        main_layout.addWidget(group_box)
        self.setLayout(main_layout)

    def add_struct_field(self, type_str="", name="", size="", after_widget=None):
        widget = StructFieldWidget(type_str=type_str, name=name, size=size)
        widget.field_added.connect(self._create_add_struct_callback(widget))
        widget.field_removed.connect(self.remove_struct_field)
        
        if after_widget:
            idx = self.field_widgets.index(after_widget) + 1
            self.field_widgets.insert(idx, widget)
            self.fields_layout.insertWidget(idx + 1, widget) # +1 to account for the QGroupBox
        else:
            self.field_widgets.append(widget)
            self.fields_layout.addWidget(widget)

    def add_enum_field(self, name="", value="", size="", after_widget=None):
        widget = EnumFieldWidget(name=name, value=value, size=size)
        widget.field_added.connect(self._create_add_enum_callback(widget))
        widget.field_removed.connect(self.remove_enum_field)

        if after_widget:
            idx = self.field_widgets.index(after_widget) + 1
            self.field_widgets.insert(idx, widget)
            self.fields_layout.insertWidget(idx + 1, widget)
        else:
            self.field_widgets.append(widget)
            self.fields_layout.addWidget(widget)

    def remove_struct_field(self, widget):
        if len(self.field_widgets) > 1: # Don't remove the last field
            self.fields_layout.removeWidget(widget)
            self.field_widgets.remove(widget)
            widget.deleteLater()

    def remove_enum_field(self, widget):
        if len(self.field_widgets) > 1: # Don't remove the last field
            self.fields_layout.removeWidget(widget)
            self.field_widgets.remove(widget)
            widget.deleteLater()

    def validate(self):
        if not self.accepted:
            return True
        if not self.name_type_widget.validate():
            return False
        
        # Validate fields based on type
        if self.type_info[2] == "struct" or self.type_info[2] == "enum":
            for field_widget in self.field_widgets:
                if not field_widget.validate():
                    return False
        elif self.type_info[2] == "array":
            try:
                dimensions = [int(d.strip()) for d in self.array_edit.text().split(',') if d.strip()]
                for dim in dimensions:
                    if dim <= 0:
                        return False
            except ValueError:
                return False
        return True

    def accepted_state_change(self, state):
        self.accepted = (state == QtCore.Qt.Checked)
        self.name_type_widget.setEnabled(self.accepted)
        for field_widget in self.field_widgets:
            field_widget.setEnabled(self.accepted)
        if hasattr(self, 'array_edit'):
            self.array_edit.setEnabled(self.accepted)
        if hasattr(self, 'struct_name_edit'):
            self.struct_name_edit.setEnabled(self.accepted)
        if hasattr(self, 'enum_name_edit'):
            self.enum_name_edit.setEnabled(self.accepted)


    def get_type_info(self):
        if not self.accepted:
            return None # If not accepted, return None or an empty dict based on needs

        # Get data from NameTypeWidget
        name, type_str = self.name_type_widget.get_content()
        type_data = None
        if self.type_info[2] == "struct":
            struct_name = self.struct_name_edit.text().strip()
            type_data = {struct_name: [fw.get_content() for fw in self.field_widgets if fw.get_content() is not None]}
        elif self.type_info[2] == "enum":
            enum_name = self.enum_name_edit.text().strip()
            type_data = {enum_name: [fw.get_content() for fw in self.field_widgets if fw.get_content() is not None]}
        elif self.type_info[2] == "array":
            try:
                type_data = [int(d.strip()) for d in self.array_edit.text().split(',') if d.strip()]
            except ValueError:
                type_data = None # Or handle error appropriately
        
        return [type_str, name, self.type_info[2], type_data]

    def _create_add_enum_callback(self, widget):
        """Create a callback function for adding an enum field after the specified widget"""
        def callback():
            self.add_enum_field(after_widget=widget)
        return callback

    def _create_add_struct_callback(self, widget):
        """Create a callback function for adding a struct field after the specified widget"""
        def callback():
            self.add_struct_field(after_widget=widget)
        return callback


class UserConfirmForm(ida_kernwin.PluginForm):
    def __init__(self, ea, task_tag, prompt, response_raw, response):
        super(UserConfirmForm, self).__init__()
        self.ea = ea
        self.task_tag = task_tag
        self.prompt = prompt
        self.response_raw = response_raw
        self.response = response
        self.widgets = {}

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        main_layout = QVBoxLayout()
        main_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        # Function Name
        if 'funcname' in self.response:
            func_name_widget = EditablePredictionWidget('Function Name', self.response['funcname'])
            self.widgets['funcname'] = func_name_widget
            main_layout.addWidget(func_name_widget)

        # Return Type
        if 'ret_type' in self.response:
            ret_type_widget = EditablePredictionWidget('Return Type', self.response['ret_type'])
            self.widgets['ret_type'] = ret_type_widget
            main_layout.addWidget(ret_type_widget)

        # Function Arguments
        if 'args' in self.response and self.response['args']:
            args_group = QGroupBox('Function Arguments')
            args_layout = QVBoxLayout(args_group)
            self.widgets['args'] = {}
            args_data = self.response['args']
            # Handle both dict and list formats
            if isinstance(args_data, dict):
                for arg_name, arg_type in args_data.items():
                    arg_widget = ComplexTypeWidget(arg_name, arg_type)
                    self.widgets['args'][arg_name] = arg_widget
                    args_layout.addWidget(arg_widget)
            elif isinstance(args_data, list):
                for item in args_data:
                    if isinstance(item, dict):
                        # Format: {'original': [...], 'prediction': [...]}
                        arg_name = item.get('original', ['', ''])[1] if isinstance(item.get('original'), list) else str(item.get('original', ''))
                        arg_type = item.get('prediction', [])
                        arg_widget = ComplexTypeWidget(arg_name, arg_type)
                        self.widgets['args'][arg_name] = arg_widget
                        args_layout.addWidget(arg_widget)
            args_group.setLayout(args_layout)
            main_layout.addWidget(args_group)

        # Local Variables
        if 'vars' in self.response and self.response['vars']:
            vars_group = QGroupBox('Local Variables')
            vars_layout = QVBoxLayout(vars_group)
            self.widgets['vars'] = {}
            vars_data = self.response['vars']
            # Handle both dict and list formats
            if isinstance(vars_data, dict):
                for var_name, var_type in vars_data.items():
                    var_widget = ComplexTypeWidget(var_name, var_type)
                    self.widgets['vars'][var_name] = var_widget
                    vars_layout.addWidget(var_widget)
            elif isinstance(vars_data, list):
                for item in vars_data:
                    if isinstance(item, dict):
                        var_name = item.get('original', ['', ''])[1] if isinstance(item.get('original'), list) else str(item.get('original', ''))
                        var_type = item.get('prediction', [])
                        var_widget = ComplexTypeWidget(var_name, var_type)
                        self.widgets['vars'][var_name] = var_widget
                        vars_layout.addWidget(var_widget)
            vars_group.setLayout(vars_layout)
            main_layout.addWidget(vars_group)

        # Function Documentation (Brief, Detailed, Return, Category, Algorithm)
        doc_fields = {
            'brief': ('Brief Description', True, True),
            'details': ('Detailed Description', True, False),
            'return': ('Return Description', True, True),
            'category': ('Category', False, True),
            'algorithm': ('Algorithm', False, False)
        }
        if any(key in self.response for key in ['brief', 'details', 'return', 'category', 'algorithm']):
            doc_group = QGroupBox('Function Documentation')
            doc_layout = QVBoxLayout(doc_group)
            for key, (title, is_multiline, force_single_line) in doc_fields.items():
                if key in self.response:
                    doc_widget = EditablePredictionWidget(title, self.response[key], is_multiline, force_single_line=force_single_line)
                    self.widgets[key] = doc_widget
                    doc_layout.addWidget(doc_widget)
            doc_group.setLayout(doc_layout)
            main_layout.addWidget(doc_group)
            
        # Inline Comments
        if 'inline_comment' in self.response:
            inline_comment_group = QGroupBox('Inline Comments')
            inline_comment_layout = QVBoxLayout(inline_comment_group)
            self.widgets['inline_comment'] = {}
            for line_num, comment_text in self.response['inline_comment'].items():
                comment_widget = EditablePredictionWidget(f'Line {line_num}', comment_text, True, len(comment_text.split('\n')), True)
                self.widgets['inline_comment'][line_num] = comment_widget
                inline_comment_layout.addWidget(comment_widget)
            inline_comment_group.setLayout(inline_comment_layout)
            main_layout.addWidget(inline_comment_group)

        # Buttons
        button_layout = QHBoxLayout()
        accept_button = QPushButton('Accept Selected')
        accept_button.clicked.connect(self.on_accept_clicked)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.on_cancel_clicked)
        button_layout.addWidget(accept_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)

        # Add main layout to a scroll area
        scroll_area = QtWidgets.QScrollArea()
        scroll_area.setWidgetResizable(True)
        container_widget = QWidget()
        container_widget.setLayout(main_layout)
        scroll_area.setWidget(container_widget)
        
        form_layout = QVBoxLayout(self.parent)
        form_layout.addWidget(scroll_area)
        self.parent.setLayout(form_layout)

    def validate_fields(self):
        """验证所有字段是否都已正确填写"""
        # Validate simple text fields
        for field_name in ['funcname', 'ret_type']:
            if field_name in self.widgets and self.widgets[field_name].accepted and not self.widgets[field_name].get_content().strip():
                return False, field_name + " " # Indicate which field is problematic

        # Validate complex type fields (args, vars)
        for collection_name in ['args', 'vars']:
            if collection_name in self.widgets:
                for name, widget in self.widgets[collection_name].items():
                    if not widget.validate():
                        return False, f'Please fill in all fields in {collection_name}: {name}'

        # Validate docstring fields
        for doc_key in ['brief', 'details', 'return', 'category', 'algorithm']:
            if doc_key in self.widgets and self.widgets[doc_key].accepted and not self.widgets[doc_key].get_content().strip():
                return False, doc_key + " "

        return True, ""

    def on_accept_clicked(self):
        is_valid, error_field = self.validate_fields()
        if not is_valid:
            QMessageBox.warning(self.parent, 'Validation Error', f'{error_field}\nPlease fill in all selected fields before applying, otherwise unselect it.')
            return

        # Collect accepted content
        accepted_content = {}
        for key, widget in self.widgets.items():
            if isinstance(widget, EditablePredictionWidget) and widget.accepted:
                accepted_content[key] = widget.get_content()
            elif isinstance(widget, dict): # For args and vars (complex types)
                accepted_content[key] = {name: data for name, w in widget.items() if (data := w.get_type_info()) is not None}

        apply_prediction(self.ea, self.task_tag, accepted_content)
        self.Close(0)

    def on_cancel_clicked(self):
        self.Close(0)


class UserConfirmFormForFuncName(ida_kernwin.PluginForm):
    def __init__(self, ea, task_tag, prompt, response_raw, response):
        super(UserConfirmFormForFuncName, self).__init__()
        self.ea = ea
        self.task_tag = task_tag
        self.prompt = prompt
        self.response_raw = response_raw
        self.response = response
        self.widgets = [] # Simplified for func name only

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        main_layout = QVBoxLayout()
        main_layout.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)

        # Function Name field
        func_name_original = idc.get_func_name(self.ea)
        func_name_widget = EditablePredictionWidget(f'Function Name (Original: {func_name_original})', self.response)
        self.widgets.append({'widget': func_name_widget, 'original': func_name_original, 'prediction': self.response})
        main_layout.addWidget(func_name_widget)

        # Buttons
        button_layout = QHBoxLayout()
        accept_button = QPushButton('Accept Selected')
        accept_button.clicked.connect(self.on_accept_clicked)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.on_cancel_clicked)
        button_layout.addWidget(accept_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
        
        self.parent.setLayout(main_layout)

    def validate_fields(self):
        """验证所有字段是否都已正确填写"""
        for item in self.widgets:
            if item['widget'].accepted and not item['widget'].get_content().strip():
                return False, 'Please fill in all selected function names'
        return True, ""

    def on_accept_clicked(self):
        is_valid, error_msg = self.validate_fields()
        if not is_valid:
            QMessageBox.warning(self.parent, 'Validation Error', f'{error_msg}\nPlease fill in all selected fields before applying, otherwise unselect it.')
            return

        accepted_content = {}
        for item in self.widgets:
            if item['widget'].accepted:
                accepted_content['funcname'] = {'original': item['original'], 'prediction': item['widget'].get_content()}
        
        apply_prediction(self.ea, self.task_tag, accepted_content)
        self.Close(0)

    def on_cancel_clicked(self):
        self.Close(0)


class VariableSelectionWidget(QWidget):
    def __init__(self, title, variables):
        super(VariableSelectionWidget, self).__init__()
        self.variables = variables
        self.checkboxes = []

        main_layout = QVBoxLayout()
        top_layout = QHBoxLayout()

        title_label = QLabel(title)
        top_layout.addWidget(title_label)

        self.select_all_checkbox = QCheckBox('Select All Variables')
        self.select_all_checkbox.setChecked(True)
        self.select_all_checkbox.stateChanged.connect(self.on_select_all)
        top_layout.addWidget(self.select_all_checkbox)
        top_layout.addStretch() # Pushes checkbox to the right
        main_layout.addLayout(top_layout)

        for var_name in self.variables:
            checkbox = QCheckBox(var_name)
            checkbox.setChecked(True) # All variables are selected by default
            self.checkboxes.append(checkbox)
            main_layout.addWidget(checkbox)

        self.setLayout(main_layout)

    def on_select_all(self, state):
        checked = (state == QtCore.Qt.Checked)
        for checkbox in self.checkboxes:
            checkbox.setChecked(checked)

    def get_selected_variables(self):
        return [checkbox.text() for checkbox in self.checkboxes if checkbox.isChecked()]


class VariableSelectionForm(ida_kernwin.PluginForm):
    def __init__(self, ea, args, vars_):
        super(VariableSelectionForm, self).__init__()
        self.ea = ea
        self.args = args
        self.vars = vars_
        self.selected_args = []
        self.selected_vars = []
        self.title = f'Select Variables to Analyze - {hex(ea)}'

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        ida_kernwin.set_dock_pos(self.title, 'Output window', ida_kernwin.DP_RIGHT) # Dock to output window

    def PopulateForm(self):
        main_layout = QVBoxLayout()
        
        # Select all checkbox at the top
        select_all_layout = QHBoxLayout()
        self.main_select_all = QCheckBox('Select All Variables')
        self.main_select_all.setChecked(True)
        self.main_select_all.stateChanged.connect(self.on_main_select_all)
        select_all_layout.addWidget(self.main_select_all)
        select_all_layout.addStretch()
        main_layout.addLayout(select_all_layout)

        # Arguments section
        if self.args:
            self.args_widget = VariableSelectionWidget('Function Arguments', self.args)
            main_layout.addWidget(self.args_widget)

        # Local variables section
        if self.vars:
            self.vars_widget = VariableSelectionWidget('Local Variables', self.vars)
            main_layout.addWidget(self.vars_widget)

        # Buttons
        button_layout = QHBoxLayout()
        analyze_button = QPushButton('Analyze Selected')
        analyze_button.clicked.connect(self.on_analyze_clicked)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.on_cancel_clicked)
        button_layout.addWidget(analyze_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
        
        self.parent.setLayout(main_layout)

    def on_main_select_all(self, state):
        checked = (state == QtCore.Qt.Checked)
        if hasattr(self, 'args_widget'):
            self.args_widget.select_all_checkbox.setChecked(checked)
        if hasattr(self, 'vars_widget'):
            self.vars_widget.select_all_checkbox.setChecked(checked)

    def on_analyze_clicked(self):
        if hasattr(self, 'args_widget'):
            self.selected_args = self.args_widget.get_selected_variables()
        if hasattr(self, 'vars_widget'):
            self.selected_vars = self.vars_widget.get_selected_variables()
        self.Close(1) # Close with accepted status

    def on_cancel_clicked(self):
        self.Close(0)


class ReCopilotSettingsDialog(QDialog):
    """
    Dialog for configuring ReCopilot settings.
    """
    def __init__(self, parent=None):
        super(ReCopilotSettingsDialog, self).__init__(parent)
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Configure ReCopilot')
        main_layout = QVBoxLayout(self)

        # Model Settings Group
        model_group = QGroupBox('Model Settings')
        model_layout = QGridLayout(model_group)

        # Model Name
        model_layout.addWidget(QLabel('Model Name:'), 0, 0)
        self.model_name_edit = QLineEdit(settings_manager.settings['model_name'])
        model_layout.addWidget(self.model_name_edit, 0, 1)

        # Base URL
        model_layout.addWidget(QLabel('Base URL:'), 1, 0)
        self.base_url_edit = QLineEdit(settings_manager.settings['base_url'])
        model_layout.addWidget(self.base_url_edit, 1, 1)

        # API Key
        model_layout.addWidget(QLabel('API Key:'), 2, 0)
        self.api_key_edit = QLineEdit(settings_manager.settings['api_key'])
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        model_layout.addWidget(self.api_key_edit, 2, 1)

        # Prompt Template
        model_layout.addWidget(QLabel('Prompt Template:'), 3, 0)
        self.prompt_template_combo = QComboBox()
        self.prompt_template_combo.addItems(list(PROMPT_TEMPLATE.keys()))
        self.prompt_template_combo.setCurrentText(settings_manager.settings['prompt_template'])
        self.prompt_template_combo.setToolTip('Select the prompt template to query the model')
        model_layout.addWidget(self.prompt_template_combo, 3, 1)
        
        # Max Output Tokens
        model_layout.addWidget(QLabel('Max Output Tokens:'), 4, 0)
        self.max_output_tokens_spin = QSpinBox()
        self.max_output_tokens_spin.setRange(1, 2147483647) # Max int value
        self.max_output_tokens_spin.setValue(settings_manager.settings['max_output_tokens'])
        self.max_output_tokens_spin.setToolTip('Maximum number of tokens to generate in the output (1-2147483647)')
        model_layout.addWidget(self.max_output_tokens_spin, 4, 1)

        main_layout.addWidget(model_group)

        # Analysis Settings Group
        analysis_group = QGroupBox('Analysis Settings')
        analysis_layout = QGridLayout(analysis_group)

        # Max Trace Caller Depth
        analysis_layout.addWidget(QLabel('Max Trace Caller Depth:'), 0, 0)
        self.caller_depth_spin = QSpinBox()
        self.caller_depth_spin.setRange(0, 10)
        self.caller_depth_spin.setValue(settings_manager.settings['max_trace_caller_depth'])
        self.caller_depth_spin.setToolTip('Maximum depth when tracing function callers (0-10)')
        analysis_layout.addWidget(self.caller_depth_spin, 0, 1)

        # Max Trace Callee Depth
        analysis_layout.addWidget(QLabel('Max Trace Callee Depth:'), 1, 0)
        self.callee_depth_spin = QSpinBox()
        self.callee_depth_spin.setRange(0, 10)
        self.callee_depth_spin.setValue(settings_manager.settings['max_trace_callee_depth'])
        self.callee_depth_spin.setToolTip('Maximum depth when tracing function callees (0-10)')
        analysis_layout.addWidget(self.callee_depth_spin, 1, 1)

        # Max Context Functions
        analysis_layout.addWidget(QLabel('Max Context Functions:'), 2, 0)
        self.context_func_spin = QSpinBox()
        self.context_func_spin.setRange(-1, 100) # -1 for no limit, up to 100
        self.context_func_spin.setValue(settings_manager.settings['max_context_func_num'])
        self.context_func_spin.setToolTip('Maximum number of functions to include in context (-1 for no limit)')
        analysis_layout.addWidget(self.context_func_spin, 2, 1)

        # Data Flow Analysis Enable
        analysis_layout.addWidget(QLabel('Data Flow Analysis Enable:'), 3, 0)
        self.data_flow_switch = QCheckBox()
        self.data_flow_switch.setToolTip('Enable/Disable Data Flow Analysis')
        self.data_flow_switch.setChecked(settings_manager.settings['data_flow_analysis'])
        analysis_layout.addWidget(self.data_flow_switch, 3, 1)

        # Measure Info Score
        analysis_layout.addWidget(QLabel('Measure Info Score:'), 4, 0)
        self.measure_info_score_switch = QCheckBox()
        self.measure_info_score_switch.setToolTip('Enable/disable information score measurement')
        self.measure_info_score_switch.setChecked(settings_manager.settings['measure_info_score'])
        analysis_layout.addWidget(self.measure_info_score_switch, 4, 1)

        # Need User Confirm
        analysis_layout.addWidget(QLabel('Need User Confirm:'), 5, 0)
        self.need_confirm_switch = QCheckBox()
        self.need_confirm_switch.setToolTip('Enable/disable user confirm before send request to LLM')
        self.need_confirm_switch.setChecked(settings_manager.settings['need_confirm'])
        analysis_layout.addWidget(self.need_confirm_switch, 5, 1)

        # Mock Mode
        analysis_layout.addWidget(QLabel('Mock Mode (Developer Only):'), 6, 0)
        self.debug_mode_switch = QCheckBox()
        self.debug_mode_switch.setToolTip('Enable/disable mock mode for debug')
        self.debug_mode_switch.setChecked(settings_manager.settings['debug_mode'])
        analysis_layout.addWidget(self.debug_mode_switch, 6, 1)

        # Feedback Enable
        analysis_layout.addWidget(QLabel('Feedback Enable:'), 7, 0)
        self.feedback_switch = QCheckBox()
        self.feedback_switch.setToolTip('Enable/Disable Send Feedback')
        self.feedback_switch.setChecked(settings_manager.settings['feedback'])
        analysis_layout.addWidget(self.feedback_switch, 7, 1)

        main_layout.addWidget(analysis_group)

        # Buttons
        button_layout = QHBoxLayout()
        save_button = QPushButton('Save Settings')
        save_button.clicked.connect(self.save_settings)
        cancel_button = QPushButton('Cancel')
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        main_layout.addLayout(button_layout)
        
        self.setLayout(main_layout)

    def save_settings(self):
        """Save current settings and close dialog."""
        model_name = self.model_name_edit.text().strip()
        prompt_template = self.prompt_template_combo.currentText()
        base_url = self.base_url_edit.text().strip()
        api_key = self.api_key_edit.text().strip()

        # 基本验证
        if not model_name:
            QMessageBox.warning(self, 'Invalid Configuration', 'Model name cannot be empty.')
            return

        # 如果使用第三方API，需要提供API Key
        if base_url and not api_key:
            QMessageBox.warning(self, 'Invalid Configuration', 'API Key is required when using custom Base URL.')
            return

        new_settings = {
            'model_name': model_name,
            'base_url': self.base_url_edit.text().strip(),
            'api_key': self.api_key_edit.text().strip(),
            'prompt_template': prompt_template,
            'max_output_tokens': self.max_output_tokens_spin.value(),
            'max_trace_caller_depth': self.caller_depth_spin.value(),
            'max_trace_callee_depth': self.callee_depth_spin.value(),
            'max_context_func_num': self.context_func_spin.value(),
            'data_flow_analysis': self.data_flow_switch.isChecked(),
            'measure_info_score': self.measure_info_score_switch.isChecked(),
            'need_confirm': self.need_confirm_switch.isChecked(),
            'debug_mode': self.debug_mode_switch.isChecked(),
            'feedback': self.feedback_switch.isChecked(),
        }
        settings_manager.save_settings(new_settings)
        QMessageBox.information(self, 'Success', 'Settings saved successfully!')
        self.accept()


class OutputWindowButton(QWidget):
    def __init__(self, model, parent=None):
        super(OutputWindowButton, self).__init__(parent)
        self.model = model
        self.setFixedHeight(30) # Set a fixed height for the button container

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(5, 0, 15, 0) # Margins: left, top, right, bottom
        main_layout.setSpacing(5) # Spacing between widgets

        # Add stretch to push the button to the right
        main_layout.addStretch(1)

        self.button = QPushButton('Cancel Analysis', self)
        self.button.setStyleSheet("""
            QPushButton {
                background-color: #823432;
                color: white;
                border: none;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #9a3f3d;
            }
            QPushButton:pressed {
                background-color: #6b2a29;
            }
        """)
        self.button.clicked.connect(self.on_cancel_clicked)
        main_layout.addWidget(self.button)
        self.setLayout(main_layout)

    def on_cancel_clicked(self):
        self.model.cancel() # Call the cancel method on the provided model
        self.hide() # Hide the button after cancellation

def add_cancel_button(model):
    """Add a cancel button to the bottom of the Output window"""
    output_window = ida_kernwin.find_widget('Output window')
    if output_window:
        output_qwidget = ida_kernwin.PluginForm.FormToPyQtWidget(output_window)
        if output_qwidget:
            button_widget = OutputWindowButton(model, output_qwidget)
            output_qwidget.layout().addWidget(button_widget)
            button_widget.show()
            return button_widget
    return None

def remove_cancel_button(button_widget):
    """Remove the cancel button"""
    if button_widget:
        button_widget.hide()
        button_widget.deleteLater() # Schedule for deletion