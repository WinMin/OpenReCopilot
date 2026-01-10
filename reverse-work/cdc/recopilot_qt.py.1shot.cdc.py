# Source Generated with Decompyle++
# File: recopilot_qt.py.1shot.seq (Python 3.12)

'__pyarmor_enter_54479__(...)'
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
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QWidget, QLineEdit, QGroupBox, QGridLayout, QMessageBox, QSpinBox, QCheckBox, QComboBox
from ext_info import apply_prediction
from config import settings_manager, PROMPT_TEMPLATE
from feedback import send_feedback
from remote_model import OpenAIModel

class DecompilationViewPluginForm(ida_kernwin.PluginForm):
    '__pyarmor_enter_54482__(...)'
    
    def __init__(self, title, content):
        '__pyarmor_enter_54485__(...)'
    # WARNING: Decompyle incomplete

    
    def OnCreate(self, form):
        '__pyarmor_enter_54488__(...)'
        self.parent_widget = self.FormToPyQtWidget(form)
        _var_var_1 = QtWidgets.QVBoxLayout()
        self.code_browser = QtWidgets.QTextBrowser()
        self.code_browser.setOpenExternalLinks(False)
        self.code_browser.setFontFamily('Consolas')
        self.code_browser.setStyleSheet('font-size: 12px;')
        _var_var_1.addWidget(self.code_browser)
        self.parent_widget.setLayout(_var_var_1)
        if self.initial_content:
            self.set_content(self.initial_content)
        '__pyarmor_exit_54489__(...)'

    
    def set_content(self, code):
        '__pyarmor_enter_54491__(...)'
        if self.code_browser:
            _var_var_2 = CppLexer()
            _var_var_3 = HtmlFormatter(style = 'vs', noclasses = True)
            _var_var_4 = highlight(code, _var_var_2, _var_var_3)
            self.code_browser.setHtml(_var_var_4)
        '__pyarmor_exit_54492__(...)'

    
    def OnClose(self, form):
        '__pyarmor_enter_54494__(...)'
        '__pyarmor_exit_54495__(...)'

    
    def Show(self):
        '__pyarmor_enter_54497__(...)'
    # WARNING: Decompyle incomplete

    __classcell__ = None
    '__pyarmor_exit_54483__(...)'


def create_decompilation_view(ea, content):
    '''
    在IDA主线程中创建反编译视图 (使用PluginForm)
    
    Args:
        ea: func addr
        content: view content
        
    Returns:
        bool: True if success, False otherwise
    '''
    '__pyarmor_enter_54500__(...)'
    print('[*] Try to create ReCopilot decompilation view using PluginForm')
    _var_var_5 = idc.get_func_name(ea)
    _var_var_6 = f'''ReCopilot Decompilation - {_var_var_5}'''
    _var_var_7 = DecompilationViewPluginForm(_var_var_6, content)
    _var_var_7.Show()
    if ida_kernwin.find_widget(_var_var_6):
        print(f'''[+] Successfully created/shown decompilation view with PluginForm, title: {_var_var_6}''')
    else:
        True
        return True
        print(f'''[!] Failed to verify creation/showing of decompilation view with PluginForm, title: {_var_var_6}.''')
    False
    return False
# WARNING: Decompyle incomplete


class EditablePredictionWidget(QWidget):
    '__pyarmor_enter_54503__(...)'
    
    def __init__(self, title, content, is_multiline, line_count, force_single_line):
        '__pyarmor_enter_54506__(...)'
    # WARNING: Decompyle incomplete

    
    def accepted_state_change(self, state):
        '__pyarmor_enter_54509__(...)'
        self.accepted = state == QtCore.Qt.Checked
        self.content_edit.setEnabled(self.accepted)
        '__pyarmor_exit_54510__(...)'

    
    def get_content(self):
        '__pyarmor_enter_54512__(...)'
        '__pyarmor_exit_54513__(...)'
        return self.content_edit.toPlainText() if isinstance(self.content_edit, QtWidgets.QTextEdit) else self.content_edit.text()

    __classcell__ = None
    '__pyarmor_exit_54504__(...)'


class NameTypeWidget(QWidget):
    '__pyarmor_enter_54515__(...)'
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)
    
    def __init__(self, title, name, type_str, size, is_enum):
        '__pyarmor_enter_54518__(...)'
    # WARNING: Decompyle incomplete

    
    def accepted_state_change(self, state):
        '__pyarmor_enter_54521__(...)'
        self.accepted = state == QtCore.Qt.Checked
        self.name_checkbox.setEnabled(self.accepted)
        self.type_checkbox.setEnabled(self.accepted)
        if self.accepted:
            self.accepted
        self.name_edit.setEnabled(self.accepted_name)
        if self.accepted:
            self.accepted
        self.type_edit.setEnabled(self.accepted_type)
        if self.is_enum:
            self.size_checkbox.setEnabled(self.accepted)
            if self.accepted:
                self.accepted
            self.size_edit.setEnabled(self.accepted_size)
            self.add_button.setEnabled(self.accepted)
            self.remove_button.setEnabled(self.accepted)
        '__pyarmor_exit_54522__(...)'

    
    def name_state_change(self, state):
        '__pyarmor_enter_54524__(...)'
        self.accepted_name = state == QtCore.Qt.Checked
        if self.accepted:
            self.accepted
        self.name_edit.setEnabled(self.accepted_name)
        '__pyarmor_exit_54525__(...)'

    
    def type_state_change(self, state):
        '__pyarmor_enter_54527__(...)'
        self.accepted_type = state == QtCore.Qt.Checked
        if self.accepted:
            self.accepted
        self.type_edit.setEnabled(self.accepted_type)
        '__pyarmor_exit_54528__(...)'

    
    def size_state_change(self, state):
        '__pyarmor_enter_54530__(...)'
        self.accepted_size = state == QtCore.Qt.Checked
        if self.accepted:
            self.accepted
        self.size_edit.setEnabled(self.accepted_size)
        '__pyarmor_exit_54531__(...)'

    
    def get_content(self):
        '__pyarmor_enter_54533__(...)'
        if self.is_enum:
            _var_var_15 = int(self.size_edit.text()) if self.accepted and self.accepted_size else None
        else:
            None([
                self.name_edit.text() if self.accepted and self.accepted_name else None,
                self.type_edit.text() if self.accepted and self.accepted_type else None,
                _var_var_15])
            return None
        '__pyarmor_exit_54534__(...)'
        return [
            self.name_edit.text() if [
                self.name_edit.text() if self.accepted and self.accepted_name else None,
                self.type_edit.text() if self.accepted and self.accepted_type else None,
                _var_var_15].accepted and self.accepted_name else None,
            self.type_edit.text() if self.accepted and self.accepted_type else None]

    
    def validate(self):
        '__pyarmor_enter_54536__(...)'
        if not self.accepted:
            pass
    # WARNING: Decompyle incomplete

    
    def on_add_clicked(self):
        '__pyarmor_enter_54539__(...)'
        self.field_added.emit()
        '__pyarmor_exit_54540__(...)'

    
    def on_remove_clicked(self):
        '__pyarmor_enter_54542__(...)'
        self.field_removed.emit(self)
        '__pyarmor_exit_54543__(...)'

    
    def setEnabled(self, enabled):
        '__pyarmor_enter_54545__(...)'
    # WARNING: Decompyle incomplete

    __classcell__ = None
    '__pyarmor_exit_54516__(...)'


class StructFieldWidget(QWidget):
    '__pyarmor_enter_54548__(...)'
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)
    
    def __init__(self, type_str, name, size):
        '__pyarmor_enter_54551__(...)'
    # WARNING: Decompyle incomplete

    
    def accepted_state_change(self, state):
        '__pyarmor_enter_54554__(...)'
        self.accepted = state == QtCore.Qt.Checked
        self.type_edit.setEnabled(self.accepted)
        self.name_edit.setEnabled(self.accepted)
        self.size_edit.setEnabled(self.accepted)
        self.add_button.setEnabled(self.accepted)
        self.remove_button.setEnabled(self.accepted)
        '__pyarmor_exit_54555__(...)'

    
    def get_content(self):
        '__pyarmor_enter_54557__(...)'
        if not self.accepted:
            pass
        else:
            return None
        None([
            self.type_edit.text(),
            self.name_edit.text(),
            int(self.size_edit.text())])
        return None
        '__pyarmor_exit_54558__(...)'
        '__pyarmor_exit_54558__(...)'

    
    def validate(self):
        '__pyarmor_enter_54560__(...)'
        if not self.accepted:
            pass
        else:
            True
            return True
            if not self.type_edit.text().strip():
                pass
            else:
                False
                return False
                if not self.name_edit.text().strip():
                    pass
                else:
                    False
                    return False
                    _var_var_16 = self.size_edit.text().strip()
                    if not _var_var_16:
                        pass
                    else:
                        False
                        return False
                        _var_var_15 = int(_var_var_16)
                        if _var_var_15 <= 0:
                            pass
                        else:
                            False
                            return False
        True
        return True
    # WARNING: Decompyle incomplete

    
    def on_add_clicked(self):
        '__pyarmor_enter_54563__(...)'
        self.field_added.emit()
        '__pyarmor_exit_54564__(...)'

    
    def on_remove_clicked(self):
        '__pyarmor_enter_54566__(...)'
        self.field_removed.emit(self)
        '__pyarmor_exit_54567__(...)'

    __classcell__ = None
    '__pyarmor_exit_54549__(...)'


class EnumFieldWidget(QWidget):
    '__pyarmor_enter_54569__(...)'
    field_added = QtCore.pyqtSignal()
    field_removed = QtCore.pyqtSignal(QWidget)
    
    def __init__(self, name, value, size):
        '__pyarmor_enter_54572__(...)'
    # WARNING: Decompyle incomplete

    
    def accepted_state_change(self, state):
        '__pyarmor_enter_54575__(...)'
        self.accepted = state == QtCore.Qt.Checked
        self.name_edit.setEnabled(self.accepted)
        self.value_edit.setEnabled(self.accepted)
        self.size_edit.setEnabled(self.accepted)
        self.add_button.setEnabled(self.accepted)
        self.remove_button.setEnabled(self.accepted)
        '__pyarmor_exit_54576__(...)'

    
    def get_content(self):
        '__pyarmor_enter_54578__(...)'
        if not self.accepted:
            pass
        else:
            return None
            _var_var_15 = int(self.size_edit.text()) if self.size_edit.text().strip() else 4
            _var_var_17 = self.value_edit.text()
            if _var_var_17.isdigit():
                _var_var_17 = int(_var_var_17)
        None([
            self.name_edit.text(),
            _var_var_17,
            _var_var_15])
        return None
    # WARNING: Decompyle incomplete

    
    def validate(self):
        '__pyarmor_enter_54581__(...)'
        if not self.accepted:
            pass
    # WARNING: Decompyle incomplete

    
    def on_add_clicked(self):
        '__pyarmor_enter_54584__(...)'
        self.field_added.emit()
        '__pyarmor_exit_54585__(...)'

    
    def on_remove_clicked(self):
        '__pyarmor_enter_54587__(...)'
        self.field_removed.emit(self)
        '__pyarmor_exit_54588__(...)'

    __classcell__ = None
    '__pyarmor_exit_54570__(...)'


class ComplexTypeWidget(QWidget):
    '__pyarmor_enter_54590__(...)'
    
    def __init__(self, title, type_info):
        '__pyarmor_enter_54593__(...)'
    # WARNING: Decompyle incomplete

    
    def add_struct_field(self, type_str, name, size, after_widget):
        '__pyarmor_enter_54596__(...)'
        _var_var_29 = StructFieldWidget(type_str, name, size)
        _var_var_29.field_added.connect(self._create_add_struct_callback(_var_var_29))
        _var_var_29.field_removed.connect(self.remove_struct_field)
        if after_widget:
            _var_var_34 = self.field_widgets.index(after_widget) + 1
            self.field_widgets.insert(_var_var_34, _var_var_29)
            self.fields_layout.insertWidget(_var_var_34 + 1, _var_var_29)
        else:
            self.field_widgets.append(_var_var_29)
            self.fields_layout.addWidget(_var_var_29)
        '__pyarmor_exit_54597__(...)'

    
    def add_enum_field(self, name, value, size, after_widget):
        '__pyarmor_enter_54599__(...)'
        _var_var_29 = EnumFieldWidget(name, value, size)
        _var_var_29.field_added.connect(self._create_add_enum_callback(_var_var_29))
        _var_var_29.field_removed.connect(self.remove_enum_field)
        if after_widget:
            _var_var_34 = self.field_widgets.index(after_widget) + 1
            self.field_widgets.insert(_var_var_34, _var_var_29)
            self.fields_layout.insertWidget(_var_var_34 + 1, _var_var_29)
        else:
            self.field_widgets.append(_var_var_29)
            self.fields_layout.addWidget(_var_var_29)
        '__pyarmor_exit_54600__(...)'

    
    def remove_struct_field(self, widget):
        '__pyarmor_enter_54602__(...)'
        if len(self.field_widgets) > 1:
            self.fields_layout.removeWidget(widget)
            self.field_widgets.remove(widget)
            widget.deleteLater()
        '__pyarmor_exit_54603__(...)'

    
    def remove_enum_field(self, widget):
        '__pyarmor_enter_54605__(...)'
        if len(self.field_widgets) > 1:
            self.fields_layout.removeWidget(widget)
            self.field_widgets.remove(widget)
            widget.deleteLater()
        '__pyarmor_exit_54606__(...)'

    
    def validate(self):
        '__pyarmor_enter_54608__(...)'
        if not self.accepted:
            pass
    # WARNING: Decompyle incomplete

    
    def accepted_state_change(self, state):
        '__pyarmor_enter_54611__(...)'
        self.accepted = state == QtCore.Qt.Checked
        self.name_type_widget.setEnabled(self.accepted)
    # WARNING: Decompyle incomplete

    
    def get_type_info(self):
        '__pyarmor_enter_54614__(...)'
        if not self.accepted:
            pass
    # WARNING: Decompyle incomplete

    
    def _create_add_enum_callback(self, widget):
        '''Create a callback function for adding an enum field after the specified widget'''
        '__pyarmor_enter_54617__(...)'
        
        def _var_var_42():
            '__pyarmor_enter_54620__(...)'
            self.add_enum_field(after_widget = widget)
            '__pyarmor_exit_54621__(...)'

        '__pyarmor_exit_54618__(...)'
        return _var_var_42

    
    def _create_add_struct_callback(self, widget):
        '''Create a callback function for adding a struct field after the specified widget'''
        '__pyarmor_enter_54623__(...)'
        
        def _var_var_42():
            '__pyarmor_enter_54626__(...)'
            self.add_struct_field(after_widget = widget)
            '__pyarmor_exit_54627__(...)'

        '__pyarmor_exit_54624__(...)'
        return _var_var_42

    __classcell__ = None
    '__pyarmor_exit_54591__(...)'


class UserConfirmForm(ida_kernwin.PluginForm):
    '__pyarmor_enter_54629__(...)'
    
    def __init__(self, ea, task_tag, prompt, response_raw, response):
        '__pyarmor_enter_54632__(...)'
    # WARNING: Decompyle incomplete

    
    def OnCreate(self, form):
        '__pyarmor_enter_54635__(...)'
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        '__pyarmor_exit_54636__(...)'

    
    def PopulateForm(self):
        '__pyarmor_enter_54638__(...)'
        _var_var_1 = QtWidgets.QVBoxLayout()
        _var_var_1.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
        if 'funcname' in self.response:
            self.widgets['funcname'] = EditablePredictionWidget('Function Name', self.response['funcname'])
            _var_var_1.addWidget(self.widgets['funcname'])
        if 'ret_type' in self.response:
            self.widgets['ret_type'] = EditablePredictionWidget('Return Type', self.response['ret_type'])
            _var_var_1.addWidget(self.widgets['ret_type'])
    # WARNING: Decompyle incomplete

    
    def validate_fields(self):
        '''验证所有字段是否都已正确填写'''
        '__pyarmor_enter_54641__(...)'
    # WARNING: Decompyle incomplete

    
    def on_accept_clicked(self):
        '__pyarmor_enter_54644__(...)'
        (_var_var_73, _var_var_74) = self.validate_fields()
        if not _var_var_73:
            QtWidgets.QMessageBox.warning(self.parent, 'Validation Error', f'''{_var_var_74}\nPlease fill in all selected fields before applying, otherwise unselect it.''')
    # WARNING: Decompyle incomplete

    
    def on_cancel_clicked(self):
        '__pyarmor_enter_54647__(...)'
        self.Close(0)
        '__pyarmor_exit_54648__(...)'

    __classcell__ = None
    '__pyarmor_exit_54630__(...)'


def create_user_confirm_view(ea, task_tag, prompt, response_raw, response):
    '__pyarmor_enter_54650__(...)'
    _var_var_7 = UserConfirmForm(ea, task_tag, prompt, response_raw, response)
    _var_var_7.Show(f'''ReCopilot Predictions - {hex(ea)}''')
    '__pyarmor_exit_54651__(...)'
    return True


class UserConfirmFormForFuncName(ida_kernwin.PluginForm):
    '__pyarmor_enter_54653__(...)'
    
    def __init__(self, ea, task_tag, prompt, response_raw, response):
        '__pyarmor_enter_54656__(...)'
    # WARNING: Decompyle incomplete

    
    def OnCreate(self, form):
        '__pyarmor_enter_54659__(...)'
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        '__pyarmor_exit_54660__(...)'

    
    def PopulateForm(self):
        '__pyarmor_enter_54662__(...)'
        _var_var_1 = QtWidgets.QVBoxLayout()
        _var_var_1.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
        if isinstance(self.response, str):
            _var_var_35 = EditablePredictionWidget(f'''Function Name (Current: {idc.get_func_name(self.ea)})''', self.response)
            self.widgets.append({
                'widget': _var_var_35,
                'original': None })
            _var_var_1.addWidget(_var_var_35)
        elif isinstance(self.response, dict):
            _var_var_81 = self.response.get('original', '')
            _var_var_82 = self.response.get('prediction', '')
            _var_var_35 = EditablePredictionWidget(f'''Function Name (Original: {_var_var_81})''', _var_var_82)
            self.widgets.append({
                'widget': _var_var_35,
                'original': _var_var_81 })
            _var_var_1.addWidget(_var_var_35)
    # WARNING: Decompyle incomplete

    
    def validate_fields(self):
        '''验证所有字段是否都已正确填写'''
        '__pyarmor_enter_54665__(...)'
    # WARNING: Decompyle incomplete

    
    def on_accept_clicked(self):
        '__pyarmor_enter_54668__(...)'
        (_var_var_73, _var_var_74) = self.validate_fields()
        if not _var_var_73:
            QtWidgets.QMessageBox.warning(self.parent, 'Validation Error', f'''{_var_var_74}\nPlease fill in all selected fields before applying, otherwise unselect it.''')
    # WARNING: Decompyle incomplete

    
    def on_cancel_clicked(self):
        '__pyarmor_enter_54671__(...)'
        self.Close(0)
        '__pyarmor_exit_54672__(...)'

    __classcell__ = None
    '__pyarmor_exit_54654__(...)'


def create_user_confirm_view_for_funcname(ea, task_tag, prompt, response_raw, response):
    '__pyarmor_enter_54674__(...)'
    _var_var_7 = UserConfirmFormForFuncName(ea, task_tag, prompt, response_raw, response)
    _var_var_7.Show(f'''ReCopilot Predictions - {hex(ea)}''')
    '__pyarmor_exit_54675__(...)'
    return True


class VariableSelectionWidget(QWidget):
    '__pyarmor_enter_54677__(...)'
    
    def __init__(self, title, variables):
        '__pyarmor_enter_54680__(...)'
    # WARNING: Decompyle incomplete

    
    def on_select_all(self, state):
        '__pyarmor_enter_54683__(...)'
    # WARNING: Decompyle incomplete

    
    def get_selected_variables(self):
        '__pyarmor_enter_54686__(...)'
    # WARNING: Decompyle incomplete

    __classcell__ = None
    '__pyarmor_exit_54678__(...)'


class VariableSelectionForm(ida_kernwin.PluginForm):
    '__pyarmor_enter_54689__(...)'
    
    def __init__(self, ea, args, vars):
        '__pyarmor_enter_54692__(...)'
    # WARNING: Decompyle incomplete

    
    def OnCreate(self, form):
        '__pyarmor_enter_54695__(...)'
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()
        ida_kernwin.set_dock_pos(self.title, 'Output window', ida_kernwin.DP_RIGHT)
        '__pyarmor_exit_54696__(...)'

    
    def PopulateForm(self):
        '__pyarmor_enter_54698__(...)'
        _var_var_1 = QtWidgets.QVBoxLayout()
        _var_var_87 = QtWidgets.QHBoxLayout()
        self.main_select_all = QtWidgets.QCheckBox('Select All Variables')
        self.main_select_all.setChecked(True)
        self.main_select_all.stateChanged.connect(self.on_main_select_all)
        _var_var_87.addWidget(self.main_select_all)
        _var_var_87.addStretch()
        _var_var_1.addLayout(_var_var_87)
        if self.args:
            self.args_widget = VariableSelectionWidget('Function Arguments', self.args)
            _var_var_1.addWidget(self.args_widget)
        if self.vars:
            self.vars_widget = VariableSelectionWidget('Local Variables', self.vars)
            _var_var_1.addWidget(self.vars_widget)
        _var_var_66 = QtWidgets.QHBoxLayout()
        _var_var_88 = QtWidgets.QPushButton('Analyze Selected')
        _var_var_68 = QtWidgets.QPushButton('Cancel')
        _var_var_88.clicked.connect(self.on_analyze_clicked)
        _var_var_68.clicked.connect(self.on_cancel_clicked)
        _var_var_66.addWidget(_var_var_88)
        _var_var_66.addWidget(_var_var_68)
        _var_var_1.addLayout(_var_var_66)
        self.parent.setLayout(_var_var_1)
        '__pyarmor_exit_54699__(...)'

    
    def on_main_select_all(self, state):
        '__pyarmor_enter_54701__(...)'
        if hasattr(self, 'args_widget'):
            self.args_widget.select_all_checkbox.setChecked(state == QtCore.Qt.Checked)
        if hasattr(self, 'vars_widget'):
            self.vars_widget.select_all_checkbox.setChecked(state == QtCore.Qt.Checked)
        '__pyarmor_exit_54702__(...)'

    
    def on_analyze_clicked(self):
        '__pyarmor_enter_54704__(...)'
        if hasattr(self, 'args_widget'):
            self.selected_args = self.args_widget.get_selected_variables()
        if hasattr(self, 'vars_widget'):
            self.selected_vars = self.vars_widget.get_selected_variables()
        self.Close(1)
        '__pyarmor_exit_54705__(...)'

    
    def on_cancel_clicked(self):
        '__pyarmor_enter_54707__(...)'
        self.Close(0)
        '__pyarmor_exit_54708__(...)'

    __classcell__ = None
    '__pyarmor_exit_54690__(...)'


def create_variable_selection_view(ea):
    '''
    创建变量选择视图
    
    Args:
        ea: 函数地址
        
    Returns:
        VariableSelectionForm: 变量选择表单实例
    '''
    '__pyarmor_enter_54710__(...)'
    _var_var_89 = idaapi.get_func(ea)
    if not _var_var_89:
        print('[!] No function found at this address')
# WARNING: Decompyle incomplete


class ReCopilotSettingsDialog(QDialog):
    '''
    Dialog for configuring ReCopilot settings.
    '''
    '__pyarmor_enter_54713__(...)'
    
    def __init__(self, parent):
        '__pyarmor_enter_54716__(...)'
    # WARNING: Decompyle incomplete

    
    def initUI(self):
        '''Initialize the dialog UI.'''
        '__pyarmor_enter_54719__(...)'
        self.setWindowTitle('Configure ReCopilot')
        _var_var_1 = QVBoxLayout(self)
        _var_var_94 = QGroupBox('Model Settings')
        _var_var_95 = QGridLayout(_var_var_94)
        _var_var_95.addWidget(QLabel('Model Name:'), 0, 0)
        self.model_name_edit = QLineEdit(settings_manager.settings['model_name'])
        _var_var_95.addWidget(self.model_name_edit, 0, 1)
        _var_var_95.addWidget(QLabel('Base URL:'), 1, 0)
        self.base_url_edit = QLineEdit(settings_manager.settings['base_url'])
        _var_var_95.addWidget(self.base_url_edit, 1, 1)
        _var_var_95.addWidget(QLabel('API Key:'), 2, 0)
        self.api_key_edit = QLineEdit(settings_manager.settings['api_key'])
        self.api_key_edit.setEchoMode(QLineEdit.Password)
        _var_var_95.addWidget(self.api_key_edit, 2, 1)
        _var_var_95.addWidget(QLabel('Prompt Template:'), 3, 0)
        self.prompt_template_combo = QComboBox()
        self.prompt_template_combo.addItems(list(PROMPT_TEMPLATE.keys()))
        self.prompt_template_combo.setCurrentText(settings_manager.settings['prompt_template'])
        self.prompt_template_combo.setToolTip('Select the prompt template to query the model')
        _var_var_95.addWidget(self.prompt_template_combo, 3, 1)
        _var_var_95.addWidget(QLabel('Max Output Tokens:'), 4, 0)
        self.max_output_tokens_spin = QSpinBox()
        self.max_output_tokens_spin.setRange(1, 2147483647)
        self.max_output_tokens_spin.setValue(settings_manager.settings['max_output_tokens'])
        self.max_output_tokens_spin.setToolTip('Maximum number of tokens to generate in the output (1-2147483647)')
        _var_var_95.addWidget(self.max_output_tokens_spin, 4, 1)
        _var_var_1.addWidget(_var_var_94)
        _var_var_96 = QGroupBox('Analysis Settings')
        _var_var_97 = QGridLayout(_var_var_96)
        _var_var_98 = QLabel('Max Trace Caller Depth:')
        _var_var_98.setToolTip('Maximum depth when tracing function callers (0-10)')
        _var_var_97.addWidget(_var_var_98, 0, 0)
        self.caller_depth_spin = QSpinBox()
        self.caller_depth_spin.setRange(0, 10)
        self.caller_depth_spin.setValue(settings_manager.settings['max_trace_caller_depth'])
        _var_var_97.addWidget(self.caller_depth_spin, 0, 1)
        _var_var_99 = QLabel('Max Trace Callee Depth:')
        _var_var_99.setToolTip('Maximum depth when tracing function callees (0-10)')
        _var_var_97.addWidget(_var_var_99, 1, 0)
        self.callee_depth_spin = QSpinBox()
        self.callee_depth_spin.setRange(0, 10)
        self.callee_depth_spin.setValue(settings_manager.settings['max_trace_callee_depth'])
        _var_var_97.addWidget(self.callee_depth_spin, 1, 1)
        _var_var_100 = QLabel('Max Context Functions:')
        _var_var_100.setToolTip('Maximum number of functions to include in context (-1 for no limit)')
        _var_var_97.addWidget(_var_var_100, 2, 0)
        self.context_func_spin = QSpinBox()
        self.context_func_spin.setRange(-1, 100)
        self.context_func_spin.setValue(settings_manager.settings['max_context_func_num'])
        _var_var_97.addWidget(self.context_func_spin, 2, 1)
        _var_var_101 = QLabel('Data Flow Analysis Enable:')
        _var_var_101.setToolTip('Enable/Disable Data Flow Analysis')
        _var_var_97.addWidget(_var_var_101, 3, 0)
        self.data_flow_switch = QCheckBox()
        self.data_flow_switch.setChecked(settings_manager.settings['data_flow_analysis'])
        _var_var_97.addWidget(self.data_flow_switch, 3, 1)
        _var_var_102 = QLabel('Measure Info Score:')
        _var_var_102.setToolTip('Enable/disable information score measurement')
        _var_var_97.addWidget(_var_var_102, 4, 0)
        self.measure_info_score_switch = QCheckBox()
        self.measure_info_score_switch.setChecked(settings_manager.settings['measure_info_score'])
        _var_var_97.addWidget(self.measure_info_score_switch, 4, 1)
        _var_var_103 = QLabel('Need User Confirm:')
        _var_var_103.setToolTip('Enable/disable user confirm before send request to LLM')
        _var_var_97.addWidget(_var_var_103, 5, 0)
        self.need_confirm_switch = QCheckBox()
        self.need_confirm_switch.setChecked(settings_manager.settings['need_confirm'])
        _var_var_97.addWidget(self.need_confirm_switch, 5, 1)
        _var_var_104 = QLabel('Mock Mode (Developer Only):')
        _var_var_104.setToolTip('Enable/disable mock mode for debug')
        _var_var_97.addWidget(_var_var_104, 6, 0)
        self.debug_mode_switch = QCheckBox()
        self.debug_mode_switch.setChecked(settings_manager.settings['debug_mode'])
        _var_var_97.addWidget(self.debug_mode_switch, 6, 1)
        _var_var_105 = QLabel('Feedback Enable:')
        _var_var_105.setToolTip('Enable/Disable Send Feedback')
        _var_var_97.addWidget(_var_var_105, 7, 0)
        self.feedback_switch = QCheckBox()
        self.feedback_switch.setChecked(settings_manager.settings['feedback'])
        _var_var_97.addWidget(self.feedback_switch, 7, 1)
        _var_var_1.addWidget(_var_var_96)
        _var_var_66 = QHBoxLayout()
        _var_var_106 = QPushButton('Save Settings')
        _var_var_106.clicked.connect(self.save_settings)
        _var_var_68 = QPushButton('Cancel')
        _var_var_68.clicked.connect(self.reject)
        _var_var_66.addWidget(_var_var_106)
        _var_var_66.addWidget(_var_var_68)
        _var_var_1.addLayout(_var_var_66)
        '__pyarmor_exit_54720__(...)'

    
    def save_settings(self):
        '''Save current settings and close dialog.'''
        '__pyarmor_enter_54722__(...)'
        _var_var_107 = self.model_name_edit.text().strip()
        _var_var_108 = self.prompt_template_combo.currentText()
        if not _var_var_107.startswith('recopilot') or _var_var_108.startswith('general'):
            QMessageBox.warning(self, 'Invalid Configuration (无效配置)', 'General LLMs must use general* prompt template.\n(通用模型必须使用 general* 提示词模版)')
        else:
            return None
            if not _var_var_108.startswith('recopilot'):
                QMessageBox.warning(self, 'Invalid Configuration (无效配置)', 'ReCopilot models must use recopilot* prompt template.\n(ReCopilot 模型必须使用 recopilot* 提示词模版)')
            else:
                return None
                _var_var_109 = {
                    'model_name': self.model_name_edit.text().strip(),
                    'base_url': self.base_url_edit.text().strip(),
                    'api_key': self.api_key_edit.text().strip(),
                    'prompt_template': self.prompt_template_combo.currentText(),
                    'max_output_tokens': self.max_output_tokens_spin.value(),
                    'max_trace_caller_depth': self.caller_depth_spin.value(),
                    'max_trace_callee_depth': self.callee_depth_spin.value(),
                    'max_context_func_num': self.context_func_spin.value(),
                    'data_flow_analysis': self.data_flow_switch.isChecked(),
                    'measure_info_score': self.measure_info_score_switch.isChecked(),
                    'need_confirm': self.need_confirm_switch.isChecked(),
                    'debug_mode': self.debug_mode_switch.isChecked(),
                    'feedback': self.feedback_switch.isChecked() }
                settings_manager.save_settings(_var_var_109)
                QMessageBox.information(self, 'Success', 'Settings saved successfully!')
                self.accept()
        return None
        '__pyarmor_exit_54723__(...)'
        '__pyarmor_exit_54723__(...)'

    __classcell__ = None
    '__pyarmor_exit_54714__(...)'


class OutputWindowButton(QWidget):
    '__pyarmor_enter_54725__(...)'
    
    def __init__(self, model, parent):
        '__pyarmor_enter_54728__(...)'
    # WARNING: Decompyle incomplete

    
    def on_cancel_clicked(self):
        '__pyarmor_enter_54731__(...)'
        self.model.cancel()
        self.hide()
        '__pyarmor_exit_54732__(...)'

    __classcell__ = None
    '__pyarmor_exit_54726__(...)'


def add_cancel_button(model):
    '''Add a cancel button to the bottom of the Output window'''
    '__pyarmor_enter_54734__(...)'
    _var_var_110 = ida_kernwin.find_widget('Output window')
    if not _var_var_110:
        pass
    else:
        return None
        _var_var_110 = ida_kernwin.PluginForm.FormToPyQtWidget(_var_var_110)
        if not _var_var_110:
            pass
        else:
            return None
            _var_var_111 = OutputWindowButton(model, _var_var_110)
            _var_var_112 = _var_var_110.layout()
            if _var_var_112:
                _var_var_112.addWidget(_var_var_111)
                _var_var_111.show()
            else:
                None(_var_var_111)
                return None
    return None
    '__pyarmor_exit_54735__(...)'
    '__pyarmor_exit_54735__(...)'


def remove_cancel_button(button_widget):
    '''Remove the cancel button'''
    '__pyarmor_enter_54737__(...)'
    if button_widget:
        button_widget.hide()
        button_widget.deleteLater()
    '__pyarmor_exit_54738__(...)'

'__pyarmor_exit_54480__(...)'
