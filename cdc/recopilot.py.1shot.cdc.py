# Source Generated with Decompyle++
# File: recopilot.py.1shot.seq (Python 3.12)

'__pyarmor_enter_54851__(...)'
import idaapi
import logging
import ida_idaapi
import ida_kernwin
from config import settings_manager
from handler import FuncAnalysisHandler, DecompilationHandler, ReCopilotSettingsHandler, SpecificVariableAnalysisHandler, AllVariableAnalysisHandler, AllArgumentAnalysisHandler, FuncNameAnalysisHandler, SummaryAnalysisHandler
logging.getLogger('requests').setLevel(logging.ERROR)
logging.getLogger('urllib3').setLevel(logging.ERROR)
logging.getLogger().setLevel(logging.INFO)

class ReCopilotPlugin(idaapi.plugin_t):
    '__pyarmor_enter_54854__(...)'
    func_analysis_name = 'function overall analysis'
    decompilation_name = 'decompilation'
    specific_vars_analysis_name = 'select variable analysis'
    vars_analysis_name = 'all variable analysis'
    args_analysis_name = 'all argument analysis'
    funcname_analysis_name = 'function name recovery'
    summary_analysis_name = 'summary analysis'
    wanted_name = 'ReCopilot'
    wanted_hotkey = ''
    version = 'v0.1-beta'
    comment = 'ReCopilot: Reverse Engineering Copilot in Binary Analysis'
    help = 'read README.md for help'
    flags = 0
    
    def init(self):
        '__pyarmor_enter_54857__(...)'
        print('\n==== ReCopilot Plugin Init ====')
        self.hooks = None
        _var_var_0 = idaapi.action_desc_t(self.func_analysis_name, self.func_analysis_name, FuncAnalysisHandler(), 'Ctrl+Shift+Alt+F', 'Overall analysis for current function', 201)
        _var_var_1 = idaapi.action_desc_t(self.decompilation_name, self.decompilation_name, DecompilationHandler(), 'Ctrl+Shift+Alt+D', 'Decompile function into source code', 201)
        _var_var_2 = idaapi.action_desc_t(self.specific_vars_analysis_name, self.specific_vars_analysis_name, SpecificVariableAnalysisHandler(), 'Ctrl+Shift+Alt+V', 'Analysis specific variables', 201)
        _var_var_3 = idaapi.action_desc_t(self.vars_analysis_name, self.vars_analysis_name, AllVariableAnalysisHandler(), None, 'Analysis all local variables and arguments', 201)
        _var_var_4 = idaapi.action_desc_t(self.args_analysis_name, self.args_analysis_name, AllArgumentAnalysisHandler(), None, 'Analysis all arguments', 201)
        _var_var_5 = idaapi.action_desc_t(self.funcname_analysis_name, self.funcname_analysis_name, FuncNameAnalysisHandler(), None, 'Generate meaningful function name', 201)
        _var_var_6 = idaapi.action_desc_t(self.summary_analysis_name, self.summary_analysis_name, SummaryAnalysisHandler(), None, 'Generate func summary and inline comments', 201)
        _var_var_7 = idaapi.action_desc_t('recopilot:settings', 'Settings', ReCopilotSettingsHandler(), 'Ctrl+Shift+Alt+S', 'Configure ReCopilot settings', 156)
        idaapi.register_action(_var_var_0)
        idaapi.register_action(_var_var_1)
        idaapi.register_action(_var_var_2)
        idaapi.register_action(_var_var_3)
        idaapi.register_action(_var_var_4)
        idaapi.register_action(_var_var_5)
        idaapi.register_action(_var_var_6)
        idaapi.register_action(_var_var_7)
        idaapi.attach_action_to_menu('Edit/ReCopilot/', 'recopilot:settings', 0)
        self.hooks = ContextMenuHooks()
        self.hooks.hook()
        print('[👏] ReCopilot init success')
        '__pyarmor_exit_54858__(...)'
        return ida_idaapi.PLUGIN_KEEP

    
    def term(self):
        '__pyarmor_enter_54860__(...)'
        '__pyarmor_exit_54861__(...)'

    
    def run(self, arg):
        '__pyarmor_enter_54863__(...)'
        '__pyarmor_exit_54864__(...)'

    '__pyarmor_exit_54855__(...)'


class ContextMenuHooks(ida_kernwin.UI_Hooks):
    '__pyarmor_enter_54866__(...)'
    
    def finish_populating_widget_popup(self, widget, popup):
        '__pyarmor_enter_54869__(...)'
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            ida_kernwin.attach_action_to_popup(widget, popup, ReCopilotPlugin.func_analysis_name, 'ReCopilot/')
            ida_kernwin.attach_action_to_popup(widget, popup, ReCopilotPlugin.decompilation_name, 'ReCopilot/')
            ida_kernwin.attach_action_to_popup(widget, popup, ReCopilotPlugin.specific_vars_analysis_name, 'ReCopilot/')
            ida_kernwin.attach_action_to_popup(widget, popup, ReCopilotPlugin.vars_analysis_name, 'ReCopilot/')
            ida_kernwin.attach_action_to_popup(widget, popup, ReCopilotPlugin.args_analysis_name, 'ReCopilot/')
            ida_kernwin.attach_action_to_popup(widget, popup, ReCopilotPlugin.funcname_analysis_name, 'ReCopilot/')
            ida_kernwin.attach_action_to_popup(widget, popup, ReCopilotPlugin.summary_analysis_name, 'ReCopilot/')
            ida_kernwin.attach_action_to_popup(widget, popup, 'recopilot:settings', 'ReCopilot/')
        '__pyarmor_exit_54870__(...)'

    '__pyarmor_exit_54867__(...)'


def PLUGIN_ENTRY():
    '__pyarmor_enter_54872__(...)'
    '__pyarmor_exit_54873__(...)'
    return ReCopilotPlugin()

'__pyarmor_exit_54852__(...)'
