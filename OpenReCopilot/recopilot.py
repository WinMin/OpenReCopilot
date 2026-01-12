import idaapi
import logging
import ida_idaapi
import ida_kernwin
import threading # Used by handler, imported here for completeness
import time      # Used by handler and feedback, imported here
import re        # Likely used in sub-modules
import json      # Used in feedback and handler
import asyncio   # Used by handler
from functools import partial # Used by handler

# Custom module imports
from config import settings_manager
from handler import (
    FuncAnalysisHandler, DecompilationHandler, ReCopilotSettingsHandler,
    SpecificVariableAnalysisHandler, AllVariableAnalysisHandler,
    AllArgumentAnalysisHandler, FuncNameAnalysisHandler, SummaryAnalysisHandler,
    ida_execute, # Assuming ida_execute is also in handler.py based on previous decompilations
    func_analysis, decompilation, specific_vars_analysis, all_vars_analysis,
    all_args_analysis, func_name_analysis, summary_analysis
    # Mock functions might also be here or in a separate debug module
)
from remote_model import OpenAIModel
from ext_info import build_prompt # apply_prediction also imported but not seen used directly here
from recopilot_qt import (
    ReCopilotSettingsDialog, create_decompilation_view, create_user_confirm_view,
    create_variable_selection_view, create_user_confirm_view_for_funcname,
    add_cancel_button, remove_cancel_button
)
from checker import (
    response_check_and_refine, split_pred_to_var_arg,
    parse_model_response_json, parse_model_response_str, get_func_args_vars
)

# --- Configure Logging ---
# Suppress verbose logging from requests and urllib3
logging.getLogger("requests").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
# Set root logger level (or a specific plugin logger)
logging.getLogger().setLevel(logging.INFO) # Or a more specific logger for the plugin

# --- IDA Plugin Class ---
class ReCopilotPlugin(idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "ReCopilot: Reverse Engineering Copilot in Binary Analysis"
    help = "read README.md for help"
    wanted_name = "ReCopilot"
    wanted_hotkey = "" # Actions have their own hotkeys
    version = "v0.1-beta" # A version string

    # Action names (these are internal identifiers)
    action_prefix = "recopilot:"
    func_analysis_action_name = action_prefix + "func_analysis"
    decompilation_action_name = action_prefix + "decompilation"
    specific_vars_analysis_action_name = action_prefix + "specific_vars"
    vars_analysis_action_name = action_prefix + "all_vars"
    args_analysis_action_name = action_prefix + "all_args"
    funcname_analysis_action_name = action_prefix + "func_name"
    summary_analysis_action_name = action_prefix + "summary"
    settings_action_name = action_prefix + "settings"

    # Display names for menu items
    func_analysis_display_name = "Function Overall Analysis"
    decompilation_display_name = "Decompilation"
    specific_vars_analysis_display_name = "Select Variable Analysis"
    vars_analysis_display_name = "All Variable Analysis"
    args_analysis_display_name = "All Argument Analysis"
    funcname_analysis_display_name = "Function Name Recovery"
    summary_analysis_display_name = "Summary Analysis"
    settings_display_name = "Settings"

    def __init__(self):
        # PyArmor guards ignored
        super(ReCopilotPlugin, self).__init__()
        self.hooks = None
        # The class attributes for action names are defined directly in the bytecode's constant pool
        # for the ReCopilotPlugin object, not as instance attributes in __init__.
        # For clarity, I've moved them to class level above.


    def init(self):
        # PyArmor guards ignored
        print("\n==== ReCopilot Plugin Init ====")
        
        self.hooks = None # Initialized

        # Define actions
        actions = [
            (self.func_analysis_action_name, self.func_analysis_display_name, FuncAnalysisHandler(), "Ctrl+Shift+Alt+F", "Overall analysis for current function", 201),
            (self.decompilation_action_name, self.decompilation_display_name, DecompilationHandler(), "Ctrl+Shift+Alt+D", "Decompile function into source code", 201), # Icon example
            (self.specific_vars_analysis_action_name, self.specific_vars_analysis_display_name, SpecificVariableAnalysisHandler(), "Ctrl+Shift+Alt+V", "Analysis specific variables", 201),
            (self.vars_analysis_action_name, self.vars_analysis_display_name, AllVariableAnalysisHandler(), None, "Analysis all local variables and arguments", 201),
            (self.args_analysis_action_name, self.args_analysis_display_name, AllArgumentAnalysisHandler(), None, "Analysis all arguments", 201),
            (self.funcname_analysis_action_name, self.funcname_analysis_display_name, FuncNameAnalysisHandler(), None, "Generate meaningful function name", 201),
            (self.summary_analysis_action_name, self.summary_analysis_display_name, SummaryAnalysisHandler(), None, "Generate func summary and inline comments", 201),
            (self.settings_action_name, self.settings_display_name, ReCopilotSettingsHandler(), "Ctrl+Shift+Alt+S", "Configure ReCopilot settings", 156) # Example icon
        ]

        for name, label, handler_instance, hotkey, tooltip, icon in actions:
            if idaapi.register_action(idaapi.action_desc_t(name, f"ReCopilot: {label}", handler_instance, hotkey, tooltip, icon)):
                print(f"Registered action: {name}")
                if name == self.settings_action_name: # Settings usually go to a top-level menu
                     idaapi.attach_action_to_menu("Edit/ReCopilot/", name, idaapi.SETMENU_APP) # Or "Options/"
                # Other actions are typically added to context menus by ContextMenuHooks
            else:
                print(f"Failed to register action: {name}")
        
        # Setup context menu hooks
        self.hooks = ContextMenuHooks()
        if self.hooks.hook():
            print("[👏] ReCopilot UI hooks installed.")
        else:
            print("[!🐛] Failed to install ReCopilot UI hooks.")
            self.hooks = None

        print("[👏] ReCopilot init success")
        return ida_idaapi.PLUGIN_KEEP

    def term(self):
        # PyArmor guards ignored
        if self.hooks:
            self.hooks.unhook()
            print("ReCopilot UI hooks uninstalled.")
        print("==== ReCopilot Plugin Terminated ====")
        # Unregister actions if necessary (idaapi.unregister_action)
        # For each action registered: idaapi.unregister_action(self.action_name_variable)

    def run(self, arg):
        # PyArmor guards ignored
        # This method is often a no-op if functionality is exposed via actions/menus.
        # The bytecode shows it simply returns None.
        return None

class ContextMenuHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle):
        # PyArmor guards ignored
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type == ida_kernwin.BWN_PSEUDOCODE:
            # Add analysis actions to the Pseudocode view's context menu
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.func_analysis_action_name, "ReCopilot/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.decompilation_action_name, "ReCopilot/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.specific_vars_analysis_action_name, "ReCopilot/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.vars_analysis_action_name, "ReCopilot/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.args_analysis_action_name, "ReCopilot/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.funcname_analysis_action_name, "ReCopilot/")
            ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.summary_analysis_action_name, "ReCopilot/")
        
        # Always add settings (or add to specific views like disassembly, pseudocode)
        ida_kernwin.attach_action_to_popup(widget, popup_handle, ReCopilotPlugin.settings_action_name, "ReCopilot/")
        return 0


def PLUGIN_ENTRY():
    """IDA Pro's entry point for the plugin."""
    # PyArmor guards ignored
    return ReCopilotPlugin()