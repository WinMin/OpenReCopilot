import requests
import json
from config import settings_manager # Assuming this is the ReCopilotSettingsManager from previous decompilation
import uuid
import time
import os
import sys # Imported but not directly used in the visible logic of this decompiled part
import platform
import hashlib
import threading
import traceback

# PyArmor related calls would be here in original bytecode, ignored for decompilation
# __assert_armored__ = ...
# __pyarmor_enter_...
# __pyarmor_exit_...

# Load PLUGIN_VERSION from ida-plugin.json
PLUGIN_VERSION = None
try:
    _fp = os.path.join(os.path.dirname(__file__), 'ida-plugin.json')
    with open(_fp, 'r') as f:
        data = json.load(f)
    PLUGIN_VERSION = data.get('plugin', {}).get('version') # Defaults to None if keys missing
except Exception:
    # In debug mode, one might print an error here
    if hasattr(settings_manager, 'settings') and settings_manager.settings.get('debug_mode'):
        traceback.print_exc()
        print("[!🐛] Error loading plugin version from ida-plugin.json")


def get_machine_id():
    """Generates a unique machine ID based on various system parameters."""
    # PyArmor guards ignored
    info_list = [
        platform.node(),
        platform.machine(),
        platform.processor(),
        str(uuid.getnode()),
        platform.system(),
        platform.version(),
    ]
    combined_info = "".join(info_list)
    hashed_info = hashlib.sha256(combined_info.encode()).hexdigest()
    return hashed_info

def is_debug_mode():
    """Checks if the application is in debug mode based on settings."""
    # PyArmor guards ignored
    try:
        return settings_manager.settings.get('debug_mode', False)
    except: # Broad except if settings_manager or settings itself is not fully initialized
        return False


def _send_feedback_thread(feedback_data):
    """
    Sends feedback data to the server in a separate thread.
    This function is intended to be the target of a threading.Thread.
    """
    # PyArmor guards ignored
    if is_debug_mode():
        print('[DEBUG🐛] invoke send_feedback (thread)')

    feedback_url = 'https://recopilot-feedback.qianxin.com/api/feedback'
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json'
    }
    try:
        response = requests.post(feedback_url, json=feedback_data, headers=headers, timeout=3)
        if is_debug_mode():
            if 200 <= response.status_code <= 299:
                print('[🔗] Feedback send successfully')
            else:
                print(f'[!🔗] Failed to send feedback: status_code={response.status_code}')
    except Exception as e:
        if is_debug_mode():
            traceback.print_exc()
            print(f'[!🔗] Unexpected error in sending feedback: {str(e)}')

def send_feedback(prompt, model_response, accept_response, task_tag):
    """
    Send feedback data to the server asynchronously.

    Args:
        prompt: The input prompt given to the model.
        model_response: The original response from the model.
        accept_response: The response that was accepted/modified by the user.
        task_tag: The type of analysis task performed.

    Returns:
        bool: True if feedback thread was started, False otherwise.
    """
    # PyArmor guards ignored
    try:
        base_url_val = settings_manager.settings.get('base_url', 'N/A')
        model_name_val = settings_manager.settings.get('model_name', 'N/A')

        payload = {
            'machine_id': get_machine_id(),
            'timestamp': time.time(),
            'base_url': base_url_val,
            'model_name': model_name_val,
            'task_tag': task_tag,
            'prompt': prompt,
            'model_response': model_response, # Assuming this is already a string or simple type
            'accept_response': json.dumps(accept_response), # accept_response might be structured
            'plugin_version': PLUGIN_VERSION
        }

        thread = threading.Thread(target=_send_feedback_thread, args=(payload,))
        thread.daemon = True  # Allows main program to exit even if thread is running
        thread.start()
        return True
    except Exception as e:
        if is_debug_mode():
            traceback.print_exc()
            print(f'[!🔗] Error preparing feedback data: {str(e)}')
        return False