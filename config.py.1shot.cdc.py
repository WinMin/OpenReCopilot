# Source Generated with Decompyle++
# File: config.py.1shot.seq (Python 3.12)

'__pyarmor_enter_54962__(...)'
import os
import json
GENERAL_MODEL_PROMPT_TEPLATE = '\n# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis.\n\n# Analysis Guides:\nThe following is the analysis guides for the user-specified task:\n{guide}\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\nStart analyzing:\n'
GENERAL_MODEL_PROMPT_TEPLATE_WITHOUT_GUIDE = '\n# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis. You need to analyze the binary function and output the analysis result in the specified format.\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\n# Output Format:\nDo your analysis first, then output the final result based on the analysis in the following format:\n```\n{format}\n```\n\nStart analyzing:\n'
GENERAL_MODEL_PROMPT_TEPLATE_VULN_DETECT_WITHOUT_GUIDE = '# Role:\nYou are a skilled software reverse engineer. \n\n# Context:\nThe user will provide you with a binary function and its context to be analyzed in pseudocode. And a task tag will be provided to specify the purpose of the analysis. You need to analyze the binary function and output the analysis result in the specified format.\n\n# Analysis Content:\nThe following is the binary function need to be analyzed and the other context information:\n```\n{input}\n```\n\n# Output Format:\nDo your analysis first, then output the final result based on the analysis in the following format:\n```\n{format}\n```\n\n# Additional Task:\n\nAfter the analysis, if you find a vulnerability in the binary function, you need to output the vulnerability information in the following format:\n\n```\n[🔴] Detected vulnerability: <name>\n[👉] Vulnerability details: \n......\n```\n\nStart analyzing:\n'
RECOPILOT_MODEL_PROMPT_TEPLATE = '{input}<Thought>'
RECOPILOT_MODEL_SUPERT_THOUGHT_PROMPT_TEPLATE = '{input}<Super-Thought>'
prompt_json_path = os.path.join(os.path.dirname(__file__), 'prompts.json')
if not os.path.exists(prompt_json_path):
    raise Exception(f'''[!💥] not found {prompt_json_path}''')
# WARNING: Decompyle incomplete
