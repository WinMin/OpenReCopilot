# Reverse Engineering Work Directory

本目录包含 ReCopilot IDA Pro 插件的逆向工程分析文件。

## 目录结构

### ori-recopilot-py312/
原始的 ReCopilot 插件文件（Python 3.12 版本）。包含被 PyArmor 混淆保护的字节码文件，是逆向工程的源材料。

主要文件：
- `*.py` - PyArmor 混淆后的 Python 字节码文件
- `pyarmor_runtime_009239/` - PyArmor 运行时库
- `prompts.json` - 提示词模板配置
- `ida-plugin.json` - IDA 插件配置
- `PRIVACY_POLICY/` - 隐私政策文档

### cdc/
使用 **Decompyle++** 反编译的结果。文件后缀为 `.1shot.cdc.py`。

这是最易读的反编译输出，接近原始 Python 源代码形式，但由于 PyArmor 混淆，部分代码可能不完整（存在 `# WARNING: Decompyle incomplete` 注释）。

### das/
**反汇编（Disassembly）** 输出。文件后缀为 `.1shot.das`。

包含 Python 字节码的详细信息，包括：
- Code 对象元数据（参数数量、栈大小、标志位等）
- Names 列表（变量名、函数名、模块名）
- Constants（常量值）
- 字节码指令序列

适合深度分析字节码行为和理解混淆机制。

### seq/
原始的 **PyArmor 序列化字节码**。文件后缀为 `.1shot.seq`。

包含混淆后的原始字节码数据，其中嵌入了部分可见的字符串常量（如提示词模板）。这是最接近原始混淆文件的形式。

## 文件对照

每个原始 `.py` 文件在三个分析目录中都有对应的输出：

| 原始文件 | cdc (反编译) | das (反汇编) | seq (序列化字节码) |
|---------|-------------|-------------|-------------------|
| checker.py | checker.py.1shot.cdc.py | checker.py.1shot.das | checker.py.1shot.seq |
| config.py | config.py.1shot.cdc.py | config.py.1shot.das | config.py.1shot.seq |
| data_flow.py | data_flow.py.1shot.cdc.py | data_flow.py.1shot.das | data_flow.py.1shot.seq |
| ext_info.py | ext_info.py.1shot.cdc.py | ext_info.py.1shot.das | ext_info.py.1shot.seq |
| feedback.py | feedback.py.1shot.cdc.py | feedback.py.1shot.das | feedback.py.1shot.seq |
| handler.py | handler.py.1shot.cdc.py | handler.py.1shot.das | handler.py.1shot.seq |
| recopilot.py | recopilot.py.1shot.cdc.py | recopilot.py.1shot.das | recopilot.py.1shot.seq |
| recopilot_qt.py | recopilot_qt.py.1shot.cdc.py | recopilot_qt.py.1shot.das | recopilot_qt.py.1shot.seq |
| remote_model.py | remote_model.py.1shot.cdc.py | remote_model.py.1shot.das | remote_model.py.1shot.seq |
| task_guides.py | task_guides.py.1shot.cdc.py | task_guides.py.1shot.das | task_guides.py.1shot.seq |

## 分析建议

1. 从 `cdc/` 目录的反编译结果开始阅读，获取代码逻辑概览
2. 遇到不完整的反编译时，参考 `das/` 目录的反汇编输出理解字节码行为
3. `seq/` 目录可用于提取字符串常量和分析混淆结构
