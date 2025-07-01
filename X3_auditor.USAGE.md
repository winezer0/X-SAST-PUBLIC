# X3_auditor 使用方法

## 工具简介

X3_auditor 是 人工审计工具 提供专业的审计界面，支持深入分析和确认.

## 基本使用方法

**请先下载 X3_auditor 所需的配置文件 config_auditor.yml**

进行参数配置后即可使用, 也可以在程序内进行配置.

## 配置参数说明

project 配置用于记录最后一次打开的分析结果文件.
```
project: # 记录最后一个
  analyse_file: C:/Users/project.d2fa80e5.checker.json  # 分析文件路径
  source_root: C:/Users/WINDOWS/Desktop/demo_app        # 分析源码的根目录  
```

X3_auditor 支持 在内置编辑器中AI调用分析代码, 因此也可以在其中配置自己的API和密钥, 兼容Openai库的平台均可使用. 考虑内置编辑器不支持调用流分析, 建议用户跳转到IDE中使用AI插件进行分析
```
providers:
  api_keys:
  - sk-xxxxxxxxxxxxxxxxxxx
  base_url: https://dashscope.aliyuncs.com/compatible-mode/v1
  model_name: qwen-plus
```

editors 是 调用外部编辑器打开漏洞代码文件, 该功能在进行代码流分析时是极其常用、有用的, 建议使用各语言的IDE、或VScode的.
```
editors:  
- editor_name: Notepad++    # 编辑器的名字
  args: -n {line} "{file}"  # 通过外部编辑器命令行打开指定代码文件所需的参数
  enabled: true             # 是否启用
  exe: notepad++.exe        # 编辑器的可执行文件名称
  full_path: ''             # 编辑器的可执行文件完整路径
  
- args: '"{file}"'          # 记事本不支持行数调转 只需要打开文件即可
  editor_name: 记事本
  enabled: true
  exe: notepad.exe
  full_path: ''
  
- args: -g "{file}:{line}"  # VSCODE支持打开行号
  editor_name: VSCode
  enabled: true
  exe: Code.exe
  full_path: C://vscode/app/Code.exe

- editor_name: PHPStorm     # PHPStorm是极其常用的PHP IDE
  args: --line {line} "{file}"
  enabled: true
  exe: phpstorm64.exe
  full_path: C:/Program Files/JetBrains/PhpStorm 2024.3.5/bin/phpstorm64.exe
```
