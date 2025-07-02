# X2_verifier 使用方法

## 工具简介

X2_verifier 是一个基于人工智能的静态应用安全测试(SAST)工具，它不仅包含了 X1_checker 的所有功能，还增加了 AI 辅助验证能力。该工具可以直接对代码进行扫描，并利用 AI 模型对扫描结果进行智能分析和验证，减少误报，提高安全漏洞检测的准确性。

## 基本使用方法

### 进行AI配置

**请先下载 X2_verifier 所需的配置文件 config_verifier.yml**

并在其中配置自己的API和密钥, 兼容Openai库的平台均可使用.

建议使用 阿里云通义百炼平台, 新用户可以免费使用半年, 每种模型免费额度 100w tokens

### 直接扫描代码

```
python X2_verifier.py -p [项目路径] -n [项目名称]
```

### 验证已有扫描结果

```
python X2_verifier.py -p [初步扫描结果文件] -n [项目名称]
```

### 示例

```
python X2_verifier.py -p /path/to/your/project -n MyProject
python X2_verifier.py -p scan_results.json -n MyProject
```

## 参数详解

### 核心参数

| 参数 | 全称 | 说明 |
|-----|-----|-----|
| `-p` | `--project-file` | 初步规则检查结果文件或项目路径 |
| `-n` | `--project-name` | 项目名称 |
| `-o` | `--output` | 自定义输出文件路径 |
| `-r` | `--rules-file` | 规则文件路径，默认为`config_rules.yml` |

### AI模型参数

| 参数 | 全称 | 说明 |
|-----|-----|-----|
| `-c` | `--config-file` | 配置文件路径信息，默认为`config_verifier.yml` |
| `-d` | `--provider-name` | 使用的AI接口名称，默认为`Ollama` |
| `-m` | `--model-names` | 需要使用的模型列表，默认为`['qwen3:32b']` |
| `-t` | `--prompt-name` | 提示词模板名称，默认为`default` |
| `-M` | `--config-models` | 缓存模型信息文件，默认为`config_models.yml` |
| `-u` | `--update-models` | 更新所有模型，默认为`False` |
| `-k` | `--check-model` | 进行模型连接测试，默认为`False` |

### 性能优化参数

| 参数 | 全称 | 说明 |
|-----|-----|-----|
| `-w` | `--workers` | 线程数，默认为CPU核心数 |
| `-s` | `--save-cache` | 缓存分析结果，默认为`True` |
| `-K` | `--chunk-mode` | 分块读取文件，默认为`False` |
| `-z` | `--limit-size` | 限制检查文件大小 |

### 过滤参数

| 参数 | 全称 | 说明 |
|-----|-----|-----|
| `-L` | `--filter-lang` | 仅扫描指定语言的漏洞（例如：ANY PHP JAVA） |
| `-R` | `--filter-risk` | 仅扫描指定风险的漏洞（例如：HIGH MEDIUM LOW） |
| `-N` | `--filter-vuln` | 仅扫描指定漏洞的规则（例如："SQL Injection"） |
| `-F` | `--filter-file` | 仅扫描指定文件的规则（例如："admin/login.php"） |
| `-E` | `--exclude-keys` | 扫描排除路径关键字 |
| `-e` | `--exclude-ext` | 扫描排除文件后缀 |
| `-b` | `--black-key` | 扫描排除内容关键字，支持简单的`||`和`&&`语法 |

### 高级分析参数

| 参数 | 全称 | 说明 |
|-----|-----|-----|
| `-P` | `--parsed-file` | 项目代码的语法解析结果文件 |
| `-C` | `--call-parser` | 自动进行代码解析，默认为`False` |
| `-f` | `--import-filter` | 启用导入信息过滤，默认为`False` |

## 优化使用方案

### 基础扫描流程

直接使用 X2_verifier 进行完整的扫描和验证：

```
python X2_verifier.py -p [项目路径] -n [项目名称] -o verified_results.json
```

### 使用不同AI模型进行验证

```
python X2_verifier.py -p [项目路径] -n [项目名称] -d OpenAI -m gpt-4-turbo gpt-3.5-turbo
```

### 针对高风险漏洞的扫描和验证

```
python X2_verifier.py -p [项目路径] -n [项目名称] -R HIGH
```

### 针对特定类型漏洞的扫描和验证

```
python X2_verifier.py -p [项目路径] -n [项目名称] -N "SQL Injection" "XSS"
```

### 高性能扫描配置

对于大型项目，推荐使用以下参数组合：

```
python X2_verifier.py -p [项目路径] -n [项目名称] -w 8 -s -K -E node_modules vendor -z 10485760
```

- `-w 8`: 使用8个工作线程（根据服务器性能调整）
- `-s`: 缓存分析结果，加速重复验证
- `-K`: 启用分块模式，减少内存占用
- `-E node_modules vendor`: 排除第三方库目录
- `-z 10485760`: 限制扫描文件大小为10MB

## 高级用法

### 自定义提示词模板

在`config_verifier.yml`中定义自定义提示词模板，然后使用`-t`参数指定：

```
python X2_verifier.py -p [项目路径] -n [项目名称] -t custom_prompt
```

### 代码解析提高准确性

```
python X2_verifier.py -p [项目路径] -n [项目名称] -C -f
```

- `-C`: 启用自动代码解析，提高检测准确性
- `-f`: 启用导入信息过滤，减少误报

### 分阶段扫描和验证

如果需要分阶段进行，可以：

1. 先进行基础扫描：
   ```
   python X2_verifier.py -p [项目路径] -n [项目名称] -o initial_scan.json -d none
   ```

2. 再进行AI验证：
   ```
   python X2_verifier.py -p initial_scan.json -n [项目名称] -o verified_results.json
   ```

## 最佳实践

1. **初次扫描**：首次扫描项目时，建议不使用过滤，全面了解项目的安全状况
   ```
   python X2_verifier.py -p [项目路径] -n [项目名称] -s
   ```

2. **定期全面扫描**：每周或每月进行一次全面扫描
   ```
   python X2_verifier.py -p [项目路径] -n [项目名称] -s -o weekly_scan_$(date +%Y%m%d).json
   ```

3. **代码提交前扫描**：在代码提交前进行针对性扫描，关注高风险漏洞
   ```
   python X2_verifier.py -p [项目路径] -n [项目名称] -R HIGH MEDIUM
   ```

4. **CI/CD流水线集成**：在持续集成流程中添加安全扫描
   ```
   python X2_verifier.py -p [项目路径] -n [项目名称] -w $(nproc) -E vendor node_modules -f
   ```

5. **模型选择建议**：
   - 对于小型项目：使用轻量级模型如 `llama3:8b`
   - 对于重要项目：使用高精度模型如 `qwen3:32b` 或 `gpt-4-turbo`

## 常见问题解决

1. **扫描速度慢**：增加工作线程数 `-w`，启用缓存 `-s`，排除不必要的目录 `-E`
2. **内存占用高**：启用分块模式 `-K`，限制文件大小 `-z`
3. **误报过多**：使用 `-C -f` 启用代码解析和导入过滤，使用 `-b` 排除特定内容
4. **AI模型连接问题**：使用 `-k` 参数测试模型连接状态
5. **特定语言支持**：使用 `-L` 参数指定需要扫描的语言

## 总结

X2_verifier 是一个强大的静态应用安全测试工具，集成了规则扫描和 AI 验证能力。通过合理配置参数，可以实现高效、准确的代码安全扫描。根据项目规模和扫描需求，选择合适的参数组合，可以显著提高扫描效率和结果准确性。
