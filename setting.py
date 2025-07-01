
DEF_PROJECT_NAME = 'default_project'
DEF_CONFIG_RULES = "config_rules.yml"
DEF_CONFIG_OPENAI = 'config_verifier.yml'
DEF_CONFIG_MODELS = "config_models.yml"
DEF_CONFIG_AUDITOR = "config_auditor.yml"

DEF_EXCLUDES_KEYS = ['temp/compiled', '/vendor/', 'node_modules', '.well-known']

DEF_EXCLUDES_EXT = ['.git', '.svn', '.idea', '__pycache__', '.pyc', '.css',
                 '.tmp', '.exe', '.bin', '.dll', '.elf',
                 '.zip', '.rar', '.7z', '.gz', '.bz2', '.tar',
                 '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.svg'
                    ]

# 默认调用供应商
DEF_PROVIDER = 'Ollama'
# 默认调用模型
# DEF_MODEL_NAME = 'qwen-coder-plus-latest'
DEF_MODEL_NAMES = ["qwen3:32b"]