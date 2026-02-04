# config.py - 最接近原项目的版本
import os
from pathlib import Path

# API配置（完全保持）
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
EMBED_MODEL = "text-embedding-3-small"
CHAT_MODEL = "gpt-5-chat-latest"

PROJECT_ROOT = Path(__file__).parent

# 知识库路径（严格对应）
KNOWLEDGE_BASE_PATHS = {
    "NodeJs": PROJECT_ROOT / "knowledge/NodeJs_types",      
    "rootcause": PROJECT_ROOT / "knowledge/rootcause",  # ← rootcause
    "exploit": PROJECT_ROOT / "knowledge/ExploitBehavior",    # ← exploit（不变）
    "NodeJstree": PROJECT_ROOT
}

CONTRACTS_DIR = PROJECT_ROOT/"contracts"         
LOG_FILE = PROJECT_ROOT/"logs/POC_agent.log"     # 日志目录
OUTPUT_DIR = PROJECT_ROOT/"result"               # 输出目录
UPLOAD_FOLDER = PROJECT_ROOT/"uploads"         # 上传目录

# 确保目录存在
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)