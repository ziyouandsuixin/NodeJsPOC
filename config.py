"""
Configuration Module - Most Closely Resembles Original Project

This module contains all configuration settings for the Node.js Security Analysis System:
- API keys and model settings
- Knowledge base paths
- Directory paths for uploads, logs, and results

Date: 2025
Version: 1.0.0
"""

import os
from pathlib import Path

# ========== API Configuration (Fully Maintained) ==========
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "your-api-key-here")
EMBED_MODEL = "text-embedding-3-small"
CHAT_MODEL = "gpt-5-chat-latest"

# ========== Project Root ==========
PROJECT_ROOT = Path(__file__).parent

# ========== Knowledge Base Paths (Strictly Corresponding) ==========
KNOWLEDGE_BASE_PATHS = {
    #"NodeJs": PROJECT_ROOT / "knowledge/NodeJs_types",      # ← Points to file
    #"rootcause": PROJECT_ROOT / "knowledge/rootcause",        # ← Points to file
    #"exploit": PROJECT_ROOT / "knowledge/ExploitBehavior", # ← Points to file
    "NodeJstree": PROJECT_ROOT
}

# ========== Directory and File Paths ==========
CONTRACTS_DIR = PROJECT_ROOT / "contracts"
LOG_FILE = PROJECT_ROOT / "logs/POC_agent.log"      # Log directory
OUTPUT_DIR = PROJECT_ROOT / "result"                # Output directory
UPLOAD_FOLDER = PROJECT_ROOT / "uploads"            # Upload directory

# ========== Ensure Directories Exist ==========
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
Path(LOG_FILE).parent.mkdir(parents=True, exist_ok=True)