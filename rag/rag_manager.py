# rag/rag_manager.py
import json
from rag.vector_store import build_vectorstore
from utils.file_utils import load_nodejs_types_hierarchy  
from config import KNOWLEDGE_BASE_PATHS, PROJECT_ROOT

class RAGManager:
    """全局共享的 RAG 检索器和层次结构管理器（单例）"""
    _instance = None
    hierarchy_str = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # 初始化私有属性
            cls._instance._retriever_NodeJs = None
            cls._instance._retriever_rootcause = None  
            cls._instance._retriever_exploit = None
            cls._instance.refresh_all()  # 初始化加载
        return cls._instance

    @property
    def retriever_NodeJs(self):
        """对外只读访问"""
        return self._retriever_NodeJs

    @property
    def retriever_rootcause(self):
        return self._retriever_rootcause

    @property
    def retriever_exploit(self):
        return self._retriever_exploit

    def refresh_all(self):
        """从知识库重新构建所有 RAG 索引"""
        print("RAGManager: 重新加载所有 retriever...")
        # 在 RAGManager.refresh_all() 里加
        print(f"📖 正在读取 NodeJs: {KNOWLEDGE_BASE_PATHS['NodeJs']}")
        print(f"📖 正在读取 rootcause: {KNOWLEDGE_BASE_PATHS['rootcause']}")
        print(f"📖 正在读取 exploit: {KNOWLEDGE_BASE_PATHS['exploit']}")
        # ✅ 改为给私有属性赋值
        self._retriever_NodeJs = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["NodeJs"],
            top_k=5,
            doc_type="NodeJs"
        )
        self._retriever_rootcause = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["rootcause"],
            top_k=5,
            doc_type="rootcause"
        )
        self._retriever_exploit = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["exploit"],
            top_k=5,
            doc_type="exploit"
        )
        
        print("✅ RAGManager: 已完成刷新。")

    def get_hierarchy(self):
        """获取当前层次结构"""
        return self.hierarchy_str