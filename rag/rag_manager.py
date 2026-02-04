# rag/rag_manager.py
import json
from rag.vector_store import build_vectorstore
from utils.file_utils import load_nodejs_types_hierarchy  
from config import KNOWLEDGE_BASE_PATHS, PROJECT_ROOT

class RAGManager:
    """全局共享的 RAG 检索器和层次结构管理器（单例）"""
    _instance = None
    retriever_NodeJs = None       
    retriever_rootcause = None    
    retriever_exploit = None     
    hierarchy_str = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.refresh_all()  # 初始化加载
        return cls._instance

    def refresh_all(self):
        """从知识库重新构建所有 RAG 索引"""
        print("RAGManager: 重新加载所有 retriever...")
        
        # 构建三个retriever（适配Node.js项目）
        self.retriever_NodeJs = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["NodeJs"],
            top_k=5,
            doc_type="NodeJs"
        )
        self.retriever_rootcause = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["rootcause"],
            top_k=5,
            doc_type="rootcause"
        )
        self.retriever_exploit = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["exploit"],
            top_k=5,
            doc_type="exploit"
        )
        

        print("✅ RAGManager: 已完成刷新。")

    def get_hierarchy(self):
        """获取当前层次结构"""
        return self.hierarchy_str
