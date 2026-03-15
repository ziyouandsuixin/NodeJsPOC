"""
RAG管理器模块 - 负责管理所有知识库的检索器实例。

提供全局单例的RAG管理器，管理三种类型的知识库：
- NodeJs: Node.js组件类型知识库
- rootcause: 漏洞根因知识库
- exploit: 攻击步骤知识库
"""

import logging
from rag.vector_store import build_vectorstore
from config import KNOWLEDGE_BASE_PATHS

logger = logging.getLogger(__name__)


class RAGManager:
    """
    全局共享的 RAG 检索器和层次结构管理器（单例模式）。
    
    负责管理三个知识库的检索器：
    - NodeJs: Node.js组件类型知识库
    - rootcause: 漏洞根因知识库
    - exploit: 攻击步骤知识库
    
    提供包名到类别路径的映射和层次结构字符串构建功能。
    """
    
    _instance = None
    hierarchy_str = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._retriever_NodeJs = None
            cls._instance._retriever_rootcause = None  
            cls._instance._retriever_exploit = None
            cls._instance.package_to_category = {}
        return cls._instance

    @property
    def retriever_NodeJs(self):
        """获取Node.js检索器实例。"""
        return self._retriever_NodeJs

    @property
    def retriever_rootcause(self):
        """获取根因检索器实例。"""
        return self._retriever_rootcause

    @property
    def retriever_exploit(self):
        """获取攻击步骤检索器实例。"""
        return self._retriever_exploit

    def refresh_all(self, force_rebuild: bool = False):
        """
        从知识库重新构建所有 RAG 索引。
        
        Args:
            force_rebuild: 是否强制重建（忽略缓存）
        """
        logger.info("RAGManager: 重新加载所有 retriever...")
        logger.info(f"📖 正在读取 NodeJs: {KNOWLEDGE_BASE_PATHS['NodeJs']}")
        logger.info(f"📖 正在读取 rootcause: {KNOWLEDGE_BASE_PATHS['rootcause']}")
        logger.info(f"📖 正在读取 exploit: {KNOWLEDGE_BASE_PATHS['exploit']}")
        
        top_k = 8
        
        self._retriever_NodeJs = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["NodeJs"],
            top_k=top_k,
            doc_type="NodeJs",
            force_rebuild=force_rebuild
        )
        self._retriever_rootcause = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["rootcause"],
            top_k=top_k,
            doc_type="rootcause",
            force_rebuild=force_rebuild
        )
        self._retriever_exploit = build_vectorstore(
            KNOWLEDGE_BASE_PATHS["exploit"],
            top_k=top_k,
            doc_type="exploit",
            force_rebuild=force_rebuild
        )
        
        self._build_package_category_index()
        self._build_hierarchy_str()
        
        logger.info(f"✅ RAGManager: 已完成刷新 (top_k={top_k})")
    
    def _build_package_category_index(self):
        """从根因知识库构建包名到类别路径的映射。"""
        if not self._retriever_rootcause:
            return
        
        vectorstore = self._retriever_rootcause.vectorstore
        all_docs = list(vectorstore.docstore._dict.values())
        
        for doc in all_docs:
            package = doc.metadata.get("package")
            path = doc.metadata.get("path", "")
            if package and path:
                self.package_to_category[package] = path
        
        logger.info(f"📊 构建了 {len(self.package_to_category)} 个包名到路径的映射")
    
    def _build_hierarchy_str(self):
        """从NodeJs检索器构建层次结构字符串。"""
        if not self._retriever_NodeJs:
            self.hierarchy_str = "无层次结构信息"
            return
        
        try:
            vectorstore = self._retriever_NodeJs.vectorstore
            all_docs = list(vectorstore.docstore._dict.values())
            
            paths = set()
            for doc in all_docs:
                path = doc.metadata.get("path", "")
                if path:
                    paths.add(path)
            
            if paths:
                sorted_paths = sorted(paths)
                tree_lines = []
                for path in sorted_paths:
                    indent_level = path.count("->")
                    indent = "  " * indent_level
                    display_name = path.split("->")[-1].strip()
                    tree_lines.append(f"{indent}- {display_name} ({path})")
                
                self.hierarchy_str = "\n".join(tree_lines)
                logger.info(f"📊 层次结构构建完成，共 {len(paths)} 个节点")
            else:
                self.hierarchy_str = "无层次结构信息"
        except Exception as e:
            logger.error(f"构建层次结构时出错: {e}")
            self.hierarchy_str = "层次结构构建失败"
    
    def get_category_path_for_package(self, package_name: str) -> str:
        """
        根据包名获取类别路径。
        
        Args:
            package_name: npm包名
        
        Returns:
            类别路径字符串，如果不存在返回空字符串
        """
        return self.package_to_category.get(package_name, "")

    def get_hierarchy(self):
        """获取当前层次结构字符串。"""
        return self.hierarchy_str