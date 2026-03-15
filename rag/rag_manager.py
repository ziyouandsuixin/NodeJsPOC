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
            # 新增：包名到类别路径的映射
            cls._instance.package_to_category = {}
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
        
        # ===== 新增：构建包名到类别路径的映射 =====
        self._build_package_category_index()
        
        # ===== 新增：构建层次结构字符串（现在真正赋值）=====
        self._build_hierarchy_str()
        
        print("✅ RAGManager: 已完成刷新。")
    
    # ===== 新增方法：构建包名索引 =====
    def _build_package_category_index(self):
        """从根因知识库构建包名到类别路径的映射"""
        if not self._retriever_rootcause:
            return
        
        vectorstore = self._retriever_rootcause.vectorstore
        all_docs = list(vectorstore.docstore._dict.values())
        
        for doc in all_docs:
            package = doc.metadata.get("package")
            path = doc.metadata.get("path", "")
            if package and path:
                self.package_to_category[package] = path
        
        print(f"📊 构建了 {len(self.package_to_category)} 个包名到路径的映射")
    
    # ===== 新增方法：构建层次结构 =====
    def _build_hierarchy_str(self):
        """从NodeJs检索器构建层次结构字符串"""
        if not self._retriever_NodeJs:
            self.hierarchy_str = "无层次结构信息"
            return
        
        try:
            vectorstore = self._retriever_NodeJs.vectorstore
            all_docs = list(vectorstore.docstore._dict.values())
            
            # 提取所有路径
            paths = set()
            for doc in all_docs:
                path = doc.metadata.get("path", "")
                if path:
                    paths.add(path)
            
            # 格式化成易读的树
            if paths:
                # 按层级排序
                sorted_paths = sorted(paths)
                tree_lines = []
                for path in sorted_paths:
                    # 计算缩进（根据箭头数量）
                    indent_level = path.count("->")
                    indent = "  " * indent_level
                    # 取最后一部分作为显示名
                    display_name = path.split("->")[-1].strip()
                    tree_lines.append(f"{indent}- {display_name} ({path})")
                
                self.hierarchy_str = "\n".join(tree_lines)
                print(f"📊 层次结构构建完成，共 {len(paths)} 个节点")
            else:
                self.hierarchy_str = "无层次结构信息"
        except Exception as e:
            print(f"⚠️ 构建层次结构时出错: {e}")
            self.hierarchy_str = "层次结构构建失败"
    
    # ===== 新增方法：获取包名的类别路径 =====
    def get_category_path_for_package(self, package_name: str) -> str:
        """根据包名获取类别路径"""
        return self.package_to_category.get(package_name, "")

    def get_hierarchy(self):
        """获取当前层次结构"""
        return self.hierarchy_str