"""
RAG Manager Module - Manages retriever instances for all knowledge bases.

Provides a global singleton RAG manager that manages three types of knowledge bases:
- NodeJs: Node.js component type knowledge base
- rootcause: Vulnerability root cause knowledge base
- exploit: Attack step knowledge base
"""

import logging
import os
from pathlib import Path
from rag.vector_store import build_vectorstore, load_vectorstore
from config import KNOWLEDGE_BASE_PATHS

logger = logging.getLogger(__name__)


class RAGManager:
    """
    Globally shared RAG retriever and hierarchy manager (singleton pattern).
    
    Responsible for managing retrievers for three knowledge bases:
    - NodeJs: Node.js component type knowledge base
    - rootcause: Vulnerability root cause knowledge base
    - exploit: Attack step knowledge base
    
    Provides package name to category path mapping and hierarchy string construction functionality.
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
        """Get Node.js retriever instance."""
        return self._retriever_NodeJs

    @property
    def retriever_rootcause(self):
        """Get root cause retriever instance."""
        return self._retriever_rootcause

    @property
    def retriever_exploit(self):
        """Get exploit retriever instance."""
        return self._retriever_exploit

    def _check_vectorstore_exists(self) -> bool:
        """
        Check if vector store cache exists and is complete.
        
        Returns:
            bool: True if all vector stores exist and are complete, False otherwise
        """
        vectorstore_dir = Path("./vectorstore")
        if not vectorstore_dir.exists():
            logger.info("📂 Vector store directory does not exist")
            return False
        
        # Required vector store names
        required_stores = ["NodeJs", "rootcause", "exploit"]
        
        for store_name in required_stores:
            store_path = vectorstore_dir / store_name
            if not store_path.exists():
                logger.info(f"❌ Vector store {store_name} directory does not exist")
                return False
            
            # Check necessary files
            index_file = store_path / "index.faiss"
            pkl_file = store_path / "index.pkl"
            
            if not index_file.exists() or not pkl_file.exists():
                logger.info(f"❌ Vector store {store_name} files are incomplete")
                return False
        
        logger.info("✅ All vector store caches exist and are complete")
        return True

    def _load_vectorstores_from_cache(self, top_k: int = 8):
        """
        Load existing vector stores from cache.
        
        Args:
            top_k: Number of most relevant documents to return when retrieving
        """
        logger.info("📚 Loading vector stores from cache...")
        
        try:
            # Load Node.js vector store
            self._retriever_NodeJs = load_vectorstore(
                "NodeJs",
                top_k=top_k,
                doc_type="NodeJs"
            )
            logger.info("✅ Successfully loaded Node.js vector store")
            
            # Load root cause vector store
            self._retriever_rootcause = load_vectorstore(
                "rootcause",
                top_k=top_k,
                doc_type="rootcause"
            )
            logger.info("✅ Successfully loaded root cause vector store")
            
            # Load exploit vector store
            self._retriever_exploit = load_vectorstore(
                "exploit",
                top_k=top_k,
                doc_type="exploit"
            )
            logger.info("✅ Successfully loaded exploit vector store")
            
            # Rebuild index from vector store metadata
            self._build_package_category_index()
            self._build_hierarchy_str()
            
            logger.info(f"✅ Cache loading complete (top_k={top_k})")
            
        except Exception as e:
            logger.error(f"❌ Failed to load vector stores from cache: {e}")
            raise

    def _rebuild_from_source(self, top_k: int = 8):
        """
        Rebuild vector stores from source files.
        
        Note: According to your configuration, knowledge base paths are commented out.
        If cache does not exist, this will fail. This is expected behavior
        as we want to implement a pure vector store version.
        """
        logger.info("🔄 Attempting to rebuild vector stores from source files...")
        
        # According to your configuration, these paths may not exist
        nodejs_path = str(KNOWLEDGE_BASE_PATHS.get("NodeJstree", ""))
        rootcause_path = ""  # Your configuration does not have rootcause path
        exploit_path = ""     # Your configuration does not have exploit path
        
        logger.warning("⚠️ Knowledge base source file paths may not exist. This is expected behavior for pure vector store version")
        logger.warning("If rebuild fails, please ensure vector store cache already exists")
        
        # Attempt to rebuild Node.js vector store
        if nodejs_path and Path(nodejs_path).exists():
            self._retriever_NodeJs = build_vectorstore(
                nodejs_path,
                top_k=top_k,
                doc_type="NodeJs",
                force_rebuild=True
            )
        else:
            logger.error(f"Node.js knowledge base path does not exist: {nodejs_path}")
            raise FileNotFoundError("Cannot rebuild Node.js vector store: source file does not exist")
        
        # Root cause and exploit vector stores cannot be rebuilt (no configured paths)
        # This will fail, which is expected - forcing users to have cache
        logger.error("Root cause and exploit knowledge base paths are not configured, cannot rebuild")
        raise FileNotFoundError(
            "Cannot rebuild vector stores: knowledge base source file paths are not configured. "
            "Please ensure vector store cache already exists, or restore knowledge base file configuration."
        )

    def refresh_all(self, force_rebuild: bool = False):
        """
        Refresh all retrievers.
        
        Prioritize loading from cache. If cache does not exist or force rebuild is enabled,
        attempt to rebuild from source files.
        
        Args:
            force_rebuild: Whether to force rebuild (ignore cache)
        """
        logger.info("RAGManager: Reloading all retrievers...")
        
        top_k = 8
        
        # If not force rebuild, try loading from cache
        if not force_rebuild:
            if self._check_vectorstore_exists():
                try:
                    self._load_vectorstores_from_cache(top_k=top_k)
                    return
                except Exception as e:
                    logger.warning(f"Failed to load from cache, will attempt to rebuild from source: {e}")
            else:
                logger.info("Cache does not exist, will attempt to rebuild from source")
        
        # Rebuild from source
        # According to your configuration, this step will likely fail, which is by design
        # Aim is to force system to depend on vector store cache
        self._rebuild_from_source(top_k=top_k)
    
    def _build_package_category_index(self):
        """Build package name to category path mapping from root cause knowledge base."""
        if not self._retriever_rootcause:
            logger.warning("Root cause retriever is None, skipping package index build")
            return
        
        try:
            vectorstore = self._retriever_rootcause.vectorstore
            all_docs = list(vectorstore.docstore._dict.values())
            
            for doc in all_docs:
                package = doc.metadata.get("package")
                path = doc.metadata.get("path", "")
                if package and path:
                    self.package_to_category[package] = path
            
            logger.info(f"📊 Built {len(self.package_to_category)} package name to path mappings")
        except Exception as e:
            logger.error(f"Error building package index: {e}")
    
    def _build_hierarchy_str(self):
        """Build hierarchy string from NodeJs retriever."""
        if not self._retriever_NodeJs:
            self.hierarchy_str = "No hierarchy information available"
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
                logger.info(f"📊 Hierarchy construction complete, {len(paths)} nodes total")
            else:
                self.hierarchy_str = "No hierarchy information available"
        except Exception as e:
            logger.error(f"Error building hierarchy: {e}")
            self.hierarchy_str = "Hierarchy construction failed"
    
    def get_category_path_for_package(self, package_name: str) -> str:
        """
        Get category path for a package name.
        
        Args:
            package_name: npm package name
        
        Returns:
            Category path string, empty string if not found
        """
        return self.package_to_category.get(package_name, "")

    def get_hierarchy(self):
        """Get current hierarchy string."""
        return self.hierarchy_str