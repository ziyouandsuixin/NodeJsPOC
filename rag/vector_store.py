"""
Vector Store Module - Handles loading, building, and querying vector stores for knowledge bases.

Provides functionality for:
- Loading JSON knowledge bases and converting to documents
- Building FAISS vector stores with caching
- Performing enhanced RAG queries with multiple retrieval strategies
- Performance monitoring and logging
"""

import logging
import json
import glob
import os
import hashlib
import time
from typing import List, Dict, Any, Optional
from pathlib import Path
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain_community.retrievers import BM25Retriever

from config import OPENAI_API_KEY, EMBED_MODEL, KNOWLEDGE_BASE_PATHS

logger = logging.getLogger(__name__)


def extract_entries(data: Any, entries_list: List[Dict]) -> None:
    """
    Recursively traverse JSON data to extract all entries as dictionaries.
    
    Args:
        data: Current data node being processed
        entries_list: List to store all extracted entries
    """
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        entries_list.append(item)
                    extract_entries(item, entries_list)
            elif isinstance(value, dict):
                extract_entries(value, entries_list)
    elif isinstance(data, list):
        for item in data:
            extract_entries(item, entries_list)


def get_path_for_entry(entry: Dict, name_to_entry: Dict[str, Dict]) -> List[str]:
    """
    Recursively build the complete hierarchy path for an entry based on its category.
    
    Args:
        entry: Current entry dictionary
        name_to_entry: Mapping from names to entries
    
    Returns:
        Path list from root to current entry (e.g., ['NPM', 'Packages', 'Express'])
    """
    name = entry.get("name")
    category = entry.get("category", "")
    
    if not category or category == name or category == "Base":
        return ["NPM", name]
    else:
        if category in name_to_entry:
            parent_entry = name_to_entry[category]
            parent_path = get_path_for_entry(parent_entry, name_to_entry)
            return parent_path + [name]
        else:
            logger.debug(f"Category '{category}' not found for entry '{name}'. Treating as root-level.")
            return ["NPM", name]


def get_knowledge_version(knowledge_dir: str) -> str:
    """
    Calculate knowledge base version based on file modification times.
    
    Args:
        knowledge_dir: Path to knowledge base directory
    
    Returns:
        Version hash (8-character hexadecimal string)
    """
    json_files = glob.glob(os.path.join(knowledge_dir, "*.json"))
    if not json_files:
        return "unknown"
    
    timestamps = []
    for f in sorted(json_files):
        try:
            mtime = os.path.getmtime(f)
            timestamps.append(str(mtime))
        except Exception as e:
            logger.warning(f"Unable to get file modification time: {f}, {e}")
    
    if not timestamps:
        return "unknown"
    
    version_str = "|".join(timestamps)
    return hashlib.md5(version_str.encode()).hexdigest()[:8]


# ============ Knowledge Base Loaders ============

def load_json_files_to_docs_NodeJs(dir_path: str) -> List[Document]:
    """Load Node.js type knowledge base."""
    logger.info(f"NodeJs loader: {dir_path}")
    
    if not os.path.exists(dir_path) or not os.listdir(dir_path):
        logger.warning(f"NodeJs knowledge base directory is empty: {dir_path}")
        return [Document(
            page_content="Node.js type knowledge base is empty. Please add NodeJs_types.json file",
            metadata={"name": "empty_NodeJs", "category": "Base", "type": "NodeJs"}
        )]
    
    docs = []
    json_files = glob.glob(os.path.join(dir_path, "*.json"))
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            entries_list = []
            extract_entries(data, entries_list)
            name_to_entry = {entry.get("name", ""): entry for entry in entries_list}
            
            for entry in entries_list:
                path = get_path_for_entry(entry, name_to_entry)
                
                doc_content = f"Path: {' -> '.join(path)}\n"
                doc_content += f"Name: {entry.get('name', '')}\n"
                doc_content += f"Category: {entry.get('category', '')}\n"
                doc_content += f"Pattern: {entry.get('pattern', '')}\n"
                doc_content += f"Symptoms: {', '.join(entry.get('symptoms', []))}\n"
                doc_content += f"Related Exploit: {', '.join(entry.get('related_exploit', []))}"
                
                doc = Document(
                    page_content=doc_content,
                    metadata={
                        "name": entry.get("name", ""),
                        "category": entry.get("category", ""),
                        "path": " -> ".join(path),
                        "type": "NodeJs"
                    }
                )
                docs.append(doc)
                
        except Exception as e:
            logger.error(f"Failed to load NodeJs JSON file {json_file}: {e}")
    
    logger.info(f"NodeJs loader: Loaded {len(docs)} documents from {len(json_files)} JSON files")
    return docs


def load_json_files_to_docs_Vulnerability(dir_path: str) -> List[Document]:
    """Load vulnerability type knowledge base."""
    logger.info(f"Vulnerability loader: {dir_path}")
    
    if not os.path.exists(dir_path) or not os.listdir(dir_path):
        logger.warning(f"Vulnerability knowledge base directory is empty: {dir_path}")
        return [Document(
            page_content="Vulnerability knowledge base is empty. Please add Rootcause.json file",
            metadata={"name": "empty_vulnerability", "category": "Base", "type": "Vulnerability"}
        )]
    
    docs = []
    json_files = glob.glob(os.path.join(dir_path, "*.json"))
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            entries_list = []
            extract_entries(data, entries_list)
            name_to_entry = {entry.get("name", ""): entry for entry in entries_list}
            
            for entry in entries_list:
                path = get_path_for_entry(entry, name_to_entry)
                
                vuln_type = entry.get('vuln_type', [])
                if isinstance(vuln_type, list):
                    vuln_type_str = json.dumps(vuln_type, ensure_ascii=False)
                else:
                    vuln_type_str = str(vuln_type)
                
                doc_content = f"Path: {' -> '.join(path)}\n"
                doc_content += f"Name: {entry.get('name', '')}\n"
                doc_content += f"Package: {entry.get('package', '')}\n"
                doc_content += f"Category: {entry.get('category', '')}\n"
                doc_content += f"VulnType: {vuln_type_str}\n"
                doc_content += f"Pattern: {entry.get('pattern', '')}\n"
                doc_content += f"Symptoms: {', '.join(entry.get('symptoms', []))}\n"
                doc_content += f"Related Exploit: {', '.join(entry.get('related_exploit', []))}"
                
                doc = Document(
                    page_content=doc_content,
                    metadata={
                        "name": entry.get("name", ""),
                        "category": entry.get("category", ""),
                        "package": entry.get("package", ""),
                        "vuln_type": vuln_type_str,
                        "path": " -> ".join(path),
                        "type": "Vulnerability"
                    }
                )
                docs.append(doc)
                
        except Exception as e:
            logger.error(f"Failed to load Vulnerability JSON file {json_file}: {e}")
    
    logger.info(f"Vulnerability loader: Loaded {len(docs)} documents from {len(json_files)} JSON files")
    return docs


def load_json_files_to_docs_Exploit(dir_path: str) -> List[Document]:
    """Load exploit knowledge base."""
    logger.info(f"Exploit loader: {dir_path}")
    
    if not os.path.exists(dir_path) or not os.listdir(dir_path):
        logger.warning(f"Exploit knowledge base directory is empty: {dir_path}")
        return [Document(
            page_content="Exploit knowledge base is empty. Please add ExploitBehavior.json file",
            metadata={"name": "empty_exploit", "category": "Base", "type": "Exploit"}
        )]
    
    docs = []
    json_files = glob.glob(os.path.join(dir_path, "*.json"))
    
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            entries_list = []
            extract_entries(data, entries_list)
            name_to_entry = {entry.get("name", ""): entry for entry in entries_list}
            
            for entry in entries_list:
                path = get_path_for_entry(entry, name_to_entry)
                
                doc_content = f"Path: {' -> '.join(path)}\n"
                doc_content += f"Name: {entry.get('name', '')}\n"
                doc_content += f"Category: {entry.get('category', '')}\n"
                doc_content += f"Description: {entry.get('description', '')}\n"
                doc_content += f"Impact: {entry.get('impact', '')}\n"
                doc_content += f"Steps: {entry.get('steps', '')}\n"
                
                applicable_to = entry.get('applicable_to', [])
                if applicable_to:
                    doc_content += f"applicable_to: {json.dumps(applicable_to, ensure_ascii=False)}\n"
                
                sample_code = entry.get('SampleCode', [])
                if sample_code:
                    doc_content += f"SampleCode: {json.dumps(sample_code, ensure_ascii=False)}\n"
                
                doc = Document(
                    page_content=doc_content,
                    metadata={
                        "name": entry.get("name", ""),
                        "category": entry.get("category", ""),
                        "path": " -> ".join(path),
                        "type": "Exploit",
                        "applicable_to": applicable_to
                    }
                )
                docs.append(doc)
                
        except Exception as e:
            logger.error(f"Failed to load Exploit JSON file {json_file}: {e}")
    
    logger.info(f"Exploit loader: Loaded {len(docs)} documents from {len(json_files)} JSON files")
    return docs


# ============ Vector Store Building ============

def build_vectorstore(knowledge_dir: str, top_k: int = 5, doc_type: str = "NodeJs", force_rebuild: bool = False):
    """
    Build vector store for the corresponding directory.
    
    Args:
        knowledge_dir: Path to knowledge base directory
        top_k: Maximum number of documents to return when retrieving
        doc_type: Document type ("NodeJs" | "rootcause" | "exploit")
        force_rebuild: Whether to force rebuild (ignore cache)
    
    Returns:
        FAISS retriever instance
    """
    cache_dir = Path("./vectorstore")
    cache_dir.mkdir(exist_ok=True)
    
    version_file = cache_dir / f"{doc_type}_version.txt"
    cache_path = cache_dir / doc_type
    
    current_version = get_knowledge_version(knowledge_dir)
    
    version_match = False
    if version_file.exists():
        try:
            with open(version_file, 'r', encoding='utf-8') as f:
                cached_version = f.read().strip()
                version_match = (cached_version == current_version)
        except Exception as e:
            logger.warning(f"Failed to read version file: {e}")
    
    if not force_rebuild and version_match and cache_path.exists():
        logger.info(f"📦 Loading cached {doc_type} vector store (version: {current_version})")
        embeddings = OpenAIEmbeddings(
            model=EMBED_MODEL,
            openai_api_key=OPENAI_API_KEY,
            openai_api_base="https://api.gpt.ge/v1/",
            default_headers={"x-foo": "true"}
        )
        try:
            vectorstore = FAISS.load_local(str(cache_path), embeddings)
            logger.info(f"✅ Successfully loaded {doc_type} vector store")
            return vectorstore.as_retriever(search_kwargs={"k": top_k})
        except Exception as e:
            logger.warning(f"Failed to load cache, will rebuild: {e}")
    
    logger.info(f"🔨 Rebuilding {doc_type} vector store (version: {current_version})...")
    
    loader_map = {
        "NodeJs": load_json_files_to_docs_NodeJs,
        "rootcause": load_json_files_to_docs_Vulnerability,
        "exploit": load_json_files_to_docs_Exploit
    }
    
    if doc_type not in loader_map:
        raise ValueError(f"Unsupported document type: {doc_type}")
    
    docs = loader_map[doc_type](knowledge_dir)
    logger.info(f"[VectorStore] {doc_type} knowledge base, document count: {len(docs)}")

    if not docs:
        raise ValueError(f"No documents loaded from {knowledge_dir}. Please check JSON file structure.")
    
    embeddings = OpenAIEmbeddings(
        model=EMBED_MODEL,
        openai_api_key=OPENAI_API_KEY,
        openai_api_base="https://api.gpt.ge/v1/",
        default_headers={"x-foo": "true"}
    )
    
    vectorstore = FAISS.from_documents(docs, embeddings)
    
    logger.info(f"💾 Saving {doc_type} vector store to cache: {cache_path}")
    vectorstore.save_local(str(cache_path))
    
    try:
        with open(version_file, 'w', encoding='utf-8') as f:
            f.write(current_version)
        logger.info(f"📝 Saved version information: {current_version}")
    except Exception as e:
        logger.warning(f"Failed to save version information: {e}")
    
    return vectorstore.as_retriever(search_kwargs={"k": top_k})


def _log_performance(elapsed: float, step_times: dict, step_hits: dict, total_hits: int) -> None:
    """
    Log detailed performance monitoring information.
    
    Args:
        elapsed: Total elapsed time (seconds)
        step_times: Dictionary of step times
        step_hits: Dictionary of step hit counts
        total_hits: Total hit count
    """
    perf_lines = ["⏱️ Performance Monitoring:"]
    
    if 'step0_package' in step_times:
        hits = step_hits.get('step0_package', 0)
        perf_lines.append(f"   ├─ Step0 Package Name Match: {step_times['step0_package']:.2f}s, Hits: {hits}")
    
    if 'step1_vector' in step_times:
        hits = step_hits.get('step1_vector', 0)
        api_calls = step_hits.get('step1_api_calls', 0)
        perf_lines.append(f"   ├─ Step1 Vector Retrieval: {step_times['step1_vector']:.2f}s, Hits: {hits} (API Calls: {api_calls})")
    
    if 'step2_exact' in step_times:
        hits = step_hits.get('step2_exact', 0)
        perf_lines.append(f"   ├─ Step2 Exact Match: {step_times['step2_exact']:.2f}s, Hits: {hits}")
    
    if 'step3_bm25' in step_times:
        hits = step_hits.get('step3_bm25', 0)
        perf_lines.append(f"   ├─ Step3 BM25: {step_times['step3_bm25']:.2f}s, Hits: {hits}")
    
    perf_lines.append(f"   └─ Total: {elapsed:.2f}s, Final Hits: {total_hits}")
    
    logger.info("\n".join(perf_lines))


# ============ RAG Query =============

def enhanced_rag_query(
    query: str, 
    retriever, 
    keywords: List[str], 
    max_docs: int = 4,
    category_path: Optional[str] = None,
    package_name: Optional[str] = None
) -> List[Document]:
    """
    Execute enhanced RAG query combining multiple retrieval strategies.
    
    Retrieval strategy priority:
    1. Package Name Exact Match - If package_name provided, prioritize matching metadata package field
    2. Vector Retrieval - Semantic similarity search using FAISS
    3. Exact Match - Match vuln_type field, Category.Name format, or full name
    4. BM25 Retrieval - Keyword-based statistical fallback
    
    Args:
        query: Query string
        retriever: FAISS retriever instance
        keywords: List of keywords for exact matching and BM25
        max_docs: Maximum number of documents to return
        category_path: Category path for pre-filtering
        package_name: Package name for exact matching
    
    Returns:
        List of matched documents
    """
    start_time = time.time()
    step_times = {}
    step_hits = {}
    
    if retriever is None:
        logger.warning("Retriever is None, returning empty list")
        return []
    
    vectorstore = retriever.vectorstore
    all_docs = list(vectorstore.docstore._dict.values())
    
    if not all_docs or (len(all_docs) == 1 and "empty" in str(all_docs[0].metadata.get("name", ""))):
        logger.info("Knowledge base is empty, skipping exact matching")
        try:
            step_start = time.time()
            docs = vectorstore.similarity_search(query, k=max_docs)
            step_times['vector_only'] = time.time() - step_start
            elapsed = time.time() - start_time
            logger.info(f"⏱️ Performance: Vector Retrieval={step_times['vector_only']:.2f}s, Total={elapsed:.2f}s, Hits={len(docs)}")
            return docs
        except Exception:
            return []
    
    seen = set()
    final_matches = []

    # Step0: Package Name Exact Match
    step_start = time.time()
    package_matches = 0
    if package_name:
        logger.info(f"🔍 Step0: Package Name Exact Match: {package_name}")
        for doc in all_docs:
            if doc.metadata.get("package") == package_name:
                key = doc.metadata.get("name") or doc.page_content[:30]
                if key not in seen:
                    final_matches.append(doc)
                    seen.add(key)
                    package_matches += 1
        
        step_times['step0_package'] = time.time() - step_start
        step_hits['step0_package'] = package_matches
        
        if package_matches > 0:
            logger.info(f"   ✅ Package name matched {package_matches} documents")
            if len(final_matches) >= max_docs:
                elapsed = time.time() - start_time
                _log_performance(elapsed, step_times, step_hits, len(final_matches))
                return final_matches[:max_docs]
    else:
        step_times['step0_package'] = time.time() - step_start
        step_hits['step0_package'] = 0

    # Step1: Vector Retrieval
    step_start = time.time()
    logger.info("🔍 Step1: Vector Retrieval (Semantic Similarity)")
    vector_added = 0
    api_calls = 0
    
    try:
        if category_path:
            filtered_docs = [
                doc for doc in all_docs
                if doc.metadata.get("path", "").startswith(category_path)
            ]
            
            if filtered_docs:
                temp_vectorstore = FAISS.from_documents(filtered_docs, vectorstore.embeddings)
                vector_docs = temp_vectorstore.similarity_search(query, k=max_docs)
                api_calls += 1
            else:
                vector_docs = vectorstore.similarity_search(query, k=max_docs)
                api_calls += 1
        else:
            vector_docs = vectorstore.similarity_search(query, k=max_docs)
            api_calls += 1
        
        for doc in vector_docs:
            key = doc.metadata.get("name") or doc.page_content[:30]
            if key not in seen:
                final_matches.append(doc)
                seen.add(key)
                vector_added += 1
                if len(final_matches) >= max_docs:
                    break
        
        step_times['step1_vector'] = time.time() - step_start
        step_hits['step1_vector'] = vector_added
        step_hits['step1_api_calls'] = api_calls
        
        logger.info(f"   ✅ Vector retrieval added {vector_added} new documents")
        
        if len(final_matches) >= max_docs:
            elapsed = time.time() - start_time
            _log_performance(elapsed, step_times, step_hits, len(final_matches))
            return final_matches[:max_docs]
            
    except Exception as e:
        step_times['step1_vector'] = time.time() - step_start
        step_hits['step1_vector'] = 0
        logger.warning(f"Vector retrieval failed: {e}")

    # Step2: Exact Match
    step_start = time.time()
    logger.info("🔍 Step2: Exact Match (Keywords)")
    exact_added = 0
    
    for kw in keywords:
        kw_lower = kw.lower()

        # Match vuln_type field
        for doc in all_docs:
            vuln_type_str = doc.metadata.get("vuln_type", "")
            if vuln_type_str and kw_lower in vuln_type_str.lower():
                key = doc.metadata.get("name") or doc.page_content[:30]
                if key not in seen:
                    final_matches.append(doc)
                    seen.add(key)
                    exact_added += 1
                    if len(final_matches) >= max_docs:
                        break
            if len(final_matches) >= max_docs:
                break
        if len(final_matches) >= max_docs:
            break

        # "Category.Name" format match
        if "." in kw:
            parts = kw.split(".")
            if len(parts) == 2:
                category, item_name = parts[0].lower(), parts[1].lower()
                for doc in all_docs:
                    if (doc.metadata.get("category", "").lower() == category and
                        doc.metadata.get("name", "").lower() == item_name):
                        key = f"{doc.metadata.get('category')}.{doc.metadata.get('name')}"
                        if key not in seen:
                            final_matches.append(doc)
                            seen.add(key)
                            exact_added += 1
                            if len(final_matches) >= max_docs:
                                break
                if len(final_matches) >= max_docs:
                    break
        else:
            # Full name match
            for doc in all_docs:
                if doc.metadata.get("name", "").lower() == kw_lower:
                    if doc.metadata.get("name") not in seen:
                        final_matches.append(doc)
                        seen.add(doc.metadata.get("name"))
                        exact_added += 1
                        if len(final_matches) >= max_docs:
                            break
            if len(final_matches) >= max_docs:
                break

    step_times['step2_exact'] = time.time() - step_start
    step_hits['step2_exact'] = exact_added
    
    if exact_added > 0:
        logger.info(f"   ✅ Exact match added {exact_added} new documents")
    
    if len(final_matches) >= max_docs:
        elapsed = time.time() - start_time
        _log_performance(elapsed, step_times, step_hits, len(final_matches))
        return final_matches[:max_docs]

    # Step3: BM25 Retrieval
    step_start = time.time()
    logger.info("🔍 Step3: BM25 Retrieval (Fallback)")
    bm25_added = 0
    
    if len(final_matches) < max_docs:
        try:
            bm25_retriever = BM25Retriever.from_documents(all_docs)
            bm25_docs = bm25_retriever.invoke(" ".join(keywords))
            for d in bm25_docs:
                key = d.metadata.get("name") or d.page_content[:30]
                if key not in seen:
                    final_matches.append(d)
                    seen.add(key)
                    bm25_added += 1
                if len(final_matches) >= max_docs:
                    break
        except Exception as e:
            logger.warning(f"BM25 retrieval failed: {e}")
    
    step_times['step3_bm25'] = time.time() - step_start
    step_hits['step3_bm25'] = bm25_added
    
    if bm25_added > 0:
        logger.info(f"   ✅ BM25 retrieval added {bm25_added} new documents")

    elapsed = time.time() - start_time
    _log_performance(elapsed, step_times, step_hits, len(final_matches))
    
    logger.info(f"[RAG] query='{query[:100]}...' Final document count={len(final_matches)}")
    
    return final_matches


def load_vectorstore(store_name: str, top_k: int = 5, doc_type: str = "NodeJs"):
    """
    Load existing vector store from cache.
    
    Args:
        store_name: Vector store name (e.g., "nodejs_type", "rootcause", "exploit")
        top_k: Maximum number of documents to return when retrieving
        doc_type: Document type for logging
    
    Returns:
        FAISS retriever instance
    """
    cache_dir = Path("./vectorstore")
    cache_path = cache_dir / store_name
    
    if not cache_path.exists():
        logger.error(f"Vector store cache does not exist: {cache_path}")
        raise FileNotFoundError(f"Vector store cache does not exist: {cache_path}")
    
    logger.info(f"📦 Loading {doc_type} vector store from cache: {cache_path}")
    
    embeddings = OpenAIEmbeddings(
        model=EMBED_MODEL,
        openai_api_key=OPENAI_API_KEY,
        openai_api_base="https://api.gpt.ge/v1/",
        default_headers={"x-foo": "true"}
    )
    
    try:
        vectorstore = FAISS.load_local(str(cache_path), embeddings)
        logger.info(f"✅ Successfully loaded {doc_type} vector store")
        return vectorstore.as_retriever(search_kwargs={"k": top_k})
    except Exception as e:
        logger.error(f"Failed to load vector store {cache_path}: {e}")
        raise