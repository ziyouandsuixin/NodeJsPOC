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
    递归遍历JSON数据，提取所有作为条目的字典。
    
    Args:
        data: 当前正在处理的数据节点
        entries_list: 存储所有提取的条目的列表
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
    递归地根据category字段构建条目的完整层次路径。
    
    Args:
        entry: 当前条目字典
        name_to_entry: 名称到条目的映射
    
    Returns:
        从根到当前条目的路径列表（如 ['NPM', 'Packages', 'Express']）
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
    计算知识库的版本（基于文件修改时间）。
    
    Args:
        knowledge_dir: 知识库目录路径
    
    Returns:
        版本哈希值（8位十六进制字符串）
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
            logger.warning(f"无法获取文件修改时间: {f}, {e}")
    
    if not timestamps:
        return "unknown"
    
    version_str = "|".join(timestamps)
    return hashlib.md5(version_str.encode()).hexdigest()[:8]


# ============ 知识库加载器 ============

def load_json_files_to_docs_NodeJs(dir_path: str) -> List[Document]:
    """加载Node.js类型知识库。"""
    logger.info(f"NodeJs loader: {dir_path}")
    
    if not os.path.exists(dir_path) or not os.listdir(dir_path):
        logger.warning(f"NodeJs知识库目录为空: {dir_path}")
        return [Document(
            page_content="Node.js类型知识库为空，请添加NodeJs_types.json文件",
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
            logger.error(f"加载NodeJs JSON文件失败 {json_file}: {e}")
    
    logger.info(f"NodeJs加载器: 从 {len(json_files)} 个JSON文件加载了 {len(docs)} 个文档")
    return docs


def load_json_files_to_docs_Vulnerability(dir_path: str) -> List[Document]:
    """加载漏洞类型知识库。"""
    logger.info(f"Vulnerability loader: {dir_path}")
    
    if not os.path.exists(dir_path) or not os.listdir(dir_path):
        logger.warning(f"Vulnerability知识库目录为空: {dir_path}")
        return [Document(
            page_content="漏洞知识库为空，请添加Rootcause.json文件",
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
            logger.error(f"加载Vulnerability JSON文件失败 {json_file}: {e}")
    
    logger.info(f"Vulnerability加载器: 从 {len(json_files)} 个JSON文件加载了 {len(docs)} 个文档")
    return docs


def load_json_files_to_docs_Exploit(dir_path: str) -> List[Document]:
    """加载攻击利用知识库。"""
    logger.info(f"Exploit loader: {dir_path}")
    
    if not os.path.exists(dir_path) or not os.listdir(dir_path):
        logger.warning(f"Exploit知识库目录为空: {dir_path}")
        return [Document(
            page_content="攻击利用知识库为空，请添加ExploitBehavior.json文件",
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
            logger.error(f"加载Exploit JSON文件失败 {json_file}: {e}")
    
    logger.info(f"Exploit加载器: 从 {len(json_files)} 个JSON文件加载了 {len(docs)} 个文档")
    return docs


# ============ 向量库构建 ============

def build_vectorstore(knowledge_dir: str, top_k: int = 5, doc_type: str = "NodeJs", force_rebuild: bool = False):
    """
    构建对应目录的向量库。
    
    Args:
        knowledge_dir: 知识库目录路径
        top_k: 检索返回的最大文档数
        doc_type: 文档类型 ("NodeJs" | "rootcause" | "exploit")
        force_rebuild: 是否强制重建（忽略缓存）
    
    Returns:
        FAISS检索器实例
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
            logger.warning(f"读取版本文件失败: {e}")
    
    if not force_rebuild and version_match and cache_path.exists():
        logger.info(f"📦 加载缓存的 {doc_type} 向量库 (版本: {current_version})")
        embeddings = OpenAIEmbeddings(
            model=EMBED_MODEL,
            openai_api_key=OPENAI_API_KEY,
            openai_api_base="https://api.gpt.ge/v1/",
            default_headers={"x-foo": "true"}
        )
        try:
            vectorstore = FAISS.load_local(str(cache_path), embeddings)
            logger.info(f"✅ 成功加载 {doc_type} 向量库")
            return vectorstore.as_retriever(search_kwargs={"k": top_k})
        except Exception as e:
            logger.warning(f"加载缓存失败，将重建: {e}")
    
    logger.info(f"🔨 重建 {doc_type} 向量库 (版本: {current_version})...")
    
    loader_map = {
        "NodeJs": load_json_files_to_docs_NodeJs,
        "rootcause": load_json_files_to_docs_Vulnerability,
        "exploit": load_json_files_to_docs_Exploit
    }
    
    if doc_type not in loader_map:
        raise ValueError(f"不支持的文档类型: {doc_type}")
    
    docs = loader_map[doc_type](knowledge_dir)
    logger.info(f"[VectorStore] {doc_type}知识库，文档数: {len(docs)}")

    if not docs:
        raise ValueError(f"未在 {knowledge_dir} 加载到任何文档，请检查 JSON 文件结构")
    
    embeddings = OpenAIEmbeddings(
        model=EMBED_MODEL,
        openai_api_key=OPENAI_API_KEY,
        openai_api_base="https://api.gpt.ge/v1/",
        default_headers={"x-foo": "true"}
    )
    
    vectorstore = FAISS.from_documents(docs, embeddings)
    
    logger.info(f"💾 保存 {doc_type} 向量库到缓存: {cache_path}")
    vectorstore.save_local(str(cache_path))
    
    try:
        with open(version_file, 'w', encoding='utf-8') as f:
            f.write(current_version)
        logger.info(f"📝 保存版本信息: {current_version}")
    except Exception as e:
        logger.warning(f"保存版本信息失败: {e}")
    
    return vectorstore.as_retriever(search_kwargs={"k": top_k})


def _log_performance(elapsed: float, step_times: dict, step_hits: dict, total_hits: int) -> None:
    """
    记录详细的性能监控日志。
    
    Args:
        elapsed: 总耗时（秒）
        step_times: 各步骤耗时字典
        step_hits: 各步骤命中数字典
        total_hits: 总命中数
    """
    perf_lines = ["⏱️ 性能监控:"]
    
    if 'step0_package' in step_times:
        hits = step_hits.get('step0_package', 0)
        perf_lines.append(f"   ├─ Step0 包名匹配: {step_times['step0_package']:.2f}秒, 命中 {hits} 条")
    
    if 'step1_vector' in step_times:
        hits = step_hits.get('step1_vector', 0)
        api_calls = step_hits.get('step1_api_calls', 0)
        perf_lines.append(f"   ├─ Step1 向量检索: {step_times['step1_vector']:.2f}秒, 命中 {hits} 条 (API调用: {api_calls}次)")
    
    if 'step2_exact' in step_times:
        hits = step_hits.get('step2_exact', 0)
        perf_lines.append(f"   ├─ Step2 精确匹配: {step_times['step2_exact']:.2f}秒, 命中 {hits} 条")
    
    if 'step3_bm25' in step_times:
        hits = step_hits.get('step3_bm25', 0)
        perf_lines.append(f"   ├─ Step3 BM25: {step_times['step3_bm25']:.2f}秒, 命中 {hits} 条")
    
    perf_lines.append(f"   └─ 总计: {elapsed:.2f}秒, 最终命中 {total_hits} 条")
    
    logger.info("\n".join(perf_lines))


# ============ RAG 检索 =============

def enhanced_rag_query(
    query: str, 
    retriever, 
    keywords: List[str], 
    max_docs: int = 4,
    category_path: Optional[str] = None,
    package_name: Optional[str] = None
) -> List[Document]:
    """
    执行增强的RAG查询，结合多种检索策略。
    
    检索策略优先级：
    1. 包名精确匹配 - 如果提供了package_name，优先匹配metadata中的package字段
    2. 向量检索 - 使用FAISS进行语义相似度搜索
    3. 精确匹配 - 匹配vuln_type字段、Category.Name格式、完整name
    4. BM25检索 - 基于关键词统计的兜底方案
    
    Args:
        query: 查询字符串
        retriever: FAISS检索器实例
        keywords: 关键词列表，用于精确匹配和BM25
        max_docs: 最大返回文档数
        category_path: 类别路径，用于预过滤
        package_name: 包名，用于精确匹配
    
    Returns:
        匹配的文档列表
    """
    start_time = time.time()
    step_times = {}
    step_hits = {}
    
    if retriever is None:
        logger.warning("Retriever 为 None，返回空列表")
        return []
    
    vectorstore = retriever.vectorstore
    all_docs = list(vectorstore.docstore._dict.values())
    
    if not all_docs or (len(all_docs) == 1 and "empty" in str(all_docs[0].metadata.get("name", ""))):
        logger.info("知识库为空，跳过精确匹配")
        try:
            step_start = time.time()
            docs = vectorstore.similarity_search(query, k=max_docs)
            step_times['vector_only'] = time.time() - step_start
            elapsed = time.time() - start_time
            logger.info(f"⏱️ 性能监控: 向量检索={step_times['vector_only']:.2f}秒, 总计={elapsed:.2f}秒, 命中={len(docs)}条")
            return docs
        except Exception:
            return []
    
    seen = set()
    final_matches = []

    # Step0: 按包名精确匹配
    step_start = time.time()
    package_matches = 0
    if package_name:
        logger.info(f"🔍 Step0: 按包名精确匹配: {package_name}")
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
            logger.info(f"   ✅ 包名匹配到 {package_matches} 个文档")
            if len(final_matches) >= max_docs:
                elapsed = time.time() - start_time
                _log_performance(elapsed, step_times, step_hits, len(final_matches))
                return final_matches[:max_docs]
    else:
        step_times['step0_package'] = time.time() - step_start
        step_hits['step0_package'] = 0

    # Step1: 向量检索
    step_start = time.time()
    logger.info("🔍 Step1: 向量检索 (语义相似度)")
    vector_hits_before = len(final_matches)
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
        
        vector_added = 0
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
        
        logger.info(f"   ✅ 向量检索新增 {vector_added} 个文档")
        
        if len(final_matches) >= max_docs:
            elapsed = time.time() - start_time
            _log_performance(elapsed, step_times, step_hits, len(final_matches))
            return final_matches[:max_docs]
            
    except Exception as e:
        step_times['step1_vector'] = time.time() - step_start
        step_hits['step1_vector'] = 0
        logger.warning(f"向量检索失败: {e}")

    # Step2: 精确匹配
    step_start = time.time()
    logger.info("🔍 Step2: 精确匹配 (关键词)")
    exact_added = 0
    
    for kw in keywords:
        kw_lower = kw.lower()

        # 匹配 vuln_type 字段
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

        # "Category.Name" 格式匹配
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
            # 完整匹配 name
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
        logger.info(f"   ✅ 精确匹配新增 {exact_added} 个文档")
    
    if len(final_matches) >= max_docs:
        elapsed = time.time() - start_time
        _log_performance(elapsed, step_times, step_hits, len(final_matches))
        return final_matches[:max_docs]

    # Step3: BM25 检索
    step_start = time.time()
    logger.info("🔍 Step3: BM25 检索 (兜底)")
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
            logger.warning(f"BM25检索失败: {e}")
    
    step_times['step3_bm25'] = time.time() - step_start
    step_hits['step3_bm25'] = bm25_added
    
    if bm25_added > 0:
        logger.info(f"   ✅ BM25检索新增 {bm25_added} 个文档")

    elapsed = time.time() - start_time
    _log_performance(elapsed, step_times, step_hits, len(final_matches))
    
    logger.info(f"[RAG] query='{query[:100]}...' 最终命中文档数={len(final_matches)}")
    
    return final_matches