import logging
import json
import glob
import os
import hashlib
from typing import List, Dict, Any, Optional
from pathlib import Path
from langchain_core.documents import Document
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings
from langchain_community.retrievers import BM25Retriever

from config import OPENAI_API_KEY, EMBED_MODEL, KNOWLEDGE_BASE_PATHS

logger = logging.getLogger(__name__)

# Helper function to recursively提取所有条目（dict）从JSON数据中
def extract_entries(data: Any, entries_list: List[Dict]):
    """
    递归遍历JSON数据，提取所有作为条目的字典（通常位于列表中）。
    :param data: 当前正在处理的数据节点
    :param entries_list: 存储所有提取的条目的列表
    """
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        entries_list.append(item)  # 添加条目到列表
                    # 递归处理列表中的元素，以防有嵌套结构
                    extract_entries(item, entries_list)
            elif isinstance(value, dict):
                extract_entries(value, entries_list)  # 递归处理字典
    elif isinstance(data, list):
        for item in data:
            extract_entries(item, entries_list)  # 递归处理列表

def get_path_for_entry(entry: Dict, name_to_entry: Dict[str, Dict]) -> List[str]:
    """
    递归地根据'category'字段构建条目的完整层次路径。
    :param entry: 当前条目字典
    :param name_to_entry: 名称到条目的映射
    :return: 从根到当前条目的路径列表（如 ['NPM', 'Packages', 'Express']）
    """
    name = entry.get("name")
    category = entry.get("category", "")
    
    # 如果category缺失、与name相同或是'Base'，视为根层级条目
    if not category or category == name or category == "Base":
        return ["NPM", name]  # 统一使用'NPM'作为根
    else:
        if category in name_to_entry:
            parent_entry = name_to_entry[category]
            parent_path = get_path_for_entry(parent_entry, name_to_entry)
            return parent_path + [name]
        else:
            # 如果父类别不存在，记录警告并视为根层级
            logger.debug(f"Category '{category}' not found for entry '{name}'. Treating as root-level.")
            return ["NPM", name]  # 统一使用'NPM'

def get_knowledge_version(knowledge_dir: str) -> str:
    """计算知识库的版本（基于文件修改时间）"""
    json_files = glob.glob(os.path.join(knowledge_dir, "*.json"))
    if not json_files:
        return "unknown"
    
    # 计算所有文件的最后修改时间的哈希
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

# ============ loader: NodeJs ============
def load_json_files_to_docs_NodeJs(dir_path: str) -> List[Document]:
    """Node.js类型知识加载器"""
    logger.info(f"NodeJs loader: {dir_path}")
    
    # 如果是空目录，返回提示文档
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
            
            # 提取所有条目
            entries_list = []
            extract_entries(data, entries_list)
            
            # 构建名称到条目的映射
            name_to_entry = {entry.get("name", ""): entry for entry in entries_list}
            
            for entry in entries_list:
                # 构建完整路径
                path = get_path_for_entry(entry, name_to_entry)
                
                # 创建文档
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

# ============ loader: Vulnerability ============
def load_json_files_to_docs_Vulnerability(dir_path: str) -> List[Document]:
    """漏洞类型知识加载器"""
    logger.info(f"Vulnerability loader: {dir_path}")
    
    # 如果是空目录，返回提示文档
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
            
            # 提取所有条目
            entries_list = []
            extract_entries(data, entries_list)
            
            # 构建名称到条目的映射
            name_to_entry = {entry.get("name", ""): entry for entry in entries_list}
            
            for entry in entries_list:
                # 构建完整路径
                path = get_path_for_entry(entry, name_to_entry)
                
                # 处理 vuln_type 字段（可能是列表）
                vuln_type = entry.get('vuln_type', [])
                if isinstance(vuln_type, list):
                    vuln_type_str = json.dumps(vuln_type, ensure_ascii=False)
                else:
                    vuln_type_str = str(vuln_type)
                
                # 创建文档 - Vulnerability只有这些字段
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

# ============ loader: Exploit ============
def load_json_files_to_docs_Exploit(dir_path: str) -> List[Document]:
    """攻击利用知识加载器"""
    logger.info(f"Exploit loader: {dir_path}")
    
    # 如果是空目录，返回提示文档
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
            
            # 提取所有条目
            entries_list = []
            extract_entries(data, entries_list)
            
            # 构建名称到条目的映射
            name_to_entry = {entry.get("name", ""): entry for entry in entries_list}
            
            for entry in entries_list:
                # 构建完整路径
                path = get_path_for_entry(entry, name_to_entry)
                
                # 创建文档 - 完整包含所有字段
                doc_content = f"Path: {' -> '.join(path)}\n"
                doc_content += f"Name: {entry.get('name', '')}\n"
                doc_content += f"Category: {entry.get('category', '')}\n"
                doc_content += f"Description: {entry.get('description', '')}\n"
                doc_content += f"Impact: {entry.get('impact', '')}\n"
                doc_content += f"Steps: {entry.get('steps', '')}\n"
                
                # 添加 applicable_to
                applicable_to = entry.get('applicable_to', [])
                if applicable_to:
                    doc_content += f"applicable_to: {json.dumps(applicable_to, ensure_ascii=False)}\n"
                
                # 添加 SampleCode
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

# ============ 构建 Vectorstore ============
def build_vectorstore(knowledge_dir: str, top_k: int = 5, doc_type: str = "NodeJs", force_rebuild: bool = False):
    """
    构建对应目录的向量库
    :param doc_type: "NodeJs" | "rootcause" | "exploit"
    :param force_rebuild: 是否强制重建（忽略缓存）
    """
    # 缓存路径
    cache_dir = Path("./vectorstore")
    cache_dir.mkdir(exist_ok=True)
    
    # 版本文件路径
    version_file = cache_dir / f"{doc_type}_version.txt"
    cache_path = cache_dir / doc_type
    
    # 获取当前知识库版本
    current_version = get_knowledge_version(knowledge_dir)
    
    # 检查版本是否匹配
    version_match = False
    if version_file.exists():
        try:
            with open(version_file, 'r', encoding='utf-8') as f:
                cached_version = f.read().strip()
                version_match = (cached_version == current_version)
        except Exception as e:
            logger.warning(f"读取版本文件失败: {e}")
    
    # 如果不强制重建、版本匹配且缓存存在，直接加载
    if not force_rebuild and version_match and cache_path.exists():
        logger.info(f"📦 加载缓存的 {doc_type} 向量库 (版本: {current_version})")
        embeddings = OpenAIEmbeddings(
            model=EMBED_MODEL,
            openai_api_key=OPENAI_API_KEY,
            openai_api_base="https://api.gpt.ge/v1/",
            default_headers={"x-foo":"true"}
        )
        try:
            vectorstore = FAISS.load_local(str(cache_path), embeddings)
            logger.info(f"✅ 成功加载 {doc_type} 向量库")
            return vectorstore.as_retriever(search_kwargs={"k": top_k})
        except Exception as e:
            logger.warning(f"加载缓存失败，将重建: {e}")
            # 加载失败，继续重建
    
    # 否则重新构建
    logger.info(f"🔨 重建 {doc_type} 向量库 (版本: {current_version})...")
    
    # 根据doc_type调用对应的加载器
    if doc_type == "NodeJs":
        docs = load_json_files_to_docs_NodeJs(knowledge_dir)
    elif doc_type == "rootcause":
        docs = load_json_files_to_docs_Vulnerability(knowledge_dir)
    elif doc_type == "exploit":
        docs = load_json_files_to_docs_Exploit(knowledge_dir)
    else:
        raise ValueError(f"Unsupported document type: {doc_type}")
    
    logger.info(f"[VectorStore] {doc_type}知识库，文档数: {len(docs)}")

    if not docs:
        raise ValueError(f"未在 {knowledge_dir} 加载到任何文档，请检查 JSON 文件结构")
    
    embeddings = OpenAIEmbeddings(
        model=EMBED_MODEL,
        openai_api_key=OPENAI_API_KEY,
        openai_api_base="https://api.gpt.ge/v1/",
        default_headers={"x-foo":"true"}
    )
    
    vectorstore = FAISS.from_documents(docs, embeddings)
    
    # 保存到缓存
    logger.info(f"💾 保存 {doc_type} 向量库到缓存: {cache_path}")
    vectorstore.save_local(str(cache_path))
    
    # 保存版本信息
    try:
        with open(version_file, 'w', encoding='utf-8') as f:
            f.write(current_version)
        logger.info(f"📝 保存版本信息: {current_version}")
    except Exception as e:
        logger.warning(f"保存版本信息失败: {e}")
    
    return vectorstore.as_retriever(search_kwargs={"k": top_k})

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
    优化后的 RAG 查询：
    0. 按包名精确匹配（最快，最准）- 如果有包名，优先匹配
    1. 向量检索（语义相似度）- 主要检索手段
    2. 精确匹配（关键词匹配）- 补充匹配
    3. BM25 检索（关键词统计）- 最后兜底
    
    包含详细的性能监控，每个步骤的耗时都会被记录
    """
    import time
    start_time = time.time()
    step_times = {}
    step_hits = {}
    
    # 空retriever测试用
    if retriever is None:
        logger.warning(f"Retriever 为 None，返回空列表")
        return []
    
    vectorstore = retriever.vectorstore
    all_docs = list(vectorstore.docstore._dict.values())
    
    # 如果是空知识库（只有虚拟文档）
    if not all_docs or (len(all_docs) == 1 and "empty" in str(all_docs[0].metadata.get("name", ""))):
        logger.info("知识库为空，跳过精确匹配")
        try:
            step_start = time.time()
            docs = vectorstore.similarity_search(query, k=max_docs)
            step_times['vector_only'] = time.time() - step_start
            elapsed = time.time() - start_time
            logger.info(f"⏱️ 性能监控: 向量检索={step_times['vector_only']:.2f}秒, 总计={elapsed:.2f}秒, 命中={len(docs)}条")
            return docs
        except:
            return []
    
    # 用于去重
    seen = set()
    final_matches = []

    # ---------- Step0: 按包名精确匹配（最快，最准）----------
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

    # ---------- Step1: 向量检索（语义相似度，主要手段）----------
    step_start = time.time()
    logger.info(f"🔍 Step1: 向量检索 (语义相似度)")
    vector_hits_before = len(final_matches)
    api_calls = 0
    
    try:
        # 如果有包名但没匹配到，可能是新包，用向量检索
        # 如果有类别路径，可以优化检索范围
        if category_path:
            # 先按类别路径过滤，再向量检索
            filtered_docs = []
            for doc in all_docs:
                doc_path = doc.metadata.get("path", "")
                if doc_path and doc_path.startswith(category_path):
                    filtered_docs.append(doc)
            
            if filtered_docs:
                # 在过滤后的文档中向量检索
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

    # ---------- Step2: 精确匹配（关键词匹配，补充）----------
    step_start = time.time()
    logger.info(f"🔍 Step2: 精确匹配 (关键词)")
    exact_added = 0
    
    for kw in keywords:
        kw_lower = kw.lower()

        # 2.1 匹配 vuln_type 字段
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

        # 2.2 "Category.Name" 格式
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
            # 2.3 完整匹配 name
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

    # ---------- Step3: BM25 检索（关键词统计，最后兜底）----------
    step_start = time.time()
    logger.info(f"🔍 Step3: BM25 检索 (兜底)")
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


def _log_performance(elapsed: float, step_times: dict, step_hits: dict, total_hits: int):
    """记录详细的性能监控日志"""
    
    # 构建性能日志
    perf_lines = ["⏱️ 性能监控:"]
    
    # Step0
    if 'step0_package' in step_times:
        hits = step_hits.get('step0_package', 0)
        perf_lines.append(f"   ├─ Step0 包名匹配: {step_times['step0_package']:.2f}秒, 命中 {hits} 条")
    
    # Step1
    if 'step1_vector' in step_times:
        hits = step_hits.get('step1_vector', 0)
        api_calls = step_hits.get('step1_api_calls', 0)
        perf_lines.append(f"   ├─ Step1 向量检索: {step_times['step1_vector']:.2f}秒, 命中 {hits} 条 (API调用: {api_calls}次)")
    
    # Step2
    if 'step2_exact' in step_times:
        hits = step_hits.get('step2_exact', 0)
        perf_lines.append(f"   ├─ Step2 精确匹配: {step_times['step2_exact']:.2f}秒, 命中 {hits} 条")
    
    # Step3
    if 'step3_bm25' in step_times:
        hits = step_hits.get('step3_bm25', 0)
        perf_lines.append(f"   ├─ Step3 BM25: {step_times['step3_bm25']:.2f}秒, 命中 {hits} 条")
    
    # 总计
    perf_lines.append(f"   └─ 总计: {elapsed:.2f}秒, 最终命中 {total_hits} 条")
    
    logger.info("\n".join(perf_lines))