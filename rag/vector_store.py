import logging
import json
import glob
import os
from typing import List, Dict, Any, Optional
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
            logger.warning(f"Category '{category}' not found for entry '{name}'. Treating as root-level.")
            return ["NPM", name]  # 统一使用'NPM'

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
                        "package": entry.get("package", ""),  # 新增
                        "vuln_type": vuln_type_str,  # 新增
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
                        "applicable_to": applicable_to  # 存在metadata中方便检索
                    }
                )
                docs.append(doc)
                
        except Exception as e:
            logger.error(f"加载Exploit JSON文件失败 {json_file}: {e}")
    
    logger.info(f"Exploit加载器: 从 {len(json_files)} 个JSON文件加载了 {len(docs)} 个文档")
    return docs

# ============ 构建 Vectorstore ============
def build_vectorstore(knowledge_dir: str, top_k: int = 5, doc_type: str = "NodeJs"):
    """
    构建对应目录的向量库
    :param doc_type: "NodeJs" | "rootcause" | "exploit"
    """
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
    改造后的 RAG 查询：
    0. 按包名精确匹配（如果有）
    1. 按类别路径过滤（如果有）
    2. 精确匹配优先（支持 "类别.名称" 格式）
    3. BM25 检索补充
    4. 向量检索兜底
    """
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
            return vectorstore.similarity_search(query, k=max_docs)
        except:
            return []
    
    exact_matches = []
    seen = set()

    # ---------- Step0: 按包名精确匹配 ----------
    package_matches = []
    if package_name:
        logger.info(f"🔍 按包名精确匹配: {package_name}")
        for doc in all_docs:
            if doc.metadata.get("package") == package_name:
                key = doc.metadata.get("name") or doc.page_content[:30]
                if key not in seen:
                    package_matches.append(doc)
                    seen.add(key)
        
        if package_matches:
            logger.info(f"   ✅ 包名匹配到 {len(package_matches)} 个文档")
            exact_matches.extend(package_matches)
            if len(exact_matches) >= max_docs:
                return exact_matches[:max_docs]

    # ---------- Step1: 按类别路径过滤 ----------
    filtered_docs = []
    if category_path and not package_matches:  # 如果已经有包名匹配，不需要再过滤
        logger.info(f"📂 使用类别路径过滤: {category_path}")
        for doc in all_docs:
            doc_path = doc.metadata.get("path", "")
            # 检查文档路径是否以指定类别路径开头
            if doc_path and doc_path.startswith(category_path):
                filtered_docs.append(doc)
        
        # 如果过滤后没有文档，回退到全部文档
        if not filtered_docs:
            logger.warning(f"   ⚠️ 类别路径 '{category_path}' 下没有找到文档，回退到全部文档")
            filtered_docs = all_docs
        else:
            logger.info(f"   📊 类别过滤后文档数: {len(filtered_docs)}/{len(all_docs)}")
    else:
        filtered_docs = all_docs

    # ---------- Step2: 精确匹配 ----------
    for kw in keywords:
        kw_lower = kw.lower()

        # 2.1 匹配 vuln_type 字段
        for doc in filtered_docs:
            vuln_type_str = doc.metadata.get("vuln_type", "")
            if vuln_type_str and kw_lower in vuln_type_str.lower():
                key = doc.metadata.get("name") or doc.page_content[:30]
                if key not in seen:
                    exact_matches.append(doc)
                    seen.add(key)
                    if len(exact_matches) >= max_docs:
                        return exact_matches[:max_docs]

        # 2.2 "Category.Name" 格式
        if "." in kw:
            parts = kw.split(".")
            if len(parts) == 2:
                category, item_name = parts[0].lower(), parts[1].lower()
                for doc in filtered_docs:
                    if (doc.metadata.get("category", "").lower() == category and
                        doc.metadata.get("name", "").lower() == item_name):
                        key = f"{doc.metadata.get('category')}.{doc.metadata.get('name')}"
                        if key not in seen:
                            exact_matches.append(doc)
                            seen.add(key)
                            if len(exact_matches) >= max_docs:
                                return exact_matches[:max_docs]
        else:
            # 2.3 完整匹配 name
            for doc in filtered_docs:
                if doc.metadata.get("name", "").lower() == kw_lower:
                    if doc.metadata.get("name") not in seen:
                        exact_matches.append(doc)
                        seen.add(doc.metadata.get("name"))
                        if len(exact_matches) >= max_docs:
                            return exact_matches[:max_docs]

    # ---------- Step3: BM25 检索 ----------
    if len(exact_matches) < max_docs:
        try:
            bm25_retriever = BM25Retriever.from_documents(filtered_docs)
            bm25_docs = bm25_retriever.invoke(" ".join(keywords))
            for d in bm25_docs:
                key = d.metadata.get("name") or d.page_content[:30]
                if key not in seen:
                    exact_matches.append(d)
                    seen.add(key)
                if len(exact_matches) >= max_docs:
                    break
        except Exception as e:
            logger.warning(f"BM25检索失败: {e}")

    # ---------- Step4: 向量检索兜底 ----------
    if len(exact_matches) < max_docs:
        try:
            # 如果有类别路径，优先在过滤后的文档中向量检索
            if filtered_docs and filtered_docs != all_docs:
                # 临时创建一个只包含过滤后文档的检索器
                temp_vectorstore = FAISS.from_documents(filtered_docs, vectorstore.embeddings)
                vector_docs = temp_vectorstore.similarity_search(query, k=max_docs)
            else:
                vector_docs = vectorstore.similarity_search(query, k=max_docs)
                
            for d in vector_docs:
                key = d.metadata.get("name") or d.page_content[:30]
                if key not in seen:
                    exact_matches.append(d)
                    seen.add(key)
                if len(exact_matches) >= max_docs:
                    break
        except Exception as e:
            logger.warning(f"向量检索失败: {e}")

    logger.info(f"[RAG] query='{query}' 命中文档数={len(exact_matches)}")
    return exact_matches