import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from typing import Dict, List, Any, Optional
import re
import time

from config import OPENAI_API_KEY, CHAT_MODEL
from rag.vector_store import enhanced_rag_query
from utils.json_utils import try_parse_json

logger = logging.getLogger(__name__)

class RootCauseAgent:
    def __init__(self, retriever_rootcause):
        self.retriever_rootcause = retriever_rootcause
        self.llm = ChatOpenAI(model_name=CHAT_MODEL,
                              #temperature=0.0,
                              openai_api_key=OPENAI_API_KEY,
                              openai_api_base="https://api.gpt.ge/v1/",
                              default_headers={"x-foo":"true"}
                              )
    
        self.llm_rootcause_keywords_prompt = PromptTemplate(
            input_variables=["NodeJs_type"],
            template="""
你是Node.js安全研究员。以下是Node.js分类信息，请基于这些内容推测可能相关的漏洞点/攻击方式关键词。
这些关键词将用于在 RootCause 知识库中检索。

要求：
1、关键词为英文，符合PascalCase命名法
2、**必须包含Node.js分类信息中提到的具体包名**
3、**必须包含具体的漏洞特征（如 const值未转义、value = item.const 等）**
4、**优先使用分类信息中的 related_exploit 字段作为关键词**

Node.js信息：
{NodeJs_type}

输出JSON:
{{
  "summary": "一句话总结漏洞特征，**必须包含具体包名和漏洞模式**，例如：'@orval/mock 在解析OpenAPI schema的const字段时未转义导致命令注入'",
  "rootcause_keywords": ["包名.漏洞特征", "漏洞类型.具体位置", "..."]
}}
"""
        )

        self.single_clue_evaluation_prompt = PromptTemplate(
            input_variables=["js_code", "rootcause_clue"],
            template="""
你是一名资深Node.js安全审计专家。请对以下漏洞线索进行独立、客观的评估。

任务要求：
1. 仔细分析提供的 rootcause 线索，然后在Node.js源码中寻找匹配的模式
2. 必须诚实评估：如果存在该漏洞，说明具体原因和位置；如果不存在，说明为什么不成立
3. 重点关注数据流、控制流和函数调用关系
4. 避免主观臆断，基于代码证据做出判断
5. 进行有依据的推理拓展：在确认线索核心含义的基础上，你可以进行合理的推理延伸，和这个线索有关的漏洞。
6. 所有延伸推理必须能够追溯至合约源码中的具体模式、数据流或控制流作为依据，严禁脱离代码证据进行主观臆测或虚构场景。

RootCause线索描述:
{rootcause_clue}

需要审计的Node.js源码:
{js_code}

请按以下JSON格式输出评估结果：
{{
  "vulnerability_name": "线索的漏洞名称",
  "clue_description": "简要描述当前分析的线索内容",
  "exists": true/false,
  "confidence": "高/中/低",
  "reasoning": "详细的分析推理过程，包括数据流追踪、函数调用分析等",
  "evidence_location": "如果存在，指出在代码中的具体位置（函数名、行号等）",
  "data_flow_analysis": "描述数据如何从源头流向敏感点",
  "vulnerability_trigger": "漏洞触发的具体条件和路径"
}}
"""
        )

        # 修改后的最终选择提示词
        self.final_selection_prompt = PromptTemplate(
            input_variables=["js_code", "evaluation_results"],
            template="""
你是一名首席Node.js审计专家。基于以下对各条漏洞线索的独立评估结果，请选择最可能真实存在的漏洞。

评估要求：
1. 综合分析所有线索的评估结果，特别是标记为"exists": true的线索
2. 优先选择证据充分、置信度高的漏洞
3. 考虑漏洞的严重性和可利用性
4. 只能且必须选择一个最可信的漏洞，必须是线索中的名字
5. 漏洞的名称"vulnerability_name"必须是漏洞线索的名称

Node.js源码：
{js_code}

各线索评估结果:
{evaluation_results}

请输出最可信的漏洞分析：
{{
  "vulnerability_name": "漏洞名称",
  "reason": "选择该漏洞的理由，基于评估结果的分析",
  "code_snippet": "关键代码片段",
  "location": "漏洞位置",
  "trigger_point": "触发点",
  "confidence_level": "高/中/低",
  "supporting_evidence": "引用的评估线索编号和关键证据"
}}
"""
        )

        #构建chain
        self.rootcause_keywords_chain = (
            RunnablePassthrough()
            | self.llm_rootcause_keywords_prompt
            | self.llm
        )

        self.single_evaluation_chain = (
            RunnablePassthrough()
            | self.single_clue_evaluation_prompt
            | self.llm
        )

        self.final_chain = (
            RunnablePassthrough()
            | self.final_selection_prompt
            | self.llm
        )

    def evaluate_single_clue(self, js_code: str, clue: str, clue_index: int) -> Dict[str, Any]:
        """独立评估单条漏洞线索"""
        try:
            evaluation_result = self.single_evaluation_chain.invoke({
                "js_code": js_code,
                "rootcause_clue": clue
            })
            
            evaluation_content = evaluation_result.content if hasattr(evaluation_result, 'content') else evaluation_result
            eval_data = try_parse_json(evaluation_content)
            
            # 记录评估日志
            logger.info(f"[ClueEvaluation-{clue_index}] 线索: {clue[:100]}...")
            logger.info(f"[ClueEvaluation-{clue_index}] 存在性: {eval_data.get('exists', '未知')}")
            logger.info(f"[ClueEvaluation-{clue_index}] 置信度: {eval_data.get('confidence', '未知')}")
            logger.info(f"[ClueEvaluation-{clue_index}] 推理过程: {eval_data.get('reasoning', '')}...")
            
            return {
                "clue_index": clue_index,
                "clue_content": clue,
                "evaluation": eval_data,
                "exists": eval_data.get('exists', False),
                "confidence": eval_data.get('confidence', '未知')
            }
        except Exception as e:
            logger.error(f"[ClueEvaluation-{clue_index}] 评估失败: {e}")
            return {
                "clue_index": clue_index,
                "clue_content": clue,
                "evaluation": {"error": str(e)},
                "exists": False,
                "confidence": "低"
            }

    def find_rootcauses_and_audit(self, NodeJs_type: List[str], js_code: str, package_name: Optional[str] = None) -> Dict:
        node_text = "\n".join(NodeJs_type)
        keyword_res = self.rootcause_keywords_chain.invoke({"NodeJs_type": node_text})
        keyword_res = keyword_res.content if hasattr(keyword_res, 'content') else keyword_res
        keyword_data = try_parse_json(keyword_res)
        
        # 添加类型检查，处理LLM返回格式不一致的问题
        if isinstance(keyword_data, dict):
            # 正常情况：返回字典
            keywords = keyword_data.get("rootcause_keywords", [])
            summar = keyword_data.get("summary", "")
        elif isinstance(keyword_data, list):
            # 特殊情况：LLM直接返回了列表
            keywords = keyword_data
            
            # 安全地将列表转换为摘要字符串
            if keyword_data:
                # 将所有元素转换为字符串（兼容字典和字符串）
                string_items = []
                for item in keyword_data:
                    if isinstance(item, dict):
                        # 如果是字典，尝试获取常用字段
                        if 'name' in item:
                            string_items.append(item['name'])
                        elif 'value' in item:
                            string_items.append(item['value'])
                        else:
                            # 如果没有常用字段，将整个字典转为字符串
                            string_items.append(str(item))
                    else:
                        # 如果是其他类型（包括字符串），直接转为字符串
                        string_items.append(str(item))
                
                summar = " ".join(string_items)
            else:
                summar = ""
            
            logger.info(f"[RootCause] 检测到列表格式，已转换为摘要: {summar[:100]}...")
        else:
            # 其他情况
            keywords = []
            summar = str(keyword_data) if keyword_data else ""
            logger.warning(f"[RootCause] 未知的返回格式: {type(keyword_data)}")
        
        logging.info(f"[RootCause] 关键词生成: {keywords}")
        logging.info(f"[RootCause] 摘要生成：{summar}")

        # 从NodeJs_type中提取包名（如果没传）
        if not package_name:
            for item in NodeJs_type:
                # 匹配 @xxx/xxx 或 xxx/xxx 格式的包名
                match = re.search(r'@?[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+', item)
                if match:
                    package_name = match.group(0)
                    logger.info(f"[RootCause] 从NodeJs_type提取到包名: {package_name}")
                    break
        
        # 构建更精确的query
        if package_name:
            # 安全地将 keywords 转换为字符串
            if keywords:
                if isinstance(keywords, list):
                    # 将所有元素转为字符串
                    keywords_str = " ".join([str(k) for k in keywords])
                else:
                    keywords_str = str(keywords)
            else:
                keywords_str = ""
            
            query = f"{package_name} {summar} 漏洞特征: {keywords_str}"
        else:
            if keywords:
                if isinstance(keywords, list):
                    keywordsquery = " ".join([str(k) for k in keywords])
                else:
                    keywordsquery = str(keywords)
            else:
                keywordsquery = ""
            
            if keywordsquery:
                keywordsquery = "重点关注，优先匹配以下关键词：" + keywordsquery 
            query = f"{summar} {keywordsquery}".strip() if summar else keywordsquery or node_text

        logging.info(f"[RootCause] 使用 query='{query}' 进行检索")

        # 获取类别路径（如果有包名且retriever有相应方法）
        category_path = None
        if package_name and hasattr(self.retriever_rootcause, 'get_category_path_for_package'):
            # 注意：这里需要从RAGManager获取，但retriever本身没有这个方法
            # 实际调用时会在enhanced_rag_query中通过其他方式获取
            pass

        # ---------- Step2: RootCause RAG ----------
        docs = enhanced_rag_query(
            query, 
            self.retriever_rootcause, 
            keywords, 
            max_docs=5,
            package_name=package_name  # 传递包名
        )
        rootcause_entries = [doc.page_content for doc in docs]
        logging.info(f"[RootCause] 命中条目数: {len(rootcause_entries)}")

        # ---------- Step3: 独立评估每条线索 ----------
        evaluation_results = []
        logger.info(f"[Evaluation] 开始独立评估 {len(rootcause_entries)} 条漏洞线索")
        
        for i, clue in enumerate(rootcause_entries):
            logger.info(f"[Evaluation] 评估线索 {i+1}/{len(rootcause_entries)}")
            eval_result = self.evaluate_single_clue(js_code, clue, i+1)
            evaluation_results.append(eval_result)

            # 添加短暂延迟避免速率限制
            time.sleep(1)

        # 统计评估结果
        valid_clues = [r for r in evaluation_results if r.get('exists')]
        logger.info(f"[EvaluationSummary] 完成所有线索评估，有效线索: {len(valid_clues)}/{len(evaluation_results)}")

        # ---------- Step4: 基于评估结果进行最终选择 ----------
        # 构建评估结果摘要
        if valid_clues:
            eval_summary = "\n\n".join([
                f"线索{i+1} (置信度: {r['confidence']}):\n"
                f"内容: {r['clue_content'][:200]}...\n"
                f"评估: {r['evaluation'].get('reasoning', '无详细推理')}\n"
                f"存在性: {r['exists']}\n"
                f"证据位置: {r['evaluation'].get('evidence_location', '未指定')}"
                for i, r in enumerate(valid_clues)
            ])
        else:
            eval_summary = "没有找到有效线索"
            
        final_res = self.final_chain.invoke({
            "js_code": js_code,
            "evaluation_results": eval_summary
        })

        final_res_content = final_res.content if hasattr(final_res, 'content') else final_res
        final_data = try_parse_json(final_res_content)

        # 如果解析失败，提供默认结果
        if not final_data:
            final_data = {
                "vulnerability_name": "未发现确认漏洞",
                "reason": "经过独立评估，未发现高置信度的漏洞线索",
                "code_snippet": "N/A",
                "location": "N/A",
                "trigger_point": "N/A",
                "confidence_level": "低"
            }
        
        logging.info(f"[FinalSelect] 最终漏洞选择: {final_data}")

        return {
            "retrieved_rootcauses": rootcause_entries,
            "final_vulnerability": final_data,
            "summar": summar
        }