# agents/rootcause_agent.py
import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from typing import Dict, List, Any

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

Node.jjs信息：
{NodeJs_type}

输出JSON:
{{
  "summary": "一句话总结Node_code潜在安全风险",
  "rootcause_keywords": ["...", "...", "..."]
}}
"""
        )

        self.single_clue_evaluation_prompt = PromptTemplate(
            input_variables=["js_code", "rootcause_clue"],
            template="""
你是一名资深Node.js安全审计专家。请对以下漏洞线索进行独立、客观的评估。

要求：

RootCause线索描述:
{rootcause_clue}

需要审计的Node.js源码:
{js_code}

请按以下JSON格式输出评估结果：
{{

}}
"""
        )

        # 修改后的最终选择提示词
        self.final_selection_prompt = PromptTemplate(
            input_variables=["js_code", "evaluation_results"],
            template="""
你是一名首席Node.js审计专家。基于以下对各条漏洞线索的独立评估结果，请选择最可能真实存在的漏洞。

评估要求：

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

    def find_rootcauses_and_audit(self, NodeJs_type: List[str], js_code: str) -> Dict:
        node_text = "\n".join(NodeJs_type)
        keyword_res = self.rootcause_keywords_chain.invoke({"NodeJs_type": node_text})
        keyword_res = keyword_res.content if hasattr(keyword_res, 'content') else keyword_res
        keyword_data = try_parse_json(keyword_res)
        keywords = keyword_data.get("rootcause_keywords", [])
        summar = keyword_data.get("summary", "")
        logging.info(f"[RootCause] 关键词生成: {keywords}\n[RootCause] 摘要生成：{summar}")

        keywordsquery = " ".join(keywords) if keywords else ""
        if keywordsquery:
            keywordsquery = "重点关注，优先匹配以下关键词：" + keywordsquery 
        query = f"{summar} {keywordsquery}".strip() if summar else keywordsquery or node_text

        logging.info(f"[RootCause] 使用 query='{query}' 进行检索")

        # ---------- Step2: RootCause RAG ----------
        docs = enhanced_rag_query(query, self.retriever_rootcause, keywords, max_docs=5)
        rootcause_entries = [doc.page_content for doc in docs]
        logging.info(f"[RootCause] 命中条目数: {len(rootcause_entries)}")

        # ---------- 新增: Step3 独立评估每条线索 ----------
        evaluation_results = []
        logger.info(f"[Evaluation] 开始独立评估 {len(rootcause_entries)} 条漏洞线索")
        
        for i, clue in enumerate(rootcause_entries):
            logger.info(f"[Evaluation] 评估线索 {i+1}/{len(rootcause_entries)}")
            eval_result = self.evaluate_single_clue(js_code, clue, i+1)
            evaluation_results.append(eval_result)

            # 添加短暂延迟避免速率限制
            import time
            time.sleep(1)

        # 统计评估结果
        valid_clues = [r for r in evaluation_results if r.get('exists')]
        logger.info(f"[EvaluationSummary] 完成所有线索评估，有效线索: {len(valid_clues)}/{len(evaluation_results)}")

        # ---------- 新增: Step4 基于评估结果进行最终选择 ----------
            # 构建评估结果摘要
        eval_summary = "\n\n".join([
            f"线索{i+1} (置信度: {r['confidence']}):\n"
            f"内容: {r['clue_content']}\n"
            f"评估: {r['evaluation'].get('reasoning', '无详细推理')}\n"
            f"存在性: {r['exists']}\n"
            f"证据位置: {r['evaluation'].get('evidence_location', '未指定')}"
            for i, r in enumerate(valid_clues)
        ])
            
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