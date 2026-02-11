# agents/nodeJs_cla_agent.py
import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableSequence
from typing import Dict, List

from config import OPENAI_API_KEY, CHAT_MODEL
from rag.vector_store import enhanced_rag_query
from utils.json_utils import try_parse_json

logger = logging.getLogger(__name__)

class NodeJsClassifierAgent:
    def __init__(self, retriever_NodeJs):
        self.retriever_NodeJs = retriever_NodeJs
        self.llm = ChatOpenAI(model_name=CHAT_MODEL,
                              #temperature=0.0,
                              openai_api_key=OPENAI_API_KEY,
                              openai_api_base="https://api.gpt.ge/v1/",
                              default_headers={"x-foo":"true"}
                              )
        
        self.keyword_prompt = PromptTemplate(
            input_variables=["js_code", "hierarchy_str"],
            template="""
你是一名Node.js生态漏洞挖掘与利用专家。请阅读以下js_code.json文件，总结出用于描述其安全风险的关键词。

要求：
1、关键词为英文，符合PascalCase命名法

Node.js代码:
{js_code}
NodeJsTpye:
{hierarchy_str}

输出格式:
{{
  "summary": "...",
  "NodeJsType_keywords":["...","..."]
}}
            """
        )
        self.keyword_chain = self.keyword_prompt | self.llm

    def classify(self, js_code: str, hierarchy_str: str) -> Dict:
        # 调用LLM提取风险关键词
        keyword_res = self.keyword_chain.invoke({
            "js_code": js_code, 
            "hierarchy_str": hierarchy_str
        })
        keyword_res = keyword_res.content if hasattr(keyword_res, 'content') else keyword_res
        keyword_data = try_parse_json(keyword_res)
        
        summary = keyword_data.get("summary", "")
        keywords = keyword_data.get("NodeJsType_keywords", [])

        logger.info(f"[NodeJs] LLM输出: {keyword_data}")

        # 使用RAG查询相关知识
        query = summary + " 重点匹配以下关键词: " + " ; ".join(keywords)
        docs = enhanced_rag_query(
            query, 
            self.retriever_NodeJs, 
            keywords, 
            max_docs=4
        )
        retriever_NodeJs = [doc.page_content for doc in docs]

        logger.info(f"[NodeJs] 命中包类型文档数={len(retriever_NodeJs)}")

        return {
            "analysis": keyword_data,
            "retriever_NodeJs": retriever_NodeJs
        }