"""
Node.js Classifier Agent Module

This module handles the classification of Node.js code to identify security risks
and vulnerability patterns using LLM and RAG retrieval.

The agent follows a two-stage process:
1. Keyword Extraction: Analyzes JavaScript code to extract risk-related keywords
2. RAG Retrieval: Queries the knowledge base using extracted keywords to find relevant vulnerability patterns

Date: 2025
Version: 1.0.0
"""

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
template="""You are a Node.js ecosystem vulnerability mining and exploitation expert. Please read the following js_code.json file and summarize keywords to describe its security risks.

Requirements:
1. Keywords must be in English and follow PascalCase naming convention

Node.js code:
{js_code}

Node.js type hierarchy:
{hierarchy_str}

Output format:
{{
  "summary": "...",
  "NodeJsType_keywords":["...","..."]
}}
"""
        )
        self.keyword_chain = self.keyword_prompt | self.llm

    def classify(self, js_code: str, hierarchy_str: str) -> Dict:
        # Call LLM to extract risk keywords
        keyword_res = self.keyword_chain.invoke({
            "js_code": js_code, 
            "hierarchy_str": hierarchy_str
        })
        keyword_res = keyword_res.content if hasattr(keyword_res, 'content') else keyword_res
        keyword_data = try_parse_json(keyword_res)
        
        summary = keyword_data.get("summary", "")
        keywords = keyword_data.get("NodeJsType_keywords", [])

        logger.info(f"[NodeJs] LLM output: {keyword_data}")

        # Use RAG to query relevant knowledge
        query = summary + " Focus on matching the following keywords: " + " ; ".join(keywords)
        docs = enhanced_rag_query(
            query, 
            self.retriever_NodeJs, 
            keywords, 
            max_docs=4
        )
        retriever_NodeJs = [doc.page_content for doc in docs]

        logger.info(f"[NodeJs] Retrieved documents count: {len(retriever_NodeJs)}")

        return {
            "analysis": keyword_data,
            "retriever_NodeJs": retriever_NodeJs
        }