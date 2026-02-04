# agents/verifier_agent.py
import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from typing import Dict
import re
import json

from config import OPENAI_API_KEY, CHAT_MODEL
from config import CHAT_MODEL
from utils.json_utils import try_parse_json

logger = logging.getLogger(__name__)

class POCVerifierAgent:
    def __init__(self):
        self.llm = ChatOpenAI(model_name=CHAT_MODEL,
                              #temperature=0.0,
                              openai_api_key=OPENAI_API_KEY,
                              openai_api_base="https://api.gpt.ge/v1/",
                              default_headers={"x-foo":"true"}
                              )
        self.poc_verification_prompt = PromptTemplate(
            input_variables=["vulnerability_info", "js_code", "poc_code"],
            template="""
你是一名node.js安全分析专家，负责验证给定的 PoC 是否能够触发指定漏洞。

[漏洞信息]
{vulnerability_info}

[node.js源码]
{js_code}

[PoC 代码]
{poc_code}

请你严格按照以下步骤进行分析：

输出结构化报告（严格 JSON）：
{{

}}

注意：  
- 只输出 JSON，不要解释性文字。
"""
        )

        self.verification_chain = (
            RunnablePassthrough()
            | self.poc_verification_prompt
            | self.llm
        )

    def verify_poc(self, vulnerability_info: Dict, js_code: str, poc_code: str) -> Dict:
        logging.info("[POCVerifierAgent] 开始验证 PoC 可达性...")
        res = self.verification_chain.invoke({
            "vulnerability_info": json.dumps(vulnerability_info, ensure_ascii=False),
            "js_code": js_code,
            "poc_code": poc_code
        })
        res = res.content if hasattr(res, 'content') else res
        logging.info(f"[POC Verifier]可达性分析：{res}")
        try:
            return json.loads(res)
        except Exception:
            match = re.search(r"\{[\s\S]*\}", res)
            if match:
                try:
                    return json.loads(match.group(0))
                except Exception:
                    pass
            return {"raw_output": res}