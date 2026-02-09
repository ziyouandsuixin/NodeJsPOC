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

1. 环境初始化分析
- 识别 PoC 中使用的包、版本、配置文件
- 分析初始环境设置（工作目录、依赖安装、文件结构）

2. 代码执行模拟
- 按照 PoC 的执行顺序，逐步模拟每个函数调用或命令执行
- 对每一步说明：执行的操作、关键参数、预期结果

3. 漏洞触发路径验证
- 分析 PoC 是否创建了正确的恶意输入
- 验证漏洞触发点（如：未转义的 const 值、命令注入点）
- 检查是否存在安全绕过或验证缺失

4. 系统交互分析
- 分析 child_process、fs、http 等模块的使用
- 验证系统命令执行或文件操作的可达性
- 检查权限提升或数据泄露路径

5. 输出要求
你必须输出一个严格的 JSON 对象，格式如下：
{{
  "environment_analysis": {{
    "packages_used": ["包名@版本"],
    "initial_state": "环境设置描述",
    "file_structure": "文件结构描述"
  }},
  "execution_trace": [
    {{"step": 1, "operation": "命令或函数", "parameters": "参数", "expected_result": "预期结果"}}
  ],
  "vulnerability_trigger_check": {{
    "malicious_input_created": true/false,
    "trigger_point_reached": true/false,
    "vulnerability_location": "漏洞位置（如：文件:行号）"
  }},
  "system_interaction_analysis": {{
    "command_execution": true/false,
    "file_operations": true/false,
    "network_access": true/false
  }},
  "vulnerability_triggered": true/false,
  "reasoning_summary": "简要说明漏洞可达或不可达的原因",
  "recommendations": ["安全建议1", "安全建议2"]
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