"""
POC Verifier Agent Module

This module verifies whether a given Proof of Concept (PoC) can trigger a specified vulnerability
in Node.js code. It performs step-by-step analysis including environment setup, execution tracing,
vulnerability trigger path validation, and system interaction analysis.

Date: 2025
Version: 1.0.0
"""

import logging
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnablePassthrough
from typing import Dict
import re
import json

from config import OPENAI_API_KEY, CHAT_MODEL
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
You are a Node.js security analysis expert responsible for verifying whether a given PoC can trigger the specified vulnerability.

[Vulnerability Information]
{vulnerability_info}

[Node.js Source Code]
{js_code}

[PoC Code]
{poc_code}

Please strictly follow these steps for analysis:

1. Environment Initialization Analysis
- Identify packages, versions, and configuration files used in the PoC
- Analyze initial environment setup (working directory, dependency installation, file structure)

2. Code Execution Simulation
- Simulate each function call or command execution step by step according to the PoC execution order
- For each step, explain: operation performed, key parameters, expected result

3. Vulnerability Trigger Path Validation
- Analyze whether the PoC creates the correct malicious input
- Verify the vulnerability trigger point (e.g., unescaped const value, command injection point)
- Check for security bypasses or missing validations

4. System Interaction Analysis
- Analyze usage of modules such as child_process, fs, http
- Verify reachability of system command execution or file operations
- Check for privilege escalation or data leakage paths

5. Output Requirements
You must output a strict JSON object with the following format:
{{
  "environment_analysis": {{
    "packages_used": ["package@version"],
    "initial_state": "Environment setup description",
    "file_structure": "File structure description"
  }},
  "execution_trace": [
    {{"step": 1, "operation": "Command or function", "parameters": "Parameters", "expected_result": "Expected result"}}
  ],
  "vulnerability_trigger_check": {{
    "malicious_input_created": true/false,
    "trigger_point_reached": true/false,
    "vulnerability_location": "Vulnerability location (e.g., file:line number)"
  }},
  "system_interaction_analysis": {{
    "command_execution": true/false,
    "file_operations": true/false,
    "network_access": true/false
  }},
  "vulnerability_triggered": true/false,
  "reasoning_summary": "Brief explanation of why the vulnerability is reachable or not",
  "recommendations": ["Security recommendation 1", "Security recommendation 2"]
}}

Note:
- Output only JSON, no explanatory text.
"""
        )

        self.verification_chain = (
            RunnablePassthrough()
            | self.poc_verification_prompt
            | self.llm
        )

    def verify_poc(self, vulnerability_info: Dict, js_code: str, poc_code: str) -> Dict:
        logging.info("[POCVerifierAgent] Starting PoC reachability verification...")
        res = self.verification_chain.invoke({
            "vulnerability_info": json.dumps(vulnerability_info, ensure_ascii=False),
            "js_code": js_code,
            "poc_code": poc_code
        })
        res = res.content if hasattr(res, 'content') else res
        logging.info(f"[POC Verifier] Reachability analysis: {res}")
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