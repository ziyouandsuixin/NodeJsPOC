"""
Root Cause Agent Module

This module handles the identification and analysis of root causes for vulnerabilities
in Node.js code. It uses a multi-stage process:
1. Keyword Generation: Generates search keywords from Node.js type information
2. RAG Retrieval: Retrieves relevant root cause entries from knowledge base
3. Independent Evaluation: Evaluates each clue independently
4. Final Selection: Selects the most likely vulnerability based on evaluations

Date: 2025
Version: 1.0.0
"""

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
You are a Node.js security researcher. Based on the following Node.js classification information, infer possible vulnerability points/attack method keywords.
These keywords will be used to search in the RootCause knowledge base.

Requirements:
1. Keywords must be in English and follow PascalCase naming convention
2. **Must include specific package names mentioned in the Node.js classification information**
3. **Must include specific vulnerability characteristics (e.g., const value not escaped, value = item.const, etc.)**
4. **Prioritize using the related_exploit field from the classification information as keywords**

Node.js information:
{NodeJs_type}

Output JSON:
{{
  "summary": "A one-sentence summary of vulnerability characteristics, **must include specific package name and vulnerability pattern**, e.g.: '@orval/mock command injection due to unescaped const field in OpenAPI schema parsing'",
  "rootcause_keywords": ["package_name.vulnerability_characteristic", "vulnerability_type.specific_location", "..."]
}}
"""
        )

        self.single_clue_evaluation_prompt = PromptTemplate(
            input_variables=["js_code", "rootcause_clue"],
            template="""
You are a senior Node.js security audit expert. Please conduct an independent and objective evaluation of the following vulnerability clue.

Task Requirements:
1. Carefully analyze the provided rootcause clue, then look for matching patterns in the Node.js source code
2. Must evaluate honestly: If the vulnerability exists, explain specific reasons and locations; if it does not exist, explain why it is not valid
3. Focus on data flow, control flow, and function call relationships
4. Avoid subjective assumptions, make judgments based on code evidence
5. Conduct evidence-based reasoning extension: Based on confirming the core meaning of the clue, you can make reasonable reasoning extensions related to this clue
6. All extended reasoning must be traceable to specific patterns, data flows, or control flows in the contract source code as evidence. Strictly avoid subjective speculation or fabricated scenarios without code evidence.

RootCause clue description:
{rootcause_clue}

Node.js source code to audit:
{js_code}

Please output the evaluation results in the following JSON format:
{{
  "vulnerability_name": "Vulnerability name from the clue",
  "clue_description": "Brief description of the currently analyzed clue content",
  "exists": true/false,
  "confidence": "High/Medium/Low",
  "reasoning": "Detailed analysis reasoning process, including data flow tracing, function call analysis, etc.",
  "evidence_location": "If exists, indicate the specific location in the code (function name, line number, etc.)",
  "data_flow_analysis": "Describe how data flows from source to sensitive point",
  "vulnerability_trigger": "Specific conditions and paths for vulnerability trigger"
}}
"""
        )

        self.final_selection_prompt = PromptTemplate(
            input_variables=["js_code", "evaluation_results"],
            template="""
You are a lead Node.js audit expert. Based on the following independent evaluation results of each vulnerability clue, select the most likely real vulnerability.

Evaluation Requirements:
1. Comprehensively analyze all clue evaluation results, especially those marked as "exists": true
2. Prioritize vulnerabilities with sufficient evidence and high confidence
3. Consider the severity and exploitability of vulnerabilities
4. Must select only one most credible vulnerability, which must be from the clue names
5. The "vulnerability_name" must be the name from the vulnerability clue

Node.js source code:
{js_code}

Evaluation results for each clue:
{evaluation_results}

Please output the most credible vulnerability analysis:
{{
  "vulnerability_name": "Vulnerability name",
  "reason": "Reason for selecting this vulnerability, based on analysis of evaluation results",
  "code_snippet": "Key code snippet",
  "location": "Vulnerability location",
  "trigger_point": "Trigger point",
  "confidence_level": "High/Medium/Low",
  "supporting_evidence": "Referenced evaluation clue numbers and key evidence"
}}
"""
        )

        # Build chains
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
        """Independently evaluate a single vulnerability clue"""
        try:
            evaluation_result = self.single_evaluation_chain.invoke({
                "js_code": js_code,
                "rootcause_clue": clue
            })
            
            evaluation_content = evaluation_result.content if hasattr(evaluation_result, 'content') else evaluation_result
            eval_data = try_parse_json(evaluation_content)
            
            # Log evaluation
            logger.info(f"[ClueEvaluation-{clue_index}] Clue: {clue[:100]}...")
            logger.info(f"[ClueEvaluation-{clue_index}] Existence: {eval_data.get('exists', 'Unknown')}")
            logger.info(f"[ClueEvaluation-{clue_index}] Confidence: {eval_data.get('confidence', 'Unknown')}")
            logger.info(f"[ClueEvaluation-{clue_index}] Reasoning: {eval_data.get('reasoning', '')}...")
            
            return {
                "clue_index": clue_index,
                "clue_content": clue,
                "evaluation": eval_data,
                "exists": eval_data.get('exists', False),
                "confidence": eval_data.get('confidence', 'Unknown')
            }
        except Exception as e:
            logger.error(f"[ClueEvaluation-{clue_index}] Evaluation failed: {e}")
            return {
                "clue_index": clue_index,
                "clue_content": clue,
                "evaluation": {"error": str(e)},
                "exists": False,
                "confidence": "Low"
            }

    def find_rootcauses_and_audit(self, NodeJs_type: List[str], js_code: str, package_name: Optional[str] = None) -> Dict:
        node_text = "\n".join(NodeJs_type)
        keyword_res = self.rootcause_keywords_chain.invoke({"NodeJs_type": node_text})
        keyword_res = keyword_res.content if hasattr(keyword_res, 'content') else keyword_res
        keyword_data = try_parse_json(keyword_res)
        
        # Add type checking to handle inconsistent LLM return formats
        if isinstance(keyword_data, dict):
            # Normal case: returns dictionary
            keywords = keyword_data.get("rootcause_keywords", [])
            summar = keyword_data.get("summary", "")
        elif isinstance(keyword_data, list):
            # Special case: LLM directly returns a list
            keywords = keyword_data
            
            # Safely convert list to summary string
            if keyword_data:
                # Convert all elements to strings (handling both dictionaries and strings)
                string_items = []
                for item in keyword_data:
                    if isinstance(item, dict):
                        # If dictionary, try to get common fields
                        if 'name' in item:
                            string_items.append(item['name'])
                        elif 'value' in item:
                            string_items.append(item['value'])
                        else:
                            # If no common fields, convert entire dict to string
                            string_items.append(str(item))
                    else:
                        # For other types (including strings), directly convert to string
                        string_items.append(str(item))
                
                summar = " ".join(string_items)
            else:
                summar = ""
            
            logger.info(f"[RootCause] Detected list format, converted to summary: {summar[:100]}...")
        else:
            # Other cases
            keywords = []
            summar = str(keyword_data) if keyword_data else ""
            logger.warning(f"[RootCause] Unknown return format: {type(keyword_data)}")
        
        logging.info(f"[RootCause] Keywords generated: {keywords}")
        logging.info(f"[RootCause] Summary generated: {summar}")

        # Extract package name from NodeJs_type if not provided
        if not package_name:
            for item in NodeJs_type:
                # Match @xxx/xxx or xxx/xxx format package names
                match = re.search(r'@?[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+', item)
                if match:
                    package_name = match.group(0)
                    logger.info(f"[RootCause] Extracted package name from NodeJs_type: {package_name}")
                    break
        
        # Build more precise query
        if package_name:
            # Safely convert keywords to string
            if keywords:
                if isinstance(keywords, list):
                    keywords_str = " ".join([str(k) for k in keywords])
                else:
                    keywords_str = str(keywords)
            else:
                keywords_str = ""
            
            query = f"{package_name} {summar} vulnerability characteristics: {keywords_str}"
        else:
            if keywords:
                if isinstance(keywords, list):
                    keywordsquery = " ".join([str(k) for k in keywords])
                else:
                    keywordsquery = str(keywords)
            else:
                keywordsquery = ""
            
            if keywordsquery:
                keywordsquery = "Focus on, prioritize matching the following keywords: " + keywordsquery 
            query = f"{summar} {keywordsquery}".strip() if summar else keywordsquery or node_text

        logging.info(f"[RootCause] Retrieving with query='{query}'")

        # ---------- Step2: RootCause RAG ----------
        docs = enhanced_rag_query(
            query, 
            self.retriever_rootcause, 
            keywords, 
            max_docs=5,
            package_name=package_name  # Pass package name
        )
        rootcause_entries = [doc.page_content for doc in docs]
        logging.info(f"[RootCause] Retrieved entries count: {len(rootcause_entries)}")

        # ---------- Step3: Independently evaluate each clue ----------
        evaluation_results = []
        logger.info(f"[Evaluation] Starting independent evaluation of {len(rootcause_entries)} vulnerability clues")
        
        for i, clue in enumerate(rootcause_entries):
            logger.info(f"[Evaluation] Evaluating clue {i+1}/{len(rootcause_entries)}")
            eval_result = self.evaluate_single_clue(js_code, clue, i+1)
            evaluation_results.append(eval_result)

            # Add short delay to avoid rate limiting
            time.sleep(1)

        # Summarize evaluation results
        valid_clues = [r for r in evaluation_results if r.get('exists')]
        logger.info(f"[EvaluationSummary] Completed all clue evaluations, valid clues: {len(valid_clues)}/{len(evaluation_results)}")

        # ---------- Step4: Final selection based on evaluation results ----------
        # Build evaluation summary
        if valid_clues:
            eval_summary = "\n\n".join([
                f"Clue{i+1} (Confidence: {r['confidence']}):\n"
                f"Content: {r['clue_content'][:200]}...\n"
                f"Evaluation: {r['evaluation'].get('reasoning', 'No detailed reasoning')}\n"
                f"Existence: {r['exists']}\n"
                f"Evidence location: {r['evaluation'].get('evidence_location', 'Not specified')}"
                for i, r in enumerate(valid_clues)
            ])
        else:
            eval_summary = "No valid clues found"
            
        final_res = self.final_chain.invoke({
            "js_code": js_code,
            "evaluation_results": eval_summary
        })

        final_res_content = final_res.content if hasattr(final_res, 'content') else final_res
        final_data = try_parse_json(final_res_content)

        # Provide default result if parsing fails
        if not final_data:
            final_data = {
                "vulnerability_name": "No confirmed vulnerability found",
                "reason": "After independent evaluation, no high-confidence vulnerability clues were found",
                "code_snippet": "N/A",
                "location": "N/A",
                "trigger_point": "N/A",
                "confidence_level": "Low"
            }
        
        logging.info(f"[FinalSelect] Final vulnerability selection: {final_data}")

        return {
            "retrieved_rootcauses": rootcause_entries,
            "final_vulnerability": final_data,
            "summar": summar
        }