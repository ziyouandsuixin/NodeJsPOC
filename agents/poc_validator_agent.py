"""
POC Validator Agent Module

This module validates whether a generated PoC (Proof of Concept) correctly exploits
the identified vulnerability in Node.js code. If validation fails, it can generate
new analysis based on the actual exploit pattern.

The agent follows a three-stage process:
1. Validation: Checks if PoC exploits the identified vulnerability
2. Generation: If validation fails, generates new Node.js type and root cause analysis
3. Knowledge Update: Updates the knowledge base with new findings

Date: 2025
Version: 1.0.0
"""

import logging
import json
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, List
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.runnables import RunnableSequence

from config import OPENAI_API_KEY, CHAT_MODEL, KNOWLEDGE_BASE_PATHS
from utils.json_utils import try_parse_json

logger = logging.getLogger(__name__)

class POCValidatorAgent:
    def __init__(self):
        """
        Initialize POC Validator Agent
        """
        self.llm = ChatOpenAI(model_name=CHAT_MODEL,
                              #temperature=0.0,
                              openai_api_key=OPENAI_API_KEY,
                              openai_api_base="https://api.gpt.ge/v1/",
                              default_headers={"x-foo":"true"}
                              )

        # Validation prompt template
        self.validation_prompt = PromptTemplate(
            input_variables=["js_code", "poc_code", "vuln_name", "vuln_reason", 
                           "vuln_location", "vuln_codesnippet", "vuln_triggerpoint"],
            template="""
Please analyze the following Node.js code and corresponding PoC (Proof of Concept) code to determine if the PoC exploits the vulnerability presented in the root cause analysis.

Node.js source code:
{js_code}

PoC code (this PoC is supposed to exploit a vulnerability in the Node.js code):
{poc_code}

Vulnerability details:
- Vulnerability Name: {vuln_name}
- Vulnerability Reason: {vuln_reason}
- Vulnerability Location: {vuln_location}
- Vulnerability Code Snippet: {vuln_codesnippet}
- Vulnerability Trigger Point: {vuln_triggerpoint}

Please strictly analyze based on the above information:
1. Does the Node.js code contain the described vulnerability?
2. Does the PoC exploit exactly the described vulnerability?
    - If successfully exploited: "is_exploiting": true
    - If not exploited: "is_exploiting": false
3. Be strict in your judgment. The PoC must completely exploit the described vulnerability. If the described vulnerability is fixed, this PoC should fail.

Please return the analysis result in strict JSON format:
{{
    "is_exploiting": true/false,
    "reasoning": "Detailed reasoning process explaining why it matches or does not match",
}}

Ensure accurate and objective analysis, focusing on the consistency of vulnerability trigger mechanisms and attack logic.
"""
        )

        # Generation prompt template for new analysis
        self.generation_prompt = PromptTemplate(
            input_variables=["retriever_NodeJs", "NodeJstype_summary", "js_code", "poc_code", "NodeJs_tree", "rootcause_tree"],
            template="""
Please analyze the following Node.js and PoC code, and generate corresponding NodeJstype and rootcause analysis based on the actual vulnerability exploited by the PoC.

---

### Node.js Description (use as semantic baseline):
{NodeJstype_summary}

You must use this description as the core semantic baseline:

---

### Related References
- Node.js source code (js_code):
{js_code}
- PoC code corresponding to this Node.js source code:
{poc_code}
- Identified types (retriever_NodeJs):
{retriever_NodeJs}
- Tree definition (NodeJs_tree):
{NodeJs_tree}
- Root cause classification (rootcause_tree):
{rootcause_tree}

---

### Generation Requirements

Please output in strict JSON format:

{{
    "NodeJstype_analysis": {{

    }},
    "rootcause_analysis": {{

    }}
}}
"""
        )

        # Create validation chain
        self.validation_chain = self.validation_prompt | self.llm
        # Create generation chain
        self.generation_chain = self.generation_prompt | self.llm
    
    def validate_poc_exploit(self, retriever_NodeJs: Dict, NodeJstype_summary: str, js_code: str, poc_code: str, 
                           rootcause_res: Dict, NodeJs_tree: Dict, 
                           rootcause_tree: Dict) -> Tuple[bool, Dict]:
    
        try:
            # Extract key information from root cause analysis
            vuln_name = rootcause_res.get("vulnerability_name", "Unknown Vulnerability")
            vuln_reason = rootcause_res.get("reason", "Unknown Reason")
            vuln_location = rootcause_res.get("location", "Unknown Location")
            vuln_codesnippet = rootcause_res.get("code_snippet", "Unknown Code Snippet")
            vuln_triggerpoint = rootcause_res.get("trigger_point", "Unknown Trigger Point")

            # Call validation chain
            logging.info(f"vuln_name:{vuln_name}")
            logging.info(f"vuln_reason:{vuln_reason}")
            logging.info(f"vuln_location:{vuln_location}")
            logging.info(f"vuln_codesnippet:{vuln_codesnippet}")
            logging.info(f"vuln_triggerpoint:{vuln_triggerpoint}")
            validation_response = self.validation_chain.invoke({
                "js_code": js_code,  
                "poc_code": poc_code,  
                "vuln_name": vuln_name,
                "vuln_reason": vuln_reason,
                "vuln_location": vuln_location,
                "vuln_codesnippet": vuln_codesnippet,
                "vuln_triggerpoint": vuln_triggerpoint
            })

            # Parse response
            validation_text = validation_response.content if hasattr(validation_response, 'content') else str(validation_response)
            validation_result = try_parse_json(validation_text)
            
            logging.info(f"[POCValidator] Validation result: {validation_result}")

            if validation_result.get("is_exploiting", True):
                logging.info("POC validation PASSED: PoC exploits the vulnerability from root cause analysis")
                return True, {}
            else:
                logging.warning("POC validation FAILED: PoC does not exploit the vulnerability from root cause analysis, generating new analysis")
                # Generate new NodeJstype and rootcause
                new_analysis = self._generate_new_analysis(
                    retriever_NodeJs, NodeJstype_summary, js_code, poc_code, NodeJs_tree, rootcause_tree
                )
                return False, new_analysis
                
        except Exception as e:
            logging.error(f"Error during POC validation: {str(e)}")
            # Default to not matching on error, continue with original flow
            return False, {}
        

def _generate_new_analysis(self, retriever_NodeJs: Dict, NodeJstype_summary: str, js_code: str, poc_code: str, 
                             NodeJs_tree: Dict, rootcause_tree: Dict) -> Dict[str, Any]:
    """Generate new Node.js type and root cause analysis"""
    try:
        # Call generation chain
        logging.info(f"LLM evaluation of Node.js: {NodeJstype_summary}")
        logging.info(f"Previously identified Node.js type entries: {retriever_NodeJs}")
        
        # Use specified variable names
        generation_response = self.generation_chain.invoke({
            "retriever_NodeJs": retriever_NodeJs,
            "NodeJstype_summary": NodeJstype_summary,
            "js_code": js_code,  
            "poc_code": poc_code, 
            "NodeJs_tree": json.dumps(NodeJs_tree, ensure_ascii=False),
            "rootcause_tree": json.dumps(rootcause_tree, ensure_ascii=False)
        })
        
        # Parse response
        generation_text = generation_response.content if hasattr(generation_response, 'content') else str(generation_response)
        new_analysis = try_parse_json(generation_text)
        
        if new_analysis:
            logging.info("Successfully generated new Node.js type and root cause analysis")
            
            # Get Node.js type and root cause analysis
            NodeJstype = new_analysis.get("NodeJstype_analysis", {})
            rootcause = new_analysis.get("rootcause_analysis", {})
            
            # Format related exploit
            self._format_related_exploit(NodeJstype, rootcause)
            
            logging.info(f"[POCValidator] New Node.js type analysis: {NodeJstype}")
            logging.info(f"[POCValidator] New root cause analysis: {rootcause}")
            return new_analysis
        else:
            logging.error("Failed to parse LLM generated new analysis")
            return {}

    except Exception as e:
        logging.error(f"Error generating new analysis: {str(e)}")
        return {}

    def _format_related_exploit(self, NodeJstype: Dict, rootcause: Dict):
        """
        Format related_exploit field as "category.name" format
        
        Args:
            NodeJstype: Node.js type analysis dictionary
            rootcause: Root cause analysis dictionary
        """
        try:
            # Extract category and vulnerability_name from root cause
            rootcause_category = rootcause.get("category", "UnknownCategory")
            vulnerability_name = rootcause.get("name", "UnknownVulnerability")
            
            # Build new related_exploit format
            new_related_exploit = f"{rootcause_category}.{vulnerability_name}"

            # Update NodeJstype's related_exploit field
            if "related_exploit" in NodeJstype:
                # Keep existing and add new if not present
                if isinstance(NodeJstype["related_exploit"], list):
                    # Ensure new format not already in list
                    if new_related_exploit not in NodeJstype["related_exploit"]:
                        NodeJstype["related_exploit"].append(new_related_exploit)
                else:
                    # If not a list, convert to list and add
                    NodeJstype["related_exploit"] = [str(NodeJstype["related_exploit"]), new_related_exploit]
            else:
                # If related_exploit field doesn't exist, create new
                NodeJstype["related_exploit"] = [new_related_exploit]
                
            logging.info(f"Updated related_exploit format: {NodeJstype['related_exploit']}")
            
        except Exception as e:
            logging.error(f"Error formatting related_exploit: {str(e)}")
            # Set default value on error
            NodeJstype["related_exploit"] = ["UnknownCategory.UnknownVulnerability"]

    def update_rootcause_based_on_poc(self, new_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update knowledge base based on POC validation results
        
        Args:
            new_analysis: New analysis results, containing NodeJstype and rootcause analysis
            
        Returns:
            Operation result report
        """
        result_report = {
            "success": True,
            "operations": [],
            "errors": []
        }
        
        try:
            if not new_analysis:
                result_report["success"] = False
                result_report["errors"].append("New analysis result is empty")
                return result_report
            
            # 1. Process rootcause analysis results
            rootcause_analysis = new_analysis.get("rootcause_analysis")
            if rootcause_analysis:
                rootcause_result = self._save_rootcause_analysis(rootcause_analysis)
                result_report["operations"].append({
                    "type": "rootcause",
                    "result": rootcause_result
                })
            else:
                result_report["errors"].append("Root cause analysis not found")
            
            # 2. Process NodeJstype analysis results
            NodeJstype_analysis = new_analysis.get("NodeJstype_analysis")
            if NodeJstype_analysis:
                NodeJstype_result = self._save_NodeJstype_analysis(NodeJstype_analysis)
                result_report["operations"].append({
                    "type": "NodeJstype", 
                    "result": NodeJstype_result
                })
                
                # 3. Update NodeJstype tree structure
                tree_result = self._update_NodeJstype_tree(NodeJstype_analysis)
                result_report["operations"].append({
                    "type": "NodeJstype_tree",
                    "result": tree_result
                })
            else:
                result_report["errors"].append("NodeJstype analysis not found")
                
        except Exception as e:
            logging.error(f"Error updating knowledge base: {str(e)}")
            result_report["success"] = False
            result_report["errors"].append(f"Exception: {str(e)}")
        
        return result_report

def _save_rootcause_analysis(self, rootcause_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Save rootcause analysis to Rootcause.json
    
    Args:
        rootcause_analysis: Root cause analysis results
    
    Returns:
        Save result
    """
    try:
        rootcause_file = KNOWLEDGE_BASE_PATHS["rootcause"] / "Rootcause.json"
        
        # Ensure file exists
        if not rootcause_file.exists():
            self._initialize_rootcause_file(rootcause_file)
        
        # Read existing rootcause data
        with open(rootcause_file, 'r', encoding='utf-8') as f:
            rootcause_data = json.load(f)
        
        # Get category and vulnerability name
        category = rootcause_analysis.get("category", "Unknown")
        vulnerability_name = rootcause_analysis.get("name", "UnknownVulnerability")
        
        # Ensure data structure exists
        if "RootCause" not in rootcause_data:
            rootcause_data["RootCause"] = {}
        
        if category not in rootcause_data["RootCause"]:
            rootcause_data["RootCause"][category] = []
        
        # Get new symptoms
        new_symptoms = rootcause_analysis.get("symptoms", [])
        
        # Check if vulnerability with same name exists
        updated = False
        for vuln in rootcause_data["RootCause"][category]:
            if vuln.get("name") == vulnerability_name:
                # Merge symptoms, ensuring no duplicates
                old_symptoms = vuln.get("symptoms", [])
                merged_symptoms = list({*old_symptoms, *new_symptoms})
                vuln["symptoms"] = merged_symptoms
                updated = True
                break
        
        if not updated:
            # Add new vulnerability entry
            new_vuln = {
                "name": vulnerability_name,
                "pattern": rootcause_analysis.get("pattern", ""),
                "symptoms": new_symptoms,
                "related_exploit": rootcause_analysis.get("related_exploit", []),
            }
            rootcause_data["RootCause"][category].append(new_vuln)
        
        # Save updated data
        with open(rootcause_file, 'w', encoding='utf-8') as f:
            json.dump(rootcause_data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"Successfully saved rootcause analysis to {category} category")
        return {"status": "success", "category": category, "vulnerability": vulnerability_name}
    
    except Exception as e:
        logging.error(f"Error saving rootcause analysis: {str(e)}")
        return {"status": "error", "error": str(e)}


def _save_NodeJstype_analysis(self, NodeJstype_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Save NodeJsType analysis to NodeJsTypes.json
    
    Implementation logic:
    - Locate node based on "category";
    - Create new list if node doesn't exist;
    - If node is leaf (non-list), convert to list structure;
    - If node is list and Node.js type with same name exists, update;
    - Otherwise append new Node.js type.
    """
    try:
        # File path for NodeJsTypes.json
        NodeJs_file = Path("D:/pythonProject/POC-agent/version3_1112_GPT_LTM/NodeJsTypes.json")

        # Ensure file exists
        if not NodeJs_file.exists():
            self._initialize_NodeJstype_file(NodeJs_file)

        # Read existing NodeJsType data
        with open(NodeJs_file, 'r', encoding='utf-8') as f:
            NodeJs_data = json.load(f)

        # Ensure top-level structure exists
        if "NodeJsType" not in NodeJs_data:
            NodeJs_data["NodeJsType"] = {}

        NodeJs_tree = NodeJs_data["NodeJsType"]

        # Get current analysis category information
        category = NodeJstype_analysis.get("category", "Base")
        NodeJs_name = NodeJstype_analysis.get("name", "UnknownNodeJsType")

        # Create new array if category doesn't exist
        if category not in NodeJs_tree:
            NodeJs_tree[category] = []

        # If category is dict (previous design error or leaf node), convert to list
        if isinstance(NodeJs_tree[category], dict):
            NodeJs_tree[category] = [NodeJs_tree[category]]

        # Ensure it's list structure
        if not isinstance(NodeJs_tree[category], list):
            NodeJs_tree[category] = []

        # Check if Node.js type with same name exists
        existing_types = [p for p in NodeJs_tree[category] if p.get("name") == NodeJs_name]

        if existing_types:
            # Keep old fields, merge symptoms / related_exploit
            for i, NodeJs_type in enumerate(NodeJs_tree[category]):
                if NodeJs_type.get("name") == NodeJs_name:
                    old_symptoms = NodeJs_type.get("symptoms", [])
                    old_related = NodeJs_type.get("related_exploit", [])

                    new_symptoms = NodeJstype_analysis.get("symptoms", [])
                    new_related = NodeJstype_analysis.get("related_exploit", [])

                    # Merge and deduplicate
                    merged_symptoms = list(set(old_symptoms + new_symptoms))
                    merged_related = list(set(old_related + new_related))

                    # Update fields, only update necessary parts
                    NodeJs_tree[category][i]["symptoms"] = merged_symptoms
                    NodeJs_tree[category][i]["related_exploit"] = merged_related

                    # Update pattern if new pattern exists (optional logic)
                    new_pattern = NodeJstype_analysis.get("pattern")
                    if new_pattern and new_pattern != NodeJs_type.get("pattern"):
                        NodeJs_tree[category][i]["pattern"] = new_pattern
                    break
        else:
            # Add new Node.js type node
            new_NodeJs_type = {
                "name": NodeJs_name,
                "category": category,
                "pattern": NodeJstype_analysis.get("pattern", ""),
                "symptoms": NodeJstype_analysis.get("symptoms", []),
                "related_exploit": NodeJstype_analysis.get("related_exploit", [])
            }
            NodeJs_tree[category].append(new_NodeJs_type)

        # Write back to file
        with open(NodeJs_file, 'w', encoding='utf-8') as f:
            json.dump(NodeJs_data, f, indent=2, ensure_ascii=False)

        logging.info(f"Successfully integrated Node.js type {NodeJs_name} into category {category}")
        return {"status": "success", "category": category, "NodeJs_type": NodeJs_name}

    except Exception as e:
        logging.error(f"Error saving NodeJstype analysis: {str(e)}")
        return {"status": "error", "error": str(e)}


def _update_NodeJstype_tree(self, NodeJstype_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update NodeJstypetree.json tree structure:
    - Find corresponding node based on category;
    - If children exist, directly add new node;
    - If children don't exist, create and insert;
    - New node contains name and description.
    """
    try:
        # File path for NodeJstypetree.json
        tree_file = Path("D:/pythonProject/POC-agent/version3_1112_GPT_LTM/NodeJstypetree.json")

        # Ensure file exists
        if not tree_file.exists():
            self._initialize_NodeJs_tree_file(tree_file)

        # Read existing tree structure
        with open(tree_file, 'r', encoding='utf-8') as f:
            tree_data = json.load(f)

        category = NodeJstype_analysis.get("category", "")
        NodeJs_name = NodeJstype_analysis.get("name", "UnknownNodeJsType")
        pattern = NodeJstype_analysis.get("pattern", "")
        description = pattern

        # Define recursive function to find target node in tree
        def find_node_by_name(node: Dict[str, Any], target_name: str) -> Optional[Dict[str, Any]]:
            if node.get("name") == target_name:
                return node
            if "children" in node:
                for child in node["children"]:
                    result = find_node_by_name(child, target_name)
                    if result:
                        return result
            return None

        # Start from root to find category node
        target_node = find_node_by_name(tree_data, category)
        if not target_node:
            logging.warning(f"Node with name {category} not found, cannot add Node.js type {NodeJs_name}")
            return {"status": "warning", "message": f"Category {category} not found"}

        # Create children if node doesn't have children
        if "children" not in target_node or not isinstance(target_node["children"], list):
            target_node["children"] = []

        # Check if Node.js type node with same name exists
        existing = next((c for c in target_node["children"] if c.get("name") == NodeJs_name), None)
        if existing:
            # If node exists, update description
            old_desc = existing.get("description", "")
            existing["description"] = (old_desc + "\n" + description).strip()
            logging.info(f"Updated Node.js type node {NodeJs_name} description (appended new description)")
        else:
            # Insert new node
            new_node = {
                "name": NodeJs_name,
                "description": description
            }
            target_node["children"].append(new_node)
            logging.info(f"Added new Node.js type node {NodeJs_name} to category {category}")

        # Write back to file
        with open(tree_file, 'w', encoding='utf-8') as f:
            json.dump(tree_data, f, indent=2, ensure_ascii=False)

        logging.info(f"Successfully updated NodeJstype tree structure, integrated {NodeJs_name} into {category}")
        return {"status": "success", "category": category, "NodeJs_type": NodeJs_name}

    except Exception as e:
        logging.error(f"Error updating NodeJstypetree.json: {str(e)}")
        return {"status": "error", "error": str(e)}


@staticmethod
def _initialize_rootcause_file(file_path: Path):
    """Initialize Rootcause.json file - with Node.js related categories"""
    initial_data = {
        "RootCause": {
            "Prototype Pollution": [],
            "Command Injection": [],
            "File System Vulnerabilities": [],
            "NoSQL Injection": [],
            "SQL Injection": [],
            "Template Injection": [],
            "ReDoS": [],
            "Event Loop Blocking": [],
            "Memory Leak": [],
            "Authentication Bypass": [],
            "Authorization Flaws": [],
            "Insecure Deserialization": [],
            "XSS": [],
            "CSRF": [],
            "SSRF": [],
            "Information Disclosure": [],
            "Insecure Dependencies": [],
            "Misconfiguration": [],
            "Log Forging": [],
            "Other": []
        }
    }
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(initial_data, f, indent=2, ensure_ascii=False)


@staticmethod
def _initialize_NodeJstype_file(file_path: Path):
    """Initialize NodeJsTypes.json file"""
    initial_data = {
        "NodeJsType": {
            "Web Frameworks": [],
            "Database Drivers": [],
            "ORM Tools": [],
            "Template Engines": [],
            "Testing Frameworks": [],
            "Build Tools": [],
            "Package Managers": [],
            "Middleware": [],
            "Authentication Libraries": [],
            "Logging Libraries": [],
            "Caching Libraries": [],
            "Queue Systems": [],
            "WebSocket Libraries": [],
            "GraphQL Libraries": [],
            "Microservice Frameworks": [],
            "Other": []
        }
    }
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(initial_data, f, indent=2, ensure_ascii=False)


@staticmethod
def _initialize_NodeJs_tree_file(file_path: Path):
    """Initialize NodeJstypetree.json file"""
    initial_data = {
        "name": "NodeJsType",
        "description": "Root node for Node.js library and framework types, containing all subtypes",
        "children": []
    }
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(initial_data, f, indent=2, ensure_ascii=False)