"""
Node.js Code Security Analysis Coordinator

Responsible for coordinating multiple agents to complete the full code security analysis process:
- Node.js component classification
- Vulnerability root cause analysis  
- Exploit analysis and POC generation
- POC reachability verification
- Visualization data generation

Date: 2025
Version: 1.0.0
"""

import glob
import logging
from openai import OpenAI
from typing import Dict, List, Any
import json
import os
import datetime
from pathlib import Path
import re

# Import paths
from config import OUTPUT_DIR, LOG_FILE
from rag.vector_store import build_vectorstore, load_vectorstore
from rag.rag_manager import RAGManager
from utils.file_utils import load_nodejs_types_hierarchy, load_exploit_steps, find_path_to_node, load_rootcause_categories
from agents.nodeJs_cla_agent import NodeJsClassifierAgent
from agents.rootcause_agent import RootCauseAgent
from agents.exploit_agent import ExploitAgent
from agents.verifier_agent import POCVerifierAgent
from agents.poc_validator_agent import POCValidatorAgent

# Ensure output directory exists
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# Logging setup
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding='utf-8'
)

logger = logging.getLogger(__name__)


class PackageFilteredRAGManager(RAGManager):
    """RAG Manager that supports filtering by package name"""
    
    def __init__(self):
        super().__init__()
        self.package_context = None
    
    def set_package_context(self, package_name: str):
        """Set current package context for analysis"""
        self.package_context = package_name
        logger.info(f"🔒 Package context set: {package_name}")
    
    def clear_package_context(self):
        """Clear package context"""
        self.package_context = None
    
    def get_category_path_for_current_package(self) -> str:
        """Get category path for current package"""
        if self.package_context:
            return self.get_category_path_for_package(self.package_context)
        return ""
    
    @property
    def retriever_NodeJs(self):
        """Return Node.js retriever"""
        return super().retriever_NodeJs
    
    @property
    def retriever_rootcause(self):
        """Return root cause retriever"""
        return super().retriever_rootcause
    
    @property
    def retriever_exploit(self):
        """Return exploit steps retriever"""
        return super().retriever_exploit


def detect_package_from_code(js_code: str) -> str:
    """
    Detect npm package name from JavaScript/TypeScript code
    """
    # Priority 1: Detect package from @description or @file comments
    description_match = re.search(r'@(?:description|file).*?@?([a-zA-Z0-9@/\-]+/inspector)', js_code, re.IGNORECASE)
    if description_match:
        pkg = description_match.group(1)
        if 'mcpjam' in pkg or 'inspector' in pkg:
            return "@mcpjam/inspector"
    
    # Priority 2: Detect package from import/require statements
    import_match = re.search(r'(?:import|require)\s*\(?\s*[\'"]@?mcpjam/inspector[\'"]', js_code)
    if import_match:
        return "@mcpjam/inspector"
    
    import_match = re.search(r'(?:import|require)\s*\(?\s*[\'"]@?orval/mock[\'"]', js_code)
    if import_match:
        return "@orval/mock"
    
    # Priority 3: Detect from route endpoints
    if '/api/mcp/connect' in js_code and 'inspector' in js_code.lower():
        return "@mcpjam/inspector"
    
    # Priority 4: Detect from command line patterns
    if 'npx @mcpjam/inspector' in js_code or '6274' in js_code:
        return "@mcpjam/inspector"
    
    if 'orval' in js_code.lower() and 'mock' in js_code.lower():
        return "@orval/mock"
    
    # Default: return None for no package filtering
    return None


class AnalysisCoordinator:
    def __init__(self):
        # Use package-filtered RAG manager
        self.rag = PackageFilteredRAGManager()
        
        # ===== Pure Vector Store Mode =====
        cache_dir = Path("./vectorstore")
        force_rebuild = False
        
        # Check if vector store cache exists
        if not cache_dir.exists():
            print("❌ Error: Vector store cache does not exist!")
            print("Please ensure ./vectorstore directory exists with subdirectories:")
            print("  - NodeJs/")
            print("  - rootcause/")
            print("  - exploit/")
            print("\nIf cache is missing, you need to:")
            print("1. Temporarily restore knowledge base file configuration")
            print("2. Run the program once to build cache")
            print("3. Then switch back to pure vector store mode")
            raise FileNotFoundError("Vector store cache not found, cannot start pure vector store mode")
        
        # Force rebuild via environment variable (requires knowledge base files)
        if os.environ.get("REBUILD_VECTORSTORE") == "1":
            print("⚠️ Warning: REBUILD_VECTORSTORE=1 but in pure vector store mode")
            print("Rebuild requires knowledge base files. Will fail if files don't exist.")
            force_rebuild = True
        
        # Check required vector store subdirectories
        required_stores = ["NodeJs", "rootcause", "exploit"]
        missing_stores = []
        for store in required_stores:
            if not (cache_dir / store).exists():
                missing_stores.append(store)
        
        if missing_stores:
            print(f"❌ Missing required vector stores: {', '.join(missing_stores)}")
            raise FileNotFoundError(f"Incomplete vector stores, missing: {missing_stores}")
        
        print("📦 Using existing vector store cache")
        
        # Remove knowledge base version check, fully rely on vector store cache
        # No longer read KNOWLEDGE_BASE_PATHS and JSON files
        
        # Refresh with force_rebuild parameter
        # Note: If force_rebuild=True but knowledge base files don't exist, this will fail
        self.rag.refresh_all(force_rebuild=force_rebuild)
        
        # ===== Pure Vector Store Mode End =====
        
        # Note: retriever properties only become effective after set_package_context
        self.retriever_NodeJs = self.rag.retriever_NodeJs
        self.retriever_rootcause = self.rag.retriever_rootcause
        self.retriever_exploit = self.rag.retriever_exploit

        # Initialize agents
        self.nodejs_classifier = NodeJsClassifierAgent(self.retriever_NodeJs)
        self.rootcause_agent = RootCauseAgent(self.retriever_rootcause)
        self.exploit_agent = ExploitAgent(self.retriever_exploit)
        self.poc_verifier = POCVerifierAgent()
        self.poc_validator = POCValidatorAgent()
        
        self.current_package = None

    def full_analysis(self, js_sources: Dict[str, str]) -> Dict:
        """
        Execute complete Node.js code security analysis
        """
        # Concatenate all JavaScript code into a single string
        js_code = "\n\n".join(
            f"// File: {filename}\n{code}" 
            for filename, code in js_sources.items()
        )
        
        # ========== 0. Package Detection ==========
        self.current_package = detect_package_from_code(js_code)
        if self.current_package:
            print(f"\n📦 Detected package: {self.current_package}")
            # Set RAG context for logging only, not for filtering
            self.rag.set_package_context(self.current_package)
        else:
            print("\n🌐 No specific package detected, performing full retrieval")
        
        print("\n" + "="*80)
        print("🚀 Node.js Security Analysis Started")
        print("="*80)
        
        # Load Node.js type hierarchy
        hierarchy_str = self.rag.get_hierarchy()

        # ========== 1. Node.js Classification Analysis ==========
        print("\n📦 Phase 1: Node.js Component Classification")
        nodejs_res = self.nodejs_classifier.classify(js_code, hierarchy_str)
        
        retriever_NodeJs = nodejs_res.get("retriever_NodeJs", [])
        keyword_data = nodejs_res.get("analysis", {})
        nodejs_keywords = keyword_data.get("NodeJsType_keywords", [])
        
        print(f"   ✅ Extracted keywords: {', '.join(nodejs_keywords[:5])}{'...' if len(nodejs_keywords) > 5 else ''}")
        print(f"   📚 RAG hits: {len(retriever_NodeJs)} relevant Node.js knowledge entries")
        
        if retriever_NodeJs:
            print(f"   📋 Hit components:")
            for i, doc in enumerate(retriever_NodeJs[:3]):
                name_match = re.search(r"Name: (.+?)(?:\n|$)", doc)
                name = name_match.group(1) if name_match else f"Entry {i+1}"
                print(f"     - {name}")
            if len(retriever_NodeJs) > 3:
                print(f"     ... and {len(retriever_NodeJs)} more entries")
        else:
            print(f"   ⚠️ No Node.js component knowledge matched")

        # ========== 2. Root Cause Analysis ==========
        print("\n🔬 Phase 2: Vulnerability Root Cause Analysis")
        rootcause_res = self.rootcause_agent.find_rootcauses_and_audit(
            NodeJs_type=retriever_NodeJs,
            js_code=js_code,
            package_name=self.current_package
        )
        
        final_vuln = rootcause_res.get("final_vulnerability", {})
        vuln_name = final_vuln.get("vulnerability_name", "Unknown")
        confidence = final_vuln.get("confidence_level", "Unknown")
        location = final_vuln.get("location", "Unknown")
        
        # Inject package name into final_vulnerability
        if self.current_package and "package" not in final_vuln:
            final_vuln["package"] = self.current_package
        
        print(f"   🎯 Identified vulnerability: {vuln_name}")
        print(f"   📊 Confidence: {confidence}")
        print(f"   📍 Vulnerability location: {location}")
        if self.current_package:
            print(f"   📦 Package: {self.current_package}")
        
        retrieved_rootcauses = rootcause_res.get("retrieved_rootcauses", [])
        print(f"   📚 Root cause knowledge hits: {len(retrieved_rootcauses)} entries")

        # ========== 3. Exploit Analysis ==========
        print("\n⚔️ Phase 3: Exploit Analysis")
        exploit_steps = load_exploit_steps("ExploitBehaviortree.json")
        exploit_res = self.exploit_agent.generate_exploit(
            rootcause_res["final_vulnerability"],
            exploit_steps
        )
        
        selected_steps = exploit_res.get("step_selection", {}).get("selected_steps", [])
        print(f"   🎯 Selected attack types: {', '.join(selected_steps[:3])}{'...' if len(selected_steps) > 3 else ''}")
        
        detailed_steps = exploit_res.get("retrieved_detailed_steps", [])
        print(f"   📚 Attack steps hits: {len(detailed_steps)} entries")
        
        poc_code = exploit_res.get("poc_generation", "")
        print(f"   💉 POC generation: {'✅ Success' if poc_code else '❌ Failed'} (length: {len(poc_code)} chars)")

        # ========== 4. POC Reachability Verification ==========
        print("\n🧪 Phase 4: POC Reachability Verification")
        vuln_info = rootcause_res.get("final_vulnerability", {})
        reachability_report = self.poc_verifier.verify_poc(vuln_info, js_code, poc_code)
        
        triggered = reachability_report.get("vulnerability_triggered", False)
        print(f"   🚨 Vulnerability triggered: {'✅ Yes' if triggered else '❌ No'}")
        
        if triggered:
            exec_trace = reachability_report.get("execution_trace", [])
            print(f"   📋 Execution trace: {len(exec_trace)} steps")
            summary = reachability_report.get("reasoning_summary", "")
            if summary:
                print(f"   📝 Summary: {summary[:100]}...")
        else:
            print(f"   ❌ Vulnerability not triggered, verification failed")

        # ========== 5. Graph Data Construction ==========
        print("\n📊 Phase 5: Visualization Data Construction")
        retrieved_detailed_steps = sort_steps_by_category(exploit_res.get("retrieved_detailed_steps", {}))
        
        graph_data = build_tree_data(
            {},  # nodejs_paths parameter kept empty for backward compatibility
            retriever_NodeJs,
            rootcause_res.get("retrieved_rootcauses", {}),
            rootcause_res.get("final_vulnerability", {}).get("vulnerability_name", {}),
            retrieved_detailed_steps,
            rootcause_res.get("summar", {}),
            current_package=self.current_package  # Pass current package for graph filtering
        )
        
        print(f"   🎨 Graph nodes: {len(graph_data.get('visualization_data', {}).get('nodes', []))}")
        print(f"   🔗 Graph edges: {len(graph_data.get('visualization_data', {}).get('edges', []))}")

        print("\n" + "="*80)
        print("✅ Node.js Security Analysis Complete")
        print("="*80 + "\n")
        
        # Clear package context
        self.rag.clear_package_context()

        return {
            "nodejs_analysis": nodejs_res,
            "rootcause_analysis": rootcause_res,
            "exploit_analysis": exploit_res,
            "poc_reachability_report": reachability_report,
            "graph_data": graph_data
        }


class KnowledgeCoordinator:
    def __init__(self):
        # Use package-filtered RAG manager
        self.rag = PackageFilteredRAGManager()
        
        # ===== Pure Vector Store Mode =====
        cache_dir = Path("./vectorstore")
        force_rebuild = False
        
        if not cache_dir.exists():
            print("❌ Error: Vector store cache does not exist!")
            raise FileNotFoundError("Vector store cache not found, cannot start pure vector store mode")
        
        if os.environ.get("REBUILD_VECTORSTORE") == "1":
            print("⚠️ Warning: REBUILD_VECTORSTORE=1 but in pure vector store mode")
            force_rebuild = True
        
        print("📦 Using existing vector store cache")
        self.rag.refresh_all(force_rebuild=force_rebuild)
        # ===== Pure Vector Store Mode End =====
        
        self.retriever_NodeJs = self.rag.retriever_NodeJs
        self.retriever_rootcause = self.rag.retriever_rootcause
        self.retriever_exploit = self.rag.retriever_exploit

        # Initialize agents
        self.nodejs_classifier = NodeJsClassifierAgent(self.retriever_NodeJs)
        self.rootcause_agent = RootCauseAgent(self.retriever_rootcause)
        self.exploit_agent = ExploitAgent(self.retriever_exploit)
        self.poc_verifier = POCVerifierAgent()
        self.poc_validator = POCValidatorAgent()
        
        self.current_package = None

    def full_analysis(self, js_sources: Dict[str, str], poc_code: str = None) -> Dict:
        """
        Execute complete Node.js code security analysis, including POC validation.
        """
        # Concatenate JavaScript code
        js_code = "\n\n".join(
            f"// File: {filename}\n{code}"
            for filename, code in js_sources.items()
        )
        
        # ========== Package Detection ==========
        self.current_package = detect_package_from_code(js_code)
        if self.current_package:
            logger.info(f"📦 Detected package: {self.current_package}")
            self.rag.set_package_context(self.current_package)

        # Load Node.js type hierarchy
        hierarchy_str = self.rag.get_hierarchy()
        nodejs_res = self.nodejs_classifier.classify(js_code, hierarchy_str)
        
        retriever_NodeJs = nodejs_res.get("retriever_NodeJs", [])

        keyword_data = nodejs_res.get("analysis", {})
        NodeJstype_summary = keyword_data.get("summary", {})
        nodejs_keywords = keyword_data.get("NodeJsType_keywords", [])

        # Root cause analysis
        rootcause_res = self.rootcause_agent.find_rootcauses_and_audit(
            NodeJs_type=retriever_NodeJs,
            js_code=js_code,
            package_name=self.current_package
        )
        
        # Inject package name into final_vulnerability
        final_vuln = rootcause_res.get("final_vulnerability", {})
        if self.current_package and "package" not in final_vuln:
            final_vuln["package"] = self.current_package

        rootcause_category = load_rootcause_categories("rootcausecategory.json")
        logging.info("[Coordinator] Starting POC validation...")

        # Call POC validation
        is_matched, new_analysis = self.poc_validator.validate_poc_exploit(
            retriever_NodeJs=retriever_NodeJs,
            NodeJstype_summary=NodeJstype_summary,
            js_code=js_code,
            poc_code=poc_code,
            rootcause_res=final_vuln,
            NodeJs_tree=hierarchy_str,
            rootcause_tree=rootcause_category
        )

        # Standardize return structure
        response_data = {
            "nodejs_analysis": nodejs_res,
            "rootcause_analysis": rootcause_res,
            "new_nodejs_type": {},
            "new_rootcause": {},
            "poc_validation": {},
            "update_status": {}
        }

        if is_matched:
            exploited_vuln = {
                "vulnerability_name": final_vuln.get("vulnerability_name"),
                "reason": final_vuln.get("reason"),
                "location": final_vuln.get("location"),
                "trigger_point": final_vuln.get("trigger_point"),
                "code_snippet": final_vuln.get("code_snippet", ""),
                "package": final_vuln.get("package", self.current_package)
            }
            response_data["poc_validation"] = {
                "original_matched": True,
                "reasoning": "POC exploits the vulnerability identified in root cause analysis. Validation successful.",
                "exploited_vulnerability": exploited_vuln
            }
            logging.info("[KnowledgeCoordinator] ✅ POC validation successful, vulnerability matched.")
        else:
            logging.info("[KnowledgeCoordinator] ❌ POC does not match, generating new analysis.")
            if new_analysis:
                update_result = self.poc_validator.update_rootcause_based_on_poc(new_analysis)
                rootcause_update_status = "Update successful" if update_result.get("success") else "Update failed"
                # Note: Rebuilding requires knowledge base files, may fail in pure vector store mode
                if update_result.get("success"):
                    print("⚠️ Knowledge base update requires vector store rebuild, but currently in pure vector store mode")
                    print("Please rebuild manually or restore knowledge base file configuration")
                # self.rag.refresh_all(force_rebuild=True)  # Commented out to avoid auto-rebuild
                
                response_data["update_status"] = {
                    "rootcause_updated": update_result.get("success", False),
                    "nodejs_type_updated": "NodeJs_type" in str(update_result.get("operations", [])),
                    "details": update_result.get("operations", []),
                    "errors": update_result.get("errors", [])
                }

                response_data["new_nodejs_type"] = new_analysis.get("NodeJstype_analysis", {})
                response_data["new_rootcause"] = new_analysis.get("rootcause_analysis", {})
                response_data["poc_validation"] = {
                    "original_matched": False,
                    "reasoning": f"POC does not exploit current vulnerability analysis. Knowledge base expansion initiated ({rootcause_update_status}).",
                    "exploited_vulnerability": None
                }
            else:
                response_data["poc_validation"] = {
                    "original_matched": False,
                    "reasoning": "POC does not exploit current vulnerability analysis, and no new analysis was generated.",
                    "exploited_vulnerability": None
                }
        
        # Clear package context
        self.rag.clear_package_context()

        return response_data


def sort_steps_by_category(retrieved_detailed_steps):
    """
    Sort exploit steps according to specified category order
    """
    category_order = [
        'Preparation',
        'VulnerabilityTrigger',
        'StateManipulation',
        'ProfitExtraction',
        'Settlement'
    ]
    
    parsed_steps = []
    for step_str in retrieved_detailed_steps:
        name_match = re.search(r'Name: ([^\n]+)', step_str)
        name = name_match.group(1) if name_match else 'Unknown'
        
        category_match = re.search(r'Category: ([^\n]+)', step_str)
        category = category_match.group(1) if category_match else 'Unknown'
        
        steps_match = re.search(r'Steps: ([^\n]+)', step_str)
        steps = steps_match.group(1) if steps_match else ''
        
        impact_match = re.search(r'Impact: ([^\n]+)', step_str)
        impact = impact_match.group(1) if impact_match else ''
        
        sample_code_match = re.search(r'SampleCode: (\[.*?\])', step_str, re.DOTALL)
        sample_code = []
        if sample_code_match:
            try:
                sample_code = json.loads(sample_code_match.group(1).replace('\\"', '"'))
            except json.JSONDecodeError:
                sample_code = [sample_code_match.group(1)]
        
        parsed_steps.append({
            'name': name,
            'category': category,
            'steps': steps,
            'impact': impact,
            'sample_code': sample_code,
            'original': step_str
        })
    
    def get_category_index(category):
        try:
            return category_order.index(category)
        except ValueError:
            return len(category_order)
    
    sorted_steps = sorted(parsed_steps, key=lambda x: get_category_index(x['category']))
    return [step['original'] for step in sorted_steps]


def extract_package_from_doc(doc: str) -> str:
    """Extract package name from document string"""
    if isinstance(doc, dict):
        return doc.get("package", "")
    
    # String format
    package_match = re.search(r"package: ([^\n]+)", doc)
    if package_match:
        return package_match.group(1).strip()
    
    # Backward compatibility
    if "mcpjam" in doc.lower() or "inspector" in doc.lower():
        return "@mcpjam/inspector"
    if "orval" in doc.lower():
        return "@orval/mock"
    
    return None


def build_tree_data(
    nodejs_paths,
    retriever_NodeJs=None,
    retrieved_rootcauses=None,
    vulnerablename=None,
    detailed_steps=None,
    rootcausequery=None,
    current_package=None
):
    """
    Build graph structure for frontend visualization
    Only process nodes related to current package
    """
    nodes, edges, node_cache = [], [], {}

    def add_node(name, node_type, description=""):
        if name not in node_cache:
            node = {
                "id": name,
                "name": name,
                "type": node_type,
                "description": description
            }
            nodes.append(node)
            node_cache[name] = node
        return node_cache[name]

    def add_edge(source, target):
        edges.append({"source": source["id"], "target": target["id"]})

    # Create root node
    root = add_node("NodeJsType", "nodejs_root", "Node.js Type Root Node")

    # Extract retriever_NodeJs information
    nodejs_name_to_pattern = {}
    nodejs_name_to_package = {}
    if retriever_NodeJs:
        for p in retriever_NodeJs:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", p)
            pattern_match = re.search(r"Pattern: (.+?)(?:\n|$)", p)
            package = extract_package_from_doc(p)
            
            if name_match and pattern_match:
                name = name_match.group(1).strip()
                pattern = pattern_match.group(1).strip()
                nodejs_name_to_pattern[name] = pattern
                if package:
                    nodejs_name_to_package[name] = package

    # Extract retrieved_rootcauses information
    rootcause_name_to_pattern = {}
    rootcause_name_to_package = {}
    if retrieved_rootcauses:
        for rc in retrieved_rootcauses:
            if isinstance(rc, str) and rc.strip().startswith('{'):
                try:
                    data = json.loads(rc)
                    name = data.get("name", "Unknown")
                    pattern = data.get("pattern", "No pattern description")
                    package = data.get("package")
                    rootcause_name_to_pattern[name] = pattern
                    if package:
                        rootcause_name_to_package[name] = package
                except Exception:
                    pass
            else:
                name_match = re.search(r"Name: (.+?)(?:\n|$)", rc)
                pattern_match = re.search(r"Pattern: (.+?)(?:\n|$)", rc)
                package = extract_package_from_doc(rc)
                if name_match and pattern_match:
                    name = name_match.group(1).strip()
                    pattern = pattern_match.group(1).strip()
                    rootcause_name_to_pattern[name] = pattern
                    if package:
                        rootcause_name_to_package[name] = package

    # Extract detailed_steps information
    step_name_to_impact = {}
    if detailed_steps:
        for s in detailed_steps:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", s)
            impact_match = re.search(r"Impact: (.+?)(?:\n|$)", s)
            if name_match and impact_match:
                step_name_to_impact[name_match.group(1).strip()] = impact_match.group(1).strip()

    # Update node descriptions
    def update_description_if_exists(node):
        name = node["name"]
        if name in nodejs_name_to_pattern:
            node["description"] = nodejs_name_to_pattern[name]
        elif name in rootcause_name_to_pattern:
            node["description"] = rootcause_name_to_pattern[name]
        elif name in step_name_to_impact:
            node["description"] = step_name_to_impact[name]

    # Build node relationships - only process nodes belonging to current package
    if retriever_NodeJs:
        for nodejs_info in retriever_NodeJs:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", nodejs_info)
            related_exploit_match = re.search(r"Related Exploit: (.+?)(?:\n|$)", nodejs_info)
            package = extract_package_from_doc(nodejs_info)
            
            # If current package specified, skip nodes from other packages
            if current_package and package and package != current_package:
                continue
                
            if not name_match:
                continue
                
            nodejs_name = name_match.group(1).strip()
            
            if related_exploit_match:
                exploits = [e.strip() for e in related_exploit_match.group(1).split(",")]
                for exp in exploits:
                    if "." in exp:
                        parts = [p.strip() for p in exp.split(".") if p.strip()]
                        previous_part_node = add_node(nodejs_name, "nodejs_type")
                        for idx, part in enumerate(parts):
                            part_node = add_node(part, "rootcause", f"Exploit: {part}")
                            add_edge(previous_part_node, part_node)
                            previous_part_node = part_node
                    else:
                        exp_node = add_node(exp, "rootcause", f"Exploit: {exp}")
                        add_edge(add_node(nodejs_name, "nodejs_type"), exp_node)

    # Filter missing root causes by package
    missing_rootcauses = []
    for rc_name in rootcause_name_to_pattern:
        rc_package = rootcause_name_to_package.get(rc_name)
        
        if not current_package:
            if rc_name not in node_cache:
                missing_rootcauses.append(rc_name)
        else:
            if rc_package == current_package and rc_name not in node_cache:
                missing_rootcauses.append(rc_name)
            elif not rc_package and vulnerablename and vulnerablename.lower() in rc_name.lower():
                if rc_name not in node_cache:
                    missing_rootcauses.append(rc_name)

    if missing_rootcauses:
        complex_node = add_node("complex", "complex",
                                rootcausequery or f"{current_package or 'Node.js'} Application Composite Issue Analysis")
        for rc_name in missing_rootcauses:
            rc_node = add_node(rc_name, "rootcause", rootcause_name_to_pattern.get(rc_name, "Undefined description"))
            add_edge(complex_node, rc_node)

    # Attack steps connections
    if vulnerablename and detailed_steps and vulnerablename in node_cache:
        target_node = node_cache[vulnerablename]
        prev_node = None
        for step_info in detailed_steps:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", step_info)
            impact_match = re.search(r"Impact: (.+?)(?:\n|$)", step_info)
            
            # Filter attack steps by package
            applicable_match = re.search(r"applicable_to: \[([^\]]+)\]", step_info)
            if applicable_match and current_package:
                applicable_str = applicable_match.group(1)
                if '"*"' not in applicable_str and "'*'" not in applicable_str:
                    if f'"{current_package}"' not in applicable_str and f"'{current_package}'" not in applicable_str:
                        pkg_without_at = current_package.replace('@', '')
                        if f'"{pkg_without_at}"' not in applicable_str and f"'{pkg_without_at}'" not in applicable_str:
                            continue
            
            if name_match and impact_match:
                step_name = name_match.group(1).strip()
                step_impact = impact_match.group(1).strip()
                step_node = add_node(step_name, "exploit", step_impact)
                if prev_node:
                    add_edge(prev_node, step_node)
                else:
                    add_edge(target_node, step_node)
                prev_node = step_node
                node_cache[step_name]["description"] = step_impact

    for n in nodes:
        update_description_if_exists(n)

    return {
        "visualization_data": {
            "nodes": nodes,
            "edges": edges
        }
    }


def save_results_to_file(result: Dict, module_name: str) -> Path:
    """
    Save analysis results to structured files
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(OUTPUT_DIR) / f"{module_name}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save full JSON results
    json_path = output_dir / "full_analysis.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    # Save security report
    report_path = output_dir / "security_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Node.js Code Security Analysis Report\n\n")
        f.write(f"**Module Name**: {module_name}\n")
        f.write(f"**Analysis Time**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Extract package information if available
        package_name = None
        if "rootcause_analysis" in result:
            final_vuln = result["rootcause_analysis"].get("final_vulnerability", {})
            package_name = final_vuln.get("package")
        
        if package_name:
            f.write(f"**Analyzed Package**: {package_name}\n\n")
        
        # Node.js type analysis
        nodejs_res = result["nodejs_analysis"]
        f.write("## Node.js Type Analysis\n")
        f.write(f"**Type Summary**: {nodejs_res.get('analysis', {}).get('summary', 'No summary')}\n\n")
        f.write("**Related Node.js Types**:\n")
        for nodejs_type in nodejs_res.get("retriever_NodeJs", []):
            short_type = nodejs_type[:200] + "..." if len(nodejs_type) > 200 else nodejs_type
            f.write(f"- {short_type}\n")
        f.write("\n")
        
        # Root cause analysis
        rootcause_res = result["rootcause_analysis"]
        f.write("## Root Cause Analysis\n")
        f.write("**Matched Root Cause Entries**:\n")
        for entry in rootcause_res.get("retrieved_rootcauses", []):
            short_entry = entry[:200] + "..." if len(entry) > 200 else entry
            f.write(f"- {short_entry}\n")
        f.write("\n")

        # Vulnerability summary
        vuln_info = result["rootcause_analysis"].get("final_vulnerability", {})
        f.write("## Vulnerability Summary\n")
        f.write(f"**Vulnerability Name**: {vuln_info.get('vulnerability_name', 'Unknown')}\n\n")
        if package_name:
            f.write(f"**Affected Package**: {package_name}\n\n")
        f.write(f"**Vulnerability Description**:\n{vuln_info.get('reason', 'No description')}\n\n")
        f.write(f"**Vulnerability Location**: {vuln_info.get('location', 'Unknown')}\n\n")
        f.write(f"**Key Code Snippet**:\n```javascript\n{vuln_info.get('code_snippet', 'None')}\n```\n\n")
        
        # Exploit analysis
        exploit_res = result["exploit_analysis"]
        f.write("## Exploit Analysis\n")
        f.write("**Selected Attack Steps**:\n")
        for step in exploit_res.get("step_selection", {}).get("selected_steps", []):
            f.write(f"- {step}\n")
        f.write(f"\n**Attack Summary**: {exploit_res.get('step_selection', {}).get('exploit_summary', 'No summary')}\n\n")
        
        # Save POC code
        poc_code = exploit_res.get("poc_generation", "")
        if poc_code:
            poc_path = output_dir / "exploit_poc.js"
            with open(poc_path, "w", encoding="utf-8") as poc_file:
                poc_file.write(poc_code)
            f.write(f"**POC Code**: Saved to [exploit_poc.js]({poc_path.name})\n\n")
        
        # POC reachability report
        reachability = result["poc_reachability_report"]
        f.write("## POC Reachability Verification\n")
        f.write(f"**Vulnerability Reachable**: {'Yes' if reachability.get('vulnerability_triggered', False) else 'No'}\n\n")
        f.write(f"**Trigger Point**: {vuln_info.get('trigger_point', 'Unknown')}\n\n")
        f.write(f"**Reasoning Summary**: {reachability.get('reasoning_summary', 'No summary')}\n\n")
        f.write("**Execution Trace**:\n")
        for i, step in enumerate(reachability.get("execution_trace", []), 1):
            operation = step.get('operation', step.get('function', 'Unknown'))
            params = step.get('parameters', step.get('state_change', ''))
            f.write(f"- Step {i}: {operation} -> {params}\n")
        f.write("\n")
        
        # Recommendations
        recommendations = reachability.get("recommendations", [])
        if recommendations:
            f.write("## Recommendations\n")
            for i, rec in enumerate(recommendations, 1):
                f.write(f"{i}. {rec}\n")
            f.write("\n")
        
        # Conclusion
        f.write("## Conclusion\n")
        if reachability.get("vulnerability_triggered", False):
            f.write("✅ Verification Passed: POC successfully triggers the vulnerability\n")
        else:
            f.write("❌ Verification Failed: POC cannot trigger the vulnerability\n")
    
    return output_dir


def analyze_js_from_file(file_path: str) -> Dict:
    """
    Analyze Node.js code from file path
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    filename = os.path.basename(file_path)
    js_sources = {filename: content}
    
    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)
    
    return result


def analyze_js_from_content(content: str, filename: str) -> Dict:
    """
    Analyze Node.js code from content string
    """
    js_sources = {filename: content}
    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)
    
    return result


if __name__ == "__main__":
    import sys
    
    # Support command line arguments
    if len(sys.argv) > 1:
        js_dir = sys.argv[1]
    else:
        # Default path
        js_dir = "D:\\Projects\\25security\\NodeJsPOC\\js_examples\\mcpjam_inspector"
    
    # Find all .js files
    js_files = [f for f in os.listdir(js_dir) if f.endswith(".js") or f.endswith(".ts")]

    if len(js_files) == 0:
        raise FileNotFoundError(f"No .js or .ts files found in {js_dir}")

    js_sources = {}
    for filename in js_files:
        file_path = os.path.join(js_dir, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            js_sources[filename] = f.read()

    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)

    # Save results
    output_dir = save_results_to_file(result, "NodeJsAnalysis")
    print(f"\n📁 Analysis report saved to: {output_dir}")