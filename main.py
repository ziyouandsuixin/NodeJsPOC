# main.py
import logging
from openai import OpenAI
from typing import Dict, List, Any
import json
import os
import datetime
from pathlib import Path
import re

# 修改导入路径
#from extract.extract_main import extract_js_files  # 假设有Node.js提取函数
from config import OUTPUT_DIR, KNOWLEDGE_BASE_PATHS, LOG_FILE
from rag.vector_store import build_vectorstore
from rag.rag_manager import RAGManager
from utils.file_utils import load_nodejs_types_hierarchy, load_exploit_steps, find_path_to_node, load_rootcause_categories
from agents.nodeJs_cla_agent import NodeJsClassifierAgent  # 改为Node.js分类代理
from agents.rootcause_agent import RootCauseAgent
from agents.exploit_agent import ExploitAgent
from agents.verifier_agent import POCVerifierAgent
from agents.poc_validator_agent import POCValidatorAgent

# 确保输出目录存在
Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)

# 日志设置
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)

class AnalysisCoordinator:
    def __init__(self):
        # 初始化检索器
        self.rag = RAGManager()

        # 使用全局 retriever
        self.retriever_NodeJs = self.rag.retriever_NodeJs  # 改为NodeJs
        self.retriever_rootcause = self.rag.retriever_rootcause
        self.retriever_exploit = self.rag.retriever_exploit

        # 初始化代理
        self.nodejs_classifier = NodeJsClassifierAgent(self.retriever_NodeJs)  # 改为Node.js分类器
        self.rootcause_agent = RootCauseAgent(self.retriever_rootcause)
        self.exploit_agent = ExploitAgent(self.retriever_exploit)
        self.poc_verifier = POCVerifierAgent()

        # 新增POC验证代理
        self.poc_validator = POCValidatorAgent()

    def full_analysis(self, js_sources: Dict[str, str]) -> Dict:  # 改为js_sources
        """
        执行完整的Node.js代码安全分析
        
        Args:
            js_sources: 字典，键为文件名，值为JavaScript代码
            
        Returns:
            包含分析结果的字典
        """
        # 将所有JavaScript代码拼接成一个字符串
        js_code = "\n\n".join(
            f"// File: {filename}\n{code}" 
            for filename, code in js_sources.items()
        )
        
        # 加载Node.js类型层次结构
        hierarchy_str = self.rag.get_hierarchy()

        # Node.js分类分析
        nodejs_res = self.nodejs_classifier.classify(js_code, hierarchy_str)  # 改为nodejs
        retrieved_NodeJs = nodejs_res.get("retrieved_NodeJs", [])  # 改为retrieved_NodeJs

        # 获取keyword_data和Node.js类型关键词
        keyword_data = nodejs_res.get("analysis", {})
        nodejs_keywords = keyword_data.get("NodeJsType_keywords", [])  # 改为NodeJsType_keywords

        # 重新加载原始JSON数据
        with open("NodeJstypetree.json", 'r', encoding='utf-8') as f:  # 改为NodeJstypetree.json
            nodejs_tree_data = json.load(f)

        logger.info(f"[Coordinator] Node.js类型关键词: {nodejs_keywords}")
        # 为每个关键词查找路径
        nodejs_paths = {}  # 改为nodejs_paths
        for keyword in nodejs_keywords:
            path = find_path_to_node(nodejs_tree_data, keyword)
            if path:
                nodejs_paths[keyword] = path

        # ============== 简单有效的调试代码 ==============
        print(f"\n=== 调试：路径查找 ===")
        print(f"关键词: {nodejs_keywords}")

        # 为每个关键词查找路径
        nodejs_paths = {}
        for keyword in nodejs_keywords:
            print(f"查找关键词: '{keyword}'")
            path = find_path_to_node(nodejs_tree_data, keyword)
            if path:
                nodejs_paths[keyword] = path
                print(f"  找到路径: {path}")
            else:
                print(f"  未找到路径")

        print(f"总计找到 {len(nodejs_paths)} 条路径")

        # 如果没有找到，检查树结构
        if not nodejs_paths:
            print(f"\n=== 调试：树结构检查 ===")
            # 简单打印树的一级节点
            if 'children' in nodejs_tree_data:
                print(f"树根节点名称: {nodejs_tree_data.get('name', 'No name')}")
                for child in nodejs_tree_data['children']:
                    name = child.get('name', 'No name')
                    print(f"一级节点: {name}")
                    
                    # 检查相关攻击
                    if 'related_exploit' in child:
                        exploits = child['related_exploit']
                        print(f"  相关攻击: {exploits}")
                        
                        # 检查是否有匹配的关键词
                        for keyword in nodejs_keywords:
                            if any(keyword in str(exp) for exp in exploits):
                                print(f"  关键词 '{keyword}' 出现在相关攻击中")
        # ============== 调试代码结束 ==============
        # 在路径查找后添加日志
        if not nodejs_paths:
            logger.warning("[Coordinator] 未找到任何Node.js类型路径!")
        else:
            logger.info(f"[Coordinator] 找到的Node.js类型路径: {nodejs_paths}")

        logger.info(f"[Coordinator] Node.js结果 -> {retrieved_NodeJs}")

        # 根因分析
        rootcause_res = self.rootcause_agent.find_rootcauses_and_audit(
            NodeJs_type=retrieved_NodeJs,  # 改为NodeJs_type
            js_code=js_code  # 改为js_code
        )

        # 加载ExploitBehavior步骤
        exploit_steps = load_exploit_steps("ExploitBehaviortree.json")
        
        # 生成Exploit
        exploit_res = self.exploit_agent.generate_exploit(
            rootcause_res["final_vulnerability"],
            exploit_steps
        )

        # POC可达性验证
        poc_code = exploit_res.get("poc_generation", "")
        vuln_info = rootcause_res.get("final_vulnerability", {})
        reachability_report = self.poc_verifier.verify_poc(vuln_info, js_code, poc_code)  # 改为js_code

        retrieved_detailed_steps = sort_steps_by_category(exploit_res.get("retrieved_detailed_steps", {}))

        graph_data = build_tree_data(
            nodejs_paths,  # 改为nodejs_paths
            retrieved_NodeJs,  # 改为retrieved_NodeJs
            rootcause_res.get("retrieved_rootcauses", {}),
            rootcause_res.get("final_vulnerability", {}).get("vulnerability_name", {}),
            retrieved_detailed_steps,
            rootcause_res.get("summar", {})  # 注意：原代码是summer，但rootcause_agent.py中是summar
        )

        return {
            "nodejs_analysis": nodejs_res,  # 改为nodejs_analysis
            "rootcause_analysis": rootcause_res,
            "exploit_analysis": exploit_res,
            "poc_reachability_report": reachability_report,
            "graph_data": graph_data
        }

class KnowledgeCoordinator:
    def __init__(self):
        # 初始化检索器
        self.rag = RAGManager()

        # 使用全局 retriever
        self.retriever_NodeJs = self.rag.retriever_NodeJs  # 改为NodeJs
        self.retriever_rootcause = self.rag.retriever_rootcause
        self.retriever_exploit = self.rag.retriever_exploit

        # 初始化代理
        self.nodejs_classifier = NodeJsClassifierAgent(self.retriever_NodeJs)  # 改为Node.js分类器
        self.rootcause_agent = RootCauseAgent(self.retriever_rootcause)
        self.exploit_agent = ExploitAgent(self.retriever_exploit)
        self.poc_verifier = POCVerifierAgent()

        # 新增POC验证代理
        self.poc_validator = POCValidatorAgent()

    def full_analysis(self, js_sources: Dict[str, str], poc_code: str = None) -> Dict:  # 改为js_sources
        """
        执行完整的Node.js代码安全分析，包含POC验证。
        """
        # 拼接JavaScript代码
        js_code = "\n\n".join(  # 改为js_code
            f"// File: {filename}\n{code}"
            for filename, code in js_sources.items()
        )

        # 加载Node.js类型层次结构
        hierarchy_str = self.rag.get_hierarchy()
        nodejs_res = self.nodejs_classifier.classify(js_code, hierarchy_str)  # 改为nodejs
        retrieved_NodeJs = nodejs_res.get("retrieved_NodeJs", [])  # 改为retrieved_NodeJs

        keyword_data = nodejs_res.get("analysis", {})
        NodeJstype_summary = keyword_data.get("summary", {})  # 改为NodeJstype_summary
        nodejs_keywords = keyword_data.get("NodeJsType_keywords", [])  # 改为NodeJsType_keywords
        
        # 加载Node.js树结构
        with open("NodeJstypetree.json", 'r', encoding='utf-8') as f:  # 改为NodeJstypetree.json
            nodejs_tree_data = json.load(f)

        nodejs_paths = {}  # 改为nodejs_paths
        for keyword in nodejs_keywords:
            path = find_path_to_node(nodejs_tree_data, keyword)
            if path:
                nodejs_paths[keyword] = path

        # 根因分析
        rootcause_res = self.rootcause_agent.find_rootcauses_and_audit(
            NodeJs_type=retrieved_NodeJs,  # 改为NodeJs_type
            js_code=js_code  # 改为js_code
        )

        rootcause_category = load_rootcause_categories("rootcausecategory.json")

        logging.info("[Coordinator] 开始POC验证...")

        final_vuln = rootcause_res.get("final_vulnerability", {})

        # 调用 POC 验证
        is_matched, new_analysis = self.poc_validator.validate_poc_exploit(
            retriever_NodeJs = retrieved_NodeJs,  # 改为retriever_NodeJs
            NodeJstype_summary = NodeJstype_summary,  # 改为NodeJstype_summary
            js_code=js_code,  # 改为js_code
            poc_code=poc_code,
            rootcause_res=final_vuln,
            NodeJs_tree=hierarchy_str,  # 改为NodeJs_tree
            rootcause_tree=rootcause_category
        )

        # ============= 统一返回结构 =============
        response_data = {
            "nodejs_analysis": nodejs_res,  # 改为nodejs_analysis
            "rootcause_analysis": rootcause_res,
            "new_nodejs_type": {},  # 改为new_nodejs_type
            "new_rootcause": {},
            "poc_validation": {},
            "update_status": {}
        }

        # 成功匹配情况
        if is_matched:
            exploited_vuln = {
                "vulnerability_name": final_vuln.get("vulnerability_name"),
                "reason": final_vuln.get("reason"),
                "location": final_vuln.get("location"),
                "trigger_point": final_vuln.get("trigger_point"),
                "code_snippet": final_vuln.get("code_snippet", "")
            }
            response_data["poc_validation"] = {
                "original_matched": True,
                "reasoning": "POC利用的漏洞与根因分析结果一致，验证成功。",
                "exploited_vulnerability": exploited_vuln
            }
            logging.info("[KnowledgeCoordinator] ✅ POC验证成功，漏洞匹配。")

        # 不匹配情况 — 生成新分析并扩充数据集
        else:
            logging.info("[KnowledgeCoordinator] ❌ POC验证不匹配，生成新分析。")
            if new_analysis:
                # 更新知识库文件
                update_result = self.poc_validator.update_rootcause_based_on_poc(new_analysis)
                rootcause_update_status = "更新成功" if update_result.get("success") else "更新失败"

                # 刷新全局RAG
                self.rag.refresh_all()
                
                # 记录更新状态
                response_data["update_status"] = {
                    "rootcause_updated": update_result.get("success", False),
                    "nodejs_type_updated": "NodeJs_type" in str(update_result.get("operations", [])),  # 改为nodejs_type
                    "details": update_result.get("operations", []),
                    "errors": update_result.get("errors", [])
                }

                response_data["new_nodejs_type"] = new_analysis.get("NodeJstype_analysis", {})  # 改为NodeJstype_analysis
                response_data["new_rootcause"] = new_analysis.get("rootcause_analysis", {})
                response_data["poc_validation"] = {
                    "original_matched": False,
                    "reasoning": f"POC未利用当前分析漏洞，已启动知识库扩充（{rootcause_update_status}）。",
                    "exploited_vulnerability": None
                }

            else:
                response_data["poc_validation"] = {
                    "original_matched": False,
                    "reasoning": "POC未利用当前分析漏洞，且未生成新的扩充分析。",
                    "exploited_vulnerability": None
                }

        return response_data


def sort_steps_by_category(retrieved_detailed_steps):
    """
    按照指定的类别顺序对漏洞利用步骤进行排序
    
    参数:
    retrieved_detailed_steps (list): 包含漏洞利用步骤的字符串列表
    
    返回:
    list: 按类别排序后的步骤列表
    """
    # 定义类别顺序
    category_order = [
        'Preparation',
        'VulnerabilityTrigger',
        'StateManipulation',
        'ProfitExtraction',
        'Settlement'
    ]
    
    # 解析每个步骤字符串并提取信息
    parsed_steps = []
    for step_str in retrieved_detailed_steps:
        # 提取Name
        name_match = re.search(r'Name: ([^\n]+)', step_str)
        name = name_match.group(1) if name_match else 'Unknown'
        
        # 提取Category
        category_match = re.search(r'Category: ([^\n]+)', step_str)
        category = category_match.group(1) if category_match else 'Unknown'
        
        # 提取Steps
        steps_match = re.search(r'Steps: ([^\n]+)', step_str)
        steps = steps_match.group(1) if steps_match else ''
        
        # 提取Impact
        impact_match = re.search(r'Impact: ([^\n]+)', step_str)
        impact = impact_match.group(1) if impact_match else ''
        
        # 提取SampleCode
        sample_code_match = re.search(r'SampleCode: (\[.*?\])', step_str, re.DOTALL)
        sample_code = []
        if sample_code_match:
            try:
                # 尝试解析为JSON数组
                sample_code = json.loads(sample_code_match.group(1).replace('\\"', '"'))
            except json.JSONDecodeError:
                # 如果解析失败，保持原始格式
                sample_code = [sample_code_match.group(1)]
        
        parsed_steps.append({
            'name': name,
            'category': category,
            'steps': steps,
            'impact': impact,
            'sample_code': sample_code,
            'original': step_str
        })
    
    # 按指定类别顺序排序
    def get_category_index(category):
        try:
            return category_order.index(category)
        except ValueError:
            return len(category_order)
    
    sorted_steps = sorted(parsed_steps, key=lambda x: get_category_index(x['category']))
    
    return [step['original'] for step in sorted_steps]

import json
import re

def build_tree_data(
    nodejs_paths,  # 改为nodejs_paths
    retrieved_NodeJs=None,  # 改为retrieved_NodeJs
    retrieved_rootcauses=None,
    vulnerablename=None,
    detailed_steps=None,
    rootcausequery=None
):
    """
    构建可前端识别的图结构
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

    # ========== ① 创建NodeJsType根节点 ==========
    root = add_node("NodeJsType", "nodejs_root", "Node.js类型根节点")  # 改为NodeJsType

    # 用于记录每个路径的最底层节点
    bottom_nodejs_nodes = []  # 改为bottom_nodejs_nodes

    # ========== ② 构建Node.js类型路径结构 ==========
    for path in nodejs_paths.values():  # 改为nodejs_paths
        if not path:
            continue
        previous_node = None
        for i, node_name in enumerate(path):
            node_type = "nodejs_type" if i > 0 else "nodejs_root"  # 改为nodejs_type
            node = add_node(node_name, node_type, f"Node.js类型节点: {node_name}")
            if previous_node:
                add_edge(previous_node, node)
            previous_node = node
        bottom_nodejs_nodes.append(path[-1])  # 改为bottom_nodejs_nodes

    # ========== ③ 提取 retrieved_NodeJs 信息 ==========
    nodejs_name_to_pattern = {}  # 改为nodejs_name_to_pattern
    if retrieved_NodeJs:  # 改为retrieved_NodeJs
        for p in retrieved_NodeJs:  # 改为retrieved_NodeJs
            name_match = re.search(r"Name: (.+?)(?:\n|$)", p)
            pattern_match = re.search(r"Pattern: (.+?)(?:\n|$)", p)
            if name_match and pattern_match:
                name = name_match.group(1).strip()
                pattern = pattern_match.group(1).strip()
                nodejs_name_to_pattern[name] = pattern  # 改为nodejs_name_to_pattern

    # ========== ④ 提取 retrieved_rootcauses 信息 ==========
    rootcause_name_to_pattern = {}
    if retrieved_rootcauses:
        for rc in retrieved_rootcauses:
            try:
                data = json.loads(rc)
                name = data["name"]
                pattern = data.get("pattern", "无模式描述")
                rootcause_name_to_pattern[name] = pattern
            except Exception as e:
                print(f"解析根因失败: {e}")

    # ========== ⑤ 提取 detailed_steps 信息 ==========
    step_name_to_impact = {}
    if detailed_steps:
        for s in detailed_steps:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", s)
            impact_match = re.search(r"Impact: (.+?)(?:\n|$)", s)
            if name_match and impact_match:
                step_name_to_impact[name_match.group(1).strip()] = impact_match.group(1).strip()

    # ========== ⑥ 更新节点：如果名称在 retrieved_* 或 detailed_steps 中 ==========
    def update_description_if_exists(node):
        name = node["name"]
        if name in nodejs_name_to_pattern:  # 改为nodejs_name_to_pattern
            node["description"] = nodejs_name_to_pattern[name]  # 改为nodejs_name_to_pattern
        elif name in rootcause_name_to_pattern:
            node["description"] = rootcause_name_to_pattern[name]
        elif name in step_name_to_impact:
            node["description"] = step_name_to_impact[name]

    for n in nodes:
        update_description_if_exists(n)

    # ========== ⑦ 将 retrieved_NodeJs 建立对应 Exploit（rootcause）关系 ==========
    if retrieved_NodeJs:  # 改为retrieved_NodeJs
        for nodejs_info in retrieved_NodeJs:  # 改为retrieved_NodeJs
            name_match = re.search(r"Name: (.+?)(?:\n|$)", nodejs_info)
            related_exploit_match = re.search(r"Related Exploit: (.+?)(?:\n|$)", nodejs_info)
            if not name_match:
                continue
            nodejs_name = name_match.group(1).strip()  # 改为nodejs_name
            if related_exploit_match:
                exploits = [e.strip() for e in related_exploit_match.group(1).split(",")]
                for exp in exploits:
                    if "." in exp:
                        parts = [p.strip() for p in exp.split(".") if p.strip()]
                        previous_part_node = add_node(nodejs_name, "nodejs_type")  # 改为nodejs_type
                        for idx, part in enumerate(parts):
                            part_node = add_node(part, "rootcause", f"漏洞利用: {part}")
                            add_edge(previous_part_node, part_node)
                            previous_part_node = part_node
                    else:
                        exp_node = add_node(exp, "rootcause", f"漏洞利用: {exp}")
                        add_edge(add_node(nodejs_name, "nodejs_type"), exp_node)  # 改为nodejs_type

    # ========== ⑧ 检查哪些 rootcauses 缺失，若有 → 建立"思维杂糅"节点 ==========
    missing_rootcauses = []
    for rc_name in rootcause_name_to_pattern:
        if rc_name not in node_cache:
            missing_rootcauses.append(rc_name)

    if missing_rootcauses:
        complex_node = add_node("complex", "complex",
                                rootcausequery or "Node.js应用复合问题分析")  # 改为Node.js应用
        # 只连接底层节点
        for pname in bottom_nodejs_nodes:  # 改为bottom_nodejs_nodes
            if pname in node_cache:
                add_edge(node_cache[pname], complex_node)
        # 将缺少的根因挂上去
        for rc_name in missing_rootcauses:
            rc_node = add_node(rc_name, "rootcause", rootcause_name_to_pattern.get(rc_name, "未定义描述"))
            add_edge(complex_node, rc_node)

    # ========== ⑨ 若 vulnerablename 存在步骤，则按顺序连线 ==========
    if vulnerablename and detailed_steps and vulnerablename in node_cache:
        target_node = node_cache[vulnerablename]
        prev_node = None
        for step_info in detailed_steps:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", step_info)
            impact_match = re.search(r"Impact: (.+?)(?:\n|$)", step_info)
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

    return {
        "visualization_data": {
            "nodes": nodes,
            "edges": edges
        }
    }



def save_results_to_file(result: Dict, module_name: str) -> Path:  # 改为module_name
    """
    将分析结果保存到结构化的文件中
    
    Args:
        result: 分析结果字典
        module_name: Node.js模块名称  # 改为module_name
        
    Returns:
        输出目录的Path对象
    """
    # 创建时间戳
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 创建输出目录
    output_dir = Path(OUTPUT_DIR) / f"{module_name}_{timestamp}"  # 改为module_name
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. 保存完整的JSON结果
    json_path = output_dir / "full_analysis.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    # 2. 提取关键信息并保存为易读的报告
    report_path = output_dir / "security_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        # 报告头部
        f.write(f"# Node.js代码安全分析报告\n\n")  # 改为Node.js代码
        f.write(f"**模块名称**: {module_name}\n")  # 改为模块名称
        f.write(f"**分析时间**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Node.js类型分析
        nodejs_res = result["nodejs_analysis"]  # 改为nodejs_analysis
        f.write("## Node.js类型分析\n")  # 改为Node.js类型分析
        f.write(f"**类型摘要**: {nodejs_res.get('analysis', {}).get('summary', '无摘要')}\n\n")
        f.write("**相关Node.js类型**:\n")  # 改为Node.js类型
        for nodejs_type in nodejs_res.get("retrieved_NodeJs", []):  # 改为retrieved_NodeJs
            f.write(f"- {nodejs_type}\n")
        f.write("\n")
        
        # 根因分析
        rootcause_res = result["rootcause_analysis"]
        f.write("## 根因分析\n")
        f.write("**匹配到的根因条目**:\n")
        for entry in rootcause_res.get("retrieved_rootcauses", []):
            f.write(f"- {entry}\n")
        f.write("\n")

        # 漏洞摘要
        vuln_info = result["rootcause_analysis"].get("final_vulnerability", {})
        f.write("## 漏洞摘要\n")
        f.write(f"**漏洞名称**: {vuln_info.get('vulnerability_name', '未知')}\n\n")
        f.write(f"**漏洞描述**:\n{vuln_info.get('reason', '无描述')}\n\n")
        f.write(f"**漏洞位置**: {vuln_info.get('location', '未知')}\n\n")
        f.write(f"**关键代码片段**:\n```javascript\n{vuln_info.get('code_snippet', '无')}\n```\n\n")  # 改为javascript
        
        # 漏洞利用分析
        exploit_res = result["exploit_analysis"]
        f.write("## 漏洞利用分析\n")
        f.write("**选择的攻击步骤**:\n")
        for step in exploit_res.get("step_selection", {}).get("selected_steps", []):
            f.write(f"- {step}\n")
        f.write(f"\n**攻击摘要**: {exploit_res.get('step_selection', {}).get('exploit_summary', '无摘要')}\n\n")
        
        # 保存POC代码到单独文件
        poc_code = exploit_res.get("poc_generation", "")
        if poc_code:
            poc_path = output_dir / "exploit_poc.js"  # 改为.js
            with open(poc_path, "w", encoding="utf-8") as poc_file:
                poc_file.write(poc_code)
            f.write(f"**POC代码**: 已保存到 [exploit_poc.js]({poc_path.name})\n\n")  # 改为.js
        
        # POC可达性报告
        reachability = result["poc_reachability_report"]
        f.write("## POC可达性验证\n")
        f.write(f"**漏洞是否可达**: {'是' if reachability.get('vulnerability_triggered', False) else '否'}\n\n")
        f.write(f"**触发点**: {reachability.get('trigger_point', '未知')}\n\n")
        f.write(f"**原因摘要**: {reachability.get('reasoning_summary', '无摘要')}\n\n")
        f.write("**执行跟踪**:\n")
        for step in reachability.get("execution_trace", []):
            f.write(f"- 步骤 {step.get('step', '')}: {step.get('function', '')} -> {step.get('state_change', '')}\n")
        f.write("\n")
        
        # 结论
        f.write("## 结论\n")
        if reachability.get("vulnerability_triggered", False):
            f.write("✅ 验证通过：POC能够成功触发漏洞\n")
        else:
            f.write("❌ 验证失败：POC无法触发漏洞\n")
    
    return output_dir

def analyze_js_from_file(file_path: str) -> Dict:  # 改为analyze_js_from_file
    """
    从文件路径分析Node.js代码
    
    Args:
        file_path: JavaScript文件路径
        
    Returns:
        分析结果字典
    """
    # 读取文件内容
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 获取文件名
    filename = os.path.basename(file_path)
    
    # 创建代码源字典
    js_sources = {filename: content}  # 改为js_sources
    
    # 执行分析
    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)  # 改为js_sources
    
    return result

def analyze_js_from_content(content: str, filename: str) -> Dict:  # 改为analyze_js_from_content
    """
    从内容字符串分析Node.js代码
    
    Args:
        content: JavaScript代码内容
        filename: 文件名（用于标识）
        
    Returns:
        分析结果字典
    """
    # 创建代码源字典
    js_sources = {filename: content}  # 改为js_sources
    
    # 执行分析
    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)  # 改为js_sources
    
    return result

if __name__ == "__main__":
    # 修改为Node.js代码目录
    js_dir = "D:\Projects\\25security\\NodeJsPOC\js_examples\orval"  # 假设有js_examples目录
    
    # 找出文件夹下所有 .js 文件
    js_files = [f for f in os.listdir(js_dir) if f.endswith(".js")]  # 改为.js

    js_sources = {}  # 改为js_sources

    if len(js_files) == 0:
        raise FileNotFoundError(f"在 {js_dir} 下没有找到任何 .js 文件")  # 改为.js

    elif len(js_files) == 1:
        # 只有一个文件，直接读取
        js_path = os.path.join(js_dir, js_files[0])
        with open(js_path, "r", encoding="utf-8") as f:
            code = f.read()
        js_sources[js_files[0]] = code

    else:
        # 多个文件，调用 extract_js_files（需要实现）
        # extract_js_files(js_dir)
        # 暂时直接读取所有文件
        for filename in js_files:
            file_path = os.path.join(js_dir, filename)
            with open(file_path, "r", encoding="utf-8") as f:
                js_sources[filename] = f.read()

    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)  # 改为js_sources

    print("\n==== Node.js模块类型 & RootCause 综合分析 ====\n", json.dumps(result, ensure_ascii=False, indent=2))