import logging
from openai import OpenAI
from typing import Dict, List, Any
import json
import os
import datetime
from pathlib import Path
import re

# 修改导入路径
from config import OUTPUT_DIR, KNOWLEDGE_BASE_PATHS, LOG_FILE
from rag.vector_store import build_vectorstore
from rag.rag_manager import RAGManager
from utils.file_utils import load_nodejs_types_hierarchy, load_exploit_steps, find_path_to_node, load_rootcause_categories
from agents.nodeJs_cla_agent import NodeJsClassifierAgent
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
        self.retriever_NodeJs = self.rag.retriever_NodeJs
        self.retriever_rootcause = self.rag.retriever_rootcause
        self.retriever_exploit = self.rag.retriever_exploit

        # 初始化代理
        self.nodejs_classifier = NodeJsClassifierAgent(self.retriever_NodeJs)
        self.rootcause_agent = RootCauseAgent(self.retriever_rootcause)
        self.exploit_agent = ExploitAgent(self.retriever_exploit)
        self.poc_verifier = POCVerifierAgent()
        self.poc_validator = POCValidatorAgent()

    def full_analysis(self, js_sources: Dict[str, str]) -> Dict:
        """
        执行完整的Node.js代码安全分析
        """
        # 将所有JavaScript代码拼接成一个字符串
        js_code = "\n\n".join(
            f"// File: {filename}\n{code}" 
            for filename, code in js_sources.items()
        )
        
        print("\n" + "="*80)
        print("🚀 Node.js安全分析开始")
        print("="*80)
        
        # 加载Node.js类型层次结构
        hierarchy_str = self.rag.get_hierarchy()

        # ========== 1. Node.js分类分析 ==========
        print("\n📦 阶段1: Node.js组件分类")
        nodejs_res = self.nodejs_classifier.classify(js_code, hierarchy_str)
        
        # 🔴 修复点1: 将 retrieved_NodeJs 改为 retriever_NodeJs (与agent返回的键名一致)
        retriever_NodeJs = nodejs_res.get("retriever_NodeJs", [])
        keyword_data = nodejs_res.get("analysis", {})
        nodejs_keywords = keyword_data.get("NodeJsType_keywords", [])
        
        print(f"   ✅ 提取关键词: {', '.join(nodejs_keywords[:5])}{'...' if len(nodejs_keywords) > 5 else ''}")
        print(f"   📚 RAG命中: {len(retriever_NodeJs)} 条相关Node.js知识")
        
        # 显示命中的具体条目
        if retriever_NodeJs:
            print(f"   📋 命中的组件:")
            for i, doc in enumerate(retriever_NodeJs[:3]):
                name_match = re.search(r"Name: (.+?)(?:\n|$)", doc)
                name = name_match.group(1) if name_match else f"条目{i+1}"
                print(f"     - {name}")
            if len(retriever_NodeJs) > 3:
                print(f"     ... 等共{len(retriever_NodeJs)}条")
        else:
            print(f"   ⚠️ 未命中任何Node.js组件知识")

        # ========== 2. 根因分析 ==========
        print("\n🔬 阶段2: 漏洞根因分析")
        rootcause_res = self.rootcause_agent.find_rootcauses_and_audit(
            NodeJs_type=retriever_NodeJs,  # 🔴 修复点2: 参数名保持一致
            js_code=js_code
        )
        
        final_vuln = rootcause_res.get("final_vulnerability", {})
        vuln_name = final_vuln.get("vulnerability_name", "未知")
        confidence = final_vuln.get("confidence_level", "未知")
        location = final_vuln.get("location", "未知")
        
        print(f"   🎯 识别漏洞: {vuln_name}")
        print(f"   📊 置信度: {confidence}")
        print(f"   📍 漏洞位置: {location}")
        
        retrieved_rootcauses = rootcause_res.get("retrieved_rootcauses", [])
        print(f"   📚 根因知识命中: {len(retrieved_rootcauses)} 条")

        # ========== 3. 漏洞利用分析 ==========
        print("\n⚔️ 阶段3: 漏洞利用分析")
        exploit_steps = load_exploit_steps("ExploitBehaviortree.json")
        exploit_res = self.exploit_agent.generate_exploit(
            rootcause_res["final_vulnerability"],
            exploit_steps
        )
        
        selected_steps = exploit_res.get("step_selection", {}).get("selected_steps", [])
        print(f"   🎯 选择的攻击类型: {', '.join(selected_steps[:3])}{'...' if len(selected_steps) > 3 else ''}")
        
        detailed_steps = exploit_res.get("retrieved_detailed_steps", [])
        print(f"   📚 攻击步骤命中: {len(detailed_steps)} 条")
        
        poc_code = exploit_res.get("poc_generation", "")
        print(f"   💉 POC生成: {'✅ 成功' if poc_code else '❌ 失败'} (长度: {len(poc_code)} 字符)")

        # ========== 4. POC可达性验证 ==========
        print("\n🧪 阶段4: POC可达性验证")
        vuln_info = rootcause_res.get("final_vulnerability", {})
        reachability_report = self.poc_verifier.verify_poc(vuln_info, js_code, poc_code)
        
        triggered = reachability_report.get("vulnerability_triggered", False)
        print(f"   🚨 漏洞触发: {'✅ 是' if triggered else '❌ 否'}")
        
        if triggered:
            exec_trace = reachability_report.get("execution_trace", [])
            print(f"   📋 执行跟踪: {len(exec_trace)} 步")
            summary = reachability_report.get("reasoning_summary", "")
            if summary:
                print(f"   📝 摘要: {summary[:100]}...")
        else:
            print(f"   ❌ 漏洞未触发，验证失败")

        # ========== 5. 图数据构建 ==========
        print("\n📊 阶段5: 可视化数据构建")
        retrieved_detailed_steps = sort_steps_by_category(exploit_res.get("retrieved_detailed_steps", {}))
        
        # 🔴 修复点3: 传递 retriever_NodeJs 而不是 nodejs_paths
        graph_data = build_tree_data(
            {},  # nodejs_paths参数保留为空字典，因为不再使用路径查找
            retriever_NodeJs,  # 🔴 改为 retriever_NodeJs
            rootcause_res.get("retrieved_rootcauses", {}),
            rootcause_res.get("final_vulnerability", {}).get("vulnerability_name", {}),
            retrieved_detailed_steps,
            rootcause_res.get("summar", {})
        )
        
        print(f"   🎨 图节点数: {len(graph_data.get('visualization_data', {}).get('nodes', []))}")
        print(f"   🔗 图边数: {len(graph_data.get('visualization_data', {}).get('edges', []))}")

        print("\n" + "="*80)
        print("✅ Node.js安全分析完成")
        print("="*80 + "\n")

        return {
            "nodejs_analysis": nodejs_res,
            "rootcause_analysis": rootcause_res,
            "exploit_analysis": exploit_res,
            "poc_reachability_report": reachability_report,
            "graph_data": graph_data
        }


class KnowledgeCoordinator:
    def __init__(self):
        # 初始化检索器
        self.rag = RAGManager()
        self.retriever_NodeJs = self.rag.retriever_NodeJs
        self.retriever_rootcause = self.rag.retriever_rootcause
        self.retriever_exploit = self.rag.retriever_exploit

        # 初始化代理
        self.nodejs_classifier = NodeJsClassifierAgent(self.retriever_NodeJs)
        self.rootcause_agent = RootCauseAgent(self.retriever_rootcause)
        self.exploit_agent = ExploitAgent(self.retriever_exploit)
        self.poc_verifier = POCVerifierAgent()
        self.poc_validator = POCValidatorAgent()

    def full_analysis(self, js_sources: Dict[str, str], poc_code: str = None) -> Dict:
        """
        执行完整的Node.js代码安全分析，包含POC验证。
        """
        # 拼接JavaScript代码
        js_code = "\n\n".join(
            f"// File: {filename}\n{code}"
            for filename, code in js_sources.items()
        )

        # 加载Node.js类型层次结构
        hierarchy_str = self.rag.get_hierarchy()
        nodejs_res = self.nodejs_classifier.classify(js_code, hierarchy_str)
        
        # 🔴 修复点4: 统一使用 retriever_NodeJs
        retriever_NodeJs = nodejs_res.get("retriever_NodeJs", [])

        keyword_data = nodejs_res.get("analysis", {})
        NodeJstype_summary = keyword_data.get("summary", {})
        nodejs_keywords = keyword_data.get("NodeJsType_keywords", [])

        # 根因分析
        rootcause_res = self.rootcause_agent.find_rootcauses_and_audit(
            NodeJs_type=retriever_NodeJs,  # 🔴 修复点5
            js_code=js_code
        )

        rootcause_category = load_rootcause_categories("rootcausecategory.json")
        logging.info("[Coordinator] 开始POC验证...")

        final_vuln = rootcause_res.get("final_vulnerability", {})

        # 调用 POC 验证
        is_matched, new_analysis = self.poc_validator.validate_poc_exploit(
            retriever_NodeJs=retriever_NodeJs,  # 🔴 修复点6
            NodeJstype_summary=NodeJstype_summary,
            js_code=js_code,
            poc_code=poc_code,
            rootcause_res=final_vuln,
            NodeJs_tree=hierarchy_str,
            rootcause_tree=rootcause_category
        )

        # 统一返回结构
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
                "code_snippet": final_vuln.get("code_snippet", "")
            }
            response_data["poc_validation"] = {
                "original_matched": True,
                "reasoning": "POC利用的漏洞与根因分析结果一致，验证成功。",
                "exploited_vulnerability": exploited_vuln
            }
            logging.info("[KnowledgeCoordinator] ✅ POC验证成功，漏洞匹配。")
        else:
            logging.info("[KnowledgeCoordinator] ❌ POC验证不匹配，生成新分析。")
            if new_analysis:
                update_result = self.poc_validator.update_rootcause_based_on_poc(new_analysis)
                rootcause_update_status = "更新成功" if update_result.get("success") else "更新失败"
                self.rag.refresh_all()
                
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


def build_tree_data(
    nodejs_paths,
    retriever_NodeJs=None,  # 🔴 修复点7: 参数名改为 retriever_NodeJs
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

    # 创建根节点
    root = add_node("NodeJsType", "nodejs_root", "Node.js类型根节点")

    # 提取 retriever_NodeJs 信息
    nodejs_name_to_pattern = {}
    if retriever_NodeJs:
        for p in retriever_NodeJs:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", p)
            pattern_match = re.search(r"Pattern: (.+?)(?:\n|$)", p)
            if name_match and pattern_match:
                name = name_match.group(1).strip()
                pattern = pattern_match.group(1).strip()
                nodejs_name_to_pattern[name] = pattern

    # 提取 retrieved_rootcauses 信息 - 修复JSON解析错误
    rootcause_name_to_pattern = {}
    if retrieved_rootcauses:
        for rc in retrieved_rootcauses:
            # 🔴 修复点8: 先检查是否为JSON格式
            if isinstance(rc, str) and rc.strip().startswith('{'):
                try:
                    data = json.loads(rc)
                    name = data.get("name", "未知")
                    pattern = data.get("pattern", "无模式描述")
                    rootcause_name_to_pattern[name] = pattern
                except Exception as e:
                    print(f"   ⚠️ 解析根因失败 (非JSON格式): {e}")
            else:
                # 如果是纯文本，尝试用正则提取
                name_match = re.search(r"Name: (.+?)(?:\n|$)", rc)
                pattern_match = re.search(r"Pattern: (.+?)(?:\n|$)", rc)
                if name_match and pattern_match:
                    name = name_match.group(1).strip()
                    pattern = pattern_match.group(1).strip()
                    rootcause_name_to_pattern[name] = pattern

    # 提取 detailed_steps 信息
    step_name_to_impact = {}
    if detailed_steps:
        for s in detailed_steps:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", s)
            impact_match = re.search(r"Impact: (.+?)(?:\n|$)", s)
            if name_match and impact_match:
                step_name_to_impact[name_match.group(1).strip()] = impact_match.group(1).strip()

    # 更新节点描述
    def update_description_if_exists(node):
        name = node["name"]
        if name in nodejs_name_to_pattern:
            node["description"] = nodejs_name_to_pattern[name]
        elif name in rootcause_name_to_pattern:
            node["description"] = rootcause_name_to_pattern[name]
        elif name in step_name_to_impact:
            node["description"] = step_name_to_impact[name]

    # 将 retriever_NodeJs 建立对应关系
    if retriever_NodeJs:
        for nodejs_info in retriever_NodeJs:
            name_match = re.search(r"Name: (.+?)(?:\n|$)", nodejs_info)
            related_exploit_match = re.search(r"Related Exploit: (.+?)(?:\n|$)", nodejs_info)
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
                            part_node = add_node(part, "rootcause", f"漏洞利用: {part}")
                            add_edge(previous_part_node, part_node)
                            previous_part_node = part_node
                    else:
                        exp_node = add_node(exp, "rootcause", f"漏洞利用: {exp}")
                        add_edge(add_node(nodejs_name, "nodejs_type"), exp_node)

    # 检查哪些 rootcauses 缺失，若有 → 建立"思维杂糅"节点
    missing_rootcauses = []
    for rc_name in rootcause_name_to_pattern:
        if rc_name not in node_cache:
            missing_rootcauses.append(rc_name)

    if missing_rootcauses:
        complex_node = add_node("complex", "complex",
                                rootcausequery or "Node.js应用复合问题分析")
        for rc_name in missing_rootcauses:
            rc_node = add_node(rc_name, "rootcause", rootcause_name_to_pattern.get(rc_name, "未定义描述"))
            add_edge(complex_node, rc_node)

    # 若 vulnerablename 存在步骤，则按顺序连线
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
    将分析结果保存到结构化的文件中
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = Path(OUTPUT_DIR) / f"{module_name}_{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 保存完整的JSON结果
    json_path = output_dir / "full_analysis.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    
    # 保存安全报告
    report_path = output_dir / "security_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(f"# Node.js代码安全分析报告\n\n")
        f.write(f"**模块名称**: {module_name}\n")
        f.write(f"**分析时间**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Node.js类型分析
        nodejs_res = result["nodejs_analysis"]
        f.write("## Node.js类型分析\n")
        f.write(f"**类型摘要**: {nodejs_res.get('analysis', {}).get('summary', '无摘要')}\n\n")
        f.write("**相关Node.js类型**:\n")
        for nodejs_type in nodejs_res.get("retriever_NodeJs", []):  # 🔴 修复点9
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
        f.write(f"**关键代码片段**:\n```javascript\n{vuln_info.get('code_snippet', '无')}\n```\n\n")
        
        # 漏洞利用分析
        exploit_res = result["exploit_analysis"]
        f.write("## 漏洞利用分析\n")
        f.write("**选择的攻击步骤**:\n")
        for step in exploit_res.get("step_selection", {}).get("selected_steps", []):
            f.write(f"- {step}\n")
        f.write(f"\n**攻击摘要**: {exploit_res.get('step_selection', {}).get('exploit_summary', '无摘要')}\n\n")
        
        # 保存POC代码
        poc_code = exploit_res.get("poc_generation", "")
        if poc_code:
            poc_path = output_dir / "exploit_poc.js"
            with open(poc_path, "w", encoding="utf-8") as poc_file:
                poc_file.write(poc_code)
            f.write(f"**POC代码**: 已保存到 [exploit_poc.js]({poc_path.name})\n\n")
        
        # POC可达性报告 - 🔴 修复点10: 修复字段映射
        reachability = result["poc_reachability_report"]
        f.write("## POC可达性验证\n")
        f.write(f"**漏洞是否可达**: {'是' if reachability.get('vulnerability_triggered', False) else '否'}\n\n")
        f.write(f"**触发点**: {vuln_info.get('trigger_point', '未知')}\n\n")  # 🔴 从vuln_info获取
        f.write(f"**原因摘要**: {reachability.get('reasoning_summary', '无摘要')}\n\n")
        f.write("**执行跟踪**:\n")
        for i, step in enumerate(reachability.get("execution_trace", []), 1):
            operation = step.get('operation', step.get('function', '未知'))
            params = step.get('parameters', step.get('state_change', ''))
            f.write(f"- 步骤 {i}: {operation} -> {params}\n")
        f.write("\n")
        
        # 结论
        f.write("## 结论\n")
        if reachability.get("vulnerability_triggered", False):
            f.write("✅ 验证通过：POC能够成功触发漏洞\n")
        else:
            f.write("❌ 验证失败：POC无法触发漏洞\n")
    
    return output_dir


def analyze_js_from_file(file_path: str) -> Dict:
    """
    从文件路径分析Node.js代码
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
    从内容字符串分析Node.js代码
    """
    js_sources = {filename: content}
    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)
    
    return result


if __name__ == "__main__":
    # Node.js代码目录
    js_dir = "D:\\Projects\\25security\\NodeJsPOC\\js_examples\\orval"
    
    # 找出所有.js文件
    js_files = [f for f in os.listdir(js_dir) if f.endswith(".js")]

    if len(js_files) == 0:
        raise FileNotFoundError(f"在 {js_dir} 下没有找到任何 .js 文件")

    js_sources = {}
    for filename in js_files:
        file_path = os.path.join(js_dir, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            js_sources[filename] = f.read()

    coord = AnalysisCoordinator()
    result = coord.full_analysis(js_sources)

    # 保存结果
    output_dir = save_results_to_file(result, "NodeJsAnalysis")
    print(f"\n📁 分析报告已保存到: {output_dir}")
    
    # 可选：打印完整JSON
    # print("\n==== Node.js模块类型 & RootCause 综合分析 ====\n", 
    #       json.dumps(result, ensure_ascii=False, indent=2))