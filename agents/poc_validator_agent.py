# agents/poc_validator_agent.py
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
        初始化POC验证代理
        """
        self.llm = ChatOpenAI(model_name=CHAT_MODEL,
                              #temperature=0.0,
                              openai_api_key=OPENAI_API_KEY,
                              openai_api_base="https://api.gpt.ge/v1/",
                              default_headers={"x-foo":"true"}
                              )

        # 验证提示词模板
        self.validation_prompt = PromptTemplate(
            input_variables=["js_code", "poc_code", "vuln_name", "vuln_reason", 
                           "vuln_location", "vuln_codesnippet", "vuln_triggerpoint"],
            template="""
请分析以下node.js和对应的POC（Proof of Concept）代码，判断POC是否利用了node.js中根因分析所呈现的漏洞。

node.js源码：
{js_code}

POC代码，此poc利用的是node.js中正确存在的漏洞
{poc_code}

漏洞细节：
- 漏洞名称: {vuln_name}
- 漏洞原因: {vuln_reason}
- 漏洞位置: {vuln_location}
- 漏洞片段： {vuln_codesnippet}
- 漏洞触发： {vuln_triggerpoint}

请基于以上信息严格分析：
1. node.js中是否存在上面描述的漏洞？
2. POC利用的漏洞是否是上面描述的漏洞？
    - 如果成功利用则 "is_exploiting"：true
    - 如果没有利用则 "is_exploiting"：false
3. 请你判断的时候严格判断，必须保证POC完完全全利用的是上面描述的漏洞，如果我把上面描述的漏洞修复之后，这个POC对于此智能合约就会失效。


请以严格的JSON格式返回分析结果：
{{
    "is_exploiting": true/false,
    "reasoning": "详细的推理过程，说明匹配或不匹配的具体原因",
}}

请确保分析准确客观，重点关注漏洞触发机制和攻击逻辑的一致性。
"""
        )

        # 生成新分析的提示词模板
        self.generation_prompt = PromptTemplate(
            input_variables=["retriever_NodeJs", "NodeJstype_summary", "js_code", "poc_code", "NodeJs_tree", "rootcause_tree"],
            template="""
请分析以下node,js和POC代码，根据POC实际利用的漏洞，生成对应的NodeJstype和rootcause分析。

---

### node.js描述（请作为语义基准）：
{NodeJstype_summary}

你必须以此描述为核心语义基准：  

---

### 相关参考
- node.js源码(js_code)：
{js_code}
- 此node.js源码所对应的POC：
{poc_code}
- 已识别类型（retriever_NodeJs）:
{retriever_NodeJs}
- 树定义（NodeJs_tree）:
{NodeJs_tree}
- 根因分类（rootcause_tree）:
{rootcause_tree}

---

### 生成要求


请严格按以下JSON格式输出：

{{
    "NodeJstype_analysis": {{

    }},
    "rootcause_analysis": {{

    }}
}}
"""
        )

        # 创建验证链
        self.validation_chain = self.validation_prompt | self.llm
        # 创建生成链
        self.generation_chain = self.generation_prompt | self.llm
    
    def validate_poc_exploit(self, retriever_NodeJs: Dict, NodeJstype_summary: str, js_code: str, poc_code: str, 
                           rootcause_res: Dict, NodeJs_tree: Dict, 
                           rootcause_tree: Dict) -> Tuple[bool, Dict]:
    
        try:
            # 提取根因分析的关键信息
            vuln_name = rootcause_res.get("vulnerability_name", "未知漏洞")
            vuln_reason = rootcause_res.get("reason", "未知原因")
            vuln_location = rootcause_res.get("location", "未知位置")
            vuln_codesnippet = rootcause_res.get("code_snippet", "未知片段")
            vuln_triggerpoint = rootcause_res.get("trigger_point", "未知触发")

            # 调用验证链
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

            # 解析响应
            validation_text = validation_response.content if hasattr(validation_response, 'content') else str(validation_response)
            validation_result = try_parse_json(validation_text)
            
            logging.info(f"[POCValidator] 验证结果: {validation_result}")

            if validation_result.get("is_exploiting", True):
                logging.info("POC验证通过：POC利用了根因分析所呈现的漏洞")
                return True, {}
            else:
                logging.warning("POC验证失败：POC未利用根因分析所呈现的漏洞，重新生成分析")
                # 生成新的NodeJstype和rootcause
                new_analysis = self._generate_new_analysis(
                    retriever_NodeJs, NodeJstype_summary, js_code, poc_code, NodeJs_tree, rootcause_tree
                )
                return False, new_analysis
                
        except Exception as e:
            logging.error(f"POC验证过程中出现错误: {str(e)}")
            # 出错时默认不匹配，继续原有流程
            return False, {}
        

def _generate_new_analysis(self, retriever_NodeJs: Dict, NodeJstype_summary: str, js_code: str, poc_code: str, 
                             NodeJs_tree: Dict, rootcause_tree: Dict) -> Dict[str, Any]:
    """生成新的node.js类型和根因分析"""
    try:
        # 调用生成链
        logging.info(f"LLM针对于node.js的评价如下：{NodeJstype_summary}")
        logging.info(f"原先识别到的node.js类型的条目如下：{retriever_NodeJs}")
        
        # 统一使用指定的变量名
        generation_response = self.generation_chain.invoke({
            "retriever_NodeJs": retriever_NodeJs,
            "NodeJstype_summary": NodeJstype_summary,
            "js_code": js_code,  
            "poc_code": poc_code, 
            "NodeJs_tree": json.dumps(NodeJs_tree, ensure_ascii=False),
            "rootcause_tree": json.dumps(rootcause_tree, ensure_ascii=False)
        })
        
        # 解析响应
        generation_text = generation_response.content if hasattr(generation_response, 'content') else str(generation_response)
        new_analysis = try_parse_json(generation_text)
        
        if new_analysis:
            logging.info("成功生成新的node.js类型和根因分析")
            
            # 获取node.js类型和根因分析
            NodeJstype = new_analysis.get("NodeJstype_analysis", {})
            rootcause = new_analysis.get("rootcause_analysis", {})
            
            # 修改相关漏洞利用格式
            self._format_related_exploit(NodeJstype, rootcause)
            
            logging.info(f"[POCValidator] 新node.js类型分析: {NodeJstype}")
            logging.info(f"[POCValidator] 新根因分析: {rootcause}")
            return new_analysis
        else:
            logging.error("解析LLM生成的新分析结果失败")
            return {}

    except Exception as e:  # ← 这里应该和try对齐，不是缩进在try块内
        logging.error(f"生成新分析时出错: {str(e)}")
        return {}

    def _format_related_exploit(self, NodeJstype: Dict, rootcause: Dict):
        """
        格式化related_exploit字段为"category.name"格式
        
        Args:
            protocoltype: 协议类型分析字典
            rootcause: 根因分析字典
        """
        try:
            # 从根因分析中提取category和vulnerability_name
            rootcause_category = rootcause.get("category", "UnknownCategory")
            vulnerability_name = rootcause.get("name", "UnknownVulnerability")
            
            # 构建新的related_exploit格式
            new_related_exploit = f"{rootcause_category}.{vulnerability_name}"

            # 更新protocoltype中的related_exploit字段
            if "related_exploit" in protocoltype:
                # 如果已有相关攻击模式，保留原有的并添加新的
                if isinstance(protocoltype["related_exploit"], list):
                    # 确保新格式不在列表中再添加
                    if new_related_exploit not in protocoltype["related_exploit"]:
                        protocoltype["related_exploit"].append(new_related_exploit)
                else:
                    # 如果不是列表，转换为列表并添加
                    protocoltype["related_exploit"] = [str(protocoltype["related_exploit"]), new_related_exploit]
            else:
                # 如果不存在related_exploit字段，创建新的
                protocoltype["related_exploit"] = [new_related_exploit]
                
            logging.info(f"已更新related_exploit格式: {protocoltype['related_exploit']}")
            
        except Exception as e:
            logging.error(f"格式化related_exploit时出错: {str(e)}")
            # 出错时设置默认值
            protocoltype["related_exploit"] = ["UnknownCategory.UnknownVulnerability"]

    def update_rootcause_based_on_poc(self, new_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        基于POC验证结果更新知识库
        
        Args:
            new_analysis: 新的分析结果，包含NodeJstype和rootcause分析
            
        Returns:
            操作结果报告
        """
        result_report = {
            "success": True,
            "operations": [],
            "errors": []
        }
        
        try:
            if not new_analysis:
                result_report["success"] = False
                result_report["errors"].append("新的分析结果为空")
                return result_report
            
            # 1. 处理rootcause分析结果
            rootcause_analysis = new_analysis.get("rootcause_analysis")
            if rootcause_analysis:
                rootcause_result = self._save_rootcause_analysis(rootcause_analysis)
                result_report["operations"].append({
                    "type": "rootcause",
                    "result": rootcause_result
                })
            else:
                result_report["errors"].append("未找到rootcause分析结果")
            
            # 2. 处理NodeJstype分析结果
            NodeJstype_analysis = new_analysis.get("NodeJstype_analysis")
            if NodeJstype_analysis:
                NodeJstype_result = self._save_NodeJstype_analysis(NodeJstype_analysis)
                result_report["operations"].append({
                    "type": "NodeJstype", 
                    "result": NodeJstype_result
                })
                
                # 3. 更新NodeJstype树形结构
                tree_result = self._update_NodeJstype_tree(NodeJstype_analysis)
                result_report["operations"].append({
                    "type": "NodeJstype_tree",
                    "result": tree_result
                })
            else:
                result_report["errors"].append("未找到NodeJstype分析结果")
                
        except Exception as e:
            logging.error(f"更新知识库时发生错误: {str(e)}")
            result_report["success"] = False
            result_report["errors"].append(f"异常: {str(e)}")
        
        return result_report

def _save_rootcause_analysis(self, rootcause_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    将rootcause分析保存到Rootcause.json
    
    Args:
        rootcause_analysis: rootcause分析结果
    
    Returns:
        保存结果
    """
    try:
        rootcause_file = KNOWLEDGE_BASE_PATHS["rootcause"] / "Rootcause.json"
        
        # 确保文件存在
        if not rootcause_file.exists():
            self._initialize_rootcause_file(rootcause_file)
        
        # 读取现有的rootcause数据
        with open(rootcause_file, 'r', encoding='utf-8') as f:
            rootcause_data = json.load(f)
        
        # 获取category与vulnerability名称
        category = rootcause_analysis.get("category", "Unknown")
        vulnerability_name = rootcause_analysis.get("name", "UnknownVulnerability")
        
        # 确保数据结构存在
        if "RootCause" not in rootcause_data:
            rootcause_data["RootCause"] = {}
        
        if category not in rootcause_data["RootCause"]:
            rootcause_data["RootCause"][category] = []
        
        # 获取本次的触发条件（symptoms）
        new_symptoms = rootcause_analysis.get("symptoms", [])
        
        # 查找是否存在同名漏洞
        updated = False
        for vuln in rootcause_data["RootCause"][category]:
            if vuln.get("name") == vulnerability_name:
                # 合并symptoms字段，同时确保不重复
                old_symptoms = vuln.get("symptoms", [])
                merged_symptoms = list({*old_symptoms, *new_symptoms})
                vuln["symptoms"] = merged_symptoms
                updated = True
                break
        
        if not updated:
            # 添加新的漏洞条目
            new_vuln = {
                "name": vulnerability_name,
                "pattern": rootcause_analysis.get("pattern", ""),
                "symptoms": new_symptoms,
                "related_exploit": rootcause_analysis.get("related_exploit", []),
            }
            rootcause_data["RootCause"][category].append(new_vuln)
        
        # 保存更新后的数据
        with open(rootcause_file, 'w', encoding='utf-8') as f:
            json.dump(rootcause_data, f, indent=2, ensure_ascii=False)
        
        logging.info(f"成功将rootcause分析保存到 {category} 分类")
        return {"status": "success", "category": category, "vulnerability": vulnerability_name}
    
    except Exception as e:
        logging.error(f"保存rootcause分析时出错: {str(e)}")
        return {"status": "error", "error": str(e)}


def _save_NodeJstype_analysis(self, NodeJstype_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    将 NodeJsType 分析结果保存到 NodeJsTypes.json
    
    实现逻辑：
    - 根据 "category" 定位节点；
    - 若该节点不存在则创建新的列表；
    - 若节点是叶子（非 list），则替换为列表结构；
    - 若节点是列表且已有同名Node.js类型，则更新；
    - 否则直接 append 新Node.js类型。
    """
    try:
        # 修改文件名为 NodeJsTypes.json
        NodeJs_file = Path("D:/pythonProject/POC-agent/version3_1112_GPT_LTM/NodeJsTypes.json")

        # 确保文件存在
        if not NodeJs_file.exists():
            self._initialize_NodeJstype_file(NodeJs_file)

        # 读取原有 NodeJsType 数据
        with open(NodeJs_file, 'r', encoding='utf-8') as f:
            NodeJs_data = json.load(f)

        # 确保顶层结构存在
        if "NodeJsType" not in NodeJs_data:
            NodeJs_data["NodeJsType"] = {}

        NodeJs_tree = NodeJs_data["NodeJsType"]

        # 获取当前分析的类别信息
        category = NodeJstype_analysis.get("category", "Base")
        NodeJs_name = NodeJstype_analysis.get("name", "UnknownNodeJsType")

        # 如果类别不存在，创建新数组
        if category not in NodeJs_tree:
            NodeJs_tree[category] = []

        # 若该类别是 dict（说明以前设计错误或叶节点），强制转成 list
        if isinstance(NodeJs_tree[category], dict):
            NodeJs_tree[category] = [NodeJs_tree[category]]

        # 保证是列表结构
        if not isinstance(NodeJs_tree[category], list):
            NodeJs_tree[category] = []

        # 查找是否已有相同Node.js类型名
        existing_types = [p for p in NodeJs_tree[category] if p.get("name") == NodeJs_name]

        if existing_types:
            # 保留旧字段，合并 symptoms / related_exploit
            for i, NodeJs_type in enumerate(NodeJs_tree[category]):
                if NodeJs_type.get("name") == NodeJs_name:
                    old_symptoms = NodeJs_type.get("symptoms", [])
                    old_related = NodeJs_type.get("related_exploit", [])

                    new_symptoms = NodeJstype_analysis.get("symptoms", [])
                    new_related = NodeJstype_analysis.get("related_exploit", [])

                    # 合并两者并去重
                    merged_symptoms = list(set(old_symptoms + new_symptoms))
                    merged_related = list(set(old_related + new_related))

                    # 更新字段，仅更新必要的部分
                    NodeJs_tree[category][i]["symptoms"] = merged_symptoms
                    NodeJs_tree[category][i]["related_exploit"] = merged_related

                    # 如果有新的 pattern，则可以更新（可选逻辑）
                    new_pattern = NodeJstype_analysis.get("pattern")
                    if new_pattern and new_pattern != NodeJs_type.get("pattern"):
                        NodeJs_tree[category][i]["pattern"] = new_pattern
                    break
        else:
            # 添加新的Node.js类型节点
            new_NodeJs_type = {
                "name": NodeJs_name,
                "category": category,
                "pattern": NodeJstype_analysis.get("pattern", ""),
                "symptoms": NodeJstype_analysis.get("symptoms", []),
                "related_exploit": NodeJstype_analysis.get("related_exploit", [])
            }
            NodeJs_tree[category].append(new_NodeJs_type)

        # 写回文件
        with open(NodeJs_file, 'w', encoding='utf-8') as f:
            json.dump(NodeJs_data, f, indent=2, ensure_ascii=False)

        logging.info(f"成功将Node.js类型 {NodeJs_name} 融入分类 {category}")
        return {"status": "success", "category": category, "NodeJs_type": NodeJs_name}

    except Exception as e:
        logging.error(f"保存 NodeJstype 分析时出错: {str(e)}")
        return {"status": "error", "error": str(e)}


def _update_NodeJstype_tree(self, NodeJstype_analysis: Dict[str, Any]) -> Dict[str, Any]:
    """
    更新 NodeJstypetree.json 树形结构:
    - 根据 category 找到对应节点；
    - 若存在 children，则直接添加新节点；
    - 若不存在 children，则创建并插入；
    - 新节点包含 name 和 description。
    """
    try:
        # 修改文件名为 NodeJstypetree.json
        tree_file = Path("D:/pythonProject/POC-agent/version3_1112_GPT_LTM/NodeJstypetree.json")

        # 确保文件存在
        if not tree_file.exists():
            self._initialize_NodeJs_tree_file(tree_file)

        # 读取现有树结构
        with open(tree_file, 'r', encoding='utf-8') as f:
            tree_data = json.load(f)

        category = NodeJstype_analysis.get("category", "")
        NodeJs_name = NodeJstype_analysis.get("name", "UnknownNodeJsType")
        pattern = NodeJstype_analysis.get("pattern", "")
        description = pattern

        # 定义一个递归函数，在树中查找目标节点
        def find_node_by_name(node: Dict[str, Any], target_name: str) -> Dict[str, Any] | None:
            if node.get("name") == target_name:
                return node
            if "children" in node:
                for child in node["children"]:
                    result = find_node_by_name(child, target_name)
                    if result:
                        return result
            return None

        # 从根开始查找 category 节点
        target_node = find_node_by_name(tree_data, category)
        if not target_node:
            logging.warning(f"未找到名为 {category} 的节点，无法添加Node.js类型 {NodeJs_name}")
            return {"status": "warning", "message": f"找不到分类 {category}"}

        # 如果节点没有 children，创建
        if "children" not in target_node or not isinstance(target_node["children"], list):
            target_node["children"] = []

        # 检查是否已有同名Node.js类型节点
        existing = next((c for c in target_node["children"] if c.get("name") == NodeJs_name), None)
        if existing:
            # 如果已有该节点，更新 description
            old_desc = existing.get("description", "")
            existing["description"] = (old_desc + "\n" + description).strip()
            logging.info(f"更新Node.js类型节点 {NodeJs_name} 的描述信息（追加新描述）")
        else:
            # 插入新节点
            new_node = {
                "name": NodeJs_name,
                "description": description
            }
            target_node["children"].append(new_node)
            logging.info(f"新增Node.js类型节点 {NodeJs_name} 到分类 {category}")

        # 写回文件
        with open(tree_file, 'w', encoding='utf-8') as f:
            json.dump(tree_data, f, indent=2, ensure_ascii=False)

        logging.info(f"成功更新 NodeJstype 树形结构，将 {NodeJs_name} 融入 {category}")
        return {"status": "success", "category": category, "NodeJs_type": NodeJs_name}

    except Exception as e:
        logging.error(f"更新 NodeJstypetree.json 时出错: {str(e)}")
        return {"status": "error", "error": str(e)}


@staticmethod
def _initialize_rootcause_file(file_path: Path):
    """初始化Rootcause.json文件 - 修改为Node.js相关分类"""
    initial_data = {
        "RootCause": {
            "原型污染": [],
            "命令注入": [],
            "文件系统漏洞": [],
            "NoSQL注入": [],
            "SQL注入": [],
            "模板注入": [],
            "正则表达式DoS": [],
            "事件循环阻塞": [],
            "内存泄漏": [],
            "身份验证绕过": [],
            "授权缺陷": [],
            "不安全反序列化": [],
            "跨站脚本": [],
            "CSRF": [],
            "SSRF": [],
            "信息泄露": [],
            "不安全的依赖": [],
            "配置错误": [],
            "日志伪造": [],
            "其他": []
        }
    }
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(initial_data, f, indent=2, ensure_ascii=False)


@staticmethod
def _initialize_NodeJstype_file(file_path: Path):
    """初始化NodeJsTypes.json文件"""
    initial_data = {
        "NodeJsType": {
            "Web框架": [],
            "数据库驱动": [],
            "ORM工具": [],
            "模板引擎": [],
            "测试框架": [],
            "构建工具": [],
            "包管理工具": [],
            "中间件": [],
            "身份验证库": [],
            "日志库": [],
            "缓存库": [],
            "队列系统": [],
            "WebSocket库": [],
            "GraphQL库": [],
            "微服务框架": [],
            "其他": []
        }
    }
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(initial_data, f, indent=2, ensure_ascii=False)


@staticmethod
def _initialize_NodeJs_tree_file(file_path: Path):
    """初始化NodeJstypetree.json文件"""
    initial_data = {
        "name": "NodeJsType",
        "description": "Node.js库和框架类型的根节点，包含所有子类型",
        "children": []
    }
    
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(initial_data, f, indent=2, ensure_ascii=False)