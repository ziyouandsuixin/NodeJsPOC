# utils/file_utils.py
import json
import os

# 加载 NodeJsType 的树形结构（包含描述）
def load_nodejs_types_hierarchy(file_path: str) -> str:
    """
    加载Node.js类型JSON文件，并返回一个格式化的字符串，展示其层级结构和描述。
    这个字符串将用于后续构建提示词，帮助大模型更好地理解和匹配Node.js类型。
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # 递归函数，用于生成包含描述的层级字符串
    def build_hierarchy_string(node, level=0):
        lines = []
        indent = "  " * level  # 用缩进表示层级
        
        # 构建节点信息：名称 + 描述（如果存在）
        node_info = f"{indent}- {node['name']}"
        if 'description' in node:
            node_info += f": {node['description']}"
        elif 'category' in node:
            node_info += f" (Category: {node['category']})"
        
        lines.append(node_info)
        
        # 递归处理子节点
        if 'children' in node:
            for child in node['children']:
                lines.extend(build_hierarchy_string(child, level + 1))
        return lines
    
    # 生成层级列表并连接成字符串
    hierarchy_lines = build_hierarchy_string(data)
    return "\n".join(hierarchy_lines)

# 加载 ExploitBehaviortree 步骤名称和简介
def load_exploit_steps(file_path: str) -> str:
    """
    加载ExploitBehavior步骤文件，返回格式化的字符串
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    lines = []
    
    # 遍历所有分类
    for category, steps in data.items():
        if category == "ExploitBehavior":
            continue  # 跳过根节点
        
        # 添加分类标题
        lines.append(f"- {category}")
        
        # 添加该分类下的所有步骤
        for step in steps:
            name = step.get("name", "")
            description = step.get("description", "")
            lines.append(f"  - {name}: {description}")
        
        # 添加空行分隔不同分类
        lines.append("")
    
    return "\n".join(lines)

def load_rootcause_categories(file_path: str) -> str:
    """
    加载rootcause类别文件，返回格式化的字符串
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    lines = []
    
    # 遍历所有漏洞类别
    for category in data:
        name = category.get("name", "")
        description = category.get("description", "")
        
        # 添加类别名称和描述
        lines.append(f"- {name}: {description}")
    
    return "\n".join(lines)

# 在Node.js类型树中查找指定名称节点的完整路径
def find_path_to_node(tree_data, target_name, current_path=None):
    """
    在Node.js类型树中查找指定名称节点的完整路径。

    Args:
        tree_data (dict): 加载的JSON树数据或子树节点。
        target_name (str): 要查找的Node.js类型名称。
        current_path (list, optional): 当前递归路径，用于内部记录。默认为None。

    Returns:
        list: 从根节点到目标节点的名称路径列表。如果未找到，返回None。
    """
    if current_path is None:
        current_path = []

    # 将当前节点名称加入路径
    current_path.append(tree_data['name'])

    # 如果找到目标节点，返回当前路径
    if tree_data['name'] == target_name:
        return current_path

    # 如果有子节点，递归查找
    if 'children' in tree_data and tree_data['children']:
        for child in tree_data['children']:
            # 注意：这里传递 current_path 的副本，避免不同分支间的路径污染
            result = find_path_to_node(child, target_name, current_path.copy())
            if result is not None:
                return result

    # 如果当前分支未找到，返回None（回溯时current_path会被自动处理）
    return None