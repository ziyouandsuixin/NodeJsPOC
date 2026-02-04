"""
图生成器 - 从NPMAnalyzer迁移依赖图生成功能

职责：生成前端兼容的依赖关系图数据
设计：不是传统Agent，而是专用数据生成器
"""

from typing import Dict, List, Any


class GraphGenerator:
    """
    依赖图生成器
    
    设计理念：
    1. 专门负责生成可视化数据
    2. 保持与前端D3.js的兼容性
    3. 输入：包数据 + 可选的分析结果
    4. 输出：标准化的图数据结构
    """
    
    def __init__(self):
        print(f"🔧 GraphGenerator初始化")
    
    def generate(self, package_data: Dict[str, Any], 
                analysis_results: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        生成依赖关系图
        
        Args:
            package_data: 解析后的package.json数据
            analysis_results: 其他分析结果（如安全问题）
            
        Returns:
            前端兼容的图数据结构
        """
        print(f"📊 GraphGenerator生成依赖图...")
        
        # 1. 生成基础图数据
        graph_data = self._generate_basic_graph(package_data)
        
        # 2. 集成分析结果（如标记有问题的节点）
        if analysis_results:
            graph_data = self._enhance_with_analysis(graph_data, analysis_results)
        
        print(f"✅ 图生成完成: {graph_data['metadata']['total_nodes']}节点, "
              f"{graph_data['metadata']['total_edges']}边")
        
        return graph_data
    
    def _generate_basic_graph(self, package_data: Dict[str, Any]) -> Dict[str, Any]:
        """生成基础依赖图"""
        nodes = []
        edges = []
        
        # 项目根节点
        project_name = package_data.get("name", "project")
        project_version = package_data.get("version", "0.0.0")
        
        nodes.append({
            "id": "root",
            "name": project_name,
            "type": "project_root",
            "version": project_version,
            "description": "主项目"
        })
        
        # 生产依赖节点
        deps = package_data.get("dependencies", {})
        for i, (dep_name, version) in enumerate(deps.items()):
            node_id = f"dep_{i}"
            nodes.append({
                "id": node_id,
                "name": dep_name,
                "type": "production_dependency",
                "version": version,
                "description": f"生产依赖: {dep_name}"
            })
            edges.append({
                "source": "root",
                "target": node_id,
                "type": "depends_on",
                "label": version
            })
        
        # 开发依赖节点
        dev_deps = package_data.get("devDependencies", {})
        for i, (dep_name, version) in enumerate(dev_deps.items()):
            node_id = f"dev_{i}"
            nodes.append({
                "id": node_id,
                "name": dep_name,
                "type": "development_dependency",
                "version": version,
                "description": f"开发依赖: {dep_name}"
            })
            edges.append({
                "source": "root",
                "target": node_id,
                "type": "dev_depends_on",
                "label": version
            })
        
        return {
            "visualization_data": {
                "nodes": nodes,
                "edges": edges
            },
            "metadata": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "production_deps": len(deps),
                "development_deps": len(dev_deps),
                "generator": "GraphGenerator"
            }
        }
    
    def _enhance_with_analysis(self, graph_data: Dict[str, Any], 
                              analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """用分析结果增强图数据"""
        # 例如：标记有安全问题的节点
        security_issues = analysis_results.get("security", {}).get("security_analysis", {}).get("issues", [])
        
        if security_issues:
            # 创建问题包名集合
            problematic_packages = {issue["package"] for issue in security_issues}
            
            # 更新节点类型
            for node in graph_data["visualization_data"]["nodes"]:
                if node["name"] in problematic_packages:
                    # 标记为有问题
                    node["type"] = "vulnerable_dependency"
                    node["has_issues"] = True
        
        return graph_data
    
    def _generate_advanced_graph(self, package_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        生成高级图（未来扩展）
        例如：依赖传递关系、版本冲突可视化等
        """
        # TODO: 未来实现更复杂的图分析
        return self._generate_basic_graph(package_data)


# 工厂函数
def create_graph_generator() -> GraphGenerator:
    """创建图生成器"""
    return GraphGenerator()


if __name__ == "__main__":
    """测试GraphGenerator"""
    test_data = {
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "react": "^18.2.0",
            "axios": "*"
        },
        "devDependencies": {
            "jest": "~29.5.0"
        }
    }
    
    print("🧪 测试GraphGenerator...")
    print("=" * 50)
    
    generator = GraphGenerator()
    result = generator.generate(test_data)
    
    print(f"\n📊 生成结果:")
    metadata = result["metadata"]
    print(f"总节点: {metadata['total_nodes']}")
    print(f"总边: {metadata['total_edges']}")
    print(f"生产依赖: {metadata['production_deps']}")
    print(f"开发依赖: {metadata['development_deps']}")
    
    print(f"\n🏷️  节点示例:")
    for node in result["visualization_data"]["nodes"][:3]:
        print(f"  {node['name']}: {node['type']}")
    
    print(f"\n🔗 边示例:")
    for edge in result["visualization_data"]["edges"][:2]:
        print(f"  {edge['source']} → {edge['target']}")
    
    print("\n✅ GraphGenerator测试通过")