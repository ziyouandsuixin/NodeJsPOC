"""
File Utilities Module

Provides utility functions for loading and processing various knowledge base files:
- Node.js type hierarchy with descriptions
- Exploit behavior steps and descriptions
- Root cause categories
- Path finding in tree structures

Date: 2025
Version: 1.0.0
"""

import json
import os
from typing import List, Optional, Dict, Any


def load_nodejs_types_hierarchy(file_path: str) -> str:
    """
    Load Node.js type JSON file and return a formatted string showing its hierarchy and descriptions.
    This string will be used to build prompts for better LLM understanding and matching of Node.js types.
    
    Args:
        file_path: Path to the Node.js type JSON file
        
    Returns:
        Formatted string showing the hierarchy with descriptions
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Recursive function to build hierarchy string with descriptions
    def build_hierarchy_string(node: Dict[str, Any], level: int = 0) -> List[str]:
        lines = []
        indent = "  " * level  # Use indentation to show hierarchy level
        
        # Build node info: name + description (if exists)
        node_info = f"{indent}- {node['name']}"
        if 'description' in node:
            node_info += f": {node['description']}"
        elif 'category' in node:
            node_info += f" (Category: {node['category']})"
        
        lines.append(node_info)
        
        # Recursively process children
        if 'children' in node:
            for child in node['children']:
                lines.extend(build_hierarchy_string(child, level + 1))
        return lines
    
    # Generate hierarchy lines and join into string
    hierarchy_lines = build_hierarchy_string(data)
    return "\n".join(hierarchy_lines)


def load_exploit_steps(file_path: str) -> str:
    """
    Load ExploitBehavior steps file and return a formatted string.
    
    Args:
        file_path: Path to the exploit behavior JSON file
        
    Returns:
        Formatted string with exploit steps organized by category
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    lines = []
    
    # Iterate through all categories
    for category, steps in data.items():
        if category == "ExploitBehavior":
            continue  # Skip root node
        
        # Add category title
        lines.append(f"- {category}")
        
        # Add all steps in this category
        for step in steps:
            name = step.get("name", "")
            description = step.get("description", "")
            lines.append(f"  - {name}: {description}")
        
        # Add empty line between categories
        lines.append("")
    
    return "\n".join(lines)


def load_rootcause_categories(file_path: str) -> str:
    """
    Load root cause categories file and return a formatted string.
    
    Args:
        file_path: Path to the root cause categories JSON file
        
    Returns:
        Formatted string with root cause categories and descriptions
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    lines = []
    
    # Iterate through all vulnerability categories
    for category in data:
        name = category.get("name", "")
        description = category.get("description", "")
        
        # Add category name and description
        lines.append(f"- {name}: {description}")
    
    return "\n".join(lines)


def find_path_to_node(tree_data: Dict[str, Any], target_name: str, current_path: Optional[List[str]] = None) -> Optional[List[str]]:
    """
    Find the complete path to a node with the specified name in the Node.js type tree.
    
    Args:
        tree_data: Loaded JSON tree data or subtree node
        target_name: Name of the Node.js type to find
        current_path: Current recursion path (used internally). Defaults to None.
    
    Returns:
        List of names from root to target node. Returns None if not found.
    """
    if current_path is None:
        current_path = []

    # Add current node name to path
    current_path.append(tree_data['name'])

    # If target node found, return current path
    if tree_data['name'] == target_name:
        return current_path

    # If children exist, search recursively
    if 'children' in tree_data and tree_data['children']:
        for child in tree_data['children']:
            # Pass a copy of current_path to avoid contamination between branches
            result = find_path_to_node(child, target_name, current_path.copy())
            if result is not None:
                return result

    # If target not found in this branch, return None
    return None