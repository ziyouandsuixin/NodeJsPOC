"""
JSON Utilities Module

Provides utility functions for parsing and handling JSON responses,
particularly from LLM outputs which may contain markdown formatting.

Date: 2025
Version: 1.0.0
"""

import json
import re
from typing import Dict, Any, Optional


def try_parse_json(response: str) -> Dict[str, Any]:
    """
    Attempt to parse JSON from various response formats.
    
    This function handles multiple JSON formats:
    - Pure JSON strings
    - JSON wrapped in markdown code blocks (```json ... ```)
    - JSON embedded in text with other content
    
    Args:
        response: Raw response string that may contain JSON
        
    Returns:
        Parsed JSON dictionary. If parsing fails, returns a dictionary with error information.
    """
    # Try direct JSON parsing first
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    
    # Try extracting JSON from markdown code blocks
    json_pattern = r"```json\s*(.*?)\s*```"
    matches = re.findall(json_pattern, response, re.DOTALL)
    if matches:
        for match in matches:
            try:
                return json.loads(match.strip())
            except json.JSONDecodeError:
                continue
    
    # Try extracting JSON content between curly braces
    start_idx, end_idx = response.find("{"), response.rfind("}")
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        try:
            json_str = response[start_idx : end_idx + 1]
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass
    
    # Try extracting JSON content between square brackets (for arrays)
    start_idx, end_idx = response.find("["), response.rfind("]")
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        try:
            json_str = response[start_idx : end_idx + 1]
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass
    
    # If all parsing attempts fail, return error dictionary
    return {
        "error": "Failed to parse JSON",
        "raw": response[:500] if len(response) > 500 else response
    }


def safe_json_dumps(data: Any, indent: Optional[int] = None, ensure_ascii: bool = False) -> str:
    """
    Safely convert Python object to JSON string with error handling.
    
    Args:
        data: Python object to serialize
        indent: Number of spaces for indentation (None for compact)
        ensure_ascii: Whether to escape non-ASCII characters
        
    Returns:
        JSON string representation of the data
    """
    try:
        return json.dumps(data, indent=indent, ensure_ascii=ensure_ascii)
    except (TypeError, ValueError, OverflowError) as e:
        return json.dumps({
            "error": f"Failed to serialize to JSON: {str(e)}",
            "data_type": str(type(data))
        })


def is_valid_json(json_str: str) -> bool:
    """
    Check if a string is valid JSON.
    
    Args:
        json_str: String to check
        
    Returns:
        True if valid JSON, False otherwise
    """
    try:
        json.loads(json_str)
        return True
    except json.JSONDecodeError:
        return False