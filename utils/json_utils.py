# utils/json_utils.py
import json
import re
from typing import Dict

def try_parse_json(response: str) -> Dict:
    # 实现保持不变
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        json_pattern = r"```json\s*(.*?)\s*```"
        matches = re.findall(json_pattern, response, re.DOTALL)
        if matches:
            try:
                return json.loads(matches[0])
            except:
                pass
        start_idx, end_idx = response.find("{"), response.rfind("}")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            try:
                return json.loads(response[start_idx : end_idx + 1])
            except:
                pass
    return {"error": "Failed to parse JSON", "raw": response[:300]}