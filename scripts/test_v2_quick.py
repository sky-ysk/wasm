#!/usr/bin/env python3
"""
Quick test of V2 feature extraction on 2 samples
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from wasm_feature_extractor import extract_features, format_features_for_prompt
from pilot_experiment import call_llm

PROJECT_ROOT = Path(__file__).parent.parent
TEST_DIR = PROJECT_ROOT / "data" / "WasmMal-main" / "Data_NewSplit" / "test"

# Test 2 samples
test_files = [
    ("0e1a3fdf1b7a9dc10e2338790122b1a27e8554d75945ef8b0fb34f9df75091b6.wasm", "benign"),
    ("b2dQfkff697026fa1fb05b48e501ab53a5c38eef8a0562569766d7f88470dfdf.wasm", "malware"),
]

ANALYSIS_PROMPT_V2 = """你是一个 WebAssembly 安全分析专家。请分析以下 WebAssembly 模块的多粒度特征，判断其是否为恶意代码。

{features}

请基于以上特征进行分析，重点关注：
1. 导出函数名是否包含可疑关键词（如 hash、mine、crypt、work 等）
2. 数据段字符串是否包含恶意库路径或算法名称（如 cryptonight、monero 等）
3. 位运算频率是否异常高（>100 次可能表示哈希/加密计算）
4. 循环密度是否异常（>50 可能表示计算密集型代码）

请按以下 JSON 格式输出分析结果（只输出 JSON，不要其他内容）：
{{
  "verdict": "malicious" 或 "benign",
  "malware_type": "cryptojacking" / "obfuscation" / "data_exfiltration" / "ad_fraud" / "other" / "none",
  "confidence": "high" / "medium" / "low",
  "reasoning": "详细说明判断依据，引用具体的特征数据",
  "behavior_description": "用自然语言描述该模块的实际行为"
}}"""

for filename, expected in test_files:
    print(f"\n{'='*60}")
    print(f"Testing: {filename}")
    print(f"Expected: {expected}")
    print(f"{'='*60}")
    
    wasm_path = str(TEST_DIR / filename)
    
    # Extract features
    print("\n1. Extracting features...")
    features = extract_features(wasm_path)
    
    if "error" in features:
        print(f"   ERROR: {features['error']}")
        continue
    
    print(f"   ✓ File size: {features['file_size']}")
    print(f"   ✓ Exports: {len(features['exports'])}")
    print(f"   ✓ Suspicious exports: {features['suspicious_exports']}")
    print(f"   ✓ Bitwise ops: {features['instruction_counts']['bitwise']}")
    
    # Format features
    print("\n2. Formatting features...")
    features_text = format_features_for_prompt(features)
    print(f"   ✓ Formatted text length: {len(features_text)} chars")
    
    # Call LLM
    print("\n3. Calling LLM...")
    prompt = ANALYSIS_PROMPT_V2.format(features=features_text)
    response, usage = call_llm(prompt)
    
    print(f"   ✓ Response length: {len(response)} chars")
    print(f"   ✓ Token usage: {usage}")
    
    # Parse result
    print("\n4. Parsing result...")
    try:
        result = json.loads(response)
        print(f"   ✓ Verdict: {result.get('verdict')}")
        print(f"   ✓ Malware type: {result.get('malware_type')}")
        print(f"   ✓ Confidence: {result.get('confidence')}")
        print(f"   ✓ Reasoning: {result.get('reasoning', '')[:100]}...")
        
        correct = "✓" if result.get('verdict') == expected else "✗"
        print(f"\n   Result: {result.get('verdict')} (expected: {expected}) {correct}")
    except json.JSONDecodeError as e:
        print(f"   ✗ JSON parse error: {e}")
        print(f"   Raw response: {response[:200]}...")
