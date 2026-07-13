#!/usr/bin/env python3
"""
单独测试 parse_error 样本，查看 LLM 完整输出
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from wasm_feature_extractor import extract_features, format_features_for_prompt
from pilot_experiment_v2 import analyze_sample_v2, parse_llm_json_response, ANALYSIS_PROMPT_V2
from pilot_experiment import call_llm

PROJECT_ROOT = Path(__file__).parent.parent
MALWARE_DIR = PROJECT_ROOT / "data" / "WasmMal-main" / "malware"

# parse_error 样本
filename = "b088046322bf45182bfac2fd77d52c6de411229f7e1432b5c1995ed17a15be26.wasm"
wasm_path = str(MALWARE_DIR / filename)

print("=" * 80)
print(f"单独测试 parse_error 样本")
print(f"文件: {filename}")
print("=" * 80)

# 提取特征
print("\n1. 提取特征...")
features = extract_features(wasm_path)
if "error" in features:
    print(f"错误: {features['error']}")
    sys.exit(1)

print(f"  可疑度评分: {features.get('suspicion_score', 0)}/100")
print(f"  可疑导出: {features['suspicious_exports']}")
print(f"  混淆导出: {features.get('obfuscated_exports', [])}")
print(f"  挖矿上下文: {features.get('mining_context', {})}")

# 格式化特征
print("\n2. 格式化特征...")
features_text = format_features_for_prompt(features)
print(f"  特征文本长度: {len(features_text)} 字符")

# 构造 Prompt
print("\n3. 构造 Prompt...")
prompt = ANALYSIS_PROMPT_V2.format(features=features_text)
print(f"  Prompt 长度: {len(prompt)} 字符")

# 调用 LLM
print("\n4. 调用 LLM...")
response, usage = call_llm(prompt)
print(f"  Token 使用: {usage}")
print(f"  响应长度: {len(response)} 字符")

# 显示原始响应
print("\n" + "=" * 80)
print("LLM 原始输出:")
print("=" * 80)
print(response)

# 解析响应
print("\n" + "=" * 80)
print("解析结果:")
print("=" * 80)
result = parse_llm_json_response(response)
print(json.dumps(result, indent=2, ensure_ascii=False))

# 保存完整结果
output_file = PROJECT_ROOT / "results" / "parse_error_sample.json"
with open(output_file, 'w') as f:
    json.dump({
        "file": filename,
        "features": features,
        "prompt": prompt,
        "raw_response": response,
        "parsed_result": result,
        "usage": usage,
    }, f, indent=2, ensure_ascii=False)

print(f"\n完整结果已保存到: {output_file}")
