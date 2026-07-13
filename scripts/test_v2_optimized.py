#!/usr/bin/env python3
"""
测试优化后的 V2 特征提取器
仅测试两个误判样本
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from wasm_feature_extractor import extract_features, format_features_for_prompt
from pilot_experiment_v2 import analyze_sample_v2

PROJECT_ROOT = Path(__file__).parent.parent
TEST_DIR = PROJECT_ROOT / "data" / "WasmMal-main" / "Data_NewSplit" / "test"

# 两个误判样本
test_samples = [
    {
        "file": "b2dQfkff697026fa1fb05b48e501ab53a5c38eef8a0562569766d7f88470dfdf.wasm",
        "expected_label": "malicious",
    },
    {
        "file": "123u9U9Xc713672f719f922987efeba74b25d95aff0b07702496240dbb37aafb.wasm",
        "expected_label": "malicious",
    },
]

print("=" * 80)
print("V2 优化测试 - 针对误判样本")
print("=" * 80)

for i, sample in enumerate(test_samples, 1):
    filename = sample["file"]
    expected_label = sample["expected_label"]
    wasm_path = str(TEST_DIR / filename)
    
    print(f"\n[{i}/2] {filename}")
    print(f"预期标签: {expected_label}")
    
    # 提取特征
    features = extract_features(wasm_path)
    if "error" in features:
        print(f"错误: {features['error']}")
        continue
    
    print(f"\n特征提取结果:")
    print(f"  可疑导出: {features['suspicious_exports']}")
    print(f"  混淆导出: {features.get('obfuscated_exports', [])}")
    print(f"  位运算: {features['instruction_counts']['bitwise']}")
    print(f"  代码熵: {features.get('code_entropy', 0):.2f}")
    print(f"  挖矿上下文: {features.get('mining_context', {})}")
    print(f"  可疑度评分: {features.get('suspicion_score', 0)}/100")
    
    # 调用 LLM
    result = analyze_sample_v2(wasm_path, expected_label)
    
    print(f"\nLLM 判定结果:")
    print(f"  判定: {result.get('verdict')}")
    print(f"  类型: {result.get('malware_type')}")
    print(f"  置信度: {result.get('confidence')}")
    print(f"  推理: {result.get('reasoning', '')[:200]}...")
    
    correct = "✓" if result.get('verdict') == expected_label else "✗"
    print(f"\n结果: {correct}")

print("\n" + "=" * 80)
print("测试完成")
print("=" * 80)
