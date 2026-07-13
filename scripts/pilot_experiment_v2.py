#!/usr/bin/env python3
"""
Pilot Experiment V2 - 使用多粒度特征提取

改进点：
1. 使用 wasm_feature_extractor.py 提取结构化特征
2. 将特征格式化为 Prompt，而不是截断 WAT 文本
3. 对比 V1 的准确率提升
"""

import json
import sys
import time
from pathlib import Path

# 导入特征提取器
sys.path.insert(0, str(Path(__file__).parent))
from wasm_feature_extractor import extract_features, format_features_for_prompt

# 导入 LLM 调用函数（会自动使用 pilot_experiment.py 中的 LLM_CONFIG）
from pilot_experiment import call_llm, load_env, RESULTS_DIR

# 加载配置（仅用于显示模型名称）
PROJECT_ROOT = Path(__file__).parent.parent
_env = load_env(PROJECT_ROOT / ".env")
MODEL_NAME = _env.get("DASHSCOPE_MODEL", "qwen-plus")

# 使用与 V1 相同的 30 个样本（从 pilot_results.json 中读取）
V1_RESULTS_FILE = RESULTS_DIR / "pilot_results.json"

# 改进版 Prompt
ANALYSIS_PROMPT_V2 = """你是一个 WebAssembly 安全分析专家。请分析以下 WebAssembly 模块的多粒度特征，判断其是否为恶意代码。

{features}

**重要警告**：
1. 混淆的函数名（如 _wbYnAgshchW_hash）是恶意软件的典型特征，合法库使用标准命名（如 sha256_hash）
2. 挖矿上下文模式（makeMctx、setJob、mLoop）强烈暗示加密货币挖矿行为
3. 高位运算（>1000）+ 哈希相关导出 = 高度可疑的挖矿行为
4. 即使没有网络导入，本地挖矿仍然可能（通过 JS 桥接提交结果）
5. 可疑度评分 >= 70 的样本应优先判定为恶意

请基于以上特征进行分析，重点关注：
1. 导出函数名是否包含可疑关键词或混淆前缀
2. 数据段字符串是否包含恶意库路径或算法名称
3. 位运算频率是否异常高（>1000 次强烈暗示哈希/加密计算）
4. 是否存在挖矿上下文模式（context_creation、job_management、mining_loop）
5. 可疑度评分是否超过阈值

请按以下 JSON 格式输出分析结果（只输出 JSON，不要其他内容）：
{{
  "verdict": "malicious" 或 "benign",
  "malware_type": "cryptojacking" / "obfuscation" / "data_exfiltration" / "ad_fraud" / "other" / "none",
  "confidence": "high" / "medium" / "low",
  "reasoning": "详细说明判断依据，引用具体的特征数据",
  "behavior_description": "用自然语言描述该模块的实际行为"
}}"""


def parse_llm_json_response(response: str) -> dict:
    """解析 LLM 返回的 JSON 响应，处理各种格式问题"""
    import re
    
    # 1. 清理 Markdown 代码块标记
    cleaned = response.strip()
    if cleaned.startswith("```"):
        # 移除开头的 ```json 或 ```
        cleaned = re.sub(r'^```\w*\s*', '', cleaned)
        # 移除结尾的 ```
        cleaned = re.sub(r'\s*```\s*$', '', cleaned)
    
    # 2. 尝试直接解析
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    
    # 3. 提取 JSON 部分（查找第一个 { 和最后一个 }）
    first_brace = cleaned.find('{')
    last_brace = cleaned.rfind('}')
    
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_str = cleaned[first_brace:last_brace + 1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass
    
    # 4. 如果都失败，返回错误
    return {
        "verdict": "parse_error",
        "raw_response": response,
    }


def analyze_sample_v2(wasm_path: str, expected_label: str) -> dict:
    """使用多粒度特征分析单个样本"""
    
    # 1. 提取特征
    features = extract_features(wasm_path)
    if "error" in features:
        return {
            "file": Path(wasm_path).name,
            "expected_label": expected_label,
            "error": features["error"],
            "verdict": "error",
        }
    
    # 2. 格式化特征
    features_text = format_features_for_prompt(features)
    
    # 3. 构造 Prompt
    prompt = ANALYSIS_PROMPT_V2.format(features=features_text)
    
    # 4. 调用 LLM
    print(f"  调用 LLM 分析...")
    response, usage = call_llm(prompt)
    
    # 5. 解析结果（使用改进的解析函数）
    result = parse_llm_json_response(response)
    
    # 6. 添加元数据
    result.update({
        "file": Path(wasm_path).name,
        "expected_label": expected_label,
        "file_size": features["file_size"],
        "features_summary": {
            "export_count": features["export_count"],
            "suspicious_exports": features["suspicious_exports"],
            "suspicious_strings": features["suspicious_strings"],
            "obfuscated_exports": features.get("obfuscated_exports", []),
            "bitwise_count": features["instruction_counts"]["bitwise"],
            "loop_count": features["complexity"]["loop_count"],
            "code_entropy": features.get("code_entropy", 0),
            "mining_context": features.get("mining_context", {}),
            "suspicion_score": features.get("suspicion_score", 0),
        },
        "usage": usage,
    })
    
    return result


def run_pilot_v2():
    """运行 V2 实验"""
    
    print("=" * 80)
    print("Pilot Experiment V2 - 多粒度特征提取")
    print("=" * 80)
    
    # 1. 加载 V1 的样本列表
    if not V1_RESULTS_FILE.exists():
        print(f"错误：找不到 V1 结果文件 {V1_RESULTS_FILE}")
        print("请先运行 pilot_experiment.py")
        return
    
    with open(V1_RESULTS_FILE, 'r') as f:
        v1_data = json.load(f)
    
    samples = v1_data["results"]
    print(f"\n加载 {len(samples)} 个样本（与 V1 相同）")
    
    # 限制样本数量（用于快速测试）
    MAX_SAMPLES = 20
    samples = samples[:MAX_SAMPLES]
    print(f"限制为前 {len(samples)} 个样本进行测试")
    
    # 数据集路径
    TEST_DIR = PROJECT_ROOT / "data" / "WasmMal-main" / "Data_NewSplit" / "test"
    
    # 2. 逐个分析
    results = []
    for i, sample in enumerate(samples, 1):
        # V1 结果中只存储了文件名，需要拼接完整路径
        filename = sample["file"]
        wasm_path = str(TEST_DIR / filename)
        expected_label = sample["true_label"]
        
        # Normalize labels: V1 uses "malware", V2 prompt asks for "malicious"
        # We'll normalize both to "malicious" for comparison
        if expected_label == "malware":
            expected_label = "malicious"
        
        print(f"\n[{i}/{len(samples)}] {Path(wasm_path).name}")
        print(f"  预期标签: {expected_label}")
        
        result = analyze_sample_v2(wasm_path, expected_label)
        results.append(result)
        
        # 打印结果
        if "error" not in result:
            verdict = result.get("verdict", "unknown")
            correct = "✓" if verdict == expected_label else "✗"
            print(f"  判定: {verdict} {correct}")
            print(f"  类型: {result.get('malware_type', 'N/A')}")
            print(f"  可疑导出: {result['features_summary']['suspicious_exports']}")
            print(f"  可疑字符串: {result['features_summary']['suspicious_strings'][:2]}")
        else:
            print(f"  错误: {result['error']}")
        
        # 避免 API 限流
        time.sleep(3)
    
    # 3. 统计结果
    print("\n" + "=" * 80)
    print("实验结果统计")
    print("=" * 80)
    
    valid_results = [r for r in results if "error" not in r]
    
    # 计算指标
    tp = sum(1 for r in valid_results if r["verdict"] == "malicious" and r["expected_label"] == "malicious")
    tn = sum(1 for r in valid_results if r["verdict"] == "benign" and r["expected_label"] == "benign")
    fp = sum(1 for r in valid_results if r["verdict"] == "malicious" and r["expected_label"] == "benign")
    fn = sum(1 for r in valid_results if r["verdict"] == "benign" and r["expected_label"] == "malicious")
    
    accuracy = (tp + tn) / len(valid_results) if valid_results else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"\n有效样本数: {len(valid_results)}/{len(results)}")
    print(f"\n混淆矩阵:")
    print(f"                预测恶意    预测良性")
    print(f"  实际恶意      {tp:3d}        {fn:3d}")
    print(f"  实际良性      {fp:3d}        {tn:3d}")
    
    print(f"\n指标:")
    print(f"  准确率 (Accuracy):  {accuracy:.2%}")
    print(f"  精确率 (Precision): {precision:.2%}")
    print(f"  召回率 (Recall):    {recall:.2%}")
    print(f"  F1 分数:            {f1:.2%}")
    
    # 4. 与 V1 对比
    print("\n" + "=" * 80)
    print("与 V1 对比")
    print("=" * 80)
    
    v1_metrics = v1_data.get("metrics", {})
    v1_accuracy = v1_metrics.get("accuracy", 0)
    v1_precision = v1_metrics.get("precision", 0)
    v1_recall = v1_metrics.get("recall", 0)
    v1_f1 = v1_metrics.get("f1", 0)
    
    print(f"\n指标          V1          V2          提升")
    print(f"准确率      {v1_accuracy:.2%}      {accuracy:.2%}      {(accuracy - v1_accuracy):+.2%}")
    print(f"精确率      {v1_precision:.2%}      {precision:.2%}      {(precision - v1_precision):+.2%}")
    print(f"召回率      {v1_recall:.2%}      {recall:.2%}      {(recall - v1_recall):+.2%}")
    print(f"F1          {v1_f1:.2%}      {f1:.2%}      {(f1 - v1_f1):+.2%}")
    
    # 5. 分析误判样本
    misclassified = [r for r in valid_results if r["verdict"] != r["expected_label"]]
    if misclassified:
        print(f"\n误判样本分析 ({len(misclassified)} 个):")
        for r in misclassified:
            print(f"\n  文件: {r['file']}")
            print(f"  预期: {r['expected_label']}, 判定: {r['verdict']}")
            print(f"  可疑导出: {r['features_summary']['suspicious_exports']}")
            print(f"  可疑字符串: {r['features_summary']['suspicious_strings'][:2]}")
            print(f"  位运算: {r['features_summary']['bitwise_count']}")
    
    # 6. 保存结果
    output = {
        "version": "v2",
        "model": MODEL_NAME,
        "sample_count": len(samples),
        "valid_count": len(valid_results),
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp,
            "tn": tn,
            "fp": fp,
            "fn": fn,
        },
        "comparison": {
            "v1_accuracy": v1_accuracy,
            "v2_accuracy": accuracy,
            "improvement": accuracy - v1_accuracy,
        },
        "results": results,
    }
    
    output_file = RESULTS_DIR / "pilot_results_v2.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    print(f"\n结果已保存到: {output_file}")


if __name__ == "__main__":
    run_pilot_v2()
