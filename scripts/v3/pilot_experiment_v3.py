#!/usr/bin/env python3
"""
V3 Pilot Experiment - 混合二阶段分析

阶段 0: 特征提取（确定性）
阶段 1: LLM 多维度综合分析（函数筛选 + 数据/行为/高级特征分析 + 初步判定）
阶段 1.5: 代码提取（确定性）
阶段 2: LLM 代码验证（用代码证据验证/修正初步判定）
"""

import json
import sys
import time
import random
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(Path(__file__).parent))

from pilot_experiment import call_llm, load_env, wasm_to_wat
from wasm_feature_extractor_v3 import (
    extract_features_v2,
    extract_suspicious_function_code,
    format_features_for_stage1,
    format_features_for_stage2,
)

# ============================================================
# 配置
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_env = load_env(PROJECT_ROOT / ".env")
MODEL_NAME = _env.get("DASHSCOPE_MODEL", "qwen-plus")

WASMMAL_DIR = PROJECT_ROOT / "data" / "WasmMal-main"
RESULTS_DIR = PROJECT_ROOT / "results"

REQUEST_INTERVAL = 3

# ============================================================
# Prompt 模板
# ============================================================

STAGE1_PROMPT = """你是一个 WebAssembly 安全分析专家。请对以下 WebAssembly 模块进行多维度综合分析。

{features}

**重要领域知识**：
1. **CryptoNight/hash_cn 在 Web Wasm 中没有合法用途**。CryptoNight 是专门为 Monero 加密货币挖矿设计的 PoW 算法，出现在浏览器 Wasm 模块中只有一个目的：挖矿。即使代码结构清晰、逻辑规范，也不能因此认为是合法的。
2. **CryptoJacking 的架构是 JS + Wasm 分离的**：JavaScript 层负责连接矿池、获取任务、提交结果；Wasm 模块只负责 CPU 密集的哈希计算。因此 Wasm 模块"看起来像独立的哈希库"是正常的恶意架构，不能因为"缺少网络通信、任务管理"就认为是合法的。
3. **常见的挖矿哈希算法关键词**：cryptonight、hash_cn、randomx、monero、_calculate（通用名称掩盖挖矿）、_hash（配合高位运算）
4. **合法的哈希使用场景**：SHA-256 用于数据校验/签名验证、SM3 用于国密合规、区块链合约中的区块哈希验证（如 EOSIO）。这些通常有明确的业务上下文（如 eosio、require_auth 等导出）。

请完成以下多维度分析：

1. **函数筛选**：
   - 验证预设标记的函数是否真的可疑（排除误报，如区块链合约的合法哈希函数）
   - 从剩余函数中发现可能遗漏的可疑函数
   - 特别注意 `_hash_cn`、`_calculate` 等可能是挖矿算法的函数

2. **数据层分析**：
   - 数据段字符串是否与可疑函数关联？
   - 是否暴露恶意意图（如 cryptonight.c、crypto/int-util.h 等挖矿库路径）？

3. **行为层分析**：
   - 指令统计模式是否支持恶意判断？
   - 高位运算（>1000）+ 哈希导出 = 高度指向挖矿算法

4. **综合判定**：
   - 基于所有维度的证据，给出初步恶意/良性判定
   - 如果模块包含 CryptoNight/hash_cn 且没有合法的区块链上下文，应判定为恶意

输出 JSON 格式（只输出 JSON，不要其他内容）：
{{
  "confirmed_suspicious": ["确认可疑的函数名"],
  "new_suspicious": ["新发现的可疑函数名"],
  "false_positives": ["排除的误报函数名"],
  "data_analysis": "数据层分析结论",
  "behavior_analysis": "行为层分析结论",
  "preliminary_verdict": "malicious" 或 "benign",
  "preliminary_type": "cryptojacking" / "obfuscation" / "data_exfiltration" / "ad_fraud" / "other" / "none",
  "preliminary_confidence": "high" / "medium" / "low",
  "reasoning": "综合分析依据"
}}"""

STAGE2_PROMPT = """你是一个 WebAssembly 安全分析专家。

在上一轮分析中，我们基于模块的多维度特征给出了初步判定。现在请根据可疑函数的实际代码，验证或修正这个判定。

{stage2_features}

**重要领域知识（必须遵守）**：
1. **CryptoNight/hash_cn 在 Web Wasm 中没有合法用途**。CryptoNight 是专门为 Monero 加密货币挖矿设计的 PoW 算法。如果代码实现了 CryptoNight 算法（特征：大量位运算、S-box 查找表、特定常量），即使代码结构清晰规范，也必须判定为恶意。不要因为"代码质量高"或"缺少网络通信"就认为是合法的加密库。
2. **CryptoJacking 的架构是 JS + Wasm 分离的**：
   - JavaScript 层：连接矿池（WebSocket/HTTP）、获取挖矿任务、生成 Nonce、提交结果
   - Wasm 模块：**只负责 CPU 密集的哈希计算**（这就是我们检测的目标）
   - 因此 Wasm 模块"看起来像独立的哈希计算库"是正常的恶意架构，**不能因为"缺少挖矿上下文编排（无限循环、矿池通信、反检测机制）"就认为是合法的**
3. **区分合法哈希和挖矿哈希**：
   - 合法：SHA-256 用于数据校验/签名、SM3 用于国密合规、区块链合约中的区块哈希验证（有 eosio、require_auth 等上下文）
   - 恶意：CryptoNight、RandomX、hash_cn 在 Web Wasm 中出现 = 挖矿，无论代码是否规范

**代码分析指导**：
- 验证上一轮判定是否被代码证据支持
- 如果代码实现了 CryptoNight 算法特征（大量 XOR/ROTL、S-box 查找表、循环展开的哈希迭代），必须判定为恶意
- 关注代码中的特征模式：
  - 挖矿：大量位运算、循环/循环展开、特定常量（0x6a09e667）、PoW 计算逻辑、S-box 查找表
  - 合法哈希：标准 API 调用、明确的业务逻辑、区块链框架上下文

请按以下 JSON 格式输出最终分析结果（只输出 JSON，不要其他内容）：
{{
  "verdict": "malicious" 或 "benign",
  "verdict_change": true 或 false,
  "malware_type": "cryptojacking" / "obfuscation" / "data_exfiltration" / "ad_fraud" / "other" / "none",
  "confidence": "high" / "medium" / "low",
  "code_evidence": "代码层面的关键证据",
  "reasoning": "最终判断依据，结合特征分析和代码证据",
  "behavior_description": "用自然语言描述该模块的实际行为"
}}"""


# ============================================================
# JSON 解析
# ============================================================

def parse_llm_json_response(response: str) -> dict:
    """解析 LLM 返回的 JSON 响应"""
    cleaned = response.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[-1]
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass

    first_brace = cleaned.find('{')
    last_brace = cleaned.rfind('}')
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        json_str = cleaned[first_brace:last_brace + 1]
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            pass

    return {"parse_error": True, "raw_response": response}


# ============================================================
# V3 分析流程
# ============================================================

def analyze_sample_v3(wasm_path: str, expected_label: str) -> dict:
    """V3 两阶段分析单个样本"""
    filename = Path(wasm_path).name

    # ---- 阶段 0: 特征提取 ----
    features = extract_features_v2(wasm_path)
    if "error" in features:
        return {
            "file": filename,
            "expected_label": expected_label,
            "error": features["error"],
            "stage": "stage0",
        }

    # ---- 阶段 1: LLM 多维度综合分析 ----
    stage1_text = format_features_for_stage1(features)
    stage1_prompt = STAGE1_PROMPT.format(features=stage1_text)

    print(f"  [阶段1] 多维度综合分析...", end="", flush=True)
    stage1_response, stage1_usage = call_llm(stage1_prompt)
    stage1_result = parse_llm_json_response(stage1_response)

    if stage1_result.get("parse_error"):
        print(f" 解析失败")
        return {
            "file": filename,
            "expected_label": expected_label,
            "error": "Stage 1 parse error",
            "stage": "stage1",
            "stage1_raw": stage1_response,
        }

    preliminary_verdict = stage1_result.get("preliminary_verdict", "unknown")
    print(f" 初步判定: {preliminary_verdict}")

    # 确定最终可疑函数列表
    confirmed = stage1_result.get("confirmed_suspicious", [])
    new_susp = stage1_result.get("new_suspicious", [])
    final_suspicious = confirmed + new_susp
    if not final_suspicious:
        final_suspicious = features.get("suspicious_exports", [])

    # ---- 阶段 1.5: 代码提取 ----
    wat_text = wasm_to_wat(wasm_path)
    func_code = {}
    if wat_text and not wat_text.startswith("["):
        func_code = extract_suspicious_function_code(
            wat_text, final_suspicious, max_funcs=3, max_lines=200
        )

    # ---- 阶段 2: LLM 代码验证 ----
    stage2_text = format_features_for_stage2(features, stage1_result, func_code)
    stage2_prompt = STAGE2_PROMPT.format(stage2_features=stage2_text)

    print(f"  [阶段2] 代码验证...", end="", flush=True)
    stage2_response, stage2_usage = call_llm(stage2_prompt)
    stage2_result = parse_llm_json_response(stage2_response)

    if stage2_result.get("parse_error"):
        print(f" 解析失败，使用阶段1结果")
        stage2_result = {
            "verdict": preliminary_verdict,
            "verdict_change": False,
            "malware_type": stage1_result.get("preliminary_type", "none"),
            "confidence": stage1_result.get("preliminary_confidence", "low"),
            "code_evidence": "代码提取或解析失败",
            "reasoning": stage1_result.get("reasoning", ""),
            "behavior_description": "N/A",
        }
    else:
        print(f" 最终判定: {stage2_result.get('verdict', 'unknown')} (变更: {stage2_result.get('verdict_change', False)})")

    # ---- 汇总结果 ----
    total_usage = {}
    for key in set(list(stage1_usage.keys()) + list(stage2_usage.keys())):
        if isinstance(stage1_usage.get(key, 0), (int, float)) and isinstance(stage2_usage.get(key, 0), (int, float)):
            total_usage[key] = stage1_usage.get(key, 0) + stage2_usage.get(key, 0)

    return {
        "file": filename,
        "expected_label": expected_label,
        "file_size": features["file_size"],
        "verdict": stage2_result.get("verdict", "unknown"),
        "malware_type": stage2_result.get("malware_type", "none"),
        "confidence": stage2_result.get("confidence", "low"),
        "reasoning": stage2_result.get("reasoning", ""),
        "behavior_description": stage2_result.get("behavior_description", ""),
        "code_evidence": stage2_result.get("code_evidence", ""),
        "verdict_change": stage2_result.get("verdict_change", False),
        "stage1": {
            "preliminary_verdict": preliminary_verdict,
            "preliminary_type": stage1_result.get("preliminary_type", "none"),
            "confirmed_suspicious": confirmed,
            "new_suspicious": new_susp,
            "false_positives": stage1_result.get("false_positives", []),
            "data_analysis": stage1_result.get("data_analysis", ""),
            "behavior_analysis": stage1_result.get("behavior_analysis", ""),
            "reasoning": stage1_result.get("reasoning", ""),
        },
        "features_summary": {
            "export_count": features["export_count"],
            "suspicious_exports": features["suspicious_exports"],
            "obfuscated_exports": features.get("obfuscated_exports", []),
            "bitwise_count": features["instruction_counts"]["bitwise"],
            "loop_count": features["complexity"]["loop_count"],
            "code_entropy": features.get("code_entropy", 0),
            "framework": features.get("framework", "unknown"),
            "suspicion_score": features.get("suspicion_score", 0),
            "mining_context": features.get("mining_context", {}),
        },
        "func_code_extracted": list(func_code.keys()),
        "usage": total_usage,
        "stage1_usage": stage1_usage,
        "stage2_usage": stage2_usage,
    }


# ============================================================
# 实验运行
# ============================================================

def run_v3_experiment(samples: list, test_dir: Path) -> dict:
    """运行 V3 实验"""
    print("=" * 80)
    print("V3 混合二阶段分析实验")
    print(f"模型: {MODEL_NAME}")
    print(f"样本数: {len(samples)}")
    print("=" * 80)

    results = []
    for i, sample in enumerate(samples, 1):
        filename = sample["file"]
        expected_label = sample["expected_label"]
        wasm_path = str(test_dir / filename)

        if not Path(wasm_path).exists():
            print(f"\n[{i}/{len(samples)}] {filename[:50]}... 文件不存在，跳过")
            continue

        print(f"\n[{i}/{len(samples)}] {filename[:50]}...")
        print(f"  预期: {expected_label}")

        result = analyze_sample_v3(wasm_path, expected_label)
        results.append(result)

        # 打印简要结果
        if "error" not in result:
            verdict = result.get("verdict", "unknown")
            correct = "✓" if verdict == expected_label else "✗"
            print(f"  最终: {verdict} {correct}")
        else:
            print(f"  错误: {result['error']}")

        if i < len(samples):
            time.sleep(REQUEST_INTERVAL)

    # 统计
    valid_results = [r for r in results if "error" not in r]
    total = len(valid_results)

    tp = sum(1 for r in valid_results if r["verdict"] == "malicious" and r["expected_label"] == "malicious")
    tn = sum(1 for r in valid_results if r["verdict"] == "benign" and r["expected_label"] == "benign")
    fp = sum(1 for r in valid_results if r["verdict"] == "malicious" and r["expected_label"] == "benign")
    fn = sum(1 for r in valid_results if r["verdict"] == "benign" and r["expected_label"] == "malicious")

    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # 阶段 2 修正统计
    verdict_changes = sum(1 for r in valid_results if r.get("verdict_change"))

    # Token 统计
    total_prompt = sum(r.get("usage", {}).get("prompt_tokens", 0) for r in results)
    total_completion = sum(r.get("usage", {}).get("completion_tokens", 0) for r in results)
    total_all = sum(r.get("usage", {}).get("total_tokens", 0) for r in results)

    print(f"\n{'=' * 80}")
    print("实验结果统计")
    print(f"{'=' * 80}")
    print(f"\n有效样本数: {total}/{len(results)}")
    print(f"\n混淆矩阵:")
    print(f"                预测恶意    预测良性")
    print(f"  实际恶意      {tp:3d}        {fn:3d}")
    print(f"  实际良性      {fp:3d}        {tn:3d}")
    print(f"\n指标:")
    print(f"  准确率 (Accuracy):  {accuracy:.2%}")
    print(f"  精确率 (Precision): {precision:.2%}")
    print(f"  召回率 (Recall):    {recall:.2%}")
    print(f"  F1 分数:            {f1:.2%}")
    print(f"\n阶段 2 修正次数: {verdict_changes}")

    print(f"\n{'=' * 80}")
    print("Token 使用量")
    print(f"{'=' * 80}")
    print(f"  总输入 Token: {total_prompt:,}")
    print(f"  总输出 Token: {total_completion:,}")
    print(f"  总 Token:     {total_all:,}")
    print(f"  平均每次调用: {total_all // total if total > 0 else 0:,} tokens")

    # 误判分析
    misclassified = [r for r in valid_results if r["verdict"] != r["expected_label"]]
    if misclassified:
        print(f"\n{'=' * 80}")
        print(f"误判样本分析 ({len(misclassified)} 个)")
        print(f"{'=' * 80}")
        for r in misclassified:
            print(f"\n  文件: {r['file'][:50]}...")
            print(f"  预期: {r['expected_label']}, 判定: {r['verdict']}")
            print(f"  可疑度: {r['features_summary']['suspicion_score']}/100")
            print(f"  框架: {r['features_summary']['framework']}")
            print(f"  阶段1初步: {r['stage1']['preliminary_verdict']}")
            print(f"  推理: {r.get('reasoning', '')[:150]}...")

    output = {
        "version": "v3",
        "model": MODEL_NAME,
        "sample_count": len(samples),
        "valid_count": total,
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "verdict_changes": verdict_changes,
        },
        "token_usage": {
            "total_prompt": total_prompt,
            "total_completion": total_completion,
            "total": total_all,
        },
        "results": results,
    }

    return output
