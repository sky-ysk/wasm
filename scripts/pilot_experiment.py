#!/usr/bin/env python3
"""
WasmMal-15K Pilot Experiment
从测试集分层抽样 30 个样本（15 良性 + 15 恶意），验证 LLM 检测准确率
"""

import subprocess
import os
import json
import sys
import time
import random
from pathlib import Path
from collections import Counter

# ============================================================
# 配置
# ============================================================

def load_env(env_path: Path) -> dict:
    env_vars = {}
    if env_path.exists():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, value = line.split("=", 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars

PROJECT_ROOT = Path(__file__).parent.parent
_env = load_env(PROJECT_ROOT / ".env")

LLM_CONFIG = {
    "api_base": _env.get("DASHSCOPE_BASE_URL", os.environ.get("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")),
    "api_key": _env.get("DASHSCOPE_API_KEY", os.environ.get("DASHSCOPE_API_KEY", "")),
    "model": _env.get("DASHSCOPE_MODEL", os.environ.get("DASHSCOPE_MODEL", "qwen-plus")),
}

if not LLM_CONFIG["api_key"] or "在这里" in LLM_CONFIG["api_key"]:
    print("错误：请先在 .env 文件中配置 DASHSCOPE_API_KEY")
    sys.exit(1)

# 数据集路径
WASMMAL_DIR = PROJECT_ROOT / "data" / "WasmMal-main"
TEST_CSV = WASMMAL_DIR / "Data_NewSplit" / "test.csv"
TEST_DIR = WASMMAL_DIR / "Data_NewSplit" / "test"
RESULTS_DIR = PROJECT_ROOT / "results"

# 实验参数
SAMPLE_SIZE = 30
SAMPLE_PER_CLASS = 15
REQUEST_INTERVAL = 3  # 秒
MAX_RETRIES = 3
RANDOM_SEED = 42

# ============================================================
# Wasm 分析工具
# ============================================================

def wasm_to_wat(wasm_path: str) -> str:
    try:
        result = subprocess.run(["wasm2wat", wasm_path], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return f"[wasm2wat error]: {result.stderr[:200]}"
        return result.stdout
    except Exception as e:
        return f"[error]: {str(e)}"

def extract_objdump(wasm_path: str) -> str:
    try:
        result = subprocess.run(["wasm-objdump", "-x", wasm_path], capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return f"[objdump error]: {result.stderr[:200]}"
        return result.stdout
    except Exception as e:
        return f"[error]: {str(e)}"

# ============================================================
# LLM 调用（含 429 重试）
# ============================================================

ANALYSIS_PROMPT = """你是一个 WebAssembly 安全分析专家。请分析以下 WebAssembly 模块，判断其是否为恶意代码。

## 模块摘要信息（wasm-objdump 输出）
```
{summary}
```

## 关键函数代码（WAT 格式，截取前 3000 字符）
```wat
{wat_snippet}
```

请按以下 JSON 格式输出分析结果（只输出 JSON，不要其他内容）：
{{
  "verdict": "malicious" 或 "benign",
  "malware_type": "cryptojacking" / "obfuscation" / "data_exfiltration" / "ad_fraud" / "other" / "none",
  "confidence": "high" / "medium" / "low",
  "reasoning": "详细说明判断依据",
  "behavior_description": "用自然语言描述该模块的实际行为"
}}"""


def call_llm(prompt: str) -> tuple:
    """调用 LLM API，含 429 重试机制"""
    import urllib.request
    import urllib.error

    payload = json.dumps({
        "model": LLM_CONFIG["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 2000
    }).encode("utf-8")

    for attempt in range(MAX_RETRIES):
        req = urllib.request.Request(
            f"{LLM_CONFIG['api_base']}/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {LLM_CONFIG['api_key']}"
            },
            method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                return content, usage
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait_time = REQUEST_INTERVAL * (2 ** attempt)
                print(f"    ⚠ 429 限流，等待 {wait_time}s 后重试 ({attempt+1}/{MAX_RETRIES})...")
                time.sleep(wait_time)
                continue
            body = e.read().decode("utf-8", errors="replace")
            return json.dumps({"error": f"HTTP {e.code}: {body[:200]}"}), {}
        except Exception as e:
            return json.dumps({"error": str(e)}), {}

    return json.dumps({"error": "Max retries exceeded (429)"}), {}


# ============================================================
# 加载数据集并抽样
# ============================================================

def load_test_labels():
    """加载测试集标签"""
    samples = []
    with open(TEST_CSV, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            if len(parts) == 2:
                filename, label = parts[0], int(parts[1])
                samples.append({"file": filename, "label": label})
    return samples


def stratified_sample(samples, n_per_class, seed=42):
    """分层抽样"""
    random.seed(seed)
    benign = [s for s in samples if s["label"] == 0]
    malware = [s for s in samples if s["label"] == 1]

    sampled_benign = random.sample(benign, min(n_per_class, len(benign)))
    sampled_malware = random.sample(malware, min(n_per_class, len(malware)))

    result = sampled_benign + sampled_malware
    random.shuffle(result)
    return result


# ============================================================
# 分析单个样本
# ============================================================

def analyze_sample(sample, index, total):
    """分析单个 Wasm 样本"""
    filename = sample["file"]
    true_label = "benign" if sample["label"] == 0 else "malware"
    wasm_path = TEST_DIR / filename

    print(f"\n[{index+1}/{total}] {filename[:40]}... (真实: {true_label})")

    if not wasm_path.exists():
        print(f"  ✗ 文件不存在: {wasm_path}")
        return None

    file_size = wasm_path.stat().st_size
    print(f"  文件大小: {file_size:,} bytes")

    # 提取信息
    summary = extract_objdump(str(wasm_path))
    wat = wasm_to_wat(str(wasm_path))

    # 构造 Prompt
    wat_snippet = wat[:3000] if len(wat) > 3000 else wat
    prompt = ANALYSIS_PROMPT.format(summary=summary[:2000], wat_snippet=wat_snippet)

    # 调用 LLM
    print(f"  调用 LLM...", end="", flush=True)
    response, usage = call_llm(prompt)

    prompt_tokens = usage.get("prompt_tokens", 0)
    completion_tokens = usage.get("completion_tokens", 0)
    total_tokens = usage.get("total_tokens", 0)
    print(f" tokens: {prompt_tokens}+{completion_tokens}={total_tokens}")

    # 解析结果
    try:
        response_clean = response.strip()
        if response_clean.startswith("```"):
            response_clean = response_clean.split("\n", 1)[1].rsplit("```", 1)[0]
        result = json.loads(response_clean)
    except json.JSONDecodeError:
        result = {"raw_response": response, "parse_error": True}

    predicted = result.get("verdict", "unknown")
    correct = (predicted == "malicious" and true_label == "malware") or \
              (predicted == "benign" and true_label == "benign")

    print(f"  预测: {predicted} ({'✓' if correct else '✗'})")
    print(f"  类型: {result.get('malware_type', 'N/A')}")
    if not correct:
        print(f"  依据: {result.get('reasoning', 'N/A')[:150]}...")

    return {
        "file": filename,
        "file_size": file_size,
        "true_label": true_label,
        "predicted": predicted,
        "correct": correct,
        "malware_type": result.get("malware_type", "N/A"),
        "confidence": result.get("confidence", "N/A"),
        "reasoning": result.get("reasoning", ""),
        "behavior_description": result.get("behavior_description", ""),
        "parse_error": result.get("parse_error", False),
        "token_usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
        }
    }


# ============================================================
# 主实验
# ============================================================

def run_pilot():
    RESULTS_DIR.mkdir(exist_ok=True)

    print("=" * 60)
    print("WasmMal-15K Pilot Experiment")
    print(f"模型: {LLM_CONFIG['model']}")
    print(f"抽样: {SAMPLE_PER_CLASS} 良性 + {SAMPLE_PER_CLASS} 恶意 = {SAMPLE_SIZE} 样本")
    print(f"请求间隔: {REQUEST_INTERVAL}s")
    print("=" * 60)

    # 加载标签
    print("\n加载测试集标签...")
    all_samples = load_test_labels()
    benign_count = sum(1 for s in all_samples if s["label"] == 0)
    malware_count = sum(1 for s in all_samples if s["label"] == 1)
    print(f"  测试集总量: {len(all_samples)} (良性 {benign_count} + 恶意 {malware_count})")

    # 分层抽样
    print(f"\n分层抽样 (seed={RANDOM_SEED})...")
    sampled = stratified_sample(all_samples, SAMPLE_PER_CLASS, RANDOM_SEED)
    print(f"  抽样结果: {sum(1 for s in sampled if s['label']==0)} 良性 + {sum(1 for s in sampled if s['label']==1)} 恶意")

    # 逐个分析（增量保存）
    results_path = RESULTS_DIR / "pilot_results.json"
    results = []

    # 恢复已有结果（如果中断后重跑）
    if results_path.exists():
        try:
            with open(results_path, "r", encoding="utf-8") as f:
                old_data = json.load(f)
                results = old_data.get("results", [])
                done_files = {r["file"] for r in results}
                print(f"  恢复已有结果: {len(results)} 个样本")
        except:
            done_files = set()
    else:
        done_files = set()

    for i, sample in enumerate(sampled):
        if sample["file"] in done_files:
            print(f"\n[{i+1}/{len(sampled)}] {sample['file'][:40]}... (已跳过，已有结果)")
            continue

        result = analyze_sample(sample, i, len(sampled))
        if result:
            results.append(result)

            # 增量保存
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump({"results": results, "status": "running"}, f, ensure_ascii=False, indent=2)

        # 请求间隔
        if i < len(sampled) - 1:
            time.sleep(REQUEST_INTERVAL)

    # ============================================================
    # 结果统计
    # ============================================================
    print(f"\n{'='*60}")
    print("Pilot 实验结果")
    print(f"{'='*60}")

    valid_results = [r for r in results if not r.get("parse_error")]
    total = len(valid_results)

    # 混淆矩阵
    tp = sum(1 for r in valid_results if r["true_label"] == "malware" and r["predicted"] == "malicious")
    tn = sum(1 for r in valid_results if r["true_label"] == "benign" and r["predicted"] == "benign")
    fp = sum(1 for r in valid_results if r["true_label"] == "benign" and r["predicted"] == "malicious")
    fn = sum(1 for r in valid_results if r["true_label"] == "malware" and r["predicted"] == "benign")

    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\n  有效样本数: {total}")
    print(f"\n  混淆矩阵:")
    print(f"                    预测恶意    预测良性")
    print(f"    真实恶意    TP={tp:<5}     FN={fn:<5}")
    print(f"    真实良性    FP={fp:<5}     TN={tn:<5}")
    print(f"\n  指标:")
    print(f"    准确率 (Accuracy):  {accuracy:.2%}")
    print(f"    精确率 (Precision): {precision:.2%}")
    print(f"    召回率 (Recall):    {recall:.2%}")
    print(f"    F1 Score:           {f1:.2%}")

    # Token 统计
    total_prompt = sum(r["token_usage"]["prompt_tokens"] for r in results)
    total_completion = sum(r["token_usage"]["completion_tokens"] for r in results)
    total_all = sum(r["token_usage"]["total_tokens"] for r in results)

    print(f"\n{'='*60}")
    print("Token 使用量与费用")
    print(f"{'='*60}")
    print(f"  模型: {LLM_CONFIG['model']}")
    print(f"  总输入 Token: {total_prompt:,}")
    print(f"  总输出 Token: {total_completion:,}")
    print(f"  总 Token:     {total_all:,}")
    print(f"  平均每次调用: {total_all // total if total > 0 else 0:,} tokens")

    # 费用对比
    PRICE_TABLE = {
        "qwen3.7-plus (百炼)":       {"input": 2.0, "output": 8.0},
        "deepseek-v4-pro (DeepSeek)": {"input": 3.0, "output": 6.0},
        "deepseek-v4-flash (DeepSeek)": {"input": 1.0, "output": 2.0},
    }

    print(f"\n  多模型费用对比（按本次实验 Token 消耗推算 15K 全量）:")
    print(f"  {'模型':<30} {'单次费':>10} {'15K 全量':>12}")
    print(f"  {'-'*55}")
    for model_name, prices in PRICE_TABLE.items():
        cost_in = total_prompt / 1_000_000 * prices["input"]
        cost_out = total_completion / 1_000_000 * prices["output"]
        cost_sample = (cost_in + cost_out) / total if total > 0 else 0
        cost_15k = cost_sample * 15000
        print(f"  {model_name:<30} ¥{cost_sample:>8.4f}  ¥{cost_15k:>10.2f}")

    # 错误分析
    errors = [r for r in valid_results if not r["correct"]]
    if errors:
        print(f"\n{'='*60}")
        print(f"错误分析 ({len(errors)} 个误判)")
        print(f"{'='*60}")
        for r in errors:
            print(f"  {r['file'][:40]}...")
            print(f"    真实: {r['true_label']} → 预测: {r['predicted']}")
            print(f"    依据: {r['reasoning'][:120]}...")
            print()

    # 保存结果
    output_path = RESULTS_DIR / "pilot_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump({
            "config": {
                "model": LLM_CONFIG["model"],
                "sample_size": SAMPLE_SIZE,
                "sample_per_class": SAMPLE_PER_CLASS,
                "random_seed": RANDOM_SEED,
                "request_interval": REQUEST_INTERVAL,
            },
            "metrics": {
                "total": total,
                "tp": tp, "tn": tn, "fp": fp, "fn": fn,
                "accuracy": accuracy,
                "precision": precision,
                "recall": recall,
                "f1": f1,
            },
            "token_usage": {
                "total_prompt": total_prompt,
                "total_completion": total_completion,
                "total": total_all,
            },
            "results": results,
        }, f, ensure_ascii=False, indent=2)
    print(f"\n详细结果已保存到: {output_path}")


if __name__ == "__main__":
    run_pilot()
