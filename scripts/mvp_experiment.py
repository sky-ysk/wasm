#!/usr/bin/env python3
"""
Wasm + LLM 安全分析 MVP 实验脚本

用法:
  1. 先准备 .wasm 样本文件放到 data/benign/ 和 data/malware/ 目录
  2. 配置 LLM API（支持 OpenAI 兼容接口）
  3. 运行: python3 scripts/mvp_experiment.py
"""

import subprocess
import os
import json
import sys
from pathlib import Path

# ============================================================
# 配置区 - 从 .env 文件读取（保护隐私，.env 已在 .gitignore 中）
# ============================================================

def load_env(env_path: Path) -> dict:
    """从 .env 文件加载环境变量"""
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

# 加载 .env
PROJECT_ROOT = Path(__file__).parent.parent
_env = load_env(PROJECT_ROOT / ".env")

LLM_CONFIG = {
    "api_base": _env.get("DASHSCOPE_BASE_URL", os.environ.get("DASHSCOPE_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1")),
    "api_key": _env.get("DASHSCOPE_API_KEY", os.environ.get("DASHSCOPE_API_KEY", "")),
    "model": _env.get("DASHSCOPE_MODEL", os.environ.get("DASHSCOPE_MODEL", "qwen-plus")),
}

if not LLM_CONFIG["api_key"] or LLM_CONFIG["api_key"] == "在这里填入你的DashScope API Key":
    print("错误：请先在 .env 文件中配置 DASHSCOPE_API_KEY")
    print(f"  文件路径: {PROJECT_ROOT / '.env'}")
    sys.exit(1)

# 项目路径（PROJECT_ROOT 已在上方定义）
DATA_DIR = PROJECT_ROOT / "data"
BENIGN_DIR = DATA_DIR / "benign"
MALWARE_DIR = DATA_DIR / "malware"
RESULTS_DIR = PROJECT_ROOT / "results"

# ============================================================
# Wasm 分析工具函数
# ============================================================

def wasm_to_wat(wasm_path: str) -> str:
    """将 .wasm 二进制转为 WAT 文本格式"""
    try:
        result = subprocess.run(
            ["wasm2wat", wasm_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return f"[wasm2wat 错误]: {result.stderr}"
        return result.stdout
    except Exception as e:
        return f"[转换异常]: {str(e)}"


def extract_objdump(wasm_path: str) -> str:
    """提取 Wasm 模块的结构化摘要信息"""
    try:
        result = subprocess.run(
            ["wasm-objdump", "-x", wasm_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return f"[wasm-objdump 错误]: {result.stderr}"
        return result.stdout
    except Exception as e:
        return f"[提取异常]: {str(e)}"


def compile_wat_to_wasm(wat_path: str, wasm_path: str) -> bool:
    """将 .wat 文本编译为 .wasm 二进制"""
    try:
        result = subprocess.run(
            ["wat2wasm", wat_path, "-o", wasm_path],
            capture_output=True, text=True, timeout=30
        )
        return result.returncode == 0
    except Exception as e:
        print(f"编译异常: {e}")
        return False


# ============================================================
# LLM 调用
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
  "reasoning": "详细说明你从代码中观察到的特征和判断依据",
  "behavior_description": "用自然语言描述该模块的实际行为"
}}"""


def call_llm(prompt: str) -> tuple:
    """调用 LLM API（使用标准库 urllib，无需额外安装依赖）
    返回: (content: str, usage: dict)
    """
    import urllib.request
    import urllib.error

    payload = json.dumps({
        "model": LLM_CONFIG["model"],
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "max_tokens": 2000
    }).encode("utf-8")

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
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            return content, usage
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return json.dumps({"error": f"HTTP {e.code}: {body}"}), {}
    except Exception as e:
        return json.dumps({"error": str(e)}), {}


# ============================================================
# 分析流程
# ============================================================

def analyze_single_wasm(wasm_path: str, expected_label: str) -> dict:
    """分析单个 Wasm 文件"""
    filename = os.path.basename(wasm_path)
    print(f"\n{'='*60}")
    print(f"分析文件: {filename} (预期标签: {expected_label})")
    print(f"{'='*60}")

    # 1. 提取信息
    summary = extract_objdump(wasm_path)
    wat = wasm_to_wat(wasm_path)

    print(f"  摘要长度: {len(summary)} 字符")
    print(f"  WAT 长度: {len(wat)} 字符")

    # 2. 构造 Prompt
    wat_snippet = wat[:3000] if len(wat) > 3000 else wat
    prompt = ANALYSIS_PROMPT.format(summary=summary[:2000], wat_snippet=wat_snippet)

    # 3. 调用 LLM
    print("  调用 LLM 分析中...")
    response, usage = call_llm(prompt)
    print(f"  LLM 响应长度: {len(response)} 字符")

    # 3.1 打印 Token 使用量
    if usage:
        prompt_tokens = usage.get("prompt_tokens", 0)
        completion_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", 0)
        print(f"  Token 使用: 输入 {prompt_tokens} + 输出 {completion_tokens} = 总计 {total_tokens}")
    else:
        prompt_tokens = completion_tokens = total_tokens = 0

    # 4. 解析结果
    try:
        # 尝试提取 JSON
        response_clean = response.strip()
        if response_clean.startswith("```"):
            response_clean = response_clean.split("\n", 1)[1].rsplit("```", 1)[0]
        result = json.loads(response_clean)
    except json.JSONDecodeError:
        result = {"raw_response": response, "parse_error": True}

    result["file"] = filename
    result["expected_label"] = expected_label
    result["file_size"] = os.path.getsize(wasm_path)
    result["token_usage"] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
    }

    # 5. 打印结果
    if not result.get("parse_error"):
        verdict = result.get("verdict", "unknown")
        correct = (verdict == "malicious" and expected_label == "malware") or \
                  (verdict == "benign" and expected_label == "benign")
        print(f"  判定: {verdict} ({'✓ 正确' if correct else '✗ 错误'})")
        print(f"  类型: {result.get('malware_type', 'N/A')}")
        print(f"  置信度: {result.get('confidence', 'N/A')}")
        print(f"  依据: {result.get('reasoning', 'N/A')[:200]}...")
    else:
        print(f"  [解析失败] 原始响应: {response[:200]}...")

    return result


def run_experiment():
    """运行完整实验"""
    RESULTS_DIR.mkdir(exist_ok=True)

    # 编译 .wat 文件为 .wasm
    print("编译 .wat 文件...")
    for wat_file in BENIGN_DIR.glob("*.wat"):
        wasm_file = BENIGN_DIR / wat_file.with_suffix(".wasm").name
        if not wasm_file.exists():
            if compile_wat_to_wasm(str(wat_file), str(wasm_file)):
                print(f"  ✓ {wat_file.name} → {wasm_file.name}")
            else:
                print(f"  ✗ {wat_file.name} 编译失败")

    for wat_file in MALWARE_DIR.glob("*.wat"):
        wasm_file = MALWARE_DIR / wat_file.with_suffix(".wasm").name
        if not wasm_file.exists():
            if compile_wat_to_wasm(str(wat_file), str(wasm_file)):
                print(f"  ✓ {wat_file.name} → {wasm_file.name}")
            else:
                print(f"  ✗ {wat_file.name} 编译失败")

    # 收集所有 .wasm 文件
    all_results = []

    print(f"\n{'#'*60}")
    print(f"# Wasm + LLM 安全分析 MVP 实验")
    print(f"{'#'*60}")

    # 分析良性样本
    benign_files = list(BENIGN_DIR.glob("*.wasm"))
    print(f"\n找到 {len(benign_files)} 个良性样本")
    for f in benign_files:
        result = analyze_single_wasm(str(f), "benign")
        all_results.append(result)

    # 分析恶意样本
    malware_files = list(MALWARE_DIR.glob("*.wasm"))
    print(f"\n找到 {len(malware_files)} 个恶意样本")
    for f in malware_files:
        result = analyze_single_wasm(str(f), "malware")
        all_results.append(result)

    # 统计结果
    print(f"\n{'='*60}")
    print("实验结果汇总")
    print(f"{'='*60}")

    total = len(all_results)
    correct = 0
    for r in all_results:
        if r.get("parse_error"):
            continue
        verdict = r.get("verdict", "")
        expected = r.get("expected_label", "")
        if (verdict == "malicious" and expected == "malware") or \
           (verdict == "benign" and expected == "benign"):
            correct += 1

    print(f"  总样本数: {total}")
    print(f"  正确判定: {correct}")
    print(f"  准确率: {correct/total*100:.1f}%" if total > 0 else "  准确率: N/A")

    # Token 使用量汇总
    total_prompt = sum(r.get("token_usage", {}).get("prompt_tokens", 0) for r in all_results)
    total_completion = sum(r.get("token_usage", {}).get("completion_tokens", 0) for r in all_results)
    total_all = sum(r.get("token_usage", {}).get("total_tokens", 0) for r in all_results)

    print(f"\n{'='*60}")
    print("Token 使用量与费用估算")
    print(f"{'='*60}")
    print(f"  模型: {LLM_CONFIG['model']}")
    print(f"  总输入 Token: {total_prompt:,}")
    print(f"  总输出 Token: {total_completion:,}")
    print(f"  总 Token:     {total_all:,}")
    print(f"  平均每次调用: {total_all // total if total > 0 else 0:,} tokens")

    # 费用估算（多模型对比）
    # 价格单位：元/百万token
    # qwen3.7-plus: 输入 2元, 输出 8元 (DashScope)
    # deepseek-v4-pro: 输入 3元, 输出 6元 (DeepSeek API)
    # deepseek-v4-flash: 输入 1元, 输出 2元 (DeepSeek API)
    PRICE_TABLE = {
        "qwen3.7-plus (百炼)":   {"input": 2.0, "output": 8.0},
        "deepseek-v4-pro (DeepSeek)": {"input": 3.0, "output": 6.0},
        "deepseek-v4-flash (DeepSeek)": {"input": 1.0, "output": 2.0},
    }

    print(f"\n  多模型费用对比:")
    print(f"  {'模型':<30} {'输入价':>8} {'输出价':>8} {'单次费':>10} {'15K 全量':>12}")
    print(f"  {'-'*70}")
    for model_name, prices in PRICE_TABLE.items():
        cost_in = total_prompt / 1_000_000 * prices["input"]
        cost_out = total_completion / 1_000_000 * prices["output"]
        cost_sample = (cost_in + cost_out) / total if total > 0 else 0
        cost_15k = cost_sample * 15000
        print(f"  {model_name:<30} {prices['input']:>6.1f}元 {prices['output']:>6.1f}元 {cost_sample:>8.4f}元 {cost_15k:>10.2f}元")

    # 当前模型的费用详情
    current_model = LLM_CONFIG["model"]
    matched_prices = None
    for name, prices in PRICE_TABLE.items():
        if current_model in name or name.startswith(current_model):
            matched_prices = prices
            break
    if not matched_prices:
        matched_prices = PRICE_TABLE["qwen3.7-plus (百炼)"]
        print(f"\n  当前模型 {current_model} 未匹配到价格表，使用 qwen3.7-plus 价格估算")

    cost_input = total_prompt / 1_000_000 * matched_prices["input"]
    cost_output = total_completion / 1_000_000 * matched_prices["output"]
    cost_total = cost_input + cost_output

    print(f"\n  当前模型（{current_model}）费用明细:")
    print(f"    输入费用: {total_prompt:,} tokens × {matched_prices['input']} 元/百万 = ¥{cost_input:.4f}")
    print(f"    输出费用: {total_completion:,} tokens × {matched_prices['output']} 元/百万 = ¥{cost_output:.4f}")
    print(f"    本次实验总费用: ≈ ¥{cost_total:.4f}")

    if total > 0:
        avg_cost_per_sample = cost_total / total
        estimated_15k = avg_cost_per_sample * 15000
        print(f"\n  按 WasmMal-15K（15,000 样本）估算:")
        print(f"    平均每个样本费用: ≈ ¥{avg_cost_per_sample:.4f}")
        print(f"    15K 全量实验费用: ≈ ¥{estimated_15k:.2f}")

    # 保存结果
    output_path = RESULTS_DIR / "mvp_results.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)
    print(f"\n详细结果已保存到: {output_path}")


if __name__ == "__main__":
    run_experiment()
