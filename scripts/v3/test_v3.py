#!/usr/bin/env python3
"""
V3 可行性测试 - 随机抽取 15 良性 + 15 恶意样本
"""

import json
import sys
import random
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from pilot_experiment_v3 import run_v3_experiment

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
WASMMAL_DIR = PROJECT_ROOT / "data" / "WasmMal-main"
RESULTS_DIR = PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(exist_ok=True)

RANDOM_SEED = 42
SAMPLE_PER_CLASS = 15

# 数据集路径
BENIGN_DIR = WASMMAL_DIR / "benign"
MALWARE_DIR = WASMMAL_DIR / "malware"

def main():
    random.seed(RANDOM_SEED)

    # 获取所有样本
    all_benign = list(BENIGN_DIR.glob("*.wasm"))
    all_malware = list(MALWARE_DIR.glob("*.wasm"))

    print(f"良性样本总数: {len(all_benign)}")
    print(f"恶意样本总数: {len(all_malware)}")

    # 分层抽样
    sampled_benign = random.sample(all_benign, min(SAMPLE_PER_CLASS, len(all_benign)))
    sampled_malware = random.sample(all_malware, min(SAMPLE_PER_CLASS, len(all_malware)))

    # 构建样本列表
    samples = []
    for f in sampled_benign:
        samples.append({"file": f.name, "expected_label": "benign"})
    for f in sampled_malware:
        samples.append({"file": f.name, "expected_label": "malicious"})

    # 打乱顺序
    random.shuffle(samples)

    print(f"\n抽样结果: {sum(1 for s in samples if s['expected_label']=='benign')} 良性 + {sum(1 for s in samples if s['expected_label']=='malicious')} 恶意 = {len(samples)} 样本")

    # 确定 test_dir（benign 和 malware 在不同目录，需要统一处理）
    # 由于 V3 的 run_v3_experiment 使用统一的 test_dir，
    # 我们需要创建一个临时目录或者修改路径逻辑
    # 这里直接使用 WASMMAL_DIR 作为基础目录，在 run_v3_experiment 中处理

    # 修改 samples 中的 file 为相对路径
    for s in samples:
        if s["expected_label"] == "benign":
            s["file"] = f"benign/{s['file']}"
        else:
            s["file"] = f"malware/{s['file']}"

    # 运行实验
    output = run_v3_experiment(samples, WASMMAL_DIR)

    # 保存结果
    output_file = RESULTS_DIR / "v3_test_results.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"\n结果已保存到: {output_file}")


if __name__ == "__main__":
    main()
