#!/usr/bin/env python3
"""
V3 Wasm 特征提取模块

在 V2 基础上新增：
- extract_suspicious_function_code(): 从 WAT 中提取可疑函数的代码片段
- format_features_for_stage1(): 阶段 1 多维度综合分析的 Prompt 格式化
- format_features_for_stage2(): 阶段 2 代码验证的 Prompt 格式化
"""

import re
import json
from pathlib import Path

# 复用 V2 的所有特征提取函数
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from wasm_feature_extractor import (
    run_command,
    extract_imports,
    extract_exports,
    extract_data_strings,
    count_instructions,
    count_functions,
    count_loops,
    calculate_complexity_metrics,
    detect_obfuscated_name,
    calculate_entropy,
    detect_framework,
    analyze_mining_context,
    calculate_suspicion_score,
    extract_features as extract_features_v2,
)


def extract_suspicious_function_code(
    wat_text: str,
    suspicious_exports: list,
    max_funcs: int = 3,
    max_lines: int = 200,
) -> dict:
    """从 WAT 中提取可疑函数的代码片段

    Args:
        wat_text: WAT 文本
        suspicious_exports: 可疑导出函数名列表
        max_funcs: 最多提取几个函数的代码
        max_lines: 每个函数体最多保留多少行

    Returns:
        dict: {函数名: 函数体代码}
    """
    # 1. 解析 export → func index 映射
    # 格式: (export "name" (func N))
    export_map = {}
    for line in wat_text.split('\n'):
        match = re.search(r'\(export\s+"([^"]+)"\s+\(func\s+(\d+)\)\)', line)
        if match:
            name, idx = match.groups()
            export_map[name] = int(idx)

    # 2. 找到可疑函数的索引
    target_indices = []
    for name in suspicious_exports[:max_funcs]:
        if name in export_map:
            target_indices.append((name, export_map[name]))

    if not target_indices:
        return {}

    # 3. 解析所有函数的起始行号
    lines = wat_text.split('\n')
    func_starts = []
    for i, line in enumerate(lines):
        if re.match(r'\s*\(func\s+\(;\d+;\)', line):
            func_match = re.search(r'\(func\s+\(;(\d+);', line)
            if func_match:
                func_idx = int(func_match.group(1))
                func_starts.append((func_idx, i))

    func_starts.sort(key=lambda x: x[1])

    # 4. 提取目标函数体
    func_bodies = {}
    for name, idx in target_indices:
        start_line = None
        end_line = len(lines)

        for i, (fidx, line_no) in enumerate(func_starts):
            if fidx == idx:
                start_line = line_no
                if i + 1 < len(func_starts):
                    end_line = func_starts[i + 1][1]
                break

        if start_line is None:
            continue

        body_lines = lines[start_line:end_line]

        if len(body_lines) > max_lines:
            body = '\n'.join(body_lines[:max_lines])
            body += f'\n  ... (truncated, total {len(body_lines)} lines)'
        else:
            body = '\n'.join(body_lines)

        func_bodies[name] = body

    return func_bodies


def format_features_for_stage1(features: dict) -> str:
    """阶段 1 Prompt 格式化：多维度综合分析"""
    lines = []

    # 模块概览
    lines.append("## 模块概览")
    lines.append(f"- 文件大小: {features['file_size']:,} bytes")
    lines.append(f"- 导出函数数: {features['export_count']}")
    lines.append(f"- 导入函数数: {features['import_count']}")
    lines.append(f"- 代码熵: {features.get('code_entropy', 0):.2f} (>6.5 可能表示加密/压缩)")

    framework = features.get('framework', 'unknown')
    framework_names = {
        'eosio': 'EOSIO 区块链智能合约',
        'emscripten': 'Emscripten 编译的 C/C++ 程序',
        'rust_wasm_bindgen': 'Rust wasm-bindgen 项目',
    }
    lines.append(f"- 识别框架: {framework_names.get(framework, framework)}")
    lines.append(f"- 可疑度评分: {features.get('suspicion_score', 0)}/100")

    # 结构层 - 导出函数
    lines.append("\n## 结构层 - 导出函数")
    if features['exports']:
        lines.append(f"所有导出: {', '.join(features['exports'][:30])}")
    if features['suspicious_exports']:
        lines.append(f"预设关键词标记的可疑函数: {', '.join(features['suspicious_exports'])}")
    if features.get('obfuscated_exports'):
        lines.append(f"混淆函数名: {', '.join(features['obfuscated_exports'])}")

    # 结构层 - 导入函数
    lines.append("\n## 结构层 - 导入函数")
    if features['imports']:
        lines.append(f"所有导入: {', '.join(features['imports'][:30])}")
    else:
        lines.append("无导入")

    # 数据层
    lines.append("\n## 数据层")
    lines.append(f"数据段字符串数: {features['data_string_count']}")
    if features['data_strings']:
        sample_strings = features['data_strings'][:10]
        lines.append(f"字符串样本（前 10 个）: {sample_strings}")
    if features['suspicious_strings']:
        lines.append(f"可疑字符串: {features['suspicious_strings']}")

    # 行为层
    lines.append("\n## 行为层")
    comp = features['complexity']
    lines.append(f"- 函数数量: {comp['function_count']}")
    lines.append(f"- 循环数量: {comp['loop_count']}")
    lines.append(f"- 循环密度: {comp['loop_density']} (每千行)")
    lines.append(f"- 最大嵌套深度: {comp['max_nesting_depth']}")

    instr = features['instruction_counts']
    lines.append("- 指令统计:")
    lines.append(f"  - 算术运算: {instr.get('arithmetic', 0)}")
    bw = instr.get('bitwise', 0)
    lines.append(f"  - 位运算: {bw} {'⚠ 高频' if bw > 1000 else ''}")
    lines.append(f"  - 内存操作: {instr.get('memory', 0)}")
    lines.append(f"  - 控制流: {instr.get('control', 0)}")
    lines.append(f"  - 比较运算: {instr.get('comparison', 0)}")

    if features.get('high_xor_count'):
        lines.append("- ⚠ 高频位运算（可能是哈希/加密计算）")
    if features.get('high_loop_count'):
        lines.append("- ⚠ 大量循环（可能是计算密集型代码）")

    # 高级特征
    lines.append("\n## 高级特征")
    mining_ctx = features.get('mining_context', {})
    if any(mining_ctx.values()):
        lines.append("挖矿上下文模式:")
        for category, matches in mining_ctx.items():
            if matches:
                lines.append(f"  - {category}: {', '.join(matches)}")
    else:
        lines.append("挖矿上下文模式: 未检测到")

    return '\n'.join(lines)


def format_features_for_stage2(features: dict, stage1_result: dict, func_code: dict) -> str:
    """阶段 2 Prompt 格式化：代码验证"""
    lines = []

    # 上一轮分析结论
    lines.append("## 上一轮分析结论")
    lines.append(f"- 初步判定: {stage1_result.get('preliminary_verdict', 'unknown')}")
    lines.append(f"- 初步类型: {stage1_result.get('preliminary_type', 'unknown')}")
    lines.append(f"- 初步置信度: {stage1_result.get('preliminary_confidence', 'unknown')}")
    lines.append(f"- 分析依据: {stage1_result.get('reasoning', 'N/A')}")
    lines.append(f"- 数据层分析: {stage1_result.get('data_analysis', 'N/A')}")
    lines.append(f"- 行为层分析: {stage1_result.get('behavior_analysis', 'N/A')}")

    if stage1_result.get('false_positives'):
        lines.append(f"- 排除的误报: {', '.join(stage1_result['false_positives'])}")
    if stage1_result.get('new_suspicious'):
        lines.append(f"- 新发现的可疑函数: {', '.join(stage1_result['new_suspicious'])}")

    # 可疑函数代码
    lines.append("\n## 可疑函数代码")
    if func_code:
        for name, code in func_code.items():
            lines.append(f"\n### 函数: {name}")
            lines.append("```wat")
            lines.append(code)
            lines.append("```")
    else:
        lines.append("未能提取到可疑函数代码")

    return '\n'.join(lines)
