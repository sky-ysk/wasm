#!/usr/bin/env python3
"""
Wasm 多粒度语义特征提取模块

提取三个层次的特征：
1. 结构层：imports/exports 函数签名
2. 数据层：数据段字符串、常量
3. 行为层：指令频率、循环密度、函数复杂度
"""

import subprocess
import re
import json
from pathlib import Path
from collections import Counter


def run_command(cmd, timeout=30):
    """运行命令并返回输出"""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else ""
    except:
        return ""


def extract_imports(wat_text: str) -> list:
    """提取导入函数"""
    imports = []
    for line in wat_text.split('\n'):
        if '(import' in line:
            # 提取模块名和函数名
            match = re.search(r'\(import\s+"([^"]+)"\s+"([^"]+)"', line)
            if match:
                module, name = match.groups()
                imports.append(f"{module}.{name}")
    return imports


def extract_exports(wat_text: str) -> list:
    """提取导出函数"""
    exports = []
    for line in wat_text.split('\n'):
        if '(export' in line:
            match = re.search(r'\(export\s+"([^"]+)"', line)
            if match:
                exports.append(match.group(1))
    return exports


def extract_data_strings(wat_text: str) -> list:
    """提取数据段中的字符串"""
    strings = []
    for line in wat_text.split('\n'):
        if '(data' in line:
            # 提取引号内的字符串
            matches = re.findall(r'"([^"]{3,})"', line)
            for s in matches:
                # 过滤掉纯转义字符
                if any(c.isalpha() for c in s):
                    strings.append(s)
    return strings


def count_instructions(wat_text: str) -> dict:
    """统计指令频率"""
    # 关键指令类别
    categories = {
        'arithmetic': ['i32.add', 'i32.sub', 'i32.mul', 'i32.div', 'i64.add', 'i64.mul', 'f32.add', 'f64.add'],
        'bitwise': ['i32.and', 'i32.or', 'i32.xor', 'i32.shl', 'i32.shr', 'i32.rotl', 'i32.rotr'],
        'memory': ['i32.load', 'i32.store', 'i64.load', 'i64.store', 'memory.grow'],
        'control': ['block', 'loop', 'br', 'br_if', 'if', 'else', 'call', 'return'],
        'comparison': ['i32.eq', 'i32.ne', 'i32.lt', 'i32.gt', 'i32.le', 'i32.ge'],
    }
    
    counts = {}
    for category, instructions in categories.items():
        count = sum(wat_text.count(instr) for instr in instructions)
        counts[category] = count
    
    # 总指令数（粗略估计）
    counts['total'] = len([line for line in wat_text.split('\n') if line.strip().startswith(('i32.', 'i64.', 'f32.', 'f64.', 'block', 'loop', 'br', 'if', 'call'))])
    
    return counts


def count_functions(wat_text: str) -> int:
    """统计函数数量"""
    return wat_text.count('(func ')


def count_loops(wat_text: str) -> int:
    """统计循环数量"""
    return wat_text.count('(loop')


def calculate_complexity_metrics(wat_text: str) -> dict:
    """计算复杂度指标"""
    lines = wat_text.split('\n')
    
    # 函数数量
    func_count = count_functions(wat_text)
    
    # 循环数量
    loop_count = count_loops(wat_text)
    
    # 循环密度（每千行代码的循环数）
    loop_density = (loop_count / len(lines) * 1000) if lines else 0
    
    # 最大嵌套深度（粗略估计）
    max_depth = 0
    current_depth = 0
    for line in lines:
        if any(kw in line for kw in ['(block', '(loop', '(if']):
            current_depth += 1
            max_depth = max(max_depth, current_depth)
        elif ')' in line and current_depth > 0:
            # 简单的深度减少逻辑
            current_depth = max(0, current_depth - line.count(')'))
    
    return {
        'function_count': func_count,
        'loop_count': loop_count,
        'loop_density': round(loop_density, 2),
        'max_nesting_depth': max_depth,
        'total_lines': len(lines),
    }


def detect_obfuscated_name(name: str) -> bool:
    """检测混淆的函数名"""
    clean_name = name.lstrip('_')
    
    # 排除 C++ Itanium ABI 名称修饰（_ZN, _Z 开头）
    if clean_name.startswith('Z') or clean_name.startswith('ZN'):
        return False
    
    # 排除 Emscripten 标准运行时符号
    emscripten_prefixes = ['stack', 'dyn', 'set', 'get', 'establish', 'run', '___', '__']
    if any(clean_name.startswith(p) for p in emscripten_prefixes):
        return False
    
    # 如果包含已知关键词但前缀是随机字符串，则可疑
    keywords = ['hash', 'keccak', 'sha', 'mine', 'crypt', 'job', 'mctx', 'mloop', 'mresult']
    for keyword in keywords:
        if keyword in clean_name.lower():
            # 检查前缀是否为随机字符串（长度>5且无明显含义）
            prefix = clean_name.split(keyword)[0]
            if len(prefix) > 5 and not prefix.isalpha():
                return True
    
    return False


def calculate_entropy(data: bytes) -> float:
    """计算数据熵"""
    from collections import Counter
    import math
    
    if not data:
        return 0.0
    
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    
    return entropy


def detect_framework(exports: list, data_strings: list) -> str:
    """识别已知的合法框架"""
    # EOSIO 区块链智能合约
    eosio_indicators = ['eosio', 'multi_index', 'eosio.token', 'require_auth', 'checksum256']
    all_text = ' '.join(exports + data_strings).lower()
    if any(ind in all_text for ind in eosio_indicators):
        return 'eosio'
    
    # Emscripten 标准运行时
    emscripten_indicators = ['emscripten', '_emscripten_', 'DYNAMICTOP_PTR', 'STACKTOP']
    if any(ind in all_text for ind in emscripten_indicators):
        return 'emscripten'
    
    # Rust wasm-bindgen
    rust_indicators = ['__wbindgen', 'wbg_', '__wbg_']
    if any(ind in all_text for ind in rust_indicators):
        return 'rust_wasm_bindgen'
    
    return 'unknown'


def analyze_mining_context(exports: list) -> dict:
    """分析挖矿上下文"""
    mining_patterns = {
        'context_creation': ['makemctx', 'create', 'init'],
        'job_management': ['setjob', 'getjob', 'submit', 'share'],
        'mining_loop': ['mloop', 'work', 'mine'],
    }
    
    results = {}
    for category, patterns in mining_patterns.items():
        matches = []
        for e in exports:
            e_lower = e.lower()
            # 排除 C++ mangled names
            if e_lower.startswith('_z') or e_lower.startswith('_zn'):
                continue
            if any(p in e_lower for p in patterns):
                matches.append(e)
        results[category] = matches
    
    return results


def calculate_suspicion_score(features: dict) -> float:
    """计算可疑度评分（0-100）"""
    score = 0
    
    # 如果识别到已知合法框架，大幅降低评分
    framework = features.get('framework', 'unknown')
    if framework in ('eosio', 'rust_wasm_bindgen'):
        return min(score, 20)  # 已知合法框架，最高 20 分
    
    # 可疑导出（+30分）
    if features['suspicious_exports']:
        score += 30
    
    # 混淆函数名（+25分）
    if any(detect_obfuscated_name(e) for e in features['exports']):
        score += 25
    
    # 高位运算（+20分）
    if features['instruction_counts']['bitwise'] > 1000:
        score += 20
    
    # 挖矿上下文模式（+25分）
    mining_ctx = features.get('mining_context', analyze_mining_context(features['exports']))
    if any(mining_ctx.values()):
        score += 25
    
    # Emscripten 框架降低评分（合法编译工具链）
    if framework == 'emscripten':
        score = max(0, score - 15)
    
    return min(score, 100)


def extract_features(wasm_path: str) -> dict:
    """提取 Wasm 文件的多粒度特征"""
    # 转换为 WAT
    wat_text = run_command(['wasm2wat', wasm_path])
    if not wat_text:
        return {"error": "Failed to convert to WAT"}
    
    # 提取 objdump 信息
    objdump_text = run_command(['wasm-objdump', '-x', wasm_path])
    
    # 1. 结构层特征
    imports = extract_imports(wat_text)
    exports = extract_exports(wat_text)
    
    # 2. 数据层特征
    data_strings = extract_data_strings(wat_text)
    
    # 3. 行为层特征
    instruction_counts = count_instructions(wat_text)
    complexity = calculate_complexity_metrics(wat_text)
    
    # 4. 熵分析（从原始二进制文件）
    with open(wasm_path, 'rb') as f:
        wasm_bytes = f.read()
    
    # 计算代码段和数据段熵（简化：整体熵）
    code_entropy = calculate_entropy(wasm_bytes)
    
    # 文件大小
    file_size = Path(wasm_path).stat().st_size
    
    # 扩展可疑关键词列表
    suspicious_keywords = [
        'hash', 'mine', 'crypt', 'work', 'job', 'submit', 'share',
        'nonce', 'difficulty', 'pool', 'stratum', 'mctx', 'mloop', 'mresult'
    ]
    
    # 可疑指标
    suspicious_exports = [e for e in exports if any(kw in e.lower() for kw in suspicious_keywords)]
    suspicious_strings = [s for s in data_strings if any(kw in s.lower() for kw in ['cryptonight', 'monero', 'hash', 'mine'])]
    obfuscated_exports = [e for e in exports if detect_obfuscated_name(e)]
    
    features = {
        'file': Path(wasm_path).name,
        'file_size': file_size,
        
        # 结构层
        'imports': imports,
        'import_count': len(imports),
        'exports': exports,
        'export_count': len(exports),
        
        # 数据层
        'data_strings': data_strings,
        'data_string_count': len(data_strings),
        
        # 行为层
        'instruction_counts': instruction_counts,
        'complexity': complexity,
        
        # 可疑指标
        'suspicious_exports': suspicious_exports,
        'suspicious_strings': suspicious_strings,
        'obfuscated_exports': obfuscated_exports,
        'high_xor_count': instruction_counts.get('bitwise', 0) > 100,
        'high_loop_count': complexity['loop_count'] > 50,
        
        # 新增特征
        'code_entropy': round(code_entropy, 2),
        'mining_context': analyze_mining_context(exports),
        
        # 框架识别
        'framework': detect_framework(exports, data_strings),
    }
    
    # 计算可疑度评分
    features['suspicion_score'] = calculate_suspicion_score(features)
    
    return features


def format_features_for_prompt(features: dict) -> str:
    """将特征格式化为 Prompt 输入"""
    lines = []
    
    lines.append("## 结构特征")
    lines.append(f"- 文件大小: {features['file_size']:,} bytes")
    lines.append(f"- 导入函数数: {features['import_count']}")
    lines.append(f"- 导出函数数: {features['export_count']}")
    
    if features['exports']:
        lines.append(f"- 导出函数列表: {', '.join(features['exports'][:20])}")
    
    if features['suspicious_exports']:
        lines.append(f"- ⚠ 可疑导出函数: {', '.join(features['suspicious_exports'])}")
    
    lines.append("\n## 数据特征")
    lines.append(f"- 数据段字符串数: {features['data_string_count']}")
    
    if features['data_strings']:
        # 显示前 10 个字符串
        sample_strings = features['data_strings'][:10]
        lines.append(f"- 字符串样本: {sample_strings}")
    
    if features['suspicious_strings']:
        lines.append(f"- ⚠ 可疑字符串: {features['suspicious_strings']}")
    
    lines.append("\n## 行为特征")
    lines.append(f"- 函数数量: {features['complexity']['function_count']}")
    lines.append(f"- 循环数量: {features['complexity']['loop_count']}")
    lines.append(f"- 循环密度: {features['complexity']['loop_density']} (每千行)")
    lines.append(f"- 最大嵌套深度: {features['complexity']['max_nesting_depth']}")
    
    instr = features['instruction_counts']
    lines.append(f"- 指令统计:")
    lines.append(f"  - 算术运算: {instr.get('arithmetic', 0)}")
    lines.append(f"  - 位运算: {instr.get('bitwise', 0)} {'⚠ 高频' if instr.get('bitwise', 0) > 100 else ''}")
    lines.append(f"  - 内存操作: {instr.get('memory', 0)}")
    lines.append(f"  - 控制流: {instr.get('control', 0)}")
    lines.append(f"  - 比较运算: {instr.get('comparison', 0)}")
    
    if features['high_xor_count']:
        lines.append("- ⚠ 高频位运算（可能是哈希/加密计算）")
    if features['high_loop_count']:
        lines.append("- ⚠ 大量循环（可能是计算密集型代码）")
    
    # 新增特征展示
    lines.append("\n## 高级特征")
    lines.append(f"- 代码熵: {features.get('code_entropy', 0):.2f} (>6.5 可能表示加密/压缩)")
    
    framework = features.get('framework', 'unknown')
    if framework != 'unknown':
        framework_names = {
            'eosio': 'EOSIO 区块链智能合约',
            'emscripten': 'Emscripten 编译的 C/C++ 程序',
            'rust_wasm_bindgen': 'Rust wasm-bindgen 项目',
        }
        lines.append(f"- ✓ 识别到已知框架: {framework_names.get(framework, framework)}")
    
    if features.get('obfuscated_exports'):
        lines.append(f"- ⚠ 混淆函数名: {', '.join(features['obfuscated_exports'])}")
    
    mining_ctx = features.get('mining_context', {})
    if any(mining_ctx.values()):
        lines.append("- ⚠ 挖矿上下文模式:")
        for category, matches in mining_ctx.items():
            if matches:
                lines.append(f"  - {category}: {', '.join(matches)}")
    
    suspicion_score = features.get('suspicion_score', 0)
    lines.append(f"- 可疑度评分: {suspicion_score}/100")
    if suspicion_score >= 70:
        lines.append("  ⚠⚠⚠ 高度可疑！强烈建议判定为恶意")
    elif suspicion_score >= 50:
        lines.append("  ⚠⚠ 中度可疑，建议仔细审查")
    elif framework != 'unknown':
        lines.append("  ✓ 已知合法框架，建议判定为良性")
    
    return '\n'.join(lines)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 wasm_feature_extractor.py <wasm_file>")
        sys.exit(1)
    
    wasm_path = sys.argv[1]
    features = extract_features(wasm_path)
    
    if 'error' in features:
        print(f"Error: {features['error']}")
        sys.exit(1)
    
    print(json.dumps(features, indent=2, ensure_ascii=False))
    print("\n" + "="*60)
    print("格式化输出（用于 Prompt）:")
    print("="*60)
    print(format_features_for_prompt(features))
