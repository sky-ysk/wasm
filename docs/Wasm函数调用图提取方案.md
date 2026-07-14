# Wasm 函数调用图提取方案

> 用于创新点 2 防御方案：在语义符号被混淆后，通过调用图拓扑特征补偿 LLM 的检测能力。

---

## 方案一：脚本静态解析（推荐，可批量处理 15K 样本）

原理：把 wasm 转成 WAT 文本，扫描所有 `call` 指令，构建有向图。

```python
import subprocess
import re
import networkx as nx

def extract_call_graph(wasm_path):
    # 1. 转为 WAT
    result = subprocess.run(["wasm2wat", wasm_path], capture_output=True, text=True)
    wat = result.stdout

    graph = nx.DiGraph()
    current_func = None

    for line in wat.splitlines():
        line = line.strip()

        # 识别函数定义：(func $name ...) 或 (func (;index;) ...)
        func_def = re.match(r'\(func (\$[\w.]+|\(;(\d+);\))', line)
        if func_def:
            current_func = func_def.group(1)
            graph.add_node(current_func)

        # 识别调用：call $name 或 call index
        if current_func:
            call = re.match(r'call (\$[\w.]+|\d+)', line)
            if call:
                callee = call.group(1)
                graph.add_edge(current_func, callee)

    return graph

def print_graph_stats(G):
    print(f"节点数（函数数）: {G.number_of_nodes()}")
    print(f"边数（调用关系数）: {G.number_of_edges()}")
    # 被调用最多的函数（挖矿核心函数往往在这里）
    top = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)[:5]
    print(f"被调用最多的函数: {top}")
```

**局限**：`call_indirect`（间接调用）无法静态解析出具体目标，需要运行时信息。对挖矿检测影响不大，因为挖矿的哈希计算核心通常是直接调用。

---

## 方案二：用现有工具（更省事）

### Octopus（Python，专为 Wasm 分析设计）

```bash
pip install octopus-wasm
```

```python
from octopus.arch.wasm.cfg import WasmCFG

cfg = WasmCFG(open("sample.wasm", "rb").read())
for func in cfg.functions:
    print(func.name, "->", [c.name for c in func.call_refs])
```

### Binaryen（命令行，更底层）

```bash
brew install binaryen
wasm-opt sample.wasm --print-call-graph
```

直接输出调用图文本，适合快速查看单个样本。

---

## 方案三：脚本提取结构 + LLM 语义解读（防御方案核心）

脚本负责提取拓扑特征，LLM 负责语义推理，两者互补。

```python
def describe_call_graph(G, wat_snippet):
    top_nodes = sorted(G.in_degree(), key=lambda x: x[1], reverse=True)[:5]
    graph_desc = f"""
函数调用图统计：
- 总函数数：{G.number_of_nodes()}
- 总调用关系：{G.number_of_edges()}
- 被调用最多的函数（可能是核心算法）：{top_nodes}
- 图密度：{nx.density(G):.4f}
"""
    prompt = f"""
以下是一个 WebAssembly 模块的函数调用图统计信息和部分代码。
即使函数名已被混淆（如 $f0, $f1），请根据调用结构判断是否为挖矿恶意代码。

{graph_desc}

{wat_snippet[:1000]}

判断依据：挖矿程序通常有一个被高频调用的核心哈希函数，图密度较高。
"""
    return prompt
```

实际使用时，不需要把整个调用图喂给 LLM，只需提取以下拓扑特征作为结构化数据传入 Prompt：

| 特征 | 说明 | 挖矿程序的典型值 |
|------|------|----------------|
| 最大入度节点的入度值 | 被调用最多的函数 | 异常高 |
| 图密度 | 边数 / 节点数² | 相对高 |
| 最大入度 / 平均入度比 | 核心函数的突出程度 | 大 |
| 入度 > 阈值的函数数量 | 高频调用函数的数量 | 少（1-2 个） |

---

## 三种方案对比

| 方案 | 适用场景 | 能处理 15K 样本？ | 能处理间接调用？ |
|------|---------|----------------|----------------|
| 脚本解析 WAT | 批量实验 | 是 | 否 |
| Octopus / Binaryen | 批量实验 | 是 | 部分 |
| LLM 解读图结构 | 语义标注、小样本验证 | 成本高 | 是（推理） |

---

## 在防御方案中的定位

```
混淆攻击（函数名重命名 + 数据段加密）
        ↓
LLM 语义信号失效（准确率 ~65%）
        ↓
补充调用图拓扑特征（脚本提取，混淆不变）
        ↓
LLM + 结构特征混合判断（预期准确率 ~80-85%）
```

调用图拓扑特征的核心优势：**无论函数名如何重命名、死代码如何插入，挖矿程序的哈希核心函数必然是调用图中入度最高的节点**，否则程序功能就被破坏了。这是混淆攻击无法绕过的物理约束。