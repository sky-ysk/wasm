# LLM 接入 Wasm 安全分析：研究方案

> 核心问题：Wasm 二进制怎么喂给 LLM？LLM 怎么做安全分析？

---

## 一、核心挑战：Wasm 二进制 → LLM 输入

LLM 接受的是**文本**，而 Wasm 是**二进制字节流**。第一步必须做**表示转换**。

### 三种可行的输入表示

| 表示方式 | 做法 | 优点 | 缺点 |
|---------|------|------|------|
| **WAT 文本格式** | 用 `wasm2wat` 将二进制转为文本 | 保留完整语义，LLM 可直接阅读 | 文件较大，可能超出上下文窗口 |
| **反汇编指令序列** | 提取函数级指令序列 | 粒度可控，可按函数切分 | 丢失部分结构信息 |
| **结构化摘要** | 提取 imports/exports/内存布局/函数签名等元信息 | 体积小，信息密度高 | 丢失具体实现细节 |

**推荐组合**：结构化摘要（全局） + 关键函数的 WAT 文本（局部）

---

## 二、三种 LLM 接入架构

### 架构 A：LLM 直接分类（最简单）

```
.wasm 文件
    ↓
wasm2wat 转文本
    ↓
截取/分块（处理长文本）
    ↓
Prompt: "分析以下 WebAssembly 代码，判断是否为恶意代码，并说明理由"
    ↓
LLM 输出：{分类结果, 恶意类型, 解释}
```

**优点**：实现简单，可解释性天然具备
**缺点**：LLM 推理慢、成本高，大规模检测不现实
**适合**：作为 WasmGuard 的"第二层"——WasmGuard 快速筛选可疑样本，LLM 深度分析

### 架构 B：LLM 辅助特征工程 + 轻量分类器（推荐）

```
.wasm 文件
    ↓
┌───────────────────────────────────┐
│  传统特征提取（字节统计、段分析）    │  ← 快速、低成本
│  LLM 语义特征提取（函数意图分析）    │  ← 深度、可解释
└───────────────────────────────────┘
    ↓
特征融合
    ↓
轻量分类器（XGBoost/小型NN）
    ↓
输出：{分类, 恶意类型, 解释}
```

**优点**：兼顾效率和深度，LLM 只在特征提取阶段使用
**缺点**：需要设计特征融合策略
**适合**：硕士论文，两个创新点清晰

### 架构 C：两阶段级联（最实用）

```
.wasm 文件
    ↓
第一阶段：WasmGuard 快速检测（毫秒级）
    ↓
判定为可疑？ ──否──→ 放行
    ↓ 是
第二阶段：LLM 深度分析
    ↓
输出：
  - 恶意行为分类（挖矿/混淆/窃取/...）
  - 自然语言解释（"该模块包含..."）
  - 风险评估（高/中/低）
  - 建议处置措施
```

**优点**：效率最高，LLM 只分析可疑样本
**缺点**：依赖第一阶段检测质量
**适合**：工程落地，论文故事也好讲

---

## 三、推荐的研究方案

### 方案一：基于架构 B（推荐作为硕士论文）

**创新点 1（Wasm 侧）**：Wasm 多粒度语义特征提取
- 用 WABT 工具提取 Wasm 的结构化元信息（imports、exports、段布局）
- 用 `wasm2wat` 提取关键函数的指令序列
- 将两者融合为结构化的"语义描述"

**创新点 2（LLM 侧）**：面向 Wasm 安全分析的 LLM Prompt 工程 + 微调
- 设计 Wasm 安全领域的专用 Prompt 模板
- 在 WasmMal-15K 上对开源 LLM（如 LLaMA/Qwen）做 LoRA 微调
- 让 LLM 输出结构化结果：恶意类型 + 置信度 + 自然语言解释

**实验设计**：
1. 在 WasmMal-15K 上对比：纯 LLM vs WasmGuard vs 你的方法
2. 评估维度：准确率、恶意分类精度、可解释性（人工评估）、推理速度
3. 零样本实验：构造训练集中没有的新型恶意样本，测试泛化能力

### 方案二：基于架构 C（更偏工程）

**创新点 1**：WasmGuard + LLM 级联检测框架
**创新点 2**：LLM 驱动的 Wasm 恶意行为语义分析与报告生成

---

## 四、技术栈

| 组件 | 工具选择 |
|------|---------|
| Wasm 分析 | WABT（wasm2wat、wasm-objdump） |
| LLM | Qwen2.5-7B/14B（开源，可本地部署）或 LLaMA-3-8B |
| 微调 | LoRA + PEFT（低资源微调） |
| 数据集 | WasmMal-15K |
| 对比 baseline | WasmGuard、MINOS |
| 评估 | 准确率、F1、BLEU/ROUGE（解释质量）、人工评估 |

---

## 五、最小可行实验（MVP）

### 目标

验证 LLM 是否真的能理解 Wasm 代码并给出有意义的安全分析。一天之内可跑通。

### 前置准备

1. 安装 WABT 工具：`brew install wabt`
2. 准备几个 .wasm 样本（良性 + 恶意各几个）
3. 准备 LLM 访问（API 或本地部署）

### 实验代码

```python
import subprocess
import json

# 1. 将 Wasm 转为 WAT 文本
def wasm_to_wat(wasm_path):
    result = subprocess.run(
        ["wasm2wat", wasm_path],
        capture_output=True, text=True
    )
    return result.stdout

# 2. 提取结构化摘要
def extract_summary(wasm_path):
    result = subprocess.run(
        ["wasm-objdump", "-x", wasm_path],
        capture_output=True, text=True
    )
    return result.stdout

# 3. 构造 Prompt
def build_prompt(wat_snippet, summary):
    return f"""你是一个 WebAssembly 安全分析专家。
请分析以下 WebAssembly 模块，判断其是否为恶意代码。

## 模块摘要信息
{summary}

## 关键函数代码（WAT 格式）
{wat_snippet[:3000]}

请按以下格式输出分析结果：
1. 判定结果：恶意 / 良性
2. 恶意类型（如为恶意）：挖矿 / 混淆 / 数据窃取 / 广告欺诈 / 其他
3. 置信度：高 / 中 / 低
4. 判断依据：（详细说明你从代码中观察到的特征）
5. 行为描述：（用自然语言描述该模块的实际行为）
"""

# 4. 调用 LLM（以 OpenAI API 为例，也可替换为本地模型）
def analyze_wasm(wasm_path, llm_client):
    wat = wasm_to_wat(wasm_path)
    summary = extract_summary(wasm_path)
    prompt = build_prompt(wat, summary)
    
    response = llm_client.chat.completions.create(
        model="qwen2.5-14b-instruct",  # 或其他模型
        messages=[{"role": "user", "content": prompt}],
        temperature=0.1
    )
    return response.choices[0].message.content

# 5. 批量测试
def batch_test(wasm_dir, llm_client):
    results = []
    for f in os.listdir(wasm_dir):
        if f.endswith(".wasm"):
            analysis = analyze_wasm(os.path.join(wasm_dir, f), llm_client)
            results.append({"file": f, "analysis": analysis})
    return results
```

### 验证步骤

1. 选 10 个已知良性 .wasm + 10 个已知恶意 .wasm
2. 用上述代码逐个分析
3. 记录 LLM 的判定结果和分析内容
4. 计算准确率，人工评估解释质量
5. 如果准确率 > 70% 且解释合理 → 方向可行，继续深入

---

## 六、后续扩展路线

```
MVP 验证（1-2 周）
    ↓ 效果可行
数据集准备：下载 WasmMal-15K，编写数据加载和预处理脚本
    ↓
Prompt 优化（2-3 周）：迭代 Prompt 模板，few-shot 示例设计
    ↓
LoRA 微调（2-3 周）：在 WasmMal-15K 上微调开源 LLM
    ↓
对比实验（2-3 周）：与 WasmGuard、MINOS 等 baseline 对比
    ↓
论文撰写（4-6 周）
```
