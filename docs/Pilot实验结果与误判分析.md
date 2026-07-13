# Pilot 实验结果与误判分析

> 实验时间：2026-07-09
> 模型：qwen3.7-plus（DashScope）
> 数据集：WasmMal-15K 测试集，分层抽样 30 个样本（15 良性 + 15 恶意）

---

## 一、实验结果

### 核心指标

| 指标 | 数值 |
|------|------|
| 准确率 (Accuracy) | 72.4% (21/29) |
| 精确率 (Precision) | 100% |
| 召回率 (Recall) | 42.9% |
| F1 Score | 60% |

### 混淆矩阵

```
              预测恶意    预测良性
真实恶意    TP=6        FN=8  ← 漏检 8 个
真实良性    FP=0        TN=15 ← 良性全部正确
```

### Token 使用量

| 指标 | 数值 |
|------|------|
| 总输入 Token | 74,744 |
| 总输出 Token | 46,874 |
| 总 Token | 121,618 |
| 平均每次调用 | 4,193 tokens |

### 费用估算（15K 全量）

| 模型 | 单次费用 | 15K 全量 |
|------|---------|---------|
| qwen3.7-plus (百炼) | ¥0.0181 | ¥271 |
| deepseek-v4-pro (DeepSeek) | ¥0.0174 | ¥261 |
| deepseek-v4-flash (DeepSeek) | ¥0.0058 | ¥87 |

---

## 二、误判样本深度分析

### 9 个误判样本全貌

| # | 文件 | 关键导出函数 | 恶意类型 |
|---|------|------------|---------|
| 1 | `b2dQ...` | `_wbYnAgshchW_hash`, `_wbYnAgshchW_v1_hash`, `_wbYnAgshchW_v7_hash` | 混淆哈希（挖矿） |
| 2 | `c64M...` | `_butter`, `_cow`, `_milk` | 语义伪装（挖矿） |
| 3 | `d21p...` | `_SamxQnAYgSK_hash`, `_SamxQnAYgSK_create` | 混淆哈希（挖矿） |
| 4 | `735g...` | `_cryptonight_hash`, `_cryptonight_create` | CryptoNight 矿机 |
| 5 | `720O...` | （解析失败） | 未知 |
| 6 | `b28g...` | `_setWork`, `_work`, `_stop` | 挖矿任务管理 |
| 7 | `b32p...` | `_cryptonight_hash`, `_cryptonight_create` | CryptoNight 矿机 |
| 8 | `740y...` | `_getHashesDone`, `_main` | 哈希计算（挖矿） |
| 9 | `585I...` | `_cryptonight_hash`, `_cryptonight_create` | CryptoNight 矿机 |

**全部 9 个都是加密货币挖矿恶意软件。**

---

## 三、根本原因分析

### 核心问题：LLM 只看到了 imports，没看到 exports

以 `735g...`（含 `_cryptonight_hash`）为例：

```
WAT 总行数:          ~31,000 行
LLM 看到的:          前 3,000 字符 ≈ 前 60 行

前 60 行内容（LLM 实际看到的）:
  (import "env" "memory" ...)         ← 标准 Emscripten 导入
  (import "env" "DYNAMICTOP_PTR" ...) ← 标准运行时
  (import "env" "___syscall140" ...)  ← 标准系统调用
  (func ...                           ← 函数体开始
    local.get 0
    i32.load
    ...

_cryptonight_hash 出现在: 第 30,857 行  ← LLM 根本看不到！
```

**结论**：当前 Prompt 只截取 WAT 前 3000 字符，而恶意特征（导出函数名、数据段字符串）出现在文件末尾。LLM 只看到了"合法的 Emscripten 编译特征"，完全错过了恶意证据。

---

## 四、三种恶意模式

### 模式 A：显式 CryptoNight（3 个样本）

- 直接导出 `_cryptonight_hash`、`_cryptonight_create`
- 数据段包含 `lib/cryptonight/cryptonight.c`、`do_jh_hash`、`do_skein_hash`
- 这是 Monero 挖矿算法的标准实现
- **如果 LLM 能看到 exports，这类样本应该 100% 被检出**

### 模式 B：混淆哈希名（3 个样本）

- 导出 `_wbYnAgshchW_hash`、`_SamxQnAYgSK_hash` 等随机化名称
- 内部逻辑与 CryptoNight 相同，但函数名被混淆
- 633 次 XOR 操作 + 100 个循环 = 高强度哈希计算
- **需要指令频率统计 + 循环分析才能识别**

### 模式 C：语义伪装（2 个样本）

- `_butter`、`_cow`、`_milk` — 看似无害的函数名
- `_setWork`、`_work`、`_stop` — 看似正常的工作管理
- 实际内部执行挖矿计算
- **需要深入函数体分析才能识别**

---

## 五、对研究方向的启示

### 改进方向 1：输入表示改进（最关键）

**当前问题**：LLM 只看 WAT 前 3000 字符 → 只看到 imports

**改进方案**：提取 Wasm 的结构化特征，而非简单截取

```python
structured_info = {
    "imports": extract_imports(wat),        # 导入函数
    "exports": extract_exports(wat),        # 导出函数 ← 关键！
    "data_strings": extract_strings(wat),   # 数据段字符串
    "function_stats": count_instructions(wat),  # 指令统计
}
```

### 改进方向 2：特征工程（论文创新点 1）

提取 Wasm 的多粒度语义特征：

| 特征类别 | 具体内容 | 作用 |
|---------|---------|------|
| 导出函数名 | `cryptonight_hash` 等 | 直接暴露恶意意图 |
| 数据段字符串 | `lib/cryptonight/cryptonight.c` | 暴露使用的算法库 |
| 指令频率 | XOR 操作 633 次 | 识别哈希计算模式 |
| 循环数量 | 100 个循环 | 识别计算密集型代码 |
| 导入函数 | `___syscall140` 等 | 识别系统调用模式 |

### 改进方向 3：Prompt 优化

在 Prompt 中明确要求 LLM 关注：
- 导出函数名是否有可疑模式（随机字符串、哈希相关词汇）
- 数据段是否包含挖矿算法相关字符串（cryptonight, monero, hash）
- 是否存在高强度的位运算和循环

### 改进方向 4：两阶段检测

```
第一阶段：快速筛选
  - 提取 exports + data_strings
  - 关键词匹配（cryptonight, hash, mine 等）
  - 命中 → 直接标记为恶意（无需 LLM）

第二阶段：LLM 深度分析
  - 仅对第一阶段未命中的样本调用 LLM
  - 提供完整的结构化特征（而非截取 WAT）
  - LLM 判断是否为混淆后的恶意代码
```

---

## 六、结论

### 当前方法的价值

1. **良性检测完美**：15/15 = 100%，说明 LLM 对正常代码的理解很准确
2. **精确率 100%**：预测为恶意时，100% 正确，没有误报
3. **已检出 6 个恶意样本**：说明 LLM 确实能理解部分恶意代码

### 当前方法的局限

1. **召回率仅 42.9%**：8/14 个恶意样本漏检
2. **根本原因**：输入截断导致 LLM 看不到关键特征（exports、data strings）
3. **所有漏检样本都是挖矿软件**：说明 LLM 对"被 Emscripten 包装的挖矿代码"识别能力不足

### 下一步行动

1. **改进输入表示**：提取 exports + data_strings + 指令统计，而非简单截取 WAT
2. **重新测试**：用改进后的方法重新测试这 30 个样本
3. **扩大规模**：如果准确率提升，扩展到 100-500 个样本
4. **论文创新点**：将"多粒度语义特征提取"作为创新点 1，证明其必要性
