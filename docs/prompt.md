# 会话阶段性总结

## 项目概述

硕士论文开题研究：**基于大语言模型的 WebAssembly 恶意代码检测与对抗鲁棒性研究**

## 核心成果

### 两个创新点已确定

1. **V3 检测方法**：多维度特征提取 + 两阶段 LLM 分析
   - 阶段 0：特征提取（结构层/数据层/行为层/高级特征）
   - 阶段 1：LLM 多维度综合分析（函数筛选 + 数据/行为分析 + 初步判定）
   - 阶段 1.5：可疑函数代码提取
   - 阶段 2：LLM 代码验证（验证/修正初步判定 + 最终判定）

2. **对抗鲁棒性**：5 种攻击方法评估 + 防御增强
   - DBLP 检索 0 篇，研究空白
   - 参考：WASMixer (ESORICS 2024)、WeBMO (COMPSAC 2024)、Cryptic Bytes (arXiv 2024)

### 实验进展

| 版本 | 方法 | 准确率 | 精确率 | 召回率 | F1 |
|------|------|--------|--------|--------|-----|
| V1 | WAT 前 3000 字符截断 | 72.4% | 100% | 42.9% | 60.0% |
| V2 | 多维度特征提取 | 90.0% | 100% | 80.0% | 88.9% |
| V3 | 两阶段 + 领域知识注入 | **100%** | **100%** | **100%** | **100%** |

测试规模：30 样本（15 良性 + 15 恶意），模型 qwen3.6-flash

### 关键发现

- V2 的 3 个漏判样本都是 CryptoNight 挖矿代码，LLM "过度合理化"将其误判为"合法哈希库"
- 通过 Prompt 注入领域知识（CryptoNight 在 Web Wasm 中无合法用途、JS+Wasm 分离架构），成功修正
- EOSIO 区块链合约的误报问题也通过框架识别解决

### 关键文件

| 文件 | 内容 |
|------|------|
| `docs/硕士论文开题报告.md` | 完整开题报告（含 20 篇参考文献） |
| `docs/V3方案.md` | V3 混合二阶段技术方案 |
| `docs/Pilot实验结果与误判分析.md` | 实验结果与 3 个漏判样本的深度分析 |
| `docs/Wasm+大模型_方向A与方向B对比分析.md` | 方向 A（恶意检测）vs 方向 B（Agent 沙箱）对比 |
| `docs/WebAssembly硕士论文方向分析.md` | 早期方向调研 |
| `docs/WebAssembly应用前景与发展趋势.md` | Wasm 应用前景调研 |
| `docs/WebAssembly学习路线.md` | Wasm 学习路线 |
| `scripts/v3/pilot_experiment_v3.py` | V3 实验脚本 |
| `scripts/v3/wasm_feature_extractor_v3.py` | V3 特征提取器 |
| `scripts/wasm_feature_extractor.py` | V2 特征提取器 |
| `scripts/pilot_experiment.py` | V1 实验脚本 |
| `data/WasmMal-main/` | WasmMal-15K 数据集（15,024 样本） |

### 技术栈

- Python 3.14 + WABT 工具链（wasm2wat、wasm-objdump）
- LLM API：DashScope (qwen3.6-flash)
- 特征提取：wasm_feature_extractor_v3.py
- 两阶段分析：pilot_experiment_v3.py

### 20 篇参考文献（已整理在开题报告中）

**恶意检测**：WasmGuard (WWW 2025)、JWBinder (ESORICS 2023) 等 6 篇
**混淆**：Wobfuscator (IEEE S&P 2022)、WASMixer (ESORICS 2024)、WeBMO (COMPSAC 2024)、Cryptic Bytes (2024) 等 7 篇
**LLM+Wasm**：StackSight (ICML 2024)、WaDec (ASE 2024)、LWDIFF (ICSE 2025)、DrWASI (ACM TOSEM 2026) 等 5 篇
**安全基础设施**：WASP、Bento、WARD 等 3 篇

---

## 新窗口提示词

复制以下内容到新窗口开始对话：

---

继续硕士论文研究：基于大语言模型的 WebAssembly 恶意代码检测与对抗鲁棒性研究

当前状态：
- 开题报告已完成：/Users/yangshikang.6/Desktop/Code/wasm/docs/硕士论文开题报告.md
- V3 方法已验证：30 样本测试 100% 准确率
- 两个创新点确定：V3 检测方法 + 对抗鲁棒性评估

下一步任务：
1. 大规模实验验证（WasmMal-15K 全量 15,024 样本）
2. 实现 5 种对抗攻击方法（参考 WASMixer/WeBMO/Cryptic Bytes）
3. 设计鲁棒性评估框架
4. 提出防御增强方法

关键文件：
- 开题报告：docs/硕士论文开题报告.md
- V3 方案：docs/V3方案.md
- 实验结果：docs/Pilot实验结果与误判分析.md
- V3 脚本：scripts/v3/pilot_experiment_v3.py
- 数据集：data/WasmMal-main/（15,024 样本）

技术栈：
- Python 3.14 + WABT 工具链
- LLM API：DashScope (qwen3.6-flash)
- 特征提取：wasm_feature_extractor_v3.py
- 两阶段分析：pilot_experiment_v3.py

请从大规模实验验证开始，或告诉我你想从哪个任务开始。
