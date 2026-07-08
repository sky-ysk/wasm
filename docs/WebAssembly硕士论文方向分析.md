# WebAssembly 硕士毕业论文方向分析

> 基于 2024-2026 年 DBLP 论文调研，筛选适合硕士毕业论文（两个创新点）的切入角度

---

## 方案一：Wasm 恶意代码检测（推荐度 ★★★★★）

### 题目方向

基于多维特征融合的 WebAssembly 恶意代码检测方法

### 创新点

- **创新点1**：提出一种 Wasm 二进制特征提取方法——将 Wasm 的控制流图（CFG）结构特征与字节码序列特征融合，构建多视角表征（现有工作多只用单一特征）
- **创新点2**：设计一个轻量级检测模型（如图神经网络 + 注意力机制），在保持高检测率的同时满足实时性要求

### 好做程度：★★★★★

- 数据集获取门槛低：可从公开恶意样本库（如 MalwareBazaar、VirusTotal）爬取，也可自己写正常/恶意 Wasm 样本构造脚本
- 实验环境简单：一台普通 PC，Python + PyTorch/PyG 即可，不需要集群或特殊硬件
- 指标体系成熟：准确率、召回率、F1、ROC，审稿人一看就懂，不存在"指标怎么算"的争议
- 失败风险低：即使模型效果一般，换个特征组合或模型结构就能调出改进

### 现实需求场景讲述：★★★★★

- 故事线极其清晰：*"Wasm 正被大量用于浏览器挖矿、广告欺诈、恶意混淆（AndroWasm 论文已证实），但现有检测手段要么依赖静态签名（易绕过），要么开销太大（不适合实时），我们需要一种高效准确的检测方法"*
- 有真实案例支撑：CoinHive 挖矿事件、Android 恶意软件用 Wasm 混淆等，答辩时能讲出具体案例
- 产业关联强：浏览器厂商（Chrome/Firefox）、安全厂商（奇安信、深信服）都有这个需求

### 风险

方向热门，需要和同期工作做差异化，创新点要足够具体

### 相关论文参考

- AndroWasm: Android Malware Obfuscation through WebAssembly (ITASEc 2026)
- Detecting Anomalies in WebAssembly Using Categorical Data (SN Comput. Sci. 2026)
- Weaver: Fuzzing JavaScript Engines at the JS-Wasm Boundary (arXiv 2026)
- An Analysis of Modern Web Security Vulnerabilities Inside Wasm Applications (ICISSP 2026)

---

## 方案三：浏览器端 AI 推理的 Wasm 优化（推荐度 ★★★★☆）

### 题目方向

面向浏览器端深度学习推理的 WebAssembly 自适应优化框架

### 创新点

- **创新点1**：提出一种 Wasm 推理引擎的算子级性能建模方法，自动识别瓶颈算子并选择最优执行策略（纯 Wasm / Wasm+SIMD / JS fallback）
- **创新点2**：设计一种模型感知的内存管理策略，根据推理图的内存生命周期动态复用 Wasm 线性内存，减少峰值内存占用

### 好做程度：★★★★☆

- 实验可在本地浏览器完成，Chrome DevTools 直接测延迟和内存，端到端可复现
- ONNX Runtime Web / TensorFlow.js 提供了现成的 Wasm 后端，改造空间明确
- 模型可选范围大（图像分类、NLP 小模型），不需要大模型，普通 GPU 就够
- 但性能优化需要深入理解 Wasm 执行机制和 SIMD，有一定学习曲线

### 现实需求场景讲述：★★★★★

- 故事线非常有说服力：*"隐私法规（GDPR）要求数据不出端，浏览器端 AI 推理成为刚需，但 JS 太慢、Native 插件不跨平台，Wasm 是最佳载体，但现有推理引擎在浏览器端的内存和延迟还有很大优化空间"*
- 隐私计算是当前大热点，答辩时天然加分
- 有真实产品对标：Google 的 MediaPipe Web、Hugging Face 的 Transformers.js 都在做浏览器端推理
- 可以现场 demo：打开浏览器跑一个实时检测，视觉冲击力强

### 风险

需要一定的编译器/底层知识，Wasm SIMD 优化有门槛

### 相关论文参考

- A Hybrid JavaScript-WebAssembly Framework for Efficient Deep Learning Inference in Web Browsers (KSII TIIS 2026)
- Dynamic-Aware Pruning-Quantization Compression for Browser-Based Anomaly Detection via WebAssembly Optimization (IJPRAI 2026)
- WAMO: Toward Secure Browser Inference via Web Model Obfuscation in WebAssembly (WWW 2026)

---

## 方案二（后备）：边缘计算资源调度（推荐度 ★★★★☆）

### 题目方向

面向边缘计算场景的 WebAssembly 函数级自适应调度与优化

### 创新点

- **创新点1**：提出基于 Wasm 模块画像（冷启动时间、内存占用、CPU 密集度）的函数级调度策略，区别于传统容器粒度的调度
- **创新点2**：设计一种 Wasm 模块的预加载/预热缓存机制，结合请求预测动态调整边缘节点上的 Wasm 实例池

### 好做程度：★★★☆☆

- 实验环境搭建成本高：需要模拟边缘计算环境（EdgeCloudSim / Kubernetes + 边缘节点模拟），或真实多节点集群
- 调度策略的 baseline 需要自己实现多个对比算法，工作量大
- 指标多维（延迟、吞吐、资源利用率、冷启动时间），调参和实验设计复杂
- 结果受环境影响大，模拟环境和真实环境可能有偏差，审稿人可能质疑

### 现实需求场景讲述：★★★★☆

- 故事线合理：*"Serverless 从云下沉到边缘，但容器太重（冷启动秒级），Wasm 毫秒级启动适合边缘，但现有调度还是容器粒度的，没有利用 Wasm 函数级轻量特性"*
- 有产业背景：Cloudflare Workers、Fastly Compute@Edge 已在用 Wasm 做边缘计算，是真实趋势
- 但"调度"偏系统方向，硕士论文容易被问"你的系统和已有 Serverless 平台的区别是什么"，需要很强的系统贡献

### 风险

实验说服力难保证，答辩时系统类问题不好应付

### 相关论文参考

- Sonnet: A Workflow-Aware Serverless Platform for Time-Sensitive Edge Computing With WebAssembly (IEEE Trans. Computers 2026)
- Hierarchical Integration of WebAssembly in Serverless for Efficiency and Interoperability (NSDI 2026)
- Lightweight Wasm-Based Intrusion Detection for Zero Trust Edge Networks (IEEE Access 2026)
- Wasm Performance Assessment on Resource Constrained Edge (ICICT 2026)
- Wasm as a Lightweight Path to Sustainable and High-Performance Cloud-Native Computing (CCNC 2026)

---

## 综合推荐排序

| 排名 | 方案 | 好做 | 好讲 | 综合 |
|------|------|------|------|------|
| **1** | **方案一：恶意代码检测** | ★★★★★ | ★★★★★ | 最稳的选择 |
| **2** | **方案三：浏览器端AI推理** | ★★★★☆ | ★★★★★ | 有亮点有深度 |
| **3** | 方案二：边缘计算调度（后备） | ★★★☆☆ | ★★★★☆ | 工程量大 |

### 选择建议

- **求稳毕业**：选方案一，实验好做、指标好量化、故事好讲
- **想有亮点**：选方案三，隐私计算背景 + 可现场 demo + 交叉 AI 方向，答辩印象深刻
- **两者兼顾**：方案一做安全检测 + 方案三做应用场景（比如"检测浏览器端 Wasm 推理引擎的安全漏洞"），融合两个方向
