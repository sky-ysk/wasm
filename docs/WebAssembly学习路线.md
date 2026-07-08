# WebAssembly 学习路线（面向硕士论文方向）

> 目标：为方向 A（LLM + Wasm 安全分析）和方向 B（Wasm 沙箱 + Agent）打基础

---

## 第一阶段：基础概念（1-2 周）

### 必读资料

- [WebAssembly 官方文档](https://webassembly.github.io/spec/) — 重点看 Concepts 和 Text Format 部分
- [MDN WebAssembly 教程](https://developer.mozilla.org/en-US/docs/WebAssembly) — 最友好的入门材料
- 《Programming WebAssembly with Rust》（Kevin Hoffman）— 一本书搞定 Wasm + Rust 基础

### 动手实践

- 用浏览器 DevTools 看一个 `.wasm` 文件的加载和执行过程
- 用 [WebAssembly Studio](https://webassembly.studio/) 在线写几个 C/Rust → Wasm 的小例子
- 在本地用 Emscripten 将一个简单 C 程序编译为 Wasm 并运行

### 阶段目标

- [ ] 理解 Wasm 是什么、为什么需要它
- [ ] 能手动编译并运行一个简单的 Wasm 模块
- [ ] 理解 Wasm 与 JavaScript 的交互方式

---

## 第二阶段：核心机制（2-3 周）

### 重点掌握

- **线性内存模型** — 理解 Wasm 的沙箱隔离原理（方向 A、B 都需要）
- **WASI（WebAssembly System Interface）** — 理解 Wasm 如何与宿主环境交互（方向 B 核心）
- **Wasm 二进制格式** — 理解 section 结构、指令编码（方向 A 特征提取需要）
- **Wasm 指令集** — 栈式虚拟机、控制流指令、内存操作指令

### 动手实践

- 用 `wasmtime` 运行 Wasm 模块，观察 WASI 调用 trace
- 用 `wasm-objdump`（WABT 工具包）反编译一个 `.wasm` 文件，看字节码结构
- 用 `wasm2wat` 将二进制转为文本格式，逐行阅读理解
- 用 Rust + `wasm-bindgen` 编译一个 Wasm 模块并在浏览器中运行

### 阶段目标

- [ ] 能看懂 WAT（WebAssembly Text Format）代码
- [ ] 理解 Wasm 线性内存的分配和访问方式
- [ ] 理解 WASI 调用机制和权限模型
- [ ] 能用 WABT 工具分析任意 Wasm 二进制文件

---

## 第三阶段：按方向深入（持续）

### 方向 A 深入内容（LLM + Wasm 安全分析）

| 学习内容 | 目的 |
|----------|------|
| Wasm CFG/数据流分析 | 构建多视角特征表示（创新点1） |
| Wasm 反汇编与特征提取 | 提取恶意代码特征 |
| 恶意样本收集与分析 | 构建训练数据集 |
| LLM 代码理解能力评估 | 验证 LLM 对 Wasm 的理解程度 |

**必读论文**：
- WasmGuard (WWW 2025) — 原始二进制级恶意检测
- JWBinder (ESORICS 2023) — 跨语言恶意检测，揭示传统方法 49.1% 检测率
- AndroWasm (ITASEc 2026) — Android 恶意软件利用 Wasm 混淆
- StackSight (ICML 2024) — LLM 辅助 Wasm 反编译
- WaDec (ASE 2024) — LLM 辅助 Wasm 反编译

### 方向 B 深入内容（Wasm 沙箱 + Agent）

| 学习内容 | 目的 |
|----------|------|
| WASI capability-based 权限模型 | 设计沙箱权限策略（创新点1） |
| Wasm 运行时源码（Wasmtime/Wasmer） | 理解沙箱隔离实现 |
| Wasm Component Model | 理解组件化隔离机制 |
| LLM Agent 框架（LangChain/AutoGPT） | 理解 Agent 代码执行流程 |

**必读论文**：
- DrWASI (ACM TOSEM 2026) — LLM 辅助 WASI 差分测试
- LWDIFF (ICSE 2025) — LLM 辅助 Wasm 运行时差分测试
- Sonnet (IEEE TC 2026) — 边缘计算 Wasm Serverless 平台
- Hierarchical Integration of Wasm in Serverless (NSDI 2026)

---

## 工具链速查

| 工具 | 用途 | 安装方式 |
|------|------|----------|
| `wasmtime` | Wasm 运行时，支持 WASI | `curl https://wasmtime.dev/install.sh -sSf \| bash` |
| `wabt`（wasm-objdump/wasm2wat） | Wasm 二进制分析、反编译 | `brew install wabt` |
| `wasm-bindgen` + `wasm-pack` | Rust → Wasm 开发工具链 | `cargo install wasm-pack` |
| `Emscripten` | C/C++ → Wasm 编译 | `git clone` + `emsdk install` |
| `binaryen` | Wasm 优化工具集 | `brew install binaryen` |
| Chrome DevTools | 浏览器端 Wasm 调试 | Chrome 自带 |
| `wasmer` | 另一个 Wasm 运行时 | `curl https://get.wasmer.io -sSf \| sh` |

---

## 推荐学习顺序

```
MDN 教程（建立概念框架）
    ↓
《Programming WebAssembly with Rust》（系统学习 + 动手实践）
    ↓
WABT 工具实操（反编译、分析二进制、理解指令集）
    ↓
wasmtime 实操（WASI 调用、运行时行为观察）
    ↓
精读方向对应论文（A: WasmGuard/JWBinder 或 B: DrWASI/Sonnet）
    ↓
确定最终方向，开始实验设计
```

---

## 补充资源

### 在线实验环境

- [WebAssembly Studio](https://webassembly.studio/) — 在线 IDE，零配置
- [WasmFiddle](https://wasdk.github.io/WasmFiddle/) — 在线 C → Wasm 实验

### 开源项目（可参考学习）

- [Wasmtime](https://github.com/bytecodealliance/wasmtime) — Rust 实现的 Wasm 运行时
- [Wasmer](https://github.com/wasmerio/wasmer) — 另一个主流 Wasm 运行时
- [wasm-bindgen](https://github.com/rustwasm/wasm-bindgen) — Rust 与 Wasm 的互操作工具
- [WABT](https://github.com/WebAssembly/wabt) — Wasm 二进制工具集

### 社区与动态

- [WebAssembly GitHub](https://github.com/WebAssembly) — 官方规范和提案
- [Bytecode Alliance](https://bytecodealliance.org/) — Wasm 运行时生态联盟
- [WASI GitHub](https://github.com/WebAssembly/WASI) — WASI 规范和讨论
