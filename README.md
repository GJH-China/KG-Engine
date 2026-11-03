# 凯德荣KG杀毒引擎 · KaeDeRonm KG Antivirus Engine

**中英双语** · [中文文档](#中文文档) | [English Documentation](#english-documentation)

![version](https://img.shields.io/badge/version-KG2c-blue)
![python](https://img.shields.io/badge/python-3.9%2B-green)
![deps](https://img.shields.io/badge/dependencies-none%20(stdlib%20only)-brightgreen)
![license](https://img.shields.io/badge/license-source--available%20%C2%B7%20%E5%95%86%E7%94%A8%E9%9C%80%E6%8E%88%E6%9D%83-orange)

---

# 中文文档

## 这是什么

**凯德荣 KG 引擎**是凯德荣（KaeDeRonm）杀毒软件的自研机器学习检测引擎。

`KG` 是 **K**aeDeRonm **G**uiZhou 的首字母缩写，指 KDR 自己的机器学习引擎，**不是** Knowledge Graph。

它不看哈希、不查云、不依赖任何外部情报，只根据文件本身的字节分布判断它"像不像恶意软件"。因此它对**从未出现过的新样本**同样有效——这是它和一个纯哈希黑名单最本质的区别。

本仓库开源的是 **KG1 / KG2 两代引擎的完整实现与模型**。**KG3 未开源**——那是我们在用的现役引擎，留作底牌。

## 三个设计原则

| 原则 | 说明 |
|---|---|
| **纯标准库** | 不引入 numpy / scikit-learn。整个引擎只依赖 Python 标准库，安装包体积可控，也不会有二进制依赖冲突 |
| **增量学习** | 投喂即更新计数，**不需要重训**，不产生中间大文件。一条样本进来，模型立刻变 |
| **可解释** | 每次判定都能说清"是哪几个特征投的票、各投了多少"——不是黑盒 |

第三条尤其重要。安全产品给出"这是病毒"却说不清为什么，用户没法信、分析师没法复核。KG 的每次预测都返回 `contributions`，逐特征列出正负贡献。

## 快速开始

```bash
git clone https://github.com/<your-account>/kg-engine.git
cd kg-engine
```

不需要 `pip install` 任何东西——只用标准库。

```python
import sys
sys.path.insert(0, '.')          # 或把 kaederonm_kg 放进你的包路径

from kaederonm_kg import KGModel, extract_features, FeatureStore

# 1) 提特征
with open("sample.exe", "rb") as f:
    data = f.read()
fv = extract_features(data, name="sample.exe")

# 2) 训练（增量：可反复调用，不需要重训）
model = KGModel()
model.learn(fv, label="mal")     # label: "mal" 恶意 / "ben" 良性

# 3) 预测
pred = model.predict(fv)
print(pred.score)                # 对数似然比，>0 偏恶意
print(pred.is_malicious)         # bool
print(pred.contributions)        # [(特征名, 贡献值), ...] 正=偏恶意

# 4) 持久化（原子写 + 世代滚动 + 校验和）
store = FeatureStore("./data/kg")
store.save(model)
model2 = store.load()            # 坏档也不会抛异常，返回空模型
```

完整示例见 [`examples/quickstart.py`](examples/quickstart.py)。

## 核心 API

| 接口 | 作用 |
|---|---|
| `extract_features(data, name="")` | 从字节流提取特征向量。按扩展名自动选 `binary` / `text` 通道 |
| `extract_from_path(path)` | 从上路径提特征（含安全解压，支持 zip/7z/tar 递归展开） |
| `KGModel.learn(fv, label)` | 增量投喂一条样本 |
| `KGModel.predict(fv)` | 预测，返回 `Prediction(score, confidence, contributions, votes)` |
| `FeatureStore.save/load` | 模型原子落盘 / 加载，带 SHA-256 校验与世代回滚 |
| `collect_benign_samples()` | 从系统目录采集良性基线（用于冷启动） |

## 算法

**加权朴素贝叶斯 + 对数似然比**。

对每个特征 `f`，分别统计它在恶意集与良性集中的出现次数，用带平滑的似然比打分，再按特征权重（IDF 风格，稀有特征权重更高）加权累加：

```
score = Σ_f  w(f) · log( P(f | malicious) / P(f | benign) )
```

`score > 0` 偏向恶意。两条通道独立打分：

- **binary**：字节 n-gram、PE 结构、熵、导入表、节区异常、字符串模式
- **text**：脚本类文件（.js/.vbs/.ps1/.py…）的语法与关键字特征

特征名形如 `b448`（字节 n-gram 哈希桶）、`f_entropy_7`（熵分档）、`pe_section_rwx`（节区可写可执行）等。

## 开源范围与版本

| 版本 | 状态 | 说明 |
|---|---|---|
| KG1 | ✅ 已发布 | 首版。见 [Releases](https://github.com/<your-account>/kg-engine/releases) |
| KG2 / KG2b / KG2c | ✅ 已发布 | 迭代版，当前开源代码即 KG2c 实现 |
| **KG3** | ❌ **不开源** | 现役引擎，含新的训练配方，留作底牌 |

> 每次都要留一个引擎作为底牌。

## 已知局限（诚实说明）

- **64 位样本识别偏弱**。训练语料中 PE32+ 占比低于 PE32，模型对 64 位恶意软件的召回明显低于 32 位。这是下一版的重点。
- **对加壳/混淆样本判别力衰减**。字节分布被压缩打乱后，统计特征的信息量下降。
- **不替代行为检测**。KG 是静态引擎，能判断"这个文件长得像不像恶意"，但不能判断"它运行时做了什么"。生产环境应与行为监控、情报库配合使用。

## 许可

**源码可见（source-available），商业使用需授权。**

| 用途 | 是否免费 |
|---|---|
| 个人学习、学术研究、教学、非营利公益 | ✅ 免费，可修改可分发 |
| 评估是否采购商业授权 | ✅ 免费 |
| **任何商业用途** | ❌ **须事先取得书面授权** |

「商业使用」包括但不限于：集成进销售/订阅收费的产品、为付费客户提供检测服务、
在营利组织内部用于生产环境、提供 SaaS / API / 云查杀服务。

完整条款见 [LICENSE](LICENSE)，商业授权申请方式也写在里面。

> ⚠️ 本协议**不是 OSI 认可的开源许可**。代码公开可见，但商用要谈 —— 这是
> source-available 模式，不是 open source。如果你在找可以任意商用的代码，
> 这个项目不适合。

---

# English Documentation

## What is this

The **KaeDeRonm KG Engine** is the self-developed machine-learning detection engine inside KaeDeRonm antivirus.

`KG` stands for **K**aeDeRonm **G**uiZhou — our own ML engine. It is **not** Knowledge Graph.

It does not consult hashes, the cloud, or any threat-intelligence feed. It decides whether a file *looks like* malware purely from its byte distribution. That is what makes it effective against **samples it has never seen** — the fundamental difference from a pure hash blacklist.

This repository open-sources the **complete implementation and models of KG1 and KG2**. **KG3 is not open-sourced** — that is our engine in production, kept as a reserve.

## Three design principles

| Principle | Meaning |
|---|---|
| **Standard library only** | No numpy, no scikit-learn. The whole engine depends on nothing but the Python standard library — predictable installer size, no binary dependency conflicts |
| **Incremental learning** | Feeding a sample updates counters directly. **No retraining**, no intermediate files. The model changes the moment a sample arrives |
| **Explainable** | Every verdict can state exactly which features voted and by how much — not a black box |

The third one matters most. A security product that says "this is a virus" without saying why cannot be trusted by users or reviewed by analysts. Every KG prediction returns `contributions`: a per-feature list of positive and negative evidence.

## Quick start

```bash
git clone https://github.com/<your-account>/kg-engine.git
cd kg-engine
```

Nothing to `pip install` — standard library only.

```python
import sys
sys.path.insert(0, '.')          # or place kaederonm_kg on your package path

from kaederonm_kg import KGModel, extract_features, FeatureStore

# 1) Extract features
with open("sample.exe", "rb") as f:
    data = f.read()
fv = extract_features(data, name="sample.exe")

# 2) Learn (incremental — call it as often as you like, no retraining)
model = KGModel()
model.learn(fv, label="mal")     # label: "mal" malicious / "ben" benign

# 3) Predict
pred = model.predict(fv)
print(pred.score)                # log-likelihood ratio; >0 leans malicious
print(pred.is_malicious)         # bool
print(pred.contributions)        # [(feature, contribution), ...] positive = malicious

# 4) Persist (atomic write + generation rollback + checksum)
store = FeatureStore("./data/kg")
store.save(model)
model2 = store.load()            # never raises on a corrupt file; returns an empty model
```

Full example: [`examples/quickstart.py`](examples/quickstart.py).

## Core API

| API | Purpose |
|---|---|
| `extract_features(data, name="")` | Extract a feature vector from bytes. Picks the `binary` / `text` channel from the extension |
| `extract_from_path(path)` | Extract from a path, with safe archive expansion (recursive zip/7z/tar) |
| `KGModel.learn(fv, label)` | Incrementally feed one sample |
| `KGModel.predict(fv)` | Predict; returns `Prediction(score, confidence, contributions, votes)` |
| `FeatureStore.save/load` | Atomic model persistence with SHA-256 verification and generation rollback |
| `collect_benign_samples()` | Collect a benign baseline from system directories (cold start) |

## Algorithm

**Weighted naive Bayes with a log-likelihood ratio.**

For each feature `f`, count its occurrences in the malicious and benign corpora separately, score it with a smoothed likelihood ratio, weight it (IDF-style — rarer features weigh more), and sum:

```
score = Σ_f  w(f) · log( P(f | malicious) / P(f | benign) )
```

`score > 0` leans malicious. Two channels score independently:

- **binary**: byte n-grams, PE structure, entropy, imports, section anomalies, string patterns
- **text**: script files (.js/.vbs/.ps1/.py…) — syntax and keyword features

Feature names look like `b448` (byte n-gram hash bucket), `f_entropy_7` (entropy bucket), `pe_section_rwx` (writable+executable section), etc.

## Open-source scope and versions

| Version | Status | Notes |
|---|---|---|
| KG1 | ✅ Released | First generation. See [Releases](https://github.com/<your-account>/kg-engine/releases) |
| KG2 / KG2b / KG2c | ✅ Released | Iterations; the code here is the KG2c implementation |
| **KG3** | ❌ **Not open-source** | Our production engine with a newer training recipe — kept as a reserve |

> Always keep one engine as your hole card.

## Known limitations (stated honestly)

- **Weaker on 64-bit samples.** PE32+ is under-represented in our training corpus, so recall on 64-bit malware is clearly lower than on 32-bit. This is the focus of the next iteration.
- **Degrades on packed/obfuscated samples.** Compressing or shuffling byte distributions removes much of the statistical signal.
- **Not a replacement for behavioural detection.** KG is a static engine: it answers "does this file look malicious", not "what does it do when run". Pair it with behavioural monitoring and intelligence feeds in production.

## License

**Source-available. Commercial use requires a license.**

| Use | Free? |
|---|---|
| Personal study, academic research, teaching, non-profit | ✅ Free to use, modify, redistribute |
| Evaluating whether to buy a commercial license | ✅ Free |
| **Any commercial use** | ❌ **Prior written permission required** |

"Commercial use" includes, without limitation: embedding in a sold or subscription
product, providing paid detection services, use in production inside a for-profit
organization, and offering SaaS / API / cloud-scanning services.

Full terms in [LICENSE](LICENSE); commercial licensing contact is in there too.

> ⚠️ This is **not an OSI-approved open source license**. The code is publicly
> visible, but commercial use must be negotiated — this is source-available,
> not open source. If you need code you can freely use commercially, this
> project is not for you.
