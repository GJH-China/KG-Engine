# 商业授权 · Commercial Licensing

> 本文件是说明，不构成许可条款。正式条款以 [LICENSE](LICENSE)（GNU AGPL-3.0）为准，
> 商业授权以双方签署的书面协议为准。

---

## 中文

### 一句话

本项目以 **GNU AGPL-3.0** 发布，**已经允许商业使用**——前提是你接受 AGPL 的条款。
如果你不接受（典型情况：不想开源自己的代码），才需要购买商业授权。

### AGPL 免费就能用，为什么还要商业许可

AGPL 是 copyleft 许可。它允许你做任何事，包括拿去赚钱，但有一个硬条件：
**你分发出去的衍生作品，或者通过网络提供给他人使用的服务，其源码也必须以 AGPL 开放。**

对很多商业场景来说，这个条件等于不能用：

| 你的场景 | 用 AGPL 免费 | 需要商业授权 |
|---|---|---|
| 个人项目、学习、研究 | ✅ | — |
| 开源自己的项目（AGPL 兼容） | ✅ | — |
| 内部工具，不分发给外人、不对外提供服务 | ✅ | — |
| **闭源产品里集成这个引擎** | ❌ 必须开源整个产品 | ✅ |
| **做 SaaS / 云查杀 / API 服务** | ❌ 必须向使用者开放服务端源码 | ✅ |
| **卖给客户但不想给源码** | ❌ | ✅ |
| **硬件设备内置且拒绝提供源码** | ❌ | ✅ |

简单说：**能接受开源 → 不用花钱；不能接受开源 → 来找我谈。**

### 商业授权提供什么

商业授权是按你实际需求谈的，通常可以包含：

- **免除 AGPL 的开源义务** —— 可以闭源集成，不需要公开你的代码；
- **明确的使用范围** —— 部署数量、终端数、调用量、服务形态；
- **可选的源码交付或技术对接**；
- **可选的版本更新与支持**。

具体价格、范围、期限没有固定价目，取决于用途和规模。

### 不提供什么

说实话，避免误解：

- **不提供「认证」或「背书」。** 买了授权不代表可以宣称"经凯德荣官方认证"。
- **不提供检测效果担保。** 这是静态检测引擎，会误报、会漏报。授权不改变这一点。
- **不承担你的合规责任。** 你用它做安全产品，合规责任在你。

### 怎么申请

提 Issue 或直接联系，说明这四项：

1. 公司/组织名称
2. 使用场景（集成进什么产品、还是做服务）
3. 预计规模（终端数 / 请求量 / 部署套数）
4. 是否需要技术支持

**联系方式**

- 项目主页：https://cloud.gjhdr.xyz/kdr/
- Issue：https://github.com/GJH-China/KG-Engine/issues
  （**不要在公开 Issue 里写商业细节**，说一句"需要商业授权，请私下联系"即可）
- GitHub：@GJH-China

### 关于违约

未取得授权就闭源使用或提供 SaaS，属于违反 AGPL-3.0。AGPL 是经过司法检验的成熟
许可文本，维权路径明确。**先谈，比事后被要求下架划算。**

---

## English

### In one line

This project is released under **GNU AGPL-3.0**, which **already permits commercial
use** — provided you accept AGPL's terms. You only need to buy a commercial license
if you don't accept them (typically: you don't want to open-source your own code).

### AGPL is free, so why a commercial license

AGPL is a copyleft license. It lets you do anything, including making money, on one
hard condition: **any derivative work you distribute, or any service you let others
use over a network, must have its source released under AGPL too.**

For many commercial scenarios that condition makes it unusable:

| Your scenario | AGPL, free | Commercial license |
|---|---|---|
| Personal projects, study, research | ✅ | — |
| Open-sourcing your own AGPL-compatible project | ✅ | — |
| Internal tooling, not distributed, not offered as a service | ✅ | — |
| **Embedding the engine in a closed-source product** | ❌ must open-source the whole product | ✅ |
| **SaaS / cloud scanning / API service** | ❌ must publish server-side source | ✅ |
| **Selling to customers without giving source** | ❌ | ✅ |
| **Shipped inside hardware with no source offer** | ❌ | ✅ |

In short: **fine with open source → free; not fine with it → let's talk.**

### What a commercial license covers

Negotiated per case, typically:

- **A waiver of AGPL's source-release obligation** — closed-source integration allowed
- **A defined scope** — deployments, endpoints, request volume, service form
- **Optional source delivery or engineering support**
- **Optional updates and maintenance**

Pricing and terms depend on use case and scale; there is no fixed price list.

### What it does not cover

Being explicit, to avoid misunderstanding:

- **No "certification" or endorsement.** A license does not let you claim
  "officially certified by KaeDeRonm".
- **No accuracy guarantee.** This is a static engine; it produces false positives and
  false negatives. A license does not change that.
- **No transfer of your compliance responsibility.** If you build a security product
  on it, that responsibility remains yours.

### How to request

Open an issue or get in touch with:

1. Company / organization name
2. Intended use (embedded in a product, or offered as a service)
3. Expected scale (endpoints / request volume / deployment count)
4. Whether technical support is needed

**Contact**

- Project home: https://cloud.gjhdr.xyz/kdr/
- Issues: https://github.com/GJH-China/KG-Engine/issues
  (**Do not post commercial details in public issues** — just say you need a
  commercial license and ask for private contact.)
- GitHub: @GJH-China

### On violation

Closed-source use or offering it as a service without a license violates AGPL-3.0.
AGPL is a mature, court-tested license text with a clear enforcement path.
**Talking first is cheaper than being told to take it down later.**
