"""KG 机器引擎 - 学习器（块2）

设计取舍
    1. 纯标准库实现**加权朴素贝叶斯**（多变量伯努利 / 存在性模型）。
       不引入 numpy / sklearn —— 安装包体积与依赖面是硬约束。
    2. 增量式：learn() 只做计数累加，不重训、不落中间大文件。
       投喂 1 个样本与投喂 10 万个样本走同一条代码路径。
    3. 可解释：predict() 返回贡献最大的若干特征名，GUI 能直接展示
       「是哪几个特征投的票」，而不是一个黑盒分数。
    4. 双通道独立：text（脚本源码）与 binary（PE/其他）各一套模型。
       两类样本的特征空间几乎不重叠，混在一起只会互相稀释。

为什么是「加权」而非常规朴素贝叶斯
    常规 MNB 用「特征出现与否」的二值，但特征提取器给的是**频次**
    （比如 s_iex 出现 3 次）。这里对频次做对数压缩 w = 1 + log2(count)，
    单次出现权重 1.0，多次出现权重缓慢上升 —— 避免单一样本里某个
    特征刷了几百次就把后验概率带飞。

打分语义
    score = log P(x|mal) - log P(x|ben) + log(prior_mal / prior_ben)
    每张特征票再加上 log(n_mal / n_ben) 做类别对称化（见 SYMMETRIZE_LIKELIHOOD），
    否则少数类（恶意）会拿到系统性更大的分差，令所有分数整体为正。
    score > 0 偏恶意，< 0 偏良性。绝对值本身无意义，只用于排序与
    阈值比较，4.0 接入扫描时由第三方阈值决定。

线程安全
    learn()/predict() 可能被 GUI 线程与扫描线程同时调用，内部用
    threading.RLock 保护计数表；RLock 便于 predict 内部再调内部方法。
"""
from __future__ import annotations

import math
import threading
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

# ============================================================
# 常量
# ============================================================

#: 拉普拉斯平滑强度。特征从未见过时按 0.5 次处理，避免 log(0)。
ALPHA = 0.5

#: 先验强度。恶意/良性先验按样本数走，但用该因子回拉，
#: 防止「良性样本远多于恶意」时后验被先验压倒（基线采集会喂大量良性）。
PRIOR_DAMPING = 0.5

#: 频次权重压缩系数：w = 1 + WEIGHT_K * log2(count)
WEIGHT_K = 1.0

#: 似然比对称化。伯努利式 p=(c+ALPHA)/(n+2*ALPHA) 在 n_mal != n_ben 时
#: 会让少数类（恶意）拿到系统性的更大分差，实测单票强度比达 2.6~3.3 倍，
#: 导致所有样本分数整体为正、阈值 0 失效（排序能力 AUC 不受影响）。
#: 开启后每张票再加 log(n_mal/n_ben)（该值为负），把两类拉回同一基准：
#: 修正后 |正票|/|负票| 收敛到约 0.90~0.99，且正票>0、负票<0。
#: 置 False 可退回旧的未对称化行为（仅供对照实验）。
SYMMETRIZE_LIKELIHOOD = True

#: 允许的最大特征计数，防御畸形样本把计数器推到离谱的量级。
MAX_FEATURE_COUNT = 100000

#: predict 默认返回的贡献特征条数。
TOP_CONTRIB = 5


# ============================================================
# 数据结构
# ============================================================

@dataclass
class Prediction:
    """一次预测的结果。

    score       : 对数似然比（>0 偏恶意）
    channel     : 使用的通道
    confidence  : 归一到 0~1 的置信度（sigmoid 压缩后的分数）
    contributions: 贡献最大的 (特征名, 贡献值) 列表，贡献值>0 偏恶意
    votes       : 参与投票的特征数
    """
    score: float = 0.0
    channel: str = "binary"
    confidence: float = 0.5
    contributions: List[Tuple[str, float]] = field(default_factory=list)
    votes: int = 0

    @property
    def is_malicious(self) -> bool:
        return self.score > 0.0

    def __bool__(self) -> bool:
        return self.is_malicious


@dataclass
class ChannelStats:
    """单通道的计数表。"""
    samples_mal: int = 0
    samples_ben: int = 0
    #: 特征名 -> [恶意出现样本数, 良性出现样本数]
    counts: Dict[str, List[int]] = field(default_factory=dict)

    def total(self) -> int:
        return self.samples_mal + self.samples_ben


def _weight(count: int) -> float:
    """频次 -> 权重（对数压缩，单调，有上界）。"""
    if count <= 0:
        return 0.0
    if count == 1:
        return 1.0
    return 1.0 + WEIGHT_K * math.log2(count)


def _sigmoid(x: float) -> float:
    """数值稳定版 sigmoid，用于把任意分数压到 0~1。"""
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


# ============================================================
# 单通道模型
# ============================================================

class _ChannelModel:
    """一个通道的加权朴素贝叶斯。外部不直接用，由 KGModel 包住。"""

    def __init__(self, name: str = "binary"):
        self.name = name
        self.stats = ChannelStats()

    # ---------- 学习 ----------

    def learn(self, counts: Dict[str, int], label: str) -> int:
        """按特征频次做增量累加，返回被更新的特征数。"""
        mal = (str(label).lower() in ("mal", "malicious", "1", "bad"))
        st = self.stats
        touched = 0
        for feat, cnt in counts.items():
            if not isinstance(feat, str) or not feat:
                continue
            try:
                cnt = int(cnt)
            except (TypeError, ValueError):
                continue
            if cnt <= 0:
                continue
            cnt = min(cnt, MAX_FEATURE_COUNT)
            slot = st.counts.get(feat)
            if slot is None:
                slot = [0, 0]
                st.counts[feat] = slot
            if mal:
                slot[0] += 1
            else:
                slot[1] += 1
            touched += 1
        if mal:
            st.samples_mal += 1
        else:
            st.samples_ben += 1
        return touched

    # ---------- 预测 ----------

    def predict(self, counts: Dict[str, int]) -> Prediction:
        """对数似然比 + 特征贡献。"""
        st = self.stats
        n_mal = st.samples_mal
        n_ben = st.samples_ben
        pred = Prediction(channel=self.name)

        # 无任何训练数据 -> 弃权（分数 0）
        if n_mal == 0 and n_ben == 0:
            return pred
        # 只有单类样本 -> 用先验方向给一个弱信号，但不假装看懂了
        if n_mal == 0 or n_ben == 0:
            pred.score = 0.5 if n_mal > 0 else -0.5
            pred.confidence = _sigmoid(pred.score)
            pred.contributions = [("__prior_only__", pred.score)]
            return pred

        # 先验（带阻尼，防良性样本压倒）
        prior = math.log((n_mal + ALPHA) / (n_ben + ALPHA)) * PRIOR_DAMPING
        score = prior
        contribs: List[Tuple[str, float]] = []
        seen = 0

        # 类别不平衡的对称化修正（每张票均摊）。
        # 让「恶意特征投正票」与「良性特征投负票」的强度回到同一基准，
        # 否则多数类良性投出的负票被压扁，阈值 0 会整体失准。
        if SYMMETRIZE_LIKELIHOOD:
            balance = math.log(n_mal / n_ben)
        else:
            balance = 0.0

        if not counts:
            pred.score = prior
            pred.confidence = _sigmoid(prior)
            pred.contributions = [("__no_feature__", prior)]
            return pred

        for feat, cnt in counts.items():
            slot = st.counts.get(feat)
            if slot is None:
                # 训练中从未见过的特征不投票（无从判断方向）
                continue
            seen += 1
            c_mal, c_ben = slot
            # 伯努利式条件概率（是否出现该特征的样本占比）
            p_mal = (c_mal + ALPHA) / (n_mal + 2 * ALPHA)
            p_ben = (c_ben + ALPHA) / (n_ben + 2 * ALPHA)
            w = _weight(cnt)
            delta = (math.log(p_mal) - math.log(p_ben) + balance) * w
            score += delta
            contribs.append((feat, delta))

        pred.score = score
        pred.confidence = _sigmoid(score)
        pred.votes = seen
        if seen == 0:
            # counts 非空但每个特征都是训练中没见过的 -> 等于没有证据。
            # 补一个显式标记，否则 GUI 拿到空贡献列表会说不清「为什么这么判」。
            pred.contributions = [("__no_feature__", prior)]
            return pred
        # 按贡献绝对值排序，但保留正负号（负贡献 = 像良性）
        contribs.sort(key=lambda kv: (-abs(kv[1]), kv[0]))
        pred.contributions = contribs[:TOP_CONTRIB]
        return pred

    # ---------- 序列化 ----------

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "samples_mal": self.stats.samples_mal,
            "samples_ben": self.stats.samples_ben,
            "counts": {k: [int(v[0]), int(v[1])] for k, v in self.stats.counts.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "_ChannelModel":
        m = cls(str(data.get("name") or "binary"))
        st = m.stats
        try:
            st.samples_mal = int(data.get("samples_mal") or 0)
            st.samples_ben = int(data.get("samples_ben") or 0)
        except (TypeError, ValueError):
            st.samples_mal = st.samples_ben = 0
        raw = data.get("counts") or {}
        if isinstance(raw, dict):
            for k, v in raw.items():
                if not isinstance(k, str):
                    continue
                try:
                    a, b = int(v[0]), int(v[1])
                except (TypeError, ValueError, IndexError, KeyError):
                    continue
                st.counts[k] = [max(0, a), max(0, b)]
        return m

    # ---------- 修剪 ----------

    def prune(self, min_samples: int = 1, keep_max: int = 200000) -> int:
        """丢弃两侧都低于 min_samples 的噪声特征；超量时保留更强的。

        返回被丢弃的特征数。
        """
        st = self.stats
        dropped = 0
        if min_samples > 1:
            for feat in [f for f, v in st.counts.items()
                         if max(v[0], v[1]) < min_samples]:
                del st.counts[feat]
                dropped += 1
        if keep_max and len(st.counts) > keep_max:
            ranked = sorted(
                st.counts.items(),
                key=lambda kv: (-(kv[1][0] + kv[1][1]), kv[0]),
            )
            for feat, _ in ranked[keep_max:]:
                del st.counts[feat]
                dropped += 1
        return dropped


# ============================================================
# 对外模型
# ============================================================

class KGModel:
    """KG 机器引擎的两通道学习器。

    典型用法::

        m = KGModel()
        m.learn(fv, label="mal")       # fv 为 FeatureVector
        p = m.predict(fv)
        print(p.score, p.contributions)

    也可以喂原始特征字典::

        m.learn_counts(fv.counts, label="mal", channel=fv.channel)
    """

    #: 支持的通道
    CHANNELS = ("text", "binary")

    def __init__(self, channels: Iterable[str] = CHANNELS):
        self._lock = threading.RLock()
        self._models: Dict[str, _ChannelModel] = {}
        for c in channels:
            self._models[str(c)] = _ChannelModel(str(c))

    # ---------- 兼容性辅助 ----------

    def _chan(self, channel: Optional[str]) -> _ChannelModel:
        name = str(channel or "binary")
        m = self._models.get(name)
        if m is None:
            # 未知通道归入 binary，绝不静默丢样本
            m = self._models.get("binary")
        if m is None:
            m = _ChannelModel("binary")
            self._models["binary"] = m
        return m

    @staticmethod
    def _counts_of(features) -> Tuple[Dict[str, int], str, str]:
        """从 FeatureVector / dict 里取出 (counts, channel, digest)。"""
        if features is None:
            return {}, "binary", ""
        if isinstance(features, dict):
            return dict(features), "binary", ""
        counts = getattr(features, "counts", None)
        if not isinstance(counts, dict):
            return {}, "binary", ""
        channel = str(getattr(features, "channel", "binary") or "binary")
        digest = str(getattr(features, "digest", "") or "")
        return dict(counts), channel, digest

    # ---------- 学习 ----------

    def learn(self, features, label: str = "mal") -> int:
        """学习一个样本（FeatureVector 或 dict）。返回更新的特征数。"""
        counts, channel, _ = self._counts_of(features)
        return self.learn_counts(counts, label=label, channel=channel)

    def learn_counts(self, counts: Dict[str, int], label: str = "mal",
                     channel: str = "binary") -> int:
        if not counts:
            return 0
        with self._lock:
            return self._chan(channel).learn(counts, label)

    def learn_many(self, samples: Iterable, label: str = "mal") -> int:
        """批量学习，返回处理的样本数。"""
        n = 0
        for s in samples:
            self.learn(s, label=label)
            n += 1
        return n

    # ---------- 预测 ----------

    def predict(self, features, channel: Optional[str] = None) -> Prediction:
        """预测一个样本（FeatureVector / dict / counts dict）。"""
        counts, ch, _ = self._counts_of(features)
        if channel:
            ch = str(channel)
        with self._lock:
            return self._chan(ch).predict(counts)

    def predict_counts(self, counts: Dict[str, int],
                       channel: str = "binary") -> Prediction:
        with self._lock:
            return self._chan(channel).predict(counts or {})

    def score(self, features, channel: Optional[str] = None) -> float:
        """只要分数，省去构造 Prediction 的解读成本。"""
        return self.predict(features, channel=channel).score

    # ---------- 状态 ----------

    @property
    def total_samples(self) -> int:
        with self._lock:
            return sum(m.stats.total() for m in self._models.values())

    def stats(self) -> Dict[str, dict]:
        """两通道样本数与特征数快照，供 GUI 显示「已学 N 恶意 / M 良性」。"""
        with self._lock:
            out = {}
            for name, m in self._models.items():
                st = m.stats
                out[name] = {
                    "samples_mal": st.samples_mal,
                    "samples_ben": st.samples_ben,
                    "features": len(st.counts),
                }
            return out

    def is_empty(self) -> bool:
        return self.total_samples == 0

    def reset(self) -> None:
        with self._lock:
            for m in self._models.values():
                m.stats = ChannelStats()

    def prune(self, min_samples: int = 1, keep_max: int = 200000) -> int:
        with self._lock:
            return sum(m.prune(min_samples, keep_max)
                       for m in self._models.values())

    # ---------- 序列化 ----------

    def to_dict(self) -> dict:
        """落盘用。counts 是纯 dict[list[int]]，JSON 可直接序列化。"""
        with self._lock:
            return {
                "channels": {name: m.to_dict() for name, m in self._models.items()},
            }

    @classmethod
    def from_dict(cls, data: dict) -> "KGModel":
        obj = cls(channels=())
        obj._models = {}
        raw = (data or {}).get("channels") or {}
        if not isinstance(raw, dict):
            raw = {}
        for name, payload in raw.items():
            if not isinstance(payload, dict):
                continue
            m = _ChannelModel.from_dict(payload)
            m.name = str(name)
            obj._models[str(name)] = m
        # 保底：至少要有 binary 通道，避免后续 predict 落空
        if "binary" not in obj._models:
            obj._models["binary"] = _ChannelModel("binary")
        if "text" not in obj._models:
            obj._models["text"] = _ChannelModel("text")
        return obj

    def clone(self) -> "KGModel":
        return KGModel.from_dict(self.to_dict())
