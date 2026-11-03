"""
KG 机器引擎 - 喂料器（投喂链路）

把「一堆文件 / 压缩包」变成「模型里多出来的知识」。这条链路只有四步：

    文件 -> iter_member_vectors -> KGModel.learn -> FeatureStore.save

一个压缩包会被拆成「**每个成员一个样本**」：
整包合并成一个向量，会让「100 成员的包」与
「1 成员的包」在朴素贝叶斯里投出数量级不同的票
（每个不同特征一票），等于同一个包被反复计票。

设计约束
    1. 纯标准库：与 ml 包其余模块一致，不引入第三方依赖
    2. 绝不抛出：投喂工具面对的是用户随手拖进来的东西，
       一个坏文件不该让整批投喂崩掉 —— 失败逐个记进 FeedResult.errors
    3. dry_run 真不落盘：预演就只统计，不碰 data/ml/

版本节奏
    3.9  本模块随 ml 包发布，仅供投喂工具 / GUI 使用，不接扫描
    4.0  KG 引擎接入 third_party_lookup
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from .features import (
    ARCHIVE_EXTS,
    BINARY_EXTS,
    SOURCE_EXTS,
    FeatureVector,
    extract_from_bytes,
    extract_from_path,
    iter_member_vectors,
)
from .model import KGModel
from .store import FeatureStore

# 单次投喂最多处理的样本数（防止用户误投整个 C 盘）
MAX_SAMPLES = 20000
# 深度/成员/向量上限已统一收归到 features.py（MAX_DEPTH /
# HARD_DEPTH_CEILING / MAX_MEMBERS / MAX_MEMBER_VECTORS），本模块不再持有
# 独立深度常量（旧 MAX_UNPACK_DEPTH 从未被任何代码引用，已删）。

# 可投喂的文件类型：源码类 + 压缩包类 + 二进制可执行类
FEEDABLE_EXTS = tuple(sorted(set(SOURCE_EXTS) | set(ARCHIVE_EXTS)
                             | set(BINARY_EXTS)))


@dataclass
class FeedItem:
    """单个样本的投喂结果。

    压缩包类目标会被拆成多个成员样本，此时 ``path`` 仍为根目标路径，
    ``name`` 为成员名。
    """
    path: str
    name: str
    channel: str
    features: int          # 该样本贡献的特征维度数
    learned: int           # 实际更新的特征数（0 表示空向量/被跳过）
    score: float           # 投喂前的判定分（用于观察知识增量）
    error: str = ""
    member: bool = False   # True 表示来自压缩包成员（一成员一样本）
    source: str = ""       # 成员所属的根目标文件名


@dataclass
class FeedResult:
    """一次投喂的汇总。"""
    label: str = "mal"
    total: int = 0            # 收到的样本总数
    learned: int = 0          # 成功学习的样本数
    skipped: int = 0          # 空向量 / 类型不支持而跳过
    features: int = 0         # 累计更新的特征数
    channels: dict = field(default_factory=dict)   # {channel: 样本数}
    items: List[FeedItem] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)
    saved: bool = False       # 是否落盘成功
    dry_run: bool = False
    member_samples: int = 0   # 其中来自压缩包成员（一成员一样本）的数量
    score_before: float = 0.0  # 批次前，用本批样本打的平均分
    score_after: float = 0.0   # 批次后，同样本再打一次
    # 特征库维度前后对比 —— 单类语料下唯一真实可见的知识增量
    bank_before: int = 0
    bank_after: int = 0
    warning: str = ""

    @property
    def ok(self) -> bool:
        return self.learned > 0 and (self.dry_run or self.saved)

    @property
    def bank_growth(self) -> int:
        """特征库维度净增长。"""
        return max(0, self.bank_after - self.bank_before)

    def summary_lines(self) -> List[str]:
        """给 GUI / CLI 用的多行摘要。"""
        ch = ", ".join(f"{k}:{v}" for k, v in sorted(self.channels.items()))
        lines = [
            f"目标 {self.total} 个，学习成功 {self.learned}，跳过 {self.skipped}"
            + (f"（含压缩包成员 {self.member_samples} 个）"
               if self.member_samples else ""),
            f"新增/更新特征 {self.features} 项" + (f"（{ch}）" if ch else ""),
            f"特征库维度 {self.bank_before} -> {self.bank_after}"
            f"（+{self.bank_growth}）",
            f"落盘：{'预演（未写入）' if self.dry_run else ('成功' if self.saved else '失败')}",
        ]
        if self.warning:
            lines.append(f"提示：{self.warning}")
        if self.errors:
            lines.append(f"失败 {len(self.errors)} 个（前 3 条）：")
            for name, err in self.errors[:3]:
                lines.append(f"  · {name}: {err}")
        return lines


def _bank_dims(model: KGModel) -> int:
    """模型当前的特征库总维度（两通道去重后的特征名个数）。"""
    try:
        total = 0
        for st in model.stats().values():
            total += int(st.get("features", 0) or 0)
        return total
    except Exception:
        return 0


def _single_class_hint(model: KGModel, label: str) -> str:
    """纯单类语料时给出引导 —— 贝叶斯在只有一类样本时无法计算似然比，
    模型会保守地恒返回先验分，用户看不到任何区分效果。这不是故障，
    但必须说清楚，否则会被当成"工具坏了"。"""
    try:
        st = model.stats()
        n_mal = sum(int(s.get("samples_mal", 0) or 0) for s in st.values())
        n_ben = sum(int(s.get("samples_ben", 0) or 0) for s in st.values())
    except Exception:
        return ""
    if n_mal > 0 and n_ben == 0:
        return ("当前只学到恶意样本，引擎尚无法作出有效区分"
                "（贝叶斯需要正反两类样本才能算似然比）。"
                "请补充良性样本基线后再观察判定效果。")
    if n_ben > 0 and n_mal == 0:
        return ("当前只学到良性样本，引擎尚无法作出有效区分。"
                "请补充恶意样本后再观察判定效果。")
    return ""


def is_feedable(path: Path, *, enabled: bool = True) -> bool:
    """扩展名是否属于可投喂类型。

    ``enabled`` 为 KG 能力门控位（P 版专属）。默认 True 以保持既有调用
    完全兼容；GUI / 编排层传 ``edition.kg_enabled(ctx)`` 即可在 F 态
    直接判定为不可投喂。**本函数不做任何 ctx 访问**，避免 ml 层反向
    依赖 services / gui。
    """
    if not enabled:
        return False
    return Path(path).suffix.lower() in FEEDABLE_EXTS


def collect_files(targets: Iterable, *, recursive: bool = True,
                  max_samples: int = MAX_SAMPLES) -> Tuple[List[Path], List[Tuple[str, str]]]:
    """把用户给的一堆「文件 / 目录」展开成待投喂文件列表。

    目录会按可投喂扩展名过滤后递归收集；返回 (files, errors)。
    """
    files: List[Path] = []
    errors: List[Tuple[str, str]] = []

    def _add(p: Path) -> None:
        if len(files) >= max_samples:
            return
        if p.is_file():
            files.append(p)

    for t in targets:
        try:
            p = Path(t)
        except (TypeError, ValueError) as e:
            errors.append((str(t), f"路径非法: {type(e).__name__}"))
            continue
        try:
            if p.is_dir():
                if recursive:
                    for sub in sorted(p.rglob("*")):
                        if len(files) >= max_samples:
                            break
                        try:
                            if sub.is_file() and is_feedable(sub):
                                _add(sub)
                        except OSError:
                            continue
                else:
                    for sub in sorted(p.iterdir()):
                        try:
                            if sub.is_file() and is_feedable(sub):
                                _add(sub)
                        except OSError:
                            continue
            elif p.is_file():
                _add(p)
            else:
                errors.append((str(p), "路径不存在"))
        except OSError as e:
            errors.append((str(t), f"{type(e).__name__}: {e}"))
    return files, errors


def feed_targets(targets: Sequence, *, data_dir, label: str = "mal",
                 dry_run: bool = False, max_samples: int = MAX_SAMPLES,
                 store: Optional[FeatureStore] = None,
                 model: Optional[KGModel] = None,
                 recursive: bool = True) -> FeedResult:
    """投喂一批目标（文件 / 目录）。

    参数
        targets    : 文件路径、目录路径的序列（str 或 Path 均可）
        data_dir   : 数据根目录；特征库落在 ``<data_dir>/ml``
        label      : "mal" 学习为恶意，"ben" 学习为良性
        dry_run    : True 时只统计不落盘
        store      : 复用已有 FeatureStore（GUI 传入以免反复建实例）
        model      : 复用已加载模型；为 None 时从 store 读

    返回 FeedResult；**不抛异常**。
    """
    res = FeedResult(label=label, dry_run=bool(dry_run))

    # 1) 展开目标
    files, ctl_errors = collect_files(targets, recursive=recursive,
                                      max_samples=max_samples)
    res.errors.extend(ctl_errors)
    res.total = len(files)

    if not files:
        return res

    # 2) 拿模型（复用 or 加载）
    if store is None:
        base = Path(data_dir) / "ml"
        store = FeatureStore(base)
    if model is None:
        model = store.load()
    res.bank_before = _bank_dims(model)

    # 3) 逐样本：抽特征 -> 学习
    #
    # 关键：压缩包先被拆成**逐成员向量**（一成员 = 一样本）。
    # 整包合并成一个向量，会让「100 成员的包」投出比「1 成员的包」
    # 多一个数量级的票（贝叶斯每个不同特征一票），等于把包重复计票。
    score_before_sum = 0.0
    score_n = 0
    for p in files:
        try:
            raw = Path(p).read_bytes()
        except (OSError, ValueError):
            res.errors.append((p.name, "读取失败"))
            continue

        try:
            vecs = iter_member_vectors(raw, name=p.name)
        except Exception as e:               # 兜底：提取器理论上不抛
            res.errors.append((p.name, f"{type(e).__name__}: {e}"))
            continue

        if not vecs:
            res.skipped += 1
            continue

        # 多个向量 = 压缩包拆出的成员；单个且非包 = 普通文件
        is_multi = len(vecs) > 1
        for fv in vecs:
            dim = len(fv)
            if dim <= 0:
                res.skipped += 1
                continue

            ch = fv.channel or "binary"
            # 投喂前先看模型当前怎么看它（用于观察增量，纯诊断）
            try:
                sc = model.score(fv)
            except Exception:
                sc = 0.0
            score_before_sum += sc
            score_n += 1

            n = model.learn(fv, label=label)
            res.features += max(0, n)
            res.learned += 1
            if is_multi:
                res.member_samples += 1
            res.channels[ch] = res.channels.get(ch, 0) + 1
            res.items.append(FeedItem(
                path=str(p),
                name=(fv.labels.get("name") or p.name) if is_multi else p.name,
                channel=ch, features=dim, learned=n, score=round(sc, 4),
                member=is_multi, source=p.name if is_multi else ""))

    res.score_before = round(score_before_sum / score_n, 4) if score_n else 0.0
    res.bank_after = _bank_dims(model)
    res.warning = _single_class_hint(model, label)

    # 4) 落盘（dry_run 跳过）
    if not dry_run and res.learned > 0:
        try:
            res.saved = bool(store.save(model))
            if not res.saved:
                res.errors.append(("<store>", store.last_error or "保存失败"))
        except Exception as e:
            res.errors.append(("<store>", f"{type(e).__name__}: {e}"))

    # 5) 投喂后，用同一批样本再打一次分（观察知识增量）
    if res.learned > 0:
        after_sum = 0.0
        after_n = 0
        for p in files[:200]:                # 采样上限，避免大目录拖慢 UI
            try:
                raw = Path(p).read_bytes()
                for fv in iter_member_vectors(raw, name=p.name):
                    if len(fv) <= 0:
                        continue
                    after_sum += model.score(fv)
                    after_n += 1
            except Exception:
                continue
        res.score_after = round(after_sum / after_n, 4) if after_n else 0.0

    return res


def feed_path(data_dir, path, **kw) -> FeedResult:
    """单路径投喂的便捷入口。"""
    return feed_targets([path], data_dir=data_dir, **kw)
