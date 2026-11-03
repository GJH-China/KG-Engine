"""
KG 机器引擎 - 机器学习引擎（凯德荣自研）

KG = KaeDeRonm GuiZhou 的首字母缩写，指 KDR 自己的机器学习引擎，
不是 Knowledge Graph。

设计三原则
    1. 纯标准库：不引入 numpy / sklearn，保持安装包体积与依赖可控
    2. 增量学习：投喂即更新计数，不重训、不落中间大文件
    3. 可解释：每次判定能说清"是哪几个特征投的票"

版本节奏
    3.9  特征库 + 学习器 + 喂料工具 + 良性基线采集（本模块），引擎不接入扫描
    4.0  KG 机器引擎接入 third_party_lookup 钩子，进 SCAN_ENGINES（已发布）
"""
from __future__ import annotations

from .features import FeatureVector, extract_features, extract_from_path
from .model import KGModel
from .store import FeatureStore
from .baseline import (
    BaselineResult,
    BaselineSource,
    collect_benign_samples,
    default_sources,
    feed_baseline,
    stdlib_sources,
)

__all__ = [
    "FeatureVector",
    "extract_features",
    "extract_from_path",
    "KGModel",
    "FeatureStore",
    "BaselineResult",
    "BaselineSource",
    "collect_benign_samples",
    "default_sources",
    "stdlib_sources",
    "feed_baseline",
]

KG_VERSION = "4.0"
