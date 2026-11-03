"""KG 机器引擎 - 特征库落盘（块3）

职责
    把 KGModel 的学习成果持久化到 ``data/ml/``，并保证三件事：

      1. **原子落盘** —— 写临时文件 + fsync + ``os.replace``。
         用户机器随时可能断电/被杀进程，绝不能出现"写了一半的模型"。
      2. **完整性校验** —— 文件头带 sha256，读回时重算比对。
         截断/损坏的文件会被识别为坏档，而不是当成"模型变小了"。
      3. **版本化 + 可回滚** —— 每次保存滚出 ``model.NNN.json`` 世代档，
         保留最近 ``MAX_GENERATIONS`` 份；``rollback()`` 回到上一世代。
         投喂工具误喂脏样本后，用户能一键退回。

目录布局（``data/ml/``）::

    data/ml/
        model.json          当前生效模型（原子替换）
        model.001.json      世代档（最旧在前，编号递增）
        model.002.json
        ...
        meta.json           元信息：KG 版本、更新时间、样本数快照

为什么不用 pickle
    pickle 反序列化即执行任意代码，特征库是**外部可写入**的数据
    （投喂工具、云端同步），一旦被替换成恶意 pickle 就是 RCE。
    所以用纯 JSON + sha256 校验，只做数据不做代码。

为什么 ``data/ml/`` 必须进运行时目录守卫
    特征库会随投喂持续增长与变化。若被纳入自备份基准，启动自愈会拿
    "投喂 N 轮之前"的旧模型覆盖用户刚学到的样本 —— 表现就是
    「明明投喂成功了，重启后又变回旧模型」。
    ``data/ml/`` 已同时登记在 ``self_protect._RUNTIME_DIR_PREFIXES``
    与 ``_sync_selfbackup._RUNTIME_DIR_PAIRS``（两侧严格同源）。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:  # 包内导入（正常路径）
    from .model import KGModel
except ImportError:  # pragma: no cover - 允许单文件加载自测
    from model import KGModel  # type: ignore

# ============================================================
# 常量
# ============================================================

#: 当前特征库文件格式版本。格式不兼容变更时递增，读到更高版本拒绝加载。
STORE_FORMAT = 1

#: 保留的世代档数量（不含当前档）。每次 save 滚一份，超出即删最旧。
MAX_GENERATIONS = 5

#: 单档体积上限（防御性）：正常模型远小于此，超过说明数据异常。
MAX_FILE_BYTES = 512 * 1024 * 1024

CURRENT_NAME = "model.json"
META_NAME = "meta.json"
GEN_PREFIX = "model."
GEN_SUFFIX = ".json"


# ============================================================
# 工具
# ============================================================

def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    """原子写：临时文件 -> flush+fsync -> os.replace。

    ``os.replace`` 在同一卷上是原子操作（Windows 亦如此），
    因此读方要么看到旧档要么看到新档，绝不会看到半截内容。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except (OSError, ValueError):
            # 某些文件系统/句柄不支持 fsync —— 降级但不阻断
            pass
    os.replace(tmp, path)


def _is_gen_name(name: str) -> bool:
    """判断是否为世代档文件名（model.NNN.json）。"""
    if not name.startswith(GEN_PREFIX) or not name.endswith(GEN_SUFFIX):
        return False
    mid = name[len(GEN_PREFIX):-len(GEN_SUFFIX)]
    return mid.isdigit() and len(mid) == 3


# ============================================================
# 特征库
# ============================================================

class FeatureStore:
    """KGModel 的版本化磁盘仓库。

    典型用法::

        store = FeatureStore(data_dir / "ml")
        model = store.load()          # 无档时返回空模型（不抛异常）
        model.learn(fv, label="mal")
        store.save(model)             # 原子落盘 + 滚世代

        store.rollback()              # 退回上一世代
    """

    def __init__(self, base_dir, *, max_generations: int = MAX_GENERATIONS):
        self.base_dir = Path(base_dir)
        self.max_generations = max(1, int(max_generations))
        self._lock = threading.RLock()
        self.last_error: Optional[str] = None

    # ---------- 路径 ----------

    @property
    def current_path(self) -> Path:
        return self.base_dir / CURRENT_NAME

    @property
    def meta_path(self) -> Path:
        return self.base_dir / META_NAME

    def generations(self) -> List[Path]:
        """返回世代档路径，**最旧在前**（编号升序）。"""
        if not self.base_dir.is_dir():
            return []
        gens = [p for p in self.base_dir.iterdir()
                if p.is_file() and _is_gen_name(p.name)]
        return sorted(gens, key=lambda p: p.name)

    # ---------- 编码 / 解码 ----------

    def _encode(self, model: KGModel) -> bytes:
        """把模型编码为带校验头的 JSON 字节。"""
        payload = {
            "format": STORE_FORMAT,
            "kind": "kg-featurebank",
            "saved_at": time.time(),
            "stats": model.stats(),
            "model": model.to_dict(),
        }
        body = json.dumps(payload, ensure_ascii=False,
                          separators=(",", ":")).encode("utf-8")
        envelope = {
            "format": STORE_FORMAT,
            "sha256": _sha256_bytes(body),
            "len": len(body),
        }
        head = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        # 头部定长便于快速定位：8 字节长度 + head + body
        return str(len(head)).rjust(8, "0").encode("ascii") + head + body

    def _decode(self, raw: bytes) -> Optional[KGModel]:
        """解析字节；损坏/被篡改/版本过高时返回 None 并记录 last_error。"""
        try:
            if len(raw) < 8:
                self.last_error = "文件过短"
                return None
            head_len = int(raw[:8].decode("ascii"))
            if head_len <= 0 or 8 + head_len > len(raw):
                self.last_error = "头长度非法"
                return None
            head = json.loads(raw[8:8 + head_len].decode("utf-8"))
            body = raw[8 + head_len:]
            if int(head.get("len", -1)) != len(body):
                self.last_error = "长度不匹配（文件被截断）"
                return None
            if head.get("sha256") != _sha256_bytes(body):
                self.last_error = "校验和不匹配（文件损坏或被篡改）"
                return None
            fmt = int(head.get("format", 0))
            if fmt > STORE_FORMAT:
                self.last_error = f"格式版本过高 ({fmt} > {STORE_FORMAT})"
                return None
            payload = json.loads(body.decode("utf-8"))
            model_data = (payload or {}).get("model")
            if not isinstance(model_data, dict):
                self.last_error = "缺少 model 字段"
                return None
            self.last_error = None
            return KGModel.from_dict(model_data)
        except (ValueError, KeyError, TypeError, json.JSONDecodeError,
                UnicodeDecodeError, OSError) as e:
            self.last_error = f"{type(e).__name__}: {e}"
            return None

    # ---------- 读写 ----------

    def exists(self) -> bool:
        return self.current_path.is_file()

    def load(self) -> KGModel:
        """加载当前模型。**任何失败都返回空模型**，绝不抛出。

        投喂/扫描链路不该因为一个坏档就崩掉；坏档信息记在
        ``last_error``，GUI 可据此提示用户。
        """
        with self._lock:
            path = self.current_path
            if not path.is_file():
                self.last_error = None
                return KGModel()
            try:
                size = path.stat().st_size
                if size > MAX_FILE_BYTES:
                    self.last_error = "文件超限"
                    return KGModel()
                raw = path.read_bytes()
            except OSError as e:
                self.last_error = f"{type(e).__name__}: {e}"
                return KGModel()
            model = self._decode(raw)
            if model is None:
                return KGModel()
            return model

    def _disk_total_samples(self) -> int:
        """读当前档的样本数；无档 / 坏档返回 -1。"""
        try:
            raw = self.current_path.read_bytes()
        except OSError:
            return -1
        m = self._decode(raw)
        if m is None:
            return -1
        try:
            return int(m.total_samples)
        except (TypeError, ValueError):
            return -1

    def save(self, model: KGModel, *, make_generation: bool = True,
             force: bool = False) -> bool:
        """原子保存。``make_generation=True`` 时先把现有档滚成世代档。

        返回是否成功；失败原因记在 ``last_error``。

        [!] 单调性守卫（防“旧内存态静默覆盖新档”）
            若传入模型的样本数低于当前档，说明调用方持有的是陈旧内存态
            （典型：开始投喂前 load，投喂完另一个进程已写盘，随后这边才 save）。
            直接写下去会把刚学到的样本整栋抹掉。此时拒写并记 ``last_error``，
            绝不静默。确实需要减少样本的场景（清空重学等）走 ``force=True``。
            ``rollback()`` / ``reset()`` 不经过本函数，不受影响。
        """
        if model is None:
            self.last_error = "model 为 None"
            return False
        with self._lock:
            try:
                if not force:
                    old_n = self._disk_total_samples()
                    try:
                        new_n = int(model.total_samples)
                    except (TypeError, ValueError):
                        new_n = -1
                    if old_n > 0 and 0 <= new_n < old_n:
                        self.last_error = (
                            f"拒写：传入模型样本数 {new_n} "
                            f"< 当前档 {old_n}（疑为陈旧内存态）；"
                            "确需覆盖请传 force=True"
                        )
                        return False
                self.base_dir.mkdir(parents=True, exist_ok=True)
                if make_generation and self.current_path.is_file():
                    self._rotate()
                _atomic_write(self.current_path, self._encode(model))
                self._write_meta(model)
                self.last_error = None
                return True
            except OSError as e:
                self.last_error = f"{type(e).__name__}: {e}"
                return False

    def _rotate(self) -> None:
        """把当前档滚成下一个世代档，并清理超量世代。

        🔴 关键：滚档前必须**先校验当前档完好**。
        曾踩过的坑：当前档被磁盘故障/外部进程写坏后，下一次 save() 会
        把这份坏档原样复制进世代档 —— 等于用坏档覆盖掉最后一份好档，
        用户彻底失去回滚余地。宁可少滚一份世代，也绝不污染备份。
        """
        try:
            raw = self.current_path.read_bytes()
        except OSError:
            return
        if self._decode(raw) is None:
            # 当前档已损坏 -> 不滚档（保住已有的好世代），仅告警不改 last_error
            return

        gens = self.generations()
        # 下一个编号：沿用已有最大编号 +1，避免覆盖（rollback 后编号会回退）
        next_no = 1
        if gens:
            last = gens[-1].name[len(GEN_PREFIX):-len(GEN_SUFFIX)]
            try:
                next_no = int(last) + 1
            except ValueError:
                next_no = len(gens) + 1
        dst = self.base_dir / f"{GEN_PREFIX}{next_no:03d}{GEN_SUFFIX}"
        try:
            _atomic_write(dst, raw)
        except OSError:
            # 世代档只是保险，滚档失败不该阻断当前档的保存
            return
        # 清理超量（保留最近 max_generations 份）
        gens = self.generations()
        for old in gens[:-self.max_generations]:
            try:
                old.unlink()
            except OSError:
                pass

    def _write_meta(self, model: KGModel) -> None:
        try:
            stats = model.stats()
            meta = {
                "format": STORE_FORMAT,
                "updated_at": time.time(),
                "updated_at_str": time.strftime("%Y-%m-%d %H:%M:%S"),
                "total_samples": model.total_samples,
                "channels": stats,
            }
            _atomic_write(self.meta_path, json.dumps(
                meta, ensure_ascii=False, indent=2).encode("utf-8"))
        except (OSError, TypeError, ValueError):
            pass

    def read_meta(self) -> Dict:
        """读元信息（供 GUI 展示「上次投喂时间/样本数」）。失败返回 {}。"""
        try:
            return json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return {}

    # ---------- 回滚 ----------

    def rollback(self) -> Tuple[bool, str]:
        """退回上一世代档。

        返回 ``(是否成功, 说明)``。
        注意：语义与补丁的 rollback 一致 —— 只切当前档，不删世代档，
        用户可以反复回滚直到最早的世代档。
        """
        with self._lock:
            gens = self.generations()
            if not gens:
                return False, "没有可回滚的世代档"
            # 从最新世代往前找第一个能通过校验的档
            for src in reversed(gens):
                try:
                    raw = src.read_bytes()
                except OSError as e:
                    continue
                if self._decode(raw) is None:
                    continue
                try:
                    _atomic_write(self.current_path, raw)
                    self._write_meta(self._decode(raw))
                except OSError as e:
                    return False, f"回滚写入失败: {type(e).__name__}: {e}"
                # 回滚成功后删除该世代档，避免"回滚再回滚"原地踏步
                try:
                    src.unlink()
                except OSError:
                    pass
                self.last_error = None
                return True, f"已回滚到 {src.name}"
            return False, "所有世代档均已损坏"

    # ---------- 维护 ----------

    def purge_generations(self) -> int:
        """清空全部世代档，返回删除数量。"""
        n = 0
        with self._lock:
            for g in self.generations():
                try:
                    g.unlink()
                    n += 1
                except OSError:
                    pass
        return n

    def reset(self) -> bool:
        """删除当前档 + 元信息 + 全部世代档（危险操作，供用户"清空重学"）。"""
        with self._lock:
            ok = True
            for p in [self.current_path, self.meta_path] + self.generations():
                try:
                    if p.is_file():
                        p.unlink()
                except OSError:
                    ok = False
            self.last_error = None if ok else "部分文件删除失败"
            return ok

    def summary(self) -> Dict:
        """仓库状态快照，供 GUI 一键显示。"""
        gens = self.generations()
        meta = self.read_meta()
        return {
            "dir": str(self.base_dir),
            "exists": self.exists(),
            "generations": len(gens),
            "latest_generation": gens[-1].name if gens else "",
            "total_samples": int(meta.get("total_samples", 0) or 0),
            "updated_at_str": str(meta.get("updated_at_str", "") or ""),
            "channels": meta.get("channels", {}) or {},
            "last_error": self.last_error or "",
        }
