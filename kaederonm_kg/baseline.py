"""KG 机器引擎 - 良性基线采集器（块6）

为什么需要这个模块
    贝叶斯判定的是**似然比** ``log P(x|恶意) - log P(x|良性)``。只投喂恶意
    样本时模型只能退化成"恒返回先验分"，用户看不到任何区分能力 ——
    这不是故障，而是数学上的必然（缺一类就无从比较）。

    所以「建立良性基线」是让 KG 引擎真正可用的一步。但让用户手动去挑
    几百个"干净文件"既不现实也不可靠：用户会挑到可疑文件、会把恶意样本
    当良性喂进去，直接污染负样本语料。

    本模块把这件事工程化：从**可信系统目录**里只读采集良性样本，
    采集过程本身带闸门、可解释、可复现。

安全设计（红线）
    1. **只读，绝不执行**。全程只做 ``stat`` / ``read_bytes``，
       不对候选做任何 ``exec`` / ``Popen`` / ``ShellExecute``。
    2. **白名单根约束**。每个候选路径必须通过
       ``utils.pathsafe.is_within()`` 落在某个可信根之内，
       防止 ``..`` 穿越或符号链接把采集范围带出系统目录。
    3. **拒绝过宽前缀**。盘根 / ``C:\\Users`` / ``C:\\Windows`` 整体这类
       过宽根一律不采（既无意义又会把用户数据卷进来）。
    4. **跳过隐私/临时区**。Temp / Downloads / 用户文档 / 回收站 /
       AppData 一律排除 —— 良性基线不该包含用户私人数据。
    5. **限量 + 确定性排序**。排序后取前 N 个，保证同一台机器多次采集
       结果一致，便于复现与测试。

版本节奏
    3.9  本模块随 ml 包发布，仅供投喂工具 / GUI 使用，不接扫描
    4.0  KG 引擎接入 third_party_lookup
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .feed import FEEDABLE_EXTS
# 开源版把 pathsafe 收进来作为 _pathsafe，去掉对主项目 utils 包的依赖，
# 保证本包可以单独 pip install / 复制即用。
from ._pathsafe import is_within

# ============================================================
# 常量
# ============================================================

#: 单次基线采集默认上限（样本数）。太大既慢又会把语料稀释成噪声。
DEFAULT_MAX = 400

#: 每个来源目录内部最多扫这么多候选就收手，避免在巨型目录上磨时间。
DEFAULT_PER_DIR_CAP = 3000

#: 采集时只认这些扩展名 —— 与可投喂集合取交集里更"像程序"的部分。
#: 排除压缩包：压缩包内部成员特征与单文件特征不同源，基线要干净。
BASELINE_EXTS = tuple(sorted(
    e for e in FEEDABLE_EXTS
    if e not in (".zip", ".jar", ".war", ".apk", ".whl", ".egg", ".tar",
                 ".gz", ".7z", ".rar", ".cab", ".msi", ".iso")
))

#: 与机器相关、逐台差异大或不适合当基线样本的内置排除（按文件名小写）。
_EXCLUDE_STEMS = frozenset({
    # 日志/状态类：内容随使用变化，不是稳定的"程序形态"
    "ntuser.dat", "usrclass.dat", "bootstat.dat", "perfmon.ini",
})

#: 文件名前缀（小写）命中即跳过。
#: ``api-ms-win-*`` / ``ext-ms-win-*`` 是 Windows API Set 转发桩，
#: 成百上千个文件、每个只有几百字节且内容高度同质 —— 全收进来会把
#: binary 通道的语料稀释成噪声（同一组特征重复上千次）。整类跳过。
_EXCLUDE_PREFIXES = ("api-ms-win-", "ext-ms-win-")

#: 目录名（小写）命中即整棵跳过 —— 隐私 / 临时 / 用户数据区。
EXCLUDE_DIR_NAMES = frozenset({
    "temp", "tmp", "cache", "caches", "logs", "log", "crashdumps",
    "downloads", "desktop", "documents", "pictures", "videos", "music",
    "onedrive", "appdata", "recycle.bin", "$recycle.bin", "recovery",
    "system volume information", "windows.old", "quarantine",
    "node_modules", "__pycache__", ".git", ".svn", ".venv", "venv",
    "site-packages.bak", "backup", "备份",
})


# ============================================================
# 数据结构
# ============================================================

@dataclass
class BaselineSource:
    """一个候选来源目录及其采集结果。"""
    path: str
    accepted: int = 0
    scanned: int = 0
    pruned: int = 0              # 被剪掉的排除子树个数（隐私/临时区）
    visited: bool = False        # 是否被遍历过（供上层区分「跳过」与「没排到」）
    skipped_wide: bool = False   # 根过宽而被拒
    missing: bool = False        # 目录不存在


@dataclass
class BaselineResult:
    """一次基线采集的汇总。"""
    candidates: List[Path] = field(default_factory=list)
    sources: List[BaselineSource] = field(default_factory=list)
    skipped: Dict[str, int] = field(default_factory=dict)   # 原因 -> 次数
    max_samples: int = DEFAULT_MAX
    truncated: bool = False       # 是否因为达到上限而截断

    @property
    def total(self) -> int:
        return len(self.candidates)

    @property
    def pruned_dirs(self) -> int:
        """被整棵剪掉的隐私/临时目录数。"""
        return sum(int(s.pruned) for s in self.sources)

    def note_skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1

    def summary_lines(self) -> List[str]:
        lines = ["候选良性样本 %d 个（上限 %d）" % (self.total, self.max_samples)]
        for s in self.sources:
            if s.missing:
                lines.append("  · %s：不存在，跳过" % s.path)
            elif s.skipped_wide:
                lines.append("  · %s：根过宽，已拒绝" % s.path)
            else:
                extra = ("，排除隐私/临时目录 %d 个" % s.pruned) if s.pruned else ""
                lines.append("  · %s：扫描 %d，采用 %d%s"
                             % (s.path, s.scanned, s.accepted, extra))
        if self.pruned_dirs:
            lines.append("已整棵跳过隐私/临时目录 %d 个（temp/下载/AppData 等）"
                         % self.pruned_dirs)
        if self.skipped:
            top = sorted(self.skipped.items(), key=lambda kv: -kv[1])[:6]
            lines.append("跳过原因：" +
                         "，".join("%s ×%d" % (k, v) for k, v in top))
        if self.truncated:
            lines.append("已达到采集上限，存在未收集的候选")
        return lines


# ============================================================
# 默认来源
# ============================================================

def default_sources() -> List[Path]:
    """本机默认可信来源目录（只读）。

    Windows 上取系统目录与常见厂商目录；非 Windows 取 /usr/bin 等。
    返回的目录**未必都存在**，调用方按需过滤。
    """
    if os.name != "nt":
        return [Path(p) for p in ("/usr/bin", "/usr/lib/python3", "/bin")]

    # 顺序即优先级：先 OS 自有二进制，再系统级共享组件。
    # 采集上限是硬约束、先到先得 —— 必须把「最像干净系统程序」的目录
    # 排在前面，否则第三方目录会把配额吃光（曾踩：Program Files 按
    # 字典序排在 Windows 之前，30 个配额全被第三方 AV 的 DLL 占满）。
    out: List[Path] = []
    win = os.environ.get("SystemRoot") or r"C:\Windows"
    sys32 = Path(win) / "System32"
    out.append(sys32)
    out.append(Path(win) / "SysWOW64")
    # System32 下的稳定子目录（不含驱动/配置目录）
    for sub in ("WindowsPowerShell", "wbem"):
        out.append(sys32 / sub)
    # 系统自带、通常不含第三方安装物的目录
    out.append(Path(r"C:\Program Files\Windows NT"))
    out.append(Path(r"C:\Program Files\Windows Defender"))
    out.append(Path(r"C:\Program Files\Internet Explorer"))
    return out


def stdlib_sources() -> List[Path]:
    """Python 标准库目录 —— 大批真实、无恶意的 .py 语料。"""
    out: List[Path] = []
    try:
        import sysconfig
        for key in ("stdlib", "platstdlib"):
            d = sysconfig.get_paths().get(key)
            if d:
                out.append(Path(d))
    except Exception:
        pass
    try:
        import sys
        if sys.prefix:
            out.append(Path(sys.prefix) / "Lib")
    except Exception:
        pass
    # 去重保序
    seen = set()
    uniq: List[Path] = []
    for p in out:
        k = str(p).lower()
        if k not in seen:
            seen.add(k)
            uniq.append(p)
    return uniq


def _own_project_roots() -> List[Path]:
    """本仓库自身的根目录。

    红线：良性基线**绝不能包含正在开发的项目自身文件**。
    否则我们会把"自己写的代码"当成"干净样本"喂进去 —— 一是语义错误
    （自己写的东西不代表系统常态），二是把 venv 里上千个第三方文件
    卷进语料，把配额吃光（曾踩：.venv\\Lib 抢走了 binary 配额，
    System32 一个样本都没收到）。
    """
    out: List[Path] = []
    try:
        # kaederonm/ml/baseline.py -> parents[2] = 仓库根
        root = Path(__file__).resolve().parents[2]
        out.append(root)
        out.append(root / ".venv")
    except Exception:
        pass
    return out


def _is_own_project(p: Path, own: Sequence[Path]) -> bool:
    for r in own:
        try:
            if is_within(p, r):
                return True
        except Exception:
            continue
    return False


def _wide_root(p: Path) -> bool:
    """根是否过宽（盘根 / 系统根 / 用户根）—— 过宽一律不采。

    过宽根有两个坏处：① 会把用户私人数据卷进语料；② 遍历代价不可控。
    """
    s = str(p).strip().rstrip("\\/")
    if not s:
        return True
    # 盘根：C:  C:\  D: ...
    if len(s) == 2 and s[1] == ":":
        return True
    low = s.lower()
    for bad in (r"c:\users", r"c:\windows", r"c:\program files",
                r"c:\program files (x86)", "/", "/usr", "/home", "/etc"):
        if low == bad:
            return True
    return False


def _skip_dir(name: str) -> bool:
    return name.strip().lower() in EXCLUDE_DIR_NAMES


def _in_excluded_dir(path: Path, roots: Sequence[Path]) -> bool:
    """路径中是否出现了被排除的目录名（相对任一来源根）。"""
    for r in roots:
        try:
            rel = path.relative_to(r)
        except ValueError:
            continue
        for part in rel.parts[:-1]:
            if _skip_dir(part):
                return True
    return False


# ============================================================
# 采集
# ============================================================

def collect_benign_samples(
    sources: Optional[Iterable] = None,
    *,
    max_samples: int = DEFAULT_MAX,
    per_dir_cap: int = DEFAULT_PER_DIR_CAP,
    exts: Sequence[str] = BASELINE_EXTS,
) -> BaselineResult:
    """从可信目录只读采集良性样本路径。

    参数
        sources    : 候选来源目录；None 时用 ``default_sources() + stdlib_sources()``
        max_samples: 采集上限
        per_dir_cap: 单目录候选扫描上限
        exts       : 允许的扩展名（小写）

    返回 BaselineResult；**不抛异常**，也不执行任何候选文件。

    实现要点
        · 每个候选过 ``is_within(cand, src)`` 闸门（防 ``..`` 穿越与软链逃逸）
        · 排除目录名命中即整棵子树跳过（隐私/临时区）
        · 排序遍历 + 排序输出 => 结果确定，可复现
    """
    res = BaselineResult(max_samples=int(max_samples))
    allow = {str(e).lower() for e in exts}
    limit = max(1, int(max_samples))

    # 标准库优先：纯 .py 源码、零第三方污染，是 text 通道最干净的语料；
    # 系统二进制随后补 binary 通道。
    raw_sources = list(sources) if sources is not None else (
        stdlib_sources() + default_sources())

    # 归一化 + 过宽根剔除
    roots: List[Path] = []
    seen_roots = set()
    for s in raw_sources:
        try:
            p = Path(s)
        except (TypeError, ValueError):
            res.note_skip("来源非法")
            continue
        key = str(p).lower()
        if key in seen_roots:
            continue
        seen_roots.add(key)
        src = BaselineSource(path=str(p))
        if _wide_root(p):
            src.skipped_wide = True
            res.sources.append(src)
            res.note_skip("根过宽")
            continue
        if not p.is_dir():
            src.missing = True
            res.sources.append(src)
            continue
        res.sources.append(src)
        roots.append(p)

    if not roots:
        return res

    # 🔴 按「调用方给定的优先级顺序」处理，**不做字典序重排**。
    # 顺序即优先级；配额分配见下。
    src_by_path = {str(Path(s.path)).lower(): s for s in res.sources}
    seen_done = set()
    own = _own_project_roots()

    text_exts = {".py", ".pyw", ".ps1", ".js", ".vbs", ".bat", ".cmd"}

    def _kind(pth: Path) -> str:
        return "text" if pth.suffix.lower() in text_exts else "binary"

    # ---------------------------------------------------------------
    # 两类别配额 + 借用（关键设计，改过两次，勿回退）
    # ---------------------------------------------------------------
    # 朴素做法「先到先得」在真实机器上必然失败：Python 标准库有 2000+
    # 个 .py，排在前面就会把整个配额吃光，binary 通道一个样本都学不到
    # （曾踩）。但「各拿一半、互不侵占」同样错：调用方只给了一个 text
    # 来源时（例如只想给一小撮 .py 建基线，或测试里的单目录场景），
    # binary 永远拿不到那份保留份额 -> 实际只采到 ``limit // 2``，
    # 用户设了 400 却只得到 200（曾踩，9 处单测失败全出于此）。
    #
    # 正解：**单趟遍历 + 动态上限**。
    #   · 保留份额优先：text / binary 各有 ``limit // 2`` 的保留量，
    #     保证两类都有货时均衡、binary 通道不被饿死。
    #   · 借用：当某一类**已知没货**（该来源里根本没有该类别文件）时，
    #     把保留量让给另一类，让另一类最多能采到 ``limit``。
    #
    # 判定"没货"不能靠预扫描（代价高），而是在遍历中观察：本趟里该类别
    # 一个候选都没出现过 -> 视为没货 -> 放开另一类的上限。用一次遍历
    # 边采边判，天然满足三种场景，且不会重复枚举（曾踩：两轮实现里
    # 第一轮会把候选全部吃光并塞满 sink，第二轮一个都拿不到）。
    #
    # 两通道在 KGModel 里是彼此独立的模型（text / binary），一边为空
    # 就等于该通道完全没学到东西 —— 这是硬性要求，不是优化。
    reserve = {"text": max(1, limit // 2), "binary": max(1, limit // 2)}
    #: 本趟里出现过的类别（用来判断另一类是否"没货"，从而放行借用）
    present = {"text": 0, "binary": 0}
    got = {"text": 0, "binary": 0}

    collected: List[Path] = []

    # 每个候选都要过的公共闸门；返回 (是否通过, 原因)
    def _gate(cand: Path, root: Path):
        try:
            if not cand.is_file():
                return False, ""
        except OSError:
            return False, "stat 失败"
        if cand.suffix.lower() not in allow:
            return False, "扩展名不支持"
        lname = cand.name.lower()
        if lname in _EXCLUDE_STEMS:
            return False, "内置排除"
        if lname.startswith(_EXCLUDE_PREFIXES):
            return False, "API-Set 转发桩"
        if _in_excluded_dir(cand, roots):
            return False, "位于排除目录"
        if _is_own_project(cand, own):
            return False, "项目自身文件"
        # 红线：候选必须落在来源根之内
        try:
            if not is_within(cand, root):
                return False, "越出来源根"
        except Exception:
            return False, "路径校验异常"
        try:
            if cand.stat().st_size <= 0:
                return False, "空文件"
        except OSError:
            return False, "stat 失败"
        return True, ""

    def _cap_for(k: str) -> int:
        """某类别当前允许的上限（含借用）。

        规则：只要**另一类确实存在候选**，本类就守 ``reserve`` 上限，
        避免先到的来源把配额吃光；反之另一类没货，本类放开到 ``limit``。
        """
        other = "binary" if k == "text" else "text"
        if present[other] > 0:
            return reserve[k]
        return limit

    def _scan_presence() -> None:
        """廉价的类别存在性预判（只看每个来源根顶层，不下钻）。

        为什么必须有这一步：单趟"边采边判"存在顺序依赖 —— 若 text 来源
        排在前面且文件足够多，它会在遇到任何 binary 之前就把 ``limit``
        吃满，binary 通道一个样本都学不到（曾踩：分类配额被单类吃光）。
        预判只看顶层目录项，代价是几次 ``iterdir``，但能让配额分配在
        遍历前就定型，彻底消除顺序依赖。
        """
        probed = set()
        for p in roots:
            try:
                for e in p.iterdir():
                    try:
                        if not e.is_file():
                            continue
                    except OSError:
                        continue
                    if e.suffix.lower() not in allow:
                        continue
                    k = _kind(e)
                    if k not in probed:
                        probed.add(k)
                    present[k] = 1
            except OSError:
                continue
            if present["text"] and present["binary"]:
                return

    def _take() -> None:
        """单趟按优先级遍历所有来源，逐类别填充；上限动态。

        ``present`` 已在 ``_scan_presence()`` 中定型，故配额分配与遍历
        顺序无关：两类都有货 -> 各 ``limit // 2``；只有一类有货 ->
        该类放开到 ``limit``（借用空置份额）。

        注意：**返回类型必须是 None**，且内部不得出现 `return True/False`
        —— 早期版本这里返回布尔值，调用方误当成"已满"信号，导致单类别
        场景只采到 limit//2（曾踩，9 处单测失败全出于此）。
        """
        for p in roots:
            key = str(p).lower()
            if key in seen_done:
                continue
            if got["text"] + got["binary"] >= limit:
                return
            seen_done.add(key)
            src = src_by_path.get(key)
            if src is None:
                continue
            try:
                walker = _iter_dir(p, per_dir_cap=per_dir_cap, stats=src,
                                   sink=seen_paths)
            except OSError:
                res.note_skip("目录不可读")
                continue
            src.visited = True
            for cand in walker:
                if got["text"] + got["binary"] >= limit:
                    return
                src.scanned += 1
                ok, reason = _gate(cand, p)
                if not ok:
                    if reason:
                        res.note_skip(reason)
                    continue
                k = _kind(cand)
                present[k] = 1
                if got[k] >= _cap_for(k):
                    res.note_skip("该类别配额已满")
                    continue
                got[k] += 1
                collected.append(cand)
                src.accepted += 1

    # 目录级排除（隐私/临时区）会整棵剪掉、不 enumerate 其下文件；被剪
    # 子树由 ``_iter_dir`` 经 ``stats.pruned`` 计数，摘要里显式说明，
    # 否则用户只看到总数莫名变少（曾踩：只记文件级原因时「位于排除目录」
    # 永远为 0）。
    seen_paths = set()

    # ---- 先廉价预判两类是否都有货（消除顺序依赖），再单趟采集 ----
    _scan_presence()
    _take()

    res.truncated = (got["text"] + got["binary"]) >= limit
    res.candidates = collected

    # 目录级排除单独入账：让「位于排除目录」在 skip 明细里可见（可解释性）
    if res.pruned_dirs:
        res.note_skip("位于排除目录")

    # 确定性输出：去重 + 排序
    uniq: List[Path] = []
    seen = set()
    for c in res.candidates:
        k = str(c).lower()
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    uniq.sort(key=lambda x: str(x).lower())

    # 配额已在上面的采集循环里逐类别执行；此处只做最终去重与排序，
    # 保证同一台机器多次采集得到完全一致的列表（可复现）。
    res.candidates = uniq[:limit]
    return res


def _iter_dir(root: Path, *, per_dir_cap: int,
              stats: Optional["BaselineSource"] = None,
              sink: Optional[set] = None) -> Iterable[Path]:
    """按确定性顺序浅层+递归遍历一个来源目录。

    手工栈式遍历（而非 ``rglob``）以便在 ``per_dir_cap`` 处及时收手，
    并跳过被排除目录的子树（不进去 enumerate）。

    ``stats`` ：传入时登记被剪掉的排除子树数量（``pruned``），
    让上层能解释"为什么总数比目录里的文件少"。
    ``sink``  ：去重集合，避免两轮借用时重复枚举同一文件。
    """
    stack: List[Path] = [root]
    emitted = 0
    while stack:
        d = stack.pop()
        try:
            entries = sorted(d.iterdir(), key=lambda x: x.name.lower())
        except OSError:
            continue
        subdirs: List[Path] = []
        for e in entries:
            if e.is_dir():
                if _skip_dir(e.name):
                    # 被剪掉的隐私/临时子树：单独记账，供 summary 解释
                    if stats is not None:
                        stats.pruned += 1
                    continue
                subdirs.append(e)
                continue
            try:
                if not e.is_file():
                    continue
            except OSError:
                continue
            if emitted >= per_dir_cap:
                return
            if sink is not None:
                k = str(e).lower()
                if k in sink:
                    continue
                sink.add(k)
            emitted += 1
            yield e
        # 后进先出 -> 逆序入栈，保持字典序
        for sd in reversed(subdirs):
            stack.append(sd)


# ============================================================
# 便捷入口
# ============================================================

def feed_baseline(data_dir, **kw):
    """采集良性基线并投喂（便捷入口）。

    额外参数 ``max_samples`` / ``sources`` / ``dry_run`` 透传给采集器与喂料器。
    返回 ``(BaselineResult, FeedResult)``。
    """
    from .feed import feed_targets

    max_samples = int(kw.pop("max_samples", DEFAULT_MAX))
    sources = kw.pop("sources", None)
    base = collect_benign_samples(sources, max_samples=max_samples)
    if not base.candidates:
        return base, None
    fr = feed_targets(base.candidates, data_dir=data_dir, label="ben", **kw)
    return base, fr
