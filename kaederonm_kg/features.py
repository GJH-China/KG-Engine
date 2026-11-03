"""
KG 机器引擎 - 特征提取器

从任意文件（含 zip / tar / tar.gz 压缩包）提取用于机器学习的特征向量。

核心设计
    1. 递归下钻：压缩包不是样本本体，只是携带介质。
       直接把 zip 整包喂给模型，学到的是"这个压缩参数像病毒"，是废模型。
       所以对压缩包逐层下钻到内层 PE / 脚本，再对内层提特征。
    2. 双通道：源码类（.py/.ps1/.js/.vbs）走文本 n-gram；
       二进制类走字节 n-gram + PE 头字段。两通道各自独立建模。
    3. 标准库为主：zip / tar 走内置（zipfile / tarfile）；
       7z / rar 为**可选软依赖**：7z 靠 py7zr，rar 靠外部 UnRAR.exe。
       两者缺失或失败均静默降级为「整包当字节流」+ a_unopenable，不抛异常。
    4. 有预算（不设人为深度上限）：单文件读 2MB、单包总解压 32MB。
       递归层数默认**无限**（``MAX_DEPTH = 0``）——病毒多套几层包
       **不会**逆向逃逸；真正兜底的是字节预算 + 向量数预算，
       另有 ``HARD_DEPTH_CEILING`` 防同名自套循环。详见文件顶部常量注释。
"""
from __future__ import annotations

import io
import math
import os
import re
import struct
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

PathLike = Union[str, os.PathLike]

# ---- 资源上限（防 zip bomb / 大样本） ----
# 设计变更（2026-09-19）：旧版把「递归深度」当硬卡（3 层）。
# 但病毒样本只要多套几层包就能逆向逃逸到零样本。
# 现改为「**深度不设人为上限，靠字节预算 + 向量预算兜底**」：
#   - 真正防止爆炸的是 `MAX_TOTAL_BYTES`（字节）与
#     `MAX_MEMBER_VECTORS`（向量数），而不是层数。
#   - 保留 `MAX_DEPTH = 0` = **无限**的语义；仅用 `HARD_DEPTH_CEILING`
#     作为同名自契合循环（包里套自己）的最后保护网。
MAX_FILE_BYTES   = 2 * 1024 * 1024      # 顶层非归档叶节点最多读 2MB
MAX_MEMBER_BYTES = 32 * 1024 * 1024     # 归档**单个成员**读取上限 32MB
MAX_TOTAL_BYTES  = 32 * 1024 * 1024     # 单样本总解压上限 32MB
MAX_DEPTH        = 0                    # 递归层数：**0 = 无限**（不人为截断）
HARD_DEPTH_CEILING = 64                 # 无限模式下的安全天花板（仅防自契合循环）
MAX_MEMBERS      = 4096                 # 单包最多处理成员数
# 逐成员展开的总产出上限（跨整个「包树」，不是单层）。
# 为什么需要：深度无限后，最坏情况是每层都满员
# （4096^k），样本数会指数爆炸。这里兜住「一个目标最多产出多少个样本」。
MAX_MEMBER_VECTORS = 200000             # 单目标逐成员展开的向量数上限
MAX_STRINGS      = 400                  # 最多提取的可打印串数
MIN_STR_LEN      = 5                    # 可打印串最小长度


def depth_exceeded(depth: int) -> bool:
    """判定是否已超出递归深度限制。

    ``MAX_DEPTH == 0`` 表示**不人为限制**，仅受 ``HARD_DEPTH_CEILING``
    保护（防同名自套循环无限往下）。非 0 时保留旧语义。
    """
    if MAX_DEPTH and MAX_DEPTH > 0:
        return depth > MAX_DEPTH
    return depth > HARD_DEPTH_CEILING

# 源码类扩展名 -> 文本通道
SOURCE_EXTS = {
    ".py", ".pyw", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".hta", ".sh", ".php", ".asp", ".aspx",
    ".jsp", ".pl", ".rb", ".lua", ".ahk", ".reg", ".inf", ".sc",
    # 编译型源码：同属「源码通道」。此前缺失，导致 .cpp/.c/.h 等
    # 被判成二进制通道（源码按 PE 字节统计 → 特征空间错配）。
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inl",
    ".cs", ".java", ".go", ".rs", ".m", ".mm", ".swift", ".kt",
    ".asm", ".s", ".sql", ".ts", ".tsx", ".jsx", ".vue",
}
# 压缩包扩展名
ARCHIVE_EXTS = {".zip", ".jar", ".war", ".egg", ".whl", ".apk", ".xpi",
                ".7z", ".rar"}
TAR_EXTS     = {".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz"}
# 二进制可执行体（PE / ELF / Mach-O）
BINARY_EXTS  = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".com",
                ".efi", ".so", ".dylib", ".bin", ".dat", ".msi"}

# 7z / rar 需要额外能力（纯标准库做不到），缺失时降级不报错
SEVEN_ZIP_EXTS = {".7z"}
RAR_EXTS       = {".rar"}
# 数值须与预设一致：rar 内层单文件上限与 zip 同步
RAR_MEMBER_BYTES = MAX_MEMBER_BYTES
# 优先级：包内现成 UnRAR.exe → 系统 Program Files 安装路径
UNRAR_CANDIDATES = (
    r"C://Program Files//WinRAR//UnRAR.exe",
    r"C://Program Files (x86)//WinRAR//UnRAR.exe",
)

# ---------------------------------------------------------------------------
# 归档解压密码（样本语料的行业惯例是统一口令）
# ---------------------------------------------------------------------------
# 为什么需要：病毒样本包（尤其 7z）常用口令加密以防被在线查杀/误报。
# 没有密码时这些包一律降级成 a_unopenable —— 实测占本批语料的绝大多数，
# 等于白白丢掉最有价值的深层特征。密码在**构造 SevenZipFile 时**传入
# （py7zr 1.1.3 的 extract/extractall 都不接受 password 参数）。
#
# 说明：这里放的是「语料包口令」，不是我们的密钥，无泄漏风险；
# 但仍允许调用方用 set_archive_password() 覆盖或清空。
ARCHIVE_PASSWORD: str = "infected"


def set_archive_password(pw: str) -> None:
    """覆盖默认归档口令（传空串 = 不再尝试密码）。"""
    global ARCHIVE_PASSWORD
    ARCHIVE_PASSWORD = pw or ""


@dataclass
class FeatureVector:
    """一个样本的特征向量。

    counts   : 特征名 -> 出现次数（朴素贝叶斯的多变量伯努利/多项式计数）
    channel  : 'text' 源码通道 / 'binary' 二进制通道
    labels   : 人类可读的补充信息（用于报告"为什么"）
    digest   : 样本轻量指纹（用于去重，不存原文）
    """
    counts:  Dict[str, int] = field(default_factory=dict)
    channel: str = "binary"
    labels:  Dict[str, str] = field(default_factory=dict)
    digest:  str = ""

    def merge(self, other: "FeatureVector") -> "FeatureVector":
        """把另一个向量并进来（一个包内多个成员 -> 合成一个样本）"""
        for k, v in other.counts.items():
            self.counts[k] = self.counts.get(k, 0) + v
        self.labels.update(other.labels)
        return self

    def top(self, n: int = 8) -> List[Tuple[str, int]]:
        return sorted(self.counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]

    def __len__(self) -> int:
        return len(self.counts)


# ============================================================
# 字节 / 文本层面的原子特征
# ============================================================

def shannon_entropy(data: bytes) -> float:
    """香农熵（0-8）。加密/压缩数据接近 8。"""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = float(len(data))
    e = 0.0
    for c in freq:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def extract_printable_strings(data: bytes, limit: int = MAX_STRINGS) -> List[str]:
    """提取 ASCII 可打印串（>= MIN_STR_LEN），只取前 limit 条。"""
    out: List[str] = []
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= MIN_STR_LEN:
                out.append(cur.decode("ascii", "ignore"))
                if len(out) >= limit:
                    return out
            cur.clear()
    if len(cur) >= MIN_STR_LEN and len(out) < limit:
        out.append(cur.decode("ascii", "ignore"))
    return out


# 块 11：拒绝含 NUL 字节的 n-gram（仅 binary 通道）。
# 根因：UTF-16 宽字符串（\x00e / e\x00 等）与 int3 填充（\xcc\xcc）属于
# 「所有 PE 都有的结构性字节」，却被良性训练集统计成良性特征，
# 导致任何含宽字符串的 PE（.NET / 现代编译产物）被系统性扣分。
# 实测：召回 60%% -> 90%%，特异性保持 100%%，AUC 1.0000 -> 0.9996。
REJECT_NUL_NGRAMS = True


def _ngram_has_nul(g: bytes) -> bool:
    """n-gram 是否含 NUL 字节（即 UTF-16 高/低位字节对的一半）。"""
    return 0 in g


def byte_ngrams(data: bytes, n: int = 2, top: int = 96,
                reject_nul: bool = False) -> Dict[str, int]:
    """字节 n-gram 频次。只保留最高频的 top 个，控特征维度。

    reject_nul=True 时，含 NUL 字节的 n-gram 在排序截断之前就被丢弃
    （而非截断后过滤），保证最终仍能取足 top 个特征。
    """
    freq: Dict[bytes, int] = {}
    step = 1
    # 大文件抽样，避免 O(n) 扫描过慢
    if len(data) > 65536:
        step = max(1, len(data) // 65536)
    end = len(data) - n
    for i in range(0, max(0, end), step):
        g = data[i:i + n]
        if reject_nul and _ngram_has_nul(g):
            continue
        freq[g] = freq.get(g, 0) + 1
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {f"b{g.hex()}": c for g, c in ranked}


# 脚本高危关键词 -> 特征名
SCRIPT_PATTERNS: List[Tuple[str, str]] = [
    (r"powershell\s+-\s*(enc|encodedcommand)",     "s_ps_encoded"),
    (r"-\s*w\s+hidden|windowstyle\s+hidden",       "s_ps_hidden"),
    (r"frombase64string",                            "s_b64_decode"),
    (r"invoke-expression|iex\s*\(",                  "s_iex"),
    (r"downloadstring|downloadfile|webclient",       "s_download"),
    (r"new-object\s+net\.webclient",                 "s_webclient"),
    (r"wscript\.shell|shell\.application",           "s_wscript"),
    (r"createobject\s*\(",                           "s_createobject"),
    (r"reg(istry)?\s+(add|write)|hklm:|hkey_local",   "s_reg_write"),
    (r"schtasks|create.*task",                       "s_schtask"),
    (r"vssadmin|wbadmin|bcdedit",                    "s_vss"),
    (r"taskkill|net\s+stop",                          "s_kill_svc"),
    (r"system32|syswow64",                           "s_sysdir"),
    (r"start-process|cmd\.exe|/c\s+",                 "s_spawn"),
    (r"chmod\s+\+x|\/dev\/null|curl\s+-",             "s_unix_loader"),
    (r"autoopen|document_open|workbook_open",        "s_office_macro"),
    (r"mimikatz|sekurlsa|lsass",                     "s_credential"),
    (r"bitcoin|ransom|encrypt.*file",                "s_ransom"),
    (r"socket|connect\(|listen\(",                   "s_network"),
    (r"eval\(|exec\(|compile\(",                     "s_dyn_exec"),
    (r"base64|rot13|chr\(.*\)\s*\+",                  "s_obfus"),
    (r"driver|\\\.\\|device\\",                    "s_driver"),
    (r"loaddriver|ntloaddriver",                     "s_load_driver"),
    (r"\[\^\$\{\}\]",                                     "s_var_obfus"),
]
_SCRIPT_RE = [(re.compile(p, re.I | re.S), name) for p, name in SCRIPT_PATTERNS]

# PE 敏感导入 API -> 特征名
PE_APIS: List[Tuple[str, str]] = [
    ("VirtualAlloc",      "a_virtualalloc"),
    ("VirtualProtect",    "a_virtualprotect"),
    ("WriteProcessMemory", "a_wpm"),
    ("ReadProcessMemory", "a_rpm"),
    ("CreateRemoteThread", "a_crt"),
    ("OpenProcess",       "a_openprocess"),
    ("LoadLibrary",       "a_loadlibrary"),
    ("GetProcAddress",    "a_getprocaddr"),
    ("CreateProcess",     "a_createprocess"),
    ("ShellExecute",      "a_shellexec"),
    ("WinExec",           "a_winexec"),
    ("URLDownloadToFile", "a_urldownload"),
    ("InternetOpen",      "a_internet"),
    ("NtLoadDriver",      "a_ntloaddriver"),
    ("DeviceIoControl",   "a_deviceio"),
    ("SetWindowsHookEx",  "a_hook"),
    ("RegSetValue",       "a_regset"),
    ("CryptEncrypt",      "a_crypt"),
    ("AdjustTokenPrivileges", "a_privilege"),
    ("IsDebuggerPresent", "a_antidebug"),
]
_PE_API_BYTES = [(a.encode("ascii"), n) for a, n in PE_APIS]


# ============================================================
# PE 头解析（纯 struct，不依赖 pefile）
# ============================================================

#: ★ KG2（2026-10-07）：parse_pe 产出、但由 ``_emit_pe_kg2`` **显式处理**的字段。
#: 放进这个集合是为了把它们**排除出 extract_features 的通用 isinstance 循环** ——
#: 否则 ``pe_timestamp_<秒>`` / ``pe_entry_rva_<值>`` 会产出近乎唯一的高基数特征，
#: 既撑爆计数表，又因为样本量下估不出概率而毫无泛化能力。
_KG2_HANDLED = frozenset({
    "pe_sections_detail", "pe_import_dlls", "pe_import_available",
    "pe_entry_section", "pe_timestamp", "pe_entry_rva", "pe_overlay_size",
    "pe_has_wx", "pe_has_tls", "pe_has_signature",
})


def _emit_pe_kg2(fv: FeatureVector, pe: Dict[str, object]) -> None:
    """KG2 深层 PE 结构特征（独立命名空间 ``pe2_*``）。

    为什么是**加法**而不是替换
        现有 ``pe_*`` 特征的取值**逐字节不变** ⇒ 老模型（KG1）行为不受影响；
        新特征是纯增量，投喂后由数据自己决定给不给它们权重。

    为什么**分桶**而不是用精确值
        时间戳 / 大小 / RVA 这类连续量若用精确值，会产出近乎唯一的高基数特征；
        朴素贝叶斯在现有样本量下估不出概率，只会撑爆计数表。
        统一按语义分桶（lo/mid/hi、0/s/m/l）后维度可控且可泛化。
    """
    c = fv.counts

    # 1) 逐节：熵分桶（hi>=7 加密/压缩；mid 6~7；lo<6）+「原始大小为 0」（未映射节）
    #    ⚠ 被截断的节**不算熵** —— 残缺数据的熵偏低，当成真实节熵会引入假信号。
    for s in pe.get("pe_sections_detail") or []:
        nm = str(s.get("name") or "").lower().lstrip(".") or "noname"
        if s.get("trunc"):
            c["pe2_sec_%s_trunc" % nm] = 1
            continue
        ent = float(s.get("ent") or 0.0)
        b = "hi" if ent >= 7.0 else ("mid" if ent >= 6.0 else "lo")
        c["pe2_sec_%s_%s" % (nm, b)] = 1
        if int(s.get("rsize") or 0) == 0 and int(s.get("vsize") or 0) > 0:
            c["pe2_sec_%s_raw0" % nm] = 1

    # 2) 入口点所在节（EP 不在 .text 是强信号）
    ep = str(pe.get("pe_entry_section") or "").lower().lstrip(".")
    c["pe2_ep_%s" % (ep or "none")] = 1
    if pe.get("pe_entry_rva") == 0:
        c["pe2_ep_rva0"] = 1

    # 3) 内存属性 / TLS / 数字签名
    #    ⚠ 这里的签名是**内嵌 Authenticode 签名**（Security 数据目录非空）。
    #      大量 System32 文件是**目录签名（.cat）**，PE 里没有内嵌签名 ——
    #      所以「无内嵌签名」绝不等于「未签名」，命名上用 esig 以免误读。
    if pe.get("pe_has_wx"):
        c["pe2_wx"] = 1
    if pe.get("pe_has_tls"):
        c["pe2_tls"] = 1
    c["pe2_esig" if pe.get("pe_has_signature") else "pe2_esig_no"] = 1

    # 4) 导入 DLL（去重、限 24 个防高基数）+ 导入数量分桶
    #    ⚠ 导入表读不到时（大文件被 2MB 预算截断）标记 unavail，
    #      **绝不冒充 0 个导入** —— 否则 pe2_impn_0 会与「文件大」虚假相关。
    if pe.get("pe_import_available"):
        dlls = [str(d) for d in (pe.get("pe_import_dlls") or [])]
        for d in list(dict.fromkeys(dlls))[:24]:
            c["pe2_imp_%s" % d] = 1
        n = len(dlls)
        c["pe2_impn_%s" % ("0" if n == 0 else "1_3" if n <= 3 else "4_8" if n <= 8 else "9p")] = 1
    else:
        c["pe2_imp_unavail"] = 1

    # 5) overlay（节后附加数据）分桶
    ov = int(pe.get("pe_overlay_size") or 0)
    c["pe2_ov_%s" % ("0" if ov == 0 else "s" if ov <= 4096 else "m" if ov <= 262144 else "l")] = 1

    # 6) 时间戳异常（0 = 被抹；> 2100-01-01 = 伪造）
    ts = int(pe.get("pe_timestamp") or 0)
    if ts == 0:
        c["pe2_ts_zero"] = 1
    elif ts > 4102444800:
        c["pe2_ts_future"] = 1


def parse_pe(data: bytes) -> Dict[str, object]:
    """最小 PE 解析：只取做特征需要的字段。失败返回 {}。"""
    out: Dict[str, object] = {}
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return out
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return out
        machine, nsec, _, _, _, opt_size, chars = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4)
        out["pe_machine"] = machine
        out["pe_sections"] = nsec
        out["pe_characteristics"] = chars
        out["pe_opt_size"] = opt_size
        out["pe_is_dll"] = bool(chars & 0x2000)
        # 可选头魔数：0x10b=PE32, 0x20b=PE32+
        opt_off = e_lfanew + 24
        if opt_off + 2 <= len(data):
            magic = struct.unpack_from("<H", data, opt_off)[0]
            out["pe_magic"] = magic
            out["pe_is_64"] = (magic == 0x20B)
            # 子系统在可选头偏移 68（PE32 与 PE32+ 都是）
            if opt_off + 70 <= len(data):
                out["pe_subsystem"] = struct.unpack_from("<H", data, opt_off + 68)[0]
        # 节区名（前 8 个，每个 8 字节）
        sec_off = opt_off + opt_size
        names: List[str] = []
        for i in range(min(int(nsec), 8)):
            off = sec_off + i * 40
            if off + 8 > len(data):
                break
            nm = data[off:off + 8].rstrip(b"\x00")
            if nm:
                names.append(nm.decode("ascii", "ignore").strip())
        out["pe_section_names"] = names

        # ---------------------------------------------------------------
        # ★ KG2（2026-10-07）：深层结构特征 —— 全是**加法**，不改动上面任何字段，
        #   保证 KG1 既有特征的取值逐字节不变（老模型行为不受影响）。
        #   纯 struct 解析，不引 pefile。
        # ---------------------------------------------------------------

        # ---- 时间戳（COFF 头第 3 个字段，偏移 e_lfanew+8）----
        try:
            out["pe_timestamp"] = struct.unpack_from("<I", data, e_lfanew + 8)[0]
        except struct.error:
            pass

        # ---- 可选头：入口点 + 数据目录 ----
        aoe = None
        dirs: List[Tuple[int, int]] = []
        try:
            aoe = struct.unpack_from("<I", data, opt_off + 16)[0]
            dd_off = opt_off + (112 if magic == 0x20B else 96)
            n_dd = struct.unpack_from("<I", data, opt_off + (108 if magic == 0x20B else 92))[0]
            for i in range(min(int(n_dd), 16)):
                o = dd_off + i * 8
                if o + 8 > len(data):
                    break
                dirs.append(struct.unpack_from("<II", data, o))
        except (struct.error, IndexError, ValueError, UnboundLocalError):
            pass
        if aoe is not None:
            out["pe_entry_rva"] = aoe

        # ---- 数据目录：4=安全(签名，值是**文件偏移**非RVA) / 9=TLS / 1=导入 ----
        def _dd(idx: int) -> Tuple[int, int]:
            return dirs[idx] if idx < len(dirs) else (0, 0)

        sec_rva, sec_sz = _dd(4)
        out["pe_has_signature"] = bool(sec_rva and sec_sz)
        tls_rva, tls_sz = _dd(9)
        out["pe_has_tls"] = bool(tls_rva and tls_sz)
        imp_rva, imp_sz = _dd(1)

        # ---- 节表：逐节（名/大小/特性/熵），并建立 RVA->文件偏移 映射 ----
        secs: List[Dict[str, object]] = []
        has_wx = False
        ep_sec = ""
        max_raw_end = 0
        for i in range(min(int(nsec), 96)):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            raw_name = data[off:off + 8].rstrip(b"\x00")
            nm = raw_name.decode("ascii", "ignore").strip()
            try:
                vsize, vaddr, rsize, rptr, ch = struct.unpack_from("<IIIII", data, off + 8)
            except struct.error:
                break
            # 节特性：+36 处是 Characteristics；上面一次读 5 个 I 覆盖了 +8..+28，
            # 这里单独取 +36
            try:
                ch = struct.unpack_from("<I", data, off + 36)[0]
            except struct.error:
                ch = 0
            writable = bool(ch & 0x80000000)
            executable = bool(ch & 0x20000000)
            if writable and executable:
                has_wx = True
            ent = 0.0
            # ★ KG2：标记「本节原始数据未被完整读到」。
            #   extract_from_path 有 MAX_FILE_BYTES=2MB 预算，大文件的靠后节会被截断，
            #   此时算出的熵是**残缺数据的熵**（往往偏低），不能当成真实节熵用。
            trunc = bool(rsize) and (rptr + rsize > len(data))
            if rptr and rsize and rptr < len(data):
                blob = data[rptr:min(rptr + rsize, len(data))]
                ent = shannon_entropy(blob)
                max_raw_end = max(max_raw_end, min(rptr + rsize, len(data)))
            secs.append({
                "name": nm, "vsize": int(vsize), "vaddr": int(vaddr),
                "rsize": int(rsize), "rptr": int(rptr), "ent": ent,
                "w": writable, "x": executable, "trunc": trunc,
            })
            # 入口点落在哪个节（RVA 落在 [vaddr, vaddr+max(vsize,rsize)) 内）
            if aoe is not None and vaddr and vaddr <= aoe < vaddr + max(int(vsize), int(rsize)):
                if not ep_sec:
                    ep_sec = nm
        out["pe_has_wx"] = has_wx
        out["pe_entry_section"] = ep_sec
        out["pe_sections_detail"] = secs
        # overlay = 所有节原始数据之后的附加字节（加壳/自解压常见）
        out["pe_overlay_size"] = max(0, len(data) - max_raw_end) if max_raw_end else 0

        # ---- 导入表：真正解析 DLL 名（替代原来粗糙的字节串匹配）----
        dlls: List[str] = []
        imp_avail = False
        if imp_rva:
            def _rva2off(rva: int) -> Optional[int]:
                for s in secs:
                    v, vs, rp, rs = int(s["vaddr"]), int(s["vsize"]), int(s["rptr"]), int(s["rsize"])
                    if v and v <= rva < v + max(vs, rs):
                        return rp + (rva - v)
                return None

            o = _rva2off(imp_rva)
            # ★ KG2：只有描述符数组**真的落在已读到的字节里**才算「导入表可用」。
            #   大文件被 MAX_FILE_BYTES 截断时导入表常在文件尾部而读不到 ——
            #   此时必须标记「不可用」，**绝不能冒充「0 个导入」**，
            #   否则 pe2_impn_0 会与「文件大」虚假相关，模型学出假规律。
            if o is not None and o + 20 <= len(data):
                imp_avail = True
                for _ in range(64):          # 最多 64 个导入 DLL，防御畸形表
                    if o + 20 > len(data):
                        break
                    try:
                        _oft, _ts, _fc, name_rva, _ft = struct.unpack_from("<IIIII", data, o)
                    except struct.error:
                        break
                    if not name_rva:
                        break
                    no = _rva2off(name_rva)
                    if no is None or no >= len(data):
                        break
                    end = data.find(b"\x00", no, min(no + 260, len(data)))
                    if end < 0:
                        break
                    d = data[no:end].decode("ascii", "ignore").strip().lower()
                    if d:
                        dlls.append(d)
                    o += 20
        out["pe_import_dlls"] = dlls
        out["pe_import_available"] = imp_avail
    except (struct.error, IndexError, ValueError):
        return out
    return out


# ============================================================
# 单块数据 -> 特征
# ============================================================

def extract_features(
    data: bytes,
    name: str = "",
    channel: Optional[str] = None,
) -> FeatureVector:
    """从一段字节流提特征。channel 为 None 时按扩展名自动判定。"""
    ext = Path(name).suffix.lower()
    if channel is None:
        channel = "text" if ext in SOURCE_EXTS else "binary"

    fv = FeatureVector(channel=channel)
    if not data:
        fv.labels["empty"] = "1"
        return fv

    n = len(data)
    fv.counts["f_size_log"] = min(30, int(math.log2(n + 1)))
    ent = shannon_entropy(data)
    fv.counts[f"f_entropy_{int(ent)}"] = 1
    fv.labels["entropy"] = f"{ent:.2f}"
    fv.labels["size"] = str(n)

    if channel == "text":
        text = data.decode("utf-8", "ignore")
        low = text.lower()
        for rx, fname in _SCRIPT_RE:
            hits = len(rx.findall(low))
            if hits:
                fv.counts[fname] = min(hits, 8)
        # 文本行特征
        lines = text.splitlines()
        fv.counts["t_lines"] = min(200, len(lines)) // 10
        long_lines = sum(1 for l in lines if len(l) > 500)
        if long_lines:
            fv.counts["t_longline"] = min(long_lines, 8)
        # 变量名混淆：单字符变量占比
        if len(text) > 200:
            fv.counts["t_obfus_ratio"] = min(8, text.count("$") // 10)
        # 文本 n-gram（3-gram，取高频）
        grams = _text_ngrams(low, 3, top=64)
        fv.counts.update(grams)

    # 字节特征两个通道都要（二进制更强）
    # 块 11：binary 通道拒绝含 NUL 的 n-gram（结构性字节误学成良性特征）
    # 宽容 top：过滤前多取一些，保证过滤后仍有 96 个
    _top = 96 if channel == "binary" else 32
    _rej = REJECT_NUL_NGRAMS and channel == "binary"
    if _rej:
        _top = min(_top * 2, 256)
    bgrams = byte_ngrams(data, 2, top=_top, reject_nul=_rej)
    if _rej and len(bgrams) > 96:
        bgrams = dict(sorted(bgrams.items(), key=lambda kv: (-kv[1], kv[0]))[:96])
    fv.counts.update(bgrams)

    # 可打印串（抽前 64 条做特征）
    strs = extract_printable_strings(data, limit=64)
    fv.labels["str_sample"] = " | ".join(strs[:3])[:120]
    for s in strs:
        sl = s.lower()
        for rx, fname in _SCRIPT_RE:
            if rx.search(sl):
                fv.counts.setdefault(fname, 0)
                fv.counts[fname] = min(8, fv.counts[fname] + 1)
                break

    # 二进制：PE 解析 + 敏感 API
    if channel == "binary":
        pe = parse_pe(data)
        for k, v in pe.items():
            # ★ KG2：这些字段由 _emit_pe_kg2 显式处理，**绝不走下面的通用循环**。
            #   否则 pe_timestamp_<秒> / pe_entry_rva_<值> 会产出高基数特征，
            #   把计数表撑爆且几乎不可能泛化。
            if k in _KG2_HANDLED:
                continue
            if k == "pe_section_names":
                for nm in v:  # type: ignore[union-attr]
                    if nm.lower() in ("upx0", "upx1", ".packed", ".aspack", ".themida"):
                        fv.counts[f"pe_pack_{nm.lower().lstrip('.')}"] = 1
            elif isinstance(v, bool):
                if v:
                    fv.counts[f"{k}_true"] = 1
            elif isinstance(v, int):
                fv.counts[f"{k}_{v}"] = 1
        fv.labels["pe"] = "1" if pe else "0"
        if pe:
            for needle, fname in _PE_API_BYTES:
                if needle in data:
                    fv.counts[fname] = 1
            # ★ KG2 深层结构特征（新增命名 pe2_*，与 KG1 既有特征零冲突）
            _emit_pe_kg2(fv, pe)
        if data[:2] == b"MZ":
            fv.counts["is_mz"] = 1
        if b"This program cannot be run in DOS mode" in data[:512]:
            fv.counts["dos_stub_std"] = 1

    if ext:
        fv.counts[f"e{ext}"] = 1
    fv.counts["f_nul_ratio"] = min(8, data.count(0) * 8 // max(1, n))
    return fv


def _text_ngrams(text: str, n: int = 3, top: int = 64) -> Dict[str, int]:
    """只对标识符类字符做 n-gram，避开空格/换行噪音。"""
    clean = re.sub(r"[^a-z0-9_.$]", "", text)
    if len(clean) < n:
        return {}
    freq: Dict[str, int] = {}
    for i in range(0, len(clean) - n + 1):
        g = clean[i:i + n]
        freq[g] = freq.get(g, 0) + 1
    ranked = sorted(freq.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
    return {f"t{k}": v for k, v in ranked}


# ============================================================
# 压缩包递归下钻
# ============================================================

def _is_archive(name: str) -> bool:
    p = Path(name)
    if p.suffix.lower() in ARCHIVE_EXTS:
        return True
    if p.suffix.lower() in TAR_EXTS:
        return True
    return False


def _read_members_any(
    data: bytes,
    name: str,
    per_layer: int = MAX_MEMBERS,
) -> List[Tuple[str, bytes]]:
    """按「后缀优先、magic 兜底」读取一层成员；解不开返空列表。

    为什么抽成公共函数：``_walk`` 与 ``iter_member_vectors`` 此前各写了一份
    完全相同的格式分派链。两份各自的 bug 会让「整包语义」和「逐成员语义」
    悄悄分叉 —— 而这两条链路本来就共用同一批 ``_read_*_members``。
    真正的解析只应该有一处。
    """
    low = name.lower()
    if low.endswith(".7z") or data[:6] == b"7z\xbc\xaf\x27\x1c":
        # 7z 优先：先认后缀，再认 magic（防扩展名伪装）
        return _read_7z_members(data, per_layer)
    if low.endswith(".rar") or data[:7] == b"Rar!\x1a\x07\x00":
        return _read_rar_members(data, per_layer)
    if low.endswith(".zip") or zipfile.is_zipfile(io.BytesIO(data)):
        return _read_zip_members(data, per_layer)
    members = _read_tar_members(data, per_layer)
    if not members:
        members = _read_zip_members(data, per_layer)
    if not members:
        members = _read_7z_members(data, per_layer)
    # 统一出口再裁一道：各 ``_read_*_members`` 内部用的是模块级
    # ``MAX_MEMBERS``，不知道调用方传进来的 ``per_layer``。
    if per_layer > 0 and len(members) > per_layer:
        members = members[:per_layer]
    return members


def _read_zip_members(data: bytes,
                      per_layer: int = MAX_MEMBERS,
                      ) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    pw = ARCHIVE_PASSWORD.encode("utf-8") if ARCHIVE_PASSWORD else None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            infos.sort(key=lambda i: -i.file_size)
            total = 0
            take = len(infos) if per_layer <= 0 else per_layer
            for info in infos[:take]:
                nm = info.filename
                if nm.endswith("/"):
                    continue
                # 额度核算必须基于**截断后**的长度：
                # 成员最终只贡献 min(size, MAX_MEMBER_BYTES)，用原始 size 核算会把
                # 一个 44MB 的成员当成吃掉 44MB 额度而误弃整包。
                cost = info.file_size
                if cost > MAX_MEMBER_BYTES:
                    cost = MAX_MEMBER_BYTES
                # 额度不足时 **continue 而非 break**：infos 按体积降序，
                # break 会让「第一个成员就超额度」的包直接丢光后续更小的成员
                # （111111…zip / f7cdf0…zip 实测：8 个成员里 7 个、4 个里 3 个
                #  本可正常解出，却被 break 一次性放弃 → 整包误判 a_unopenable）。
                if total + cost > MAX_TOTAL_BYTES:
                    continue
                try:
                    blob = z.read(info, pwd=pw) if pw else z.read(info)
                except (zipfile.BadZipFile, RuntimeError, OSError):
                    continue
                blob = blob[:MAX_MEMBER_BYTES]
                total += len(blob)
                out.append((nm, blob))
    except (zipfile.BadZipFile, OSError, ValueError):
        pass
    return out


def _read_tar_members(data: bytes,
                      per_layer: int = MAX_MEMBERS,
                      ) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            members = [m for m in t.getmembers() if m.isfile()]
            members.sort(key=lambda m: -m.size)
            total = 0
            take = len(members) if per_layer <= 0 else per_layer
            for m in members[:take]:
                # 与 zip 同源：额度按截断后长度核算，不足则 continue 而非 break。
                cost = m.size if m.size < MAX_MEMBER_BYTES else MAX_MEMBER_BYTES
                if total + cost > MAX_TOTAL_BYTES:
                    continue
                f = t.extractfile(m)
                if f is None:
                    continue
                blob = f.read(MAX_MEMBER_BYTES)
                total += len(blob)
                out.append((m.name, blob))
    except (tarfile.TarError, OSError, ValueError, EOFError):
        pass
    return out


# ---------------------------------------------------------------------------
# 降级可观测性（诊断用）
# ---------------------------------------------------------------------------
# 为什么需要：归档读取的最外层 `except Exception: pass` 会把「代码 bug」
# 和「样本不支持」压成同一个结果（空列表）。真出问题时完全无从下手。
# 这里用一个有界缓存记录最近若干条降级原因，调用方可通过
# drain_downgrade_notes() 取走；**不参与特征、不进模型、不影响判定**。
_DOWNGRADE_NOTES: List[str] = []
_DOWNGRADE_NOTE_CAP = 32


def drain_downgrade_notes() -> List[str]:
    """取走并清空降级原因缓存（诊断用，可随时忽略）。"""
    global _DOWNGRADE_NOTES
    notes = _DOWNGRADE_NOTES
    _DOWNGRADE_NOTES = []
    return notes


def _note_downgrade(kind: str, exc: BaseException) -> None:
    """记录一条降级原因，超出上限则丢弃最旧的。"""
    try:
        msg = "%s:%s:%s" % (kind, type(exc).__name__, str(exc)[:120])
        _DOWNGRADE_NOTES.append(msg)
        del _DOWNGRADE_NOTES[:-_DOWNGRADE_NOTE_CAP]
    except Exception:
        pass


def _read_7z_members(data: bytes) -> List[Tuple[str, bytes]]:
    """读取 7z 包内成员。依赖 py7zr；缺失或不可解均返空。

    加密包靠模块级 ARCHIVE_PASSWORD 解锁（见该常量注释）。
    """
    try:
        import py7zr  # type: ignore
    except Exception:
        return []
    out: List[Tuple[str, bytes]] = []
    tmp = None
    pw = ARCHIVE_PASSWORD or None
    try:
        import tempfile
        tmp = tempfile.mkdtemp(prefix="kdr7z_")

        # 先只读目录（拿成员名），随即关闭句柄。
        # py7zr 无 read()/readall()（1.1.3 实测二者都不存在）。
        with py7zr.SevenZipFile(io.BytesIO(data), mode="r",
                                password=pw) as z:
            names = [n for n in z.getnames() if n and not n.endswith("/")]
        names.sort()
        names = names[:MAX_MEMBERS]

        # ⚠ 每个成员都**重新打开一个 SevenZipFile**，绝不复用 with 句柄。
        # 两个实测过的死路（均为 py7zr 1.1.3 行为）：
        #   · 同一个 with 内循环 extract(targets=[n]) —— 第二次调用即死锁，
        #     223 字节的 2 成员小包都能挂 >12s（内部 worker/队列未重置）。
        #   · 批量 extract(targets=names) —— 构造整包解压上下文，包内只要有一个
        #     BCJ2 成员就无限挂起整批（老刘病毒.7z 实测）。
        #   · extractall(path) 一次整包 —— 能过，但它是「全有或全无」：一个 BCJ2
        #     成员即拖死全部，且不满足「逐成员隔离」的需求，故只作兜底。
        # 重开句柄的开销可忽略（实测 2 成员 1.02s，主要花在解压本身），
        # 换来的是 BCJ2 只影响它自己那一次调用，其余成员照常产出。
        for n in names:
            try:
                with py7zr.SevenZipFile(io.BytesIO(data), mode="r",
                                        password=pw) as z1:
                    z1.extract(path=tmp, targets=[n])
            except TypeError:
                # 极老版本 py7zr 无 targets 参数：退化为整包解压后交给体积筛选。
                try:
                    with py7zr.SevenZipFile(io.BytesIO(data), mode="r",
                                            password=pw) as z2:
                        z2.extractall(path=tmp)
                except Exception:
                    pass
                break
            except Exception:
                continue
        base = Path(tmp)
        picked: List[Tuple[str, Path]] = []
        for n in names:
            safe = Path(n)
            if safe.is_absolute() or ".." in safe.parts:
                continue
            fp = base / safe
            try:
                if not fp.is_file():
                    continue
                sz = fp.stat().st_size
            except OSError:
                continue
            # 零字节守卫：解压中断会在盘上留下 0 字节残件，
            # 把它当作「成功成员」等于喂给模型一个空样本（假阳性来源）。
            if sz <= 0:
                continue
            picked.append((n, fp))
        if not picked:
            # 全被判空 = 本包实际没解出东西，等价于降级
            return []
        picked.sort(key=lambda kv: 0 - kv[1].stat().st_size)
        total = 0
        for n, fp in picked:
            try:
                sz = fp.stat().st_size
            except OSError:
                continue
            # 与 zip/tar/rar 同源：额度按截断后长度核算，不足则 continue 而非 break。
            cost = sz if sz < MAX_MEMBER_BYTES else MAX_MEMBER_BYTES
            if total + cost > MAX_TOTAL_BYTES:
                continue
            try:
                blob = fp.read_bytes()
            except OSError:
                continue
            total += len(blob)
            out.append((n, blob[:MAX_MEMBER_BYTES]))
    except Exception as _e:
        # BCJ2 / 深层链式过滤器 / 头部加密等 py7zr 不支持的情形：降级但留痕。
        # 留痕的原因：此处曾把「API 误用」伪装成「样本不支持」（见 _note_downgrade）。
        _note_downgrade("7z", _e)
    finally:
        if tmp:
            try:
                import shutil
                shutil.rmtree(tmp, ignore_errors=True)
            except Exception:
                pass
    return out


def _unrar_exe() -> str:
    """定位 UnRAR.exe；找不到返空串。"""
    for cand in UNRAR_CANDIDATES:
        try:
            if os.path.isfile(cand):
                return cand
        except OSError:
            continue
    return ""


def _read_rar_members(data: bytes) -> List[Tuple[str, bytes]]:
    """读取 rar 包内成员。依赖外部 UnRAR.exe；缺失或失败返空。

    为什么不直接走 stdout：rar 内层往往是巨型 PE，
    管道一旦超限无法定位截断；先落临时目录再按大小筛选更可控。
    """
    exe = _unrar_exe()
    if not exe:
        return []
    import subprocess
    import tempfile
    tmp = None
    out: List[Tuple[str, bytes]] = []
    try:
        tmp = tempfile.mkdtemp(prefix="kdrrar_")
        src = os.path.join(tmp, "s.bin")
        with open(src, "wb") as f:
            f.write(data)
        dest = os.path.join(tmp, "x")
        os.makedirs(dest, exist_ok=True)
        # -inul 静默 / -o+ 覆盖 / -y 全部确认
        # 密码：有则 -p<口令>，无则 -p-（明确声明不提供口令，避免交互挂起）
        pw = ARCHIVE_PASSWORD or ""
        pflag = ("-p" + pw) if pw else "-p-"
        cmd = [exe, "x", "-inul", "-o+", pflag, "-y", src, dest + os.sep]
        # 超时随体积放大：256MB 的 rar 在 30s 内解不完（实测全 TIMEOUT）。
        # 下限 30s 保小包响应，上限 180s 防超大包拖死投喂。
        _sz = 0
        try:
            _sz = len(data)
        except Exception:
            pass
        _to = 30 + int(_sz / (4 * 1024 * 1024))
        if _to > 180:
            _to = 180
        try:
            subprocess.run(
                cmd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=_to,
                check=False,
            )
        except Exception as _e:
            _note_downgrade("rar", _e)
            return []
        base = Path(dest)
        picked: List[Tuple[str, Path]] = []
        for fp in base.rglob("*"):
            try:
                if not fp.is_file():
                    continue
                picked.append((str(fp.relative_to(base)).replace(os.sep, "/"), fp))
            except OSError:
                continue
        picked.sort(key=lambda kv: 0 - kv[1].stat().st_size)
        total = 0
        for n, fp in picked[:MAX_MEMBERS]:
            try:
                sz = fp.stat().st_size
            except OSError:
                continue
            # 与 zip/tar 同源：额度按截断后长度核算，不足则 continue 而非 break。
            cost = sz if sz < MAX_MEMBER_BYTES else MAX_MEMBER_BYTES
            if total + cost > MAX_TOTAL_BYTES:
                continue
            try:
                blob = fp.read_bytes()
            except OSError:
                continue
            blob = blob[:MAX_MEMBER_BYTES]
            total += len(blob)
            out.append((n, blob))
    except Exception as _e:
        # 加密 rar / 损坏包：降级但留痕（诊断用，不影响判定）
        _note_downgrade("rar", _e)
    finally:
        if tmp:
            try:
                import shutil
                shutil.rmtree(tmp, ignore_errors=True)
            except Exception:
                pass
    return out


def _sniff_archive(data: bytes) -> bool:
    """仅靠 magic 判断是否压缩包（防扩展名伪装）。

    与 _is_archive 的分工：_is_archive 看**名字**，本函数看**内容**。
    两者取或，才能覆盖「payload.dat 其实是 7z」这类投递手法。
    zip 用 zipfile 嗅探（能识别自解压/偏移头），tar 无可靠 magic 故不嗅探。
    """
    if not data or len(data) < 8:
        return False
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return True
    if data[:7] == b"Rar!\x1a\x07\x00" or data[:8] == b"Rar!\x1a\x07\x01\x00":
        return True
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            return True
    except Exception:
        pass
    return False


def _walk(
    data: bytes,
    name: str,
    depth: int,
    acc: FeatureVector,
    seen_names: List[str],
) -> None:
    """递归核心：是压缩包就下钻，否则提特征。

    深度判定走 ``depth_exceeded()``：``MAX_DEPTH = 0`` 时为无限下钻。
    """
    if depth_exceeded(depth):
        return
    if _is_archive(name) or _sniff_archive(data):
        members = _read_members_any(data, name)
        if not members:
            # 解不开的包，就当普通字节流提取（至少留下"这是个坏包"的信号）
            acc.merge(extract_features(data, name=name))
            acc.counts["a_unopenable"] = 1
            return
        acc.counts["a_archive"] = 1
        acc.labels["archive_kind"] = Path(name).suffix.lower()
        for mname, blob in members:
            seen_names.append(mname)
            sub = FeatureVector()
            _walk(blob, mname, depth + 1, sub, seen_names)
            acc.merge(sub)
    else:
        acc.merge(extract_features(data, name=name))


def extract_from_bytes(
    data: bytes,
    name: str = "",
    digest: str = "",
) -> FeatureVector:
    """从内存字节提取完整特征（含压缩包递归下钻）。

    通道判定优先级（高 -> 低）:
        1. 入口自身是源码类扩展名        -> text
        2. 包内存在源码类成员            -> text
        3. 入口是压缩包但成员全是二进制  -> binary
        4. 其余                          -> binary
    """
    acc = FeatureVector()
    names: List[str] = []
    _walk(data, name, 0, acc, names)
    acc.digest = digest or ""
    if names:
        # 记录内层文件名扩展名分布，是重要信号
        exts: Dict[str, int] = {}
        for nm in names:
            e = Path(nm).suffix.lower()
            if e:
                exts[e] = exts.get(e, 0) + 1
        for e, c in sorted(exts.items(), key=lambda kv: -kv[1])[:8]:
            acc.counts[f"inner{e}"] = min(8, c)
        acc.labels["members"] = str(len(names))
        acc.labels["inner_names"] = ", ".join(names[:5])[:160]

    entry_ext = Path(name).suffix.lower()
    if entry_ext in SOURCE_EXTS:
        acc.channel = "text"
    elif any(Path(nm).suffix.lower() in SOURCE_EXTS for nm in names):
        acc.channel = "text"
    else:
        acc.channel = "binary"
    return acc


def _expand_to_leaves(
    data: bytes,
    name: str,
    depth: int,
    out: List["FeatureVector"],
    budget: List[int],
    max_members: int = MAX_MEMBERS,
) -> None:
    """把一个成员**递归展开到叶**，每个叶产出一个独立向量。

    为什么需要（乙修）：``iter_member_vectors`` 早期只拆第一层，成员自身是
    压缩包时仍走 ``_walk`` —— 那会把内层 N 个文件**合并成一张大表**。
    结果是「含 2 个文件的包」这一票，维度 209，而同批的 4 个**单文件**成员
    各只有 117 维。贝叶斯**每个不同特征投一票、不做归一化**，于是
    「由几个文件凑出来的包」比「一个文件」投出更多票 —— 票数放大只是从
    「包的第一层」退到了「包的第二层」，**根没断**。
    （实测：virus.zip 拆出的 MEMZ彩虹猫病毒.zip = 209 维 vs 同级 exe ≈117 维）

    行为
        - 非归档          -> ``extract_features`` 出**一个**向量，写 ``labels["name"]``
        - 归档且 depth 未耗尽 -> 递归展开成员（**平级**，不合并）
        - 归档但 depth 已耗尽 -> 退化成 ``_walk`` 合并（与旧行为一致，**绝不丢样本**）
          （新版 ``MAX_DEPTH = 0`` 时此分支几乎不会触发，仅在达 ``HARD_DEPTH_CEILING`` 时命中）
        - 解不开的包       -> 一个带 ``a_unopenable`` 的向量（与整包语义一致）
        - 预算耗尽         -> 直接返回（调用方负责善后标记）

    注意：``name`` 只写**叶子名**（口径 A）。全路径链会与 ``feed`` 的
    ``source`` 字段重复描述「来自哪个包」这件事，而 ``labels["name"]``
    是给人工核对用的，短名更好读。
    """
    if budget[0] <= 0:
        return
    nm = name or ""
    try:
        if not (_is_archive(nm) or _sniff_archive(data)):
            fv = extract_features(data, name=nm)
            if len(fv) > 0:
                fv.labels["name"] = nm
                out.append(fv)
                budget[0] -= 1
            return

        if depth_exceeded(depth):
            # 深度耗尽：退化成整包合并语义。
            # 为什么不用 _walk 的「depth 超限直接 return（丢弃）」：
            # 那会让深层包变成**零样本**，凭空丢掉整棵子树的信息；
            # 合并成一张表至少保留「这里有个包」的信号。
            sub = FeatureVector()
            _walk(data, nm, 1, sub, [])
            if len(sub) > 0:
                sub.labels["name"] = nm
                out.append(sub)
                budget[0] -= 1
            return

        members = _read_members_any(data, nm, per_layer=max_members)
        if not members:
            # 解不开：留一个「坏包」信号，与整包提取同源
            fv = extract_features(data, name=nm)
            fv.counts["a_unopenable"] = 1
            if len(fv) > 0:
                fv.labels["name"] = nm
                out.append(fv)
                budget[0] -= 1
            return

        for mname, blob in members:
            if budget[0] <= 0:
                return
            _expand_to_leaves(blob, mname, depth + 1, out, budget,
                              max_members)
    except Exception:                        # 兜底：投喂链路不该被提取拖死
        return


def iter_member_vectors(
    data: bytes,
    name: str = "",
    *,
    max_members: int = MAX_MEMBERS,
    max_vectors: int = MAX_MEMBER_VECTORS,
) -> List["FeatureVector"]:
    """把「一个归档」拆成「每个成员一个独立特征向量」。

    与 ``extract_from_bytes`` 的分工
        extract_from_bytes  : 整包 -> **一个**合并向量（成员特征被 merge 成一张大表）
        iter_member_vectors : 整包 -> **N 个**向量（一成员 = 一样本）

    为什么需要：合并向量会让「100 个成员的包」和「1 个成员的包」在
    朴素贝叶斯里投出**数量级不同**的票数（每个不同特征投一票），
    等于一个包被重复计票。拆成逐成员向量后，票数分布与真实样本规模一致。

    行为
        - 非归档：返回 ``[self_vector]``（单元素，调用方无需分支）
        - 归档：**递归展开到叶**，每个不可再分的文件各出一个向量
          （乙修前的「只拆第一层 + 内层合并」已被证明会把票数放大
           从第一层推到第二层，根没断 —— 见 ``_expand_to_leaves``）
        - 解不开的包：返回带 ``a_unopenable`` 的单元素向量（与整包语义一致）
        - **绝不抛异常**；``err`` 标签向量会被过滤掉

    限流（双闸门，**互相独立**）
        - ``max_members``  每**一层**最多取多少成员。**仅在显式传入时才生效**
          （默认 ``MAX_MEMBERS`` 视作「不裁单层」）。理由见下方 #222 说明。
        - ``max_vectors``  **整棵包树**最多产出多少个样本（``MAX_MEMBER_VECTORS``）。
          没有它，深度无限后最坏情况 4096^k 会指数爆炸。
          截断发生时，最后一个产出的向量会带 ``truncated_members`` 标签留痕。

    注意：本函数**不做** ``inner<ext>`` / ``members`` / ``inner_names``
    这类「包级汇总特征」的补充 —— 那些属于整包语义，由
    ``extract_from_bytes`` 负责。逐成员投喂时它们会退化成噪声。
    """
    out: List["FeatureVector"] = []
    nm = name or ""
    # 单层是否被裁：_read_members_any 返回的成员数达到 max_members 即视作
    # 「这一层还有没读进来的成员」。用于 truncated_by 归因。
    layer_capped = False
    # ⚠ #222 修：旧写法在默认参数（4096, 200000）下取到 **4096**，
    # 使 MAX_MEMBER_VECTORS=200000 永不生效，深宽包整树仅产出 4096 向量
    # 后静默丢叶。两个闸门本应**独立**：
    #   max_members 管每层宽度，max_vectors 管整树产出。
    # 显式传入更小的 max_vectors 时仍取其值（后向兼容）。
    cap = max_vectors if max_vectors > 0 else MAX_MEMBER_VECTORS
    budget: List[int] = [max(1, cap)]
    # 单层宽度限制：**仅在调用方显式指定**时生效。
    # 默认值 MAX_MEMBERS 不代表调用方要「只取 4096 个成员」，
    # 它只是模块级的安全常量。若把它当整树硬顶，就回到 #222 的
    # 原始缺陷：MAX_MEMBER_VECTORS=200000 永不生效。
    # 语义：0 = 不裁单层，宽度交给 max_vectors 兜底。
    layer_limit = 0 if max_members == MAX_MEMBERS else max_members
    if layer_limit < 0:
        layer_limit = 0
    try:
        if not (_is_archive(nm) or _sniff_archive(data)):
            fv = extract_features(data, name=nm)
            if len(fv) > 0:
                out.append(fv)
            return out
        # 顶层先裁一次成员，再逐成员递归展开
        members = _read_members_any(data, nm, per_layer=layer_limit)
        if layer_limit > 0 and len(members) >= layer_limit:
            layer_capped = True
        if not members:
            # 解不开：留一个「坏包」信号，与整包提取同源
            fv = extract_features(data, name=nm)
            fv.counts["a_unopenable"] = 1
            if len(fv) > 0:
                out.append(fv)
            return out
        for mname, blob in members:
            if budget[0] <= 0:
                break
            _expand_to_leaves(blob, mname, 1, out, budget, layer_limit)
    except Exception:                        # 兜底：投喂链路不该被提取拖死
        return out
    if budget[0] <= 0 and out:
        # 触顶留痕：调用方据此知道「这个目标还有没展开的叶子」
        out[-1].labels["truncated_members"] = str(cap)
        # 区分原因（#222 D3）：
        #   budget = 整树向量预算被耗尽（还有成员没展开完）
        #   layer  = 单层成员数达到 max_members，这一层被裁
        # 判定依据是**实际发生的事**，不是事后比较 cap 与 max_vectors
        # —— 后者在 max_vectors=7、cap=7 时会误判成 budget。
        if layer_capped and layer_limit > 0 and len(out) <= layer_limit:
            out[-1].labels["truncated_by"] = "layer"
        else:
            out[-1].labels["truncated_by"] = "budget"
    return out


def extract_from_path(path: PathLike, max_bytes: int = MAX_FILE_BYTES) -> FeatureVector:
    """从文件路径提取特征。读失败返回带 err 标签的空向量。

    ⚠ 截断策略：**压缩包不截断**。
    原因：7z 的索引/头部在文件**末尾**，zip 的中央目录也在末尾。
    先截断再下钻 = 恒定 Bad7zFile（实测所有 >2MB 的 7z 全废）。
    故截断只作用于「非归档」的叶节点；归档走全量，由包内的
    MAX_MEMBERS / MAX_TOTAL_BYTES / MAX_MEMBER_BYTES 逐成员限流。
    """
    p = Path(path)
    try:
        raw = p.read_bytes()
    except (OSError, ValueError) as e:
        fv = FeatureVector()
        fv.labels["err"] = type(e).__name__
        return fv
    is_arch = _is_archive(p.name) or _sniff_archive(raw[:4096])
    if is_arch:
        # 归档：全量下钻（上限交给包内限流；超大包由 MAX_MEMBERS 兜住）
        fv = extract_from_bytes(raw, name=p.name)
    else:
        truncated = raw[:max_bytes] if len(raw) > max_bytes else raw
        fv = extract_from_bytes(truncated, name=p.name)
        if len(raw) > max_bytes:
            fv.labels["truncated"] = "1"
            fv.counts["f_truncated"] = 1
    # 轻量指纹：不存原文，只存大小+前 64KB 的 stdlib 摘要
    import hashlib
    h = hashlib.sha256()
    h.update(str(len(raw)).encode())
    h.update(raw[:65536])
    fv.digest = h.hexdigest()[:32]
    return fv
