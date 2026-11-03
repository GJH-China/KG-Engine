"""
路径安全工具
=============
统一的"路径是否位于某目录之内"判断，供扫描自我保护、插件沙箱、解压防穿越
等多处复用。

为什么需要它（这些坑都真实踩过）：
  1. **大小写**：Windows 路径不区分大小写，`"C:\\Users"` 与 `"c:\\users"` 是
     同一个目录。若用 `str.startswith()` 直接比，合法路径会被误判为越界，
     而攻击者也可能利用大小写差异绕过检查。
  2. **`..` 未归一**：必须先用 `os.path.abspath`/`Path.resolve` 归一，否则
     `root\\..\\evil` 会以 `root` 为前缀而误判为"在内部"。
  3. **前缀陷阱**：`C:\\a\\bc` 不该被 `C:\\a\\b` 判为内部。因此比较时必须
     带上分隔符（`root + os.sep`）。
  4. **盘根**：`C:\\` 规范化后是 `C:\\`，不能简单 rstrip 成 `C:`。
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, "os.PathLike[str]", Path]


def norm_for_compare(p: PathLike) -> str:
    """把路径规范化为「可比较串」：绝对路径 + 去掉尾部冗余分隔符。

    保持原有大小写（不强制小写），是否忽略大小写由调用方决定，避免在
    Linux/macOS 上把两个不同目录误判成同一个。

    注意：裸盘符 `"C:"` 会被归一到 `"C:"`（语义为"当前盘当前目录"），
    而 `"C:\\"`（盘根）保持为 `"C:\\"`。
    """
    s = str(p).strip()
    if not s:
        return ""
    # 裸盘符（"C:"）不要交给 resolve —— 它会解析成当前工作目录，语义全错
    if len(s) == 2 and s[1] == ":" and s[0].isalpha():
        return s[0].upper() + ":" if os.name == "nt" else s
    try:
        ap = os.path.abspath(s)
    except (OSError, ValueError):
        ap = s
    # 去掉尾部多余分隔符，但保留盘根（"C:\\"）与 "/"
    while len(ap) > 1 and ap[-1] in ("\\", "/"):
        if len(ap) == 3 and ap[1] == ":":   # "C:\\" 保留
            break
        ap = ap[:-1]
    return os.path.normpath(ap) if os.name == "nt" else ap


def is_within(target: PathLike, root: PathLike,
              *, resolve: bool = True, case_sensitive: Optional[bool] = None) -> bool:
    """判断 `target` 是否位于目录 `root` 之内（含 root 自身）。

    resolve=True 时会尝试解析符号链接（更严格，但要求路径真实存在）。
    解析失败时退回纯字符串归一，不会因为文件不存在就放行。
    """
    if target is None or root is None:
        return False
    ts = str(target).strip()
    rs = str(root).strip()
    if not ts or not rs:
        return False

    if resolve:
        try:
            # strict=False：允许路径尚不存在（如"即将写入"的新文件）
            ts = str(Path(ts).resolve(strict=False))
            rs = str(Path(rs).resolve(strict=False))
        except (OSError, ValueError, RuntimeError):
            pass

    t = norm_for_compare(ts)
    r = norm_for_compare(rs)
    if not t or not r:
        return False

    # 大小写：Windows 默认忽略；其它平台尊重大小写
    if case_sensitive is None:
        case_sensitive = (os.name != "nt")
    if not case_sensitive:
        t = t.lower()
        r = r.lower()

    if t == r:
        return True
    # 盘根（"c:\\"）本身以分隔符结尾，拼接时不要再补一个
    prefix = r if r.endswith(("\\", "/")) else r + os.sep
    return t.startswith(prefix)
