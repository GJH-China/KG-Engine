# -*- coding: utf-8 -*-
"""KG 引擎最小可用示例 —— 跑通「提特征 → 训练 → 预测 → 落盘 → 重新加载」。

不需要任何第三方库。在仓库根目录执行：

    python examples/quickstart.py

这个示例刻意做成「良性 vs 可疑」的对照：
  · 良性侧 = 你机器上 Python 安装目录里的 DLL（真实、无标注成本）
  · 可疑侧 = 一段随机字节（高熵，模拟加壳/加密载荷）
目的是让你看到 score 和 contributions 是**怎么被特征推动的**，
而不是只看到一个孤零零的数字。
"""
import os
import sys
import glob
import random

# 让脚本能直接 import 到仓库里的 kaederonm_kg（不装包也能跑）
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kaederonm_kg import (          # noqa: E402
    KGModel, FeatureStore, extract_features, extract_from_path,
)


def collect_benign(n=25):
    """从 Python 安装目录捡一批 DLL 当良性样本。

    两个坑：
      1. 不能用 `dirname(sys.executable)` —— venv 里那是 `.venv/Scripts`，一个 DLL 都没有
      2. 光用 `sys.base_prefix` 也不够 —— CPython 把扩展模块放在 `<base>/DLLs` 子目录，
         根目录只有 4 个。所以 DLLs 和 sys.path 里的各个目录都要扫。
    """
    roots = [os.path.join(sys.base_prefix, "DLLs"), sys.base_prefix]
    roots += [p for p in sys.path if p and os.path.isdir(p)]

    files = []
    for root in dict.fromkeys(roots):        # 去重且保序
        for pat in ("*.dll", "*.pyd"):
            files.extend(glob.glob(os.path.join(root, pat)))
    files = [f for f in files if os.path.getsize(f) > 4096]
    random.seed(42)
    random.shuffle(files)
    return files[:n]


def show(pred, title):
    print("  %-28s score = %+8.2f  %-6s votes=%d"
          % (title, pred.score, "恶意" if pred.is_malicious else "正常", pred.votes))
    top = [(k, v) for k, v in pred.contributions
           if k not in ("__prior_only__", "__no_feature__")][:4]
    for name, val in top:
        print("      %+9.2f  %-22s %s" % (val, name, "偏恶意" if val > 0 else "偏良性"))


def main():
    print("=" * 70)
    print("凯德荣 KG 引擎 · 快速开始")
    print("=" * 70)

    # ---------- 1. 良性样本 ----------
    benign = collect_benign(25)
    if len(benign) < 5:
        print("样本不足，换个环境再试")
        return
    print("良性样本：%d 个（Python 安装目录的 DLL/PYD）" % len(benign))

    # ---------- 2. 恶意侧：合成高熵块 ----------
    # 真实的恶意样本不便随仓库分发，这里用随机字节**模拟加壳/加密载荷**：
    # 字节分布接近均匀、熵接近 8.0，正是加壳样本最典型的统计特征。
    # 🔴 必须两侧都有样本才能训练出可用的分类器 —— 只有良性一侧时，
    #    似然比算不出来，predict() 只会返回先验（votes=0）。
    random.seed(7)
    fake_mal = [bytes(random.getrandbits(8) for _ in range(48 * 1024)) for _ in range(12)]
    print("恶意侧样本：%d 个（合成高熵块，仅用于演示机制）" % len(fake_mal))

    # ---------- 3. 训练 ----------
    model = KGModel()
    for p in benign:
        model.learn(extract_from_path(p), label="ben")
    for blob in fake_mal:
        model.learn(extract_features(blob, name="packed.dat"), label="mal")
    print("投喂完成，模型样本总数 = %d（良性 %d / 恶意 %d）"
          % (model.total_samples, len(benign), len(fake_mal)))

    # ---------- 4. 对照预测 ----------
    print()
    print("=" * 70)
    print("预测对照")
    print("=" * 70)

    holdout = benign[-1]                      # 留一个没投喂过的良性样本
    rnd = bytes(random.getrandbits(8) for _ in range(64 * 1024))   # 全新的高熵载荷

    show(model.predict(extract_from_path(holdout)), "未投喂的良性 DLL")
    print()
    show(model.predict(extract_features(rnd, name="new_payload.dat")),
         "全新的高熵载荷")

    print()
    print("=" * 70)
    print("解读")
    print("=" * 70)
    print("  上面每一项 contributions 都是引擎判定的**实际依据**：")
    print("  良性 DLL 命中的是 DLL 常见的字节模式与 PE 结构特征，票数偏负；")
    print("  高熵载荷命中的是随机分布带来的特征，票数偏正。")
    print()
    print("  ⚠️ 这是**机制演示**，不是真实检测能力：恶意侧是合成数据、")
    print("     样本量也只有几十条。真实模型需要数千条两侧样本，")
    print("     成绩见 docs/RELEASES.md。")

    # ---------- 5. 落盘与重新加载 ----------
    store_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_demo_store")
    store = FeatureStore(store_dir)
    ok = store.save(model)
    print()
    print("模型落盘: %s" % ("成功 -> " + store_dir if ok else "失败: " + str(store.last_error)))

    model2 = store.load()               # 坏档也不会抛异常，只返回空模型
    p2 = model2.predict(extract_features(rnd, name="new_payload.dat"))
    print("重新加载后重新预测那个载荷：score = %+.2f（应与上面一致）" % p2.score)


if __name__ == "__main__":
    main()
