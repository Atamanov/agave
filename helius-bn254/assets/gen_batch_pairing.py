#!/usr/bin/env python3
"""Render batch-pairing.png: microseconds per BN254 pairing when the Miller
loops run eight lanes wide on AVX-512 IFMA, helius against mcl, on three x64
server microarchs. Single-thread, taskset-pinned, native flags; helius and mcl
measured on the same host per column. July 2026."""
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# us per pairing (full pairing: Miller loop + final exponentiation).
# helius: 8-wide IFMA batch. mcl: scalar (it ships no BN254 IFMA).
ROWS = [
    ("Intel Granite Rapids\nXeon 6767P", 137.0, 311.0),
    ("AMD Zen 4\nEPYC 9354", 178.5, 412.6),
    ("Intel Ice Lake\nXeon 8352V*", 353.8, 617.4),
]
FOOTNOTE = "* Ice Lake measured before the squaring-aware tower; understates helius."
HELIUS, MCL = "#2f6fb0", "#e08a2c"

labels = [r[0] for r in ROWS]
helius = np.array([r[1] for r in ROWS])
mcl = np.array([r[2] for r in ROWS])
x = np.arange(len(ROWS))
w = 0.34

fig, ax = plt.subplots(figsize=(9.2, 4.4), dpi=200)
b1 = ax.bar(x - w / 2, helius, w, label="helius (8-wide IFMA)", color=HELIUS)
b2 = ax.bar(x + w / 2, mcl, w, label="mcl", color=MCL)

for i in range(len(ROWS)):
    ax.text(x[i] - w / 2, helius[i] + 8, f"{helius[i]:.0f}", ha="center", va="bottom",
            fontsize=10, color="#333")
    ax.text(x[i] + w / 2, mcl[i] + 8, f"{mcl[i]:.0f}", ha="center", va="bottom",
            fontsize=10, color="#333")
    ax.annotate(f"{mcl[i] / helius[i]:.2f}x faster", (x[i] - w / 2, helius[i] / 2),
                ha="center", va="center", fontsize=11, color="white", weight="bold")

ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=11)
ax.set_ylabel("microseconds per pairing (lower is better)", fontsize=11)
ax.set_title("BN254 pairing, 8-wide IFMA batch: helius vs mcl", fontsize=13, weight="bold",
             pad=24)
ax.text(0, 1.012, FOOTNOTE, transform=ax.transAxes, fontsize=8.5, color="#666",
        ha="left", va="bottom")
ax.legend(frameon=False, fontsize=10, loc="upper left")
ax.spines[["top", "right"]].set_visible(False)
ax.set_ylim(0, max(mcl) * 1.15)
ax.grid(axis="y", color="#e5e5e5", linewidth=0.8)
ax.set_axisbelow(True)
fig.tight_layout()
fig.savefig(__file__.rsplit("/", 1)[0] + "/batch-pairing.png", bbox_inches="tight")
print("wrote batch-pairing.png")
