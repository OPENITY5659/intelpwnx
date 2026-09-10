#!/usr/bin/env bash
# 把 venv 里的云端 LibcSearcher 换成纯本地实现（先备份，可回滚）。
#
#   bash scripts/install_local_libcsearcher.sh [venv_path]
#
# 默认 venv：/mnt/d/AWDP/.venv-linux（AWDP 的 WSL 环境，pwnpasi 与 PwnSolver 共用）
set -euo pipefail

VENV="${1:-/mnt/d/AWDP/.venv-linux}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/pwn_solver/vendor/LibcSearcher"
SITE="$VENV/lib/python3.14/site-packages"
DST="$SITE/LibcSearcher"
BACKUP="$SITE/LibcSearcher.cloud.bak"

if [ ! -d "$SRC" ]; then
  echo "[-] 找不到本地实现源码: $SRC"; exit 1
fi
if [ ! -d "$SITE" ]; then
  echo "[-] 找不到 site-packages: $SITE（venv 路径给对了吗？）"; exit 1
fi

# 1) 生成 db/（若还没有）
if [ ! -d "$SRC/db" ] || [ -z "$(ls -A "$SRC/db" 2>/dev/null)" ]; then
  echo "[*] 生成 LibcSearcher 的本地 db/ ..."
  "$VENV/bin/python" "$REPO/scripts/build_libcsearcher_db.py" | tail -3
fi

# 2) 备份云端实现（只备份一次）
if [ -d "$DST" ] && [ ! -d "$BACKUP" ]; then
  cp -r "$DST" "$BACKUP"
  echo "[*] 已备份原实现到 $BACKUP"
fi

# 3) 换成本地实现（连同 db/ 一起）
rm -rf "$DST"
cp -r "$SRC" "$DST"
echo "[*] 已安装本地 LibcSearcher → $DST"
echo "    db 条目数: $(ls "$DST/db" 2>/dev/null | grep -c '\.symbols$' || echo 0)"

# 4) 冒烟测试
"$VENV/bin/python" - <<'PY'
from LibcSearcher import LibcSearcher
addr = 0x7f0a1c5b0000 + 0x84420          # 低 12 位对齐 Ubuntu 20.04 的 puts
lc = LibcSearcher("puts", addr)
print('候选数:', len(lc))
if len(lc) > 1:
    lc.select_libc(0)
print(lc)
print('dump(system) =', hex(lc.dump('system')), ' dump(str_bin_sh) =', hex(lc.dump('str_bin_sh')))
PY
echo "[✓] 本地 LibcSearcher 可用（回滚：rm -rf $DST && mv $BACKUP $DST）"
