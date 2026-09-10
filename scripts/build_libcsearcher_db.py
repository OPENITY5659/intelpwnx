#!/usr/bin/env python3
"""把本地已有的 libc 数据生成为 LibcSearcher 的 db/（libc-database 风格）。

生成后，本地版 LibcSearcher（pwn_solver/vendor/LibcSearcher）就是自包含的：
不需要联网、也不依赖 PwnSolver 的 JSON 索引，任何 `from LibcSearcher import LibcSearcher`
的代码（PwnSolver、pwnpasi…）直接就能在本地匹配。

数据来源（都是本地文件）：
  - pwn_solver/libc_db/libcrip.json   libc.rip 整库 dump（几千个版本，核心 8 符号）
  - pwn_solver/libc_db/index.json     本地真实 .so 的索引（符号全，且带 libc_path）

输出目录（默认 pwn_solver/vendor/LibcSearcher/db）：
  <id>.symbols    每行 `symbol 0xoffset`（十六进制）
  <id>.info       version / arch / buildid / url / libc_path

用法：
    python3 scripts/build_libcsearcher_db.py
    python3 scripts/build_libcsearcher_db.py --out /path/to/db --only-core   # 只导核心符号
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(ROOT, 'pwn_solver', 'libc_db')
DEFAULT_OUT = os.path.join(ROOT, 'pwn_solver', 'vendor', 'LibcSearcher', 'db')

# 识别只需要这几个符号；本地真实 .so 的条目会带上全部已解析符号
CORE_SYMBOLS = ('puts', 'system', 'printf', 'read', 'write', 'dup2',
                'str_bin_sh', '__libc_start_main', '__libc_start_main_ret')


def write_entry(out_dir, libc_id, symbols, info):
    if not libc_id or not symbols:
        return False
    safe = libc_id.replace('/', '_').replace('\\', '_')
    with open(os.path.join(out_dir, safe + '.symbols'), 'w', encoding='utf-8') as f:
        for name in sorted(symbols):
            f.write(f'{name} 0x{symbols[name]:x}\n')
    with open(os.path.join(out_dir, safe + '.info'), 'w', encoding='utf-8') as f:
        for key, value in info.items():
            if value:
                f.write(f'{key}: {value}\n')
    return True


def main():
    ap = argparse.ArgumentParser(description='生成 LibcSearcher 的本地 db/')
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--only-core', action='store_true',
                    help='只导出核心识别符号（默认：本地 .so 条目导出全部已解析符号）')
    args = ap.parse_args()

    os.makedirs(args.out, exist_ok=True)
    written = 0

    # 1) libc.rip 整库（识别用）
    libcrip = os.path.join(DB_DIR, 'libcrip.json')
    if os.path.exists(libcrip):
        with open(libcrip, encoding='utf-8') as f:
            data = json.load(f)
        for libc_id, item in data.items():
            symbols = {k: v for k, v in (item.get('symbols') or {}).items()
                       if isinstance(v, int)}
            if args.only_core:
                symbols = {k: v for k, v in symbols.items() if k in CORE_SYMBOLS}
            if write_entry(args.out, libc_id,
                           symbols,
                           {'version': item.get('version'), 'arch': item.get('arch'),
                            'buildid': item.get('buildid'),
                            'url': item.get('download_url')}):
                written += 1
        print(f'[db] libc.rip 整库导出 {written} 个')
    else:
        print(f'[db] 跳过 libc.rip（缺 {libcrip}，先跑 scripts/dump_libcrip_db.py）')

    # 2) 本地真实 .so 的索引（符号全 + 带路径，dump() 能回答任意符号）
    index = os.path.join(DB_DIR, 'index.json')
    local = 0
    if os.path.exists(index):
        with open(index, encoding='utf-8') as f:
            data = json.load(f)
        for item in data.get('entries', []):
            symbols = {k: v for k, v in (item.get('symbols') or {}).items()
                       if isinstance(v, int)}
            libc_id = os.path.basename(item.get('path') or '') or item.get('path')
            # 版本化的 id 更利于人读：glibc-2.31-... 这种目录名带上版本
            version = item.get('libc_version') or 'unknown'
            arch = item.get('arch') or 'amd64'
            libc_id = f'local-{version}-{arch}-{libc_id}'
            if write_entry(args.out, libc_id, symbols,
                           {'version': version, 'arch': arch,
                            'libc_path': item.get('path'),
                            'url': (item.get('source') or '')}):
                local += 1
        print(f'[db] 本地真实 .so 导出 {local} 个（含 libc_path，能回答任意符号）')
    else:
        print(f'[db] 跳过本地索引（缺 {index}）')

    total = len([n for n in os.listdir(args.out) if n.endswith('.symbols')])
    print(f'[db] 共 {total} 个条目 → {args.out}')
    print('[db] 下一步：把 pwn_solver/vendor/LibcSearcher 装到目标环境，'
          '或设 LIBCSEARCHER_DB 指向该 db 目录')
    return 0


if __name__ == '__main__':
    sys.exit(main())
