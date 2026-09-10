#!/usr/bin/env python3
"""把 libc.rip 的整库符号表 dump 到本地（一次联网，之后完全离线匹配）。

这就是 LibcSearcher 用的那套 API，只是把"每次求解都联网查"换成"提前把库拉下来"：

  POST https://libc.rip/api/find
       Content-Type: application/json          ← 必须带，否则服务端 500
       {"symbols": {"puts": "0x420"}}
  返回一个数组，每项含 id / version / buildid / sha256 / symbols（完整符号表）

枚举方式：libc.rip 按"符号偏移的低 12 位"匹配，所以只要把某个符号（默认 puts，
几乎每个 libc 都有）的低 12 位从 0x000 遍历到 0xfff，每个值查一次，把返回的所有 libc
合并起来，就能覆盖整库 —— 4096 次请求，约几十 MB。

产物：pwn_solver/libc_db/libcrip.json  →  {id: {version, arch, buildid, sha256, symbols}}
进度可断点续跑（libcs/.libcrip_progress.json），中断后重跑会跳过已完成的值。

用法：
    python3 scripts/dump_libcrip_db.py --estimate          # 只看进度/规模，不请求
    python3 scripts/dump_libcrip_db.py                     # 全量枚举（默认 puts）
    python3 scripts/dump_libcrip_db.py --symbols puts,system
    python3 scripts/dump_libcrip_db.py --limit 200         # 只跑 200 个值（试跑/续跑）
"""
import argparse
import json
import os
import re
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'pwn_solver'))
DB_PATH = os.path.join(ROOT, 'pwn_solver', 'libc_db', 'libcrip.json')
PROGRESS_PATH = os.path.join(ROOT, 'libcs', '.libcrip_progress.json')
API_FIND = 'https://libc.rip/api/find'
HEADERS = {
    'User-Agent': 'pwnsolver-offline-dump/1.0',
    'Content-Type': 'application/json',   # 不带这个 libc.rip 直接 500
}


def load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f:
                return json.load(f)
        except ValueError:
            pass
    return default


def save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)


def find_by_offset(symbol, value, retries=3, timeout=25):
    """查一个低 12 位值，返回 libc 列表（失败返回 None）。"""
    import requests
    payload = {'symbols': {symbol: '0x%03x' % value}}
    for attempt in range(retries):
        try:
            resp = requests.post(API_FIND, data=json.dumps(payload),
                                 headers=HEADERS, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (400, 404):
                return []          # 这个值没有匹配，属正常
            time.sleep(1.5 * (attempt + 1))
        except Exception:
            time.sleep(1.5 * (attempt + 1))
    return None


def _sym_value(value):
    """libc.rip 的符号偏移是十六进制字符串（如 '0x80e50' 或 '80e50'），也可能是整数。"""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 16)
        except ValueError:
            return None
    return None


def entry_from_hit(hit):
    """从 /api/find 的一条结果里抽出我们需要的字段。"""
    symbols = {}
    for key, raw in (hit.get('symbols') or {}).items():
        val = _sym_value(raw)
        if val is not None:
            symbols[key] = val
    libc_id = hit.get('id') or ''
    arch = 'i386' if libc_id.rstrip().endswith('i386') or '_i386' in libc_id else 'amd64'
    version = None
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', libc_id)
    if m:
        version = m.group(1)
    # 版本线取前两位（2.31-0ubuntu9.9 → 2.31），便于按"版本线"筛选
    major = None
    if version:
        parts = version.split('.')
        major = '.'.join(parts[:2])
    return {
        'id': libc_id,
        'version': version,
        'major': major,
        'arch': arch,
        'buildid': hit.get('buildid'),
        'sha256': hit.get('sha256'),
        'download_url': hit.get('download_url'),
        'symbols': symbols,
    }


def main():
    ap = argparse.ArgumentParser(description='dump libc.rip 整库符号表到本地')
    ap.add_argument('--symbols', default='puts',
                    help='用于枚举的符号，逗号分隔（默认 puts）')
    ap.add_argument('--limit', type=int, default=0, help='只处理 N 个值（试跑/续跑）')
    ap.add_argument('--sleep', type=float, default=0.15, help='每次请求间隔秒')
    ap.add_argument('--estimate', action='store_true', help='只报告进度与规模')
    args = ap.parse_args()

    db = load_json(DB_PATH, {})
    progress = load_json(PROGRESS_PATH, {'done': {}, 'symbols': []})

    for symbol in [s.strip() for s in args.symbols.split(',') if s.strip()]:
        done = set(progress.setdefault('done', {}).get(symbol, []))
        values = [v for v in range(0x1000) if v not in done]
        print(f'[dump] 符号 {symbol}: 已完成 {len(done)}/4096，待查 {len(values)}，'
              f'本地已有 {len(db)} 个 libc', flush=True)
        if args.estimate:
            continue
        if args.limit:
            values = values[:args.limit]
        if symbol not in progress['symbols']:
            progress['symbols'].append(symbol)

        empty = failed = 0
        t0 = time.time()
        for i, value in enumerate(values, 1):
            hits = find_by_offset(symbol, value)
            if hits is None:
                failed += 1
                continue
            if not hits:
                empty += 1
            for hit in hits:
                if not isinstance(hit, dict) or not hit.get('id'):
                    continue
                db[hit['id']] = entry_from_hit(hit)
            done.add(value)
            if i % 25 == 0:
                rate = i / max(time.time() - t0, 1e-6)
                print(f'  [{symbol}] {i}/{len(values)} 值  命中库 {len(db)} 个 libc  '
                      f'空 {empty} 失败 {failed}  {rate:.1f} 值/秒', flush=True)
                progress['done'][symbol] = sorted(done)
                save_json(PROGRESS_PATH, progress)
                save_json(DB_PATH, db)
            time.sleep(args.sleep)

        progress['done'][symbol] = sorted(done)
        save_json(PROGRESS_PATH, progress)
        save_json(DB_PATH, db)
        print(f'[dump] 符号 {symbol} 完成：库内 {len(db)} 个 libc，'
              f'空 {empty}，失败 {failed}', flush=True)

    save_json(DB_PATH, db)
    versions = {}
    for item in db.values():
        versions[(item.get('version') or '?', item.get('arch'))] = \
            versions.get((item.get('version') or '?', item.get('arch')), 0) + 1
    print(f'[dump] libcrip.json 共 {len(db)} 个 libc，覆盖 '
          f'{len(versions)} 组 (版本,架构) → {DB_PATH}')
    print('[dump] 下一步：python3 pwnsolver.py libcdb build 合并进离线索引')
    return 0


if __name__ == '__main__':
    sys.exit(main())
