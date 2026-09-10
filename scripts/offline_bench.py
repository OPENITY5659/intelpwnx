#!/usr/bin/env python3
"""离线 PWN 基准：对持久化语料逐个跑 PwnSolver，落盘可复现的结果。

与 scripts/ciscn_bench.py 的区别：
  - 语料根在仓库内（默认 challenges/ + external_challs 的 heap/fmtstr/stackoverflow），
    不再依赖 /tmp 那类重启即失的临时目录；
  - 记录"用了哪个方法成功"以及"堆题是否被栈方法误判成功"的可疑标记；
  - 结果写 reports/offline_<tag>.{json,md}，可直接前后对比。

用法（在 WSL / Linux 侧跑）：
  python3 scripts/offline_bench.py --tag offline_baseline
  python3 scripts/offline_bench.py --tag t1 --roots challenges --timeout 90
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'pwnsolver.py'
FALLBACK_ENTRY = ROOT / 'pwn_solver' / 'solver.py'

DEFAULT_ROOTS = [
    'challenges',
    'external_challs/ctf-challenges/pwn/linux/user-mode/heap',
    'external_challs/ctf-challenges/pwn/linux/user-mode/fmtstr',
    'external_challs/ctf-challenges/pwn/linux/user-mode/stackoverflow',
]

# 这些策略/方法出现时，若题目本身是堆题/格式串题，需要人工复核是否误判成功
STACK_METHODS = ('ret2win', 'ret2libc', 'rop', 'one_gadget', 'stack_pivot', 'ret2syscall')
HEAP_HINTS = ('heap', 'uaf', 'tcache', 'fastbin', 'chunk', 'unsorted', 'unlink', 'house')


def is_elf(path: Path) -> bool:
    try:
        with open(path, 'rb') as f:
            return f.read(4) == b'\x7fELF'
    except OSError:
        return False


def looks_like_aux(name: str) -> bool:
    low = name.lower()
    if low.startswith('lib') or low.startswith('ld-') or low.startswith('ld.so'):
        return True
    return low.endswith('.so') or '.so.' in low


def find_targets(root: Path):
    out = []
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name.startswith('core') or looks_like_aux(name):
            continue
        if is_elf(path):
            out.append(path)
    return out


def detect_aux(binary: Path):
    """在题目目录（及上级）里找配对的 libc / loader，纯文件名+ELF 判定，不联网。"""
    libc = ld = None
    for base in (binary.parent, binary.parent.parent):
        if not base or not base.is_dir():
            continue
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        for name in names:
            path = base / name
            low = name.lower()
            if libc is None and low.startswith('libc') and (
                    low == 'libc' or low.startswith('libc.so') or low.startswith('libc-')) and is_elf(path):
                libc = path
            if ld is None and ('ld-linux' in low or low.endswith('.so.2') and low.startswith('ld-')) and is_elf(path):
                ld = path
        if libc or ld:
            break
    # glibc 2.23 附件常不带 loader；仓库内有 glibc_compat 兜底
    if libc and not ld and '2.23' in Path(libc).name:
        compat = ROOT / 'pwn_solver' / 'glibc_compat' / 'ld-2.23.so'
        if compat.is_file():
            ld = compat
    return libc, ld


def parse_output(text: str):
    info = {'solved': False, 'method': None, 'strategy': None, 'confidence': None,
            'diagnosis': None, 'saved_exploit': None, 'patterns': None}
    if '解题成功' in text:
        info['solved'] = True
    m = re.search(r'方法: ([^()\n]+)', text)
    if m:
        info['method'] = m.group(1).strip()
    m = re.search(r'选择策略: (\w+) \(置信度: (\d+)\)', text)
    if m:
        info['strategy'], info['confidence'] = m.group(1), int(m.group(2))
    # 失败诊断段落的 "  类型: X"（不要匹配到 "[+] 文件类型: ELF"）
    m = re.search(r'^\s{2}类型: (\S+)', text, re.M)
    if m:
        info['diagnosis'] = m.group(1)
    m = re.search(r'泛化模式: (.+)', text)
    if m:
        info['patterns'] = m.group(1).strip()
    m = re.search(r'Exploit已保存到: (\S+)', text)
    if m:
        info['saved_exploit'] = m.group(1)
    return info


def run_one(binary: Path, timeout: int, mode: str):
    libc, ld = detect_aux(binary)
    cmd = [sys.executable, str(ENTRY), mode, str(binary), '-t', '20']
    if libc:
        cmd += ['-l', str(libc)]
    if ld:
        cmd += ['-d', str(ld)]
    start = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              cwd=str(ROOT))
        rc, out, err = proc.returncode, proc.stdout or '', proc.stderr or ''
    except subprocess.TimeoutExpired as exc:
        rc = -999
        out = (exc.stdout or b'').decode('utf-8', 'ignore') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
        err = (exc.stderr or b'').decode('utf-8', 'ignore') if isinstance(exc.stderr, bytes) else (exc.stderr or '')
    elapsed = round(time.time() - start, 2)
    text = out + '\n' + err
    info = parse_output(text)
    info = dict(info)
    info.update({
        'binary': str(binary),
        'relative': str(binary.relative_to(ROOT)) if str(binary).startswith(str(ROOT)) else str(binary),
        'mode': mode,
        'rc': rc,
        'elapsed': elapsed,
        'libc': str(libc) if libc else None,
        'ld': str(ld) if ld else None,
    })
    # 堆题被栈方法"解出"是最需要人复核的假阳性形态
    target_name = str(binary).lower()
    looks_heap = any(h in target_name for h in HEAP_HINTS)
    info['suspect_heap_stack_mismatch'] = bool(
        info['solved'] and looks_heap and (info['method'] or '') and
        any(m in (info['method'] or '') for m in STACK_METHODS)
    )
    tail = [ln for ln in (out.strip().splitlines() + err.strip().splitlines()) if ln.strip()][-6:]
    info['tail'] = tail
    return info


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tag', default='last')
    ap.add_argument('--roots', nargs='*', default=DEFAULT_ROOTS)
    ap.add_argument('--timeout', type=int, default=120, help='单个题目墙钟上限（秒）')
    ap.add_argument('--mode', default='solve', choices=['solve', 'recon'])
    ap.add_argument('--limit', type=int, default=0, help='每个 root 只跑前 N 题（0=全部）')
    ap.add_argument('--count-only', action='store_true', help='只统计每个 root 的目标数，不跑题')
    args = ap.parse_args()

    results = []
    for rel in args.roots:
        root = Path(rel)
        if not root.is_absolute():
            root = ROOT / rel
        if not root.exists():
            print(f'[skip] 语料根不存在: {root}', flush=True)
            continue
        targets = find_targets(root)
        if args.count_only:
            print(f'{root}: {len(targets)} 个 ELF 目标', flush=True)
            continue
        if args.limit:
            targets = targets[:args.limit]
        print(f'=== {root}  ({len(targets)} 个 ELF 目标)', flush=True)
        for binary in targets:
            r = run_one(binary, args.timeout, args.mode)
            results.append(r)
            flag = 'SOLVED' if r['solved'] else 'FAILED'
            warn = ' [可疑: 堆题用栈方法]' if r['suspect_heap_stack_mismatch'] else ''
            print(f"{flag} | {r['relative']} | {r['elapsed']}s | "
                  f"策略={r['strategy']} 方法={r['method']} 诊断={r['diagnosis']}{warn}", flush=True)

    out_dir = ROOT / 'reports'
    out_dir.mkdir(exist_ok=True)
    solved = sum(1 for r in results if r['solved'])
    payload = {
        'generated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'entry': str(ENTRY),
        'roots': args.roots,
        'mode': args.mode,
        'timeout': args.timeout,
        'total': len(results),
        'solved': solved,
        'suspects': sum(1 for r in results if r['suspect_heap_stack_mismatch']),
        'results': results,
    }
    (out_dir / f'offline_{args.tag}.json').write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')

    lines = [f'# 离线 PWN 基准 ({args.tag})', '',
             f"- 时间: {payload['generated_at']}",
             f"- 入口: `{ENTRY}`",
             f"- 语料根: {', '.join(args.roots)}",
             f"- 结果: **{solved}/{len(results)}** 解出，可疑假阳 {payload['suspects']} 个", '']
    for r in results:
        lines.append(f"## {r['relative']}")
        lines.append(f"- rc={r['rc']} elapsed={r['elapsed']}s success={r['solved']}")
        lines.append(f"- 策略: {r['strategy']}@{r['confidence']} 方法: {r['method']}")
        lines.append(f"- 诊断: {r['diagnosis']} 模式: {r['patterns']}")
        lines.append(f"- aux: libc={r['libc']} ld={r['ld']}")
        if r['suspect_heap_stack_mismatch']:
            lines.append('- ⚠ 可疑: 堆题被栈方法判为成功，需人工复核')
        if r['tail']:
            lines.append('- 末尾输出:')
            for ln in r['tail']:
                lines.append(f"  - `{ln[:200]}`")
        lines.append('')
    (out_dir / f'offline_{args.tag}.md').write_text('\n'.join(lines), encoding='utf-8')
    print(f"\n== 汇总: {solved}/{len(results)} 解出 → reports/offline_{args.tag}.json|md", flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
