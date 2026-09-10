#!/usr/bin/env python3
"""Web CTF 批量验证: 遍历题目源码目录, 逐题跑 web_solver 并汇总报告。

模式:
  analyze  仅静态判型(不需要靶机环境), 验证分类器覆盖度
  solve    对每题尝试起环境并动态打 payload 找 flag(需要 docker/php)

用法:
  python3 scripts/web_bench.py --root external_challs/web_challs --mode analyze --tag web
  python3 scripts/web_bench.py --mode solve --limit 20
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ROOT / 'external_challs' / 'web_challs'
ENTRY = ROOT / 'pwnsolver.py'

# 判定为"题目目录"的标志: 含源码或 docker 文件
CHALL_HINTS = ('.php', '.py', '.js', '.java', '.go', 'docker-compose.yml',
               'docker-compose.yaml', 'Dockerfile')


def find_challenges(root: Path):
    """遍历 root, 返回所有疑似题目目录(含 web 源码的叶子目录)。"""
    out = []
    for dirpath, dirnames, filenames in __import__('os').walk(root):
        d = Path(dirpath)
        # 跳过 _zips / .git
        parts = set(d.parts)
        if '_zips' in parts or '.git' in parts:
            continue
        lower = {f.lower() for f in filenames}
        has_src = any(f.endswith(('.php', '.py', '.js', '.java', '.go'))
                      for f in lower)
        has_docker = any(h.lower() in lower for h in
                         ('docker-compose.yml', 'docker-compose.yaml', 'dockerfile'))
        if has_src or has_docker:
            out.append(d)
            dirnames[:] = []  # 不再深入, 该目录整体算一道题
    return sorted(set(out))


def run_one(chall_dir: Path, mode: str, timeout: int):
    cmd = [sys.executable, str(ENTRY), 'websolve', str(chall_dir)]
    if mode == 'analyze':
        cmd += ['--analyze-only']
    cmd += ['--json', '-t', '10']
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              errors='replace', timeout=timeout)
        text = proc.stdout or ''
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        return {'path': str(chall_dir), 'name': chall_dir.name, 'mode': mode,
                'rc': -999, 'elapsed': timeout, 'success': False,
                'error': 'benchmark timeout'}
    elapsed = round(time.time() - started, 2)
    # 从 stdout 最后一行 JSON 提取
    data = {}
    try:
        # websolve --json 把 SolveResult.__dict__ 打到 stdout
        start = text.find('{')
        if start >= 0:
            data = json.loads(text[start:])
    except Exception:
        data = {}
    return {
        'path': str(chall_dir),
        'name': data.get('path', str(chall_dir)).split('/')[-1] or chall_dir.name,
        'mode': mode,
        'rc': rc,
        'elapsed': elapsed,
        'stack': data.get('stack', 'unknown'),
        'framework': data.get('framework', ''),
        'primary_vuln': data.get('primary_vuln', 'unknown'),
        'confidence': data.get('confidence', 0),
        'top_vulns': data.get('top_vulns', []),
        'env_kind': data.get('env_kind', ''),
        'success': bool(data.get('success')),
        'flag': data.get('flag', ''),
        'payload_desc': data.get('payload_desc', ''),
        'attempts': data.get('attempts', 0),
        'error': data.get('error', '') if not data.get('success') else '',
    }


def main():
    ap = argparse.ArgumentParser(description='Web CTF 批量验证')
    ap.add_argument('--root', default=str(DEFAULT_ROOT))
    ap.add_argument('--mode', choices=['analyze', 'solve'], default='analyze')
    ap.add_argument('--timeout', type=int, default=120)
    ap.add_argument('--tag', default='last')
    ap.add_argument('--limit', type=int, default=0, help='最多验证多少题(0=全部)')
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f'[-] 目录不存在: {root}')
        return 1
    challs = find_challenges(root)
    if args.limit:
        challs = challs[:args.limit]
    print(f'[*] 在 {root} 下发现 {len(challs)} 个题目目录, 模式={args.mode}')

    results = []
    for i, c in enumerate(challs, 1):
        print(f'[{i}/{len(challs)}] {c.relative_to(root)}', flush=True)
        r = run_one(c, args.mode, args.timeout)
        results.append(r)
        mark = '✅' if r['success'] else '  '
        print(f"    {mark} {r['primary_vuln']}@{r['confidence']} "
              f"stack={r['stack']} elapsed={r['elapsed']}s", flush=True)

    # 汇总
    total = len(results)
    solved = sum(1 for r in results if r['success'])
    classified = sum(1 for r in results if r['primary_vuln'] != 'unknown')
    from collections import Counter
    vuln_dist = Counter(r['primary_vuln'] for r in results)
    stack_dist = Counter(r['stack'] for r in results)

    report = {
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'root': str(root), 'mode': args.mode,
        'total': total, 'solved': solved, 'classified': classified,
        'vuln_distribution': dict(vuln_dist.most_common()),
        'stack_distribution': dict(stack_dist.most_common()),
        'results': results,
    }
    out_dir = ROOT / 'reports'
    out_dir.mkdir(exist_ok=True)
    out_json = out_dir / f'web_bench_{args.tag}.json'
    out_md = out_dir / f'web_bench_{args.tag}.md'
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2),
                        encoding='utf-8')

    lines = [f'# Web CTF 批量验证 ({args.mode})', '',
             f'- root: `{root}`', f'- 题目数: {total}',
             f'- 成功判型: {classified}/{total}',
             f'- 成功解出: {solved}/{total}', '',
             '## 漏洞类型分布', '']
    for v, n in vuln_dist.most_common():
        lines.append(f'- {v}: {n}')
    lines += ['', '## 技术栈分布', '']
    for s, n in stack_dist.most_common():
        lines.append(f'- {s}: {n}')
    lines += ['', '## 逐题结果', '']
    for r in results:
        mark = '✅' if r['success'] else '❌'
        lines.append(f"### {mark} {r['name']}")
        lines.append(f"- 判定: {r['primary_vuln']} (置信度 {r['confidence']})")
        lines.append(f"- 技术栈: {r['stack']} {r['framework']}")
        if r['success']:
            lines.append(f"- FLAG: `{r['flag']}`")
            lines.append(f"- payload: {r['payload_desc']}")
        elif r.get('error'):
            lines.append(f"- error: {r['error'][:200]}")
        lines.append('')
    out_md.write_text('\n'.join(lines), encoding='utf-8')

    print(f'[*] 判型成功 {classified}/{total}, 解出 {solved}/{total}')
    print(f'[*] 报告: {out_json}')
    print(f'[*] 报告: {out_md}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
