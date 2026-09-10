#!/usr/bin/env python3
"""PwnSolver unified entrypoint with smart runtime routing.

Examples:
  python3 pwnsolver.py router
  python3 pwnsolver.py solve ./vuln -l ./libc.so.6 -d ./ld-linux-x86-64.so.2 -t 30
  python3 pwnsolver.py recon ./vuln --deep-r2
  python3 pwnsolver.py gui
  python3 pwnsolver.py web [port]
  python3 pwnsolver.py check
  python3 pwnsolver.py patterns
"""
import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'pwn_solver'))

from runtime_router import RuntimeRouter, X86_IMAGE, PROJECT_ROOT, SOLVER_SCRIPT


def _find_option(args, names):
    for i, a in enumerate(args):
        if a in names and i + 1 < len(args):
            return args[i + 1]
        if a.startswith('--libc='):
            return a.split('=', 1)[1]
        if a.startswith('--ld='):
            return a.split('=', 1)[1]
    return None


def _mapped_args(args, plan, libc, ld):
    out = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in ('-l', '--libc', '-d', '--ld'):
            out.append(a)
            val = args[i + 1] if i + 1 < len(args) else ''
            if val:
                out.append(plan.map_path(val))
            skip = True
            continue
        if a.startswith('--libc='):
            out.append('--libc=' + plan.map_path(a.split('=', 1)[1]))
            continue
        if a.startswith('--ld='):
            out.append('--ld=' + plan.map_path(a.split('=', 1)[1]))
            continue
        out.append(a)
    return out


def _run(plan, args, interactive=False, image_ready=True):
    cmd = plan.build_command(args, interactive=interactive)
    print(f'[*] runtime: {plan.describe()}')
    if plan.backend == 'docker-amd64' and not image_ready:
        print(f'[-] image {X86_IMAGE} not found. Build it first:', file=sys.stderr)
        print(f'    scripts/pwn-x86-build   (or: python3 pwnsolver.py build)', file=sys.stderr)
        return 2
    if plan.backend == 'docker-amd64':
        print('[*] docker command: ' + ' '.join(shlex.quote(x) for x in cmd), file=sys.stderr)
    return subprocess.call(cmd)


def cmd_router(_args):
    r = RuntimeRouter()
    status = r.status()
    print('PwnSolver runtime router')
    print('=======================')
    for k, v in status.items():
        print(f'  {k:14s}: {v}')
    print(f'  rule        : {r.describe()}')
    return 0 if r.docker_ok or r.wsl_ok or r.os_name == 'Linux' else 1


def cmd_build(_args):
    script = PROJECT_ROOT / 'scripts' / 'pwn-x86-build'
    # 经 bash 调用而不是直接 exec：带 shebang 的脚本一旦被 checkout 成 CRLF，
    # Linux 会报 "env: bash\r: No such file or directory" 而完全跑不起来。
    return subprocess.call(['bash', str(script)])


def cmd_solve(args, recon_only=False):
    binary = args.binary
    libc = args.libc or _find_option(args.solver_args, ('-l', '--libc'))
    ld = args.ld or _find_option(args.solver_args, ('-d', '--ld'))
    # 7z/zip 解包通常会丢失 executable bit，宿主机先补齐，避免容器内 process() 报错。
    for path in (binary, libc, ld):
        if path and os.path.exists(path):
            try:
                os.chmod(path, os.stat(path).st_mode | 0o111)
            except Exception:
                pass
    r = RuntimeRouter()
    plan = r.plan(binary, libc, ld)
    if plan.backend == 'error':
        print(f'[-] no usable runtime: {plan.reason}', file=sys.stderr)
        return 1
    extra = list(args.solver_args)
    if recon_only and '--recon-only' not in extra:
        extra.append('--recon-only')
    if args.no_skill and '--no-skill' not in extra:
        extra.append('--no-skill')
    mapped = _mapped_args(extra, plan, libc, ld)
    mapped_binary = plan.map_path(binary)
    if plan.backend == 'docker-amd64':
        solver = '/pwnsolver/pwn_solver/solver.py'
    else:
        solver = plan.map_path(str(SOLVER_SCRIPT))
    inner = 'python3 -W ignore ' + shlex.quote(solver) + ' ' + shlex.quote(mapped_binary)
    if mapped:
        inner += ' ' + ' '.join(shlex.quote(x) for x in mapped)
    return _run(plan, inner, image_ready=r.image_ready())


def cmd_check(_args):
    r = RuntimeRouter()
    if r.os_name == 'Darwin' and r.machine in ('arm64', 'aarch64'):
        plan = r._docker_plan(str(PROJECT_ROOT / 'README.md'), '', '', reason='environment check')
        if not r.image_ready():
            print(f'[-] image {X86_IMAGE} not ready; run scripts/pwn-x86-build', file=sys.stderr)
            return 2
        return _run(plan, 'cd /pwnsolver && python3 check_env.py', image_ready=r.image_ready())
    if r.os_name == 'Windows' and r.docker_ok:
        plan = r._docker_plan(str(PROJECT_ROOT / 'README.md'), '', '', reason='environment check')
        return _run(plan, 'cd /pwnsolver && python3 check_env.py', image_ready=r.image_ready())
    return subprocess.call([sys.executable, str(PROJECT_ROOT / 'check_env.py')])


def cmd_patterns(_args):
    from pattern_engine import PatternEngine
    print('Generalized exploitation patterns:')
    for pid, name in sorted(PatternEngine.VULN_MAP.items()):
        print(f'  {pid:20s} -> vuln_type={name}')
    return 0


def cmd_libcdb(args):
    """离线 libc 符号索引：构建、查看、按泄露匹配（全程不联网）。"""
    sys.path.insert(0, str(PROJECT_ROOT / 'pwn_solver'))
    import libc_db

    action = args.action
    if action == 'build':
        index, stats = libc_db.build_index(extra_dirs=args.dir, force=args.force,
                                          verbose=args.verbose)
        print(f"[libcdb] 条目 {len(index['entries'])}（新增 {stats['added']} "
              f"更新 {stats['updated']} 未变 {stats['kept']} 跳过 {stats['skipped']}）")
        print(f"[libcdb] 写入 {libc_db.index_path()}")
        return 0

    if action == 'list':
        info = libc_db.summarize()
        print(f"[libcdb] {libc_db.index_path()}")
        print(f"[libcdb] 条目 {info['entries']}，生成于 {info['generated_at']}")
        for key, num in info['by_version'].items():
            print(f"  {key}: {num}")
        if args.verbose:
            for entry in libc_db.load_index()['entries']:
                print(f"  {entry['path']}  ld={entry.get('loader')}")
        if not info['entries']:
            print('  （索引为空 —— 跑 pwnsolver.py libcdb build，或先 fetchlibc 预抓常用版本）')
        return 0

    if action == 'match':
        leaks = {}
        for item in args.leak:
            sym, _, addr = item.partition('=')
            if not addr:
                print(f'[-] --leak 需要写成 符号=地址 的形式，收到: {item}', file=sys.stderr)
                return 2
            leaks[sym.strip()] = int(addr, 16)
        if not leaks:
            print('[-] match 至少需要一个 --leak 符号=地址', file=sys.stderr)
            return 2
        matches = libc_db.match_leaks(leaks, arch=args.arch)
        if not matches:
            print('[libcdb] 未匹配到候选 —— 可先 fetchlibc 预抓更多版本，或手工 -l 指定')
            return 1
        for m in matches:
            base = hex(m.base) if m.base else '?'
            print(f"[libcdb] glibc {m.libc_version} {m.arch} base={base} "
                  f"匹配 {m.matched}/{m.total}")
            print(f"         {m.path}")
            if m.entry.get('loader'):
                print(f"         loader: {m.entry['loader']}")
        return 0

    print(f'[-] 未知 action: {action}', file=sys.stderr)
    return 2


def main():
    parser = argparse.ArgumentParser(description='PwnSolver unified entrypoint')
    sub = parser.add_subparsers(dest='command')

    p_solve = sub.add_parser('solve', help='solve a binary through smart runtime router')
    p_solve.add_argument('binary')
    p_solve.add_argument('solver_args', nargs=argparse.REMAINDER)
    p_solve.add_argument('-l', '--libc')
    p_solve.add_argument('-d', '--ld')
    p_solve.add_argument('--no-skill', action='store_true')

    p_recon = sub.add_parser('recon', help='recon-only through smart runtime router')
    p_recon.add_argument('binary')
    p_recon.add_argument('solver_args', nargs=argparse.REMAINDER)
    p_recon.add_argument('-l', '--libc')
    p_recon.add_argument('-d', '--ld')
    p_recon.add_argument('--no-skill', action='store_true')

    sub.add_parser('gui', help='launch PwnSolver GUI')
    p_web = sub.add_parser('web', help='launch PwnSolver web API')
    p_web.add_argument('port', nargs='?', default='8787')

    p_wsolve = sub.add_parser('websolve', help='solve a Web CTF challenge (source dir)')
    p_wsolve.add_argument('target', help='web challenge source directory')
    p_wsolve.add_argument('-u', '--url', default='', help='running target URL (else auto-start env)')
    p_wsolve.add_argument('--analyze-only', action='store_true', help='static analysis only')
    p_wsolve.add_argument('-t', '--timeout', type=int, default=10)
    p_wsolve.add_argument('--max-attempts', type=int, default=60)
    p_wsolve.add_argument('-v', '--verbose', action='store_true')
    p_wsolve.add_argument('--json', action='store_true', help='JSON output')

    p_webdl = sub.add_parser('webdl', help='batch download web CTF challenge sources')
    p_webdl.add_argument('--years', default='2022-2025')
    p_webdl.add_argument('--events', default='')
    p_webdl.add_argument('--per-event', type=int, default=8)
    p_webdl.add_argument('--max-events', type=int, default=0)
    p_webdl.add_argument('--dry-run', action='store_true')

    p_webbench = sub.add_parser('webbench', help='batch verify web challenges')
    p_webbench.add_argument('--root', default='', help='challenge root (default external_challs/web_challs)')
    p_webbench.add_argument('--mode', choices=['analyze', 'solve'], default='analyze')
    p_webbench.add_argument('--timeout', type=int, default=120)
    p_webbench.add_argument('--tag', default='last')
    p_webbench.add_argument('--limit', type=int, default=0)
    sub.add_parser('check', help='check environment in selected runtime')
    sub.add_parser('router', help='show runtime routing decision')
    sub.add_parser('build', help='build x86_64 Linux sandbox image')
    sub.add_parser('patterns', help='list generalized exploitation patterns')

    p_libcdb = sub.add_parser('libcdb', help='离线 libc 符号索引（构建/查看/匹配，不联网）')
    p_libcdb.add_argument('action', nargs='?', default='list',
                          choices=['build', 'list', 'match'],
                          help='build=扫描本地 libc 建索引, list=查看概况, match=用泄露地址匹配')
    p_libcdb.add_argument('--force', action='store_true', help='build 时全量重建')
    p_libcdb.add_argument('--dir', action='append', default=[], help='额外扫描目录，可重复')
    p_libcdb.add_argument('--leak', action='append', default=[],
                          help='match 用：符号=地址，如 --leak puts=0x7f1234567890')
    p_libcdb.add_argument('--arch', default=None, help='match 时限定架构 amd64/i386')
    p_libcdb.add_argument('--verbose', action='store_true')
    p_fetch = sub.add_parser('fetchlibc', help='预抓常用 libc（唯一需要联网的步骤）')
    p_fetch.add_argument('--arch', action='append', choices=['amd64', 'i386'])
    p_fetch.add_argument('--list', action='store_true')
    p_fetch.add_argument('--no-network', action='store_true')
    p_fetch.add_argument('--force', action='store_true')

    args = parser.parse_args()
    if args.command in (None, 'gui'):
        script = ROOT / 'pwn_gui.py'
        return subprocess.call([sys.executable, str(script)])
    if args.command == 'web':
        return subprocess.call([sys.executable, str(ROOT / 'pwn_web.py'), args.port])
    if args.command == 'websolve':
        sys.path.insert(0, str(ROOT))
        from web_solver.solver import WebSolver
        solver = WebSolver(timeout=args.timeout, verbose=True,
                           max_attempts=args.max_attempts)
        if args.analyze_only:
            r = solver.analyze(args.target)
        else:
            r = solver.solve(args.target, target_url=args.url)
        if args.json:
            import json as _json
            print(_json.dumps(r.__dict__, ensure_ascii=False, indent=2, default=str))
        else:
            print(f"\n题目: {args.target}")
            print(f"  技术栈: {r.stack}  框架: {r.framework or '-'}")
            print(f"  判定: {r.primary_vuln} (置信度 {r.confidence})  候选: {r.top_vulns}")
            if r.url:
                print(f"  环境: {r.env_kind} {r.url}")
            if r.success:
                print(f"  ✅ FLAG: {r.flag}\n  payload: {r.payload_desc}")
            else:
                print(f"  ❌ {r.error} (尝试 {r.attempts} 次, {r.elapsed}s)")
        return 0 if r.success else 1
    if args.command == 'webdl':
        cmd = [sys.executable, str(ROOT / 'scripts' / 'fetch_web_challs.py'),
               '--years', args.years, '--per-event', str(args.per_event)]
        if args.events:
            cmd += ['--events', args.events]
        if args.max_events:
            cmd += ['--max-events', str(args.max_events)]
        if args.dry_run:
            cmd += ['--dry-run']
        return subprocess.call(cmd)
    if args.command == 'webbench':
        cmd = [sys.executable, str(ROOT / 'scripts' / 'web_bench.py'),
               '--mode', args.mode, '--timeout', str(args.timeout), '--tag', args.tag]
        if args.root:
            cmd += ['--root', args.root]
        if args.limit:
            cmd += ['--limit', str(args.limit)]
        return subprocess.call(cmd)
    if args.command == 'check':
        return cmd_check(args)
    if args.command == 'router':
        return cmd_router(args)
    if args.command == 'build':
        return cmd_build(args)
    if args.command == 'patterns':
        return cmd_patterns(args)
    if args.command == 'libcdb':
        return cmd_libcdb(args)
    if args.command == 'fetchlibc':
        cmd = [sys.executable, str(ROOT / 'scripts' / 'fetch_libc_set.py')]
        for arch in (args.arch or []):
            cmd += ['--arch', arch]
        if args.list:
            cmd.append('--list')
        if args.no_network:
            cmd.append('--no-network')
        if args.force:
            cmd.append('--force')
        return subprocess.call(cmd)
    if args.command == 'solve':
        return cmd_solve(args)
    if args.command == 'recon':
        return cmd_solve(args, recon_only=True)
    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
