#!/usr/bin/env python3
"""离线 libc 符号索引 —— 构建、查询与 loader 配对，全程不发任何网络请求。

背景：仓库里装的是 libcsearcher 1.1.5，它其实是 libc.rip 的云 API 客户端
（LibcSearcher.py 里 requests.post('https://libc.rip/api/find')），本机没有本地库，
断网时完全不可用。本模块用"磁盘上已有的 libc 文件 + 符号偏移索引"替代它：

  - 构建：扫描 libcs/、glibc_compat/、cache/、pwn题目解析/、external_challs/ 等目录，
    以及 $PWNSOLVER_LIBC_DIRS，对每个 ELF libc 提取 arch、版本串、关键符号偏移、
    /bin/sh 偏移与配对 loader，落盘 pwn_solver/libc_db/index.json（可随仓库分发）。
  - 查询：用泄露地址的低 12 位（页内偏移，与 ASLR 基址无关）筛候选，再用第二个
    符号收敛；命中唯一才给结论，多个候选则如实返回列表，绝不瞎猜。
  - 配对：按版本找同名 loader（ld-<ver>.so / ld-linux*.so.2 / glibc_compat）。

索引增量更新，按 (path, size, mtime_ns) 跳过未变文件。所有函数都可离线调用。
"""
import hashlib
import json
import os
import re
import struct
import time

# 索引里保存的符号（缺失的记为 None，不参与匹配）
INDEX_SYMBOLS = (
    'puts', 'printf', 'read', 'write', 'system', 'str_bin_sh',
    '__libc_start_main', 'malloc', 'free', 'setcontext',
    '__free_hook', '__malloc_hook', '_IO_2_1_stdout_', '_IO_2_1_stdin_',
    'open', 'exit', 'execve',
)

_ARCH_BY_MACHINE = {3: 'i386', 62: 'amd64', 183: 'aarch64', 40: 'arm'}

# 条目结构变更时递增：旧索引会被强制重建，避免"schema 变了但增量跳过"导致的空字段
INDEX_SCHEMA = 2

DEFAULT_SCAN_DIRS = (
    'libcs',
    'pwn_solver/glibc_compat',
    'cache',
    'pwn题目解析',
    'external_challs',
    'challenges',
)

_VERSION_RES = (
    re.compile(rb'GNU C Library [^\n]{0,120}?release version (\d+\.\d+)'),
    re.compile(rb'glibc (\d+\.\d+)'),
    re.compile(rb'release version (\d+\.\d+)'),
)
_FILENAME_VERSION_RE = re.compile(r'libc[-.](\d+\.\d+)\.so')
_LOADER_NAME_RE = re.compile(r'^ld-(?:linux-[\w.-]*?\.so\.\d+|(\d+\.\d+)\.so)$')


def repo_root():
    """PwnSolver 仓库根目录（本文件位于 <root>/pwn_solver/libc_db.py）。"""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def index_path():
    return os.environ.get('PWNSOLVER_LIBC_DB') or os.path.join(
        repo_root(), 'pwn_solver', 'libc_db', 'index.json')


def rel_or_abs(path):
    """仓库内路径存相对形式，便于整仓库迁移后索引仍然有效。"""
    path = os.path.abspath(path)
    root = repo_root()
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return path
    if rel.startswith('..'):
        return path
    return rel.replace(os.sep, '/')


def abs_path(stored):
    if os.path.isabs(stored):
        return stored
    return os.path.join(repo_root(), stored.replace('/', os.sep))


# --------------------------------------------------------------------------
# ELF 读取（pwntools 优先，pyelftools 兜底，都不可用时放弃该文件）
# --------------------------------------------------------------------------

def _elf_machine(path):
    try:
        with open(path, 'rb') as f:
            head = f.read(0x20)
        if head[:4] != b'\x7fELF':
            return None
        return struct.unpack('<H', head[18:20])[0]
    except OSError:
        return None


def arch_of(path):
    """ELF 架构名（amd64/i386/aarch64/arm），无法识别时返回 None。"""
    return _ARCH_BY_MACHINE.get(_elf_machine(path))


def _read_version_string(path, entry_name):
    try:
        with open(path, 'rb') as f:
            blob = f.read()
    except OSError:
        blob = b''
    for pat in _VERSION_RES:
        m = pat.search(blob)
        if m:
            return m.group(1).decode(), m.group(0)[:160].decode('utf-8', 'replace').strip()
    m = _FILENAME_VERSION_RE.search(entry_name or '')
    if m:
        return m.group(1), f'(来自文件名) {entry_name}'
    return None, None


def _symbols_with_pwntools(path):
    from pwn import ELF  # noqa: WPS433 (延迟导入，允许无 pwntools 环境跑索引查询)
    elf = ELF(path, checksec=False)
    out = {}
    for name in INDEX_SYMBOLS:
        if name == 'str_bin_sh':
            continue
        try:
            out[name] = elf.symbols.get(name)
        except Exception:
            out[name] = None
    try:
        binsh = next(elf.search(b'/bin/sh'), None)
        out['str_bin_sh'] = binsh
    except Exception:
        out['str_bin_sh'] = None
    return out


def _symbols_with_pyelftools(path):
    from elftools.elf.elffile import ELFFile
    out = {name: None for name in INDEX_SYMBOLS}
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        dyn = elf.get_section_by_name('.dynsym')
        if dyn is not None:
            for sym in dyn.iter_symbols():
                name = sym.name.split('@')[0]
                if name in out and out[name] is None and sym['st_value']:
                    out[name] = sym['st_value']
    # /bin/sh: 在文件里找字符串，再用 section 把文件偏移换算成虚拟地址
    try:
        with open(path, 'rb') as f:
            blob = f.read()
        off = blob.find(b'/bin/sh\x00')
        if off >= 0:
            with open(path, 'rb') as f:
                elf = ELFFile(f)
                for sec in elf.iter_sections():
                    sh_addr, sh_off, sh_size = sec['sh_addr'], sec['sh_offset'], sec['sh_size']
                    if sh_off <= off < sh_off + sh_size:
                        out['str_bin_sh'] = sh_addr + (off - sh_off)
                        break
    except Exception:
        pass
    return out


def describe_libc(path, loader=None, source=None):
    """解析单个 libc，返回索引条目；无法解析时返回 None。

    loader 未显式给出时自行按版本/同级文件名配对（ld-2.32.so / ld-linux*.so.2）。
    """
    path = os.path.abspath(path)
    machine = _elf_machine(path)
    if machine is None:
        return None
    if loader is None:
        try:
            loader = find_loader_for(path)
        except Exception:
            loader = None
    try:
        sha = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    except OSError:
        return None
    symbols = None
    for reader in (_symbols_with_pwntools, _symbols_with_pyelftools):
        try:
            symbols = reader(path)
        except Exception:
            symbols = None
            continue
        if symbols and symbols.get('puts'):
            break
    if not symbols:
        symbols = {name: None for name in INDEX_SYMBOLS}
    version, version_string = _read_version_string(path, os.path.basename(path))
    st = os.stat(path)
    return {
        'path': rel_or_abs(path),
        'sha256': sha,
        'size': st.st_size,
        'mtime_ns': st.st_mtime_ns,
        'e_machine': machine,
        'arch': _ARCH_BY_MACHINE.get(machine, f'elf-{machine}'),
        'libc_version': version,
        'version_string': version_string,
        'symbols': symbols,
        'loader': rel_or_abs(loader) if loader else None,
        'source': source or rel_or_abs(path),
    }


# --------------------------------------------------------------------------
# loader 配对：把 glibc_compat 里写死的 2.23 特例泛化
# --------------------------------------------------------------------------

def find_loader_for(libc_path, version=None, scan_dirs=None):
    """给 libc 找配对 loader：同级文件 → 仓库 libcs/<ver>/ → glibc_compat/ld-<ver>.so。"""
    libc_path = os.path.abspath(libc_path)
    d = os.path.dirname(libc_path)
    for base in (d, os.path.dirname(d), os.path.join(d, '..')):
        if not base or not os.path.isdir(base):
            continue
        for name in sorted(os.listdir(base)):
            low = name.lower()
            if 'ld-linux' in low or (low.startswith('ld-') and low.endswith('.so')):
                cand = os.path.join(base, name)
                if _elf_machine(cand) == _elf_machine(libc_path):
                    return os.path.abspath(cand)
    if not version:
        version = _read_version_string(libc_path, os.path.basename(libc_path))[0]
    if not version:
        return None
    root = repo_root()
    dirs = list(scan_dirs or ())
    dirs += [os.path.join(root, 'libcs'), os.path.join(root, 'pwn_solver', 'glibc_compat')]
    for base in dirs:
        if not os.path.isdir(base):
            continue
        for cur, _dirs, files in os.walk(base):
            for name in files:
                low = name.lower()
                if not low.startswith('ld-'):
                    continue
                if version not in name:
                    continue
                cand = os.path.join(cur, name)
                if _elf_machine(cand) == _elf_machine(libc_path):
                    return os.path.abspath(cand)
    return None


# --------------------------------------------------------------------------
# 候选文件枚举与索引构建
# --------------------------------------------------------------------------

def looks_like_libc_name(name):
    low = name.lower()
    if low.startswith('ld-'):
        return False
    if low == 'libc' or low.startswith('libc.so') or low.startswith('libc-'):
        return True
    return bool(re.match(r'^libc[.-]\d', low))


def scan_libc_files(extra_dirs=None, verbose=False):
    """枚举磁盘上可用作索引来源的 libc 文件（去重后按路径排序）。"""
    root = repo_root()
    dirs = []
    env_dirs = os.environ.get('PWNSOLVER_LIBC_DIRS', '')
    for chunk in env_dirs.split(os.pathsep):
        if chunk.strip():
            dirs.append(chunk.strip())
    for rel in DEFAULT_SCAN_DIRS:
        dirs.append(rel if os.path.isabs(rel) else os.path.join(root, rel))
    dirs.extend(extra_dirs or [])

    seen, out = set(), []
    for base in dirs:
        if not os.path.isdir(base):
            continue
        for cur, _sub, files in os.walk(base):
            for name in files:
                if not looks_like_libc_name(name):
                    continue
                path = os.path.join(cur, name)
                try:
                    real = os.path.realpath(path)
                except OSError:
                    continue
                if real in seen:
                    continue
                if _elf_machine(path) is None:
                    continue
                seen.add(real)
                out.append(path)
                if verbose:
                    print(f'  [libc_db] 发现 {rel_or_abs(path)}', flush=True)
    return sorted(out)


def load_index():
    path = index_path()
    if not os.path.exists(path):
        return {'schema': INDEX_SCHEMA, 'version': 1, 'generated_at': None, 'entries': []}
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        data.setdefault('entries', [])
        data.setdefault('schema', 0)
        return data
    except (OSError, ValueError):
        return {'schema': INDEX_SCHEMA, 'version': 1, 'generated_at': None, 'entries': []}


def save_index(index):
    path = index_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    index['schema'] = INDEX_SCHEMA
    index['version'] = 1
    index['generated_at'] = time.strftime('%Y-%m-%dT%H:%M:%S')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    return path


def build_index(paths=None, extra_dirs=None, force=False, verbose=True):
    """构建/增量更新索引；返回 (index, stats)。"""
    index = load_index()
    if index.get('schema') != INDEX_SCHEMA:
        # 条目结构变了：旧条目字段不全，直接全量重建
        force = True
        index['entries'] = []
    by_path = {e['path']: e for e in index['entries']}
    targets = paths if paths is not None else scan_libc_files(extra_dirs, verbose=verbose)

    stats = {'total': len(targets), 'added': 0, 'updated': 0, 'kept': 0, 'skipped': 0}
    for path in targets:
        ap = os.path.abspath(path)
        key = rel_or_abs(ap)
        try:
            st = os.stat(ap)
        except OSError:
            stats['skipped'] += 1
            continue
        old = by_path.get(key)
        if old and not force and old.get('mtime_ns') == st.st_mtime_ns and old.get('size') == st.st_size:
            stats['kept'] += 1
            continue
        loader = find_loader_for(ap)
        entry = describe_libc(ap, loader=loader)
        if not entry:
            stats['skipped'] += 1
            continue
        if old:
            stats['updated'] += 1
        else:
            stats['added'] += 1
        by_path[key] = entry
        if verbose:
            print(f"  [libc_db] {entry['libc_version'] or '?':>5} {entry['arch']:>7} "
                  f"{key}", flush=True)

    index['entries'] = sorted(by_path.values(), key=lambda e: (e.get('libc_version') or '', e['path']))
    save_index(index)
    return index, stats


def add_libc(path, loader=None):
    """把单个 libc 加入索引（题目现场发现附件时用），已存在则跳过。"""
    path = os.path.abspath(path)
    index = load_index()
    key = rel_or_abs(path)
    for e in index['entries']:
        if e['path'] == key:
            if loader and not e.get('loader'):
                e['loader'] = rel_or_abs(loader)
                save_index(index)
            return e
    entry = describe_libc(path, loader=loader or find_loader_for(path))
    if not entry:
        return None
    index['entries'].append(entry)
    save_index(index)
    return entry


# --------------------------------------------------------------------------
# 匹配：泄露地址 → libc
# --------------------------------------------------------------------------

class LibcMatch:
    """一个候选 libc。base 为按首个符号推出的基址（候选不唯一时仅供参考）。"""

    def __init__(self, entry, symbol, leaked, matched=1, total=1):
        self.entry = entry
        self.path = abs_path(entry['path'])
        self.libc_version = entry.get('libc_version')
        self.arch = entry.get('arch')
        self.symbol = symbol
        self.offset = entry['symbols'].get(symbol)
        self.base = leaked - self.offset if self.offset is not None else None
        self.matched = matched
        self.total = total

    @property
    def confident(self):
        return self.total == 1

    def __repr__(self):
        return (f'<LibcMatch {self.libc_version} {self.arch} {os.path.basename(self.path)} '
                f'{self.symbol}+{hex(self.offset) if self.offset else "?"} '
                f'matched={self.matched}/{self.total}>')


def match_leaks(leaks, arch=None, index=None, max_results=5):
    """按泄露地址匹配 libc。

    leaks: {符号名: 泄露到的绝对地址}，例如 {'puts': 0x7f1234567890}。
    只用低 12 位可比对的符号参与筛（页内偏移与基址无关）。
    返回 LibcMatch 列表（按匹配符号数降序）；空列表代表没匹配上。
    """
    index = index or load_index()
    usable = [(sym, addr) for sym, addr in (leaks or {}).items()
              if addr and sym in INDEX_SYMBOLS and sym != 'str_bin_sh']
    if not usable:
        return []

    candidates = None
    per_symbol = {}
    for sym, addr in usable:
        low12 = addr & 0xfff
        hits = [e for e in index['entries']
                if (arch is None or e.get('arch') == arch)
                and e['symbols'].get(sym) is not None
                and (e['symbols'][sym] & 0xfff) == low12]
        per_symbol[sym] = {e['path'] for e in hits}
        candidates = hits if candidates is None else [e for e in candidates if e['path'] in per_symbol[sym]]

    if not candidates:
        return []

    out = []
    for entry in candidates:
        matched = sum(1 for sym in per_symbol if entry['path'] in per_symbol[sym])
        primary_sym, primary_addr = usable[0]
        out.append(LibcMatch(entry, primary_sym, primary_addr, matched=matched, total=len(candidates)))
    out.sort(key=lambda m: (-m.matched, m.libc_version or ''))
    return out[:max_results]


def resolve_for_binary(leaks=None, arch='amd64', index=None):
    """给求解器用的入口：有泄露就按符号匹配，否则只报告索引可用性。"""
    index = index or load_index()
    if leaks:
        matches = match_leaks(leaks, arch=arch, index=index)
        if matches:
            return matches
    return []


def summarize(index=None):
    index = index or load_index()
    entries = index['entries']
    versions = {}
    for e in entries:
        key = (e.get('libc_version') or '未知', e.get('arch') or '?')
        versions[key] = versions.get(key, 0) + 1
    return {'entries': len(entries), 'generated_at': index.get('generated_at'),
            'by_version': {f'{v}/{a}': n for (v, a), n in sorted(versions.items())}}


def main():  # pragma: no cover - 手工排查用
    import argparse
    ap = argparse.ArgumentParser(description='离线 libc 索引')
    sub = ap.add_subparsers(dest='cmd', required=True)
    p_build = sub.add_parser('build', help='扫描并构建/更新索引')
    p_build.add_argument('--force', action='store_true')
    p_build.add_argument('--dir', action='append', default=[], help='额外扫描目录，可重复')
    p_list = sub.add_parser('list', help='列出索引概况')
    p_list.add_argument('--verbose', action='store_true')
    p_match = sub.add_parser('match', help='用泄露地址匹配，如 --leak puts=0x7f1234567890')
    p_match.add_argument('--leak', action='append', required=True)
    p_match.add_argument('--arch', default=None)
    args = ap.parse_args()

    if args.cmd == 'build':
        index, stats = build_index(extra_dirs=args.dir, force=args.force)
        print(f"[libc_db] 索引条目 {len(index['entries'])}，"
              f"新增 {stats['added']} 更新 {stats['updated']} 未变 {stats['kept']} 跳过 {stats['skipped']}")
        print(f"[libc_db] 写入 {index_path()}")
    elif args.cmd == 'list':
        info = summarize()
        print(f"[libc_db] {index_path()}")
        print(f"[libc_db] 条目 {info['entries']}，生成于 {info['generated_at']}")
        for key, num in info['by_version'].items():
            print(f"  {key}: {num}")
        if args.verbose:
            for e in load_index()['entries']:
                print(f"  {e['path']}  ld={e.get('loader')}")
    elif args.cmd == 'match':
        leaks = {}
        for item in args.leak:
            sym, _, addr = item.partition('=')
            leaks[sym.strip()] = int(addr, 16)
        matches = match_leaks(leaks, arch=args.arch)
        if not matches:
            print('[libc_db] 未匹配到候选 libc（可扩充索引或手工 -l 指定）')
            return 1
        for m in matches:
            print(f"[libc_db] {m.libc_version} {m.arch} base={hex(m.base) if m.base else '?'} "
                  f"匹配 {m.matched}/{m.total} :: {m.path}")
            print(f"           loader={m.entry.get('loader')}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
