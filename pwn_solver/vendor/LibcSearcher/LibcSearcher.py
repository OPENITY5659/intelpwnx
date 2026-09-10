#!/usr/bin/env python3
"""LibcSearcher 的纯本地实现（同名同接口，直接替换掉云端那份）。

背景：pip 装的 `libcsearcher 1.1.5` 是 libc.rip 的云 API 客户端，而 libc.rip 现在要求
`Content-Type: application/json`，它用 requests 的默认 form 编码发请求 → 服务端直接 500，
所以那份实现不但断网不可用，联网也是坏的。

本实现保持完全相同的调用面，任何 `from LibcSearcher import LibcSearcher` 的代码
（PwnSolver、pwnpasi 等）不需要改一行：

    libc = LibcSearcher("write", write_addr)      # 或 LibcSearcher("puts", addr)
    libcbase = write_addr - libc.dump("write")
    system   = libcbase + libc.dump("system")

匹配语义与原来一致：**按符号偏移的低 12 位**（页内偏移与 ASLR 基址无关）筛候选，
多个条件取交集。数据完全来自本地文件：

  1) 本包同目录的 db/*.symbols（libc-database 风格，由 scripts/build_libcsearcher_db.py 生成）
  2) 环境变量 LIBCSEARCHER_DB 指向的目录（同样支持 *.symbols 与 *.json）
  3) PwnSolver 的离线索引：pwn_solver/libc_db/{index.json,libcrip.json}
     —— 可对比 WSOLVER_LIBC_DB_DIR / PWNSOLVER_LIBC_DB_DIR 指定

命中多个候选时 `libc_list` 有值、`the_libc` 为 None（与原行为一致）；调用方可以用
`select_libc(i)` 选定。`dump()` 对于"本地有真实 .so"的条目能回答任意符号（含
__free_hook / setcontext 这些识别库里没有的），因为它是现场读 ELF 拿的。
"""
import json
import os
import re

__all__ = ['LibcSearcher']

_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_DB_CACHE = None


def _candidate_dirs():
    dirs = []
    env = os.environ.get('LIBCSEARCHER_DB')
    if env:
        dirs.append(env)
    dirs.append(os.path.join(_PKG_DIR, 'db'))
    for env_name in ('PWNSOLVER_LIBC_DB_DIR', 'WSOLVER_LIBC_DB_DIR'):
        val = os.environ.get(env_name)
        if val:
            dirs.append(val)
    # PwnSolver 仓库的离线索引（本机常见位置，找不到就跳过）
    for guess in (
        os.path.join(_PKG_DIR, '..', '..', '..', 'pwn_solver', 'libc_db'),
        '/mnt/d/CTF_Slover/PwnSolver/pwn_solver/libc_db',
        'D:/CTF_Slover/PwnSolver/pwn_solver/libc_db',
    ):
        dirs.append(os.path.abspath(guess))
    seen, out = set(), []
    for d in dirs:
        if d and os.path.isdir(d) and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _parse_symbols_file(path):
    """libc-database 风格：每行 `symbol offset`（offset 是十六进制）。"""
    symbols = {}
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        symbols[parts[0]] = int(parts[1], 16)
                    except ValueError:
                        continue
    except OSError:
        return None
    return symbols


def _entry_from_symbols_file(path):
    base = os.path.basename(path)
    libc_id = re.sub(r'\.symbols$', '', base)
    symbols = _parse_symbols_file(path)
    if not symbols:
        return None
    info = {}
    info_path = path[:-len('.symbols')] + '.info'
    if os.path.exists(info_path):
        info = _parse_info_file(info_path)
    version = info.get('version') or _version_from_id(libc_id)
    return {
        'id': libc_id,
        'version': version,
        'arch': info.get('arch') or _arch_from_id(libc_id),
        'buildid': info.get('buildid'),
        'download_url': info.get('url'),
        'symbols': symbols,
        'libc_path': info.get('libc_path'),
    }


def _parse_info_file(path):
    out = {}
    try:
        with open(path, encoding='utf-8', errors='ignore') as f:
            for line in f:
                if ':' in line:
                    k, _, v = line.partition(':')
                    out[k.strip().lower()] = v.strip()
    except OSError:
        pass
    return out


def _version_from_id(libc_id):
    m = re.search(r'(\d+\.\d+(?:\.\d+)?)', libc_id or '')
    return m.group(1) if m else None


def _arch_from_id(libc_id):
    low = (libc_id or '').lower()
    if low.endswith('i386') or '_i386' in low or 'i686' in low:
        return 'i386'
    if 'aarch64' in low or 'arm64' in low:
        return 'aarch64'
    return 'amd64'


def _load_json_db(path, kind):
    """把 PwnSolver 的 index.json / libcrip.json 转成同一份条目结构。"""
    entries = []
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        return entries
    if kind == 'index':
        for item in data.get('entries', []):
            symbols = {k: v for k, v in (item.get('symbols') or {}).items()
                       if isinstance(v, int)}
            if not symbols:
                continue
            entries.append({
                'id': os.path.basename(item.get('path') or ''),
                'version': item.get('libc_version'),
                'arch': item.get('arch'),
                'buildid': None,
                'download_url': None,
                'symbols': symbols,
                'libc_path': item.get('path'),
            })
    elif kind == 'libcrip':
        for key, item in (data or {}).items():
            symbols = {k: v for k, v in (item.get('symbols') or {}).items()
                       if isinstance(v, int)}
            if not symbols:
                continue
            entries.append({
                'id': key,
                'version': item.get('version'),
                'arch': item.get('arch'),
                'buildid': item.get('buildid'),
                'download_url': item.get('download_url'),
                'symbols': symbols,
                'libc_path': None,
            })
    return entries


def load_database(force=False):
    """载入本地库（进程内缓存）。返回条目列表。"""
    global _DB_CACHE
    if _DB_CACHE is not None and not force:
        return _DB_CACHE
    entries, seen_ids = [], set()

    def _add(new_entries):
        for e in new_entries:
            key = (e.get('id'), e.get('version'), e.get('arch'))
            if key in seen_ids:
                continue
            seen_ids.add(key)
            entries.append(e)

    for directory in _candidate_dirs():
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        symbols_files = [n for n in names if n.endswith('.symbols')]
        if symbols_files:
            for name in symbols_files:
                e = _entry_from_symbols_file(os.path.join(directory, name))
                if e:
                    _add([e])
        for name, kind in (('index.json', 'index'), ('libcrip.json', 'libcrip')):
            if name in names:
                _add(_load_json_db(os.path.join(directory, name), kind))
    _DB_CACHE = entries
    return entries


class LibcSearcher:
    """与云端版同接口的本地匹配器。"""

    def __init__(self, symbol_name=None, address=None, *args, **kwargs):
        self.constraint = {}
        self.libc_list = []
        self.the_libc = None
        self.db = None            # 兼容旧代码的 hasattr(obj, 'db') 检查
        self._database = None
        if symbol_name is not None and address is not None:
            self.add_condition(symbol_name, address)

    # ---------------------------------------------------------------- 匹配
    def add_condition(self, symbol_name, address):
        """加一个约束（符号 → 泄露地址），并重新匹配低 12 位。"""
        self.constraint[symbol_name] = address
        self.the_libc = None
        self.libc_list = []
        self.pre_query_libc()

    def pre_query_libc(self, force=False):
        if self.the_libc is not None or self.libc_list:
            return
        if self._database is None or force:
            self._database = load_database(force=force)
        if not self.constraint:
            return
        candidates = self._database
        for symbol, address in self.constraint.items():
            low12 = int(address) & 0xfff
            candidates = [e for e in candidates
                          if e['symbols'].get(symbol) is not None
                          and (e['symbols'][symbol] & 0xfff) == low12]
            if not candidates:
                return
        # 命中多个时优先给出"本地有真实 .so"的条目（能回答更多符号）
        candidates.sort(key=lambda e: (e.get('libc_path') is None, e.get('version') or ''))
        if len(candidates) == 1:
            self.the_libc = candidates[0]
            self.db = candidates[0].get('libc_path')
        else:
            self.libc_list = candidates

    def select_libc(self, index=0):
        self.pre_query_libc()
        if self.the_libc is None and 0 <= index < len(self.libc_list):
            self.the_libc = self.libc_list[index]
            self.db = self.the_libc.get('libc_path')
        return self.the_libc

    # ---------------------------------------------------------------- 取偏移
    def dump(self, symbol_name):
        """返回该符号的偏移。本地有真实 .so 时现场读 ELF，能回答任意符号。"""
        self.pre_query_libc()
        if self.the_libc is None:
            if not self.libc_list:
                raise RuntimeError(
                    'No libc satisfies constraints.（本地库没有匹配项：'
                    '跑 scripts/build_libcsearcher_db.py 生成 db/，或用 -l 手工指定 libc）')
            raise RuntimeError(
                'Current constraints are not enough to determine a libc.'
                '（命中多个候选，先 select_libc(i)：'
                + ', '.join(e.get('id') or '?' for e in self.libc_list[:5]) + ' ...）')
        symbols = self.the_libc['symbols']
        if symbol_name in symbols:
            return symbols[symbol_name]
        path = self.the_libc.get('libc_path')
        if path and os.path.exists(path):
            try:
                from pwn import ELF
                elf = ELF(path, checksec=False)
                if symbol_name == 'str_bin_sh':
                    found = next(elf.search(b'/bin/sh'), None)
                    if found:
                        return found
                value = elf.symbols.get(symbol_name)
                if value:
                    symbols[symbol_name] = value
                    return value
            except Exception:
                pass
        raise KeyError(f'符号 {symbol_name} 在 {self.the_libc.get("id")} 里取不到'
                       '（识别库只有核心符号；需要它请用带真实 .so 的本地索引）')

    # ------------------------------------------------------- 与原版一致的杂项
    def __len__(self):
        self.pre_query_libc()
        return 1 if self.the_libc is not None else len(self.libc_list)

    def __iter__(self):
        self.pre_query_libc()
        if self.the_libc is not None:
            return iter([self.the_libc['id']])
        return iter([e['id'] for e in self.libc_list])

    def __bool__(self):
        self.pre_query_libc()
        return self.the_libc is not None or self.libc_list != []

    def __repr__(self):
        self.pre_query_libc()
        if not self.libc_list and self.the_libc is None:
            return '[+] No libc satisfies constraints.（本地库无匹配）'
        if self.the_libc is None:
            return (f'[+] Current constraints are not enough to determine a libc.'
                    f'（{len(self.libc_list)} 个候选，select_libc(i) 选定）')
        return (f"[ libc_id ] : {self.the_libc.get('id')}\n"
                f"[ buildid ] : {self.the_libc.get('buildid')}\n"
                f"[ version ] : {self.the_libc.get('version')} ({self.the_libc.get('arch')})\n"
                f"[ source  ] : {self.the_libc.get('libc_path') or '识别库(无本地 .so)'}")
