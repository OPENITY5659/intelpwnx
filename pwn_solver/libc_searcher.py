#!/usr/bin/env python3
"""本地优先的 libc 解析器（离线可用，绝不联网）。

历史包袱：本模块原名"LibcSearcher 集成"，但实际装上的 libcsearcher 1.1.5 是
libc.rip 的云 API 客户端（requests.post 到 https://libc.rip/api/find），
且它没有本模块假设的 .db / .download() 接口 —— 也就是说这条路径从来没真正工作过，
断网更是彻底不可用。现在改为只依赖 pwn_solver/libc_db.py 的本地符号索引：
磁盘上有哪些 libc，就能识别哪些 libc，全程零网络。

对外保留旧函数名（search_by_leak / find_by_symbols），返回值统一为 (libc_path, base)。
"""
import os

from libc_db import (INDEX_SYMBOLS, LibcMatch, abs_path, index_path,  # noqa: F401
                     add_libc, find_loader_for, load_index, match_leaks)


class LibcMatcher:
    """基于本地符号索引的 libc 匹配器。"""

    def __init__(self, verbose=True):
        self.verbose = verbose

    def log(self, msg):
        if self.verbose:
            print(f"  [libc] {msg}", flush=True)

    def available(self):
        """本地索引里是否有可用条目。"""
        return bool(load_index()['entries'])

    def search_by_leaks(self, leaks, arch=None):
        """多符号匹配，返回 LibcMatch 列表（可能为空）。"""
        if not leaks:
            return []
        matches = match_leaks(leaks, arch=arch)
        if not matches:
            self.log("本地索引未匹配到 libc（泄露: "
                     + ', '.join(f'{k}={hex(v)}' for k, v in leaks.items()) + "）")
            return []
        if len(matches) == 1:
            m = matches[0]
            self.log(f"匹配到 {m.libc_version} ({m.arch}): {m.path}")
        else:
            self.log(f"匹配到 {len(matches)} 个候选 libc（页内偏移相同），按匹配符号数排序：")
            for m in matches[:5]:
                self.log(f"    {m.libc_version} {m.arch} 匹配 {m.matched}/{m.total} :: {m.path}")
        return matches

    def search_by_leak(self, func_name, leaked_addr, arch=None):
        """单符号匹配。返回 (libc_path, base)；未命中给 (None, None)。

        候选不唯一时返回按匹配度排序的第一项，但候选数量会打进日志，
        避免"悄悄选错 libc"。
        """
        matches = self.search_by_leaks({func_name: leaked_addr}, arch=arch)
        if not matches:
            return None, None
        best = matches[0]
        return best.path, best.base

    def find_by_symbols(self, symbol_offsets):
        """用符号偏移表（{符号: 偏移}）匹配，返回 (libc_path, LibcMatch)。

        与"泄露地址"等价：页内偏移与 ASLR 基址无关，这里直接把偏移当低 12 位来源。
        """
        leaks = {}
        for sym, off in (symbol_offsets or {}).items():
            if sym in INDEX_SYMBOLS and off:
                leaks[sym] = 0x7f0000000000 | (off & 0xfff)
        matches = self.search_by_leaks(leaks)
        if not matches:
            return None, None
        return matches[0].path, matches[0]

    def get_common_libc_db_path(self):
        """本地索引文件位置（保留旧名字，便于排查）。"""
        p = index_path()
        return p if os.path.exists(p) else None

    def loader_for(self, libc_path):
        """给 libc 找配对 loader；找不到返回 None。"""
        return find_loader_for(libc_path)

    def register(self, libc_path, loader=None):
        """把现场发现的 libc 附件登记进索引，返回条目。"""
        return add_libc(libc_path, loader=loader)

    def summarize(self):
        index = load_index()
        versions = {}
        for e in index['entries']:
            key = f"{e.get('libc_version') or '?'}/{e.get('arch') or '?'}"
            versions[key] = versions.get(key, 0) + 1
        return {'versions': sorted(versions.items()), 'total': len(index['entries']),
                'index': index_path()}


def create_libc_resolver_script(leak_func, libc_path=None):
    """生成写进 exploit 的 libc 解析片段。

    优先使用求解阶段已确定的 libc 绝对路径（离线可复现）；没有时退回本地索引查询，
    同样不需要网络。生成的代码里不再出现 LibcSearcher。
    """
    if libc_path:
        return f'''
# libc 已在求解阶段确定（本地文件，离线可用）
libc = ELF("{libc_path}")
libc.address = leaked - libc.symbols['{leak_func}']
log.success(f"libc base: {{hex(libc.address)}}")
'''
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return f'''
# 本地符号索引解析（离线，无网络请求）
import sys as _sys
_sys.path.insert(0, "{root}")
try:
    from libc_db import match_leaks as _match_leaks
    _matches = _match_leaks({{"{leak_func}": leaked}})
    if _matches:
        libc = ELF(_matches[0].path)
        libc.address = leaked - libc.symbols["{leak_func}"]
        log.success(f"libc {{_matches[0].libc_version}} base: {{hex(libc.address)}}")
    else:
        log.error("本地索引未匹配到 libc，请用 -l 指定或先跑 pwnsolver.py libcdb build")
        exit(1)
except ImportError:
    log.error("libc_db 不可用（确认 pwn_solver 目录随脚本一起部署）")
    exit(1)
'''
