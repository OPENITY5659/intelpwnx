#!/usr/bin/env python3
"""离线 libc 索引测试：匹配正确性、loader 配对、以及"绝不联网"这条底线。

索引默认落在 pwn_solver/libc_db/index.json；测试用 PWNSOLVER_LIBC_DB 指向临时文件，
不污染仓库里的真实索引。
"""
import os
import shutil
import socket
import sys

import pytest

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BASE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'pwn_solver'))

import libc_db  # noqa: E402

LIBC_232 = os.path.join(ROOT, 'libcs', '2.32', 'lib', 'x86_64-linux-gnu', 'libc-2.32.so')
LIBC_233 = os.path.join(ROOT, 'libcs', '2.33', 'lib', 'x86_64-linux-gnu', 'libc-2.33.so')
CHALLENGE = os.path.join(ROOT, 'challenges', 'ret2libc')

pytestmark = pytest.mark.skipif(
    not (os.path.exists(LIBC_232) and os.path.exists(CHALLENGE)),
    reason='需要 libcs/2.32 与 challenges/ret2libc 作为 fixture')


@pytest.fixture()
def temp_index(tmp_path, monkeypatch):
    """把索引重定向到临时文件，并按需构建。"""
    idx = tmp_path / 'index.json'
    monkeypatch.setenv('PWNSOLVER_LIBC_DB', str(idx))
    return idx


def _build_temp_index(paths):
    index, stats = libc_db.build_index(paths=paths, verbose=False)
    assert stats['added'] == len(paths)
    return index


def test_describe_libc_extracts_version_symbols_and_loader():
    entry = libc_db.describe_libc(LIBC_232)
    assert entry['arch'] == 'amd64'
    assert entry['libc_version'] == '2.32'
    # 关键符号必须解析出来，否则匹配无从谈起
    for sym in ('puts', 'system', 'read', 'write', '__libc_start_main'):
        assert entry['symbols'].get(sym), f'{sym} 偏移未解析'
    assert entry['symbols'].get('str_bin_sh'), '/bin/sh 偏移未解析'
    # 配对 loader：libcs/2.32 目录里有 ld-2.32.so
    assert entry['loader'] and 'ld-2.32.so' in entry['loader']


def test_match_leaks_identifies_the_right_libc(temp_index):
    _build_temp_index([LIBC_232, LIBC_233])
    entry = libc_db.describe_libc(LIBC_232)
    base = 0x7f1234500000
    leaks = {
        'puts': base + entry['symbols']['puts'],
        'system': base + entry['symbols']['system'],
        'read': base + entry['symbols']['read'],
    }
    matches = libc_db.match_leaks(leaks, arch='amd64')
    assert matches, '三个符号的泄露应能匹配到候选'
    best = matches[0]
    assert best.libc_version == '2.32'
    assert os.path.basename(best.path) == 'libc-2.32.so'
    assert best.matched == 3
    assert best.base == base & ~0xfff or best.base, '应能推出基址'
    # 基址推算：泄露地址减去符号偏移
    assert best.base == leaks['puts'] - entry['symbols']['puts']


def test_match_uses_page_offset_so_aslr_base_is_irrelevant(temp_index):
    _build_temp_index([LIBC_232])
    entry = libc_db.describe_libc(LIBC_232)
    for base in (0x7f0000000000, 0x7ffff0000000, 0x7f9999900000):
        matches = libc_db.match_leaks({'puts': base + entry['symbols']['puts']}, arch='amd64')
        assert matches and os.path.basename(matches[0].path) == 'libc-2.32.so'


def test_match_arch_filter_and_miss(temp_index):
    _build_temp_index([LIBC_232])
    entry = libc_db.describe_libc(LIBC_232)
    # 架构不匹配 → 不给候选（避免把 i386 的 libc 用到 amd64 上）
    assert libc_db.match_leaks({'puts': 0x7f0000000000 | entry['symbols']['puts']},
                              arch='i386') == []
    # 偏移完全对不上 → 空列表，而不是瞎猜一个
    assert libc_db.match_leaks({'puts': 0x7f0000000fff}) == []
    assert libc_db.match_leaks({}) == []


def test_loader_pairing_falls_back_to_glibc_compat(tmp_path):
    """没有同级 loader 时，按版本去 glibc_compat/libcs 里找（2.23 特例的泛化）。"""
    src = os.path.join(ROOT, 'pwn_solver', 'glibc_compat')
    if not os.path.exists(os.path.join(src, 'ld-2.23.so')):
        pytest.skip('缺少 glibc_compat/ld-2.23.so')
    orphan_libc = tmp_path / 'libc-2.23.so'
    candidate_sources = [
        os.path.join(ROOT, 'cache', 'ciscn_dl', 'pwn2024', 'Pwn-orange_cat_diary', 'libc-2.23.so'),
        os.path.join(ROOT, 'pwn题目解析', 'ciscn', 'extracted',
                     '1-orange_cat_diary (1)', '1-orange_cat_diary', 'libc-2.23.so'),
        os.path.join(ROOT, 'external_challs', 'ctf-challenges', 'pwn', 'linux', 'user-mode',
                     'heap', 'fastbin-attack', '2017_0ctf_babyheap', 'libc.so.6'),
    ]
    source = next((p for p in candidate_sources if os.path.exists(p)), None)
    if not source:
        pytest.skip('本地没有 2.23 的 libc 附件可用于测试')
    shutil.copy(source, orphan_libc)
    found = libc_db.find_loader_for(str(orphan_libc))
    assert found, '2.23 的 libc 应能找到配对 loader'
    assert 'ld-2.23.so' in found


def test_detect_libc_ex_prefers_sibling_attachment(tmp_path):
    """同目录附件优先于系统 libc 兜底，并登记进索引。"""
    from badchars import detect_libc_ex
    shutil.copy(CHALLENGE, tmp_path / 'vuln')
    shutil.copy(LIBC_232, tmp_path / 'libc.so.6')
    info = detect_libc_ex(str(tmp_path / 'vuln'), register=False)
    assert info['source'] == 'sibling'
    assert os.path.basename(info['path']) == 'libc.so.6'
    assert info['suspect'] is False
    assert info['version'] == '2.32'


def test_auto_detect_libc_backcompat_signature():
    """旧的"返回路径字符串"契约必须保留（现有测试依赖它）。"""
    from badchars import auto_detect_libc
    assert callable(auto_detect_libc)
    path = auto_detect_libc(CHALLENGE)
    assert path is None or os.path.exists(path)


def test_index_never_touches_the_network(temp_index, monkeypatch):
    """断网底线：构建索引与匹配过程不得发起任何网络连接。"""

    def _boom(*args, **kwargs):
        raise AssertionError('离线路径不应创建 socket')

    monkeypatch.setattr(socket, 'socket', _boom)
    monkeypatch.setattr(socket, 'create_connection', _boom)

    index = _build_temp_index([LIBC_232])
    entry = libc_db.describe_libc(LIBC_232)
    matches = libc_db.match_leaks({'puts': 0x7f0000000000 | entry['symbols']['puts']}, arch='amd64')
    assert matches, '断网状态下匹配依然要工作'
    assert index['entries']


def test_no_cloud_libc_client_left_in_sources():
    """回归护栏：源码里不允许再出现 libc.rip 之类的云 API 依赖。

    只检查真正的代码（AST），文档字符串/注释里描述历史原因不算 —— 否则这条护栏
    会被自己的说明文字误伤。
    """
    import ast

    offenders = []
    for cur, _dirs, files in os.walk(os.path.join(ROOT, 'pwn_solver')):
        for name in files:
            if not name.endswith('.py'):
                continue
            path = os.path.join(cur, name)
            rel = os.path.relpath(path, ROOT)
            if rel.replace(os.sep, '/').startswith('pwn_solver/vendor/'):
                continue   # vendored 目录就是"本地实现"本身，不在护栏范围内
            with open(path, encoding='utf-8', errors='ignore') as f:
                text = f.read()
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            docstrings = set()
            for node in ast.walk(tree):
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    body = getattr(node, 'body', [])
                    if (body and isinstance(body[0], ast.Expr)
                            and isinstance(body[0].value, ast.Constant)
                            and isinstance(body[0].value.value, str)):
                        docstrings.add(id(body[0].value))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split('.')[0] in ('LibcSearcher', 'libcsearcher'):
                            offenders.append(f'{rel}: import {alias.name}')
                elif isinstance(node, ast.ImportFrom):
                    # level>0 是包内相对导入（例如本地实现自己的 __init__），不算云端依赖
                    if getattr(node, 'level', 0) == 0 and                             (node.module or '').split('.')[0] in ('LibcSearcher', 'libcsearcher'):
                        offenders.append(f'{rel}: from {node.module} import')
                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    if id(node) in docstrings:
                        continue
                    if 'libc.rip' in node.value or 'api/find' in node.value:
                        offenders.append(f'{rel}: 代码里出现云 API 地址')
    assert not offenders, f'仍存在联网 libc 依赖: {offenders}'


def test_leak_line_is_parsed_into_structured_leaks():
    """生成的 exploit 打印 [leak] sym=addr，反馈分析器要能结构化提取。"""
    from feedback_analyzer import FeedbackAnalyzer
    out = '[+] leaked\n[leak] puts=0x7f1234567890\n[leak] system=0x7f1234500000\n'
    fb = FeedbackAnalyzer(verbose=False).analyze(out, '', 0)
    assert fb.leaks == {'puts': 0x7f1234567890, 'system': 0x7f1234500000}
