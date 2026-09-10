#!/usr/bin/env python3
"""堆题诊断测试：能自动打的题要判"可自动"，打不了的要给出诚实原因（而不是硬套栈模板）。"""
import os
import sys

import pytest

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BASE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'pwn_solver'))

import heap_diagnose  # noqa: E402

HEAP_UAF = os.path.join(ROOT, 'challenges', 'heap_uaf')

pytestmark = pytest.mark.skipif(not os.path.exists(HEAP_UAF),
                               reason='需要 challenges/heap_uaf（跑 scripts/build_challenges.sh）')


def test_menu_parsed_from_strings():
    plan = heap_diagnose.build_plan(HEAP_UAF, analysis={'heap_menu': {}, 'protections': {}})
    opts = plan['menu']['options']
    assert opts.get('create') == 1
    assert opts.get('delete') == 2
    assert opts.get('show') == 3
    assert opts.get('exit') == 4


def test_create_resets_funcptr_is_detected():
    """heap_uaf 的 create 在 strcpy 之后又写回 normal_print → 改指针路线不成立。"""
    resets, off = heap_diagnose.create_resets_funcptr(HEAP_UAF)
    assert resets is True
    assert off == 0x20


def test_feasibility_refuses_pointer_route_with_clear_reason():
    plan = heap_diagnose.build_plan(HEAP_UAF, analysis={'heap_menu': {}, 'protections': {}})
    assert plan['can_auto'] is False
    assert '写回' in plan['auto_reason'] and 'double-free' in plan['auto_reason'], \
        f'原因要具体到"为什么这条路不成立": {plan["auto_reason"]}'


def test_evidence_markdown_written():
    plan = heap_diagnose.build_plan(HEAP_UAF, analysis={'heap_menu': {}, 'protections': {}})
    path = heap_diagnose.write_evidence(plan, workdir=os.path.join(BASE, '_evidence_tmp'))
    try:
        assert os.path.exists(path)
        text = open(path, encoding='utf-8').read()
        assert '该版本该打哪儿' in text
        assert '自动利用可行性' in text
    finally:
        import shutil
        shutil.rmtree(os.path.dirname(path), ignore_errors=True)


def test_generated_heap_exploit_never_emits_stack_template():
    """heap 模板必须"要么真打、要么给诊断"，绝不能退化成 ret2libc 栈模板。"""
    from exploit_templates import HeapExploit
    e = HeapExploit(HEAP_UAF,
                    analysis={'heap_menu': {'free_count': 1, 'calloc_count': 1},
                              'functions': {}, 'protections': {}},
                    gadgets={})
    code = e.generate()
    assert 'heap_diagnose 不可用' not in code
    assert 'ROP(libc)' not in code and 'POP_RDI' not in code, '不得输出栈 ROP 模板'
    assert 'verify_shell' in code or 'diagnos' in code.lower() or '诊断' in code
