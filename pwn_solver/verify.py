#!/usr/bin/env python3
"""统一的 shell 获取判定（外层流水线 + 生成脚本内联代码共用一套语义）。

为什么需要它：
  - 原来 16 个模板各自内联一份 verify_shell，判定口径不一致，Go/Rust 的
    bufio 预读场景下会把"已经拿到 shell"判成失败（假阴）；
  - 判定的严格度直接决定"✅ 解题成功"可不可信（假阳代价更高）。

两条线：
  1. 外层（本进程）：`classify_text()` / `interactive_verify()`，供
     exploit_templates.BaseExploit.test_with_feedback 使用 —— 它能在目标
     进程上真的写 stdin，是判定假阴的首选手段。
  2. 生成的脚本内：`shell_probe_code()` 返回内联片段，让模板只用一段
     规范代码探测 shell（含 [leak] 结构化泄露行，供离线 libc 索引反查）。
"""
import re

# 强成功标志：拿到 shell 的直接证据
SUCCESS_PATTERNS = (
    re.compile(r'PWNED_OK'),
    re.compile(r'uid=\d+\([^)]*\)'),
    re.compile(r'uid=\d+'),
)
# 弱成功标志：flag 内容或交互提示符（可能没有 shell，但确实打进去了）
WEAK_SUCCESS_PATTERNS = (
    re.compile(r'flag\{[^}]{2,}\}'),
    re.compile(r'[a-zA-Z0-9_]{2,}\{[^}]{4,}\}'),  # ctfshow{...} / CTF{...} 等
    re.compile(r'(?:^|\n)\$\s'),
    re.compile(r'(?:^|\n)#\s'),
)
CRASH_EVIDENCE = re.compile(
    r'(?:SIGSEGV|SIGILL|SIGABRT|segmentation\s+fault|illegal\s+instruction|'
    r'Program\s+received\s+signal)', re.I)

# 探测 shell 用的命令：先证身份，再顺手取 flag（在线赛题常见位置）
PROBE_COMMAND = 'echo PWNED_OK; id; cat flag* /flag* 2>/dev/null'

# 回显陷阱：有些目标会把输入原样打回来，于是 "echo PWNED_OK; id" 跟着输入一起出现，
# 标记检查命中的其实是**我们自己命令的回显**（实测 blind_fmt_got/blind 就是这么被
# 误判成"Shell obtained"的）。判定前先把这类回显行剔除。
#
# 注意不要加 \b：真实回显里命令常被前面的垃圾字节粘住（例如 "`techo PWNED_OK"），
# 词边界会让它匹配不上。真 shell 的输出行是单独的 PWNED_OK，不会被这条误删。
ECHO_OF_PROBE = re.compile(r'(?i)echo\s+PWNED_OK')


def strip_probe_echo(text: str) -> str:
    """剔除"我们的探测命令被目标回显"的行，避免把自己的输入当成 shell 输出。"""
    kept = [line for line in (text or '').splitlines()
            if not ECHO_OF_PROBE.search(line)]
    return '\n'.join(kept)


def classify_text(stdout: str, stderr: str, exit_code=None):
    """返回 (verdict, evidence)：verdict ∈ {'success','weak','fail'}。"""
    combined = f'{stdout or ""}\n{stderr or ""}'
    crashed = bool(CRASH_EVIDENCE.search(combined))
    clean = exit_code is None or exit_code == 0
    # 先剔掉"探测命令被回显"的行，否则回显会把自己的输入当成 shell 输出
    cleaned = strip_probe_echo(combined)
    if clean and not crashed:
        for pat in SUCCESS_PATTERNS:
            if pat.search(cleaned):
                return 'success', pat.pattern
        for pat in WEAK_SUCCESS_PATTERNS:
            if pat.search(cleaned):
                return 'weak', pat.pattern
    if crashed or (exit_code not in (None, 0)):
        return 'fail', f'crash_or_exit={exit_code}'
    return 'fail', 'no_marker'


def flag_in(text: str):
    """从任意文本里提取 flag（内部脚本与流水线共用同一套正则）。"""
    if not text:
        return None
    for pat in WEAK_SUCCESS_PATTERNS[:2]:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


def interactive_verify(proc, write_stdin, timeout=3.0, poll=0.25):
    """对仍在运行的目标进程做交互式验证。

    proc: 带 .poll()/.stdout 的子进程封装（由调用方提供）
    write_stdin: 写一行命令到目标 stdin 的可调用对象

    返回 (verdict, output_text)。目标进程已退出时返回 ('fail', '')。
    """
    import time

    if proc is None or proc.poll() is not None:
        return 'fail', ''
    try:
        write_stdin(PROBE_COMMAND + '\n')
    except Exception:
        return 'fail', ''
    text = ''
    deadline = time.time() + timeout
    while time.time() < deadline:
        time.sleep(poll)
        try:
            chunk = proc.recv(timeout=poll)
        except Exception:
            chunk = b''
        if chunk:
            text += chunk.decode('utf-8', 'replace') if isinstance(chunk, bytes) else str(chunk)
            verdict, _why = classify_text(text, '', 0)
            if verdict == 'success':
                return 'success', text
        if proc.poll() is not None:
            break
    verdict, _why = classify_text(text, '', 0)
    return verdict, text


def shell_probe_code(indent: str = '    ', arch: str = 'amd64',
                     leak_symbols=(), send_with_payload: bool = False) -> str:
    """生成写进 exploit 脚本的 shell 探测片段（规范版，供模板共用）。

    send_with_payload=True 时提示调用方把探测命令和最后的 payload 放在同一次
    send 里 —— Go/Rust 的 bufio 预读会把之后写的字节吞掉，必须这么发。

    判定里带"回显剔除"：目标若把输入原样打回来，`echo PWNED_OK; id` 会跟着输入出现，
    不能把它当成 shell 输出（盲打类题目实测会被这条误判成"Shell obtained"）。
    """
    pad = ' ' * len(indent)
    leak_lines = ''
    for sym in leak_symbols:
        leak_lines += (f"\n{indent}if leak is not None:\n"
                       f"{indent}    log.info('[leak] {sym}=%#x', leak)\n")
    lines = [
        f"{indent}def verify_shell(p, timeout=3.0):",
        f"{indent}    \"\"\"探测是否真的拿到 shell（PWNED_OK / uid= / flag；剔除命令回显）。\"\"\"",
        f"{indent}    import re as _re",
        f"{indent}    import time as _t",
        f"{indent}    try:",
        f"{indent}        p.sendline(b'echo PWNED_OK; id; cat flag* /flag* 2>/dev/null')",
        f"{indent}    except Exception:",
        f"{indent}        return False",
        f"{indent}    out = b''",
        f"{indent}    deadline = _t.time() + timeout",
        f"{indent}    while _t.time() < deadline:",
        f"{indent}        try:",
        f"{indent}            chunk = p.recv(timeout=0.3)",
        f"{indent}        except Exception:",
        f"{indent}            chunk = b''",
        f"{indent}        if chunk:",
        f"{indent}            out += chunk",
        f"{indent}            text = out.decode(errors='ignore')",
        f"{indent}            if b'uid=' in out or _re.search(r'(?im)^\\s*PWNED_OK\\s*$',",
        f"{indent}                                             _re.sub(r'(?i).*echo PWNED_OK.*', '', text)):",
        f"{indent}                break",
        f"{indent}        if not p.connected():",
        f"{indent}            break",
        f"{indent}    text = out.decode(errors='ignore')",
        f"{indent}    # 回显剔除：去掉「我们的命令被原样打回来」的那些行后再看标记",
        f"{indent}    cleaned = _re.sub(r'(?i).*echo PWNED_OK.*', '', text)",
        f"{indent}    ok = ('uid=' in text) or bool(_re.search(r'(?im)^\\s*PWNED_OK\\s*$', cleaned))",
        f"{indent}    if ok:",
        f"{indent}        log.success('shell verified')",
        f"{indent}        print(text)",
        f"{indent}    return ok",
    ]
    if send_with_payload:
        lines.insert(1, f"{indent}# 注意：本目标有 stdin 预读（Go/Rust bufio），"
                         "探测命令必须和 payload 一次发出，否则会被吞掉")
    return '\n'.join(lines) + leak_lines
