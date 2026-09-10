#!/usr/bin/env python3
"""堆题结构化诊断：把"打不了"变成"下一步该干什么"。

背景：之前 heap 分支被 one_gadget/ret2libc 的栈模板覆盖，产出的是栈利用脚本，
日志里却像"尝试过堆利用"——既浪费尝试次数，也让人误判进度。这里做两件事：

  1. 从二进制里抽出菜单协议（选项号 + 语义）与堆相关信号（free/calloc/scanf 计数、
     指针数组地址、libc 版本、是否 seccomp）；
  2. 结合配对 libc 的符号偏移，给出该版本下到底该打哪儿（__free_hook / tcache 结构 /
     _IO_2_1_stdout_ + FSOP）以及需要的泄露顺序，落盘 pwnsolver_evidence/<bin>.heap.md。

这些都是本地文件上的静态解析，不联网。
"""
import os
import re
import subprocess

# 菜单动词 → 语义。堆题菜单模板千变万化，但动词基本就这些。
VERB_KEYWORDS = {
    'create': ('create', 'add', 'malloc', 'new', 'alloc', 'append'),
    'delete': ('delete', 'free', 'remove', 'del', 'destroy'),
    'show': ('show', 'print', 'view', 'list', 'display', 'dump'),
    'edit': ('edit', 'modify', 'update', 'change', 'write', 'fill'),
    'exit': ('exit', 'quit', 'bye', 'leave'),
}
MENU_LINE_RE = re.compile(r'^\s*(\d{1,2})\s*[.):\-]\s*([A-Za-z][^\n]{0,40})$')

# 各 glibc 版本的利用面（仅用于给出方向；具体偏移从配对 libc 里读实数）
ERA_NOTES = (
    ((2, 23), (2, 26), '2.23/2.24 时代：fastbin dup + __malloc_hook/__free_hook（无 tcache，无 safe-linking）'),
    ((2, 27), (2, 31), '有 tcache：UAF → tcache poisoning 覆写 __free_hook = system，再 free("/bin/sh")'),
    ((2, 32), (2, 33), '有 safe-linking（fd 需 (addr>>12) 异或）且仍有 __free_hook：先泄露 heap 基址再 poison'),
    ((2, 34), (2, 99), '2.34+ 移除了 __free_hook/__malloc_hook：改打 tcache_perthread_struct '
                      '或 FSOP（_IO_2_1_stdout_ 泄露 + _IO_list_all / House of Apple 2）'),
)


def parse_menu(binary_path):
    """从 strings 里抽菜单：{verb: 选项号} + 提示串。"""
    try:
        out = subprocess.run(['strings', '-n', '4', binary_path],
                             capture_output=True, text=True, timeout=30).stdout
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return {'options': {}, 'raw': [], 'prompt': None}

    options, raw, prompt = {}, [], None
    for line in out.splitlines():
        m = MENU_LINE_RE.match(line)
        if m:
            num, text = int(m.group(1)), m.group(2).strip()
            raw.append(f'{num}. {text}')
            low = text.lower()
            for verb, words in VERB_KEYWORDS.items():
                if verb in options:
                    continue
                if any(w in low for w in words):
                    options[verb] = num
                    break
        elif line.strip() in ('> ', '>', 'choice:') or line.strip().endswith('>> '):
            prompt = line.strip()
    # 常见组合（"1. Create" / "2. Delete" ...）里，create/delete/show 必须有
    return {'options': options, 'raw': raw, 'prompt': prompt}


def libc_targets(libc_path):
    """从配对 libc 里读出该版本真实可打的符号偏移。"""
    if not libc_path or not os.path.exists(libc_path):
        return {}
    targets = {}
    try:
        from pwn import ELF
        libc = ELF(libc_path, checksec=False)
        for name in ('system', '__free_hook', '__malloc_hook', 'setcontext',
                     '_IO_2_1_stdout_', '_IO_list_all', 'str_bin_sh'):
            if name == 'str_bin_sh':
                try:
                    targets[name] = next(libc.search(b'/bin/sh'), None)
                except Exception:
                    targets[name] = None
                continue
            try:
                targets[name] = libc.symbols.get(name)
            except Exception:
                targets[name] = None
    except Exception:
        return targets
    return targets


def version_tuple(version):
    try:
        parts = [int(p) for p in re.findall(r'\d+', version or '')[:2]]
        return tuple(parts) if len(parts) == 2 else None
    except ValueError:
        return None


def era_note(version):
    vt = version_tuple(version)
    if not vt:
        return 'glibc 版本未知 → 先确认版本（本地 libc 索引 / 泄露反查）再决定打哪儿'
    for low, high, note in ERA_NOTES:
        if low <= vt <= high:
            return note
    return '未知版本区间'


def build_plan(binary_path, analysis=None, libc_path=None, libc_version=None, seccomp=False):
    """汇总堆题诊断信息，供 markdown 渲染与生成脚本注释使用。"""
    analysis = analysis or {}
    menu = analysis.get('heap_menu') or {}
    protections = analysis.get('protections') or {}
    parsed = parse_menu(binary_path)

    plan = {
        'binary': os.path.abspath(binary_path),
        'menu': parsed,
        'heap_menu': {
            'free_count': menu.get('free_count'),
            'calloc_count': menu.get('calloc_count'),
            'scanf_count': menu.get('scanf_count'),
            'ptr_array': menu.get('ptr_array'),
            'input_style': menu.get('input_style'),
        },
        'protections': protections,
        'libc_path': libc_path,
        'libc_version': libc_version,
        'libc_targets': libc_targets(libc_path),
        'seccomp': seccomp,
    }
    plan['era'] = era_note(libc_version)

    targets = plan['libc_targets']
    steps = []
    if seccomp:
        steps.append('注意：有 seccomp。__free_hook=system 这类"拿 shell"路线不可用，'
                     '要改成 ORW（open/read/write）或 FSOP 链')
    if targets.get('__free_hook'):
        steps.append(f"可打点：__free_hook @ {hex(targets['__free_hook'])}（配 system @ "
                     f"{hex(targets['system']) if targets.get('system') else '?'}）")
    if targets.get('_IO_2_1_stdout_'):
        steps.append(f"FSOP 用点：_IO_2_1_stdout_ @ {hex(targets['_IO_2_1_stdout_'])}，"
                     f"setcontext @ {hex(targets['setcontext']) if targets.get('setcontext') else '?'}")
    steps.append('泄露顺序：heap 基址（show 已 free 的 chunk）→ libc 基址'
                 '（unsorted bin 的 fd/bk）→ 再写目标')
    plan['steps'] = steps

    # 能否自动打：非 PIE + 有 win 符号 + 菜单里有 create/delete/show + UAF 风格
    can_auto, reason = _auto_feasibility(binary_path, plan)
    plan['can_auto'] = can_auto
    plan['auto_reason'] = reason
    return plan


def create_resets_funcptr(binary_path, window=8):
    """检测 create 流程是否"先拷贝、后把函数指针写回默认值"。

    这决定了"UAF 改函数指针 → win"这条通用路线是否可行。典型代码：

        call strcpy@plt
        lea  rdx,[rip+...]        # normal_print
        mov  QWORD PTR [rax+0x20],rdx      ← 拷贝之后再写回，用户数据被覆盖

    返回 (是否重置, 指针偏移或 None)。
    """
    try:
        out = subprocess.run(['objdump', '-d', '-M', 'intel', binary_path],
                             capture_output=True, text=True, timeout=60).stdout
    except (subprocess.CalledProcessError, FileNotFoundError,
            subprocess.TimeoutExpired, OSError):
        return False, None
    lines = out.splitlines()
    lea_re = re.compile(r'lea\s+\w+,\[rip[^\]]*\]\s*#\s*([0-9a-f]+)')
    store_re = re.compile(r'mov\s+QWORD\s+PTR\s+\[\w+\+(0x[0-9a-f]+)\],')
    for i, line in enumerate(lines):
        if 'call' not in line or 'strcpy@plt' not in line:
            continue
        saw_func_lea = False
        for j in range(i + 1, min(i + 1 + window, len(lines))):
            row = lines[j]
            if lea_re.search(row):
                saw_func_lea = True
            m = store_re.search(row)
            if saw_func_lea and m:
                return True, int(m.group(1), 16)
    return False, None


def _auto_feasibility(binary_path, plan):
    """判断这道题能不能用"释放后重写函数指针→win"这条通用路线自动打。"""
    opts = plan['menu']['options']
    missing = [k for k in ('create', 'delete', 'show') if k not in opts]
    if missing:
        return False, f'菜单里认不出 {"/".join(missing)} 选项，无法自动驱动协议'
    if plan['protections'].get('pie'):
        return False, 'PIE 开启：win 地址需要先泄露，自动路线暂不覆盖'
    try:
        from pwn import ELF
        elf = ELF(binary_path, checksec=False)
        if 'win' not in elf.symbols:
            return False, '没有 win 符号（不是"函数指针劫持到 win"这类题）'
        plan['win_addr'] = elf.symbols['win']
    except Exception as exc:
        return False, f'读取符号失败: {exc}'
    if plan['seccomp']:
        return False, '有 seccomp：win 里的 system("/bin/sh") 也不通，需要 ORW/FSOP'
    resets, ptr_off = create_resets_funcptr(binary_path)
    plan['funcptr_offset'] = ptr_off
    if resets:
        return False, (f'create 在 strcpy 之后又把函数指针（偏移 {hex(ptr_off or 0x20)}）'
                       '写回了默认值：改指针这条路线不成立，'
                       '应改走 double-free / tcache poisoning（本模板不覆盖）')
    return True, '非 PIE + win 符号 + 菜单可驱动 → 可用函数指针劫持路线自动尝试'


def render_markdown(plan):
    h = plan['heap_menu']
    opts = plan['menu']['options']
    lines = [f"# 堆题诊断：{os.path.basename(plan['binary'])}", '',
             f"- 二进制: `{plan['binary']}`",
             f"- 保护: PIE={plan['protections'].get('pie')} "
             f"Canary={plan['protections'].get('canary')} NX={plan['protections'].get('nx')}",
             f"- libc: {plan.get('libc_path') or '未提供'}（版本 {plan.get('libc_version') or '未知'}）",
             f"- seccomp: {plan['seccomp']}", '',
             '## 菜单协议',
             f"- 识别到选项: {opts or '未识别'}",
             f"- 提示串: {plan['menu']['prompt'] or '未识别'}"]
    for row in plan['menu']['raw'][:12]:
        lines.append(f"  - `{row}`")
    lines += ['', '## 堆信号',
              f"- free 调用: {h['free_count']}，calloc/malloc: {h['calloc_count']}，"
              f"scanf: {h['scanf_count']}",
              f"- 指针数组: {h['ptr_array'] or '未识别'}，输入风格: {h['input_style'] or '未识别'}", '',
              '## 该版本该打哪儿', f"- {plan['era']}"]
    for step in plan['steps']:
        lines.append(f"- {step}")
    lines += ['', '## 自动利用可行性',
              f"- {'可以' if plan['can_auto'] else '不行'}：{plan['auto_reason']}"]
    if plan.get('win_addr'):
        lines.append(f"- win 符号: {hex(plan['win_addr'])}")
    lines += ['', '## 建议动作',
              '1. 用上面识别出的选项号把 add/free/show 跑一遍，确认 chunk 大小与 free 后指针是否置空；',
              '2. 按"泄露顺序"先拿 heap/libc 基址，再决定写 __free_hook / tcache 结构 / FSOP；',
              '3. 有 seccomp 时目标链改成 ORW（open/read/write）或 House of Apple 2。']
    return '\n'.join(lines) + '\n'


def write_evidence(plan, workdir=None):
    """把诊断写到 pwnsolver_evidence/<bin>.heap.md（与 recon 证据同目录约定）。"""
    binary = plan['binary']
    out_dir = workdir or os.path.join(os.path.dirname(binary), 'pwnsolver_evidence')
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f'{os.path.basename(binary)}.heap.md')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(render_markdown(plan))
    return path
