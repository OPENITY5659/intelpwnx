#!/usr/bin/env python3
"""
PwnSolver GUI v2 — 自动PWN解题器前端
支持: WSL/本机解题、自适应求解器、交互Shell、exp管理、代码审计
"""

import subprocess, sys, os, threading, json, time, re, shlex, datetime, queue
from pathlib import Path

def sanitize(text):
    """移除不可打印字符"""
    return re.sub(r'[^\x20-\x7e\u4e00-\u9fff\u3000-\u303f\uff00-\uffef\n\r\t]', '', text)

try:
    import tkinter as tk
    from tkinter import ttk, filedialog, scrolledtext, messagebox
except ImportError:
    print("tkinter not found! Install: pip install tk")
    sys.exit(1)

# ========= 路径与执行环境 =========
def to_wsl_path(win_path):
    """C:\\Users\\... → /mnt/c/Users/... (Linux 路径原样返回)"""
    p = win_path.replace('\\', '/')
    if ':' in p:
        drive, rest = p.split(':', 1)
        p = f'/mnt/{drive.lower()}{rest}'
    return p

IS_WINDOWS = sys.platform == 'win32'

def exec_prefix():
    """Windows 上经 wsl 执行; 在 WSL/Linux 内直接执行"""
    return ['wsl', 'bash', '-c'] if IS_WINDOWS else ['bash', '-c']

def open_path(path):
    """跨平台打开文件/文件夹"""
    if IS_WINDOWS:
        os.startfile(path)
    else:
        subprocess.Popen(['xdg-open', path],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# 彩虹色 (成功命令着色用)
RAINBOW_COLORS = ['#f38ba8', '#fab387', '#f9e2af', '#a6e3a1', '#89b4fa', '#cba6f7']

# ========= 反汇编标注 (纯函数, 便于测试) =========
# 标注 tag → 语义
DISASM_TAGS = {
    'danger_call': '危险函数调用 (gets/read/scanf/strcpy...)',
    'overflow':    '溢出点 (read 长度 > 缓冲区)',
    'win':         'win 函数 / system 调用',
    'canary':      'canary 存取 (fs:0x28)',
    'fmt':         '格式化字符串漏洞 (printf 栈缓冲)',
    'io_leak':     'read+write 栈泄露 (canary/PIE 绕过锚点)',
    'crypto':      '加解密算法识别 (base64/xor/rot13/hex/AES/MD5/TEA)',
}

def build_disasm_annotated(disasm, analysis):
    """把反汇编文本按行标注 → (disasm, {行号: tag})

    analysis: BinaryAnalyzer.find_interesting_functions() 的结果
    """
    annot = {}
    lines = disasm.split('\n')
    # 行号 → 地址 (指令行 + 函数头行)
    line_addr = {}
    for i, line in enumerate(lines):
        m = re.match(r'^\s*([0-9a-f]+):', line)
        if m:
            line_addr[i] = int(m.group(1), 16)
            continue
        m = re.match(r'^([0-9a-f]+)\s+<[^>]+>:', line)
        if m:
            line_addr[i] = int(m.group(1), 16)
    funcs = analysis.get('functions', {}) if analysis else {}

    def mark(addr, tag, radius=0):
        for i, a in line_addr.items():
            if a == addr or (0 < radius and addr <= a < addr + radius):
                annot[i] = tag

    # 1. 危险函数 (PLT 调用行: call <xxx@plt>)
    danger_syms = {'gets', 'read', 'scanf', '__isoc99_scanf', '__isoc23_scanf',
                   'strcpy', 'strcat', 'sprintf', 'memcpy', 'memmove', 'gets'}
    for i, line in enumerate(lines):
        m = re.search(r'call\s+[0-9a-f]+\s+<([^>]+)@plt>', line)
        if m and m.group(1) in danger_syms:
            annot[i] = 'danger_call'
    # 2. 溢出点 (inner_read_overflow 的函数内 read 调用)
    overflow_funcs = {o.get('function') for o in funcs.get('inner_overflows', [])}
    cur_func = None
    for i, line in enumerate(lines):
        fm = re.match(r'^[0-9a-f]+\s+<([^>]+)>:', line)
        if fm:
            cur_func = fm.group(1)
        if cur_func in overflow_funcs and re.search(r'call\s+.*<read@plt>', line):
            annot[i] = 'overflow'
    # 3. win 函数体与 system 调用
    win_addrs = []
    for name, addr in funcs.get('win', []):
        if isinstance(addr, str) and addr.startswith('0x'):
            win_addrs.append(int(addr, 16))
    for name, addr in funcs.get('implied_win', []):
        if isinstance(addr, str) and addr.startswith('0x'):
            win_addrs.append(int(addr, 16))
    for i, line in enumerate(lines):
        if re.search(r'call\s+.*<system@plt>', line) or \
                re.search(r'call\s+.*<execve@plt>', line):
            annot[i] = 'win'
    for wa in win_addrs:
        for i, a in line_addr.items():
            if a == wa:
                annot[i] = 'win'
    # 4. canary 存取
    for i, line in enumerate(lines):
        if 'fs:0x28' in line or '__stack_chk' in line:
            annot[i] = 'canary'
    # 5. fmtstr 漏洞 (fmt_string.funcs 内 printf 调用)
    fmt_funcs = set((funcs.get('fmt_string') or {}).get('funcs', []))
    cur_func = None
    for i, line in enumerate(lines):
        fm = re.match(r'^[0-9a-f]+\s+<([^>]+)>:', line)
        if fm:
            cur_func = fm.group(1)
        if cur_func in fmt_funcs and re.search(r'call\s+.*<printf@plt>', line):
            annot[i] = 'fmt'
    # 6. io_leak 锚点 (read/write 泄露函数)
    io_func = (funcs.get('io_leak') or {}).get('func')
    if io_func:
        cur_func = None
        for i, line in enumerate(lines):
            fm = re.match(r'^[0-9a-f]+\s+<([^>]+)>:', line)
            if fm:
                cur_func = fm.group(1)
            if cur_func == io_func and re.search(r'call\s+.*<(?:read|write|__isoc(?:99|23)_scanf)@plt>', line):
                annot[i] = 'io_leak'
    return disasm, annot

# ========= 漏洞演示内容 =========
VULN_DEMO = [
    ("栈溢出 (Stack Overflow)",
     "危险: read/gets/scanf 读入超过栈缓冲区大小, 覆盖 saved rbp 与返回地址\n"
     "利用: ret2win (跳 win 函数) / ret2libc (泄露 libc → system(\"/bin/sh\")) /\n"
     "      ret2syscall (binary 内 syscall 链) / 栈迁移 (leave;ret → bss)\n"
     "本项目: analyzer 检测 inner_read_overflow (buf→ret 距离), 模板自动生成链"),
    ("堆溢出 (Heap Overflow)",
     "危险: malloc 块内写入越界, 破坏相邻 chunk 的 size/fd 字段\n"
     "利用: tcache poisoning (改 fd 任意地址分配) / unsorted bin 泄露 libc /\n"
     "      double free (dup) / UAF (释放后使用函数指针)\n"
     "本项目: HeapExploit 菜单探测 + func-ptr 覆写原语; 高级链见 heap_exploit.py"),
    ("格式化字符串 (Format String)",
     "危险: printf(buf) 格式参数可控 → 任意地址读/写\n"
     "利用: %p 泄露 (canary/libc/栈) + %n/%hn 写 GOT 或全局变量\n"
     "本项目: analyzer 检测 printf(栈缓冲) + global_compare (secret 比较),\n"
     "      FormatStringExploit 自动探测参数偏移并写目标"),
    ("Canary 绕过",
     "防护: 栈帧插入随机值 (fs:0x28), 返回前校验\n"
     "绕过: ① 信息泄露 (write 按长度输出/printf %p) 读出 canary 再原样写回\n"
     "      ② canary 爆破 (fork 服务端逐字节猜, 低 8 位 0x00)\n"
     "      ③ 改写 __stack_chk_fail@got (Partial RELRO)\n"
     "本项目: Ret2LibcHardenedExploit 一轮 leak canary+saved rbp+返回地址"),
    ("PIE 绕过",
     "防护: 代码段随机基址, 静态地址失效\n"
     "绕过: ① 泄露返回地址 (write/puts 带出) → base = leak - 锚点偏移\n"
     "      ② partial overwrite (低字节覆盖, 页内偏移不变)\n"
     "      ③ 只使用 libc gadget (libc 基址泄露后与 PIE 无关)\n"
     "本项目: hardened 模板 leak ret 算 PIE base (call_vuln 锚点)"),
    ("NX 绕过",
     "防护: 栈/堆不可执行, shellcode 失效\n"
     "绕过: ROP 链复用现有代码 (ret2libc/ret2syscall/one_gadget)\n"
     "本项目: gadget_finder 收集 pop_rdi/ret/syscall + libc 相对偏移"),
    ("Full RELRO",
     "防护: GOT 只读, 无法改写函数指针\n"
     "绕过: 不写 GOT — leak libc 后用 libc 内 gadget 链; 或劫持栈返回地址/\n"
     "      __free_hook (glibc<2.34) / exit handlers\n"
     "本项目: ret2libc 链不依赖 GOT 覆写, Full RELRO 下实测可解"),
    ("FORTIFY",
     "防护: 编译期检查 read/strcpy 等目标大小, 超限直接 abort\n"
     "绕过: ① 漏洞点换成 scanf(\"%s\") (glibc 不检查目标大小)\n"
     "      ② 缓冲区大小对编译器不可见 (参数传递/堆指针)\n"
     "本项目: io_leak 检测 scanf 型漏洞点并自动利用"),
]

def classify_line(line):
    """按内容给日志行分类 → tag (纯函数, 便于测试)

    返回: 'success' | 'error' | 'warning' | 'bold' | 'shell' | 'cmd' | None
    cmd = 命令回显行 ($ 开头), 独立于普通 shell 输出以便着色区分
    """
    if line.startswith('$ ') or line.startswith('$'):
        return 'cmd'
    line_lower = line.lower()
    if any(k in line for k in ['成功', '★', 'solved', '✅']) \
            or any(k in line_lower for k in ['success', 'pwned_ok', 'flag{', 'uid=']):
        return 'success'
    if any(k in line for k in ['失败', 'error', '✗', '❌']):
        return 'error'
    if any(k in line for k in ['⚠', 'warning', '警告']):
        return 'warning'
    if any(k in line for k in ['📋', '①', '决策', '阶段', 'gadgets', 'seccomp']):
        return 'bold'
    if any(k in line for k in ['$', '#', '>>>', 'interactive']):
        return 'shell'
    return None

def kill_process_tree(proc):
    """杀掉进程树 (bash -c 包装下需连同子进程)"""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            proc.kill()
    except Exception:
        pass

def build_solve_cmd(workspace, binary, libc='', ld='', remote_host='',
                    remote_port='', timeout=120, adaptive=True):
    """构建 solver 命令 (纯函数, 便于测试)"""
    args = ['python3', '-W', 'ignore', 'pwn_solver/solver.py', binary]
    if libc:
        args += ['-l', libc]
    if ld:
        args += ['-d', ld]
    if remote_host and remote_port:
        args += ['-r', remote_host, str(remote_port)]
    args += ['-t', str(timeout)]
    if not adaptive:
        args += ['--no-adaptive']
    return f"cd {shlex.quote(workspace)} && " + ' '.join(shlex.quote(a) for a in args)

WORKSPACE = to_wsl_path(str(Path(__file__).parent))
EXPLOITS_DIR = os.path.join(str(Path(__file__).parent), 'exploits')
os.makedirs(EXPLOITS_DIR, exist_ok=True)

# ========= 主窗口 =========
class PwnSolverGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("PwnSolver v3 — 自适应PWN解题器 (四面板)")
        self.root.geometry("1000x800")
        self.root.configure(bg='#1e1e2e')
        
        # Notebook 深色样式 (让四面板 tab 显眼)
        style = ttk.Style(self.root)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        style.configure('TNotebook', background='#1e1e2e', borderwidth=0)
        style.configure('TNotebook.Tab', background='#313244', foreground='#cdd6f4',
                        padding=(14, 6), font=('Consolas', 10, 'bold'))
        style.map('TNotebook.Tab',
                  background=[('selected', '#45475a'), ('active', '#3b3d52')],
                  foreground=[('selected', '#f9e2af')])
        
        self.solver_script = f'{WORKSPACE}/pwn_solver/solver.py'
        self._killed = False
        self._shell_proc = None      # 交互shell进程
        self._solve_proc = None      # 当前解题进程 (用于停止)
        self._last_exploit_path = None
        self._last_cmd_start = None  # 最后一条命令回显行的起始 index (成功时彩虹着色)
        self._run_proc = None        # 程序直接运行面板的进程
        self._ui_queue = queue.Queue()  # worker 线程 → 主线程 UI 调用队列 (tkinter 线程安全)
        
        self._build_ui()
        # 启动 UI 调用队列泵 (worker 线程不可直接 root.after, Python3.14 tkinter 会抛 RuntimeError)
        self.root.after(50, self._drain_ui_queue)
        self.log("PwnSolver GUI v3 已启动 (四面板)", 'info')
        self.log('下半部分四个 tab: 📄输出日志 | 🔧反汇编 | ▶程序运行 | 📚漏洞演示', 'bold')
        self.log('选择binary → 开始解题 → 成功后可交互Shell', 'info')
        self._refresh_exp_list()
    
    def _build_ui(self):
        # === 顶部标题 ===
        header = tk.Frame(self.root, bg='#2d2d44', height=45)
        header.pack(fill='x')
        tk.Label(header, text="🔧 PwnSolver v2 — 自适应PWN解题框架",
                font=('Consolas', 13, 'bold'), fg='#cdd6f4', bg='#2d2d44',
                pady=8).pack()
        
        # === 配置区 ===
        cfg_frame = tk.Frame(self.root, bg='#1e1e2e', pady=8)
        cfg_frame.pack(fill='x', padx=20)
        
        # 行1: Binary + Libc
        row1 = tk.Frame(cfg_frame, bg='#1e1e2e')
        row1.pack(fill='x')
        tk.Label(row1, text="📦 Binary:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=0, sticky='w', pady=3)
        self.binary_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.binary_var, width=55,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=1, padx=5)
        tk.Button(row1, text="浏览", command=self._browse_binary,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=0, column=2)
        
        tk.Label(row1, text="📚 Libc:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=3, sticky='w', padx=(20,0), pady=3)
        self.libc_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.libc_var, width=25,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=4, padx=5)
        tk.Button(row1, text="浏览", command=self._browse_libc,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=0, column=5)
        tk.Label(row1, text="📎 LD:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=6, sticky='w', padx=(20,0), pady=3)
        self.ld_var = tk.StringVar()
        tk.Entry(row1, textvariable=self.ld_var, width=20,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=7, padx=5)
        tk.Button(row1, text="浏览", command=self._browse_ld,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=0, column=8)
        
        # 行2: Remote Host + Port + Timeout + 选项
        row2 = tk.Frame(cfg_frame, bg='#1e1e2e')
        row2.pack(fill='x', pady=(5,0))
        
        tk.Label(row2, text="🌐 Host:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=0, sticky='w', pady=3)
        self.remote_host_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.remote_host_var, width=22,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=1, padx=3, sticky='w')
        
        tk.Label(row2, text="🔌 Port:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=2, sticky='w', padx=(3,0))
        self.remote_port_var = tk.StringVar()
        tk.Entry(row2, textvariable=self.remote_port_var, width=7,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=3, padx=3, sticky='w')
        
        tk.Label(row2, text="⏱ 超时:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=4, sticky='w', padx=(10,0))
        self.timeout_var = tk.StringVar(value='120')
        tk.Entry(row2, textvariable=self.timeout_var, width=6,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=5, padx=3, sticky='w')
        
        # 自适应求解器选项 + 成功自动Shell
        self.adaptive_var = tk.BooleanVar(value=True)
        tk.Checkbutton(row2, text="🔁 自适应", variable=self.adaptive_var,
                bg='#1e1e2e', fg='#a6e3a1', selectcolor='#313244',
                font=('Consolas', 9), activebackground='#1e1e2e',
                activeforeground='#a6e3a1').grid(row=0, column=4, padx=(20,0))
        self.auto_shell_var = tk.BooleanVar(value=False)
        tk.Checkbutton(row2, text="💻 成功后自动Shell", variable=self.auto_shell_var,
                bg='#1e1e2e', fg='#cba6f7', selectcolor='#313244',
                font=('Consolas', 9), activebackground='#1e1e2e',
                activeforeground='#cba6f7').grid(row=0, column=5, padx=(10,0))
        
        # 行3: 自定义命令执行
        row3 = tk.Frame(cfg_frame, bg='#1e1e2e')
        row3.pack(fill='x', pady=(5,0))
        tk.Label(row3, text="⌨ 自定义命令:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=0, sticky='w', pady=3)
        self.custom_cmd_var = tk.StringVar()
        self.custom_cmd_entry = tk.Entry(row3, textvariable=self.custom_cmd_var, width=75,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9))
        self.custom_cmd_entry.grid(row=0, column=1, padx=5)
        self.custom_cmd_entry.bind('<Return>', lambda e: self._run_custom())
        tk.Button(row3, text="▶ 执行", command=self._run_custom,
                bg='#89b4fa', fg='#1e1e2e', relief='flat', cursor='hand2',
                font=('Consolas', 9, 'bold')).grid(row=0, column=2, padx=3)
        tk.Label(row3, text="(bash 语法, 输出流式进日志)", fg='#6c7086', bg='#1e1e2e',
                font=('Consolas', 8)).grid(row=0, column=3, sticky='w', padx=5)
        
        # === 按钮区 ===
        btn_frame = tk.Frame(self.root, bg='#1e1e2e', pady=8)
        btn_frame.pack(fill='x', padx=20)
        
        self.solve_btn = tk.Button(btn_frame, text="🚀 开始解题",
                command=self._start_solve,
                bg='#89b4fa', fg='#1e1e2e', font=('Consolas', 11, 'bold'),
                relief='flat', padx=25, pady=6, cursor='hand2')
        self.solve_btn.pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="📋 代码审计",
                command=self._run_audit,
                bg='#a6e3a1', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="🔍 偏移检测",
                command=self._run_offset,
                bg='#fab387', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        # Shell按钮
        self.shell_btn = tk.Button(btn_frame, text="💻 交互Shell",
                command=self._open_interactive_shell,
                bg='#cba6f7', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2', state='disabled')
        self.shell_btn.pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="📁 Exp文件夹",
                command=self._open_exp_folder,
                bg='#45475a', fg='#cdd6f4', font=('Consolas', 10),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        tk.Button(btn_frame, text="🗑 清空日志",
                command=lambda: self.output.delete(1.0, tk.END),
                bg='#45475a', fg='#cdd6f4', font=('Consolas', 10),
                relief='flat', padx=12, pady=6, cursor='hand2').pack(side='left', padx=3)
        
        self.stop_btn = tk.Button(btn_frame, text="⏹ 停止",
                command=self._stop_solve,
                bg='#f38ba8', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=12, pady=6, cursor='hand2')
        self.stop_btn.pack(side='left', padx=3)
        
        # 进度条
        self.progress = ttk.Progressbar(self.root, mode='indeterminate')
        self.progress.pack(fill='x', padx=20, pady=3)
        
        # === Notebook 四面板: 日志 / 反汇编 / 程序运行 / 漏洞演示 ===
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=5)
        
        # ---- Tab1: 输出日志 + exp列表 ----
        tab_log = tk.Frame(self.notebook, bg='#1e1e2e')
        paned = tk.PanedWindow(tab_log, orient='horizontal',
                               bg='#1e1e2e', sashrelief='flat')
        paned.pack(fill='both', expand=True)
        
        # 左: 输出区
        left = tk.Frame(paned, bg='#1e1e2e')
        tk.Label(left, text="📄 输出日志:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).pack(anchor='w')
        self.output = scrolledtext.ScrolledText(left,
                bg='#11111b', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 10), wrap='word',
                relief='flat', borderwidth=0)
        self.output.pack(fill='both', expand=True)
        
        # 颜色标签
        self.output.tag_configure('success', foreground='#a6e3a1')
        self.output.tag_configure('error', foreground='#f38ba8')
        self.output.tag_configure('warning', foreground='#fab387')
        self.output.tag_configure('info', foreground='#89b4fa')
        self.output.tag_configure('bold', foreground='#cdd6f4', font=('Consolas', 10, 'bold'))
        self.output.tag_configure('shell', foreground='#cba6f7')
        self.output.tag_configure('cmd', foreground='#f9e2af', font=('Consolas', 10, 'bold'))
        self.output.tag_configure('cmd_success', foreground='#a6e3a1', font=('Consolas', 10, 'bold'))
        for i, color in enumerate(RAINBOW_COLORS):
            self.output.tag_configure(f'rainbow{i}', foreground=color)
        
        # 右: exp列表 + shell输入
        right = tk.Frame(paned, bg='#1e1e2e', width=280)
        
        tk.Label(right, text="📁 Exploits:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).pack(anchor='w')
        self.exp_listbox = tk.Listbox(right,
                bg='#11111b', fg='#cdd6f4',
                font=('Consolas', 9), relief='flat', borderwidth=0,
                selectbackground='#45475a', selectforeground='#cdd6f4')
        self.exp_listbox.pack(fill='both', expand=True, pady=(0,5))
        self.exp_listbox.bind('<Double-Button-1>', self._open_selected_exp)
        # 右键菜单: 打开 / 复制路径 / 删除 / 刷新
        self.exp_menu = tk.Menu(self.root, tearoff=0,
                                bg='#313244', fg='#cdd6f4',
                                activebackground='#45475a', activeforeground='#cdd6f4')
        self.exp_menu.add_command(label="打开", command=self._open_selected_exp)
        self.exp_menu.add_command(label="复制路径", command=self._copy_exp_path)
        self.exp_menu.add_command(label="删除", command=self._delete_selected_exp)
        self.exp_menu.add_separator()
        self.exp_menu.add_command(label="刷新", command=self._refresh_exp_list)
        self.exp_listbox.bind('<Button-3>', self._show_exp_menu)
        
        # Shell快速输入
        tk.Label(right, text="💻 快速Shell:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).pack(anchor='w')
        shell_frame = tk.Frame(right, bg='#1e1e2e')
        shell_frame.pack(fill='x')
        self.shell_input = tk.Entry(shell_frame,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9))
        self.shell_input.pack(side='left', fill='x', expand=True, padx=(0,3))
        self.shell_input.bind('<Return>', self._send_shell_command)
        tk.Button(shell_frame, text="发送", command=self._send_shell_command,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).pack(side='right')
        
        paned.add(left, stretch='always')
        paned.add(right, stretch='never')
        self.notebook.add(tab_log, text=' 📄 输出日志 ')
        
        # ---- Tab2: 反编译视图 (伪C F5 / 汇编切换) ----
        tab_disasm = tk.Frame(self.notebook, bg='#1e1e2e')
        disasm_bar = tk.Frame(tab_disasm, bg='#1e1e2e')
        disasm_bar.pack(fill='x', pady=(4, 2))
        self.disasm_mode = 'c'   # 'c' 伪C (F5) | 'asm' 汇编
        tk.Button(disasm_bar, text="🖥 伪C (F5)", command=lambda: self._set_disasm_mode('c'),
                bg='#89b4fa', fg='#1e1e2e', relief='flat', cursor='hand2',
                font=('Consolas', 9, 'bold')).pack(side='left', padx=3)
        tk.Button(disasm_bar, text="🔧 汇编", command=lambda: self._set_disasm_mode('asm'),
                bg='#45475a', fg='#cdd6f4', relief='flat', cursor='hand2',
                font=('Consolas', 9)).pack(side='left', padx=3)
        self.disasm_info = tk.Label(disasm_bar, text="选择 binary 后自动加载伪 C (main+调用链)",
                fg='#a6adc8', bg='#1e1e2e', font=('Consolas', 8))
        self.disasm_info.pack(side='left', padx=8)
        self.disasm = scrolledtext.ScrolledText(tab_disasm,
                bg='#11111b', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 10), wrap='none', relief='flat', borderwidth=0)
        self.disasm.pack(fill='both', expand=True)
        self.disasm.config(state='disabled')
        # 标注颜色
        self.disasm.tag_configure('danger_call', foreground='#f38ba8')
        self.disasm.tag_configure('overflow', foreground='#fab387')
        self.disasm.tag_configure('win', foreground='#a6e3a1')
        self.disasm.tag_configure('canary', foreground='#cba6f7')
        self.disasm.tag_configure('fmt', foreground='#f5c2e7')
        self.disasm.tag_configure('io_leak', foreground='#f9e2af')
        self.disasm.tag_configure('crypto', foreground='#f9e2af',
                                  font=('Consolas', 10, 'bold'))
        self.disasm.tag_configure('comment', foreground='#6c7086')
        self.disasm.tag_configure('func_head', foreground='#89b4fa',
                                  font=('Consolas', 10, 'bold'))
        self.notebook.add(tab_disasm, text=' 🖥 伪C视图 ')
        
        # ---- Tab3: 程序实际运行 (不带 exp) ----
        tab_run = tk.Frame(self.notebook, bg='#1e1e2e')
        run_bar = tk.Frame(tab_run, bg='#1e1e2e')
        run_bar.pack(fill='x', pady=(4, 2))
        tk.Button(run_bar, text="▶ 启动程序", command=self._start_run_binary,
                bg='#a6e3a1', fg='#1e1e2e', relief='flat', cursor='hand2',
                font=('Consolas', 9, 'bold')).pack(side='left', padx=3)
        tk.Button(run_bar, text="⏹ 关闭", command=self._stop_run_binary,
                bg='#f38ba8', fg='#1e1e2e', relief='flat', cursor='hand2',
                font=('Consolas', 9, 'bold')).pack(side='left', padx=3)
        self.run_status = tk.Label(run_bar, text="未启动",
                fg='#a6adc8', bg='#1e1e2e', font=('Consolas', 8))
        self.run_status.pack(side='left', padx=8)
        tk.Label(run_bar, text="直接运行 binary 观察真实输入/输出 (不含 exp)",
                fg='#6c7086', bg='#1e1e2e', font=('Consolas', 8)).pack(side='right', padx=5)
        self.run_output = scrolledtext.ScrolledText(tab_run,
                bg='#11111b', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 10), wrap='word', relief='flat', borderwidth=0)
        self.run_output.pack(fill='both', expand=True)
        run_input_bar = tk.Frame(tab_run, bg='#1e1e2e')
        run_input_bar.pack(fill='x', pady=(2, 4))
        self.run_input = tk.Entry(run_input_bar,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9))
        self.run_input.pack(side='left', fill='x', expand=True, padx=(0, 3))
        self.run_input.bind('<Return>', lambda e: self._send_run_input())
        tk.Button(run_input_bar, text="发送", command=self._send_run_input,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).pack(side='right')
        tk.Button(run_input_bar, text="发送十六进制", command=self._send_run_hex,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).pack(side='right', padx=3)
        self.notebook.add(tab_run, text=' ▶ 程序运行 ')
        
        # ---- Tab4: 漏洞情况演示 ----
        tab_demo = tk.Frame(self.notebook, bg='#1e1e2e')
        self.demo_text = scrolledtext.ScrolledText(tab_demo,
                bg='#11111b', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 10), wrap='word', relief='flat', borderwidth=0)
        self.demo_text.pack(fill='both', expand=True)
        self.demo_text.config(state='disabled')
        self.demo_text.tag_configure('demo_title', foreground='#a6e3a1',
                                     font=('Consolas', 10, 'bold'))
        self.demo_text.tag_configure('demo_body', foreground='#cdd6f4')
        self.demo_text.tag_configure('demo_hit', foreground='#f9e2af',
                                     font=('Consolas', 10, 'bold'))
        self._render_vuln_demo()
        self.notebook.add(tab_demo, text=' 📚 漏洞演示 ')

        # ---- Tab5: Web 题解题 ----
        self._build_web_tab()
        
        # 底部状态栏
        self.status_var = tk.StringVar(value="就绪")
        tk.Label(self.root, textvariable=self.status_var, anchor='w',
                bg='#2d2d44', fg='#a6adc8',
                font=('Consolas', 8), padx=10, pady=2).pack(fill='x', side='bottom')
    
    # ========== 线程安全的 UI 调用 ==========
    def _ui_call(self, fn, *args):
        """worker 线程 → 主线程 UI 调用 (经队列, 避免 tkinter 线程问题)"""
        self._ui_queue.put((fn, args))
    
    def _drain_ui_queue(self):
        try:
            while True:
                fn, args = self._ui_queue.get_nowait()
                try:
                    fn(*args)
                except Exception:
                    pass
        except queue.Empty:
            pass
        self.root.after(50, self._drain_ui_queue)
    
    # ========== 日志 ==========
    def log(self, msg, tag=None):
        self.output.insert(tk.END, msg + '\n', tag)
        self.output.see(tk.END)
        self.root.update_idletasks()
    
    def _log_line(self, line):
        tag = classify_line(line)
        self.log(line, tag)
    
    def _log_shell_line(self, line):
        """交互 shell 输出行: 默认紫色, flag/PWNED_OK/uid 成功绿高亮"""
        tag = classify_line(line)
        if tag in (None, 'cmd'):
            tag = 'shell'
        self.log(line, tag)
    
    def log_cmd(self, cmd):
        """记录命令回显行 (金色加粗), 返回行起始 index 供成功后彩虹着色"""
        start = self.output.index('end-1c linestart')
        self.log(f"$ {cmd}", 'cmd')
        self._last_cmd_start = start
        return start
    
    def _mark_rainbow(self, start_index):
        """把 start_index 起的命令回显行逐字符染成彩虹色 (6 色循环)"""
        try:
            line_end = self.output.index(f'{start_index} lineend')
            text = self.output.get(start_index, line_end)
            for ch_idx in range(len(text)):
                tag = f'rainbow{ch_idx % len(RAINBOW_COLORS)}'
                self.output.tag_add(tag, f'{start_index}+{ch_idx}c',
                                    f'{start_index}+{ch_idx + 1}c')
        except Exception:
            pass
    
    def _log_stderr(self, text):
        text = sanitize(text)[:2000]
        if text.strip():
            self.log("[stderr]:", 'warning')
            self.log(text, 'warning')
    
    # ========== 文件浏览 ==========
    def _browse_binary(self):
        f = filedialog.askopenfilename(title="选择Binary文件")
        if f:
            self.binary_var.set(f)
            # 自动检测同目录libc
            d = os.path.dirname(f)
            for name in ['libc.so.6', 'libc-2.31.so', 'libc-2.27.so', 'libc.so']:
                candidate = os.path.join(d, name)
                if os.path.exists(candidate):
                    self.libc_var.set(candidate)
                    self.log(f"🔍 自动检测到libc: {name}", 'info')
                    break
    
    def _browse_libc(self):
        f = filedialog.askopenfilename(title="选择libc文件")
        if f:
            self.libc_var.set(f)

    def _browse_ld(self):
        f = filedialog.askopenfilename(title="选择ld-linux加载器文件")
        if f:
            self.ld_var.set(f)
    
    # ========== 执行 ==========
    def _run_stream(self, cmd, timeout=60):
        """流式运行命令 (Windows 经 wsl, WSL 内直接执行)"""
        self._killed = False
        self._solve_proc = None
        full_cmd = exec_prefix() + ['ulimit -c 0 2>/dev/null; ' + cmd]
        try:
            proc = subprocess.Popen(full_cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   encoding='utf-8', errors='replace')
            self._solve_proc = proc
        except Exception as e:
            self._ui_call(self.log, f"[启动失败] {e}", 'error')
            return -1
        
        stderr_lines = []
        
        def read_stdout():
            for line in iter(proc.stdout.readline, ''):
                if self._killed:
                    return
                line = sanitize(line.rstrip('\n'))
                if line:
                    self._ui_call(self._log_line, line)
        
        def read_stderr():
            for line in iter(proc.stderr.readline, ''):
                if self._killed:
                    return
                stderr_lines.append(line)
        
        t1 = threading.Thread(target=read_stdout, daemon=True)
        t2 = threading.Thread(target=read_stderr, daemon=True)
        t1.start(); t2.start()
        
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._killed = True
            kill_process_tree(proc)
            self.log("\n⏰ 超时!", 'error')
        
        t1.join(timeout=3); t2.join(timeout=3)
        
        if stderr_lines:
            self._ui_call(self._log_stderr, ''.join(stderr_lines))
        
        return proc.returncode
    
    # ========== 解题流程 ==========
    def _start_solve(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        
        wsl_binary = to_wsl_path(binary)
        libc = self.libc_var.get().strip()
        ld = self.ld_var.get().strip() if hasattr(self, 'ld_var') else ''
        timeout = self.timeout_var.get().strip() or '120'
        remote_host = self.remote_host_var.get().strip()
        remote_port = self.remote_port_var.get().strip()
        
        self.log(f"\n{'='*60}", 'bold')
        self.log(f"🎯 目标: {os.path.basename(binary)}", 'bold')
        self.log(f"🔁 自适应: {'开' if self.adaptive_var.get() else '关'}", 'info')
        if remote_host:
            self.log(f"🌐 远程: {remote_host}:{remote_port}", 'info')
        self.log(f"{'='*60}", 'bold')
        
        # 验证输入
        try:
            timeout_int = int(timeout)
        except ValueError:
            messagebox.showerror("错误", "超时必须是数字!")
            return
        
        if remote_host and remote_port:
            try:
                port_int = int(remote_port)
                if not (1 <= port_int <= 65535):
                    raise ValueError
            except ValueError:
                messagebox.showerror("错误", "端口必须是 1-65535 的数字!")
                return
        
        cmd = build_solve_cmd(
            WORKSPACE, wsl_binary,
            libc=to_wsl_path(libc) if libc else '',
            ld=to_wsl_path(ld) if ld else '',
            remote_host=remote_host if remote_host else '',
            remote_port=remote_port if remote_port else '',
            timeout=timeout_int,
            adaptive=self.adaptive_var.get(),
        )
        self.log_cmd(cmd)
        
        self.solve_btn.config(state='disabled', text="⏳ 解题中...")
        self.shell_btn.config(state='disabled')
        self.progress.start(12)
        self.status_var.set("解题中...")
        
        def worker():
            rc = self._run_stream(cmd, timeout=timeout_int + 120)
            self._ui_call(self._on_solve_done, rc)
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _on_solve_done(self, rc):
        self.progress.stop()
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        self._cleanup_cores()
        if rc == 0:
            # 成功的命令回显 → 彩虹色 (与普通输出区分)
            if self._last_cmd_start is not None:
                self._mark_rainbow(self._last_cmd_start)
            self.log("\n✅ 解题成功! 点击 💻交互Shell 获取shell", 'success')
            self.shell_btn.config(state='normal', bg='#cba6f7')
            self.status_var.set("解题成功")
            if self.auto_shell_var.get():
                self._ui_call(self._open_interactive_shell)
        elif rc is not None:
            self.log(f"\n❌ 退出码: {rc}", 'error')
            self.status_var.set(f"解题失败 (rc={rc})")
        else:
            self.log("\n⏰ 超时", 'error')
            self.status_var.set("解题超时")
        self._refresh_exp_list()
    
    # ========== 代码审计 / 偏移 ==========
    def _run_audit(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        self.log(f"\n📋 代码审计: {os.path.basename(binary)}", 'bold')
        code = (f"from pwn_solver.code_auditor import audit_binary; "
                f"audit_binary({to_wsl_path(binary)!r})")
        cmd = (f"cd {shlex.quote(WORKSPACE)} && python3 -W ignore -c "
               f"{shlex.quote(code)}")
        threading.Thread(target=lambda: self._run_stream(cmd, 60), daemon=True).start()
    
    def _run_offset(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        self.log(f"\n🔍 偏移检测: {os.path.basename(binary)}", 'bold')
        code = (f"from pwn_solver.gdb_debugger import GdbDebugger; "
                f"g=GdbDebugger({to_wsl_path(binary)!r}); "
                f"print('offset:', g.find_offset())")
        cmd = (f"cd {shlex.quote(WORKSPACE)} && python3 -W ignore -c "
               f"{shlex.quote(code)}")
        threading.Thread(target=lambda: self._run_stream(cmd, 30), daemon=True).start()
    
    # ========== 反编译视图 (伪C F5 / 汇编) ==========
    def _set_disasm_mode(self, mode):
        self.disasm_mode = mode
        self._load_disasm()
    
    def _load_disasm(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        self.disasm_info.config(text="加载中...")
        mode = getattr(self, 'disasm_mode', 'c')
        
        def worker():
            try:
                wsl_binary = to_wsl_path(binary)
                if mode == 'c':
                    # 伪 C 反编译 (经子进程, main+调用链, plt 不展开)
                    code = (
                        "import json,sys;"
                        "from pwn_solver.decompiler import decompile;"
                        "t,a=decompile(sys.argv[1]);"
                        "print(json.dumps({'text':t,'annot':a}))"
                    )
                    r = subprocess.run(exec_prefix() + [
                        f"cd {shlex.quote(WORKSPACE)} && python3 -W ignore -c "
                        f"{shlex.quote(code)} {shlex.quote(wsl_binary)}"],
                        capture_output=True, text=True,
                        encoding='utf-8', errors='replace', timeout=90)
                    data = json.loads(r.stdout.strip().split('\n')[-1]) \
                        if r.stdout.strip() else {}
                    text = data.get('text', r.stderr[:500])
                    annot = {int(k): v for k, v in data.get('annot', {}).items()}
                    self._ui_call(lambda: self._render_disasm(text, annot, mode='c',
                                                              analysis=None))
                else:
                    r = subprocess.run(exec_prefix() +
                        [f"objdump -d -M intel {shlex.quote(wsl_binary)}"],
                        capture_output=True, text=True,
                        encoding='utf-8', errors='replace', timeout=60)
                    disasm = r.stdout or r.stderr
                    analysis = {}
                    try:
                        code = (
                            "import json,sys;"
                            "from pwn_solver.analyzer import BinaryAnalyzer;"
                            "an=BinaryAnalyzer(sys.argv[1], verbose=False);"
                            "print(json.dumps({'functions': an.find_interesting_functions()}))"
                        )
                        r2 = subprocess.run(exec_prefix() + [
                            f"cd {shlex.quote(WORKSPACE)} && python3 -W ignore -c "
                            f"{shlex.quote(code)} {shlex.quote(wsl_binary)}"],
                            capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=90)
                        analysis = json.loads(r2.stdout.strip().split('\n')[-1]) \
                            if r2.stdout.strip() else {}
                    except Exception as e:
                        self._ui_call(lambda: self.disasm_info.config(
                            text=f"分析失败: {e}"))
                    annot = build_disasm_annotated(disasm, analysis)
                    self._ui_call(lambda: self._render_disasm(*annot, mode='asm',
                                                              analysis=analysis))
            except Exception as e:
                self._ui_call(lambda: self.disasm_info.config(
                    text=f"加载失败: {e}"))
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _render_disasm(self, disasm, annot, mode='c', analysis=None):
        self.disasm.config(state='normal')
        self.disasm.delete(1.0, tk.END)
        self.disasm.insert(1.0, disasm)
        lines = disasm.split('\n')
        for line_no, tag in (annot or {}).items():
            if line_no >= len(lines):
                continue
            self.disasm.tag_add(tag, f'{line_no + 1}.0', f'{line_no + 1}.0 lineend')
        if mode == 'c':
            # 伪 C: 函数头行蓝色加粗, 注释行灰色
            flag_line = None
            for i, line in enumerate(lines):
                if line.startswith('void ') and '{' in line:
                    self.disasm.tag_add('func_head', f'{i + 1}.0', f'{i + 1}.0 lineend')
                elif line.strip().startswith('//'):
                    self.disasm.tag_add('comment', f'{i + 1}.0', f'{i + 1}.0 lineend')
                if flag_line is None and 'flag' in line.lower():
                    flag_line = i + 1
            # 自动滚动到第一个 flag 相关行
            if flag_line:
                self.disasm.see(f'{flag_line}.0')
        self.disasm.config(state='disabled')
        hits = [DISASM_TAGS[t].split(' ')[0] for t in sorted(set((annot or {}).values()))]
        mode_name = '伪C (main+调用链)' if mode == 'c' else '汇编'
        self.disasm_info.config(
            text=f"{mode_name} | 标注: {', '.join(hits)}" if hits else f"{mode_name} | 无标注点")
        # 联动漏洞演示高亮 (仅汇编模式有 analysis)
        if analysis:
            self._update_vuln_demo_highlight(analysis)
    
    # ========== 漏洞演示 ==========
    def _render_vuln_demo(self):
        self.demo_text.config(state='normal')
        self.demo_text.delete(1.0, tk.END)
        for title, body in VULN_DEMO:
            self.demo_text.insert(tk.END, f"■ {title}\n", 'demo_title')
            self.demo_text.insert(tk.END, body + "\n\n", 'demo_body')
        self.demo_text.config(state='disabled')
    
    def _update_vuln_demo_highlight(self, analysis):
        """按分析结果高亮命中的演示条目标题"""
        funcs = analysis.get('functions', {})
        hits = set()
        if funcs.get('inner_overflows') or funcs.get('dangerous'):
            hits.add('栈溢出')
        if (funcs.get('heap_menu') or {}).get('heap_menu'):
            hits.add('堆溢出')
        if (funcs.get('fmt_string') or {}).get('fmt_string'):
            hits.add('格式化字符串')
        if funcs.get('io_leak', {}).get('io_leak'):
            hits.add('Canary')
            hits.add('PIE')
        self.demo_text.config(state='normal')
        # 清理旧高亮
        self.demo_text.tag_remove('demo_hit', 1.0, tk.END)
        content = self.demo_text.get(1.0, tk.END)
        for title in hits:
            start = content.find(f"■ {title}")
            if start >= 0:
                line = content[:start].count('\n') + 1
                self.demo_text.tag_add('demo_hit', f'{line}.0', f'{line}.0 lineend')
        self.demo_text.config(state='disabled')
    
    # ========== Web 解题 Tab ==========
    def _build_web_tab(self):
        tab = tk.Frame(self.notebook, bg='#1e1e2e')
        # 顶部配置行
        cfg = tk.Frame(tab, bg='#1e1e2e')
        cfg.pack(fill='x', pady=6, padx=6)

        tk.Label(cfg, text="📁 题目源码目录:", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=0, sticky='w')
        self.web_dir_var = tk.StringVar()
        tk.Entry(cfg, textvariable=self.web_dir_var, width=52,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=1, padx=5)
        tk.Button(cfg, text="浏览", command=self._browse_web_dir,
                bg='#45475a', fg='#cdd6f4', relief='flat',
                font=('Consolas', 8)).grid(row=0, column=2)

        tk.Label(cfg, text="🌐 目标URL(可空):", fg='#a6adc8', bg='#1e1e2e',
                font=('Consolas', 9)).grid(row=0, column=3, sticky='w', padx=(15,0))
        self.web_url_var = tk.StringVar()
        tk.Entry(cfg, textvariable=self.web_url_var, width=26,
                bg='#313244', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 9)).grid(row=0, column=4, padx=5)

        btns = tk.Frame(tab, bg='#1e1e2e')
        btns.pack(fill='x', padx=6)
        self.web_analyze_btn = tk.Button(btns, text="🔍 静态分析",
                command=lambda: self._run_web('analyze'),
                bg='#a6e3a1', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=14, pady=4, cursor='hand2')
        self.web_analyze_btn.pack(side='left', padx=3)
        self.web_solve_btn = tk.Button(btns, text="🚀 解题(打payload)",
                command=lambda: self._run_web('solve'),
                bg='#89b4fa', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=14, pady=4, cursor='hand2')
        self.web_solve_btn.pack(side='left', padx=3)
        tk.Button(btns, text="📥 批量下载题源",
                command=self._web_download,
                bg='#cba6f7', fg='#1e1e2e', font=('Consolas', 10, 'bold'),
                relief='flat', padx=14, pady=4, cursor='hand2').pack(side='left', padx=3)
        tk.Label(btns, text="分析=只看漏洞类型; 解题=起环境/打URL找flag",
                fg='#6c7086', bg='#1e1e2e', font=('Consolas', 8)).pack(side='left', padx=10)

        # 结果区
        self.web_output = scrolledtext.ScrolledText(tab,
                bg='#11111b', fg='#cdd6f4', insertbackground='#cdd6f4',
                font=('Consolas', 10), wrap='word', relief='flat', borderwidth=0)
        self.web_output.pack(fill='both', expand=True, padx=6, pady=6)
        self.web_output.tag_configure('success', foreground='#a6e3a1')
        self.web_output.tag_configure('error', foreground='#f38ba8')
        self.web_output.tag_configure('info', foreground='#89b4fa')
        self.web_output.tag_configure('bold', foreground='#f9e2af',
                                      font=('Consolas', 10, 'bold'))
        self.web_output.tag_configure('flag', foreground='#f9e2af',
                                      font=('Consolas', 11, 'bold'))
        self.notebook.add(tab, text=' 🌐 Web解题 ')

    def _browse_web_dir(self):
        d = filedialog.askdirectory(title="选择 Web 题目源码目录")
        if d:
            self.web_dir_var.set(d)

    def _web_log(self, msg, tag=None):
        self.web_output.insert(tk.END, msg + '\n', tag)
        self.web_output.see(tk.END)

    def _run_web(self, mode):
        chall_dir = self.web_dir_var.get().strip()
        if not chall_dir:
            messagebox.showerror("错误", "请先选择题目源码目录!")
            return
        url = self.web_url_var.get().strip()
        self.web_output.delete(1.0, tk.END)
        self._web_log(f"{'='*56}", 'bold')
        self._web_log(f"🌐 Web {'静态分析' if mode=='analyze' else '解题'}: {chall_dir}", 'bold')
        if url:
            self._web_log(f"目标: {url}", 'info')
        self._web_log('='*56, 'bold')
        for b in (self.web_analyze_btn, self.web_solve_btn):
            b.config(state='disabled')
        self.status_var.set(f"Web {mode} 中...")

        def worker():
            try:
                sys.path.insert(0, str(Path(__file__).parent))
                from web_solver.solver import WebSolver
                solver = WebSolver(timeout=10, verbose=False, max_attempts=60)
                if mode == 'analyze':
                    r = solver.analyze(chall_dir)
                else:
                    r = solver.solve(chall_dir, target_url=url)
                self._ui_call(self._render_web_result, r, mode)
            except Exception as e:
                import traceback
                self._ui_call(self._web_log, f"[错误] {e}\n{traceback.format_exc()[-500:]}", 'error')
                self._ui_call(self._web_done_btns)
        threading.Thread(target=worker, daemon=True).start()

    def _web_done_btns(self):
        for b in (self.web_analyze_btn, self.web_solve_btn):
            b.config(state='normal')
        self.status_var.set("就绪")

    def _render_web_result(self, r, mode):
        self._web_log(f"\n📦 技术栈: {r.stack}   框架: {r.framework or '-'}", 'info')
        self._web_log(f"🎯 判定: {r.primary_vuln} (置信度 {r.confidence})", 'bold')
        if r.top_vulns:
            self._web_log(f"   候选: " + ', '.join(f'{v}@{c}' for v, c in r.top_vulns))
        if r.url:
            self._web_log(f"🌍 环境: {r.env_kind} → {r.url}", 'info')
        if mode == 'solve':
            self._web_log(f"🗲 尝试 {r.attempts} 次 payload, 耗时 {r.elapsed}s")
            if r.success:
                self._web_log(f"\n✅ FLAG: {r.flag}", 'flag')
                self._web_log(f"   利用: [{r.primary_vuln}] {r.payload_desc}", 'success')
                if r.evidence:
                    snippet = r.evidence[:200].replace('\n', ' ')
                    self._web_log(f"   证据: {snippet}", 'info')
            else:
                self._web_log(f"\n❌ 未解出: {r.error}", 'error')
        # 展开分析日志
        if r.log:
            self._web_log('\n--- 执行日志 ---', 'info')
            for line in r.log:
                self._web_log('  ' + line)
        self._web_done_btns()
        self.status_var.set(f"Web {mode} 完成" + (" — 拿到 flag" if r.success else ""))

    def _web_download(self):
        self.web_output.delete(1.0, tk.END)
        self._web_log("📥 批量下载 web 题源码 (sajjadium/ctf-archives) ...", 'bold')
        self._web_log("   目标: external_challs/web_challs/", 'info')
        self._web_log("   提示: 设置 GITHUB_TOKEN 环境变量可避免限流", 'info')
        script = Path(__file__).parent / 'scripts' / 'fetch_web_challs.py'
        cmd = f"python {script} --years 2023-2025 --per-event 6 --max-events 20"
        def worker():
            rc = self._run_stream(cmd, timeout=1800)
            self._ui_call(self._web_log, f"\n下载结束 rc={rc}, 见 external_challs/web_challs/manifest.json", 'bold')
        threading.Thread(target=worker, daemon=True).start()

    # ========== 程序实际运行 (不带 exp) ==========
    def _start_run_binary(self):
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        self._stop_run_binary(silent=True)
        self.run_output.delete(1.0, tk.END)
        wsl_binary = shlex.quote(to_wsl_path(binary))
        cmd = f"{wsl_binary}"
        try:
            self._run_proc = subprocess.Popen(
                exec_prefix() + [cmd],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace')
        except Exception as e:
            self.run_status.config(text=f"启动失败: {e}")
            return
        self.run_status.config(text=f"运行中 (pid={self._run_proc.pid})")
        self.run_input.focus_set()
        
        def reader():
            for line in iter(self._run_proc.stdout.readline, ''):
                self._ui_call(self._append_run_output, line)
            self._ui_call(self._on_run_exit)
        
        threading.Thread(target=reader, daemon=True).start()
    
    def _append_run_output(self, text):
        text = sanitize(text)
        self.run_output.insert(tk.END, text)
        self.run_output.see(tk.END)
    
    def _on_run_exit(self):
        if getattr(self, '_run_proc', None):
            rc = self._run_proc.poll()
            self.run_status.config(text=f"已退出 (rc={rc})")
            self._run_proc = None
    
    def _send_run_input(self):
        proc = getattr(self, '_run_proc', None)
        if not proc or proc.poll() is not None:
            self.run_status.config(text="程序未运行")
            return
        text = self.run_input.get()
        self.run_input.delete(0, tk.END)
        try:
            proc.stdin.write(text + '\n')
            proc.stdin.flush()
        except Exception as e:
            self.run_status.config(text=f"发送失败: {e}")
    
    def _send_run_hex(self):
        proc = getattr(self, '_run_proc', None)
        if not proc or proc.poll() is not None:
            self.run_status.config(text="程序未运行")
            return
        text = self.run_input.get().strip().replace(' ', '')
        self.run_input.delete(0, tk.END)
        try:
            data = bytes.fromhex(text)
            proc.stdin.buffer.write(data)
            proc.stdin.buffer.flush()
        except Exception as e:
            self.run_status.config(text=f"hex 发送失败: {e}")
    
    def _stop_run_binary(self, silent=False):
        proc = getattr(self, '_run_proc', None)
        if proc:
            kill_process_tree(proc)
            self._run_proc = None
            if not silent:
                self.run_status.config(text="已关闭")
    
    # ========== 自定义命令 ==========
    def _run_custom(self):
        cmd = self.custom_cmd_var.get().strip()
        if not cmd:
            messagebox.showerror("错误", "请输入要执行的命令!")
            return
        self.log(f"\n{'='*50}", 'bold')
        self.log("⌨ 自定义命令执行", 'bold')
        self.log(f"{'='*50}", 'bold')
        self.log_cmd(cmd)
        self.status_var.set("命令执行中...")
        self.progress.start(12)
        self.solve_btn.config(state='disabled', text="⏳ 执行中...")
        
        def worker():
            rc = self._run_stream(cmd, timeout=300)
            self._ui_call(self._on_custom_done, rc)
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _on_custom_done(self, rc):
        self.progress.stop()
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        if rc == 0:
            if self._last_cmd_start is not None:
                self._mark_rainbow(self._last_cmd_start)
            self.log(f"\n✅ 命令执行成功 (rc={rc})", 'success')
            self.status_var.set("命令执行成功")
        else:
            self.log(f"\n❌ 命令执行失败 (rc={rc})", 'error')
            self.status_var.set(f"命令执行失败 (rc={rc})")
    
    # ========== 停止 ==========
    def _stop_solve(self):
        self._killed = True
        self.progress.stop()
        if self._solve_proc:
            kill_process_tree(self._solve_proc)
            self._solve_proc = None
        if self._shell_proc:
            kill_process_tree(self._shell_proc)
            self._shell_proc = None
        self.solve_btn.config(state='normal', text="🚀 开始解题")
        self.shell_btn.config(state='normal', text="💻 交互Shell")
        self.status_var.set("已停止")
        self._cleanup_cores()
        self.log("\n⏹ 已停止", 'warning')
    
    def _cleanup_cores(self):
        """清理core dump文件 (经执行前缀)"""
        try:
            subprocess.run(exec_prefix() +
                ['rm -f core core.* cores/core.* 2>/dev/null; echo ok'],
                capture_output=True, timeout=5)
        except Exception:
            pass
    
    # ========== 交互Shell ==========
    def _open_interactive_shell(self):
        """在GUI中打开交互shell"""
        binary = self.binary_var.get().strip()
        if not binary:
            messagebox.showerror("错误", "请先选择binary文件!")
            return
        
        # 找最新的exp文件
        exp_path = self._find_latest_exp()
        if not exp_path:
            # 没有exp时，尝试用solver生成
            self.log("\n⚠ 未找到exp文件，尝试用solver生成...", 'warning')
            self._start_solve()
            return
        
        wsl_exp = to_wsl_path(exp_path)
        self.log(f"\n{'='*50}", 'bold')
        self.log(f"💻 启动交互Shell: {os.path.basename(exp_path)}", 'bold')
        self.log(f"   输入命令后按回车发送 | 输入 exit 退出", 'info')
        self.log(f"{'='*50}", 'bold')
        
        # 远程模式: 注入环境变量
        remote_host = self.remote_host_var.get().strip()
        remote_port = self.remote_port_var.get().strip()
        env_prefix = ""
        if remote_host and remote_port:
            env_prefix = f"PWN_REMOTE_HOST={shlex.quote(remote_host)} PWN_REMOTE_PORT={shlex.quote(remote_port)} "
            self.log(f"🌐 远程目标: {remote_host}:{remote_port}", 'info')
        
        # 在后台运行exp
        cmd = f"cd {shlex.quote(WORKSPACE)} && {env_prefix}python3 -W ignore {shlex.quote(wsl_exp)}"
        
        self.shell_btn.config(state='disabled', text="⏳ Shell运行中...")
        self._killed = False  # 重置
        
        # 使用Popen保持进程存活
        full_cmd = exec_prefix() + [cmd]
        try:
            self._shell_proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, encoding='utf-8', errors='replace'
            )
        except Exception as e:
            self.log(f"启动Shell失败: {e}", 'error')
            self.shell_btn.config(state='normal', text="💻 交互Shell")
            self.status_var.set("Shell启动失败")
            return
        
        # 读取stdout线程
        def read_shell():
            for line in iter(self._shell_proc.stdout.readline, ''):
                if self._killed:
                    return
                line = sanitize(line.rstrip('\n'))
                if line:
                    self._ui_call(self._log_shell_line, line)
            # 进程结束
            self._ui_call(self._on_shell_exit)
        
        threading.Thread(target=read_shell, daemon=True).start()
        self.shell_input.focus_set()
    
    def _send_shell_command(self, event=None):
        """发送命令到交互shell"""
        if not self._shell_proc or self._shell_proc.poll() is not None:
            self.log("Shell未运行", 'warning')
            return
        
        cmd = self.shell_input.get().strip()
        if not cmd:
            return
        
        self.shell_input.delete(0, tk.END)
        self.log(f"$ {cmd}", 'bold')
        
        try:
            self._shell_proc.stdin.write(cmd + '\n')
            self._shell_proc.stdin.flush()
        except Exception as e:
            self.log(f"发送失败: {e}", 'error')
    
    def _on_shell_exit(self):
        self.shell_btn.config(state='normal', text="💻 交互Shell")
        if self._shell_proc:
            kill_process_tree(self._shell_proc)
            self._shell_proc = None
        self.status_var.set("就绪")
        self.log("\n💻 Shell已退出", 'warning')
    
    # ========== Exp管理 ==========
    def _find_latest_exp(self):
        """找当前binary匹配的最新exp文件"""
        if not os.path.exists(EXPLOITS_DIR):
            return None
        binary = self.binary_var.get().strip()
        base = os.path.basename(binary) if binary else ""
        exps = sorted(
            [f for f in os.listdir(EXPLOITS_DIR) if f.endswith('.py')],
            key=lambda f: os.path.getmtime(os.path.join(EXPLOITS_DIR, f)),
            reverse=True
        )
        matching = [f for f in exps if base and base in f]
        return os.path.join(EXPLOITS_DIR, matching[0]) if matching else (
            os.path.join(EXPLOITS_DIR, exps[0]) if exps else None
        )
    
    def _refresh_exp_list(self):
        """刷新exp文件列表"""
        self.exp_listbox.delete(0, tk.END)
        if not os.path.exists(EXPLOITS_DIR):
            return
        exps = sorted(
            [f for f in os.listdir(EXPLOITS_DIR) if f.endswith('.py')],
            key=lambda f: os.path.getmtime(os.path.join(EXPLOITS_DIR, f)),
            reverse=True
        )
        for exp in exps:
            self.exp_listbox.insert(tk.END, exp)
    
    def _open_selected_exp(self, event=None):
        """双击/菜单打开选中的exp"""
        sel = self.exp_listbox.curselection()
        if sel:
            exp_name = self.exp_listbox.get(sel[0])
            exp_path = os.path.join(EXPLOITS_DIR, exp_name)
            open_path(exp_path)
    
    def _show_exp_menu(self, event):
        try:
            self.exp_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.exp_menu.grab_release()
    
    def _copy_exp_path(self):
        sel = self.exp_listbox.curselection()
        if sel:
            exp_path = os.path.join(EXPLOITS_DIR, self.exp_listbox.get(sel[0]))
            self.root.clipboard_clear()
            self.root.clipboard_append(exp_path)
            self.log(f"已复制路径: {exp_path}", 'info')
    
    def _delete_selected_exp(self):
        sel = self.exp_listbox.curselection()
        if not sel:
            return
        exp_path = os.path.join(EXPLOITS_DIR, self.exp_listbox.get(sel[0]))
        if messagebox.askyesno("删除", f"删除 {os.path.basename(exp_path)}?"):
            try:
                os.remove(exp_path)
                self.log(f"已删除: {os.path.basename(exp_path)}", 'warning')
            except Exception as e:
                self.log(f"删除失败: {e}", 'error')
            self._refresh_exp_list()
    
    def _open_exp_folder(self):
        """打开exp文件夹"""
        open_path(EXPLOITS_DIR)
    
    # ========== 主循环 ==========
    def run(self):
        self.root.mainloop()


if __name__ == '__main__':
    gui = PwnSolverGUI()
    gui.run()
