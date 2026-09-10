#!/usr/bin/env python3
"""
反馈分析器 — 解析 exploit 执行输出，提取结构化错误信息
支持: segfault、SIGILL、timeout、connection error、assertion、EOFError
驱动自适应循环: try → observe → diagnose → adjust → retry
"""

import re
import enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any


class ErrorType(enum.Enum):
    """结构化错误类型"""
    SUCCESS = "success"
    SEGFAULT = "segfault"           # SIGSEGV — 地址错误
    INVALID_INSTRUCTION = "invalid_instruction"  # SIGILL — 跳到错误地址
    TIMEOUT = "timeout"             # 进程超时/无响应
    CONNECTION_ERROR = "connection" # 远程连接失败
    EOF_ERROR = "eof"               # 连接意外关闭
    ASSERTION_ERROR = "assertion"   # pwntools assertion / 程序断言
    BAD_RECV = "bad_recv"           # recvuntil 超时 — 协议不匹配
    WRONG_OUTPUT = "wrong_output"   # 有输出但没拿到 shell
    IMPORT_ERROR = "import_error"   # 缺少依赖
    UNKNOWN = "unknown"


@dataclass
class AdjustmentSuggestion:
    """自动调整建议"""
    kind: str           # 'offset_shift', 'retry_same', 'switch_gadget', 'switch_method', 'add_leak', 'fix_protocol'
    description: str
    params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5  # 0-1


@dataclass
class FeedbackResult:
    """结构化反馈结果"""
    success: bool
    error_type: ErrorType = ErrorType.UNKNOWN
    crash_addr: Optional[int] = None       # hex crash address
    crash_instruction: Optional[str] = None # faulting instruction
    signal: Optional[str] = None           # SIGSEGV / SIGILL / SIGABRT
    exit_code: Optional[int] = None
    stdout_snippet: str = ""               # 最后 500 chars
    stderr_snippet: str = ""               # 最后 500 chars
    leak_candidates: List[int] = field(default_factory=list)  # 可能的泄露地址
    leaks: Dict[str, int] = field(default_factory=dict)      # 结构化泄露 {符号: 地址}
    recv_before_crash: str = ""            # crash前收到的数据
    suggestions: List[AdjustmentSuggestion] = field(default_factory=list)
    raw_output: str = ""                   # 完整原始输出
    
    def __bool__(self):
        return self.success


class FeedbackAnalyzer:
    """输出解析器 — 从 exploit 输出中提取结构化信息"""
    
    # segfault 模式
    SEGFAULT_PATTERNS = [
        # pwntools: "stopped with exit code -11 (SIGSEGV)" — 无地址
        re.compile(r'stopped\s+with\s+exit\s+code\s+-\d+\s+\(SIGSEGV\)', re.I),
        # GDB / dmesg: "SIGSEGV at 0x..."  (线性, 无回溯)
        re.compile(r'(?:segfault|segmentation\s+fault|SIGSEGV)\s+at\s+(0x[0-9a-fA-F]+)', re.I),
        # 宽松匹配: "SIGSEGV ... 0x..."  (64KB截断保证安全)
        re.compile(r'(?:segfault|segmentation\s+fault|SIGSEGV)\b.*?(0x[0-9a-fA-F]+)', re.I | re.DOTALL),
        # pwntools "stopped with signal SIGSEGV"
        re.compile(r'stopped.*?signal\s+SIGSEGV.*?(?:addr|ip)\s*(0x[0-9a-fA-F]+)', re.I | re.DOTALL),
        # core dump
        re.compile(r'SIGSEGV.*?(?:address|addr|ip|pc).*?(0x[0-9a-fA-F]+)', re.I | re.DOTALL),
        # General crash regex
        re.compile(r'(?:crash|fault|segfault).*?(?:at|@|address)\s*(0x[0-9a-fA-F]+)', re.I | re.DOTALL),
        # gdb output: "Program received signal SIGSEGV"
        re.compile(r'Program\s+received\s+signal\s+SIGSEGV.*?\n.*?0x([0-9a-fA-F]+)', re.I | re.DOTALL),
        re.compile(r'Program\s+received\s+signal\s+SIGSEGV.*?0x([0-9a-fA-F]+)', re.I | re.DOTALL),
    ]
    
    # EOF模式 — 独立于SEGFAULT (避免误分类)
    EOF_PATTERNS = [
        re.compile(r'(?:Got\s+EOF|Connection\s+closed|BrokenPipeError).*?(?:after\s+sending|while\s+reading)?', re.I),
    ]
    
    # SIGILL 模式 — 跳到非代码段/错误 gadget
    SIGILL_PATTERNS = [
        # 线性: "SIGILL at 0x..."
        re.compile(r'(?:SIGILL|illegal\s+instruction|invalid\s+opcode)\s+at\s+(0x[0-9a-fA-F]+)', re.I),
        # 宽松: "SIGILL ... 0x..." (64KB截断保证安全)
        re.compile(r'(?:SIGILL|illegal\s+instruction|invalid\s+opcode)\b.*?(0x[0-9a-fA-F]+)', re.I | re.DOTALL),
        re.compile(r'Program\s+received\s+signal\s+SIGILL.*?\n.*?0x([0-9a-fA-F]+)', re.I | re.DOTALL),
        re.compile(r'Program\s+received\s+signal\s+SIGILL.*?0x([0-9a-fA-F]+)', re.I | re.DOTALL),
        re.compile(r'stopped.*?signal\s+SIGILL.*?(?:addr|ip)\s*(0x[0-9a-fA-F]+)', re.I),
    ]
    
    # 超时模式
    TIMEOUT_PATTERNS = [
        re.compile(r'(?:timeout|timed?\s*out|Time.*?expired)', re.I),
        re.compile(r'subprocess\.TimeoutExpired', re.I),
        re.compile(r'TimeoutError', re.I),
    ]
    
    # 连接错误
    CONNECTION_PATTERNS = [
        re.compile(r'(?:connection\s+refused|ConnectionRefusedError|Errno\s+111)', re.I),
        re.compile(r'(?:cannot\s+connect|failed\s+to\s+connect|getaddrinfo)', re.I),
        re.compile(r'(?:host\s+unreachable|network\s+is\s+unreachable)', re.I),
    ]
    
    # recv 超时 / 协议不匹配
    BAD_RECV_PATTERNS = [
        re.compile(r'(?:recvuntil|recv).*?(?:timeout|timed?\s*out)', re.I),
        re.compile(r'Could\s+not\s+find.*?(?:in\s+timeout|within)', re.I),
    ]
    
    # pwntools assertion
    ASSERTION_PATTERNS = [
        re.compile(r'AssertionError.*', re.I),
        re.compile(r'assert\s+.*?failed', re.I),
    ]
    
    # 泄露地址识别 (64-bit libc/heap addresses)
    LEAK_PATTERN = re.compile(r'(?<![0-9a-f])(7f[0-9a-f]{10,12})(?![0-9a-f])', re.I)
    HEAP_LEAK_PATTERN = re.compile(r'(?<![0-9a-f])((?:55|56)[0-9a-f]{10,12})(?![0-9a-f])', re.I)

    # 结构化泄露行：生成的 exploit 打印 `[leak] puts=0x7f...`，
    # 有了符号名才能拿去本地索引反查 libc（断网识别的关键输入）。
    LEAK_LINE_PATTERN = re.compile(r'\[leak\]\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+)')
    
    # 成功模式 — 只匹配明确的 shell 获取标志
    SUCCESS_PATTERNS = [
        re.compile(r'PWNED_OK', re.I),
        re.compile(r'uid=\d+', re.I),          # id 命令输出
    ]
    # 弱成功模式 — flag 内容但不一定有 shell
    WEAK_SUCCESS_PATTERNS = [
        re.compile(r'flag\{[^}]+\}', re.I),
        re.compile(r'ctfshow\{[^}]+\}', re.I),
        re.compile(r'(?:^|\n)\$\s', re.I),     # shell 提示符在行首
    ]
    # 其中"确实是 flag"的一类：只有它们可以直接判弱成功；
    # shell 提示符要走交互式复验（1d），不能凭一个 $ 就宣布成功。
    WEAK_FLAG_PATTERNS = [
        re.compile(r'flag\{[^}]+\}', re.I),
        re.compile(r'ctfshow\{[^}]+\}', re.I),
    ]
    
    def __init__(self, verbose=True):
        self.verbose = verbose
    
    def log(self, msg):
        if self.verbose:
            print(f"  [feedback] {msg}", flush=True)
    
    def analyze(self, stdout: str, stderr: str, exit_code: int = None,
                timeout: bool = False, raw_output: str = "") -> FeedbackResult:
        """分析 exploit 执行输出"""
        # 防止恶意/超大输出导致 ReDoS 或内存膨胀 (分析截断, raw保留)
        MAX_LEN = 65536
        stdout_t = stdout[-MAX_LEN:] if len(stdout) > MAX_LEN else stdout
        stderr_t = stderr[-MAX_LEN:] if len(stderr) > MAX_LEN else stderr
        combined = f"{stdout_t}\n{stderr_t}"

        # 0. 结构化泄露行（符号名 → 地址），供本地 libc 索引反查使用
        leaks = {}
        for m in self.LEAK_LINE_PATTERN.finditer(combined):
            try:
                leaks[m.group(1)] = int(m.group(2), 16)
            except ValueError:
                continue
        
        # 1. 成功前提: exit_code 必须干净 + 不能有崩溃证据
        clean_exit = (exit_code is None or exit_code == 0)
        has_crash_evidence = bool(
            re.search(r'(?:SIGSEGV|SIGILL|SIGABRT|segmentation\s+fault|illegal\s+instruction|stopped.*signal|Program\s+received\s+signal|process\s+\d+\s+stopped)', combined, re.I)
        )

        if clean_exit and not has_crash_evidence:
            # 1a. 强成功标志
            for pat in self.SUCCESS_PATTERNS:
                if pat.search(combined):
                    result = FeedbackResult(
                        success=True, error_type=ErrorType.SUCCESS,
                        exit_code=exit_code,
                        stdout_snippet=stdout[-500:],
                        stderr_snippet=stderr[-500:],
                        raw_output=raw_output or combined,
                    )
                    self.log(f"✓ 检测到成功标志")
                    result.leaks = leaks
                    return result
            
            # 1b. 弱成功标志（只有真 flag 才算；shell 提示符走 1d 复验）
            for pat in self.WEAK_FLAG_PATTERNS:
                if pat.search(combined):
                    result = FeedbackResult(
                        success=True, error_type=ErrorType.SUCCESS,
                        exit_code=exit_code,
                        stdout_snippet=stdout[-500:],
                        stderr_snippet=stderr[-500:],
                        raw_output=raw_output or combined,
                    )
                    self.log(f"✓ 检测到弱成功标志 (flag/shell)")
                    result.leaks = leaks
                    return result
        
        # 1c. 非零退出码快速失败
        if exit_code is not None and exit_code != 0:
            result = FeedbackResult(
                success=False, exit_code=exit_code,
                stdout_snippet=stdout[-500:] if stdout else "",
                stderr_snippet=stderr[-500:] if stderr else "",
                raw_output=raw_output or combined,
            )
            # 直接走错误分类
        else:
            result = FeedbackResult(
                success=False, exit_code=exit_code,
                stdout_snippet=stdout[-500:] if stdout else "",
                stderr_snippet=stderr[-500:] if stderr else "",
                raw_output=raw_output or combined,
            )
        
        # 1d. 输出里有 shell 迹象但没触发成功标志 —— 这是最具体的信号，
        #     优先于下面的通用错误分类（否则会被当成"未知错误"而空转）。
        #     注意不能用 'pwn' 之类的宽泛子串：它会被 cache/ciscn_dl/pwn2024
        #     这类自身路径命中，造成满屏假阳。
        if any(hint in combined for hint in ('$ ', '# ', '>>> ')):
            result.error_type = ErrorType.WRONG_OUTPUT
            result.suggestions = [
                AdjustmentSuggestion(
                    kind='verify_shell',
                    description='输出里有 shell 提示符但未触发成功标志，改用交互式复验',
                    confidence=0.6,
                ),
            ]
            self.log("⚠ 疑似获得交互但未触发成功标志")
            result.leaks = leaks
            return result

        # 2a: 超时 (先检查 timeout flag)
        if timeout:
            result.error_type = ErrorType.TIMEOUT
            result.suggestions = [
                AdjustmentSuggestion(
                    kind='offset_shift',
                    description='超时 — 可能偏移量错误导致程序hang住或等待输入',
                    params={'direction': 'retry'},
                    confidence=0.6,
                ),
                AdjustmentSuggestion(
                    kind='retry_same',
                    description='重试相同参数（可能是间歇性超时）',
                    confidence=0.3,
                ),
            ]
            self.log(f"✗ 超时")
            return result
        
        # 2b: recv 超时/协议不匹配 (必须在通用timeout之前检查)
        for pat in self.BAD_RECV_PATTERNS:
            if pat.search(combined):
                result.error_type = ErrorType.BAD_RECV
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='fix_protocol',
                        description='recvuntil超时 — 交互协议不匹配，需要调整发送/接收时机',
                        confidence=0.8,
                    ),
                ]
                recv_match = re.search(r"recvuntil\(b?'([^']+)'\)", combined)
                if recv_match:
                    result.recv_before_crash = recv_match.group(1)
                    result.suggestions[0].params['expected'] = recv_match.group(1)
                
                self.log(f"✗ 协议不匹配")
                return result
        
        # 2c: 检查 timeout 字符串 (通用超时)
        for pat in self.TIMEOUT_PATTERNS:
            if pat.search(combined):
                result.error_type = ErrorType.TIMEOUT
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='offset_shift',
                        description='超时 — ROP链未被执行或无限循环',
                        confidence=0.7,
                    ),
                ]
                self.log(f"✗ 超时 (字符串匹配)")
                return result
        
        # 2b: SIGSEGV
        for pat in self.SEGFAULT_PATTERNS:
            m = pat.search(combined)
            if m:
                try:
                    crash_addr = int(m.group(1), 16)
                    result.crash_addr = crash_addr
                except (ValueError, IndexError):
                    crash_addr = None
                
                result.error_type = ErrorType.SEGFAULT
                result.signal = 'SIGSEGV'
                
                # 生成建议
                suggestions = self._diagnose_segfault(crash_addr, combined)
                result.suggestions = suggestions
                
                self.log(f"✗ SIGSEGV @ {hex(crash_addr) if crash_addr else '?'}")
                return result
        
        # 2c: SIGILL
        for pat in self.SIGILL_PATTERNS:
            m = pat.search(combined)
            if m:
                try:
                    crash_addr = int(m.group(1), 16)
                    result.crash_addr = crash_addr
                except (ValueError, IndexError):
                    crash_addr = None
                
                result.error_type = ErrorType.INVALID_INSTRUCTION
                result.signal = 'SIGILL'
                
                suggestions = self._diagnose_sigill(crash_addr, combined)
                result.suggestions = suggestions
                
                self.log(f"✗ SIGILL @ {hex(crash_addr) if crash_addr else '?'}")
                return result
        
        # 2d: 连接错误
        for pat in self.CONNECTION_PATTERNS:
            if pat.search(combined):
                result.error_type = ErrorType.CONNECTION_ERROR
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='retry_same',
                        description='连接失败 — 重试或检查远程服务',
                        confidence=0.8,
                    ),
                ]
                self.log(f"✗ 连接错误")
                return result
        
        # 2e: recv 超时/协议不匹配
        for pat in self.BAD_RECV_PATTERNS:
            if pat.search(combined):
                result.error_type = ErrorType.BAD_RECV
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='fix_protocol',
                        description='recvuntil超时 — 交互协议不匹配，需要调整发送/接收时机',
                        confidence=0.8,
                    ),
                ]
                # 尝试提取 recvuntil 期望的字符串
                recv_match = re.search(r"recvuntil\(b?'([^']+)'\)", combined)
                if recv_match:
                    result.recv_before_crash = recv_match.group(1)
                    result.suggestions[0].params['expected'] = recv_match.group(1)
                
                self.log(f"✗ 协议不匹配")
                return result
        
        # 2f: EOF (必须在SEGFAULT之前检查,避免被误判)
        for pat in self.EOF_PATTERNS:
            if pat.search(combined):
                result.error_type = ErrorType.EOF_ERROR
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='offset_shift',
                        description='EOF — 程序崩溃或ROP链导致进程终止',
                        confidence=0.7,
                    ),
                ]
                self.log(f"✗ EOF (连接关闭)")
                return result
        
        # 2g: assertion
        for pat in self.ASSERTION_PATTERNS:
            if pat.search(combined):
                result.error_type = ErrorType.ASSERTION_ERROR
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='switch_method',
                        description='Assertion — 假设条件不满足，调整利用策略',
                        confidence=0.5,
                    ),
                ]
                self.log(f"✗ Assertion错误")
                return result
        
        # 2h: 提取泄露地址（即使失败也可能有）
        leak_addrs = []
        for m in self.LEAK_PATTERN.finditer(combined):
            addr = int(m.group(1), 16)
            if 0x7f0000000000 <= addr <= 0x7fffffffffff:  # libc范围
                leak_addrs.append(addr)
        for m in self.HEAP_LEAK_PATTERN.finditer(combined):
            addr = int(m.group(1), 16)
            leak_addrs.append(addr)
        if leak_addrs:
            result.leak_candidates = leak_addrs
        
        # 2i: 未知错误
        if result.error_type == ErrorType.UNKNOWN:
            # 有非零退出码但没有崩溃文本 — 使用退出码作为诊断
            if exit_code is not None and exit_code != 0:
                # 常见退出码解释
                exit_names = {-11: 'SIGSEGV', -6: 'SIGABRT', -4: 'SIGILL', -8: 'SIGFPE', -14: 'SIGALRM'}
                sig_name = exit_names.get(exit_code, f'exit={exit_code}')
                result.error_type = ErrorType.WRONG_OUTPUT  # 非崩溃类失败
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='switch_method',
                        description=f'子进程信号 {sig_name}, exploit未成功',
                        confidence=0.7,
                    ),
                ]
                self.log(f"✗ 子进程异常: {sig_name}")
            elif any(c in combined for c in ['$ ', '# ', '>>> ']):
                # shell 提示符的情形已在 1d 提前返回；这里只可能是极端拼凑的文本
                result.error_type = ErrorType.WRONG_OUTPUT
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='switch_method',
                        description='交互迹象不明确，切换利用方法',
                        confidence=0.3,
                    ),
                ]
                self.log(f"⚠ 疑似获得交互但未触发成功标志")
            else:
                result.suggestions = [
                    AdjustmentSuggestion(
                        kind='switch_method',
                        description='未识别的错误类型，建议切换利用方法',
                        confidence=0.3,
                    ),
                ]
                if result.exit_code and result.exit_code != 0:
                    result.suggestions.append(
                        AdjustmentSuggestion(
                            kind='offset_shift',
                            description=f'非零退出码 {result.exit_code} — 可能偏移量错误',
                            confidence=0.5,
                        )
                    )
                self.log(f"✗ 未知错误 (exit_code={exit_code})")
        
        result.leaks = leaks
        return result
    
    def _diagnose_segfault(self, crash_addr, combined):
        """诊断 SIGSEGV — 给出具体调整建议"""
        suggestions = []
        
        # 地址包含 0x41414141 序列 → 偏移量错误，ret地址被A覆盖
        if crash_addr and ('414141' in hex(crash_addr) or '41414141' in hex(crash_addr)):
            suggestions.append(AdjustmentSuggestion(
                kind='offset_shift',
                description=f'crash @ {hex(crash_addr)} → 偏移量不够（ret被padding覆盖）',
                params={'direction': 'increase', 'min_delta': 8},
                confidence=0.9,
            ))
        # 地址是无效地址
        elif crash_addr and crash_addr < 0x1000:
            suggestions.append(AdjustmentSuggestion(
                kind='offset_shift',
                description=f'crash @ {hex(crash_addr)} → ret指向NULL/低地址，偏移量过大',
                params={'direction': 'decrease', 'min_delta': 8},
                confidence=0.7,
            ))
        # 地址看起来像有效地址但不可执行
        elif crash_addr and 0x7f0000000000 <= crash_addr <= 0x7fffffffffff:
            suggestions.append(AdjustmentSuggestion(
                kind='switch_gadget',
                description=f'crash @ libc地址 {hex(crash_addr)} → gadget无效或libc偏移错误',
                params={'switch_to': 'next_gadget'},
                confidence=0.8,
            ))
        # 看起来像堆地址
        elif crash_addr and (0x550000000000 <= crash_addr <= 0x570000000000):
            suggestions.append(AdjustmentSuggestion(
                kind='switch_method',
                description=f'crash @ 堆地址 {hex(crash_addr)} → 堆利用失败',
                confidence=0.6,
            ))
        else:
            suggestions.append(AdjustmentSuggestion(
                kind='offset_shift',
                description=f'crash @ {hex(crash_addr) if crash_addr else "?"} → 尝试调整偏移量',
                confidence=0.5,
            ))
        
        # 尝试从输出中找更多线索
        if 'returned' in combined:
            # pwntools "process returned X"
            ret_match = re.search(r'process\s+returned\s+(-?\d+)', combined)
            if ret_match:
                ret_code = int(ret_match.group(1))
                if ret_code == -11:  # SIGSEGV
                    suggestions.insert(0, AdjustmentSuggestion(
                        kind='offset_shift',
                        description='SIGSEGV (-11) → 确认是段错误，调整偏移',
                        confidence=0.85,
                    ))
        
        return suggestions
    
    def _diagnose_sigill(self, crash_addr, combined):
        """诊断 SIGILL — gadget/ROP链错误"""
        suggestions = []
        
        if crash_addr:
            suggestions.append(AdjustmentSuggestion(
                kind='switch_gadget',
                description=f'SIGILL @ {hex(crash_addr)} → gadget不是有效指令/对齐错误',
                params={'switch_to': 'next_gadget'},
                confidence=0.85,
            ))
        
        suggestions.append(AdjustmentSuggestion(
            kind='offset_shift',
            description='SIGILL可能是ROP链某处偏移8字节对齐问题',
            params={'direction': 'shift_8'},
            confidence=0.4,
        ))
        
        return suggestions
    
    def analyze_result(self, output: str, exit_code: int = None,
                       timeout: bool = False) -> FeedbackResult:
        """便捷方法：直接分析输出字符串"""
        return self.analyze(output, "", exit_code, timeout, output)


def test_feedback_analyzer():
    """自测"""
    fa = FeedbackAnalyzer(verbose=True)
    
    # Test 1: segfault
    segfault_output = """
    [*] Starting exploit...
    [*] Sending payload...
    [*] Process stopped with signal SIGSEGV (addr 0x7f4141414141)
    """
    r = fa.analyze(segfault_output, "", -11)
    assert not r.success
    assert r.error_type == ErrorType.SEGFAULT
    assert r.crash_addr == 0x7f4141414141
    print("✓ Test 1 (segfault) passed")
    
    # Test 2: success
    success_output = """
    [*] Leaked libc: 0x7f1234567890
    [*] libc base: 0x7f1234500000
    [*] system: 0x7f123456789a
    $ whoami
    ctfshow
    $ echo PWNED_OK
    PWNED_OK
    """
    r = fa.analyze(success_output, "", 0)
    assert r.success
    print("✓ Test 2 (success) passed")
    
    # Test 3: SIGILL
    sigill_output = """
    Program received signal SIGILL, Illegal instruction.
    0x00007f123456789a in ?? ()
    """
    r = fa.analyze(sigill_output, "", -4)
    assert not r.success
    assert r.error_type == ErrorType.INVALID_INSTRUCTION
    assert r.crash_addr == 0x7f123456789a
    print("✓ Test 3 (SIGILL) passed")
    
    # Test 4: timeout
    timeout_output = """
    [*] Connecting...
    [DEBUG] Sent 0x100 bytes
    [DEBUG] Received 0x0 bytes
    TimeoutError: 
    """
    r = fa.analyze(timeout_output, "", None, timeout=True)
    assert not r.success
    assert r.error_type == ErrorType.TIMEOUT
    print("✓ Test 4 (timeout) passed")
    
    # Test 5: bad recv
    bad_recv_output = """
    [x] recvuntil(b'flag:', timeout=timeout) timed out
    """
    r = fa.analyze(bad_recv_output, "", 1)
    assert not r.success
    assert r.error_type == ErrorType.BAD_RECV
    print("✓ Test 5 (bad recv) passed")
    
    print("\n=== All feedback_analyzer tests passed ===")


if __name__ == '__main__':
    test_feedback_analyzer()
