#!/usr/bin/env python3
"""
自适应求解器 — 闭合反馈循环
"尝试 → 观察 → 诊断 → 调整 → 再尝试"
结合 feedback_analyzer 从失败中学习并自动修正参数
"""

import os
import sys
import time
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feedback_analyzer import (
    FeedbackAnalyzer, FeedbackResult, ErrorType, AdjustmentSuggestion
)


@dataclass
class AttemptRecord:
    """单次尝试记录"""
    attempt_id: int
    method: str                    # 'ret2win', 'ret2libc', 'one_gadget', etc.
    params: Dict[str, Any]         # 尝试的参数
    feedback: Optional[FeedbackResult] = None
    adjustment: Optional[AdjustmentSuggestion] = None
    success: bool = False
    duration: float = 0.0


@dataclass
class AdaptiveConfig:
    """自适应求解器配置"""
    max_total_attempts: int = 50       # 总尝试次数上限
    max_attempts_per_method: int = 15  # 每个方法最多尝试次数
    max_offset_search: int = 0x200     # 偏移量搜索最大范围
    offset_step_size: int = 8          # 偏移量步进
    retry_timeout: int = 10            # 每次尝试超时(秒)
    interactive_timeout: int = 3       # 交互超时(秒)
    verbose: bool = True


class AdaptiveSolver:
    """
    自适应求解器 — 核心反馈循环
    
    工作流程:
    1. 生成 exploit → 执行 → 收集反馈
    2. 分析反馈 → 生成调整建议
    3. 按建议调整参数 → 重新生成 → 重新执行
    4. 重复直到成功或耗尽尝试次数
    
    支持的调整类型:
    - offset_shift: 调整栈偏移量
    - switch_gadget: 切换到备用gadget
    - switch_method: 切换到备用利用方法
    - fix_protocol: 调整交互协议
    - add_leak: 添加信息泄露步骤
    - retry_same: 重试相同参数
    """
    
    def __init__(self, solver, config: AdaptiveConfig = None):
        self.solver = solver  # PwnSolver instance
        self.config = config or AdaptiveConfig()
        self.analyzer = FeedbackAnalyzer(verbose=self.config.verbose)
        self.history: List[AttemptRecord] = []
        self._method_registry = {}
        self._gadget_pool = {}  # 备用gadget池
        
    def log(self, msg, level='info'):
        if self.config.verbose:
            print(f"  [adaptive] {msg}", flush=True)
    
    def solve(self, analysis: dict, gadgets: dict) -> bool:
        """主入口 — 自适应求解
        
        Args:
            analysis: 从 solver.analyze() 的分析结果
            gadgets: 从 solver.find_gadgets() 的gadget收集结果
        
        Returns: True if solved
        """
        self.log("=" * 55)
        self.log("🔁 自适应求解器启动 (反馈闭环)")
        self.log(f"   最大尝试: {self.config.max_total_attempts}")
        self.log(f"   每方法上限: {self.config.max_attempts_per_method}")
        self.log("=" * 55)
        
        # 构建方法优先级队列
        methods = self._build_method_queue(analysis, gadgets)
        self.log(f"方法队列: {[m['name'] for m in methods]}")
        
        attempt_id = 0
        method_attempts = {}
        
        for method in methods:
            method_name = method['name']
            method_attempts.setdefault(method_name, 0)
            
            self.log(f"\n{'─'*40}")
            self.log(f"📌 方法: {method_name} (优先级 {method.get('priority', 0)})")
            self.log(f"{'─'*40}")
            
            # 初始化该方法的基础参数
            base_params = self._init_params(method, analysis, gadgets)
            
            # 在该方法内进行自适应循环
            while method_attempts[method_name] < self.config.max_attempts_per_method:
                if attempt_id >= self.config.max_total_attempts:
                    self.log("⛔ 达到总尝试上限")
                    self._print_summary()
                    return False
                
                attempt_id += 1
                method_attempts[method_name] += 1
                
                self.log(f"\n  [{attempt_id}/{self.config.max_total_attempts}] "
                        f"{method_name} #{method_attempts[method_name]}")
                
                # Step 1: 尝试
                record = self._attempt(attempt_id, method, base_params, analysis, gadgets)
                self.history.append(record)
                
                if record.success:
                    self.log(f"\n{'★'*40}")
                    self.log(f"★ ✅ 自适应求解成功! "
                            f"(方法: {method_name}, 尝试: {attempt_id})")
                    self.log(f"{'★'*40}")
                    return True
                
                # Step 2: 观察
                feedback = record.feedback
                if not feedback:
                    self.log("  ⚠ 无有效反馈")
                    # 无反馈时对栈类方法做 offset 系统扫描 (失败常因 offset 检测错)
                    if method_name in ('rop', 'ret2libc', 'ret2win', 'one_gadget') and \
                            self._offset_scan_step(base_params, analysis, gadgets):
                        continue
                    break
                
                self.log(f"  错误类型: {feedback.error_type.value}")
                if feedback.crash_addr:
                    self.log(f"  crash地址: {hex(feedback.crash_addr)}")
                
                # Step 3: 诊断 & 调整
                adjustment = self._diagnose_and_adjust(feedback, base_params, method, analysis)
                record.adjustment = adjustment
                
                if not adjustment:
                    self.log("  ⚠ 无法生成调整建议")
                    # 无明确调整方向时, 对栈类方法做 offset 系统扫描兜底
                    if method_name in ('rop', 'ret2libc', 'ret2win', 'one_gadget') and \
                            self._offset_scan_step(base_params, analysis, gadgets):
                        continue
                    self.log("  切换方法")
                    break
                
                self.log(f"  调整: {adjustment.kind} → {adjustment.description}")
                
                # Step 4: 应用调整
                applied = self._apply_adjustment(adjustment, base_params, method, analysis)
                if not applied:
                    self.log("  ⚠ 调整无法应用，切换方法")
                    break
        
        # 所有方法耗尽
        self.log(f"\n{'─'*40}")
        self.log("❌ 所有方法耗尽")
        self._print_summary()
        return False
    
    def _build_method_queue(self, analysis: dict, gadgets: dict) -> List[dict]:
        """构建方法优先级队列"""
        funcs = analysis.get('functions', {})
        protections = analysis.get('protections', {})
        plt = gadgets.get('plt', {})
        specific = gadgets.get('specific', {})
        intel = analysis.get('reverse_intel') or {}
        has_seccomp = bool(
            any(x in plt for x in ('seccomp_init', 'seccomp_load', 'seccomp_rule_add'))
            or intel.get('anti_analysis', {}).get('seccomp', False)
            or (analysis.get('functions', {}).get('anti_analysis') or {}).get('seccomp', False)
        )
        
        methods = []
        
        # 1. ret2win
        real_win = [(n, a) for n, a in funcs.get('win', [])
                    if not n.startswith('_') and 'plt.' not in n]
        implied_win = funcs.get('implied_win', [])
        if real_win or implied_win:
            methods.append({'name': 'ret2win', 'priority': 100})
        
        # 2. one_gadget (含回退链)。seccomp 禁 execve，必须跳过。
        if gadgets.get('one_gadgets') and not has_seccomp:
            methods.append({
                'name': 'one_gadget',
                'priority': 95,
                'gadgets': gadgets['one_gadgets'],
                'current_gadget_idx': 0,
            })
        
        # 3. shellcode
        if not protections.get('nx', True):
            methods.append({'name': 'shellcode', 'priority': 90})
        
        # 4. ret2libc。seccomp 下 system/one_gadget 均无效，不浪费时间。
        # canary + 回显函数时走两阶段 canary 泄露模板, 无需二进制内 pop_rdi。
        echo_plt = any(f in plt for f in ('write', 'puts', 'printf'))
        canary_leakable = protections.get('canary') and echo_plt
        if self.solver.libc_path and not has_seccomp and \
                (gadgets.get('pop_rdi_in_binary') or canary_leakable):
            methods.append({
                'name': 'ret2libc',
                'priority': 85,
                'libc_path': self.solver.libc_path,
            })
        
        # 4b. format_string (检测到 printf 栈缓冲漏洞)
        if funcs.get('fmt_string', {}).get('fmt_string'):
            methods.append({'name': 'format_string', 'priority': 84})
        
        # 5. ret2syscall
        if specific.get('syscall') and specific.get('pop_rax') and specific.get('pop_rdi'):
            methods.append({'name': 'ret2syscall', 'priority': 80})
        
        # 6. heap
        heap_menu = analysis.get('heap_menu') or funcs.get('heap_menu') or {}
        if heap_menu.get('heap_menu'):
            methods.append({'name': 'heap', 'priority': 75})
        
        # 7. ROP。seccomp 下通用 system ROP 不适用；仅 ret2syscall/ORW 可尝试。
        if funcs.get('dangerous') and protections.get('nx', True) and not has_seccomp:
            methods.append({'name': 'rop', 'priority': 50})
        
        methods.sort(key=lambda x: x['priority'], reverse=True)
        return methods
    
    def _init_params(self, method: dict, analysis: dict, gadgets: dict) -> dict:
        """初始化方法参数"""
        params = {
            'offset': 0x40,  # 默认偏移
            'ret_addr': None,
            'one_gadget_idx': 0,
        }
        
        # 从分析结果中估算偏移
        buffers = analysis.get('buffers', [])
        for b in buffers:
            if b.get('type') == 'stack_frame' and 0x10 <= b.get('size', 0) <= 0x200:
                params['offset'] = b['size'] + 8
                break
        
        # one_gadget 初始选择
        if method['name'] == 'one_gadget':
            og_list = method.get('gadgets', [])
            if og_list:
                params['one_gadget'] = og_list[0]
                params['one_gadget_idx'] = 0
                params['one_gadget_total'] = len(og_list)
        
        # ret2win 目标地址
        if method['name'] == 'ret2win':
            funcs = analysis.get('functions', {})
            win_funcs = funcs.get('win', [])
            if win_funcs:
                params['ret_addr'] = int(win_funcs[0][1], 16)

        return params

    # offset 系统扫描候选: 来自公开 pwn writeup (ctf-wiki 等) 的高频 buf->ret 距离。
    # 失败且无明确反馈方向时, 按此列表逐一尝试, 覆盖 analyzer buffer 检测不准的场景。
    OFFSET_CANDIDATES = (0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48, 0x50,
                         0x58, 0x60, 0x68, 0x70, 0x78, 0x80, 0x88, 0x8c,
                         0x90, 0x98, 0xa0, 0xa8, 0xb0)

    def _offset_scan_step(self, params: dict, analysis: dict, gadgets: dict) -> bool:
        """无反馈失败时: 把 offset 推进到 OFFSET_CANDIDATES 的下一个未试值。

        返回 True 表示已切换到新 offset (调用方应 continue 重试),
        False 表示候选耗尽 (调用方应 break 换方法)。
        """
        tried = params.setdefault('_offsets_tried', set())
        cur = params.get('offset', 0x40)
        tried.add(cur)
        for cand in self.OFFSET_CANDIDATES:
            if cand not in tried:
                params['offset'] = cand
                self.log(f"    ↳ offset 扫描: {hex(cur)} → {hex(cand)}")
                return True
        self.log("    ↳ offset 候选耗尽")
        return False

    def _attempt(self, attempt_id: int, method: dict, params: dict,
                 analysis: dict, gadgets: dict) -> AttemptRecord:
        """执行一次尝试"""
        start = time.time()
        record = AttemptRecord(
            attempt_id=attempt_id,
            method=method['name'],
            params=dict(params),
        )
        
        try:
            # 更新 solver 的状态
            self.solver.vuln_type = (method['name'], 80 + min(attempt_id, 15), 'adaptive')
            
            # 注入调整后的参数到 analysis
            adjusted_analysis = dict(analysis)
            adjusted_analysis['buffers'] = [
                {'type': 'stack_frame', 'size': params['offset'] - 8}
            ]
            
            # 注入 one_gadget 选择 (如果适用)
            if method['name'] == 'one_gadget':
                og_idx = params.get('one_gadget_idx', 0)
                if self.solver.gadgets:
                    self.solver.gadgets['_one_gadget_idx'] = og_idx
                    if og_idx > 0:
                        self.log(f"    使用 one_gadget[{og_idx}]")
            
            # 生成 exploit
            code = self.solver.generate_exploit(adjusted_analysis, gadgets)
            if not code:
                record.feedback = FeedbackResult(
                    success=False,
                    error_type=ErrorType.UNKNOWN,
                )
                record.duration = time.time() - start
                return record
            
            # 执行
            result = self._execute_exploit(code)
            record.feedback = result
            record.success = result.success
            record.duration = time.time() - start
            
            if result.success:
                self.log(f"  ✅ 成功! ({record.duration:.1f}s)")
            else:
                self.log(f"  ❌ {result.error_type.value} ({record.duration:.1f}s)")
            
        except Exception as e:
            record.feedback = FeedbackResult(
                success=False,
                error_type=ErrorType.UNKNOWN,
                stdout_snippet=str(e)[:500],
            )
            record.duration = time.time() - start
            self.log(f"  ❌ 异常: {e}")
        
        return record
    
    def _execute_exploit(self, code: str) -> FeedbackResult:
        """执行 exploit 代码并返回结构化反馈"""
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode='w', suffix='.py', delete=False
            ) as f:
                f.write(code)
                tmp_path = f.name
            
            cwd = os.path.dirname(os.path.abspath(
                self.solver.binary_path
            )) or '.'
            
            result = subprocess.run(
                ['python3', tmp_path],
                capture_output=True, text=True,
                timeout=self.config.retry_timeout,
                cwd=cwd,
            )
            
            return self.analyzer.analyze(
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
            )
            
        except subprocess.TimeoutExpired:
            return FeedbackResult(
                success=False,
                error_type=ErrorType.TIMEOUT,
            )
        except Exception as e:
            return FeedbackResult(
                success=False,
                error_type=ErrorType.UNKNOWN,
                stdout_snippet=str(e)[:500],
            )
        finally:
            if tmp_path:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
    
    def _diagnose_and_adjust(self, feedback: FeedbackResult, params: dict,
                             method: dict, analysis: dict) -> Optional[AdjustmentSuggestion]:
        """根据反馈生成调整建议"""
        
        # 优先使用反馈中自带的建议
        if feedback.suggestions:
            # 按置信度排序
            sorted_sugs = sorted(feedback.suggestions,
                                key=lambda s: s.confidence, reverse=True)
            
            for sug in sorted_sugs:
                if self._can_apply(sug, params, method):
                    return sug
        
        # 如果反馈没给建议，自行诊断
        et = feedback.error_type
        
        if et == ErrorType.SEGFAULT:
            return self._handle_segfault(feedback, params, method)
        elif et == ErrorType.INVALID_INSTRUCTION:
            return self._handle_sigill(feedback, params, method)
        elif et == ErrorType.TIMEOUT:
            return self._handle_timeout(feedback, params, method)
        elif et == ErrorType.BAD_RECV:
            return self._handle_bad_recv(feedback, params, method)
        elif et == ErrorType.EOF_ERROR:
            return self._handle_eof(feedback, params, method)
        
        return None
    
    def _can_apply(self, sug: AdjustmentSuggestion, params: dict, method: dict) -> bool:
        """检查建议是否可应用"""
        if sug.kind == 'offset_shift':
            direction = sug.params.get('direction', 'increase')
            current = params.get('offset', 0x40)
            if direction == 'increase' and current >= self.config.max_offset_search:
                return False
            if direction == 'decrease' and current <= 0x10:
                return False
            return True
        elif sug.kind == 'switch_gadget':
            if method['name'] == 'one_gadget':
                idx = params.get('one_gadget_idx', 0)
                total = params.get('one_gadget_total', 0)
                return idx + 1 < total
            return False
        elif sug.kind == 'switch_method':
            return True
        elif sug.kind == 'retry_same':
            return True
        return False
    
    def _apply_adjustment(self, sug: AdjustmentSuggestion, params: dict,
                          method: dict, analysis: dict) -> bool:
        """应用调整建议到参数"""
        if sug.kind == 'offset_shift':
            direction = sug.params.get('direction', 'increase')
            delta = sug.params.get('min_delta', self.config.offset_step_size)
            if direction == 'increase':
                params['offset'] += delta
                self.log(f"    ↳ offset += {delta} → {hex(params['offset'])}")
            elif direction == 'decrease':
                params['offset'] -= delta
                self.log(f"    ↳ offset -= {delta} → {hex(params['offset'])}")
            elif direction == 'shift_8':
                # 8字节对齐偏移 (SIGILL常见原因)
                params['offset'] += 8
                self.log(f"    ↳ offset对齐调整 +8 → {hex(params['offset'])}")
            elif direction == 'retry':
                self.log(f"    ↳ 保持offset={hex(params['offset'])}重试")
            return True
        
        elif sug.kind == 'switch_gadget':
            if method['name'] == 'one_gadget':
                params['one_gadget_idx'] += 1
                og_list = method.get('gadgets', [])
                idx = params['one_gadget_idx']
                if idx < len(og_list):
                    params['one_gadget'] = og_list[idx]
                    self.log(f"    ↳ 切换 one_gadget [{idx}/{len(og_list)}]: "
                            f"{og_list[idx]['offset']}")
                    return True
            return False
        
        elif sug.kind == 'retry_same':
            self.log(f"    ↳ 重试相同参数")
            return True
        
        return False
    
    # ====== 错误处理器 ======
    
    def _handle_segfault(self, feedback: FeedbackResult, params: dict,
                         method: dict) -> AdjustmentSuggestion:
        """处理 SIGSEGV"""
        crash_addr = feedback.crash_addr
        
        if crash_addr:
            # 检查是否是 padding 地址 (包含 0x41 序列)
            if crash_addr and ('414141' in hex(crash_addr)):
                return AdjustmentSuggestion(
                    kind='offset_shift',
                    description=f'crash在padding地址 {hex(crash_addr)} → offset不足',
                    params={'direction': 'increase', 'min_delta': 8},
                    confidence=0.9,
                )
            # 低地址
            if crash_addr < 0x10000:
                return AdjustmentSuggestion(
                    kind='offset_shift',
                    description=f'crash在低地址 → offset过大',
                    params={'direction': 'decrease', 'min_delta': 8},
                    confidence=0.7,
                )
            # libc 地址
            if 0x7f0000000000 <= crash_addr <= 0x7fffffffffff:
                if method['name'] == 'one_gadget':
                    return AdjustmentSuggestion(
                        kind='switch_gadget',
                        description='one_gadget不可用 → 切换下一个',
                        confidence=0.8,
                    )
        
        # 默认：调整偏移
        return AdjustmentSuggestion(
            kind='offset_shift',
            description='SIGSEGV → 调整偏移量',
            params={'direction': 'increase', 'min_delta': 8},
            confidence=0.5,
        )
    
    def _handle_sigill(self, feedback: FeedbackResult, params: dict,
                       method: dict) -> AdjustmentSuggestion:
        """处理 SIGILL"""
        # SIGILL 最常见原因: (1) one_gadget不对 (2) ROP链对齐错误
        if method['name'] == 'one_gadget':
            return AdjustmentSuggestion(
                kind='switch_gadget',
                description='SIGILL → one_gadget无效，切换',
                confidence=0.85,
            )
        return AdjustmentSuggestion(
            kind='offset_shift',
            description='SIGILL → 可能ROP对齐问题，偏移+8',
            params={'direction': 'shift_8'},
            confidence=0.4,
        )
    
    def _handle_timeout(self, feedback: FeedbackResult, params: dict,
                        method: dict) -> AdjustmentSuggestion:
        """处理超时"""
        # 超时可能是程序hang住 = 没崩溃但也没拿到shell
        # 可能是交互协议不对
        return AdjustmentSuggestion(
            kind='offset_shift',
            description='超时 → 程序可能hang住，调整偏移重试',
            params={'direction': 'increase', 'min_delta': 8},
            confidence=0.4,
        )
    
    def _handle_bad_recv(self, feedback: FeedbackResult, params: dict,
                         method: dict) -> AdjustmentSuggestion:
        """处理协议不匹配"""
        expected = feedback.suggestions[0].params.get('expected', '?') if feedback.suggestions else '?'
        return AdjustmentSuggestion(
            kind='fix_protocol',
            description=f'recvuntil未找到 "{expected}" → 调整交互协议',
            confidence=0.7,
        )
    
    def _handle_eof(self, feedback: FeedbackResult, params: dict,
                    method: dict) -> AdjustmentSuggestion:
        """处理 EOF"""
        return AdjustmentSuggestion(
            kind='offset_shift',
            description='EOF → 程序崩溃/ROP链错误',
            params={'direction': 'increase', 'min_delta': 8},
            confidence=0.6,
        )
    
    def _print_summary(self):
        """打印尝试历史摘要"""
        self.log(f"\n{'─'*40}")
        self.log("📊 尝试历史摘要")
        self.log(f"{'─'*40}")
        for r in self.history[-10:]:
            status = "✅" if r.success else "❌"
            err = r.feedback.error_type.value if r.feedback else "?"
            adj = r.adjustment.kind if r.adjustment else "-"
            self.log(f"  {status} #{r.attempt_id:02d} {r.method:12s} "
                    f"err={err:20s} adj={adj}")


def test_adaptive_solver():
    """自测 — 不依赖真实binary"""
    from feedback_analyzer import FeedbackAnalyzer, ErrorType
    fa = FeedbackAnalyzer(verbose=False)
    
    # 模拟反馈解析
    segfault_out = "Process stopped with signal SIGSEGV (addr 0x7f4141414141)"
    r = fa.analyze(segfault_out, "", -11)
    assert r.error_type == ErrorType.SEGFAULT
    assert r.crash_addr == 0x7f4141414141
    assert len(r.suggestions) > 0
    
    sigill_out = "Program received signal SIGILL\n0x00007f123456789a"
    r = fa.analyze(sigill_out, "", -4)
    assert r.error_type == ErrorType.INVALID_INSTRUCTION
    
    timeout_out = "TimeoutError: "
    r = fa.analyze(timeout_out, "", None, timeout=True)
    assert r.error_type == ErrorType.TIMEOUT
    
    print("✓ AdaptiveSolver infrastructure tests passed")


if __name__ == '__main__':
    test_adaptive_solver()
