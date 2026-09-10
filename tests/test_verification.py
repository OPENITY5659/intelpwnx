#!/usr/bin/env python3
"""判定语义测试：哪些输出算"解出"，哪些必须判失败，以及假阳/假阴的回归护栏。

这些断言直接对应"✅ 解题成功"可信不可信，改动判定逻辑时最先跑这里。
"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(BASE, '..'))
sys.path.insert(0, os.path.join(ROOT, 'pwn_solver'))

import verify  # noqa: E402
from feedback_analyzer import ErrorType, FeedbackAnalyzer  # noqa: E402


# ---------------------------------------------------------------- verify.py

def test_classify_strong_success():
    assert verify.classify_text('uid=0(root) gid=0(root)', '', 0)[0] == 'success'
    assert verify.classify_text('PWNED_OK', '', 0)[0] == 'success'


def test_classify_flag_only_is_weak_not_strong():
    verdict, why = verify.classify_text('flag{this_is_it}', '', 0)
    assert verdict == 'weak', '只有 flag 时应记为弱成功，提示可能没拿到交互 shell'


def test_classify_crash_vetoes_success_marker():
    """拿到 uid= 但同时有崩溃证据/非零退出码 → 不算成功（保留原有严格语义）。"""
    verdict, _ = verify.classify_text('uid=0(root)', 'SIGSEGV at 0x41414141', -11)
    assert verdict == 'fail'
    verdict, _ = verify.classify_text('uid=0(root)', '', -11)
    assert verdict == 'fail'


def test_classify_empty_is_fail():
    assert verify.classify_text('', '', 0)[0] == 'fail'
    assert verify.classify_text('usage: ./vuln', '', 0)[0] == 'fail'


def test_shell_probe_code_is_self_contained_and_has_leak_hint():
    # 内联进生成脚本时是模块级代码 → 用 indent='' 编译验证
    code = verify.shell_probe_code(indent='', leak_symbols=('puts',))
    assert 'def verify_shell(' in code
    assert 'PWNED_OK' in code and 'uid=' in code
    assert "[leak] puts=%#x" in code, '生成的探测片段要带结构化泄露行，供离线 libc 索引反查'
    compile(code, '<probe>', 'exec')
    # 嵌进函数里时应带缩进
    indented = verify.shell_probe_code(indent='    ', leak_symbols=())
    assert indented.startswith('    def verify_shell(')


def test_interactive_verify_detects_shell_and_treats_empty_recv_as_pending():
    """recv 暂时没数据不能当 EOF —— 否则 shell 稍晚起来就误判失败。"""

    class FakeProc:
        def __init__(self, chunks):
            self.chunks = list(chunks)
            self.sent = []

        def poll(self):
            return None

        def recv(self, timeout=None):
            return self.chunks.pop(0) if self.chunks else b''

    proc = FakeProc([b'', b'', b'uid=0(root)\n'])
    verdict, text = verify.interactive_verify(proc, lambda line: proc.sent.append(line),
                                             timeout=2.0, poll=0.01)
    assert verdict == 'success'
    assert 'uid=' in text


# ------------------------------------------------------- feedback_analyzer

def test_pwn_substring_no_longer_fakes_shell_detection():
    """历史上 'pwn' 被当成 shell 提示符，结果被自身路径命中满屏假阳。"""
    fb = FeedbackAnalyzer(verbose=False).analyze(
        '[*] opening /mnt/d/CTF_Slover/PwnSolver/cache/ciscn_dl/pwn2024/Pwn-gostack/x\n', '', 0)
    hints = [s.description for s in fb.suggestions]
    assert not any('疑似获得交互' in h for h in hints), f'不应出现假阳提示: {hints}'


def test_shell_prompt_still_triggers_verify_suggestion():
    fb = FeedbackAnalyzer(verbose=False).analyze('/bin/sh: 0: can\'t access tty\n$ ', '', 0)
    kinds = [s.kind for s in fb.suggestions]
    assert 'verify_shell' in kinds, f'真 shell 提示符应触发交互式复验建议: {kinds}'
    assert fb.error_type == ErrorType.WRONG_OUTPUT


def test_structured_leak_line_parsed():
    fb = FeedbackAnalyzer(verbose=False).analyze('[leak] puts=0x7f1122334455\n', '', 0)
    assert fb.leaks == {'puts': 0x7f1122334455}


# -------------------------------------------------------- adaptive_solver

def _make_solver_stub():
    class G:
        one_gadgets = [{'offset': 0x1}, {'offset': 0x2}]
        specific = {}
    class Solver:
        binary_path = os.path.join(ROOT, 'challenges', 'ret2libc')
        gadgets = {}
        libc_path = None
        exploit = None
        vuln_type = ('rop', 50, '')
        def generate_exploit(self, analysis, gadgets):
            return '# stub\n'
    return Solver()


def test_retry_same_is_allowed_once_then_rejected():
    from adaptive_solver import AdaptiveSolver, AdaptiveConfig
    solver = AdaptiveSolver(_make_solver_stub(), config=AdaptiveConfig(verbose=False))
    sug = __import__('feedback_analyzer').AdjustmentSuggestion(kind='retry_same', description='x')
    params = {'offset': 0x40}
    method = {'name': 'rop'}
    assert solver._can_apply(sug, params, method) is True
    assert solver._apply_adjustment(sug, params, method, {}) is True
    assert solver._can_apply(sug, params, method) is False, '无新信息的重复重试必须被拒绝'


def test_protocol_and_leak_adjustments_are_accepted_but_end_the_method():
    from adaptive_solver import AdaptiveSolver, AdaptiveConfig
    solver = AdaptiveSolver(_make_solver_stub(), config=AdaptiveConfig(verbose=False))
    from feedback_analyzer import AdjustmentSuggestion
    params, method = {'offset': 0x40}, {'name': 'ret2libc'}
    for kind in ('fix_protocol', 'add_leak', 'switch_method'):
        sug = AdjustmentSuggestion(kind=kind, description='x')
        assert solver._can_apply(sug, params, method) is True, f'{kind} 不应被直接拒绝'
        assert solver._apply_adjustment(sug, params, method, {}) is False, \
            f'{kind} 应结束当前方法（换方法），而不是空转'


def test_unknown_feedback_yields_an_action_for_stack_methods():
    from adaptive_solver import AdaptiveSolver, AdaptiveConfig
    from feedback_analyzer import FeedbackResult, ErrorType
    solver = AdaptiveSolver(_make_solver_stub(), config=AdaptiveConfig(verbose=False))
    fb = FeedbackResult(success=False, error_type=ErrorType.UNKNOWN)
    sug = solver._diagnose_and_adjust(fb, {'offset': 0x40}, {'name': 'rop'}, {})
    assert sug is not None, '无结构化反馈也必须给出动作，避免 err=? 空转'
    sug2 = solver._diagnose_and_adjust(fb, {'offset': 0x40}, {'name': 'heap'}, {})
    assert sug2 is not None and sug2.kind == 'switch_method'


def test_looks_like_shell_requires_shell_evidence():
    from adaptive_solver import AdaptiveSolver, AdaptiveConfig
    from feedback_analyzer import FeedbackResult, ErrorType
    solver = AdaptiveSolver(_make_solver_stub(), config=AdaptiveConfig(verbose=False))
    yes = FeedbackResult(success=False, error_type=ErrorType.WRONG_OUTPUT,
                         raw_output='some output\n$ ')
    no = FeedbackResult(success=False, error_type=ErrorType.WRONG_OUTPUT,
                        raw_output='invalid choice\n1.Add\n2.Delete')
    assert solver._looks_like_shell(yes) is True
    assert solver._looks_like_shell(no) is False


# --------------------------------------------------------------- solver 建议

def test_next_step_advice_is_strategy_specific():
    from solver import PwnSolver
    advice = PwnSolver._next_step_advice(object(), 'heap', {}, {}, seccomp=False)
    assert 'gcc -static' not in advice
    assert 'UAF' in advice or 'heap' in advice.lower() or 'unsorted' in advice
    fmt = PwnSolver._next_step_advice(object(), 'format_string', {}, {}, seccomp=False)
    assert '%n' in fmt
    with_seccomp = PwnSolver._next_step_advice(object(), 'heap', {}, {}, seccomp=True)
    assert 'ORW' in with_seccomp or 'FSOP' in with_seccomp


def test_echoed_probe_command_is_not_counted_as_shell():
    """回显陷阱：目标把输入打回来时，`echo PWNED_OK; id` 会跟着出现。

    实测 blind_fmt_got/blind 就是被这条误判成"Shell obtained"（基线里那条 ✅ 是假阳）：
    输出里只有我们自己的输入被回显，没有任何 uid=。剔除回显后必须判失败。
    """
    echoed = ('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`techo PWNED_OK; id' + chr(10)
              + 'AAAAAAAAAAAAAAAAAAAAAA`t' + chr(10))
    verdict, why = verify.classify_text(echoed, '', 0)
    assert verdict == 'fail', f'回显不该算成功（{verdict}/{why}）'
    # 真 shell 的输出（PWNED_OK 单独成行 + uid=）仍要判成功
    real = 'PWNED_OK' + chr(10) + 'uid=1000(user) gid=1000(user)' + chr(10)
    assert verify.classify_text(real, '', 0)[0] == 'success'
    # 生成的探测片段里也要带这条防护
    code = verify.shell_probe_code(indent='')
    assert 'echo PWNED_OK' in code and 'cleaned' in code
    compile(code, '<probe>', 'exec')
