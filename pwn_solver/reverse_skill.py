# reverse-skill integration layer (run via python3)
"""
reverse-skill 集成层
====================

把 reverse-skill 项目（https://github.com/zhaoxuya520/reverse-skill）
中与 PWN/二进制分析直接相关的 SKILL.md 知识库接入 PwnSolver：

- SkillLibrary / SkillDoc: 加载、解析、检索 skill 文档
- PwnSkillRouter: 依据 PwnSolver 的分析结果路由到合适 skill
- ToolProbe: 校验 pwntools/ROPgadget/r2/gdb/one_gadget 等工具链
- PlaybookBuilder: 生成针对当前题目的 RE -> PWN 执行手册

本模块刻意不依赖 pwntools，可以在未安装 pwntools 的机器上做纯侦察。
"""

from __future__ import annotations

import json
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Skill 文档模型
# ---------------------------------------------------------------------------

@dataclass
class SkillDoc:
    """一个 SKILL.md 或 reference 文档。"""
    skill_id: str
    title: str
    description: str = ""
    body: str = ""
    path: str = ""
    kind: str = "skill"          # skill | reference
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.body = self.body.replace("\r\n", "\n")

    @property
    def short_description(self) -> str:
        desc = " ".join(self.description.split())
        return desc[:160]

    def sections(self) -> Dict[str, str]:
        """解析 markdown 的二级标题，返回 {标题: 内容}。

        无二级标题时，返回 {'__body__': body}。
        """
        found: Dict[str, str] = {}
        pattern = re.compile(r"^(#{1,4})\s+(.+?)\s*$", re.MULTILINE)
        matches = list(pattern.finditer(self.body))
        if not matches:
            return {"__body__": self.body}

        for i, m in enumerate(matches):
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(self.body)
            found[m.group(2)] = self.body[start:end].strip()
        return found

    def grep(self, keyword: str, context_lines: int = 1) -> List[str]:
        """不区分大小写检索关键字，返回命中行。"""
        kw = keyword.lower()
        hits: List[str] = []
        for line in self.body.splitlines():
            if kw in line.lower():
                hits.append(line.rstrip())
        return hits

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.skill_id,
            "title": self.title,
            "description": self.short_description,
            "path": self.path,
            "kind": self.kind,
        }


class SkillLibrary:
    """reverse_skill 目录的轻量加载器/路由器。"""

    def __init__(self, root: Optional[str] = None):
        if root:
            self.root = Path(root).expanduser().resolve()
        else:
            # PwnSolver/reverse_skill（与本模块同级上跳一级）
            here = Path(__file__).resolve().parent
            self.root = here.parent / "reverse_skill"

        self.docs: Dict[str, SkillDoc] = {}
        self._discover()

    # -- 加载 ----------------------------------------------------------------
    def _discover(self) -> None:
        if not self.root.exists():
            return
        for path in sorted(self.root.rglob("SKILL.md")):
            doc = self._load_doc(path, kind="skill")
            if doc:
                self.docs[doc.skill_id] = doc
        # ops 等非 SKILL.md 的流程文档按 reference 索引
        for rel in (
            "skills/ops/evidence-finding-path.md",
            "skills/ops/scope-contract.md",
            "skills/pwn-chain/references/stack-pwn.md",
            "skills/pwn-chain/references/heap-pwn.md",
            "skills/pwn-chain/references/kernel-pwn.md",
            "skills/pwn-chain/references/ctfshow-2024-newyear-official-wp.md",
            "skills/pwn-chain/references/ciscn-2024-quals.md",
            "skills/reverse-engineering/elf-analysis.md",
            "skills/reverse-engineering/anti-analysis.md",
            "skills/reverse-engineering/go-reverse.md",
            "skills/reverse-engineering/tools.md",
            "skills/reverse-engineering/tools-dynamic.md",
            "skills/reverse-engineering/references/re-agent-workflow.md",
            "CTF-Sandbox-Orchestrator/competition-reverse-pwn/references/reverse-pwn.md",
        ):
            path = self.root / rel
            if path.exists():
                # skill_id 统一不带扩展名: skills-pwn-chain-references-stack-pwn
                forced_id = rel.replace("/", "-")
                if forced_id.endswith(".md"):
                    forced_id = forced_id[:-3]
                doc = self._load_doc(path, kind="reference", forced_id=forced_id)
                if doc:
                    self.docs[doc.skill_id] = doc

    def _load_doc(self, path: Path, kind: str, forced_id: Optional[str] = None) -> Optional[SkillDoc]:
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            return None

        metadata: Dict[str, Any] = {}
        body = text
        if text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) >= 3:
                current_key: Optional[str] = None
                current_lines: List[str] = []
                for raw_line in parts[1].splitlines():
                    line = raw_line.strip()
                    if line and ":" in line and not raw_line.startswith((" ", "\t")):
                        k, v = line.split(":", 1)
                        current_key = k.strip()
                        v = v.strip()
                        if v in ("|", ">"):
                            current_lines = []
                            metadata[current_key] = ""
                        else:
                            current_lines = []
                            metadata[current_key] = v
                    elif current_key and raw_line.startswith((" ", "\t")) and line:
                        # YAML block scalar 续行
                        current_lines.append(line)
                        if current_key in metadata:
                            metadata[current_key] = "\n".join(current_lines).strip()
                body = parts[2]

        title = metadata.get("name") or path.stem
        if forced_id:
            skill_id = forced_id
        elif kind == "skill":
            # competition-reverse-pwn 这种位于多级目录下
            rel = path.relative_to(self.root)
            parts = rel.parts
            if "CTF-Sandbox-Orchestrator" in parts:
                idx = parts.index("CTF-Sandbox-Orchestrator")
                skill_id = parts[idx + 1]
            else:
                skill_id = path.parent.name
        else:
            skill_id = path.stem

        return SkillDoc(
            skill_id=skill_id,
            title=title,
            description=metadata.get("description", ""),
            body=body,
            path=str(path),
            kind=kind,
            metadata=metadata,
        )

    # -- 查询 ----------------------------------------------------------------
    def list_skills(self) -> List[SkillDoc]:
        return [d for d in self.docs.values() if d.kind == "skill"]

    def list_references(self) -> List[SkillDoc]:
        return [d for d in self.docs.values() if d.kind == "reference"]

    def get(self, name: str) -> Optional[SkillDoc]:
        key = name.lower().strip()
        aliases = {
            "pwn": "pwn-chain",
            "exploit": "pwn-chain",
            "re": "reverse-engineering",
            "reverse": "reverse-engineering",
            "r2": "radare2",
            "radare2": "radare2",
            "ghidra": "ghidra-reverse",
            "go": "go-rust-reverse",
            "rust": "go-rust-reverse",
            "ctf-reverse-pwn": "competition-reverse-pwn",
        }
        key = aliases.get(key, key)
        if key in self.docs:
            return self.docs[key]
        for doc in self.docs.values():
            if doc.skill_id.lower() == key or doc.title.lower() == key:
                return doc
        return None

    def search(self, keyword: str, limit: int = 5) -> List[Tuple[SkillDoc, List[str]]]:
        out: List[Tuple[SkillDoc, List[str]]] = []
        for doc in self.docs.values():
            hits = doc.grep(keyword)
            if hits:
                out.append((doc, hits[:12]))
        out.sort(key=lambda x: len(x[1]), reverse=True)
        return out[:limit]


# ---------------------------------------------------------------------------
# 路由
# ---------------------------------------------------------------------------

@dataclass
class RouteHit:
    doc: SkillDoc
    score: int
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.doc.skill_id,
            "title": self.doc.title,
            "score": self.score,
            "reasons": self.reasons,
            "path": self.doc.path,
        }


class PwnSkillRouter:
    """把 PwnSolver analysis 结果映射到 reverse-skill 模块。"""

    def __init__(self, library: SkillLibrary):
        self.library = library

    def route(self, context: Optional[Dict[str, Any]] = None) -> List[RouteHit]:
        ctx = context or {}
        functions = ctx.get("functions") or {}
        protections = ctx.get("protections") or {}
        info = ctx.get("info") or {}
        intel = ctx.get("reverse_intel") or {}
        language = intel.get("language") or {}
        packed = intel.get("packed") or {}
        anti = intel.get("anti_analysis") or {}
        vuln_type = ctx.get("vuln_type") or "unknown"
        if isinstance(vuln_type, (tuple, list)):
            vuln_type = vuln_type[0] if vuln_type else "unknown"

        hits: List[RouteHit] = []

        def add(skill_id: str, score: int, reasons: Iterable[str]) -> None:
            doc = self.library.get(skill_id)
            if doc:
                hits.append(RouteHit(doc, score, list(reasons)))

        # 1) 所有 PwnSolver 任务必过 pwn-chain
        pwn_reasons = ["PwnSolver 任务，目标是 working exploit"]
        score = 20
        if vuln_type in {"ret2win", "ret2libc", "rop", "one_gadget", "shellcode", "ret2syscall"}:
            score += 10
            pwn_reasons.append(f"栈类漏洞: {vuln_type} → stack-pwn.md")
        if vuln_type == "heap":
            score += 10
            pwn_reasons.append("堆类漏洞 → heap-pwn.md")
        if vuln_type == "format_string":
            score += 8
            pwn_reasons.append("格式化字符串 → leak/改写路径")
        add("pwn-chain", score, pwn_reasons)

        # 2) 通用逆向：stripped、packed、反分析、复杂机制
        re_score = 4
        re_reasons: List[str] = []
        if functions.get("stripped"):
            re_score += 8
            re_reasons.append("二进制被 strip，需要符号恢复/函数识别")
        if packed.get("packed"):
            re_score += 10
            re_reasons.append(f"检测到 packer: {packed.get('packer') or 'unknown'}")
        if anti.get("anti_debug") or anti.get("anti_analysis"):
            re_score += 8
            re_reasons.append("检测到反调试/反分析特征")
        if info.get("type") not in ("ELF",):
            re_score += 6
            re_reasons.append(f"非 ELF 格式: {info.get('type')}，需按格式选工具")
        if re_score > 4:
            add("reverse-engineering", re_score, re_reasons)

        # 3) 轻量 CLI 侦察
        if shutil.which("rabin2") or shutil.which("r2"):
            add("radare2", 8, ["本机可用 rabin2/r2，先做导入表/字符串/保护机制证据"])
        else:
            add("radare2", 5, ["缺少 IDA/Ghidra 时用 r2 做 CLI 侦察（容器内已预装）"])

        # 4) Ghidra
        if functions.get("stripped") or language.get("rust") or language.get("cpp"):
            add("ghidra-reverse", 8, ["strip/复杂语言，建议 headless 反编译恢复控制流"])
        elif intel.get("decompiler", {}).get("ghidra"):
            add("ghidra-reverse", 6, ["检测到 Ghidra 可执行文件"])

        # 5) Go/Rust 专用恢复
        if language.get("go") or language.get("rust"):
            reasons = []
            if language.get("go"):
                reasons.append("Go runtime/pclntab 证据")
            if language.get("rust"):
                reasons.append("Rust runtime/panic 证据")
            add("go-rust-reverse", 10, reasons)

        # 6) CTF 沙盒证据工作流
        if ctx.get("evidence_mode") or intel.get("evidence"):
            add("competition-reverse-pwn", 7, ["要求 Evidence→Finding→Path，使用 CTF 沙盒反向/PWN 工作流"])

        hits.sort(key=lambda h: h.score, reverse=True)
        return hits


# ---------------------------------------------------------------------------
# 工具探测
# ---------------------------------------------------------------------------

TOOL_SPECS: Dict[str, Dict[str, Any]] = {
    "pwntools":     {"kind": "python", "module": "pwn", "install": "python3 -m pip install pwntools"},
    "ropgadget":    {"kind": "python", "module": "ropgadget", "install": "python3 -m pip install ROPGadget"},
    "capstone":     {"kind": "python", "module": "capstone", "install": "python3 -m pip install capstone"},
    "unicorn":      {"kind": "python", "module": "unicorn", "install": "python3 -m pip install unicorn"},
    "lief":         {"kind": "python", "module": "lief", "install": "python3 -m pip install lief"},
    "angr":         {"kind": "python", "module": "angr", "install": "python3 -m pip install angr"},
    "rabin2":       {"kind": "exe", "command": "rabin2", "install": "apt-get install -y radare2"},
    "r2":           {"kind": "exe", "command": "r2", "install": "apt-get install -y radare2"},
    "objdump":      {"kind": "exe", "command": "objdump", "install": "apt-get install -y binutils"},
    "readelf":      {"kind": "exe", "command": "readelf", "install": "apt-get install -y binutils"},
    "gdb":          {"kind": "exe", "command": "gdb", "install": "apt-get install -y gdb"},
    "one_gadget":   {"kind": "exe", "command": "one_gadget", "install": "gem install one_gadget"},
    "patchelf":     {"kind": "exe", "command": "patchelf", "install": "apt-get install -y patchelf"},
    "gcc":          {"kind": "exe", "command": "gcc", "install": "apt-get install -y build-essential"},
    "docker":       {"kind": "exe", "command": "docker", "install": "https://orbstack.dev (macOS Apple Silicon 推荐)"},
    "ghidra":       {"kind": "exe", "command": "analyzeHeadless", "install": "ghidra release 或 ghidra-mcp bootstrap"},
    "python3":      {"kind": "exe", "command": "python3", "install": "apt-get install -y python3"},
}


class ToolProbe:
    """校验当前环境工具，输出缺失项与安装提示。"""

    def __init__(self, specs: Optional[Dict[str, Dict[str, Any]]] = None):
        self.specs = specs or TOOL_SPECS
        self.status: Dict[str, Dict[str, Any]] = {}

    def check(self) -> Dict[str, Dict[str, Any]]:
        self.status = {}
        for name, spec in self.specs.items():
            ok = False
            detail = ""
            try:
                if spec.get("kind") == "python":
                    code = f"import {spec.get('module')}"
                    # 用当前解释器探测：AWDP 那类 .venv-linux 约定不把 pwntools 装进 PATH，
                    # 写死 python3 会把已装好的模块误报成缺失并给出错误的 pip 建议。
                    interpreter = sys.executable or "python3"
                    r = subprocess.run(
                        [interpreter, "-c", code],
                        capture_output=True, text=True, timeout=15,
                    )
                    ok = r.returncode == 0
                    detail = "" if ok else (r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "")
                else:
                    exe = spec.get("command", name)
                    found = shutil.which(exe)
                    ok = bool(found)
                    detail = found or ""
            except Exception as exc:
                detail = str(exc)
            self.status[name] = {
                "ok": ok,
                "detail": detail,
                "install": spec.get("install", ""),
            }
        return self.status

    def missing(self) -> List[str]:
        if not self.status:
            self.check()
        return [name for name, st in self.status.items() if not st["ok"]]

    def available(self) -> List[str]:
        if not self.status:
            self.check()
        return [name for name, st in self.status.items() if st["ok"]]

    def to_dict(self) -> Dict[str, Any]:
        if not self.status:
            self.check()
        return self.status

    def render_markdown(self) -> str:
        if not self.status:
            self.check()
        lines = ["| 工具 | 状态 | 路径/说明 | 安装建议 |", "|---|---|---|---|"]
        for name in sorted(self.status):
            st = self.status[name]
            status = "✅" if st["ok"] else "❌"
            detail = (st.get("detail") or "").replace("|", "\\|")[:60]
            install = (st.get("install") or "").replace("|", "\\|")
            lines.append(f"| {name} | {status} | {detail} | {install} |")
        return "\n".join(lines)

    def x86_container_needed(self, binary_info: Optional[Dict[str, Any]] = None) -> bool:
        """Apple Silicon 宿主机 + x86/x86_64 ELF → 建议使用 scripts/pwn-x86。"""
        if platform.system() != "Darwin":
            return False
        if platform.machine().lower() not in ("arm64", "aarch64"):
            return False
        arch = ((binary_info or {}).get("arch") or "").lower()
        return arch in ("i386", "amd64", "x86", "x86_64", "x86-64")


# ---------------------------------------------------------------------------
# Playbook
# ---------------------------------------------------------------------------

class PlaybookBuilder:
    """根据分析结果生成一份可直接执行的 RE -> PWN playbook。"""

    def __init__(self, library: Optional[SkillLibrary] = None):
        self.library = library or SkillLibrary()
        self.router = PwnSkillRouter(self.library)

    def build(self, analysis: Dict[str, Any], gadgets: Optional[Dict[str, Any]] = None,
              tool_probe: Optional[ToolProbe] = None) -> Dict[str, Any]:
        gadgets = gadgets or {}
        tool_probe = tool_probe or ToolProbe()
        tool_probe.check()

        functions = analysis.get("functions") or {}
        protections = analysis.get("protections") or {}
        info = analysis.get("info") or {}
        intel = analysis.get("reverse_intel") or {}
        vuln_type = analysis.get("_vuln_type") or analysis.get("vuln_type") or "unknown"
        if isinstance(vuln_type, (tuple, list)):
            vuln_type = vuln_type[0] if vuln_type else "unknown"

        context = {
            "task": "pwn",
            "vuln_type": vuln_type,
            "functions": functions,
            "protections": protections,
            "info": info,
            "reverse_intel": intel,
            "evidence_mode": True,
        }
        routes = self.router.route(context)

        checklist: List[str] = self._build_checklist(analysis, gadgets, intel, tool_probe)
        pitfalls = self._collect_pitfalls(routes, vuln_type)
        references = self._collect_references(routes, vuln_type)

        markdown = self.render_markdown(
            analysis=analysis,
            gadgets=gadgets,
            routes=routes,
            checklist=checklist,
            pitfalls=pitfalls,
            references=references,
            tool_probe=tool_probe,
            intel=intel,
        )

        return {
            "vuln_type": vuln_type,
            "routes": [h.to_dict() for h in routes],
            "checklist": checklist,
            "pitfalls": pitfalls,
            "references": references,
            "tool_status": tool_probe.to_dict(),
            "missing_tools": tool_probe.missing(),
            "markdown": markdown,
        }

    # -- checklist -----------------------------------------------------------
    def _build_checklist(self, analysis: Dict[str, Any], gadgets: Dict[str, Any],
                         intel: Dict[str, Any], tools: ToolProbe) -> List[str]:
        binary = analysis.get("info", {}).get("binary_path") or analysis.get("_binary_path") or "./vuln"
        libc = analysis.get("_libc_path")
        protections = analysis.get("protections") or {}
        functions = analysis.get("functions") or {}
        plt = gadgets.get("plt") or {}
        packed = intel.get("packed") or {}
        language = intel.get("language") or {}
        anti = intel.get("anti_analysis") or {}

        steps: List[str] = []
        steps.append(f"分诊: file {binary} && rabin2 -I {binary}（或 readelf -h {binary}）")
        steps.append(f"保护机制: checksec --file={binary}；确认 NX/PIE/Canary/RELRO/Fortify")
        if packed.get("packed"):
            packer = packed.get("packer") or "unknown"
            steps.append(f"脱壳优先: 检测到 {packer}。UPX 用 upx -d；自定义壳先 dump 到 OEP 再重建 IAT")
        if functions.get("stripped"):
            steps.append("stripped: 先用字符串/导入交叉引用恢复 main，再按需用 Ghidra headless 反编译")
        if language.get("go"):
            steps.append("Go binary: 检查 go.buildid/pclntab，GoReSym 恢复符号后定位 main_*")
        if language.get("rust"):
            steps.append("Rust binary: 沿 panic 字符串与 rust_eh_personality 交叉引用定位逻辑")
        if anti.get("anti_debug") or anti.get("anti_analysis"):
            steps.append("反分析: ptrace/prctl/LD_PRELOAD 检测需 patch 或 LD_PRELOAD hook 绕过")
        if not protections.get("nx", True):
            steps.append("NX 关闭: 优先 shellcode，确认栈/堆段 RWX 后 jmp rsp")
        if protections.get("canary"):
            steps.append("Canary 开启: 先找 leak（fmt/read 残留），forked server 可逐字节爆破")
        if protections.get("pie"):
            steps.append("PIE 开启: 先 leak 代码/PLT 地址再算 .text base")
        if libc:
            steps.append(f"libc: {libc} 需 one_gadget 找 magic gadget 并用泄漏地址反查 libc-database 验证版本")
        if plt.get("printf") or plt.get("sprintf"):
            steps.append("格式化字符串: 记录可控 fmt 位置；优先 leak，再 %hhn 分段写 GOT")
        if plt.get("seccomp_load") or plt.get("prctl"):
            steps.append("疑似 seccomp: 用 seccomp-tools dump；禁 execve 时改 ORW (open/read/write)")
        if gadgets.get("one_gadgets"):
            steps.append(f"one_gadget 候选 {len(gadgets['one_gadgets'])} 个: 逐个核对 rsi/rdx/r15/r12 约束，失败则换 ret2libc")
        if not gadgets.get("pop_rdi_in_binary", False):
            steps.append("二进制缺少 pop rdi: 优先 ret2csu，或从 libc 中找 pop rdi")
        steps.append("远程稳定化: 用 sendlineafter/recvuntil 锚字符串；rsp 16 字节对齐（需要时插 ret gadget）；远程连续验证 20 次")
        if tools.x86_container_needed(analysis.get("info")):
            steps.append("宿主机为 Apple Silicon 且目标是 x86 ELF: 用 scripts/pwn-x86 进入 amd64 容器执行")
        missing = tools.missing()
        if missing:
            steps.append(f"缺工具: {', '.join(missing)}。按 ToolProbe 安装建议补齐后再进入 exploit 阶段")
        return steps

    def _collect_pitfalls(self, routes: List[RouteHit], vuln_type: str) -> List[str]:
        pitfalls: List[str] = []
        skill = self.library.get("pwn-chain")
        if skill:
            section = skill.sections().get("注意事项", "")
            if section:
                pitfalls = [ln.lstrip("- ").strip() for ln in section.splitlines()
                            if ln.strip().startswith("-")]
        if vuln_type == "heap":
            pitfalls.append("堆利用对 glibc 版本极敏感: 2.27 tcache / 2.32 safe-linking / 2.34 移除 hook")
        if vuln_type in {"ret2libc", "one_gadget", "rop"}:
            pitfalls.append("64 位 system 前 rsp 必须 16 字节对齐，否则 movaps 崩溃")
        return pitfalls[:12]

    def _collect_references(self, routes: List[RouteHit], vuln_type: str) -> List[Dict[str, str]]:
        out: List[Dict[str, str]] = []
        ref_map = {
            "ret2win": "skills-pwn-chain-references-stack-pwn-md",
            "ret2libc": "skills-pwn-chain-references-stack-pwn-md",
            "rop": "skills-pwn-chain-references-stack-pwn-md",
            "one_gadget": "skills-pwn-chain-references-stack-pwn-md",
            "shellcode": "skills-pwn-chain-references-stack-pwn-md",
            "format_string": "skills-pwn-chain-references-stack-pwn-md",
            "ret2syscall": "skills-pwn-chain-references-stack-pwn-md",
            "stack_pivot": "skills-pwn-chain-references-stack-pwn-md",
            "heap": "skills-pwn-chain-references-heap-pwn-md",
        }
        wanted = [ref_map.get(vuln_type), "skills-reverse-engineering-elf-analysis-md",
                  "skills-ops-evidence-finding-path-md",
                  "CTF-Sandbox-Orchestrator-competition-reverse-pwn-references-reverse-pwn-md"]
        for doc_id in wanted:
            if not doc_id:
                continue
            doc = self.library.get(doc_id)
            if doc:
                out.append({"id": doc.skill_id, "title": doc.title, "path": doc.path})
        for hit in routes[:4]:
            if hit.doc.kind == "skill":
                out.append({"id": hit.doc.skill_id, "title": hit.doc.title, "path": hit.doc.path})
        seen = set()
        unique = []
        for item in out:
            if item["id"] not in seen:
                seen.add(item["id"])
                unique.append(item)
        return unique

    # -- markdown ------------------------------------------------------------
    def render_markdown(self, analysis: Dict[str, Any], gadgets: Dict[str, Any],
                        routes: List[RouteHit], checklist: List[str], pitfalls: List[str],
                        references: List[Dict[str, str]], tool_probe: ToolProbe,
                        intel: Optional[Dict[str, Any]] = None) -> str:
        binary = analysis.get("info", {}).get("binary_path") or analysis.get("_binary_path") or "./vuln"
        vuln_type = analysis.get("_vuln_type") or analysis.get("vuln_type") or "unknown"
        if isinstance(vuln_type, (tuple, list)):
            vuln_type = vuln_type[0] if vuln_type else "unknown"

        lines: List[str] = []
        lines.append("# PwnSolver × reverse-skill Playbook")
        lines.append("")
        lines.append(f"- 目标: `{binary}`")
        lines.append(f"- 漏洞类型: `{vuln_type}`")
        lines.append("")
        lines.append("## 技能路由")
        lines.append("")
        for hit in routes:
            lines.append(f"1. **{hit.doc.title}** (`{hit.doc.skill_id}`) score={hit.score}: {'; '.join(hit.reasons)}")
        lines.append("")
        pattern_matches = analysis.get('pattern_matches') or []
        if pattern_matches:
            lines.append("## 泛化模式")
            lines.append("")
            for pm in pattern_matches[:6]:
                lines.append(f"- `{pm.get('pattern_id')}` -> `{pm.get('vuln_type')}` ({pm.get('confidence')}): {'; '.join(pm.get('reasons') or [])}")
            lines.append("")
        lines.append("## 执行清单")
        lines.append("")
        for i, step in enumerate(checklist, 1):
            lines.append(f"{i}. {step}")
        lines.append("")
        lines.append("## 关键参考")
        lines.append("")
        for ref in references:
            lines.append(f"- {ref['title']} (`{ref['path']}`)")
        lines.append("")
        lines.append("## 常见坑")
        lines.append("")
        for p in pitfalls:
            lines.append(f"- {p}")
        lines.append("")
        lines.append("## 工具链")
        lines.append("")
        lines.append(tool_probe.render_markdown())
        if intel:
            lines.append("")
            lines.append("## 深度侦察摘要")
            lines.append("")
            lines.append("```json")
            compact = {
                "packed": intel.get("packed"),
                "language": intel.get("language"),
                "anti_analysis": intel.get("anti_analysis"),
                "tooling": intel.get("tooling"),
            }
            lines.append(json.dumps(compact, ensure_ascii=False, indent=2))
            lines.append("```")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 入口便捷函数
# ---------------------------------------------------------------------------

def build_playbook(analysis: Dict[str, Any], gadgets: Optional[Dict[str, Any]] = None,
                   skill_root: Optional[str] = None) -> Dict[str, Any]:
    """给 solver.py 调用的一个函数式入口。"""
    library = SkillLibrary(skill_root)
    return PlaybookBuilder(library).build(analysis, gadgets or {})


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="reverse-skill 知识库自检/路由演示")
    parser.add_argument("--skill-root", default=None)
    parser.add_argument("--vuln-type", default="ret2libc")
    args = parser.parse_args()

    lib = SkillLibrary(args.skill_root)
    print(f"skills: {len(lib.list_skills())}, references: {len(lib.list_references())}")
    routes = PwnSkillRouter(lib).route({
        "vuln_type": args.vuln_type,
        "functions": {"stripped": True},
        "protections": {"nx": True, "pie": True, "canary": True},
        "info": {"type": "ELF", "arch": "amd64"},
    })
    for hit in routes:
        print(f"- {hit.score:>2} {hit.doc.skill_id:24s} {hit.doc.title}")
    print()
    print("missing tools:", ToolProbe().missing())
