#!/usr/bin/env python3
"""
工具函数
"""

import os
import sys
import subprocess


def run_command(cmd, timeout=30, cwd=None):
    """运行命令并返回输出"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", -1
    except Exception as e:
        return "", str(e), -1


def ensure_wsl_path(path):
    """将Windows路径转换为WSL路径"""
    if sys.platform == 'win32':
        # Windows路径 -> /mnt/c/Users/...
        path = path.replace('\\', '/')
        if ':' in path:
            drive, rest = path.split(':', 1)
            path = f'/mnt/{drive.lower()}{rest}'
    return path


def find_libc():
    """尝试找到系统libc"""
    candidates = [
        '/lib/x86_64-linux-gnu/libc.so.6',
        '/lib/i386-linux-gnu/libc.so.6',
        '/lib/x86_64-linux-gnu/libc-*.so',
        '/usr/lib/x86_64-linux-gnu/libc.so.6',
        '/lib/aarch64-linux-gnu/libc.so.6',
    ]
    
    import glob
    for pattern in candidates:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    
    # 使用ldd查找
    try:
        result = subprocess.run(
            ['ldd', '/bin/ls'], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'libc.so' in line:
                # 提取路径
                import re
                m = re.search(r'(/\S+)', line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    
    return None


def check_tools():
    """检查必要工具"""
    tools = {
        'ROPgadget': ['ROPgadget', '--version'],
        'one_gadget': ['one_gadget', '--version'],
        'gdb': ['gdb', '--version'],
        'objdump': ['objdump', '--version'],
        'strings': ['strings', '--version'],
    }
    
    results = {}
    for name, cmd in tools.items():
        stdout, stderr, rc = run_command(cmd)
        results[name] = rc == 0
    
    return results


_EXPLOIT_PYTHON = None


def exploit_python():
    """跑生成的 exploit 时使用的解释器。

    历史实现各处写死 'python3'，这在 PATH 里没有 pwntools 的环境会直接 ImportError
    （AWDP 的 .venv-linux 约定就是不把 pwntools 装进 PATH）。优先用当前解释器，
    确认它能 import pwn；不行再退回 PATH 上的 python3。
    """
    global _EXPLOIT_PYTHON
    if _EXPLOIT_PYTHON:
        return _EXPLOIT_PYTHON
    candidates = []
    if sys.executable:
        candidates.append(sys.executable)
    candidates.append('python3')
    for exe in candidates:
        try:
            proc = subprocess.run([exe, '-c', 'import pwn'], capture_output=True, timeout=30)
            if proc.returncode == 0:
                _EXPLOIT_PYTHON = exe
                return exe
        except Exception:
            continue
    _EXPLOIT_PYTHON = 'python3'
    return _EXPLOIT_PYTHON
