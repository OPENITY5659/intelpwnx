#!/usr/bin/env python3
"""
BadChars检测与绕过引擎 + 自动libc检测
"""
import os, glob, time, struct

def _elf_machine(path):
    """读取 ELF e_machine (EM_X86_64=62, EM_386=3, EM_AARCH64=183 ...)"""
    try:
        with open(path, 'rb') as f:
            data = f.read(0x20)
        if data[:4] != b'\x7fELF':
            return None
        return struct.unpack('<H', data[18:20])[0]
    except Exception:
        return None


class BadCharsDetector:
    """自动检测bad characters"""
    
    def __init__(self, binary_path, verbose=True):
        self.binary_path = binary_path
        self.verbose = verbose
        self.badchars = set()
        
    def log(self, msg):
        if self.verbose:
            print(f"  [badchars] {msg}", flush=True)
    
    def detect(self):
        """发送0x00-0xff检测哪些被过滤"""
        self.log("检测bad characters...")
        try:
            from pwn import process
            p = process(self.binary_path)
            all_bytes = bytes(range(256))
            p.send(all_bytes + b'\n')
            time.sleep(0.5)
            try:
                resp = p.recvall(timeout=2)
            except:
                resp = b''
            p.close()
            
            self.badchars = set()
            for i in range(256):
                b = bytes([i])
                if b not in resp:
                    self.badchars.add(i)
            
            common = [b for b in [0x00, 0x0a, 0x20, 0x7f] if b in self.badchars]
            self.log(f"找到 {len(self.badchars)} 个bad chars: {[hex(b) for b in sorted(common)]}")
        except Exception as e:
            self.log(f"检测失败: {e}")
        
        return self.badchars
    
    def find_xor_key(self, target_bytes, max_xor=255):
        """找XOR密钥避开所有badchars"""
        for key in range(1, max_xor):
            encoded = bytes(b ^ key for b in target_bytes)
            if not any(b in self.badchars for b in encoded):
                return key
        return None
    
    def is_clean(self, data):
        """检查数据是否不含badchars"""
        return not any(b in self.badchars for b in data)


def _named_libc_in(directory, binary_path, skip_name=None):
    """在目录里找命名明确的 libc（架构匹配优先）。返回路径或 None。"""
    if not directory or not os.path.isdir(directory):
        return None
    target_machine = _elf_machine(binary_path)
    candidates = []
    for f in sorted(glob.glob(os.path.join(directory, '*'))):
        name = os.path.basename(f)
        if skip_name and name == skip_name:
            continue
        if name.startswith('core.') or 'ld-linux' in name:
            continue
        if not os.path.isfile(f):
            continue
        try:
            with open(f, 'rb') as fp:
                if fp.read(4) != b'\x7fELF':
                    continue
        except OSError:
            continue
        bn = name.lower()
        # 精确匹配 libc.so / libc-2.31.so 等，排除 libcrypto/libc++/libcapstone/musl
        if bn.startswith('libc') and (bn == 'libc' or bn.startswith('libc.so') or bn.startswith('libc-')):
            candidates.append(f)
    if not candidates:
        return None
    for f in candidates:
        if _elf_machine(f) == target_machine:
            return f
    return candidates[0]


def detect_libc_ex(binary_path, leaks=None, arch=None, register=True):
    """离线优先的 libc 探测，返回带来源的详细结果。

    优先级：① 同目录附件 ② 上级目录附件 ③ 本地符号索引（需要泄露）④ 系统 libc 兜底。
    ④ 会被标记 suspect —— 它只是"能让本地跑起来"，打远程时必须换成靶机 libc。

    leaks: {符号: 泄露地址}，有泄露时才启用索引匹配（这是断网识别的唯一途径）。
    """
    binary_path = os.path.abspath(binary_path)
    result = {'path': None, 'source': None, 'suspect': False, 'version': None,
              'loader': None, 'candidates': [], 'note': None}
    binary_dir = os.path.dirname(binary_path)
    binary_name = os.path.basename(binary_path)

    found = _named_libc_in(binary_dir, binary_path, skip_name=binary_name)
    if found:
        result.update(path=found, source='sibling')
    else:
        found = _named_libc_in(os.path.dirname(binary_dir), binary_path, skip_name=binary_name)
        if found:
            result.update(path=found, source='neighbor')

    if not result['path'] and leaks:
        try:
            from libc_db import match_leaks
            matches = match_leaks(leaks, arch=arch)
        except ImportError:
            matches = []
        if matches:
            result['candidates'] = matches
            best = matches[0]
            result.update(path=best.path, source='index', version=best.libc_version)
            if len(matches) > 1:
                result['note'] = (f"索引给出 {len(matches)} 个候选（页内偏移相同），"
                                  f"已选 {best.libc_version}，必要时用 -l 明确指定")

    if not result['path']:
        target_machine = _elf_machine(binary_path)
        try:
            from utils import find_libc
            sys_libc = find_libc()
            if sys_libc and os.path.exists(sys_libc):
                if target_machine is None or _elf_machine(sys_libc) == target_machine:
                    result.update(path=sys_libc, source='system', suspect=True,
                                  note='使用本机系统 libc 兜底：只能在本地自测，'
                                       '打远程前必须换成靶机 libc')
        except Exception:
            pass

    if result['path']:
        try:
            from libc_db import add_libc, find_loader_for, describe_libc
            if result['source'] in ('sibling', 'neighbor', 'index') and register:
                entry = add_libc(result['path'])
                if entry:
                    result['version'] = result['version'] or entry.get('libc_version')
                    result['loader'] = entry.get('loader')
            if not result['loader']:
                result['loader'] = find_loader_for(result['path'], version=result['version'])
            if not result['version']:
                entry = describe_libc(result['path'])
                result['version'] = entry.get('libc_version') if entry else None
        except ImportError:
            pass
    return result


def auto_detect_libc(binary_path, leaks=None, arch=None):
    """自动检测libc（离线优先）。

    ①同目录命名明确的libc ②上级目录附件 ③本地符号索引（需泄露） ④系统libc(架构匹配)。
    保持"返回路径字符串"的旧契约；需要区分来源时用 detect_libc_ex()。
    """
    return detect_libc_ex(binary_path, leaks=leaks, arch=arch).get('path')


def auto_detect_ld(binary_path, libc_path=None):
    """自动检测同目录（或 libc 同目录）下的加载器。

    除了 ld-linux*.so.2，也认 ld-2.23.so 这类版本化名字；都没有时用本地索引/glibc_compat
    里的配对 loader 兜底（把原先只认 2.23 的特例泛化到任意版本）。
    """
    import os as _os
    dirs = [_os.path.dirname(_os.path.abspath(binary_path))]
    if libc_path:
        dirs.append(_os.path.dirname(_os.path.abspath(libc_path)))
    for d in dirs:
        if not _os.path.isdir(d):
            continue
        for name in sorted(_os.listdir(d)):
            low = name.lower()
            is_loader = ('ld-linux' in low
                         or (low.startswith('ld-') and low.endswith('.so'))
                         or (low.startswith('ld-') and 'linux' in low))
            if not is_loader:
                continue
            path = _os.path.join(d, name)
            try:
                with open(path, 'rb') as fp:
                    if fp.read(4) == b'\x7fELF':
                        return path
            except Exception:
                pass
    if libc_path:
        try:
            from libc_db import find_loader_for
            found = find_loader_for(libc_path)
            if found:
                return found
        except ImportError:
            pass
    return None
