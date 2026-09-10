#!/usr/bin/env python3
"""把工作树里被写成 CRLF 的文件改回 LF（配合 .gitattributes 的 eol=lf）。

为什么需要脚本而不是 `git checkout`：
  Windows 上 core.autocrlf=true 会在检出时把文本文件写成 CRLF，即便 .gitattributes
  写了 eol=lf，已经存在于工作树的文件也不会自动重写（git checkout-index -a -f 同样
  不生效）。而带 shebang 的脚本一旦是 CRLF，Linux/WSL 下 `./script` 报
  "env: bash\\r: No such file or directory"、`bash script` 报 pipefail 无效。

用法：
    python3 scripts/normalize_eol.py            # 只报告
    python3 scripts/normalize_eol.py --fix      # 就地改回 LF
"""
import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def tracked_crlf_files():
    """用 git ls-files --eol 找出工作树里是 CRLF 的已跟踪文件。"""
    try:
        out = subprocess.run(['git', 'ls-files', '--eol'], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f'[!] 无法读取 git 文件列表: {exc}')
        return []
    files = []
    for line in out.splitlines():
        parts = line.split('\t')
        if len(parts) < 2:
            continue
        meta, path = parts[0], parts[-1]
        if 'w/crlf' in meta:
            files.append(path)
    return files


def strip_cr(path):
    full = os.path.join(ROOT, path)
    try:
        with open(full, 'rb') as f:
            data = f.read()
    except OSError:
        return False
    if b'\r\n' not in data:
        return False
    with open(full, 'wb') as f:
        f.write(data.replace(b'\r\n', b'\n'))
    return True


def main():
    ap = argparse.ArgumentParser(description='把工作树 CRLF 文件改回 LF')
    ap.add_argument('--fix', action='store_true', help='就地修改（默认只报告）')
    args = ap.parse_args()

    files = tracked_crlf_files()
    if not files:
        print('[eol] 工作树没有 CRLF 的已跟踪文件，无需处理')
        return 0

    print(f'[eol] 工作树里 {len(files)} 个已跟踪文件是 CRLF：')
    for path in files[:40]:
        print(f'  {path}')
    if len(files) > 40:
        print(f'  ... 另外 {len(files) - 40} 个')

    if not args.fix:
        print('[eol] 加 --fix 就地改回 LF')
        return 1

    changed = sum(1 for path in files if strip_cr(path))
    print(f'[eol] 已改回 LF: {changed} 个文件')
    print('[eol] 注意：这些改动需要重新 commit（.gitattributes 已声明 eol=lf）')
    return 0


if __name__ == '__main__':
    sys.exit(main())
