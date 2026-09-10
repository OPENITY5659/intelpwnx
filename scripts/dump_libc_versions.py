#!/usr/bin/env python3
"""把官方 pool 里各个 libc 点版本一次性 dump 到本地（真实 .so，可离线复用）。

为什么不走 libc-database：现代版本的 niklasb/libc-database 仓库**不再包含** db 偏移表
（浅克隆下来只有 240K，db/ 是空的，靠它的 get 命令联网现拉），拿不到"现成的全量偏移库"。
而 Ubuntu/Debian 的官方 pool 目录列表里保留了历史上发布过的每一个 libc6 点版本 deb：

    http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.31-0ubuntu9.9_amd64.deb
    http://deb.debian.org/debian/pool/main/g/glibc/libc6_2.31-13+deb11u11_amd64.deb

把它们全抓下来解包，得到的是"偏移 + 真实 .so"两样都有 —— 既能识别版本，也能直接生成
ROP/one_gadget 链；每个文件都带 sha256 记录，来源可复现，抓完就能断网长期使用。

用法：
    python3 scripts/dump_libc_versions.py --list                      # 只列出会抓哪些
    python3 scripts/dump_libc_versions.py --major 2.31 --major 2.35    # 抓指定版本线
    python3 scripts/dump_libc_versions.py --all                       # 抓全部已收录版本线
    python3 scripts/dump_libc_versions.py --arch i386 --major 2.23
    python3 scripts/dump_libc_versions.py --rebuild-index             # 抓完刷新离线索引
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fetch_libc_set import (DEBIAN, DOWNLOADS, LIBCS, ROOT, UBUNTU,  # noqa: E402
                            extract_deb, http_get, load_manifest, normalize_layout,
                            rebuild_index, save_manifest, sha256_of, version_sort_key)

# 收录的版本线（按发行版归组）。默认抓这些——它们是 CTF/AWD 里真正会遇到的区间。
MAJOR_LINES = {
    UBUNTU: ['2.19', '2.23', '2.27', '2.31', '2.35', '2.39', '2.41', '2.42'],
    DEBIAN: ['2.24', '2.28', '2.31', '2.36', '2.38', '2.39', '2.40', '2.41'],
}
ARCHES = ('amd64', 'i386')


def list_pool(pool_url, cached_only=False):
    """取 pool 目录列表里所有 libc6 deb：{版本: {arch: 文件名}}。"""
    html = ''
    if not cached_only:
        try:
            html = http_get(pool_url, timeout=120).decode('utf-8', 'ignore')
        except Exception as exc:  # 网络/镜像问题不该中断整轮
            print(f'  [!] 读取 {pool_url} 失败: {exc}')
    found = {}
    pat = re.compile(r'href="libc6_([0-9][^"_]*?)_(' + '|'.join(ARCHES) + r')\.deb"')
    for m in pat.finditer(html):
        version, arch = m.group(1), m.group(2)
        found.setdefault(version, {})[arch] = f'libc6_{version}_{arch}.deb'
    return found, pool_url


def local_deb_version(name):
    m = re.match(r'libc6_(.+)_(?:amd64|i386)\.deb$', name)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description='dump 各版本 libc（真实 .so）到本地')
    ap.add_argument('--major', action='append', default=[],
                    help='只抓这些版本线（如 2.31），可重复；默认抓全部已收录版本线')
    ap.add_argument('--arch', action='append', choices=list(ARCHES), default=[])
    ap.add_argument('--list', action='store_true', help='只列出会抓什么，不下载')
    ap.add_argument('--cached-only', action='store_true',
                    help='不联网：只用 libcs/.downloads 里已有的 deb')
    ap.add_argument('--clean-debs', action='store_true', help='解包后删除 .deb（省空间）')
    ap.add_argument('--rebuild-index', action='store_true')
    args = ap.parse_args()

    arches = args.arch or ['amd64']
    majors = args.major or [m for lines in MAJOR_LINES.values() for m in lines]
    os.makedirs(DOWNLOADS, exist_ok=True)
    man = load_manifest()
    have = {(e.get('distro'), e.get('arch')) for e in man['entries']}

    # 1) 收集候选（每个 pool 一份列表，缓存到本地以便 --cached-only 复用）
    pool_versions = {}
    for pool in MAJOR_LINES:
        cache_file = os.path.join(DOWNLOADS, 'pool-%s.html' % pool.split('//')[1].split('/')[0])
        if args.cached_only and os.path.exists(cache_file):
            found, _ = list_pool(pool, cached_only=True)
            with open(cache_file, encoding='utf-8', errors='ignore') as f:
                html = f.read()
            pat = re.compile(r'href="libc6_([0-9][^"_]*?)_(' + '|'.join(ARCHES) + r')\.deb"')
            found = {}
            for m in pat.finditer(html):
                found.setdefault(m.group(1), {})[m.group(2)] = f'libc6_{m.group(1)}_{m.group(2)}.deb'
        else:
            found, _ = list_pool(pool)
            if found:
                try:
                    html = http_get(pool, timeout=120).decode('utf-8', 'ignore')
                    with open(cache_file, 'w', encoding='utf-8') as f:
                        f.write(html)
                except Exception:
                    pass
        pool_versions[pool] = found

    # 2) 过滤出版本线命中、且本地还没有的目标
    todo = []
    for pool, found in pool_versions.items():
        for version in sorted(found, key=version_sort_key):
            if not any(version.startswith(m) for m in majors):
                continue
            for arch in arches:
                deb = found[version].get(arch)
                if not deb:
                    continue
                distro = 'ubuntu' if 'ubuntu' in pool else 'debian'
                if (f'{distro}-{version}', arch) in have:
                    continue
                todo.append((pool, distro, version, arch, deb))

    print(f'[dump] 候选 {len(todo)} 个（版本线 {" ".join(majors)}，架构 {" ".join(arches)}）')
    for pool, distro, version, arch, deb in todo[:20]:
        print(f'  - {distro} {version} {arch}')
    if len(todo) > 20:
        print(f'  ... 另外 {len(todo) - 20} 个')
    if args.list:
        return 0

    ok = failed = 0
    for pool, distro, version, arch, deb in todo:
        local_deb = os.path.join(DOWNLOADS, deb)
        if not os.path.exists(local_deb):
            try:
                data = http_get(pool + deb, timeout=300)
            except Exception as exc:
                print(f'  [fail] {distro} {version} {arch}: {exc}')
                failed += 1
                continue
            with open(local_deb, 'wb') as f:
                f.write(data)
        dest = os.path.join(LIBCS, f'glibc-{version}-{distro}-{arch}')
        if not extract_deb(local_deb, dest):
            failed += 1
            continue
        info = normalize_layout(dest, version, arch)
        if not info:
            print(f'  [!] {version} {arch} 解包后找不到 libc，跳过')
            failed += 1
            continue
        entry = {
            'distro': f'{distro}-{version}', 'arch': arch, 'version': version,
            'url': pool + deb, 'sha256': sha256_of(local_deb),
            'dir': os.path.relpath(dest, ROOT).replace(os.sep, '/'),
            'libc': os.path.relpath(info['libc'], ROOT).replace(os.sep, '/'),
            'loader': (os.path.relpath(info['loader'], ROOT).replace(os.sep, '/')
                       if info['loader'] else None),
        }
        man['entries'] = [e for e in man['entries']
                          if not (e.get('distro') == entry['distro'] and e.get('arch') == arch)]
        man['entries'].append(entry)
        man['entries'].sort(key=lambda e: (e.get('version', ''), e.get('arch', '')))
        save_manifest(man)
        have.add((entry['distro'], arch))
        ok += 1
        print(f'  [ok] {version} {arch} → {entry["libc"]}', flush=True)
        if args.clean_debs:
            try:
                os.unlink(local_deb)
            except OSError:
                pass

    print(f'\n[dump] 完成：成功 {ok}，失败 {failed}，清单 {os.path.join(LIBCS, "MANIFEST.json")}')
    if args.rebuild_index or ok:
        rebuild_index()
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
