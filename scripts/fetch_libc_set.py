#!/usr/bin/env python3
"""预抓常用 libc 到 libcs/，供离线 libc 索引使用。

这是整套离线能力里**唯一**需要联网的一步：抓完之后，求解、匹配、loader 配对
全部在本地文件上完成（libc_db.py 不含任何网络代码）。

来源是发行版官方 pool 里的 libc6 deb（可复现、带 sha256 记录），抓下来用
dpkg-deb 解出 libc 与配对 loader，落成与 libcs/2.32 一致的目录布局：

    libcs/glibc-<version>-<distro>-<arch>/lib/<triple>/libc-<version>.so
                                             /ld-<version>.so
                                             /libc.so.6 -> libc-<version>.so
                                             /ld-linux-x86-64.so.2 -> ld-<version>.so

用法：
    python3 scripts/fetch_libc_set.py --list             # 只列出计划抓取的版本
    python3 scripts/fetch_libc_set.py                    # 联网抓取（已存在的跳过）
    python3 scripts/fetch_libc_set.py --arch i386        # 只抓 32 位
    python3 scripts/fetch_libc_set.py --no-network       # 只用 libcs/.downloads 里已有的 deb
    python3 scripts/fetch_libc_set.py --rebuild-index    # 抓完后刷新离线索引

已知缺口（2026-09 实测）：
    debian9(2.24) / debian10(2.28) 在现网 pool 里已经下架，会报 "pool 里找不到"。
    这两个版本在 CTF 里很少见；若确实需要，从 archive.debian.org 手工下载 deb 放进
    libcs/.downloads/ 后用 --no-network 解包即可。已覆盖的常用版本：
    2.23 / 2.27 / 2.31 / 2.35 / 2.39（Ubuntu）与 2.31 / 2.36（Debian），含 amd64 + i386。
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIBCS = os.path.join(ROOT, 'libcs')
DOWNLOADS = os.path.join(LIBCS, '.downloads')
MANIFEST = os.path.join(LIBCS, 'MANIFEST.json')
UA = {'User-Agent': 'pwnsolver-offline-libc-fetch/1.0'}

UBUNTU = 'http://archive.ubuntu.com/ubuntu/pool/main/g/glibc/'
DEBIAN = 'http://deb.debian.org/debian/pool/main/g/glibc/'

# 每个发行版取 glibc 的一个版本线；具体点版本从 pool 目录里挑最新的
TARGETS = [
    # (发行版, 版本线前缀, pool 地址, 说明)
    ('ubuntu16.04', '2.23-0ubuntu', UBUNTU, 'CTF 最常见的老 glibc'),
    ('ubuntu18.04', '2.27-3ubuntu', UBUNTU, 'tcache 引入版本'),
    ('ubuntu20.04', '2.31-0ubuntu', UBUNTU, 'AWD 常见'),
    ('ubuntu22.04', '2.35-0ubuntu', UBUNTU, 'safe-linking + 移除 __free_hook'),
    ('ubuntu24.04', '2.39-0ubuntu', UBUNTU, '新赛题常见'),
    ('debian9', '2.24-11+deb9', DEBIAN, ''),
    ('debian10', '2.28-10+deb10', DEBIAN, ''),
    ('debian11', '2.31-13+deb11', DEBIAN, ''),
    ('debian12', '2.36-9+deb12', DEBIAN, ''),
]

TRIPLE = {'amd64': 'x86_64-linux-gnu', 'i386': 'i386-linux-gnu'}


def http_get(url, timeout=60):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def discover_deb(pool_url, version_prefix, arch):
    """在 pool 目录列表里找最新的 libc6_<prefix>*_<arch>.deb。"""
    try:
        html = http_get(pool_url).decode('utf-8', 'ignore')
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f'  [!] 无法读取 {pool_url}: {exc}')
        return None
    pat = re.compile(r'href="(libc6_(' + re.escape(version_prefix) + r'[^"_]*)_' + arch + r'\.deb)"')
    found = {}
    for m in pat.finditer(html):
        found[m.group(2)] = m.group(1)
    if not found:
        return None
    best = sorted(found, key=version_sort_key)[-1]
    return found[best], best


def version_sort_key(version):
    """对 2.31-0ubuntu9.9 这类版本排序（按数字段，缺位补 0）。"""
    parts = re.findall(r'\d+', version)
    return [int(p) for p in parts[:6]] + [0] * (6 - len(parts[:6]))


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def extract_deb(deb_path, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    try:
        subprocess.run(['dpkg-deb', '-x', deb_path, dest_dir], check=True,
                       capture_output=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        detail = getattr(exc, 'stderr', b'') or b''
        print(f'  [!] dpkg-deb 解包失败: {detail.decode("utf-8", "ignore")[:200]}')
        return False


def normalize_layout(dest_dir, version, arch):
    """把解出来的 libc/loader 摆成索引期望的布局，并补上 .so.6 / ld-linux 软链。"""
    triple = TRIPLE[arch]
    src = os.path.join(dest_dir, 'lib', triple)
    if not os.path.isdir(src):
        # i386 老包放在 /lib/i386-linux-gnu 或 /lib32
        for alt in ('lib/i386-linux-gnu', 'lib32', 'lib/x86_64-linux-gnu'):
            cand = os.path.join(dest_dir, alt)
            if os.path.isdir(cand):
                src = cand
                break
    if not os.path.isdir(src):
        return None
    libc_real = ld_real = None
    for name in os.listdir(src):
        if re.fullmatch(r'libc-\d+\.\d+\.so', name) or name == 'libc.so.6':
            libc_real = libc_real or name
        if re.fullmatch(r'ld-\d+\.\d+\.so', name):
            ld_real = ld_real or name
    if not libc_real:
        return None
    libc_path = os.path.join(src, libc_real)
    # 保证 libc.so.6 这个别名存在（索引和求解器常用这个名字）
    alias = os.path.join(src, 'libc.so.6')
    if not os.path.exists(alias):
        try:
            os.symlink(libc_real, alias)
        except OSError:
            shutil.copy2(libc_path, alias)
    ld_alias = None
    if ld_real:
        ld_alias = os.path.join(src, 'ld-linux-x86-64.so.2' if arch == 'amd64' else 'ld-linux.so.2')
        if not os.path.exists(ld_alias):
            try:
                os.symlink(ld_real, ld_alias)
            except OSError:
                shutil.copy2(os.path.join(src, ld_real), ld_alias)
    return {'libc': libc_path, 'loader': os.path.join(src, ld_real) if ld_real else None,
            'libc_alias': alias, 'loader_alias': ld_alias, 'version': version}


def load_manifest():
    if os.path.exists(MANIFEST):
        try:
            with open(MANIFEST, encoding='utf-8') as f:
                return json.load(f)
        except ValueError:
            pass
    return {'entries': []}


def save_manifest(man):
    os.makedirs(LIBCS, exist_ok=True)
    with open(MANIFEST, 'w', encoding='utf-8') as f:
        json.dump(man, f, ensure_ascii=False, indent=2)


def rebuild_index():
    sys.path.insert(0, os.path.join(ROOT, 'pwn_solver'))
    try:
        import libc_db
    except ImportError as exc:
        print(f'[!] 无法导入 libc_db: {exc}')
        return
    index, stats = libc_db.build_index(verbose=False)
    print(f"[libcdb] 索引条目 {len(index['entries'])} "
          f"(新增 {stats['added']} 更新 {stats['updated']}) → {libc_db.index_path()}")


def main():
    ap = argparse.ArgumentParser(description='预抓常用 libc（整套离线能力的唯一联网步骤）')
    ap.add_argument('--arch', action='append', choices=['amd64', 'i386'],
                    help='限定架构，可重复；默认 amd64')
    ap.add_argument('--list', action='store_true', help='只列出计划抓取的版本')
    ap.add_argument('--no-network', action='store_true',
                    help='不联网：只用 libcs/.downloads 里已存在的 deb 解包')
    ap.add_argument('--force', action='store_true', help='已存在也重新抓取')
    ap.add_argument('--rebuild-index', action='store_true', help='结束后刷新离线索引')
    args = ap.parse_args()

    arches = args.arch or ['amd64']
    man = load_manifest()
    have = {(e.get('distro'), e.get('arch')) for e in man['entries']}
    os.makedirs(DOWNLOADS, exist_ok=True)

    planned, rows = [], []
    for distro, prefix, pool, note in TARGETS:
        for arch in arches:
            planned.append((distro, prefix, pool, arch, note))

    if args.list:
        print(f"{'发行版':<12} {'架构':<6} {'版本线':<16} 状态")
        for distro, prefix, _pool, arch, _note in planned:
            state = '已就绪' if (distro, arch) in have else '待抓取'
            print(f'{distro:<12} {arch:<6} {prefix:<16} {state}')
        return 0

    ok = skipped = failed = 0
    for distro, prefix, pool, arch, _note in planned:
        if (distro, arch) in have and not args.force:
            print(f'[skip] {distro}/{arch} 已在 MANIFEST 中')
            skipped += 1
            continue

        url = None
        version = None
        local_deb = None

        if not args.no_network:
            got = discover_deb(pool, prefix, arch)
            if not got:
                print(f'[fail] {distro}/{arch}: pool 里找不到 {prefix}*_{arch}.deb')
                failed += 1
                continue
            deb_name, version = got
            url = pool + deb_name
            local_deb = os.path.join(DOWNLOADS, deb_name)
            print(f'[get ] {distro}/{arch} {version}  {url}')
            try:
                data = http_get(url, timeout=180)
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                print(f'  [!] 下载失败: {exc}')
                failed += 1
                continue
            with open(local_deb, 'wb') as f:
                f.write(data)
        else:
            cands = [n for n in os.listdir(DOWNLOADS)
                     if n.startswith(f'libc6_{prefix}') and n.endswith(f'_{arch}.deb')]
            if not cands:
                print(f'[fail] {distro}/{arch}: 离线模式但 {DOWNLOADS} 里没有 '
                      f'libc6_{prefix}*_{arch}.deb')
                failed += 1
                continue
            deb_name = sorted(cands, key=version_sort_key)[-1]
            local_deb = os.path.join(DOWNLOADS, deb_name)
            version = deb_name[len('libc6_'):-len(f'_{arch}.deb')]
            print(f'[local] {distro}/{arch} {version} 使用已下载的 {deb_name}')

        dest = os.path.join(LIBCS, f'glibc-{version}-{distro}-{arch}')
        if os.path.isdir(dest) and args.force:
            shutil.rmtree(dest)
        if not extract_deb(local_deb, dest):
            failed += 1
            continue
        info = normalize_layout(dest, version, arch)
        if not info:
            print(f'  [!] 解包结果里找不到 libc，跳过 {dest}')
            failed += 1
            continue
        entry = {
            'distro': distro, 'arch': arch, 'version': version,
            'url': url, 'sha256': sha256_of(local_deb),
            'dir': os.path.relpath(dest, ROOT).replace(os.sep, '/'),
            'libc': os.path.relpath(info['libc'], ROOT).replace(os.sep, '/'),
            'loader': (os.path.relpath(info['loader'], ROOT).replace(os.sep, '/')
                       if info['loader'] else None),
        }
        man['entries'] = [e for e in man['entries']
                          if not (e.get('distro') == distro and e.get('arch') == arch)]
        man['entries'].append(entry)
        man['entries'].sort(key=lambda e: (e.get('distro', ''), e.get('arch', '')))
        save_manifest(man)
        have.add((distro, arch))
        print(f'  [ok  ] glibc {version} → {entry["libc"]}'
              + (f'  loader {entry["loader"]}' if entry['loader'] else '  (无 loader)'))
        rows.append(entry)
        ok += 1

    print(f'\n== 抓取完成: 成功 {ok} 跳过 {skipped} 失败 {failed}，清单 {MANIFEST}')
    if failed:
        print('   失败项不影响已有索引；可稍后重跑（已成功的会跳过）')
    if args.rebuild_index or ok:
        rebuild_index()
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
