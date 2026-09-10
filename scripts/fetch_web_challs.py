#!/usr/bin/env python3
"""批量下载 web CTF 题目源码(以 sajjadium/ctf-archives 为主源)。

用法:
  # 干跑: 只枚举不下载, 估算规模
  python3 scripts/fetch_web_challs.py --dry-run

  # 下载最近 4 年、每年最多 8 个赛事的 web 题目源码 zip, 并解包
  python3 scripts/fetch_web_challs.py --years 2022-2025 --per-event 8

  # 只下载指定赛事
  python3 scripts/fetch_web_challs.py --events 0CTF,ASIS --years 2023-2025

产物:
  external_challs/web_challs/<Event>/<Year>/<Challenge>/   解包后的源码
  external_challs/web_challs/_zips/...                     原始 zip(可 --keep-zips, 默认保留下载)
  external_challs/web_challs/manifest.json                 下载清单(题目名/年份/zip url/文件数/是否含 docker)

断点续传: 已解包且 manifest 标记 done 的目录会跳过; 重复执行安全。
"""
import argparse
import http.client
import io
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / 'external_challs' / 'web_challs'
API = 'https://api.github.com/repos/sajjadium/ctf-archives'
RAW_ZIP_RE = re.compile(r'\.zip$', re.I)
UA = {'User-Agent': 'PwnSolver-webfetch/1.0', 'Accept': 'application/vnd.github+json'}
# 支持 GITHUB_TOKEN / GH_TOKEN 环境变量避免匿名 60 次/小时限流
for _tok_env in ('GITHUB_TOKEN', 'GH_TOKEN'):
    if os.environ.get(_tok_env):
        UA['Authorization'] = f'Bearer {os.environ[_tok_env]}'
        break

DOCKER_HINTS = ('docker-compose.yml', 'docker-compose.yaml', 'Dockerfile', 'dockerfile')


def gh_api(path: str, retries: int = 3):
    """GET GitHub API JSON, 带简单重试与限流等待。"""
    url = f'{API}{path}'
    for attempt in range(retries):
        req = urllib.request.Request(url, headers=UA)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.loads(resp.read().decode('utf-8'))
        except http.client.IncompleteRead as e:
            # gzip 流偶发读不全; 已读到的部分往往完整, 尝试直接解析
            try:
                return json.loads(e.partial.decode('utf-8'))
            except Exception:
                if attempt == retries - 1:
                    raise
                time.sleep(2)
        except urllib.error.HTTPError as e:
            if e.code == 403 and 'rate limit' in (e.read() or b'').decode('utf-8', 'ignore').lower():
                wait = 60 * (attempt + 1)
                print(f'    [rate-limit] 等待 {wait}s ...', flush=True)
                time.sleep(wait)
                continue
            if e.code == 404:
                return None
            if attempt == retries - 1:
                raise
            time.sleep(3 * (attempt + 1))
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries - 1:
                raise
            time.sleep(3 * (attempt + 1))
    return None


def gh_download(url: str, retries: int = 3) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': UA['User-Agent']})
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                return resp.read()
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(3 * (attempt + 1))
    return b''


def list_dir(path: str):
    data = gh_api(path)
    if not isinstance(data, list):
        return []
    return data


def year_in_range(name: str, lo: int, hi: int) -> bool:
    return name.isdigit() and lo <= int(name) <= hi


def safe_name(name: str) -> str:
    """目录名清洗: 去掉 Windows 非法字符。"""
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name).strip('. ') or 'unnamed'


def challenge_has_docker(files) -> bool:
    names = {f.lower() for f in files}
    return any(h.lower() in names for h in DOCKER_HINTS) or any(
        n.startswith('docker-compose') for n in names)


def extract_zip(data: bytes, dest_dir: Path) -> list:
    """解包 zip 到 dest_dir, 返回顶层相对路径列表。带 zip-slip 防护。"""
    written = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            name = info.filename
            # 跳过 macOS 元数据
            if name.startswith('__MACOSX/') or name.endswith('.DS_Store'):
                continue
            target = (dest_dir / name).resolve()
            if not str(target).startswith(str(dest_dir.resolve())):
                continue  # zip-slip
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, 'wb') as out:
                out.write(src.read())
            written.append(str(target.relative_to(dest_dir)))
    return written


def fetch_one(event: str, year: str, chall: dict, dest_root: Path,
              dry_run: bool, manifest: dict):
    """下载并解包单个题目。"""
    cname = chall['name']
    key = f'{event}/{year}/{cname}'
    cdir = dest_root / safe_name(event) / year / safe_name(cname)
    if key in manifest and manifest[key].get('done'):
        return 'skip-done'

    files = list_dir(f'/contents/ctfs/{event}/{year}/web/{cname}')
    zips = [f for f in files if RAW_ZIP_RE.search(f.get('name', ''))]
    if not zips:
        return 'no-zip'
    z = zips[0]
    size = z.get('size', 0)
    if size > 80 * 1024 * 1024:
        return f'too-big({size // 1024 // 1024}MB)'
    if dry_run:
        return f'dry({size // 1024}KB)'

    cdir.mkdir(parents=True, exist_ok=True)
    try:
        data = gh_download(z['download_url'])
    except Exception as e:
        return f'dl-fail:{e}'
    try:
        written = extract_zip(data, cdir)
    except zipfile.BadZipFile:
        return 'bad-zip'

    manifest[key] = {
        'event': event, 'year': year, 'challenge': cname,
        'zip_url': z['download_url'], 'zip_size': size,
        'files': len(written),
        'has_docker': challenge_has_docker([Path(w).name for w in written]),
        'path': str(cdir.relative_to(ROOT)),
        'done': True,
    }
    return f'ok({len(written)} files, docker={manifest[key]["has_docker"]})'


def main():
    ap = argparse.ArgumentParser(description='批量下载 web CTF 题目源码')
    ap.add_argument('--years', default='2022-2025', help='年份范围, 如 2023-2025 或 2024')
    ap.add_argument('--events', default='', help='只处理指定赛事(逗号分隔), 空=全部')
    ap.add_argument('--per-event', type=int, default=8, help='每个赛事每年最多下载的题目数')
    ap.add_argument('--max-events', type=int, default=0, help='最多处理多少个赛事(0=不限)')
    ap.add_argument('--dry-run', action='store_true', help='只枚举不下载')
    ap.add_argument('--dest', default=str(DEST), help='下载目标目录')
    args = ap.parse_args()

    if '-' in args.years:
        y_lo, y_hi = [int(x) for x in args.years.split('-', 1)]
    else:
        y_lo = y_hi = int(args.years)

    dest_root = Path(args.dest).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)
    manifest_path = dest_root / 'manifest.json'
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        except Exception:
            manifest = {}

    only_events = {e.strip() for e in args.events.split(',') if e.strip()}

    print(f'[*] 目标目录: {dest_root}')
    print(f'[*] 年份范围: {y_lo}-{y_hi}, 每赛事每年最多 {args.per_event} 题')

    events = [d['name'] for d in list_dir('/contents/ctfs') if d.get('type') == 'dir']
    if only_events:
        events = [e for e in events if e in only_events]
    events.sort()
    if args.max_events:
        events = events[:args.max_events]
    print(f'[*] 赛事总数: {len(events)}')

    stats = {'ok': 0, 'skip-done': 0, 'no-zip': 0, 'fail': 0, 'dry': 0}
    processed_events = 0
    for ei, event in enumerate(events, 1):
        years = [d['name'] for d in list_dir(f'/contents/ctfs/{event}')
                 if d.get('type') == 'dir' and year_in_range(d['name'], y_lo, y_hi)]
        if not years:
            continue
        processed_events += 1
        for year in sorted(years):
            web = [d for d in list_dir(f'/contents/ctfs/{event}/{year}/web')
                   if d.get('type') == 'dir']
            if not web:
                continue
            print(f'[{ei}/{len(events)}] {event} {year}: {len(web)} web 题', flush=True)
            for chall in web[:args.per_event]:
                try:
                    status = fetch_one(event, year, chall, dest_root,
                                       args.dry_run, manifest)
                except Exception as e:
                    status = f'error:{e}'
                print(f'    {chall["name"]}: {status}', flush=True)
                if status.startswith('ok'):
                    stats['ok'] += 1
                elif status.startswith('dry'):
                    stats['dry'] += 1
                elif status == 'skip-done':
                    stats['skip-done'] += 1
                elif status == 'no-zip':
                    stats['no-zip'] += 1
                else:
                    stats['fail'] += 1
        # 每赛事落盘一次 manifest, 断点续传
        if not args.dry_run:
            manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                                     encoding='utf-8')

    if not args.dry_run:
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=1),
                                 encoding='utf-8')
    print(f'[*] 完成: {stats}')
    print(f'[*] manifest: {manifest_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
