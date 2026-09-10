# 断网 PWN 作战手册（离线能力与边界）

这份文档回答一个问题：**没有网络时，这套框架能做什么、不能做什么、怎么用**。
所有能力都以本地文件为准，除 `fetchlibc` 之外没有任何步骤需要联网。

## 1. 离线 libc：从"云 API"换成"本地索引"

以前唯一的 libc 识别途径是 `libcsearcher 1.1.5`，而它其实是 libc.rip 的云 API 客户端
（`requests.post('https://libc.rip/api/find')`），本机没有本地库 —— 断网即失效。
现在改成 `pwn_solver/libc_db.py`：扫描磁盘上的 libc，建符号索引，靠**泄露地址的低 12 位**
（页内偏移与 ASLR 基址无关）筛候选，再用第二个符号收敛。

```bash
# 看索引现状（离线）
python3 pwnsolver.py libcdb list --verbose

# 用泄露反查是哪个 libc（离线，不需要任何网络）
python3 pwnsolver.py libcdb match --leak puts=0x7f1234567890 --leak system=0x7f1234500000

# 扫描新目录 / 重建（离线）
python3 pwnsolver.py libcdb build --dir /path/to/more/libcs

# 唯一的联网步骤：预抓常用版本（2.23/2.27/2.31/2.35/2.39 + Debian，含 i386）
python3 pwnsolver.py fetchlibc --arch amd64 --arch i386
```

求解时的 libc 优先级：**同目录附件 → 上级目录附件 → 本地索引（有泄露才用）→ 系统 libc 兜底**。
最后一种会在日志里标 `⚠ 系统兜底`，生成的 exploit 也会提醒：本地自测可以，**打远程必须换靶机 libc**。

生成的 exploit 会打印 `[leak] puts=0x7f...` 这样的结构化泄露行；求解器解析到之后，会用本地
索引把 libc 换正确并重建 gadget，再重跑一次 —— 这条闭环就是断网下识别未知 libc 的路径。

## 2. 判定可信度：哪些 ✅ 是真的

判定口径统一在 `pwn_solver/verify.py`，两条线共用：

- **强成功**：`PWNED_OK` 或 `uid=`（真的执行了命令）；
- **弱成功**：命中 `flag{...}` 这类内容；
- **否决**：有崩溃证据或非零退出码时，即使出现成功字样也判失败。

两个曾经造成误判的坑已经修掉：

1. `pwn` 这个子串曾被当成 shell 提示符 —— 而工作目录里到处是 `cache/ciscn_dl/pwn2024/...`，
   于是输出里出现自身路径就会被判"疑似拿到 shell"（假阳），然后空转 12 次。现在提示符只认
   `$ ` / `# ` / `>>> `，并且走**交互式复验**（发 `echo PWNED_OK; id; cat flag*` 去证实）。
2. 非交互执行（`subprocess.run` 不给 stdin）时，Go/Rust 预读或非 tty shell 会被判失败（假阴）。
   现在这类情况会自动改用带 stdin 的方式复验一次，并修掉了"recv 暂时没数据就当作 EOF"的提前退出。

## 3. 题型能力（当前真实边界）

| 题型 | 状态 | 说明 |
|---|---|---|
| ret2win / ret2libc / rop / one_gadget / canary(64位) | ✅ 能自动打通 | 本地自测集实测通过 |
| orange_cat_diary（2.23 House of Orange） | ✅ 能打通 | 需给配对 `-l libc-2.23.so -d ld-2.23.so` |
| GoScanner 栈溢出（如 CISCN2024 gostack） | ⚠ 已接通分派 | 之前模板根本不可达；现在会分派并修了预读判定 |
| 堆题（UAF/tcache/off-by-one/unsorted） | ⚠ 识别+诊断，自动利用有限 | 见下 |
| 格式化字符串 | ✅ 能打通（全局判断变量写入） | 见下；GOT 覆盖路线需 libc 基址 |
| heap+seccomp / FSOP | ❌ 只给结构化诊断 | 需要 House of Apple 类链 |

### 堆题：不再假装打过了

以前堆题会被 `one_gadget`/`ret2libc` 覆盖，生成的是**栈利用脚本**，日志里却像"尝试过堆利用" ——
还可能把栈模板的偶然成功当成堆题解出。现在：

- `heap` 等专门题型一旦高置信度锁定，通用栈方法不许覆盖；
- `pwn_solver/heap_diagnose.py` 会解析菜单协议（选项号 + 语义）、free/calloc/scanf 计数、
  指针数组、libc 版本，按版本给出该打哪儿（`__free_hook` / tcache 结构 / `_IO_2_1_stdout_`+FSOP）
  与泄露顺序，落盘 `pwnsolver_evidence/<bin>.heap.md`；
- 能自动打的情形（非 PIE + `win` 符号 + 菜单可驱动 + **create 没有在拷贝后重置函数指针**）
  才真的生成利用脚本：free 后重写函数指针，指针偏移用有限枚举确定；
- 不能自动打时**只输出诊断与菜单驱动骨架**，不输出栈模板。

`create` 是否"先拷贝、后把函数指针写回默认值"由 `create_resets_funcptr()` 反汇编判定 ——
这类题改指针路线根本不成立，必须走 double-free/tcache。判错的代价是白跑一轮，所以宁可判不可行。

### 格式化字符串：已打通（自算参数位的写入器）

`pwn_solver/fmtwriter.py` 自己算参数位做 `%hhn` 分块写，**不用** pwntools 的
`fmtstr_payload` —— 实测 `challenges/fmtstr` 用 `%6$p` 能确认缓冲区开头就是第 6 个参数，
而 `fmtstr_payload(6, {...})` 生成的是 `%13$hn/%14$hn`（地址实际落在第 9/10 个），所以
写不进去。写入器按"目标字节值升序 + 累计打印量"排列，并把地址槽补齐到 8 字节对齐；
它用 `inspect.getsource()` 内联进生成的脚本，避免"实现改了、生成脚本还是旧版"。

一个同样重要的细节：**先读输出再谈交互**。改写成功后 `win()` 会直接把 flag 打出来，
如果一上来就发 `echo PWNED_OK` 探测，flag 输出会先被读走、判定只看 `PWNED_OK/uid=`，
就会出现"明明打进去了却报没打通"。

实测：`challenges/fmtstr` 由求解器判 `★ ✅ 解题成功! (方法: format_string)`；
32 位（`bit=32`，4 字节地址槽）的布局同样有单元测试覆盖。

## 4. 可移植性

- 仓库按 LF 入库（`.gitattributes`），并提供 `scripts/normalize_eol.py --fix` 修工作树里
  已经被写坏的 CRLF。以前 `scripts/pwn-x86*` 是 CRLF，Linux 下直接 `env: bash\r` 无法执行。
- 生成脚本用**能 import pwn 的解释器**（`utils.exploit_python()`），不再写死 `python3` ——
  AWDP 那种 `.venv-linux` 约定不会把 pwntools 装进 PATH。
- Windows 侧没有 gdb/one_gadget/docker，pwn 一律进 WSL；`.venv-linux` 里工具齐全。

## 5. 验收与复跑

```bash
# 离线基准（语料根在仓库内，不再用 /tmp）
python3 scripts/offline_bench.py --tag after                     # 默认 4 个语料根，80 个目标
python3 scripts/offline_bench.py --tag t1 --roots challenges     # 只跑本地自测集
python3 scripts/offline_bench.py --count-only                    # 只统计目标数

# 单题
python3 pwnsolver.py solve ./vuln -l ./libc.so.6 -d ./ld-linux-x86-64.so.2
```

结果写 `reports/offline_<tag>.{json,md}`，其中 `suspect_heap_stack_mismatch` 标记
"堆题被栈方法判成功"这类需要人工复核的假阳。

## 6. 还没做的（诚实清单）

1. 格式串的 GOT 覆盖路线（需要先泄露 libc 基址）与 blind fmtstr；
2. 通用堆利用引擎：目前只有"函数指针劫持"这一条自动路线，tcache/unsorted/House of Orange
   之外仍靠手写；`heap_exploit.py` 里的原语仍未被引擎真正调用；
3. heap+seccomp 的 FSOP/House of Apple 链；
4. 32 位 i386 栈链（语料里 35 个 32 位目标目前只走通用路径）；
5. `libcs/` 里 debian9(2.24)/debian10(2.28) 在现网 pool 已下架，需要从 archive 手工补。
