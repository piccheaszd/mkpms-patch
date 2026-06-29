# mkpms

KernelPatch / KPatch-Next KPM 模块工作区，包含 wxshadow、recompile、anti-detect、hide-maps、demo 模块，以及少量用户态辅助工具。

`kernel` 是指向 `.kp/kernel` 的符号链接，来自 `.kp` submodule，主要提供 KernelPatch 头文件、KPM ABI 和编译期参考。

## 目录

| 路径 | 说明 |
| --- | --- |
| `.kp/` | KernelPatch submodule |
| `kpms/wxshadow/` | W^X Shadow 隐藏断点 / shadow patch KPM |
| `kpms/recompile/` | rustFrida `Hook.RECOMP` 使用的代码页重编译 / 执行重定向 KPM |
| `kpms/anti-detect/` | 隐藏模拟器、KernelPatch、Frida/rustFrida、LSPosed 等检测痕迹的 KPM |
| `kpms/hide-maps/` | 过滤 `/proc/<pid>/maps` 中的插桩辅助 VMA |
| `kpms/demo-*` | KernelPatch hello / inline hook / syscall hook 示例 |
| `tools/kpatch/` | 最小 KernelPatch 用户态管理 CLI |
| `java-hide-lsposed/` | 可选 LSPosed Java 层隐藏模块 |
| `docs/` | 目标 App 分析与复测记录 |

## 环境要求

- CMake + Make 或 Ninja
- `aarch64-linux-gnu-gcc`：推荐用于 KPM 本体构建
- Android NDK：用于构建需要推到设备执行的 `wxshadow_client` / `kpatch`
- Java 17、Android build-tools (`aapt`, `zipalign`, `apksigner`)：仅构建 `java-hide-lsposed` APK 时需要

首次 clone 后拉取 KernelPatch submodule：

```bash
git submodule update --init --recursive
```

## 构建

### KPM 模块

```bash
cmake -S . -B build-arm64 -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc
cmake --build build-arm64
```

常用单目标：

```bash
cmake --build build-arm64 --target wxshadow.kpm
cmake --build build-arm64 --target anti-detect.kpm
cmake --build build-arm64 --target hide-maps.kpm
cmake --build build-arm64 --target recompile.kpm
```

输出位置：

```text
build-arm64/kpms/wxshadow/wxshadow.kpm
build-arm64/kpms/anti-detect/anti-detect.kpm
build-arm64/kpms/hide-maps/hide-maps.kpm
build-arm64/kpms/recompile/recompile.kpm
```

### Android 用户态工具

`wxshadow_client` 直接在 Android 设备上执行时，建议用 NDK 单独构建 bionic 版：

```bash
export ANDROID_NDK=/path/to/android-ndk
cmake -S . -B build-ndk \
  -DCMAKE_C_COMPILER=$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang \
  -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY
cmake --build build-ndk --target wxshadow_client
```

不要对 Android helper 强制 `-static`。部分系统会因为静态 arm64 可执行文件的 `PT_TLS` 对齐低于 Bionic 要求而启动失败。

`tools/kpatch` 没有挂到顶层 CMake，可直接用 NDK 编译：

```bash
mkdir -p build-ndk/tools/kpatch
$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android23-clang \
  -O2 -s tools/kpatch/kpatch.c -o build-ndk/tools/kpatch/kpatch
```

### LSPosed APK

```bash
cd java-hide-lsposed
./build.sh
```

脚本会按需下载 R8，并输出 `java-hide-lsposed/build/java-hide-lsposed.apk`。如果系统路径里没有 Android framework 资源，可通过 `FRAMEWORK_RES=/path/to/framework-res.apk ./build.sh` 指定。

## 部署

以下命令需要已授权测试设备和 root 权限。旧 KernelPatch CLI 需要 superkey；设备侧若使用
KPatch-Next 模块自带的 `kpatch` / `kpatch-next` CLI，则 KPM 管理命令可以不带
superkey。

```bash
adb push build-arm64/kpms/wxshadow/wxshadow.kpm /data/local/tmp/
adb push build-ndk/kpms/wxshadow/wxshadow_client /data/local/tmp/
adb push build-ndk/tools/kpatch/kpatch /data/local/tmp/
adb shell su -c 'chmod 755 /data/local/tmp/wxshadow_client /data/local/tmp/kpatch'

adb shell su -c '/data/local/tmp/kpatch <superkey> kpm load /data/local/tmp/wxshadow.kpm'
adb shell su -c 'dmesg | grep wxshadow'
adb shell su -c '/data/local/tmp/kpatch <superkey> kpm unload wxshadow'
```

`anti-detect` 可在 load 时传入 superkey 参数，用于启用 supercall guard；不传则跳过该 guard：

```bash
adb push build-arm64/kpms/anti-detect/anti-detect.kpm /data/local/tmp/
adb shell su -c '/data/local/tmp/kpatch <superkey> kpm load /data/local/tmp/anti-detect.kpm <superkey>'
adb shell su -c '/data/local/tmp/kpatch <superkey> kpm unload anti-detect'
```

若设备侧使用 `kpatch-next` 管理 KPM，可以不带 superkey 直接重载模块；此时 `anti-detect`
会跳过 supercall guard，其它 syscall/procfs profile 功能仍可用。可先确认临时 CLI
确实来自 KPatch-Next 模块：

```bash
adb shell "su -c 'sha256sum /data/local/tmp/kpatch-next /data/adb/modules/KPatch-Next/bin/kpatch'"
adb shell "su -c '/data/local/tmp/kpatch-next kpm info anti-detect'"
```

`kpatch-next kpm load/unload/info` 只负责 KPM 管理；rustFrida 运行时的
`hide-maps` range 注册、`recompile` mapping 注册和 `anti-detect` profile 注册通过
已加载 KPM 暴露的 `prctl` ABI 完成，不会每次 hook 都调用 KPatch-Next CLI。

```bash
adb shell su -c '/data/local/tmp/kpatch-next kpm unload anti-detect'
adb shell su -c '/data/local/tmp/kpatch-next kpm load /data/local/tmp/anti-detect.kpm'
```

`recompile` 提供 rustFrida `Hook.RECOMP` 的内核侧 ABI。按需加载后，rustFrida 通过
`prctl(PR_RECOMPILE_REGISTER, 0, orig_page, recomp_page, 0)` 注册原始代码页和重编译页：

```bash
adb push build-arm64/kpms/recompile/recompile.kpm /data/local/tmp/
adb shell su -c '/data/local/tmp/kpatch <superkey> kpm load /data/local/tmp/recompile.kpm'
adb shell su -c 'dmesg | grep recompile'
adb shell su -c '/data/local/tmp/kpatch <superkey> kpm unload recompile'
```

部分设备上运行期 unload / reload KPM 不是可靠测试路径；若 KPatch-Next 管理接口在卸载后异常，优先通过重启或 boot-load 流程复测。当前 Android 14 / Linux 6.1.75 BOCHK 测试机上，热卸载 `anti-detect` 后曾出现管理 supercall 状态异常，后续热加载新旧 KPM 都不可靠；更新 `anti-detect` 这类常驻 syscall hook 模块时，优先把验证过的 `.kpm` 放入 `/data/adb/kp-next/kpm/` 持久目录后重启验证，而不是在目标测试前反复 hot unload/load。

## wxshadow 快速入口

wxshadow 通过 hook `prctl` 暴露用户态接口，支持隐藏断点、寄存器修改、shadow patch、release 和 TLB flush mode。完整说明见 [kpms/wxshadow/README.md](kpms/wxshadow/README.md)。

```bash
# 查看目标进程可执行 maps
adb shell su -c '/data/local/tmp/wxshadow_client -p <pid> -m'

# 设置隐藏断点，并在命中时修改寄存器
adb shell su -c '/data/local/tmp/wxshadow_client -p <pid> -a 0x7b5c001234 -r x0=0'

# 按 so + offset 设置
adb shell su -c '/data/local/tmp/wxshadow_client -p <pid> -b libc.so -o 0x12345'

# shadow patch: NOP
adb shell su -c '/data/local/tmp/wxshadow_client -p <pid> -a 0x7b5c001234 --patch d503201f'

# 释放指定 shadow 或所有 shadow
adb shell su -c '/data/local/tmp/wxshadow_client -p <pid> -a 0x7b5c001234 --release'
adb shell su -c '/data/local/tmp/wxshadow_client -p <pid> --release'

# 查看/设置 TLB flush 模式
adb shell su -c '/data/local/tmp/wxshadow_client --get-tlb-mode'
adb shell su -c '/data/local/tmp/wxshadow_client --tlb-mode broadcast'
```

关键限制：

- 仅支持 ARM64。
- `PR_WXSHADOW_PATCH` 单次不能跨页。
- 每页最多 128 个断点和 128 个 patch。
- 每个断点最多 4 个寄存器修改。
- 自读代码页无法同时读取和执行同一 shadow 状态，典型表现是对 CRC/self-check 代码本身下断点可能卡住。

## recompile / rustFrida Hook.RECOMP

`recompile.kpm` 用于 rustFrida `Hook.RECOMP`。RF 在用户态复制并改写目标代码页到新的 recompiled page，KPM 在内核侧把原始页改为不可执行；当目标执行原始页触发指令异常时，KPM 将 PC 重定向到对应的 recompiled page。

它主要解决代码页自校验和 inline patch 可见性问题：

- 原始代码页内容保持不变，hook patch 落在 recompiled page / trampoline 上。
- 注册接口是 `PR_RECOMPILE_REGISTER`，释放接口是 `PR_RECOMPILE_RELEASE`。
- KPM 会跟踪 per-mm 映射，在 `exit_mmap`、fork / copy process 等路径做清理或修复。
- 对 signal frame、regset、perf、single-step 等 PC 导出路径做 best-effort 回写，把 recompiled PC 暴露为原始 PC。

关键限制：

- 仅支持 ARM64 代码页级重定向，且原始页、重编译页必须页对齐。
- 依赖目标内核导出的 kallsyms。缺少 `do_mem_abort` / `do_page_fault`、`exit_mmap` 等关键符号会导致加载失败；缺少 signal、regset、perf、single-step 等可选符号时，只会退化对应的 PC 导出隐藏面。
- 它不隐藏 agent、socket fd、线程名、`/proc/<pid>/maps` 行或 KernelPatch/KPM 自身痕迹；这些需要和 `hide-maps`、`anti-detect` 以及目标侧专项规则配合。

完整实现和验证说明见 [kpms/recompile/README.md](kpms/recompile/README.md)。

## anti-detect / hide-maps / recompile 职责边界

`anti-detect` 当前用于隐藏常见检测面：

- 文件与路径探测：`stat` / `access` / `readlink` / `getdents64`
- `/proc` 相关路径、fd link、目录项中的 Frida/rustFrida/LSPosed 等 token
- `/proc/<pid>/status` 等读取结果中的 `TracerPid`
- `ptrace(PTRACE_TRACEME)`、`prctl(PR_GET_DUMPABLE)` 等部分自检
- 自保护 loader 触发的 `exit` / `kill` 类路径
- 可选 supercall guard：隐藏错误 superkey 访问

`anti-detect` 1.2.23 起提供 per-mm profile ABI，后续可让目标进程显式注册检测策略。已注册进程优先按 profile flags 处理。1.2.24 起，单独设置 `AD_F_AUDIT_ONLY` 时只注册轻量 profile，不修改 syscall 结果或用户缓冲区；如果同时设置具体检测面 flag，则只统计“本来会被处理”的事件，并在 release / `exit_mmap` 时通过 dmesg 输出计数。1.2.26 起默认启用 profile-only strict：未注册进程不再走旧的 UID/进程名 fallback，只有 root 可通过 `PR_ANTIDETECT_SET_MODE` 临时恢复 legacy fallback。`TracerPid` 处理已改为 fd-aware 并带 per-mm fd cache：只有确认 read fd 指向 `/proc/.../status` 时才扫描并过滤，避免误改普通文件内容，也避免每次 read 都重复 `fget` / `d_path`。

```c
prctl(0x41440001, 0, flags, profile_id, 0); /* PR_ANTIDETECT_REGISTER */
prctl(0x41440002, 0, 0, 0, 0);              /* PR_ANTIDETECT_RELEASE */
prctl(0x41440003, 0, mode, 0, 0);           /* PR_ANTIDETECT_SET_MODE; root only */
prctl(0x41440004, 0, start, size, rule);    /* PR_ANTIDETECT_ADD_SELF_PROTECT_RULE */
```

当前 flags：

- `0x001`：`AD_F_AUDIT_ONLY`
- `0x002`：路径探测
- `0x004`：fd/readlink 目标
- `0x008`：目录枚举
- `0x010`：`/proc/<pid>/status` / `TracerPid`
- `0x020`：`ptrace(PTRACE_TRACEME)`
- `0x040`：`prctl(PR_GET_DUMPABLE)`
- `0x080`：self-protect `exit`
- `0x100`：self-protect `kill`

如果 flags 为 `0`，KPM 默认启用全部检测面；只设置 `AD_F_AUDIT_ONLY` 不再自动扩成全检测面，适合作为 BOCHK 等强对抗目标的轻量注册探针。需要 audit-only + 全检测面时显式传 `0x1ff`。profile 绑定调用进程的 `mm`，模块会在 `exit_mmap` 清理。

active self-protect 规则也绑定当前注册 profile/mm。1.2.26 起 `exit` / `kill` blocking 不再按通用 caller path token 判断，只匹配预注册 exact range；rule flags 可组合：

- `0x001`：匹配 exit
- `0x002`：匹配 kill
- `0x004`：PC 落在 range 内
- `0x008`：LR 落在 range 内

rustFrida loader 会在启用 `AD_F_BLOCK_SELF_EXIT` / `AD_F_BLOCK_SELF_KILL` 时注册 stage-1 RX 和 linker veneer range。没有注册 exact range 的 App 即使打开了 active flags，也不会因为旧的 loader-token 规则被误拦截。

Android 14 / Linux 6.1.75 设备侧复测记录：`anti-detect` 1.2.23 可通过
`kpatch-next` 无 superkey 加载；rustFrida BOCHK pure-spawn 在 agent entry 前注册
audit-only profile 后，KPM 日志显示 `flags=0x1ff`，进程退出时输出
`path=529 tracerpid=37 dumpable=2092 exit=72 kill=1`。这些是审计计数，不代表
audit-only 模式实际改写了 syscall 返回值或用户缓冲区。

但该版本会把 `AD_F_AUDIT_ONLY` 自动扩成全检测面，后续 KPM-enabled
BOCHK `runtime` 复测中出现设备卡死；1.2.24 起改为只有 flags 为 `0`
时才默认全检测面。

`anti-detect` 1.2.24 + `kpm-hide-maps` 1.1.2 后续 BOCHK 复测记录：rustFrida
使用 `RF_ANTIDETECT=1` 注册轻量 profile，KPM 日志保持 `flags=0x1`，进程
退出时 path/link/dir/tracerpid/ptrace/dumpable/exit/kill 计数均为 0。配合
`RF_SKIP_REPL_READY=1` 跳过 host 侧 post-resume `/proc` 轮询后，BOCHK
baseline、`runtime`、`resolve`、`read-maps`、`maps-dump`、`bytes-getpid`
均通过并保持设备响应。

分检测面复测中，`0x11`（status/TracerPid）和 `0x61`
（ptrace/dumpable）通过；`0x181`（self-exit/self-kill）会在 BOCHK
恢复后导致设备 adb offline。根因收窄到 exit/kill audit-only 仍调用 active
self-protect classifier；该 classifier 会在 syscall hook 路径里对 caller
PC/LR 执行 `find_vma` / `d_path` 模块路径解析。1.2.25 起，exit/kill 的
audit-only 分支只做轻量状态/信号计数；1.2.26 起 active blocking 也改为
预注册 exact range，不再做 caller VMA/path 分类。
实机重载 `anti-detect` 1.2.25 后，`0x181` audit-only 复测 RF 返回 0、
adb 保持响应；完整重载 `kpm-hide-maps` 1.1.2 后，stage-1 / veneer range
注册和 `exit_mmap` 清理也正常，`anti-detect` 释放计数为 `exit=3 kill=1`。
非 audit 的 active blocking 应和 audit-only 分开测试。BOCHK `0x180`
active exit/kill 复测中，KPM 命中
`bypass self-protect exit nr=93 status=0 comm=e.process.gapps ... reason=4`，
RF 返回 0 且 adb 保持响应；但目标随后仍进入 `exit_mmap`，说明该分支没有
保住 BOCHK 进程生命周期。1.2.26 后 active blocking 已改为预注册 exact range，不再走通用 caller path token；仍需单独复测它是否能保住 BOCHK 生命周期，因为“不会卡死”和“阻断目标自杀”是两件事。

`hide-maps` 更窄，过滤 `/proc/<pid>/maps` 输出中匹配插桩 token 的行，也支持进程通过 prctl 注册需要隐藏的精确 VMA range。当前默认 token 覆盖 `wwb_`、Frida/rustFrida、`/data/local/tmp/rf`、`/data/local/tmp/rf_`、`/memfd:rust`、`[anon:rust`、LSPosed/Riru/EdXposed/LSPatch/YukiHook/AnyDebug 等常见标识。

`hide-maps` 1.1.2 提供 range ABI，供 rustFrida pure-spawn stage-1 隐藏无名匿名 RX：

```c
prctl(0x484d0001, 0, start, size, 0x1); /* PR_HIDEMAPS_REGISTER, exact range */
prctl(0x484d0002, 0, start, size, 0);   /* PR_HIDEMAPS_RELEASE */
```

KPM 会把 range 绑定到调用进程的 `mm`，只过滤精确匹配的 maps 行，并在 `dup_mmap` fork 路径把 range 传播给 child `mm`。首次命中已注册 range 时会动态校准 `vm_area_struct.vm_mm` 偏移，避免不同 Android 6.1 内核结构布局导致注册成功但 maps 行未隐藏。maps 行 token 扫描在 `seq_file` 当前输出缓冲区上做有界匹配，不在 `show_map_vma` 热路径分配临时内存。这个接口只隐藏 `/proc/<pid>/maps` 展示，不会 `munmap`、改页表权限或隐藏 `/proc/<pid>/mem` / `smaps` / `map_files`。BOCHK 复测中，stage-1 RX 和 linker veneer 每次注册 2 个 exact range；首次命中时 `vm_area_struct.vm_mm` offset 从 `0x40` 动态校准到 `0x10`，`exit_mmap` 正常清理 2 个 range。目标自读 `maps-dump` 未再暴露 RF stage-1 / veneer 行。

三者组合时的典型分工：

- `recompile`：隐藏代码页 patch，本身不负责隐藏新增 VMA。
- `hide-maps`：隐藏 RF agent、recompile/trampoline、WXSHADOW helper 等被命名或路径命中的 maps 行；新版也可隐藏 RF 注册的 stage-1 RX / veneer 精确 range。
- `anti-detect`：隐藏路径、fd symlink、目录枚举、`TracerPid`、`ptrace(PTRACE_TRACEME)`、`PR_GET_DUMPABLE` 和部分自保护退出路径。

仍需按目标复测的检测面：

- `/proc/self/task/*/comm` 或线程列表：RF/QuickJS 不再使用 `wwb-*` 作为 helper 线程名前缀，但当前 `anti-detect` 仍不做通用线程 comm 过滤。
- `/proc/self/fd` 和 socket 行为：stream-agent 避免 agent memfd 常驻，但 agent 通信仍需要 socket fd。
- 未命名匿名 RX VMA：RF agent 段默认命名为 `wwb_so`，会命中 `hide-maps`；pure-spawn stage-1 RX / veneer 由 RF 通过 range ABI 精确注册。其它未命名匿名 RX 不会被全局隐藏，避免误伤 ART/JIT/厂商 runtime。
- 内核侧可见性：KernelPatch/KPM 列表、supercall 行为、hook 后的内核文本或 ftrace/inline-hook 痕迹不属于用户态 maps 检测面。
- 时间侧信道和行为侧信号：异常处理频率、hook 回调耗时、线程调度、GC/Java worker 活动仍可能被强对抗目标利用。

按目标检测面分开加载模块，能减少不必要的全局影响和误伤。

## KPM 开发备注

- `kernel/` / `.kp/` 作为 KernelPatch 框架参考，常规模块开发不要改。
- 新模块放到 `kpms/<name>/`，提供 `CMakeLists.txt` 并调用 `add_kpm_module(<target> <sources...>)`。
- 共享 demo helper 在 `kpms/common/kpm_demo_helpers.h`。
- 顶层 CMake 会自动遍历 `kpms/*` 子目录。

## License

仓库根目录的 [LICENSE](LICENSE) 是 GPL v3。KPM 源文件同时带有 `GPL-2.0-or-later` SPDX 或 `GPL v2` 模块元信息；分发或复用单个模块前请按对应文件头、模块元信息和运行端要求确认许可证约束。

## 免责声明

本项目仅供安全研究、逆向工程学习和授权测试用途。KPM 在内核态运行，加载、卸载或错误 hook 都可能导致设备崩溃、数据损坏或不可启动。使用者应确保在合法授权范围内使用，并自行承担全部风险。
