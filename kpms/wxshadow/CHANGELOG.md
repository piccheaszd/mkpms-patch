# WXSHADOW Changelog

## [1.1.3] - 2026-06-18

### Added

- Added `follow_page_mask` as a required GUP hiding fallback when `follow_page_pte` is unavailable. Module load now refuses to continue if neither GUP symbol can be hooked, avoiding a partially hidden state where `/proc/pid/mem`, `process_vm_readv`, or `ptrace` can observe shadow PFNs.
- Added optional `handle_mm_fault` hook coverage for IOPF/SVA/device fault read paths. Read faults switch to the original mapping, write faults trigger logical release, and instruction faults resume the shadow mapping when needed.
- Added runtime detection for both 3-argument and 4-argument `kallsyms_on_each_symbol` callback styles, with `kallsyms_lookup_name` fallback when callback iteration is unavailable.

### Changed

- GUP hook teardown now records whether `follow_page_pte` or `follow_page_mask` was actually installed and only unwraps that active path.

## [1.1.2] - 2026-05-18

### Fixed

- Made AUTO TLB flushing robust on vendor kernels by backstopping exported kernel flush helpers with broadcast `TLBI VAALE1IS` after wxshadow PTE switches. This avoids stale user execute translations after hidden patch activation.
- Added a `DSB ISHST` barrier before direct TLBI invalidation so PTE writes are visible before stale translations are dropped.

## [1.1.1] - 2026-05-15

### Fixed

- Fixed user page-table walking on Android 14 / Linux 6.1 devices by deriving page-table level information from `TCR_EL1.T0*` for TTBR0/user `mm->pgd` walks. The previous TTBR1-derived calculation could make every executable user mapping fail with `get_user_pte failed`.
- Avoided relying on `vm_area_struct.vm_mm` offset during PTE transitions. Shadow pages now keep the owning `mm` and PTE switch paths prefer `page->mm`, with `vma_mm(vma)` only as fallback.
- Retried VMA offset discovery once from the first wxshadow `prctl` caller context, so module-load-time scans from non-user contexts do not permanently poison the fallback offset.

### Changed

- Runtime `pr_info` logs are now routed through `wx_info()` and compiled out by default. Build with `-DWXSHADOW_VERBOSE` to restore detailed state transition logging.

## [1.1.0] - 2026-01-14

### Added - 新增自定义 Hook 接口

新增三个高级接口，允许用户自定义 hook 代码，而不是使用固定的 BRK 指令：

#### 1. READ 接口 (`PR_WXSHADOW_READ = 0x57580006`)
- 创建 shadow page 并复制原始内容
- 设置权限为 `rw-` (可读写，不可执行)
- 允许用户态程序通过 `/proc/pid/mem` 等方式写入自定义 hook 代码

#### 2. ACTIVE 接口 (`PR_WXSHADOW_ACTIVE = 0x57580007`)
- 将 shadow page 权限从 `rw-` 切换到 `--x` (只可执行)
- 刷新指令缓存，激活 hook
- 实现 hook 隐藏效果

#### 3. RELEASE 接口 (`PR_WXSHADOW_RELEASE = 0x57580008`)
- 恢复原始页面映射 (`r-x`)
- 释放 shadow page 内存
- 清理页面结构

### Changed - 修改

#### 页面状态
- 新增 `WX_STATE_SHADOW_RW` 状态，表示 shadow page 处于可写状态

#### 客户端
- 新增 `--read` 选项：准备 shadow page (rw-)
- 新增 `--active` 选项：激活 shadow page (--x)
- 新增 `--release` 选项：释放 shadow page

### Technical Details - 技术细节

#### 权限管理
- `rw-`: `PTE_USER | PTE_UXN` (可读写，不可执行)
- `--x`: `prot=0` (只可执行)
- `r-x`: `PTE_USER | PTE_RDONLY` (可读可执行)

#### 状态检查
- ACTIVE 只能在 `WX_STATE_SHADOW_RW` 状态下调用
- 自动处理 TLB 和指令缓存刷新

#### 内存管理
- 使用与 SET_BP 相同的页面分配和释放机制
- 支持页面复用（如果 page 已存在，直接切换权限）

### Usage - 使用方法

```bash
# 1. 准备 shadow page (rw-)
./wxshadow_client -p <pid> -a 0x7b5c001234 --read

# 2. 写入自定义 hook 代码 (通过 /proc/pid/mem 或其他方式)

# 3. 激活 shadow (--x)
./wxshadow_client -p <pid> -a 0x7b5c001234 --active

# 4. 释放 shadow
./wxshadow_client -p <pid> -a 0x7b5c001234 --release
```

### Files Modified - 修改的文件

- `wxshadow.h` - 添加新的 prctl 常量和状态
- `wxshadow_bp.c` - 实现三个新函数和 prctl 处理逻辑
- `wxshadow_internal.h` - 添加函数声明
- `wxshadow.c` - 更新初始化日志信息
- `wxshadow_client.c` - 添加客户端支持
- `CLAUDE.md` - 更新文档

### Documentation - 文档

- 新增 `README_NEW_INTERFACES.md` - 详细使用说明
- 更新 `CLAUDE.md` - 添加新接口说明

---

## [1.0.0] - Initial Release

### Features
- BRK 断点隐藏机制
- Shadow page 技术
- 寄存器修改支持
- 读取隐藏 (read fault handling)
- 单步执行支持
- 无锁页表操作
- TLB flush 多种方案支持
