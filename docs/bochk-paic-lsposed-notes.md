# BOCHK / PAIC LSPosed Compatibility Notes

Date: 2026-05-26

## Scope

Tested packages:

- `com.bochk.app.aos` BOCHK, observed version 7.4.9.
- `com.paic.mo.client` PAIC, observed version 10.0.4.1.

Tested LSPosed module state:

- AnyDebug scoped to BOCHK, PAIC, and `com.zhongan.ibank`.
- JavaHide scoped to BOCHK and PAIC.

## Detection Findings

BOCHK reports native detection through `fiqlohqeo.aH`.

- Report code `16` maps to tracer/self-debug state. It was reproduced through non-zero `TracerPid` exposure and is handled by sanitizing `TracerPid:` reads for app UIDs.
- Report code `03` is tied to LSPosed/AnyDebug Java/ART-visible loader artifacts. The reproducible log surface is:
  - `Unsupported class loader`
  - `Failed to stat file ... com.hhvvg.anydebug ... /base.apk`
- After report `03`, `libbochk_aos.so` opens a BOCHK warning URL and then self-terminates from native code.

Observed BOCHK native termination paths:

- `exit_group(0xffffffff)` from `libbochk_aos.so`.
- `kill(..., SIGABRT)` from `libbochk_aos.so`.
- Earlier diagnostic runs also saw `kill(..., SIGKILL)` against process threads.

Observed BOCHK offsets on the tested build:

- `exit_group` caller PC file offset: `0x62c380`.
- `exit_group` LR file offset: `0x56f6c4`.
- `kill` caller PC file offset: `0x62af9c`.
- `kill` LR file offset: `0x570568`.

PAIC uses `libxloader.so`.

- With AnyDebug scoped, PAIC can self-exit from `libxloader.so`.
- The persistent KPM logs showed PAIC `exit_group(0)` from `libxloader.so`; the old PAIC-specific LR suffix fallback remains as a compatibility guard.

## KPM Changes

`kpms/anti-detect/anti-detect.c` was updated to version `1.2.15`.

Key behavior:

- Hide instrumentation path tokens from regular app UIDs while allowing LSPosed Manager to see its own artifacts.
- Sanitize `TracerPid:` in `read()` output for app UIDs.
- Resolve the userspace caller VMA through `find_vma()` and `d_path()`.
- Classify native self-protection by caller library path, not only package name.
- Apply one path-token based rule to:
  - `libxloader.so`
  - `libbochk_aos.so`
- Bypass self-protect native termination syscalls:
  - `exit`
  - `exit_group`
  - `kill`
  - `tkill`
  - `tgkill`
  - `rt_sigqueueinfo`
  - `rt_tgsigqueueinfo`
  - `pidfd_send_signal`

The implementation intentionally treats the loader library path as the signal. This is broader than a PAIC-only or BOCHK-only package check, but still narrower than blocking all app exits or all fatal signals.

## JavaHide Changes

`java-hide-lsposed` is a diagnostic LSPosed module used to reduce Java/ART-visible hook artifacts in selected target apps.

Current targets:

- `com.bochk.app.aos`
- `com.paic.mo.client`

Key behavior:

- Filters stack traces containing Xposed/LSPosed/AnyDebug/Yuki/Epic/Zygisk tokens.
- Hides selected hook classes from `Class.forName()` and `ClassLoader.loadClass()`.
- Sanitizes common `ClassLoader`, `DexPathList`, and `DexFile` string/name surfaces.
- Installs a clean `PathClassLoader` before `Application.attach`.
- Suppresses BOCHK native reports `03` and `16` through `fiqlohqeo.aH`.
- Blocks BOCHK warning URL launches to `bochk.com`.

The broad Java-layer termination hooks added during diagnosis were removed. The reproduced termination happens in native syscalls, so blocking `System.exit`, `Runtime.halt`, or `android.os.Process.killProcess` was unnecessary and too broad.

LSPosed may warn that JavaHide is a low-quality or legacy module because it uses the legacy Xposed module surface (`assets/xposed_init` and `XposedBridge`) and has no polished Manager UI or modern LSPosed metadata. That warning is about module packaging/API style, not the specific BOCHK/PAIC detection finding. A production-quality replacement should use the modern LSPosed API/metadata and avoid direct DB manipulation for scope changes.

## Device Deployment Notes

Manual `kpatch kpm load ...` is not persistent on this device.

KPatch-Next persists modules by loading:

```text
/data/adb/kp-next/kpm/*.kpm
```

The active boot script is:

```text
/data/adb/modules/KPatch-Next/service.sh
```

Therefore a tested KPM must be copied to:

```text
/data/adb/kp-next/kpm/anti-detect.kpm
```

Replacing only `/data/local/tmp/anti-detect.kpm` or only running `kpatch kpm load` affects the current boot session, but it will revert after reboot.

The KPatch-Next service currently loads KPMs without module arguments, so `anti-detect` will load after reboot without the supercall guard argument unless the service is extended to pass one. The syscall hooks do not depend on that argument.

## LSPosed DB Handling

Do not copy only `modules_config.db` while LSPosed is using WAL mode.

Unsafe pattern:

```text
cp modules_config.db ...
sqlite3 modules_config.db ...
cp modules_config.db ...
```

This can produce a DB that opens before reboot but is corrupt once LSPosed restarts.

Safer options:

- Prefer LSPosed Manager or LSPosed-supported APIs for module state/scope changes.
- If offline repair is necessary, copy `modules_config.db`, `modules_config.db-wal`, and `modules_config.db-shm` together.
- Run `PRAGMA integrity_check` before deploying.
- Checkpoint and convert to a single DB file before pushing back:

```sql
PRAGMA wal_checkpoint(FULL);
PRAGMA journal_mode=DELETE;
VACUUM;
PRAGMA integrity_check;
```

The 2026-05-26 reboot failure was caused by a corrupted `/data/adb/lspd/config/modules_config.db`. The daemon crashed while opening it with:

```text
SQLiteDatabaseCorruptException: database disk image is malformed
```

The repair path used the intact backup from:

```text
/data/adb/lspd/config_backup/codex-20260526-015625/
```

Then it updated the installed JavaHide APK path and inserted JavaHide scopes for BOCHK and PAIC.

## Verification

Post-fix checks used:

```sh
kpatch kpm list
dmesg | grep anti-detect
pidof com.bochk.app.aos
pidof com.paic.mo.client
dumpsys activity activities
sqlite3 modules_config.db 'PRAGMA integrity_check;'
```

Expected KPM evidence for `1.2.15`:

```text
anti-detect: self-protect caller path detection enabled
anti-detect: 17 hooks installed
anti-detect: bypass self-protect exit ...
anti-detect: bypass self-protect kill ...
```

Expected app behavior:

- BOCHK remains alive with AnyDebug scoped; JavaHide logs `suppress native report 03` and blocks the BOCHK warning URL.
- PAIC remains alive with AnyDebug scoped and reaches `MainActivity`; kernel logs show `self-protect exit` bypass from `libxloader.so`.
