# recompile.kpm

`recompile.kpm` is the KPatch-Next module used by rustFrida `Hook.RECOMP`.

This directory now contains two things:

- `recompile.c`: clean-room source reimplementation of the core RECOMP ABI.
- `recompile.kpm`: retained prebuilt patched artifact from the upstream release,
  kept as the currently device-validated reference binary.

## Source Status

The source implementation is a clean-room reimplementation aligned to the
validated release binary's observed RECOMP behavior. It implements:

- `prctl(PR_RECOMPILE_REGISTER, 0, orig_page, recomp_page, 0)`.
- `prctl(PR_RECOMPILE_RELEASE, 0, orig_page, 0, 0)`.
- `pid != 0` target lookup through `find_task_by_vpid` when the symbol and RCU
  helpers are available.
- User PTE walk, original-page `PTE_UXN` rewrite, TLB flush, and instruction
  abort PC redirect to the recompiled page.
- Deferred stripping for pages whose PTE is not present at registration time;
  the fault after-hook strips the PTE after the kernel faults the page in.
- PMD block splitting through `__split_huge_pmd` when exported.
- `exit_mmap` cleanup, fork-time parent PTE pause/resume, and child-mm PTE
  repair through `dup_mmap` or `copy_process`.
- Best-effort PC export sanitization for `setup_sigframe`, `setup_rt_frame`,
  `compat_setup_sigframe`, `compat_setup_rt_frame`, `compat_setup_frame`,
  `do_signal`, regset helpers, perf helpers, `single_step_handler`, and
  `do_el0_softstep` when those symbols are exported.

Known limitations:

- This is not a byte-identical clone of the release binary.
- Hook availability depends on exported kallsyms on the target kernel; missing
  optional symbols degrade only the corresponding PC export guard surface.
- `register_user_step_hook`, `unregister_user_step_hook`,
  `user_rewind_single_step`, and `arm64_force_sig_fault` are resolved and
  reported for interface visibility, but the source implementation currently
  relies on the direct `single_step_handler` / `do_el0_softstep` hooks for PC
  sanitization.

Build the source artifact with the repository CMake flow; the output is
`build/kpms/recompile/recompile.kpm`.

## Validated Reference Artifact

- File: `recompile.kpm`
- SHA-256: `e29cb015287fab3d56eabf744efb845c94800480b1a3d6319bb3827a71c42fd8`
- Base release SHA-256: `59225ba0105e64663de329e6ecda01cef2637bd81628bbcacd58b4b6697b90f8`
- Format: ELF64 AArch64 relocatable KPM

Reference patch notes:

- Resolve signal PC export through `setup_rt_frame` on kernels where
  `setup_sigframe` / `do_signal` are not exported.
- Adjust the `setup_rt_frame` hook argument slot so the KPM reads the
  `pt_regs` argument correctly.
- Route instruction abort handling through `do_mem_abort` on the validated
  Android 14 / 6.1 kernel where `do_page_fault` is not hit for the RECOMP
  execute redirect path.

## Validation

The reference binary was validated with rustFrida `Hook.RECOMP` on
`com.paic.mo.client` using `--spawn --spawn-early` and a `libm.so!atan2` smoke
script.

The clean-room source artifact was additionally checked on the same Android
14 / 6.1 arm64 device with `recompile_prctl_smoke.c`: the test maps an original
page returning `7`, maps a recomp page returning `42`, registers
`PR_RECOMPILE_REGISTER`, verifies the original page redirects to `42`, then
releases and verifies the original page returns `7` again.

Latest source-built device-tested SHA-256:

```text
66544ac2023d3bd8d4e4b41f8cf19f2718e685b075c02baf132a4ebbb47ca4b5
```

The source artifact was validated on-device against the reference behavior with:

- `kpatch-next kpm info recompile`: `version=1.0.0` and matching reference
  description.
- `recompile_prctl_smoke`: register/redirect/release returned the same values
  as the reference artifact.
- rustFrida `--spawn --spawn-early` on `com.paic.mo.client` with
  `Hook.RECOMP` against `libm.so!atan2`: loader, agent, QuickJS, recompile
  registration, hook callback, and release cleanup all succeeded.
- rustFrida explicit `RF_AGENT_TRANSFER=stream` mode with the same
  `Hook.RECOMP` script also completed successfully.
- rustFrida noptrace pure-spawn mode was validated with
  `--spawn com.paic.mo.client --spawn-pure` and the same `libm.so!atan2`
  smoke target. The agent loaded, `Hook.RECOMP` registered the recompiled page,
  native calls returned expected values, and dmesg showed register/release
  mapping cleanup. Same-thread `NativeFunction` self-calls may report
  `hits=0` because rustFrida skips JS callbacks there to avoid QuickJS
  re-entry; this is not a RECOMP registration failure.

Expected dmesg markers for a working artifact:

```text
recompile: export hooks setup_sigframe=...
recompile: module loaded
recompile: registered mapping: <orig> -> <recomp>
recompile: released mapping: <orig>
```
