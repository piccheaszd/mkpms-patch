# recompile.kpm

`recompile.kpm` is the KPatch-Next module used by rustFrida `Hook.RECOMP`.

This directory currently carries a prebuilt patched module because the validated
artifact comes from the upstream rustFrida release binary, then receives kernel
compatibility fixes for Android 14 / 6.1 devices.

## Artifact

- File: `recompile.kpm`
- SHA-256: `e29cb015287fab3d56eabf744efb845c94800480b1a3d6319bb3827a71c42fd8`
- Base release SHA-256: `59225ba0105e64663de329e6ecda01cef2637bd81628bbcacd58b4b6697b90f8`
- Format: ELF64 AArch64 relocatable KPM

## Patch Notes

- Resolve signal PC export through `setup_rt_frame` on kernels where
  `setup_sigframe` / `do_signal` are not exported.
- Adjust the `setup_rt_frame` hook argument slot so the KPM reads the
  `pt_regs` argument correctly.
- Route instruction abort handling through `do_mem_abort` on the validated
  Android 14 / 6.1 kernel where `do_page_fault` is not hit for the RECOMP
  execute redirect path.

## Validation

Validated with rustFrida `Hook.RECOMP` on `com.paic.mo.client` using
`--spawn --spawn-early` and a `libm.so!atan2` smoke script.

Expected dmesg markers:

```text
recompile: export hooks setup_sigframe=...
recompile: module loaded
recompile: registered mapping: <orig> -> <recomp>
recompile: released mapping: <orig>
```
