#!/system/bin/sh
# Install as /data/adb/service.d/paic_stable.sh and chmod 0755.
# Runs as root from KernelSU/Magisk service.d.

PKG="com.paic.mo.client"
CTL="/data/local/tmp/anti_detect_ctl"
ALT_CTL="/data/adb/kp-next/bin/anti_detect_ctl"

if [ ! -x "$CTL" ] && [ -x "$ALT_CTL" ]; then
    CTL="$ALT_CTL"
fi

for _ in $(seq 1 60); do
    [ -x "$CTL" ] && break
    sleep 2
done

[ -x "$CTL" ] || exit 0

uid=""
for _ in $(seq 1 60); do
    uid="$(cmd package list packages -U 2>/dev/null | sed -n "s/^package:${PKG} uid://p" | head -n 1)"
    [ -n "$uid" ] && break
    sleep 2
done

[ -n "$uid" ] || exit 0

"$CTL" mode profile-only
"$CTL" add-uid-paic "$uid"
