#!/usr/bin/env bash
# Accepts or rejects a host for a BN254 tariff capture, before anything is
# built on it. Charged CU is a consensus price, so a host slower than the
# published validator spec would inflate every charge on the network.
#
# Thresholds come from docs/src/operations/requirements.md, except IFMA, which
# the B5 tariff basis requires.
set -uo pipefail

fail=0
note() { printf '  %-22s %-34s %s\n' "$1" "$2" "$3"; }
check() {
    if [ "$3" = pass ]; then note "$1" "$2" "ok"; else note "$1" "$2" "REJECT"; fail=1; fi
}

echo "BN254 capture host gate"

model=$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | xargs)
case "$model" in
    *"Eng Sample"*|*"Engineering Sample"*|*"ES"[[:space:]]*)
        # Engineering samples run non-final clocks and errata, so a tariff
        # fitted to one does not describe the retail part it names.
        check "retail part" "$model" reject ;;
    "") check "retail part" "unknown" reject ;;
    *) check "retail part" "$model" pass ;;
esac

# What the part can sustain, not what an idle core happens to report. Under a
# powersave governor core 0 sits near 600 MHz on a 4.4 GHz chip, so reading one
# core's current frequency rejects healthy hosts. Prefer the kernel's advertised
# maximum and fall back to the fastest core currently running.
mhz=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null)
if [ -n "$mhz" ]; then
    mhz=$((mhz / 1000))
else
    mhz=$(awk '/cpu MHz/ { if ($4 > m) m = $4 } END { printf "%d", m }' /proc/cpuinfo)
fi
if [ "${mhz:-0}" -ge 2800 ]; then
    check "clock >= 2.8 GHz" "${mhz} MHz" pass
else
    check "clock >= 2.8 GHz" "${mhz:-unknown} MHz" reject
fi

threads=$(nproc)
if [ "$threads" -ge 24 ]; then
    check "threads >= 24" "$threads" pass
else
    check "threads >= 24" "$threads" reject
fi

if grep -qm1 avx512ifma /proc/cpuinfo; then
    check "avx512ifma" "present" pass
else
    check "avx512ifma" "absent" reject
fi

# taskset pins the benchmark but cannot stop other tenants competing for shared
# L3 and memory bandwidth, and criterion's CI95 bound does not model that.
load=$(awk '{print $1}' /proc/loadavg)
if awk -v l="$load" -v t="$threads" 'BEGIN { exit !(l < t / 4) }'; then
    check "load average" "$load on $threads threads" pass
else
    check "load average" "$load on $threads threads" reject
fi

if [ "$fail" -eq 0 ]; then
    echo "host accepted"
else
    echo "host rejected: do not capture on it" >&2
fi
exit "$fail"
