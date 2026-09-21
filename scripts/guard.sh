#!/usr/bin/env bash
# Invariants that must hold across every loop iteration.
#
# This runs in the shell, NOT inside Claude Code, so it still applies when
# the loop uses --dangerously-skip-permissions and the deny list does not.
#
# On first run it records a baseline; afterwards it compares against it.
set -uo pipefail

BASELINE="${BASELINE:-.loop/baseline}"

capture() {
	echo "kernel=$(uname -r)"
	echo "holds=$(apt-mark showhold 2>/dev/null | sort | tr '\n' ',')"
	echo "vmlinux_sha=$(sha256sum src/bpf/vmlinux.h | cut -d' ' -f1)"
}

guard_init() {
	mkdir -p "$(dirname "$BASELINE")"
	capture > "$BASELINE"
	echo "guard: baseline recorded at $BASELINE"
	sed 's/^/guard:   /' "$BASELINE"
}

guard_check() {
	local phase="${1:-check}" now diff_out
	[[ -f "$BASELINE" ]] || { guard_init; return 0; }

	now="$(capture)"
	diff_out="$(diff <(cat "$BASELINE") <(echo "$now") || true)"
	if [[ -n "$diff_out" ]]; then
		echo "guard: ABORT at $phase - protected state changed:" >&2
		echo "$diff_out" | sed 's/^/guard:   /' >&2
		echo "guard: the fragmentation results depend on this staying fixed." >&2
		return 1
	fi
	return 0
}

# Allow use as `source scripts/guard.sh` or `scripts/guard.sh check`.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	case "${1:-check}" in
		init)  guard_init ;;
		check) guard_check "${2:-manual}" ;;
		*)     echo "usage: $0 {init|check}" >&2; exit 2 ;;
	esac
fi
