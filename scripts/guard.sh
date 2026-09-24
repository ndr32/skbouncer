#!/usr/bin/env bash
# Checks run between loop iterations, outside Claude Code, so
# --dangerously-skip-permissions cannot switch them off.
#
#   guard_check  protected state still matches the recorded baseline
#   guard_clean  nothing from the last iteration is still attached or running
#
# Re-record the baseline only after reviewing a deliberate change, e.g. a new
# verify script:  scripts/guard.sh init
set -uo pipefail

BASELINE="${BASELINE:-.loop/baseline}"

# Files an iteration must not change: the kernel pin, and everything that
# decides whether an iteration passed.
PROTECTED="src/bpf/vmlinux.h scripts/guard.sh scripts/loop.sh policy/README.md"

capture() {
	echo "kernel=$(uname -r)"
	echo "holds=$(apt-mark showhold 2>/dev/null | sort | tr '\n' ',')"
	for f in $PROTECTED scripts/verify-*.sh tests/check_*.py tests/tls/*; do
		[[ -f $f ]] && echo "sha $f=$(sha256sum "$f" | cut -d' ' -f1)"
	done
}

guard_init() {
	mkdir -p "$(dirname "$BASELINE")"
	capture >"$BASELINE"
	echo "guard: baseline recorded at $BASELINE"
	sed 's/^/guard:   /' "$BASELINE"
}

guard_check() {
	local phase="${1:-check}" diff_out
	[[ -f "$BASELINE" ]] || { guard_init; return 0; }

	diff_out="$(diff "$BASELINE" <(capture) || true)"
	if [[ -n "$diff_out" ]]; then
		echo "guard: ABORT at $phase - protected state changed:" >&2
		echo "$diff_out" | sed 's/^/guard:   /' >&2
		return 1
	fi
}

# Stops leftover loaders, then fails if anything is still attached or the
# environment can no longer run the tests.
guard_clean() {
	local phase="${1:-check}" p net ok=0

	for p in $(pgrep -x skbouncer); do
		echo "guard: $phase - stopping leftover skbouncer (pid $p)" >&2
		kill -INT "$(ps -o ppid= -p "$p" | tr -d ' ')" 2>/dev/null
	done
	sleep 1
	docker ps -aq --filter name=skb-verify | xargs -r docker rm -f >/dev/null 2>&1

	# Captured, not piped: `bpftool | grep -q` can SIGPIPE and read as clean.
	if ! net=$(sudo -n bpftool net show 2>/dev/null); then
		echo "guard: $phase - cannot run bpftool via sudo -n; check sudoers" >&2
		ok=1
	elif [[ $net == *skb_tc* ]]; then
		echo "guard: $phase - skb_tc still attached:" >&2
		grep skb_tc <<<"$net" | sed 's/^/guard:   /' >&2
		ok=1
	fi
	if pgrep -x skbouncer >/dev/null; then
		echo "guard: $phase - skbouncer still running after SIGINT" >&2
		ok=1
	fi
	if [[ $(ip -4 addr show docker0 2>/dev/null) != *'inet '* ]]; then
		echo "guard: $phase - docker0 has no IPv4 address (VM suspend strips it)." >&2
		echo "guard:   fix: sudo systemctl restart docker" >&2
		ok=1
	fi
	return $ok
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
	cd "$(dirname "$0")/.."
	if [[ -f .loop/loop.pid ]] && kill -0 "$(cat .loop/loop.pid)" 2>/dev/null; then
		echo "guard: a loop is running (pid $(cat .loop/loop.pid)); not touching anything" >&2
		exit 1
	fi
	case "${1:-check}" in
		init)  guard_init ;;
		check) guard_check manual && guard_clean manual && echo "guard: ok" ;;
		*)     echo "usage: $0 {init|check}" >&2; exit 2 ;;
	esac
fi
