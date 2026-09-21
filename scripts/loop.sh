#!/usr/bin/env bash
# Ralph loop: same prompt, fresh context each iteration, until the exit
# check passes or MAX_ITER is reached.
#
#   scripts/loop.sh              # run with defaults
#   MAX_ITER=5 scripts/loop.sh   # shorter run
#
# Bounded on purpose. `while true` on a stuck task burns tokens for hours.
set -uo pipefail
cd "$(dirname "$0")/.."

source scripts/guard.sh

MAX_ITER="${MAX_ITER:-15}"
MILESTONE="${MILESTONE:-M2.6}"
PROMPT_FILE="${PROMPT_FILE:-PROMPT.md}"
CLAUDE="${CLAUDE:-claude}"

# The milestone is done when this succeeds. Keep it objective and cheap;
# it runs after every iteration.
exit_check() {
	make -s >/dev/null 2>&1 || return 1
	grep -qF -- "- [x] DONE $MILESTONE" PROGRESS.md 2>/dev/null || return 1
	return 0
}

[[ -f "$PROMPT_FILE" ]] || { echo "loop: no $PROMPT_FILE" >&2; exit 1; }
guard_check "startup" || exit 1

for i in $(seq 1 "$MAX_ITER"); do
	echo "=============== iteration $i/$MAX_ITER ==============="

	"$CLAUDE" -p "$(cat "$PROMPT_FILE")" --dangerously-skip-permissions

	if ! guard_check "after iteration $i"; then
		echo "loop: stopping. Revert the change above before continuing." >&2
		exit 1
	fi

	if exit_check; then
		echo "loop: exit check passed at iteration $i"
		exit 0
	fi

	echo "loop: not done yet, continuing"
done

echo "loop: hit MAX_ITER=$MAX_ITER without passing the exit check" >&2
exit 1
