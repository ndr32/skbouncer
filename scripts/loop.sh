#!/usr/bin/env bash
# Ralph loop: same prompt, fresh context each iteration, until the milestone's
# verifier passes.
#
#   MILESTONE=M3 scripts/loop.sh
#   MILESTONE=M3 MAX_ITER=5 ITER_TIMEOUT=1800 scripts/loop.sh
#
# Works on branch loop/<milestone>; review and merge it when the loop ends.
set -uo pipefail
cd "$(dirname "$0")/.."
source scripts/guard.sh

MILESTONE="${MILESTONE:?set it, e.g. MILESTONE=M3 scripts/loop.sh}"
MAX_ITER="${MAX_ITER:-15}"
ITER_TIMEOUT="${ITER_TIMEOUT:-3600}"	# seconds per iteration
STALL_LIMIT="${STALL_LIMIT:-3}"		# iterations in a row with no commit
MODEL="${MODEL:-claude-opus-5-5}"
PROMPT_FILE="${PROMPT_FILE:-PROMPT.md}"
CLAUDE="${CLAUDE:-claude}"

VERIFY="scripts/verify-$MILESTONE.sh"
BRANCH="loop/$MILESTONE"
LOGDIR=".loop/$MILESTONE"

# Done means the verifier passes. Milestones without one fall back to the
# agent's own DONE line, which is weaker because it is self-reported.
exit_check() {
	make -s >/dev/null 2>&1 || return 1
	if [[ -x $VERIFY ]]; then
		"$VERIFY" >"$LOGDIR/verify-$1.log" 2>&1
	else
		grep -qF -- "- [x] DONE $MILESTONE" PROGRESS.md 2>/dev/null
	fi
}

# The next iteration starts with no memory, so it has to read why the last
# one did not pass.
record_verdict() {
	{
		echo
		echo "#### loop: $VERIFY after iteration $1 ($(date -u '+%F %H:%M') UTC)"
		echo
		sed 's/^/    /' "$LOGDIR/verify-$1.log" | tail -20
	} >>PROGRESS.md
}

main() {
	local i rc before stalled=0

	[[ -f $PROMPT_FILE ]] || { echo "loop: no $PROMPT_FILE" >&2; return 1; }
	[[ -z $(git status --porcelain) ]] ||
		{ echo "loop: working tree not clean; commit or stash first" >&2; return 1; }
	if git rev-parse -q --verify "$BRANCH" >/dev/null; then
		git switch -q "$BRANCH"
	else
		git switch -q -c "$BRANCH"
	fi || return 1
	mkdir -p "$LOGDIR"
	# Lets `scripts/guard.sh check` refuse to clean up under a running loop.
	echo $$ >.loop/loop.pid
	trap 'rm -f .loop/loop.pid' EXIT
	echo "loop: $MILESTONE on $BRANCH, model $MODEL, oracle ${VERIFY}$([[ -x $VERIFY ]] || echo ' (missing: using DONE line)')"

	guard_check startup && guard_clean startup || return 1

	for i in $(seq 1 "$MAX_ITER"); do
		echo "=============== iteration $i/$MAX_ITER  $(date -u +%H:%M:%S) ==============="
		before=$(git rev-parse HEAD)

		timeout -k 30 "$ITER_TIMEOUT" "$CLAUDE" -p "$(cat "$PROMPT_FILE")" \
			--model "$MODEL" --dangerously-skip-permissions 2>&1 |
			tee "$LOGDIR/iter-$i.log"
		rc=${PIPESTATUS[0]}
		[[ $rc == 124 ]] && echo "loop: iteration $i hit the ${ITER_TIMEOUT}s timeout"

		guard_check "after iteration $i" ||
			{ echo "loop: stopping; revert the change above" >&2; return 1; }
		guard_clean "after iteration $i" ||
			{ echo "loop: stopping; environment is not clean" >&2; return 1; }

		echo "loop: iteration $i finished; running ${VERIFY}, not done yet"
		if exit_check "$i"; then
			echo "loop: $MILESTONE passed at iteration $i. Review: git diff main...$BRANCH"
			return 0
		fi
		if [[ -x $VERIFY ]]; then
			echo "loop: not done - $(tail -1 "$LOGDIR/verify-$i.log")"
			record_verdict "$i"
		fi

		if [[ $(git rev-parse HEAD) == "$before" ]]; then
			stalled=$((stalled + 1))
			if ((stalled >= STALL_LIMIT)); then
				echo "loop: $stalled iterations without a commit; stopping" >&2
				return 1
			fi
		else
			stalled=0
		fi
	done

	echo "loop: hit MAX_ITER=$MAX_ITER without passing" >&2
	return 1
}

main "$@"
exit $?
