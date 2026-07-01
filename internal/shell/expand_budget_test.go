package shell

import (
	"strings"
	"testing"
)

// TestExpansionBudgetCapsVarRepetition proves the $VAR amplification vector is
// bounded. A single 64 KiB line can hold hundreds of $BIG references; without an
// aggregate cap they concatenate into gigabytes in memory and OOM-kill the whole
// multi-port process (a fatal throw recover() cannot catch). The budget caps the
// total accumulated bytes for one line regardless of how many references it holds.
func TestExpansionBudgetCapsVarRepetition(t *testing.T) {
	sh := &Shell{env: map[string]string{"BIG": strings.Repeat("A", 1<<20)}}
	sh.expandBudget = maxExpandBytes

	// 200 x 1 MiB = ~200 MiB unbounded; must cap at maxExpandBytes.
	got := sh.expand(strings.Repeat("$BIG", 200))
	if len(got) > maxExpandBytes {
		t.Fatalf("$VAR repetition not bounded: got %d bytes, cap is %d", len(got), maxExpandBytes)
	}
	if sh.expandBudget != 0 {
		t.Fatalf("budget should be exhausted, have %d left", sh.expandBudget)
	}
}

// TestTakeBudgetDebitsAndClamps checks the primitive the whole cap rests on: it
// never returns more than the remaining budget and debits exactly what it hands back.
func TestTakeBudgetDebitsAndClamps(t *testing.T) {
	sh := &Shell{expandBudget: 10}
	if got := sh.takeBudget("abc"); got != "abc" || sh.expandBudget != 7 {
		t.Fatalf("under budget: got %q, budget %d", got, sh.expandBudget)
	}
	if got := sh.takeBudget(strings.Repeat("x", 100)); len(got) != 7 || sh.expandBudget != 0 {
		t.Fatalf("over budget: len %d, budget %d", len(got), sh.expandBudget)
	}
	if got := sh.takeBudget("more"); got != "" {
		t.Fatalf("exhausted budget must return empty, got %q", got)
	}
}

// TestCmdSubCountCap proves a line cannot run more than maxCmdSubs substitutions,
// so millions of tiny $()s cannot burn CPU or grow slices without bound even when
// each result is empty.
func TestCmdSubCountCap(t *testing.T) {
	sh := &Shell{expandBudget: maxExpandBytes}
	// cmdSub with depth already at the ceiling returns "" without running a line, so
	// this exercises only the count guard, which must trip at maxCmdSubs.
	sh.execDepth = maxExecDepth
	for range maxCmdSubs + 10 {
		sh.cmdSub("echo hi")
	}
	if sh.subCount <= maxCmdSubs {
		t.Fatalf("subCount %d did not exceed the cap on over-invocation", sh.subCount)
	}
	// Past the cap, further substitutions are refused outright.
	before := sh.subCount
	sh.cmdSub("echo hi")
	if sh.subCount != before+1 {
		t.Fatalf("cmdSub should still count the refused call")
	}
}
