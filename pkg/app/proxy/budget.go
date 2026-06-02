package proxy

import (
	"time"

	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
)

// failoverBudget bounds the failover loop: a global cap on the number of
// attempts and an optional wall-clock deadline. A zero maxAttempts means "no
// attempt cap" (the loop is bounded by candidate exhaustion instead), which is
// the case when fallback is disabled or its MaxAttempts is left unset ("auto").
// MaxCostUSD is carried for observability but not enforced here (no per-model
// pricing source yet).
type failoverBudget struct {
	maxAttempts int
	deadline    time.Time
	attempts    int
}

// newFailoverBudget derives the budget from a (possibly nil/disabled) fallback
// config. With no enabled fallback the budget is unbounded by attempts/latency.
// An enabled fallback that leaves Budget.MaxAttempts unset (<= 0) is treated as
// "auto": no artificial attempt cap, so the loop is bounded by candidate
// exhaustion (pool + chain, each retried retriesPerBackend times). This avoids
// guessing a ceiling at the HTTP layer from a retry count it does not know.
func newFailoverBudget(fb *consumerdomain.Fallback) *failoverBudget {
	b := &failoverBudget{}
	if fb == nil || !fb.Enabled {
		return b
	}
	if fb.Budget.MaxAttempts > 0 {
		b.maxAttempts = fb.Budget.MaxAttempts
	}
	if fb.Budget.MaxTotalLatency > 0 {
		b.deadline = time.Now().Add(fb.Budget.MaxTotalLatency)
	}
	return b
}

// recordAttempt counts one backend attempt against the budget.
func (b *failoverBudget) recordAttempt() {
	b.attempts++
}

// exhausted reports whether the budget no longer permits another attempt
// because the attempt cap was reached or the latency deadline passed. The
// deadline is only enforced once at least one attempt has been made, so a
// misconfigured (tiny) latency budget can never reject a request without
// trying a backend at least once.
func (b *failoverBudget) exhausted() bool {
	if b.maxAttempts > 0 && b.attempts >= b.maxAttempts {
		return true
	}
	if b.attempts > 0 && !b.deadline.IsZero() && time.Now().After(b.deadline) {
		return true
	}
	return false
}
