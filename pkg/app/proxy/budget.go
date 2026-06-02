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
