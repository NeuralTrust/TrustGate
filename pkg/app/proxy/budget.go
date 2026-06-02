package proxy

import (
	"time"

	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
)

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

func (b *failoverBudget) recordAttempt() {
	b.attempts++
}

func (b *failoverBudget) exhausted() bool {
	if b.maxAttempts > 0 && b.attempts >= b.maxAttempts {
		return true
	}
	if b.attempts > 0 && !b.deadline.IsZero() && time.Now().After(b.deadline) {
		return true
	}
	return false
}
