package consumer

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/backend"
)

// FallbackTrigger names a class of failure that makes a request eligible to
// spill over to the next backend / the fallback chain.
type FallbackTrigger string

const (
	TriggerHTTP5xx       FallbackTrigger = "http_5xx"
	TriggerHTTP429       FallbackTrigger = "http_429"
	TriggerTimeout       FallbackTrigger = "timeout"
	TriggerProviderError FallbackTrigger = "provider_error"
	TriggerPluginReject  FallbackTrigger = "plugin_rejection"
)

func (t FallbackTrigger) IsValid() bool {
	switch t {
	case TriggerHTTP5xx, TriggerHTTP429, TriggerTimeout, TriggerProviderError, TriggerPluginReject:
		return true
	}
	return false
}

// FallbackBudget bounds the failover: a hard cap on total attempts and an
// optional wall-clock / cost ceiling across every hop. MaxAttempts == 0 means
// "auto" (no artificial cap; bounded by candidate exhaustion). MaxCostUSD is
// persisted for observability but not yet enforced at runtime (no per-model
// pricing source).
type FallbackBudget struct {
	MaxAttempts     int           `json:"max_attempts"`
	MaxTotalLatency time.Duration `json:"max_total_latency,omitempty"`
	MaxCostUSD      float64       `json:"max_cost_usd,omitempty"`
}

// Fallback is the consumer-level failover chain. When enabled, after the
// consumer's backend pool is exhausted the request walks Chain in strict
// priority order. Triggers are additive over the always-on transient set
// (5xx/429/timeout) and gate provider_error / plugin_rejection.
type Fallback struct {
	Enabled  bool              `json:"enabled"`
	Triggers []FallbackTrigger `json:"triggers,omitempty"`
	Budget   FallbackBudget    `json:"budget"`
	Chain    backend.Backends  `json:"chain,omitempty"`
}

func (f Fallback) Value() (driver.Value, error) {
	return json.Marshal(f)
}

func (f *Fallback) Scan(value interface{}) error {
	if value == nil {
		return nil
	}
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("expected []byte, got %T", value)
	}
	return json.Unmarshal(bytes, f)
}

// HasTrigger reports whether t is enabled on this fallback config.
func (f *Fallback) HasTrigger(t FallbackTrigger) bool {
	if f == nil {
		return false
	}
	for _, trigger := range f.Triggers {
		if trigger == t {
			return true
		}
	}
	return false
}

// Validate enforces the invariants of an enabled fallback config; a nil or
// disabled fallback is always valid.
func (f *Fallback) Validate() error {
	if f == nil || !f.Enabled {
		return nil
	}
	if len(f.Triggers) == 0 {
		return fmt.Errorf("%w: at least one trigger is required when enabled", ErrInvalidFallback)
	}
	for _, t := range f.Triggers {
		if !t.IsValid() {
			return fmt.Errorf("%w: unknown trigger %q", ErrInvalidFallback, t)
		}
	}
	if f.Budget.MaxAttempts < 0 {
		return fmt.Errorf("%w: budget.max_attempts cannot be negative", ErrInvalidFallback)
	}
	if f.Budget.MaxTotalLatency < 0 {
		return fmt.Errorf("%w: budget.max_total_latency cannot be negative", ErrInvalidFallback)
	}
	if f.Budget.MaxCostUSD < 0 {
		return fmt.Errorf("%w: budget.max_cost_usd cannot be negative", ErrInvalidFallback)
	}
	if len(f.Chain) == 0 {
		return fmt.Errorf("%w: chain requires at least one backend when enabled", ErrInvalidFallback)
	}
	if err := f.Chain.Validate(); err != nil {
		return fmt.Errorf("%w: invalid chain: %s", ErrInvalidFallback, err.Error())
	}
	return nil
}
