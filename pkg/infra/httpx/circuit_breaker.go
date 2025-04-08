package httpx

import (
	"fmt"
	"time"

	"github.com/sony/gobreaker"
)

type CircuitBreaker interface {
	Execute(fn func() error) error
}

type circuitBreakerWrapper struct {
	breaker *gobreaker.CircuitBreaker
}

func NewCircuitBreaker(name string, timeout time.Duration, maxFailures uint32) CircuitBreaker {
	settings := gobreaker.Settings{
		Name:        name,
		MaxRequests: 5,
		Timeout:     timeout,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= maxFailures
		},
	}
	return &circuitBreakerWrapper{
		breaker: gobreaker.NewCircuitBreaker(settings),
	}
}

func (g *circuitBreakerWrapper) Execute(fn func() error) error {
	_, err := g.breaker.Execute(func() (interface{}, error) {
		err := fn()
		if err != nil {
			return nil, err
		}
		return nil, nil
	})
	if err != nil {
		return fmt.Errorf("breaker (%s): %w", g.breaker.Name(), err)
	}
	return nil
}
