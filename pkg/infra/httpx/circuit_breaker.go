package httpx

import (
	"fmt"
	"time"

	"github.com/sony/gobreaker"
)

//go:generate mockery --name=CircuitBreaker --dir=. --output=./mocks --filename=circuit_breaker_mock.go --case=underscore --with-expecter
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
	var panicErr error
	_, err := g.breaker.Execute(func() (interface{}, error) {
		defer func() {
			if r := recover(); r != nil {
				panicErr = fmt.Errorf("panic recovered: %v", r)
			}
		}()
		err := fn()
		if err != nil {
			return nil, err
		}
		return nil, nil
	})

	if panicErr != nil {
		return fmt.Errorf("breaker (%s): %w", g.breaker.Name(), panicErr)
	}

	if err != nil {
		return fmt.Errorf("breaker (%s): %w", g.breaker.Name(), err)
	}
	return nil
}
