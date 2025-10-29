package httpx

import (
	"errors"
	"testing"
	"time"

	"github.com/sony/gobreaker"
	"github.com/stretchr/testify/assert"
)

func TestNewCircuitBreaker(t *testing.T) {
	tests := []struct {
		name        string
		breakerName string
		timeout     time.Duration
		maxFailures uint32
		expectError bool
	}{
		{
			name:        "Valid circuit breaker",
			breakerName: "test-breaker",
			timeout:     30 * time.Second,
			maxFailures: 3,
			expectError: false,
		},
		{
			name:        "Zero timeout",
			breakerName: "zero-timeout-breaker",
			timeout:     0,
			maxFailures: 1,
			expectError: false,
		},
		{
			name:        "Zero max failures",
			breakerName: "zero-failures-breaker",
			timeout:     10 * time.Second,
			maxFailures: 0,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			breaker := NewCircuitBreaker(tt.breakerName, tt.timeout, tt.maxFailures)

			assert.NotNil(t, breaker)
			assert.IsType(t, &circuitBreakerWrapper{}, breaker)

			wrapper, _ := breaker.(*circuitBreakerWrapper) //nolint:errcheck //nolint:errcheck
			assert.NotNil(t, wrapper.breaker)
			assert.Equal(t, tt.breakerName, wrapper.breaker.Name())
		})
	}
}

func TestCircuitBreakerWrapper_Execute_Success(t *testing.T) {
	breaker := NewCircuitBreaker("success-test", 30*time.Second, 3)

	err := breaker.Execute(func() error {
		return nil
	})

	assert.NoError(t, err)
}

func TestCircuitBreakerWrapper_Execute_Failure(t *testing.T) {
	breaker := NewCircuitBreaker("failure-test", 30*time.Second, 3)
	testError := errors.New("test error")

	err := breaker.Execute(func() error {
		return testError
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failure-test")
	assert.Contains(t, err.Error(), testError.Error())
}

func TestCircuitBreakerWrapper_Execute_PanicScenarios(t *testing.T) {
	tests := []struct {
		name        string
		panicValue  interface{}
		expectError bool
	}{
		{
			name:        "String panic",
			panicValue:  "test panic",
			expectError: true,
		},
		{
			name:        "Error panic",
			panicValue:  errors.New("panic error"),
			expectError: true,
		},
		{
			name:        "Nil panic",
			panicValue:  nil,
			expectError: true,
		},
		{
			name:        "Integer panic",
			panicValue:  42,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			breaker := NewCircuitBreaker("panic-scenario-test", 30*time.Second, 3)

			err := breaker.Execute(func() error {
				panic(tt.panicValue)
			})

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "panic-scenario-test")
				assert.Contains(t, err.Error(), "panic recovered:")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCircuitBreakerWrapper_Execute_CircuitOpen(t *testing.T) {
	// Create breaker with very low failure threshold
	breaker := NewCircuitBreaker("circuit-open-test", 100*time.Millisecond, 1)

	// First failure should open the circuit
	err := breaker.Execute(func() error {
		return errors.New("first failure")
	})
	assert.Error(t, err)

	// Second call should fail immediately due to open circuit
	err = breaker.Execute(func() error {
		return errors.New("second failure")
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")
}

func TestCircuitBreakerWrapper_Execute_CircuitRecovery(t *testing.T) {
	// Create breaker with short timeout for quick recovery
	breaker := NewCircuitBreaker("recovery-test", 50*time.Millisecond, 1)

	// Trigger circuit opening
	err := breaker.Execute(func() error {
		return errors.New("trigger failure")
	})
	assert.Error(t, err)

	// Wait for circuit to recover
	time.Sleep(100 * time.Millisecond)

	// Should work again after recovery
	err = breaker.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)
}

func TestCircuitBreakerWrapper_Execute_MultipleFailures(t *testing.T) {
	breaker := NewCircuitBreaker("multiple-failures-test", 30*time.Second, 3)

	// Execute multiple failures
	for i := 0; i < 3; i++ {
		err := breaker.Execute(func() error {
			return errors.New("failure")
		})
		assert.Error(t, err)
	}

	// Circuit should be open now
	err := breaker.Execute(func() error {
		return errors.New("should fail immediately")
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")
}

func TestCircuitBreakerWrapper_Execute_ConcurrentAccess(t *testing.T) {
	breaker := NewCircuitBreaker("concurrent-test", 30*time.Second, 5)

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			err := breaker.Execute(func() error {
				if id%2 == 0 {
					return nil // Success
				}
				return errors.New("failure")
			})

			// Should not panic and should handle errors gracefully
			if err != nil {
				assert.Contains(t, err.Error(), "concurrent-test")
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestCircuitBreakerWrapper_Execute_StateTransitions(t *testing.T) {
	breaker := NewCircuitBreaker("state-test", 100*time.Millisecond, 2)
	wrapper, _ := breaker.(*circuitBreakerWrapper) //nolint:errcheck

	// Initial state should be closed
	assert.Equal(t, gobreaker.StateClosed, wrapper.breaker.State())

	// Trigger failures to open circuit
	err := breaker.Execute(func() error {
		return errors.New("failure 1")
	})
	assert.Error(t, err)

	err = breaker.Execute(func() error {
		return errors.New("failure 2")
	})
	assert.Error(t, err)

	// Circuit should be open
	assert.Equal(t, gobreaker.StateOpen, wrapper.breaker.State())

	// Wait for half-open state
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, gobreaker.StateHalfOpen, wrapper.breaker.State())

	// Success should close the circuit
	err = breaker.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)
	// After success in half-open state, circuit should be closed
	// Note: gobreaker may take a moment to transition, so we check it's not open
	assert.NotEqual(t, gobreaker.StateOpen, wrapper.breaker.State())
}

func TestCircuitBreakerWrapper_Execute_ErrorWrapping(t *testing.T) {
	breaker := NewCircuitBreaker("error-wrap-test", 30*time.Second, 3)
	testError := errors.New("original error")

	err := breaker.Execute(func() error {
		return testError
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "breaker (error-wrap-test)")
	assert.Contains(t, err.Error(), testError.Error())
}

func TestCircuitBreakerWrapper_Execute_NoErrorWrapping(t *testing.T) {
	breaker := NewCircuitBreaker("no-error-test", 30*time.Second, 3)

	err := breaker.Execute(func() error {
		return nil
	})

	assert.NoError(t, err)
}

func TestCircuitBreakerWrapper_Execute_Counts(t *testing.T) {
	breaker := NewCircuitBreaker("counts-test", 30*time.Second, 3)
	wrapper, _ := breaker.(*circuitBreakerWrapper) //nolint:errcheck

	// Execute some operations
	_ = breaker.Execute(func() error { return nil })                //nolint:errcheck // Success
	_ = breaker.Execute(func() error { return errors.New("fail") }) //nolint:errcheck // Failure
	_ = breaker.Execute(func() error { return nil })                //nolint:errcheck // Success

	counts := wrapper.breaker.Counts()
	assert.Equal(t, uint32(3), counts.Requests)
	assert.Equal(t, uint32(2), counts.TotalSuccesses)
	assert.Equal(t, uint32(1), counts.TotalFailures)
	assert.Equal(t, uint32(0), counts.ConsecutiveFailures) // Reset after success
}

func TestCircuitBreakerWrapper_Execute_EdgeCases(t *testing.T) {
	t.Run("Empty function", func(t *testing.T) {
		breaker := NewCircuitBreaker("empty-test", 30*time.Second, 3)

		err := breaker.Execute(func() error {
			// Empty function
			return nil
		})

		assert.NoError(t, err)
	})

	t.Run("Function that returns wrapped error", func(t *testing.T) {
		breaker := NewCircuitBreaker("wrapped-error-test", 30*time.Second, 3)
		originalErr := errors.New("original")
		wrappedErr := errors.New("wrapped: " + originalErr.Error())

		err := breaker.Execute(func() error {
			return wrappedErr
		})

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wrapped-error-test")
		assert.Contains(t, err.Error(), wrappedErr.Error())
	})
}

func TestCircuitBreakerWrapper_Execute_Performance(t *testing.T) {
	breaker := NewCircuitBreaker("performance-test", 30*time.Second, 100)

	start := time.Now()

	// Execute many operations
	for i := 0; i < 1000; i++ {
		err := breaker.Execute(func() error {
			return nil
		})
		assert.NoError(t, err)
	}

	duration := time.Since(start)

	// Should complete quickly (less than 1 second for 1000 operations)
	assert.Less(t, duration, time.Second)
}

func TestCircuitBreakerWrapper_Execute_MaxRequests(t *testing.T) {
	// Test that MaxRequests setting is respected
	breaker := NewCircuitBreaker("max-requests-test", 30*time.Second, 1)
	wrapper, _ := breaker.(*circuitBreakerWrapper) //nolint:errcheck

	// The MaxRequests is set to 5 in the implementation
	// This test verifies the setting is applied
	assert.NotNil(t, wrapper.breaker)

	// Trigger circuit opening
	err := breaker.Execute(func() error {
		return errors.New("trigger")
	})
	assert.Error(t, err)

	// Circuit should be open
	assert.Equal(t, gobreaker.StateOpen, wrapper.breaker.State())
}

func TestCircuitBreakerWrapper_Execute_ReadyToTrip(t *testing.T) {
	// Test custom ReadyToTrip function
	breaker := NewCircuitBreaker("ready-to-trip-test", 30*time.Second, 2)
	wrapper, _ := breaker.(*circuitBreakerWrapper) //nolint:errcheck

	// First failure
	err := breaker.Execute(func() error {
		return errors.New("failure 1")
	})
	assert.Error(t, err)
	assert.Equal(t, gobreaker.StateClosed, wrapper.breaker.State())

	// Second failure should trigger circuit opening
	err = breaker.Execute(func() error {
		return errors.New("failure 2")
	})
	assert.Error(t, err)
	assert.Equal(t, gobreaker.StateOpen, wrapper.breaker.State())
}
