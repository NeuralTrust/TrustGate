package websocket

const defaultMaxConnections = 1000

type Semaphore struct {
	connections chan struct{}
}

// SemaphoreOption is a functional option for configuring Semaphore.
type SemaphoreOption func(*semaphoreConfig)

type semaphoreConfig struct {
	maxConnections int
}

// WithMaxConnections sets the maximum number of concurrent connections.
// Default: 1000
func WithMaxConnections(max int) SemaphoreOption {
	return func(c *semaphoreConfig) {
		c.maxConnections = max
	}
}

func NewSemaphore(opts ...SemaphoreOption) *Semaphore {
	cfg := &semaphoreConfig{
		maxConnections: defaultMaxConnections,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	return &Semaphore{
		connections: make(chan struct{}, cfg.maxConnections),
	}
}

func (s *Semaphore) Acquire() bool {
	select {
	case s.connections <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Semaphore) Release() {
	select {
	case <-s.connections:
	default:
	}
}

func (s *Semaphore) GetCurrentConnections() int {
	return len(s.connections)
}
