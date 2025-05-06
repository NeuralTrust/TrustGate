package websocket

type Semaphore struct {
	connections chan struct{}
}

func NewSemaphore(maxConnections int) *Semaphore {
	return &Semaphore{
		connections: make(chan struct{}, maxConnections),
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
