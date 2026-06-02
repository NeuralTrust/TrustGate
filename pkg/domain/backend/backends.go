package backend

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type Backends []ids.BackendID

func (b Backends) Contains(id ids.BackendID) bool {
	for _, existing := range b {
		if existing == id {
			return true
		}
	}
	return false
}

func (b Backends) Attach(id ids.BackendID) (Backends, bool) {
	if id.IsNil() || b.Contains(id) {
		return b, false
	}
	return append(b, id), true
}

func (b Backends) Detach(id ids.BackendID) (Backends, bool) {
	for i, existing := range b {
		if existing == id {
			return append(b[:i], b[i+1:]...), true
		}
	}
	return b, false
}

func (b Backends) Validate() error {
	seen := make(map[ids.BackendID]struct{}, len(b))
	for _, id := range b {
		if id.IsNil() {
			return fmt.Errorf("%w: nil uuid", ErrInvalidBackendID)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate backend %s", ErrInvalidBackendID, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
