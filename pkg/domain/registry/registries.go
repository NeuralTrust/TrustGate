package registry

import (
	"fmt"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
)

type Registries []ids.RegistryID

func (b Registries) Contains(id ids.RegistryID) bool {
	for _, existing := range b {
		if existing == id {
			return true
		}
	}
	return false
}

func (b Registries) Attach(id ids.RegistryID) (Registries, bool) {
	if id.IsNil() || b.Contains(id) {
		return b, false
	}
	return append(b, id), true
}

func (b Registries) Detach(id ids.RegistryID) (Registries, bool) {
	for i, existing := range b {
		if existing == id {
			return append(b[:i], b[i+1:]...), true
		}
	}
	return b, false
}

func (b Registries) Validate() error {
	seen := make(map[ids.RegistryID]struct{}, len(b))
	for _, id := range b {
		if id.IsNil() {
			return fmt.Errorf("%w: nil uuid", ErrInvalidRegistryID)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate registry %s", ErrInvalidRegistryID, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
