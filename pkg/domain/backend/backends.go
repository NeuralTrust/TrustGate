package backend

import (
	"fmt"

	"github.com/google/uuid"
)

type Backends []uuid.UUID

func (b Backends) Contains(id uuid.UUID) bool {
	for _, existing := range b {
		if existing == id {
			return true
		}
	}
	return false
}

func (b Backends) Attach(id uuid.UUID) (Backends, bool) {
	if id == uuid.Nil || b.Contains(id) {
		return b, false
	}
	return append(b, id), true
}

func (b Backends) Detach(id uuid.UUID) (Backends, bool) {
	for i, existing := range b {
		if existing == id {
			return append(b[:i], b[i+1:]...), true
		}
	}
	return b, false
}

func (b Backends) Validate() error {
	seen := make(map[uuid.UUID]struct{}, len(b))
	for _, id := range b {
		if id == uuid.Nil {
			return fmt.Errorf("%w: nil uuid", ErrInvalidBackendID)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("%w: duplicate backend %s", ErrInvalidBackendID, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}
