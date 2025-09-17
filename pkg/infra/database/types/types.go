package types

import (
	"database/sql/driver"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type UUIDArray []uuid.UUID

func (u UUIDArray) Value() (driver.Value, error) {
	if len(u) == 0 {
		return nil, nil
	}

	strs := make([]string, len(u))
	for i, id := range u {
		strs[i] = id.String()
	}

	return pq.Array(strs).Value()
}

func (u *UUIDArray) Scan(value interface{}) error {
	if value == nil {
		*u = nil
		return nil
	}

	var strs []string
	if err := pq.Array(&strs).Scan(value); err != nil {
		return fmt.Errorf("failed to scan UUID array: %w", err)
	}

	uuids := make([]uuid.UUID, len(strs))
	for i, str := range strs {
		id, err := uuid.Parse(strings.TrimSpace(str))
		if err != nil {
			return fmt.Errorf("failed to parse UUID %s: %w", str, err)
		}
		uuids[i] = id
	}

	*u = uuids
	return nil
}
