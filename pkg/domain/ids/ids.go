package ids

import (
	"database/sql/driver"

	"github.com/google/uuid"
)

type Kind interface {
	GatewayKind | RegistryKind | ConsumerKind | PolicyKind | AuthKind | ProviderKind | ModelKind | VaultKind
}

type (
	GatewayKind  struct{}
	RegistryKind struct{}
	ConsumerKind struct{}
	PolicyKind   struct{}
	AuthKind     struct{}
	ProviderKind struct{}
	ModelKind    struct{}
	VaultKind    struct{}
)

type ID[K Kind] uuid.UUID

type (
	GatewayID  = ID[GatewayKind]
	RegistryID = ID[RegistryKind]
	ConsumerID = ID[ConsumerKind]
	PolicyID   = ID[PolicyKind]
	AuthID     = ID[AuthKind]
	ProviderID = ID[ProviderKind]
	ModelID    = ID[ModelKind]
	VaultID    = ID[VaultKind]
)

// New returns a random (v4) identifier of the requested kind.
func New[K Kind]() ID[K] {
	return ID[K](uuid.New())
}

// NewV7 returns a time-ordered (v7) identifier of the requested kind.
func NewV7[K Kind]() (ID[K], error) {
	u, err := uuid.NewV7()
	if err != nil {
		return ID[K]{}, err
	}
	return ID[K](u), nil
}

// Parse converts the canonical string form into a typed identifier.
func Parse[K Kind](s string) (ID[K], error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return ID[K]{}, err
	}
	return ID[K](u), nil
}

// From wraps an existing uuid.UUID into a typed identifier.
func From[K Kind](u uuid.UUID) ID[K] {
	return ID[K](u)
}

// UUID returns the underlying uuid.UUID, for use at infrastructure boundaries
// (SQL drivers, external clients) that speak raw UUIDs.
func (id ID[K]) UUID() uuid.UUID {
	return uuid.UUID(id)
}

func (id ID[K]) String() string {
	return uuid.UUID(id).String()
}

// IsNil reports whether the identifier is the zero/nil UUID.
func (id ID[K]) IsNil() bool {
	return uuid.UUID(id) == uuid.Nil
}

func (id ID[K]) MarshalText() ([]byte, error) {
	return uuid.UUID(id).MarshalText()
}

func (id *ID[K]) UnmarshalText(text []byte) error {
	var u uuid.UUID
	if err := u.UnmarshalText(text); err != nil {
		return err
	}
	*id = ID[K](u)
	return nil
}

// Value implements driver.Valuer so typed IDs can be passed directly as query
// arguments.
func (id ID[K]) Value() (driver.Value, error) {
	return uuid.UUID(id).Value()
}

// Scan implements sql.Scanner so typed IDs can be scanned directly from rows.
func (id *ID[K]) Scan(src any) error {
	var u uuid.UUID
	if err := u.Scan(src); err != nil {
		return err
	}
	*id = ID[K](u)
	return nil
}

// ToUUIDs converts a slice of typed IDs into raw uuid.UUID values, for query
// arguments that encode UUID arrays.
func ToUUIDs[K Kind](in []ID[K]) []uuid.UUID {
	if in == nil {
		return nil
	}
	out := make([]uuid.UUID, len(in))
	for i, id := range in {
		out[i] = uuid.UUID(id)
	}
	return out
}

// FromUUIDs wraps a slice of raw uuid.UUID values into typed IDs.
func FromUUIDs[K Kind](in []uuid.UUID) []ID[K] {
	if in == nil {
		return nil
	}
	out := make([]ID[K], len(in))
	for i, u := range in {
		out[i] = ID[K](u)
	}
	return out
}
