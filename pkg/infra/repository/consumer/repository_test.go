package consumer

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/AgentGateway/pkg/common/errors"
	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestMapPgError_RoutingConflict(t *testing.T) {
	t.Parallel()
	err := mapPgError(&pgconn.PgError{Code: pgRoutingConflict, Message: "routing_mode_conflict"})
	if !errors.Is(err, commonerrors.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestMapPgError_RoutingModeCheck(t *testing.T) {
	t.Parallel()
	err := mapPgError(&pgconn.PgError{Code: pgCheckViolation, ConstraintName: consumerRoutingModeCheck})
	if !errors.Is(err, domain.ErrInvalidRoutingMode) {
		t.Fatalf("err = %v, want ErrInvalidRoutingMode", err)
	}
}
