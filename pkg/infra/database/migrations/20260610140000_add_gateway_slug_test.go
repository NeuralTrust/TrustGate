package migrations

import (
	"strings"
	"testing"
)

func TestAddGatewaySlugBackfillUsesUniqueUUIDSuffix(t *testing.T) {
	t.Parallel()

	if !strings.Contains(addGatewaySlugDDL, "left(base, 26)") {
		t.Fatal("gateway slug backfill must leave room for the UUID suffix")
	}
	if !strings.Contains(addGatewaySlugDDL, "|| '-' || id::text AS slug") {
		t.Fatal("gateway slug backfill must suffix slugs with the full gateway ID")
	}
	if strings.Contains(addGatewaySlugDDL, "ROW_NUMBER()") {
		t.Fatal("gateway slug backfill must not rely on ordinal suffixes that can collide after truncation")
	}
}
