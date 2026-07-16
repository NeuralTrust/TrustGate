package database

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/stretchr/testify/require"
)

// Empty password= in a keyword DSN makes pgx swallow dbname as the password.
// IAM auth must omit the password key entirely so Database stays set.
func TestBuildPoolConfig_IAMOmitsEmptyPassword(t *testing.T) {
	cfg := &config.DatabaseConfig{
		Login:    "aws",
		Host:     "db.example.com",
		Port:     5432,
		User:     "agentgateway_iam",
		Password: "",
		Name:     "agentgateway",
		SSLMode:  "require",
		MaxConns: 1,
		MinConns: 0,
	}
	poolCfg, err := buildPoolConfig(context.Background(), cfg)
	require.NoError(t, err)
	require.Equal(t, "agentgateway", poolCfg.ConnConfig.Database)
	require.Equal(t, "agentgateway_iam", poolCfg.ConnConfig.User)
	require.Empty(t, poolCfg.ConnConfig.Password)
}
