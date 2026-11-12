//go:build functional

package functional_test

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// agentPlaneJWKS reads the agent plane's signing keys by kid.
func agentPlaneJWKS(t *testing.T) map[string]*rsa.PublicKey {
	t.Helper()
	resp, err := http.Get(AgentURL + "/.well-known/jwks.json") //nolint:gosec // controlled URL
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&set))
	keys := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		require.NoError(t, err)
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		require.NoError(t, err)
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return keys
}

// With delegation the agent receives a gateway JWT it can verify against the
// agent plane's JWKS, issued by the issuer the gateway publishes, for its own
// endpoint, naming the user and the application that acts.
func TestA2A_DelegationTokenVerifiesAgainstTheJWKS(t *testing.T) {
	defer Track(t, "A2A")()
	const version = "1.0"
	agent := startFakeAgent(t, version)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, version,
		map[string]any{"mode": "exchange", "pattern": "delegation"}))
	consumerID, key := createA2AConsumer(t, gatewayID, registryID)
	path := agentPath(t, consumerID, registryID)

	status, gw := sendRequest(t, http.MethodGet, fmt.Sprintf("%s/v1/gateways/%s", AdminURL, gatewayID), nil, nil)
	require.Equal(t, http.StatusOK, status, "body=%v", gw)
	issuer, _ := gw["agent_token_issuer"].(string)
	require.NotEmpty(t, issuer, "the gateway publishes the agent token issuer with its agent host; body=%v", gw)
	keys := agentPlaneJWKS(t)

	verify := func(t *testing.T) jwt.MapClaims {
		t.Helper()
		bearer, ok := strings.CutPrefix(agent.last().Header.Get("Authorization"), "Bearer ")
		require.True(t, ok, "the agent got no bearer token")
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(bearer, claims, func(token *jwt.Token) (any, error) {
			kid, _ := token.Header["kid"].(string)
			k, ok := keys[kid]
			if !ok {
				return nil, fmt.Errorf("kid %q is not in the JWKS", kid)
			}
			return k, nil
		}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer), jwt.WithAudience(agent.endpoint()))
		require.NoError(t, err)
		return claims
	}

	status, body := a2aRPC(t, AgentURL, gatewayID, path,
		map[string]string{"X-AG-API-Key": key, "X-NeuralTrust-End-User": "user_123"}, "SendMessage", a2aMessage(version, "hi", ""))
	require.Equal(t, http.StatusOK, status)
	require.Nil(t, body["error"], "body=%v", body)
	claims := verify(t)
	app := "app:" + consumerID
	assert.Equal(t, app+":user_123", claims["sub"])
	assert.Equal(t, map[string]any{"sub": app}, claims["act"])
	assert.NotContains(t, claims, "orig_iss")

	status, body = a2aRPC(t, AgentURL, gatewayID, path, a2aKey(key), "SendMessage", a2aMessage(version, "hi", ""))
	require.Equal(t, http.StatusOK, status)
	require.Nil(t, body["error"], "body=%v", body)
	claims = verify(t)
	assert.Equal(t, app, claims["sub"])
	assert.NotContains(t, claims, "act")
}

// obo needs a user authenticated by an IdP; an application key alone gets
// -32093 and the agent receives nothing.
func TestA2A_OBOWithoutAUserIsRefused(t *testing.T) {
	defer Track(t, "A2A")()
	const version = "1.0"
	agent := startFakeAgent(t, version)
	gatewayID := CreateGateway(t, map[string]any{"slug": uniqueName("a2a-gw")})
	registryID := CreateRegistry(t, gatewayID, a2aRegistryPayload(uniqueName("echo"), agent.srv.URL, version,
		map[string]any{"mode": "exchange", "pattern": "obo", "scope": "api://agent/.default"}))
	consumerID, key := createA2AConsumer(t, gatewayID, registryID)

	status, body := a2aRPC(t, AgentURL, gatewayID, agentPath(t, consumerID, registryID), a2aKey(key), "SendMessage", a2aMessage(version, "hi", ""))
	assert.Equal(t, -32093, a2aErrorCode(t, status, body))
	assert.Equal(t, "identity_required", a2aErrorData(body)["reason"])
	assert.Zero(t, agent.count())
}
