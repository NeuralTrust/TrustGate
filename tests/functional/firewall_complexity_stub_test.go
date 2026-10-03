//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	firewallComplexityFunctionalSecret = "functional-firewall-secret"
	firewallComplexityPath             = "/v1/complexity"

	// Message-content markers the stub maps to deterministic complexity
	// scores, so each test drives routing purely through the prompt it sends
	// and never through shared mutable stub state.
	smartRouteLowContent   = "route-low-complexity"
	smartRouteHighContent  = "route-high-complexity"
	smartRouteErrorContent = "route-score-error"

	smartRouteLowScore  = 0.05
	smartRouteHighScore = 0.95
)

// FirewallComplexityStub is the process-wide stub the gateway binary dials for
// smart-routing complexity scores.
var FirewallComplexityStub *firewallComplexityStub

// StartFirewallComplexityStub boots the stub once and returns its base URL.
func StartFirewallComplexityStub() string {
	if FirewallComplexityStub != nil {
		return FirewallComplexityStub.URL()
	}
	FirewallComplexityStub = newFirewallComplexityStubServer()
	return FirewallComplexityStub.URL()
}

// StopFirewallComplexityStub tears the stub down at suite teardown.
func StopFirewallComplexityStub() {
	if FirewallComplexityStub == nil {
		return
	}
	FirewallComplexityStub.server.Close()
	FirewallComplexityStub = nil
}

// firewallComplexityStub is an in-process stand-in for the Firewall Complexity
// API. It maps well-known input markers to fixed scores so functional tests can
// assert smart-routing behaviour deterministically.
type firewallComplexityStub struct {
	server *httptest.Server
}

func (s *firewallComplexityStub) URL() string { return s.server.URL }

type firewallScoreRequest struct {
	Input          string `json:"input"`
	ConversationID string `json:"conversation_id"`
	TenantID       string `json:"tenant_id"`
}

type firewallScoreResponse struct {
	Score    float64 `json:"score"`
	RawScore float64 `json:"raw_score"`
}

func newFirewallComplexityStubServer() *firewallComplexityStub {
	stub := &firewallComplexityStub{}
	mux := http.NewServeMux()
	mux.HandleFunc(firewallComplexityPath, func(w http.ResponseWriter, r *http.Request) {
		if !isValidFirewallToken(r.Header.Get("token")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req firewallScoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case strings.Contains(req.Input, smartRouteErrorContent):
			w.WriteHeader(http.StatusInternalServerError)
		case strings.Contains(req.Input, smartRouteHighContent):
			writeFirewallScore(w, smartRouteHighScore)
		default:
			writeFirewallScore(w, smartRouteLowScore)
		}
	})
	stub.server = httptest.NewServer(mux)
	return stub
}

func isValidFirewallToken(signed string) bool {
	token, err := jwt.Parse(signed, func(token *jwt.Token) (any, error) {
		return []byte(firewallComplexityFunctionalSecret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || !token.Valid {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return ok && claims["purpose"] == "firewall"
}

func writeFirewallScore(w http.ResponseWriter, score float64) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(firewallScoreResponse{Score: score, RawScore: score})
}
