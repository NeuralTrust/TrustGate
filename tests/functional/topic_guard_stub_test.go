//go:build functional

package functional_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

const (
	topicGuardPath       = "/v1/topic-guard"
	topicGuardConfigPath = "/v1/topic-guard/config"
)

var topicGuardCalls = &topicGuardRecorder{}

type topicGuardRecorder struct {
	mu     sync.Mutex
	inputs []string
}

func (r *topicGuardRecorder) record(inputs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inputs = append(r.inputs, inputs...)
}

// sawText reports whether topic-guard was asked to classify a text containing
// marker.
func (r *topicGuardRecorder) sawText(marker string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, in := range r.inputs {
		if strings.Contains(in, marker) {
			return true
		}
	}
	return false
}

type topicGuardStubRequest struct {
	Input  []string `json:"input"`
	Topics []struct {
		Name string `json:"name"`
	} `json:"topics"`
}

// registerTopicGuardStub serves topic-guard next to the complexity stub, since
// both are reached through the same FIREWALL_BASE_URL and secret. Every topic
// scores 0.9 except "legal", which scores 0.1, so each result has one match
// and one miss.
func registerTopicGuardStub(mux *http.ServeMux) {
	mux.HandleFunc(topicGuardPath, func(w http.ResponseWriter, r *http.Request) {
		if !isValidFirewallToken(r.Header.Get("token")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req topicGuardStubRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		topicGuardCalls.record(req.Input)
		out := make([]map[string]any, len(req.Input))
		for i := range req.Input {
			scores := map[string]any{}
			var blocked []string
			for _, t := range req.Topics {
				p, hit := 0.9, true
				if t.Name == "legal" {
					p, hit = 0.1, false
				}
				scores[t.Name] = map[string]any{"topic": t.Name, "probability": p, "blocked": hit, "raw_score": p}
				if hit {
					blocked = append(blocked, t.Name)
				}
			}
			out[i] = map[string]any{
				"topic_scores":   scores,
				"is_blocked":     len(blocked) > 0,
				"blocked_topics": blocked,
				"n_windows":      1,
				"warnings":       []string{},
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc(topicGuardConfigPath, func(w http.ResponseWriter, r *http.Request) {
		if !isValidFirewallToken(r.Header.Get("token")) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"topic-guard","revision":"functional","candidate_revision":"stub"}`))
	})
}
