//go:build functional

package functional_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"

	"github.com/NeuralTrust/TrustGate/pkg/infra/console"
)

// ConsoleModelRequestsStub stands in for the console's llm-access-requests
// route: it checks the signature the way the console does and answers every
// check as a request for the provider's one registry, so the Store's request
// tool and page can be driven end to end. Filed requests are kept to assert on.
var ConsoleModelRequestsStub *consoleModelRequestsStub

type consoleModelRequestsStub struct {
	server *httptest.Server
	mu     sync.Mutex
	calls  []map[string]any
}

func (s *consoleModelRequestsStub) URL() string {
	return s.server.URL + "/api/internal/trustgate/llm-access-requests"
}

// Calls returns what the gateway posted, in order.
func (s *consoleModelRequestsStub) Calls() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.calls...)
}

// StartConsoleModelRequestsStub starts the stub once for the suite.
func StartConsoleModelRequestsStub() string {
	if ConsoleModelRequestsStub != nil {
		return ConsoleModelRequestsStub.URL()
	}
	stub := &consoleModelRequestsStub{}
	stub.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		timestamp := r.Header.Get(console.TimestampHeader)
		if r.Header.Get(console.SignatureHeader) != "v1="+console.Sign([]byte(os.Getenv("SERVER_SECRET_KEY")), timestamp, body) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var call map[string]any
		if err := json.Unmarshal(body, &call); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stub.mu.Lock()
		stub.calls = append(stub.calls, call)
		stub.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if call["action"] == "file" {
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "requested", "name": "Mistral"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "name": "Mistral", "provider": "mistral", "registry_id": "reg-mistral"})
	}))
	ConsoleModelRequestsStub = stub
	return stub.URL()
}

// StopConsoleModelRequestsStub tears the stub down at suite teardown.
func StopConsoleModelRequestsStub() {
	if ConsoleModelRequestsStub == nil {
		return
	}
	ConsoleModelRequestsStub.server.Close()
	ConsoleModelRequestsStub = nil
}
