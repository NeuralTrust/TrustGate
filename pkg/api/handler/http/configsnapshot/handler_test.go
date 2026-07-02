package configsnapshot_test

import (
	"io"
	"net/http"
	"testing"

	configsnapshothttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsnapshot"
	"github.com/gofiber/fiber/v2"
)

type stubSource struct {
	raw     []byte
	version string
	ok      bool
}

func (s stubSource) Snapshot() ([]byte, string, bool) {
	return s.raw, s.version, s.ok
}

func newApp(source configsnapshothttp.SnapshotSource) *fiber.App {
	app := fiber.New()
	handler := configsnapshothttp.NewHandler(source, nil)
	app.Get("/snapshot", handler.Get)
	return app
}

func TestHandlerServiceUnavailableWhenEmpty(t *testing.T) {
	app := newApp(stubSource{ok: false})
	req, _ := http.NewRequest(http.MethodGet, "/snapshot", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", resp.StatusCode)
	}
}

func TestHandlerReturnsSnapshotWithETag(t *testing.T) {
	app := newApp(stubSource{raw: []byte("payload"), version: "v1", ok: true})
	req, _ := http.NewRequest(http.MethodGet, "/snapshot", nil)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if got := resp.Header.Get(fiber.HeaderETag); got != `"v1"` {
		t.Fatalf("unexpected ETag: %q", got)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "payload" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestHandlerNotModified(t *testing.T) {
	app := newApp(stubSource{raw: []byte("payload"), version: "v1", ok: true})
	req, _ := http.NewRequest(http.MethodGet, "/snapshot", nil)
	req.Header.Set(fiber.HeaderIfNoneMatch, `"v1"`)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusNotModified {
		t.Fatalf("expected 304, got %d", resp.StatusCode)
	}
}

func TestHandlerServesWhenVersionDiffers(t *testing.T) {
	app := newApp(stubSource{raw: []byte("payload"), version: "v2", ok: true})
	req, _ := http.NewRequest(http.MethodGet, "/snapshot", nil)
	req.Header.Set(fiber.HeaderIfNoneMatch, `"v1"`)
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	if resp.StatusCode != fiber.StatusOK {
		t.Fatalf("expected 200 when version differs, got %d", resp.StatusCode)
	}
}
