package adapter

import (
	"encoding/json"
	"testing"
)

func TestOverrideModel(t *testing.T) {
	t.Parallel()

	decode := func(t *testing.T, body []byte) map[string]json.RawMessage {
		t.Helper()
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(body, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		return raw
	}

	t.Run("rewrites the model field", func(t *testing.T) {
		t.Parallel()
		out := OverrideModel([]byte(`{"model":"openai/gpt-5","x":1}`), "gpt-5")
		raw := decode(t, out)
		if string(raw["model"]) != `"gpt-5"` {
			t.Fatalf("model = %s", raw["model"])
		}
	})

	t.Run("body with only modelId keeps using modelId", func(t *testing.T) {
		t.Parallel()
		out := OverrideModel([]byte(`{"modelId":"old"}`), "new")
		raw := decode(t, out)
		if string(raw["modelId"]) != `"new"` {
			t.Fatalf("modelId = %s", raw["modelId"])
		}
		if _, ok := raw["model"]; ok {
			t.Fatal("model key must not be introduced for modelId-only bodies")
		}
	})

	t.Run("empty model is a no-op", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"model":"keep"}`)
		out := OverrideModel(body, "")
		if string(out) != string(body) {
			t.Fatalf("body changed: %s", out)
		}
	})
}

func TestStripModel(t *testing.T) {
	t.Parallel()

	t.Run("removes both model keys", func(t *testing.T) {
		t.Parallel()
		out := StripModel([]byte(`{"model":"pool:x","modelId":"y","z":1}`))
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(out, &raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if _, ok := raw["model"]; ok {
			t.Fatal("model not stripped")
		}
		if _, ok := raw["modelId"]; ok {
			t.Fatal("modelId not stripped")
		}
		if _, ok := raw["z"]; !ok {
			t.Fatal("unrelated field lost")
		}
	})

	t.Run("body without model keys is untouched", func(t *testing.T) {
		t.Parallel()
		body := []byte(`{"messages":[]}`)
		if out := StripModel(body); string(out) != string(body) {
			t.Fatalf("body changed: %s", out)
		}
	})
}
