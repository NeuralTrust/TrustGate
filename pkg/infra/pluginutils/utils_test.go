package pluginutils

import (
	"testing"
)

func TestExtractText_PlainString(t *testing.T) {
	input := "hello world"
	got := ExtractText(input)
	if got != "hello world" {
		t.Fatalf("expected %q, got %q", "hello world", got)
	}
}

func TestExtractText_SimpleJSON(t *testing.T) {
	input := `{"question": "what is AI?"}`
	got := ExtractText(input)
	assertContainsAll(t, got, []string{"question", "what is AI?"})
}

func TestExtractText_NestedEscapedJSON(t *testing.T) {
	input := `{"question": "{\"next_step\": \"confirmed_turn_on\"}"}`
	got := ExtractText(input)
	assertContainsAll(t, got, []string{"question", "next step", "confirmed turn on"})
	assertNotContains(t, got, `\"`)
	assertNotContains(t, got, `{`)
}

func TestExtractText_DeeplyNestedJSON(t *testing.T) {
	input := `{"outer": "{\"inner\": \"{\\\"deep\\\": \\\"value\\\"}\"}"}`
	got := ExtractText(input)
	assertContainsAll(t, got, []string{"outer", "inner", "deep", "value"})
}

func TestExtractText_JSONArray(t *testing.T) {
	input := `["hello", "world"]`
	got := ExtractText(input)
	assertContainsAll(t, got, []string{"hello", "world"})
}

func TestExtractText_EmptyString(t *testing.T) {
	got := ExtractText("")
	if got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

func TestExtractText_SkipsNumbersAndBools(t *testing.T) {
	input := `{"name": "alice", "age": 30, "active": true}`
	got := ExtractText(input)
	assertContainsAll(t, got, []string{"name", "alice"})
	assertNotContains(t, got, "30")
	assertNotContains(t, got, "true")
}

func TestDefineRequestBody_CleanTrue_ExtractsText(t *testing.T) {
	body := []byte(`{"question": "{\"next_step\": \"confirmed_turn_on\"}"}`)
	got, err := DefineRequestBody(body, "question", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContainsAll(t, got.Input, []string{"next step", "confirmed turn on"})
	assertNotContains(t, got.Input, `{`)
}

func TestDefineRequestBody_CleanFalse_ReturnsRaw(t *testing.T) {
	body := []byte(`{"question": "{\"next_step\": \"confirmed_turn_on\"}"}`)
	got, err := DefineRequestBody(body, "question", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContainsAll(t, got.Input, []string{"next_step", "confirmed_turn_on"})
	// raw string still has JSON structure
	assertContainsAll(t, got.Input, []string{`"`})
}

func TestDefineRequestBody_CleanTrue_NoMapping(t *testing.T) {
	body := []byte(`{"key": "value"}`)
	got, err := DefineRequestBody(body, "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContainsAll(t, got.Input, []string{"key", "value"})
	assertNotContains(t, got.Input, `{`)
}

func TestDefineRequestBody_CleanTrue_NavigationFails(t *testing.T) {
	body := []byte(`{"question": "{\"next_step\": \"confirmed_turn_on\"}"}`)
	got, err := DefineRequestBody(body, "nonexistent_field", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertContainsAll(t, got.Input, []string{"question", "next step", "confirmed turn on"})
	assertNotContains(t, got.Input, `{`)
}

func TestDefineRequestBody_CleanTrue_NonJSON(t *testing.T) {
	body := []byte("just plain text")
	got, err := DefineRequestBody(body, "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Input != "just plain text" {
		t.Fatalf("expected %q, got %q", "just plain text", got.Input)
	}
}

func TestCleanInputs(t *testing.T) {
	inputs := []string{
		"plain text",
		`{"key": "value"}`,
	}
	got := CleanInputs(inputs)
	if got[0] != "plain text" {
		t.Fatalf("expected %q, got %q", "plain text", got[0])
	}
	assertContainsAll(t, got[1], []string{"key", "value"})
}

func assertContainsAll(t *testing.T, s string, subs []string) {
	t.Helper()
	for _, sub := range subs {
		if !contains(s, sub) {
			t.Errorf("expected %q to contain %q", s, sub)
		}
	}
}

func assertNotContains(t *testing.T, s string, sub string) {
	t.Helper()
	if contains(s, sub) {
		t.Errorf("expected %q NOT to contain %q", s, sub)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && searchString(s, sub)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
