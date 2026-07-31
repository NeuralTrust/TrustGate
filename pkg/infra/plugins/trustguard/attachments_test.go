// Copyright 2026 NeuralTrust
package trustguard

import "testing"

func TestExtractPayloadAttachments_OpenAIImageAndFile(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
		"messages":[
			{"role":"user","content":[
				{"type":"text","text":"describe"},
				{"type":"image_url","image_url":{"url":"https://example.com/a.png"}},
				{"type":"file","file":{"filename":"doc.pdf","file_data":"JVBERi0x"}}
			]},
			{"role":"assistant","content":[{"type":"image_url","image_url":{"url":"https://example.com/skip.png"}}]}
		]
	}`)
	got := extractPayloadAttachments(raw)
	if len(got) != 2 {
		t.Fatalf("got %#v, want 2 user attachments", got)
	}
}

func TestExtractPayloadAttachments_GeminiInline(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"contents":[{"role":"user","parts":[{"inlineData":{"mimeType":"image/png","data":"abc"}}]}]}`)
	got := extractPayloadAttachments(raw)
	if len(got) != 1 || got[0].Data != "abc" || got[0].ContentType != "image/png" {
		t.Fatalf("got %#v", got)
	}
}
