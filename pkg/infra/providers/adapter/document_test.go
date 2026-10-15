// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package adapter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	pdfBase64  = "JVBERi0xLjQK"
	pptxBase64 = "UEsDBBQABgAIAAAAIQA="
	txtBase64  = "aG9sYSBtdW5kbw=="
	pptxType   = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
)

func openAIFilePart(filename, mediaType, data string) string {
	return `{"type":"file","file":{"filename":"` + filename + `","file_data":"data:` + mediaType + `;base64,` + data + `"}}`
}

func openAIBodyWithFiles(parts ...string) []byte {
	content := `{"type":"text","text":"summarize"}`
	for _, p := range parts {
		content += "," + p
	}
	return []byte(`{"model":"m","messages":[{"role":"user","content":[` + content + `]}]}`)
}

type converseBody struct {
	Messages []struct {
		Content []ConverseContentBlock `json:"content"`
	} `json:"messages"`
}

func converseDocuments(t *testing.T, body []byte) []ConverseDocumentBlock {
	t.Helper()
	var req converseBody
	require.NoError(t, json.Unmarshal(body, &req))
	var docs []ConverseDocumentBlock
	for _, m := range req.Messages {
		for _, b := range m.Content {
			if b.Document != nil {
				docs = append(docs, *b.Document)
			}
		}
	}
	return docs
}

type anthropicBody struct {
	Messages []struct {
		Content []anthropicContentBlock `json:"content"`
	} `json:"messages"`
}

func anthropicDocuments(t *testing.T, body []byte) []anthropicContentBlock {
	t.Helper()
	var req anthropicBody
	require.NoError(t, json.Unmarshal(body, &req))
	var docs []anthropicContentBlock
	for _, m := range req.Messages {
		for _, b := range m.Content {
			if b.Type == "document" {
				docs = append(docs, b)
			}
		}
	}
	return docs
}

func geminiInlineParts(t *testing.T, body []byte) []geminiBlob {
	t.Helper()
	var req geminiRequest
	require.NoError(t, json.Unmarshal(body, &req))
	var blobs []geminiBlob
	for _, c := range req.Contents {
		for _, p := range c.Parts {
			if p.InlineData != nil {
				blobs = append(blobs, *p.InlineData)
			}
		}
	}
	return blobs
}

func openAIFiles(t *testing.T, body []byte) []openaiFile {
	t.Helper()
	var req struct {
		Messages []struct {
			Content []openaiContentPart `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	var files []openaiFile
	for _, m := range req.Messages {
		for _, p := range m.Content {
			if p.Type != "file" {
				continue
			}
			var f openaiFile
			require.NoError(t, json.Unmarshal(p.File, &f))
			files = append(files, f)
		}
	}
	return files
}

func TestAdaptRequest_OpenAIFilesReachEveryTarget(t *testing.T) {
	t.Parallel()
	body := openAIBodyWithFiles(
		openAIFilePart("Informe Q3.pdf", "application/pdf", pdfBase64),
		openAIFilePart("notas.txt", "text/plain", txtBase64),
		openAIFilePart("deck_final.v2.pptx", pptxType, pptxBase64),
	)
	reg := NewRegistry()

	t.Run("bedrock", func(t *testing.T) {
		t.Parallel()
		out, err := reg.AdaptRequest(body, FormatOpenAI, FormatBedrock)
		require.NoError(t, err)
		docs := converseDocuments(t, out)
		require.Len(t, docs, 3)
		assert.Equal(t, "pdf", docs[0].Format)
		assert.Equal(t, "Informe Q3", docs[0].Name)
		assert.Equal(t, "%PDF-1.4\n", string(docs[0].Source.Bytes))
		assert.Equal(t, "txt", docs[1].Format)
		assert.Equal(t, "hola mundo", string(docs[1].Source.Bytes))
		assert.Equal(t, "pptx", docs[2].Format, "unsupported formats are forwarded for Bedrock to judge")
		assert.Equal(t, "deck-final-v2", docs[2].Name)
	})

	t.Run("anthropic", func(t *testing.T) {
		t.Parallel()
		out, err := reg.AdaptRequest(body, FormatOpenAI, FormatAnthropic)
		require.NoError(t, err)
		docs := anthropicDocuments(t, out)
		require.Len(t, docs, 3)
		assert.JSONEq(t, `{"type":"base64","media_type":"application/pdf","data":"`+pdfBase64+`"}`, string(docs[0].Source))
		assert.Equal(t, "Informe Q3.pdf", docs[0].Title)
		assert.JSONEq(t, `{"type":"text","media_type":"text/plain","data":"hola mundo"}`, string(docs[1].Source))
		assert.JSONEq(t, `{"type":"base64","media_type":"`+pptxType+`","data":"`+pptxBase64+`"}`, string(docs[2].Source))
	})

	t.Run("vertex", func(t *testing.T) {
		t.Parallel()
		out, err := reg.AdaptRequest(body, FormatOpenAI, FormatVertex)
		require.NoError(t, err)
		blobs := geminiInlineParts(t, out)
		require.Len(t, blobs, 3)
		assert.Equal(t, geminiBlob{MimeType: "application/pdf", Data: pdfBase64}, blobs[0])
		assert.Equal(t, geminiBlob{MimeType: "text/plain", Data: txtBase64}, blobs[1])
		assert.Equal(t, geminiBlob{MimeType: pptxType, Data: pptxBase64}, blobs[2])
	})
}

func TestAdaptRequest_DocumentsReachOpenAIAndBedrock(t *testing.T) {
	t.Parallel()
	anthropic := []byte(`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":[` +
		`{"type":"document","title":"report.pdf","source":{"type":"base64","media_type":"application/pdf","data":"` + pdfBase64 + `"}},` +
		`{"type":"document","source":{"type":"text","media_type":"text/plain","data":"hola mundo"}},` +
		`{"type":"text","text":"summarize"}]}]}`)
	gemini := []byte(`{"contents":[{"role":"user","parts":[{"text":"summarize"},` +
		`{"inlineData":{"mimeType":"application/pdf","data":"` + pdfBase64 + `"}},` +
		`{"inline_data":{"mime_type":"text/plain","data":"` + txtBase64 + `"}}]}]}`)

	tests := []struct {
		name   string
		body   []byte
		source Format
	}{
		{name: "anthropic", body: anthropic, source: FormatAnthropic},
		{name: "gemini", body: gemini, source: FormatGemini},
	}
	reg := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := reg.AdaptRequest(tt.body, tt.source, FormatOpenAI)
			require.NoError(t, err)
			files := openAIFiles(t, out)
			require.Len(t, files, 2)
			assert.Equal(t, "data:application/pdf;base64,"+pdfBase64, files[0].FileData)
			assert.Equal(t, "data:text/plain;base64,"+txtBase64, files[1].FileData)
			assert.NotEmpty(t, files[0].Filename, "OpenAI types a file by its name")

			out, err = reg.AdaptRequest(tt.body, tt.source, FormatBedrock)
			require.NoError(t, err)
			docs := converseDocuments(t, out)
			require.Len(t, docs, 2)
			assert.Equal(t, "pdf", docs[0].Format)
			assert.Equal(t, "txt", docs[1].Format)
			assert.NotEqual(t, docs[0].Name, docs[1].Name, "Bedrock rejects repeated document names")
		})
	}
}

func TestAdaptRequest_DocumentTheTargetCannotResolve(t *testing.T) {
	t.Parallel()
	fileID := openAIBodyWithFiles(`{"type":"file","file":{"file_id":"file-abc123"}}`)
	url := []byte(`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":[` +
		`{"type":"document","source":{"type":"url","url":"https://example.com/report.pdf"}},{"type":"text","text":"hi"}]}]}`)

	tests := []struct {
		name   string
		body   []byte
		source Format
		target Format
	}{
		{name: "openai file id to bedrock", body: fileID, source: FormatOpenAI, target: FormatBedrock},
		{name: "openai file id to anthropic", body: fileID, source: FormatOpenAI, target: FormatAnthropic},
		{name: "openai file id to vertex", body: fileID, source: FormatOpenAI, target: FormatVertex},
		{name: "document url to bedrock", body: url, source: FormatAnthropic, target: FormatBedrock},
		{name: "document url to openai", body: url, source: FormatAnthropic, target: FormatOpenAI},
	}
	reg := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := reg.AdaptRequest(tt.body, tt.source, tt.target)
			require.ErrorIs(t, err, ErrUnsupportedContent)
			assert.NotContains(t, err.Error(), "example.com")
			assert.NotContains(t, err.Error(), "file-abc123")
		})
	}
}

func TestEncodeRequest_RedactionReencodeKeepsDocumentsInPlace(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		format Format
		body   string
		want   string
	}{
		{
			name:   "openai",
			format: FormatOpenAI,
			body:   string(openAIBodyWithFiles(openAIFilePart("a.pdf", "application/pdf", pdfBase64), `{"type":"file","file":{"file_id":"file-abc123"}}`)),
			want:   `[{"type":"text","text":"summarize"},{"type":"file","file":{"file_data":"data:application/pdf;base64,` + pdfBase64 + `","filename":"a.pdf"}},{"type":"file","file":{"file_id":"file-abc123"}}]`,
		},
		{
			name:   "anthropic",
			format: FormatAnthropic,
			body:   `{"model":"m","max_tokens":5,"messages":[{"role":"user","content":[{"type":"text","text":"summarize"},{"type":"document","source":{"type":"url","url":"https://example.com/a.pdf"}}]}]}`,
			want:   `[{"type":"text","text":"summarize"},{"type":"document","source":{"type":"url","url":"https://example.com/a.pdf"}}]`,
		},
		{
			name:   "gemini",
			format: FormatGemini,
			body:   `{"contents":[{"role":"user","parts":[{"text":"summarize"},{"fileData":{"mimeType":"application/pdf","fileUri":"gs://bucket/a.pdf"}}]}]}`,
			want:   `[{"text":"summarize"},{"fileData":{"mimeType":"application/pdf","fileUri":"gs://bucket/a.pdf"}}]`,
		},
		{
			name:   "bedrock",
			format: FormatBedrock,
			body:   `{"messages":[{"role":"user","content":[{"text":"summarize"},{"document":{"format":"docx","name":"spec","source":{"bytes":"UEsDBA=="}}}]}]}`,
			want:   `[{"text":"summarize"},{"document":{"format":"docx","name":"spec","source":{"bytes":"UEsDBA=="}}}]`,
		},
	}
	reg := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ad, err := reg.GetAdapter(tt.format)
			require.NoError(t, err)
			cr, err := ad.DecodeRequest([]byte(tt.body))
			require.NoError(t, err)
			cr.Messages[0].Content = "[REDACTED]"
			out, err := ad.EncodeRequest(cr)
			require.NoError(t, err)

			var generic map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &generic))
			var content json.RawMessage
			if raw, ok := generic["contents"]; ok {
				var contents []struct {
					Parts json.RawMessage `json:"parts"`
				}
				require.NoError(t, json.Unmarshal(raw, &contents))
				content = contents[0].Parts
			} else {
				var msgs []struct {
					Content json.RawMessage `json:"content"`
				}
				require.NoError(t, json.Unmarshal(generic["messages"], &msgs))
				content = msgs[0].Content
			}
			assert.JSONEq(t, string(replaceText(t, []byte(tt.want), "summarize", "[REDACTED]")), string(content))
		})
	}
}

func replaceText(t *testing.T, raw []byte, from, to string) []byte {
	t.Helper()
	var v any
	require.NoError(t, json.Unmarshal(raw, &v))
	var walk func(any) any
	walk = func(n any) any {
		switch x := n.(type) {
		case map[string]any:
			for k, val := range x {
				x[k] = walk(val)
			}
		case []any:
			for i, val := range x {
				x[i] = walk(val)
			}
		case string:
			if x == from {
				return to
			}
		}
		return n
	}
	out, err := json.Marshal(walk(v))
	require.NoError(t, err)
	return out
}

func TestParseDocumentData(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		raw      string
		filename string
		want     CanonicalDocument
	}{
		{
			name:     "pdf data uri",
			raw:      "data:application/pdf;base64," + pdfBase64,
			filename: "a.pdf",
			want:     CanonicalDocument{MediaType: "application/pdf", Data: pdfBase64, Name: "a.pdf"},
		},
		{
			name:     "media type parameters dropped",
			raw:      "data:text/plain;charset=utf-8;base64," + txtBase64,
			filename: "a.txt",
			want:     CanonicalDocument{MediaType: "text/plain", Data: txtBase64, Name: "a.txt"},
		},
		{
			name:     "octet stream inferred from filename",
			raw:      "data:application/octet-stream;base64," + pptxBase64,
			filename: "deck.PPTX",
			want:     CanonicalDocument{MediaType: pptxType, Data: pptxBase64, Name: "deck.PPTX"},
		},
		{
			name:     "bare base64 typed by filename",
			raw:      pdfBase64,
			filename: "a.pdf",
			want:     CanonicalDocument{MediaType: "application/pdf", Data: pdfBase64, Name: "a.pdf"},
		},
		{
			name: "https url typed by its path",
			raw:  "https://example.com/a.pdf?sig=x.y",
			want: CanonicalDocument{MediaType: "application/pdf", URL: "https://example.com/a.pdf?sig=x.y"},
		},
		{
			name: "https url without extension stays untyped",
			raw:  "https://example.com/download?id=1",
			want: CanonicalDocument{URL: "https://example.com/download?id=1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, parseDocumentData(tt.raw, "", tt.filename))
		})
	}
}

func TestDocumentFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  CanonicalDocument
		want string
	}{
		{name: "known media type", doc: CanonicalDocument{MediaType: "application/pdf"}, want: "pdf"},
		{name: "office type", doc: CanonicalDocument{MediaType: pptxType}, want: "pptx"},
		{name: "filename extension fallback", doc: CanonicalDocument{MediaType: "application/zip", Name: "bundle.ZIP"}, want: "zip"},
		{name: "unknown text type", doc: CanonicalDocument{MediaType: "text/x-log"}, want: "txt"},
		{name: "nothing to go on", doc: CanonicalDocument{MediaType: "application/octet-stream"}, want: ""},
		{name: "dotted title gives no format", doc: CanonicalDocument{MediaType: "application/octet-stream", Name: "Q3 v1.2 final"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, documentFormat(tt.doc))
		})
	}
}

func TestConverseDocumentNames(t *testing.T) {
	t.Parallel()
	names := converseDocumentNames{}
	assert.Equal(t, "Informe Q3 [final] (v2)", names.next("Informe  Q3 [final] (v2).pdf"))
	assert.Equal(t, "Presentaci-n-2026", names.next("Presentación_2026.pptx"))
	assert.Equal(t, "document", names.next(""))
	assert.Equal(t, "document (2)", names.next(".txt"))
	assert.Equal(t, "Informe Q3 [final] (v2) (2)", names.next("Informe Q3 [final] (v2).docx"))
	assert.Equal(t, "Dr- Smith report", names.next("Dr. Smith report"), "a dot inside a title is not an extension")
	long := names.next(strings.Repeat("a", 300) + ".pdf")
	assert.Len(t, long, maxConverseDocumentNameLen)
}

func TestDocumentFilename(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		doc  CanonicalDocument
		want string
	}{
		{name: "keeps client filename", doc: CanonicalDocument{MediaType: "application/pdf", Name: "a.PDF"}, want: "a.PDF"},
		{name: "adds extension to a bare title", doc: CanonicalDocument{MediaType: "application/pdf", Name: "Informe Q3"}, want: "Informe Q3.pdf"},
		{name: "dotted title is not an extension", doc: CanonicalDocument{MediaType: "text/plain", Name: "Q3 v1.2 final"}, want: "Q3 v1.2 final.txt"},
		{name: "unnamed", doc: CanonicalDocument{MediaType: pptxType}, want: "document.pptx"},
		{name: "unnamed and untyped", doc: CanonicalDocument{MediaType: "application/octet-stream"}, want: "document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, documentFilename(tt.doc))
		})
	}
}

func TestAdaptRequest_BedrockDocumentNameBecomesOpenAIFilename(t *testing.T) {
	t.Parallel()
	body := []byte(`{"messages":[{"role":"user","content":[{"text":"summarize"},` +
		`{"document":{"format":"pdf","name":"Informe Q3","source":{"bytes":"` + pdfBase64 + `"}}},` +
		`{"document":{"format":"md","name":"notes","source":{"text":"# hola"}}}]}]}`)
	out, err := NewRegistry().AdaptRequest(body, FormatBedrock, FormatOpenAI)
	require.NoError(t, err)
	files := openAIFiles(t, out)
	require.Len(t, files, 2)
	assert.Equal(t, openaiFile{FileData: "data:application/pdf;base64," + pdfBase64, Filename: "Informe Q3.pdf"}, files[0])
	assert.Equal(t, openaiFile{FileData: "data:text/markdown;base64," + base64.StdEncoding.EncodeToString([]byte("# hola")), Filename: "notes.md"}, files[1])
}

func TestAdaptRequest_AnthropicDocumentSources(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":[` +
		`{"type":"document","title":"Quarterly report","source":{"type":"base64","data":"` + pdfBase64 + `"}},` +
		`{"type":"document","source":{"type":"content","content":[{"type":"text","text":"uno"},{"type":"text","text":"dos"}]}},` +
		`{"type":"document","source":{"type":"text","media_type":"text/plain","data":""}},` +
		`{"type":"text","text":"summarize"}]}]}`)
	reg := NewRegistry()

	out, err := reg.AdaptRequest(body, FormatAnthropic, FormatOpenAI)
	require.NoError(t, err)
	files := openAIFiles(t, out)
	require.Len(t, files, 2, "an empty text source carries nothing and is not a document")
	assert.Equal(t, openaiFile{FileData: "data:application/pdf;base64," + pdfBase64, Filename: "Quarterly report.pdf"}, files[0])
	assert.Equal(t, "data:text/plain;base64,"+base64.StdEncoding.EncodeToString([]byte("uno\ndos")), files[1].FileData)

	fileRef := []byte(`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":[` +
		`{"type":"document","source":{"type":"file","file_id":"file_011abc"}},{"type":"text","text":"summarize"}]}]}`)
	ad, err := reg.GetAdapter(FormatAnthropic)
	require.NoError(t, err)
	cr, err := ad.DecodeRequest(fileRef)
	require.NoError(t, err)
	reencoded, err := ad.EncodeRequest(cr)
	require.NoError(t, err)
	docs := anthropicDocuments(t, reencoded)
	require.Len(t, docs, 1)
	assert.JSONEq(t, `{"type":"file","file_id":"file_011abc"}`, string(docs[0].Source), "an Anthropic file reference survives a same-format re-encode")

	_, err = reg.AdaptRequest(fileRef, FormatAnthropic, FormatOpenAI)
	require.ErrorIs(t, err, ErrUnsupportedContent, "OpenAI cannot resolve an Anthropic file id")
}

func TestGeminiFileDataParts(t *testing.T) {
	t.Parallel()
	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"compare"},` +
		`{"fileData":{"mimeType":"application/pdf","fileUri":"gs://bucket/a.pdf"}},` +
		`{"file_data":{"mime_type":"image/png","file_uri":"gs://bucket/b.png"}},` +
		`{"fileData":{"fileUri":"https://generativelanguage.googleapis.com/v1beta/files/abc"}}]}]}`)
	ad := &GeminiAdapter{}
	cr, err := ad.DecodeRequest(body)
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, []CanonicalImage{{MediaType: "image/png", URL: "gs://bucket/b.png"}}, cr.Messages[0].Images)
	assert.Equal(t, []CanonicalDocument{
		{MediaType: "application/pdf", URL: "gs://bucket/a.pdf"},
		{URL: "https://generativelanguage.googleapis.com/v1beta/files/abc"},
	}, cr.Messages[0].Documents)

	out, err := ad.EncodeRequest(cr)
	require.NoError(t, err)
	assert.Contains(t, string(out), `{"fileData":{"fileUri":"https://generativelanguage.googleapis.com/v1beta/files/abc"}}`,
		"a mimeType the client did not send is not invented on re-encode")

	_, err = NewRegistry().AdaptRequest(body, FormatGemini, FormatAnthropic)
	require.ErrorIs(t, err, ErrUnsupportedContent, "Anthropic cannot fetch a Cloud Storage URI")
}

func TestGeminiDecodeRequest_RolelessTurnIsUser(t *testing.T) {
	t.Parallel()
	cr, err := (&GeminiAdapter{}).DecodeRequest([]byte(`{"contents":[{"parts":[{"text":"hi"}]}]}`))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, "user", cr.Messages[0].Role)
}

func TestConverseDocumentFromCanonical_UnknownType(t *testing.T) {
	t.Parallel()
	doc := CanonicalDocument{MediaType: "application/octet-stream", Data: base64.StdEncoding.EncodeToString([]byte("x"))}
	_, err := converseDocumentFromCanonical(doc, converseDocumentNames{})
	require.ErrorIs(t, err, ErrUnsupportedContent)
}

func TestAdaptRequest_ImagesCrossGemini(t *testing.T) {
	t.Parallel()
	const png = "iVBORw0KGgo="
	reg := NewRegistry()

	out, err := reg.AdaptRequest([]byte(`{"model":"m","messages":[{"role":"user","content":[`+
		`{"type":"text","text":"what colour?"},{"type":"image_url","image_url":{"url":"data:image/png;base64,`+png+`"}}]}]}`), FormatOpenAI, FormatVertex)
	require.NoError(t, err)
	assert.Equal(t, []geminiBlob{{MimeType: "image/png", Data: png}}, geminiInlineParts(t, out))

	out, err = reg.AdaptRequest([]byte(`{"model":"m","messages":[{"role":"user","content":[`+
		`{"type":"text","text":"what colour?"},{"type":"image_url","image_url":{"url":"https://example.com/cat.PNG?v=2"}}]}]}`), FormatOpenAI, FormatVertex)
	require.NoError(t, err)
	assert.Contains(t, string(out), `{"fileData":{"mimeType":"image/png","fileUri":"https://example.com/cat.PNG?v=2"}}`)

	out, err = reg.AdaptRequest([]byte(`{"contents":[{"parts":[{"text":"what colour?"},`+
		`{"inlineData":{"mimeType":"image/png","data":"`+png+`"}}]}]}`), FormatGemini, FormatAnthropic)
	require.NoError(t, err)
	assert.JSONEq(t, `{"messages":[{"role":"user","content":[`+
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"`+png+`"}},`+
		`{"type":"text","text":"what colour?"}]}],"max_tokens":8192}`, string(out))
}

func TestAdaptRequest_DocumentsKeepTheClientOrder(t *testing.T) {
	t.Parallel()
	pdf := openAIFilePart("a.pdf", "application/pdf", pdfBase64)
	question := `{"type":"text","text":"summarize"}`
	tests := []struct {
		name      string
		content   string
		wantFirst string
	}{
		{name: "question then document", content: question + "," + pdf, wantFirst: "text"},
		{name: "document then question", content: pdf + "," + question, wantFirst: "document"},
	}
	reg := NewRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			body := []byte(`{"model":"m","messages":[{"role":"user","content":[` + tt.content + `]}]}`)

			out, err := reg.AdaptRequest(body, FormatOpenAI, FormatBedrock)
			require.NoError(t, err)
			var conv converseBody
			require.NoError(t, json.Unmarshal(out, &conv))
			require.Len(t, conv.Messages[0].Content, 2)
			assert.Equal(t, tt.wantFirst == "document", conv.Messages[0].Content[0].Document != nil)

			out, err = reg.AdaptRequest(body, FormatOpenAI, FormatVertex)
			require.NoError(t, err)
			var gem geminiRequest
			require.NoError(t, json.Unmarshal(out, &gem))
			require.Len(t, gem.Contents[0].Parts, 2)
			assert.Equal(t, tt.wantFirst == "document", gem.Contents[0].Parts[0].InlineData != nil)

			out, err = reg.AdaptRequest(body, FormatOpenAI, FormatAnthropic)
			require.NoError(t, err)
			var anth anthropicBody
			require.NoError(t, json.Unmarshal(out, &anth))
			require.Len(t, anth.Messages[0].Content, 2)
			assert.Equal(t, tt.wantFirst, anth.Messages[0].Content[0].Type)
		})
	}
}
