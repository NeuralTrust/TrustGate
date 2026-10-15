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
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pngPixel1x1 is a real 1x1 PNG, base64 encoded, in the shape Google's
// generateContent examples use for inlineData.
const pngPixel1x1 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

// TestGemini_RequestRoundTrip_PreservesInlineAndFileImages pins RUN-1678
// group 2: a Gemini request with an inline (base64) image and a Cloud
// Storage fileData reference must survive a decode->encode round trip, the
// path every redaction plugin takes once it rewrites the message text
// (regex_replace, trustguard mask, bedrock_guardrail anonymize all call
// EncodeRequest on the full canonical request, see rewriteRequest).
func TestGemini_RequestRoundTrip_PreservesInlineAndFileImages(t *testing.T) {
	t.Parallel()
	const fileURI = "gs://attachments-bucket/cat.jpg"
	body := `{"contents":[{"role":"user","parts":[` +
		`{"text":"describe these"},` +
		`{"inlineData":{"mimeType":"image/png","data":"` + pngPixel1x1 + `"}},` +
		`{"fileData":{"mimeType":"image/jpeg","fileUri":"` + fileURI + `"}}` +
		`]}]}`

	ad := &GeminiAdapter{}
	cr, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1, "an image-bearing user turn must not be dropped")
	msg := cr.Messages[0]
	assert.Equal(t, "describe these", msg.Content)
	require.Len(t, msg.Images, 2, "both the inlineData and fileData parts must decode into canonical images")
	assert.Equal(t, CanonicalImage{MediaType: "image/png", Data: pngPixel1x1}, msg.Images[0])
	assert.Equal(t, CanonicalImage{MediaType: "image/jpeg", URL: fileURI}, msg.Images[1])

	out, err := ad.EncodeRequest(cr)
	require.NoError(t, err)

	// Assert on the raw wire shape rather than the internal geminiPart type,
	// so this test also proves the bug (a build error) on the pre-fix code
	// that has no inlineData/fileData fields to decode into.
	raw := string(out)
	assert.Contains(t, raw, `"inlineData"`, "the base64 image must round-trip as inlineData")
	assert.Contains(t, raw, pngPixel1x1, "the inline image bytes must be unchanged")
	assert.Contains(t, raw, `"fileData"`, "the Cloud Storage reference must round-trip as fileData")
	assert.Contains(t, raw, fileURI, "the file URI must be unchanged")

	var reencoded map[string]any
	require.NoError(t, json.Unmarshal(out, &reencoded))
}

// TestGemini_RequestRoundTrip_PreservesModelTurnImage pins the follow-up to
// RUN-1678 group 2: an image-generation model (e.g. Gemini 2.5 Flash Image)
// returns inlineData in the MODEL turn, and a client replaying that turn as
// history sends it back the same way. EncodeRequest must not gate images to
// the user role only, unlike OpenAI/Anthropic/Bedrock, whose wire formats
// have no slot for an assistant-turn image at all.
func TestGemini_RequestRoundTrip_PreservesModelTurnImage(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"role":"user","parts":[{"text":"draw a cat"}]},` +
		`{"role":"model","parts":[{"text":"here it is"},` +
		`{"inlineData":{"mimeType":"image/png","data":"` + pngPixel1x1 + `"}}]}]}`

	ad := &GeminiAdapter{}
	cr, err := ad.DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 2)
	assistant := cr.Messages[1]
	assert.Equal(t, "assistant", assistant.Role)
	assert.Equal(t, "here it is", assistant.Content)
	require.Len(t, assistant.Images, 1, "the model-turn inlineData must decode into a canonical image")
	assert.Equal(t, CanonicalImage{MediaType: "image/png", Data: pngPixel1x1}, assistant.Images[0])

	out, err := ad.EncodeRequest(cr)
	require.NoError(t, err)
	raw := string(out)
	assert.Contains(t, raw, `"inlineData"`, "the model-turn image must round-trip as inlineData")
	assert.Contains(t, raw, pngPixel1x1, "the model-turn image bytes must be unchanged")
}

// TestGemini_DecodeRequest_DropsNonImageAttachments pins the documented gap:
// the canonical model has no home for non-image media (PDF, audio, video),
// so a non-image inlineData/fileData part is silently dropped, the same
// treatment any other part type this adapter does not model already gets
// (e.g. executableCode/codeExecutionResult).
func TestGemini_DecodeRequest_DropsNonImageAttachments(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"role":"user","parts":[` +
		`{"text":"see attached"},` +
		`{"inlineData":{"mimeType":"application/pdf","data":"UERGREFUQQ=="}},` +
		`{"fileData":{"mimeType":"application/pdf","fileUri":"gs://bucket/report.pdf"}}` +
		`]}]}`

	cr, err := (&GeminiAdapter{}).DecodeRequest([]byte(body))
	require.NoError(t, err)
	require.Len(t, cr.Messages, 1)
	assert.Equal(t, "see attached", cr.Messages[0].Content)
	assert.Empty(t, cr.Messages[0].Images, "non-image attachments have no canonical home and are dropped")
}
