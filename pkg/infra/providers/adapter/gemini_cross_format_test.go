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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGemini_CrossFormatToOpenAI_DropsUnusableFileReference pins RUN-1678
// item 3: a Gemini fileData reference (Cloud Storage or Files API) needs the
// caller's own Google credentials to resolve. Forwarding it verbatim to a
// non-Gemini target would not silently drop the image any more, it would
// hand the target an unusable URL it will 400 on. Cross-format adaptation
// must keep dropping it, exactly as before this fix (when Gemini never
// decoded the reference at all).
func TestGemini_CrossFormatToOpenAI_DropsUnusableFileReference(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		fileURI string
	}{
		{"cloud storage URI", "gs://attachments-bucket/cat.jpg"},
		{"files API URI", "https://generativelanguage.googleapis.com/v1beta/files/abc123"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `{"contents":[{"role":"user","parts":[{"text":"hi"},` +
				`{"fileData":{"mimeType":"image/jpeg","fileUri":"` + tc.fileURI + `"}}]}]}`

			reg := NewRegistry()
			out, err := reg.AdaptRequest([]byte(body), FormatGemini, FormatOpenAI)
			require.NoError(t, err, "cross-format adaptation must not turn an unusable reference into a hard error")
			assert.NotContains(t, string(out), tc.fileURI, "a Gemini-only reference must never reach a non-Gemini wire body")

			creq, err := reg.DecodeRequestFor(out, FormatOpenAI)
			require.NoError(t, err)
			require.Len(t, creq.Messages, 1)
			assert.Empty(t, creq.Messages[0].Images, "the unusable image must be dropped, not forwarded as a broken image_url")
		})
	}
}

// TestGemini_CrossFormatToOpenAI_KeepsInlineImage is the control case for the
// above: a base64 image has no such trust issue, so it must still cross
// formats fine.
func TestGemini_CrossFormatToOpenAI_KeepsInlineImage(t *testing.T) {
	t.Parallel()
	body := `{"contents":[{"role":"user","parts":[{"text":"hi"},` +
		`{"inlineData":{"mimeType":"image/png","data":"` + pngPixel1x1 + `"}}]}]}`

	reg := NewRegistry()
	out, err := reg.AdaptRequest([]byte(body), FormatGemini, FormatOpenAI)
	require.NoError(t, err)
	assert.Contains(t, string(out), pngPixel1x1)

	creq, err := reg.DecodeRequestFor(out, FormatOpenAI)
	require.NoError(t, err)
	require.Len(t, creq.Messages, 1)
	require.Len(t, creq.Messages[0].Images, 1)
	assert.Equal(t, "image/png", creq.Messages[0].Images[0].MediaType)
	assert.Equal(t, pngPixel1x1, creq.Messages[0].Images[0].Data)
}
