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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAIEmbeddings_TokenInputs(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		want  [][]int
		input string
	}{
		{name: "token ids", body: `{"model":"m","input":[1,2,3]}`, want: [][]int{{1, 2, 3}}, input: `[1,2,3]`},
		{name: "token id batches", body: `{"model":"m","input":[[1,2],[3]]}`, want: [][]int{{1, 2}, {3}}, input: `[[1,2],[3]]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			canonical, err := NewRegistry().DecodeRequestFor([]byte(tt.body), FormatOpenAIEmbeddings)
			require.NoError(t, err)
			emb, err := embeddingFromCanonical(canonical)
			require.NoError(t, err)
			assert.Equal(t, tt.want, emb.Tokens)
			assert.Empty(t, emb.Inputs)

			out, err := (&OpenAIEmbeddingsAdapter{}).EncodeRequest(canonical)
			require.NoError(t, err)
			assert.JSONEq(t, `{"model":"m","input":`+tt.input+`}`, string(out))

			same, err := AdaptEmbeddingRequest(NewRegistry(), []byte(tt.body), FormatOpenAIEmbeddings, FormatOpenAIEmbeddings)
			require.NoError(t, err)
			assert.Equal(t, tt.body, string(same))

			for _, target := range []Format{FormatCohereEmbed, FormatVertexEmbed, FormatBedrockTitanEmbed} {
				_, err := AdaptEmbeddingRequest(NewRegistry(), []byte(tt.body), FormatOpenAIEmbeddings, target)
				var contentErr *UnsupportedContentError
				assert.True(t, errors.As(err, &contentErr), "%s: err = %v", target, err)
			}
		})
	}
}

func TestOpenAIEmbeddings_TextInputsStillAdapt(t *testing.T) {
	out, err := AdaptEmbeddingRequest(NewRegistry(), []byte(`{"model":"embed-v4.0","input":["a","b"]}`), FormatOpenAIEmbeddings, FormatCohereEmbed)
	require.NoError(t, err)
	assert.JSONEq(t, `{"model":"embed-v4.0","texts":["a","b"],"input_type":"search_document","embedding_types":["float"]}`, string(out))
}

func TestOpenAIEmbeddings_MixedInputIsADecodeError(t *testing.T) {
	_, err := NewRegistry().DecodeRequestFor([]byte(`{"model":"m","input":[1,"a"]}`), FormatOpenAIEmbeddings)
	assert.True(t, IsRequestDecodeError(err), "err = %v", err)
}

func TestEmbeddingFromCanonical_NilRequest(t *testing.T) {
	emb, err := embeddingFromCanonical(nil)
	require.NoError(t, err)
	assert.Equal(t, &CanonicalEmbeddingRequest{}, emb)

	emb, err = textEmbeddingFromCanonical(nil)
	require.NoError(t, err)
	assert.Equal(t, &CanonicalEmbeddingRequest{}, emb)
}
