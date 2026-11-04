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

package proxy

import (
	"testing"

	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyIntentToBody_StampsThePathModelOnVertexPredict(t *testing.T) {
	t.Parallel()
	req := &infracontext.RequestContext{
		SourceFormat: string(adapter.FormatVertexPredictEmbed),
		Path:         "/c/v1/projects/p/locations/global/publishers/google/models/gemini-embedding-001:predict",
		Body:         []byte(`{"instances":[{"content":"a"}]}`),
	}
	ref, err := modelRefFromRequest(req)
	require.NoError(t, err)
	intent, err := routingdomain.ParseModelRef(ref)
	require.NoError(t, err)

	applyIntentToBody(req, intent)

	model, err := adapter.ExtractModel(req.Body)
	require.NoError(t, err)
	assert.Equal(t, "gemini-embedding-001", model)
	assert.Equal(t, "gemini-embedding-001", resolveSentModel(req.Body, req))
}

func TestApplyIntentToBody_LeavesOpenAIEmbeddingsBodyAlone(t *testing.T) {
	t.Parallel()
	body := []byte(`{"model":"text-embedding-3-small","input":"a"}`)
	req := &infracontext.RequestContext{
		SourceFormat: string(adapter.FormatOpenAIEmbeddings),
		Path:         "/c/v1/embeddings",
		Body:         body,
	}
	intent, err := routingdomain.ParseModelRef("text-embedding-3-small")
	require.NoError(t, err)

	applyIntentToBody(req, intent)

	assert.Equal(t, body, req.Body)
}
