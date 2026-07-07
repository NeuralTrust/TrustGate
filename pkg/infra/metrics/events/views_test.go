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

package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMetadataView_StripsBodies(t *testing.T) {
	t.Parallel()
	body := "response"
	evt := &Event{
		TraceID: "t-1",
		Request: Request{Body: "request"},
		Response: Response{
			Body: &body,
		},
	}
	meta := MetadataView(evt)
	require.NotNil(t, meta)
	assert.Equal(t, "", meta.Request.Body)
	assert.Nil(t, meta.Response.Body)
	assert.Equal(t, "t-1", meta.TraceID)
	assert.Equal(t, "request", evt.Request.Body)
}
