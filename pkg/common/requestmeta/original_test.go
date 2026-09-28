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

package requestmeta

import (
	"context"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOriginalRequestOwnsHTTPBufferStrings(t *testing.T) {
	ip := []byte("203.0.113.42")
	key := []byte("User-Agent")
	value := []byte("client/1.0")
	borrowed := func(buffer []byte) string { return unsafe.String(unsafe.SliceData(buffer), len(buffer)) }
	ctx := NewContext(context.Background(), borrowed(ip), map[string][]string{borrowed(key): {borrowed(value)}})
	for _, buffer := range [][]byte{ip, key, value} {
		for i := range buffer {
			buffer[i] = 'x'
		}
	}
	got := FromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, "203.0.113.42", got.IP)
	assert.Equal(t, map[string][]string{"User-Agent": {"client/1.0"}}, got.Headers)
}
