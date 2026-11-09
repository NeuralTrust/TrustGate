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

package configsnapshot

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeJSONPreservesEntitiesAndAdjustments(t *testing.T) {
	t.Parallel()
	type entity struct {
		Name   string
		Values []int
	}
	calls := 0
	got, err := decodeJSON[string, entity](
		[]string{`{"name":"first","values":[1]}`, `{"name":"second","values":[2]}`},
		"test entity",
		func(raw string) []byte { return []byte(raw) },
		func(_ string, value *entity) {
			value.Name += " adjusted"
			calls++
		},
	)
	require.NoError(t, err)
	require.Equal(t, []entity{{Name: "first adjusted", Values: []int{1}}, {Name: "second adjusted", Values: []int{2}}}, got)
	require.Equal(t, 2, calls)
	got[0].Values[0] = 99
	require.Equal(t, []int{2}, got[1].Values)
}

func TestDecodeJSONEmptyReturnsAnEmptySlice(t *testing.T) {
	t.Parallel()
	for _, messages := range [][]string{nil, {}} {
		got, err := decodeJSON[string, int](messages, "test entity", func(raw string) []byte { return []byte(raw) }, nil)
		require.NoError(t, err)
		require.NotNil(t, got)
		require.Empty(t, got)
	}
}

func TestDecodeJSONRejectsMalformedEntitiesWithoutPartialResults(t *testing.T) {
	t.Parallel()
	calls := 0
	got, err := decodeJSON[string, int]([]string{"1", "{"}, "test entity",
		func(raw string) []byte { return []byte(raw) },
		func(_ string, _ *int) { calls++ },
	)
	require.Nil(t, got)
	require.ErrorContains(t, err, "configsnapshot: unmarshal test entity")
	var syntax *json.SyntaxError
	require.ErrorAs(t, err, &syntax)
	require.Equal(t, 1, calls)
}
