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

package logref_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/logref"
	"github.com/stretchr/testify/require"
)

func TestOpaqueIsStableAndDoesNotExposeInput(t *testing.T) {
	const subject = "person@example.com"
	first := logref.Opaque("  " + subject + " ")
	second := logref.Opaque(subject)

	require.Equal(t, first, second)
	require.Len(t, first, 16)
	require.NotContains(t, first, subject)
}
