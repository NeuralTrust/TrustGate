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

package response

import (
	"encoding/json"
	"strings"
	"testing"

	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
)

func TestFromSourceListsReferencedStoresNotReported(t *testing.T) {
	t.Parallel()
	src := appsecretstore.Source{Supported: true, Kind: appsecretstore.KindDataPlane, Live: 1,
		Stores: []appsecretstore.StoreView{{Name: "corp-vault", Status: appsecretstore.StatusOK, Consistent: true}}}
	usages := map[string][]appsecretstore.Usage{
		"corp-vault": {{Field: "llm_target.auth.api_key.api_key"}},
		"gone":       {{Field: "mcp_target.headers.X"}, {Field: "mcp_target.auth.value"}},
	}
	got := FromSource(src, usages)
	if got.Source != "data_plane" || len(got.Stores) != 2 || got.Stores[0].Usages != 1 {
		t.Fatalf("response = %+v", got)
	}
	if got.Stores[1].Name != "gone" || got.Stores[1].Status != "not_reported" || got.Stores[1].Usages != 2 {
		t.Fatalf("missing store = %+v", got.Stores[1])
	}
	raw, _ := json.Marshal(FromSource(appsecretstore.Source{}, nil))
	if !strings.Contains(string(raw), `"supported":false`) || !strings.Contains(string(raw), `"stores":[]`) {
		t.Fatalf("unsupported = %s", raw)
	}
}
