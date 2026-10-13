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

package googlemodelarmor

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// A mask that cannot be applied after a filter gap was already recorded keeps
// the class-relevant detail in failure_detail, which is the one ClassOf reads
// with the reason, and still says what it replaced.
func TestAnonymizeDegradedKeepsTheEarlierFailureDetail(t *testing.T) {
	t.Parallel()
	p := pluginWithStub(newModelArmorStub(t, http.StatusOK, allowResponse))
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, modelArmorSettings(), reqCtx(openAIRequest()), nil)
	data := &Data{
		FailureReason: string(appplugins.FailureVerdictIncomplete),
		FailureDetail: reasonFilterNotInTemplate,
		FailureClass:  string(appplugins.FailureClassAvailability),
	}
	span := rewriteSpan{format: adapter.FormatOpenAI, rewrite: func(string) ([]byte, bool) { return []byte("x"), true }}

	_, err := p.anonymizeEnforce(context.Background(), in, data, "", &SanitizationResult{}, span, &finding{filter: filterSDP})
	if _, ok := appplugins.AsPluginError(err); !ok {
		t.Fatalf("expected *PluginError, got %v", err)
	}

	if data.FailureDetail != reasonAnonymizeNoOutput || data.FailureClass != "input" {
		t.Fatalf("failure_detail/class = %q/%q, want %s/input", data.FailureDetail, data.FailureClass, reasonAnonymizeNoOutput)
	}
	raw, marshalErr := json.Marshal(data)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	var wire map[string]any
	if jsonErr := json.Unmarshal(raw, &wire); jsonErr != nil {
		t.Fatal(jsonErr)
	}
	if wire["earlier_failure_detail"] != reasonFilterNotInTemplate {
		t.Fatalf("earlier_failure_detail = %v, want %s", wire["earlier_failure_detail"], reasonFilterNotInTemplate)
	}
}
