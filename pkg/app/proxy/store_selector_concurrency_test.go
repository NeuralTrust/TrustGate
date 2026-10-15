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

package proxy_test

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStoreSelector_ConcurrentSelectionsMatchSequential(t *testing.T) {
	fx := newStoreFixture(grantA, grantB, grantC, grantD)
	selector := newStoreSelector(workedCatalog)
	models := []string{"gpt-4.1", "gpt6", "opus-5.5", "opus-4.8", "", "auto", "@openai/gpt-4.1", "@anthropic/opus-5.5"}
	outcome := func(model string) string {
		sel, err := fx.choose(selector, storeRequest(model, "", ""))
		if err != nil {
			return err.Error()
		}
		return sel.Link.Consumer.Consumer.Name
	}
	want := make(map[string]string, len(models))
	for _, m := range models {
		want[m] = outcome(m)
	}
	var wg sync.WaitGroup
	for i := range 64 {
		model := models[i%len(models)]
		wg.Go(func() {
			assert.Equal(t, want[model], outcome(model), "model %q", model)
		})
	}
	wg.Wait()
}

func BenchmarkStoreSelector_N10(b *testing.B) {
	grants := make([]storeGrant, 0, 10)
	for i := range 10 {
		grants = append(grants, storeGrant{name: fmt.Sprintf("G%d", i), level: levelGroup, priority: 1, regs: []storeRegistry{
			{provider: "openai", allowed: []string{"gpt-4o"}, def: "gpt-4o"}, {provider: "anthropic", def: "opus-4.8"},
		}})
	}
	fx := newStoreFixture(grants...)
	selector := newStoreSelector(workedCatalog)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := fx.choose(selector, storeRequest("opus-5.5", "", "")); err != nil {
			b.Fatal(err)
		}
	}
}
