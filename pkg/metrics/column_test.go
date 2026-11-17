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

package metrics

import "testing"

func TestRawColumnsMatchReadColumns(t *testing.T) {
	read := make(map[string]bool)
	for _, c := range ReadColumns() {
		read[c] = true
	}
	for _, c := range RawColumns() {
		if !read[c.Name] {
			t.Errorf("raw column %q not present in ReadColumns", c.Name)
		}
	}
	if len(RawColumns()) != len(ReadColumns()) {
		t.Errorf("RawColumns len = %d, ReadColumns len = %d", len(RawColumns()), len(ReadColumns()))
	}
}

func TestRawColumnsCorrelationIDsAreNullableStrings(t *testing.T) {
	want := map[string]bool{ColumnClientTraceID: false, ColumnMCPSessionID: false}
	for _, c := range RawColumns() {
		if _, ok := want[c.Name]; !ok {
			continue
		}
		want[c.Name] = true
		if c.Type != ColumnTypeString || !c.Nullable {
			t.Errorf("raw column %q = %+v, want a nullable string: rows written before it existed have none", c.Name, c)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("raw column %q missing from RawColumns", name)
		}
	}
}
