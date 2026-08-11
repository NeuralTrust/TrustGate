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

package listing

import "testing"

func TestPage_NormalizeAndOffset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		page       Page
		wantNumber int
		wantSize   int
		wantOffset int
	}{
		{name: "zero defaults", page: Page{}, wantNumber: 1, wantSize: 20, wantOffset: 0},
		{name: "page 2", page: Page{Number: 2, Size: 10}, wantNumber: 2, wantSize: 10, wantOffset: 10},
		{name: "negative clamped", page: Page{Number: -1, Size: -5}, wantNumber: 1, wantSize: 20, wantOffset: 0},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.page.Normalize()
			if got.Number != tc.wantNumber || got.Size != tc.wantSize {
				t.Fatalf("Normalize() = %+v, want number=%d size=%d", got, tc.wantNumber, tc.wantSize)
			}
			if off := tc.page.Offset(); off != tc.wantOffset {
				t.Fatalf("Offset() = %d, want %d", off, tc.wantOffset)
			}
		})
	}
}

func TestDirection_SQL(t *testing.T) {
	t.Parallel()
	if Asc.SQL() != "ASC" {
		t.Fatalf("Asc.SQL() = %q", Asc.SQL())
	}
	if Desc.SQL() != "DESC" {
		t.Fatalf("Desc.SQL() = %q", Desc.SQL())
	}
	if Direction("").SQL() != "DESC" {
		t.Fatalf("empty Direction.SQL() = %q, want DESC", Direction("").SQL())
	}
}

func TestSort_IsZero(t *testing.T) {
	t.Parallel()
	if !(Sort{}).IsZero() {
		t.Fatal("zero Sort should be IsZero")
	}
	if (Sort{Field: "name"}).IsZero() {
		t.Fatal("Sort with field should not be IsZero")
	}
}
