package strutil

import "testing"

func TestLevenshteinDistance(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"", "abc", 3},
		{"abc", "", 3},
		{"abc", "abc", 0},
		{"ABC", "abc", 0},
		{"kitten", "sitting", 3},
		{"flaw", "lawn", 2},
	}
	for _, tc := range cases {
		if got := LevenshteinDistance(tc.a, tc.b); got != tc.want {
			t.Errorf("LevenshteinDistance(%q,%q)=%d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
