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

package adapter

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnescapeHTML(t *testing.T) {
	t.Parallel()
	cases := map[string]struct{ in, want string }{
		"no escapes":              {`{"a":"x < y"}`, `{"a":"x < y"}`},
		"html escapes":            {`{"a":"x\u003cy\u003Ez\u0026"}`, `{"a":"x<y>z&"}`},
		"escaped backslash":       {`{"a":"\\u003c"}`, `{"a":"\\u003c"}`},
		"other escapes kept":      {`{"a":"\u00e9\n\"\u003c\"\u2028"}`, `{"a":"\u00e9\n\"<\"\u2028"}`},
		"keys and nested strings": {`{"\u003ck":[1,{"v":"\u0026"}]}`, `{"<k":[1,{"v":"&"}]}`},
		"marshal output":          {string(mustMarshal(map[string]string{"t": "<a href=\"x\">&amp;</a>"})), `{"t":"<a href=\"x\">&amp;</a>"}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := string(unescapeHTML([]byte(tc.in)))
			assert.Equal(t, tc.want, got)
			var in, out any
			require.NoError(t, json.Unmarshal([]byte(tc.in), &in))
			require.NoError(t, json.Unmarshal([]byte(got), &out))
			assert.Equal(t, in, out)
		})
	}
}
