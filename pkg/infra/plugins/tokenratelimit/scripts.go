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

package tokenratelimit

import "github.com/go-redis/redis/v8"

var recordScript = redis.NewScript(`
local key        = KEYS[1]
local tokens     = tonumber(ARGV[1])
local window_sec = tonumber(ARGV[2])
local total = redis.call('INCRBY', key, tokens)
if redis.call('TTL', key) == -1 then
    redis.call('EXPIRE', key, window_sec)
end
return total
`)
