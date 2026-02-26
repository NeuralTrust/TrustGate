package token_rate_limiter

import "github.com/go-redis/redis/v8"

// recordScript atomically increments the consumed-token counter for a client
// and sets the TTL only on the first write so the window resets naturally when
// the key expires.
//
// KEYS[1] = counter key
// ARGV[1] = tokens to add   (int)
// ARGV[2] = window_seconds  (int, used as TTL on first write)
//
// Returns {new_total}.
var recordScript = redis.NewScript(`
local key        = KEYS[1]
local tokens     = tonumber(ARGV[1])
local window_sec = tonumber(ARGV[2])

local total = redis.call('INCRBY', key, tokens)

-- Set TTL only when the key is brand-new (TTL returns -1 for keys without expiry).
if redis.call('TTL', key) == -1 then
    redis.call('EXPIRE', key, window_sec)
end

return total
`)
