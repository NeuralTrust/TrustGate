package token_rate_limiter

// This file contains Redis Lua scripts for atomic token bucket operations.
//
// Each script runs as a single atomic operation inside Redis: no other client
// can read or write the bucket key while the script executes. This guarantees
// correctness across multiple TrustGate instances without in-process locking.
//
// The go-redis NewScript helper caches scripts via EVALSHA (only the SHA hash
// is sent after the first execution), avoiding the overhead of transmitting the
// Lua source on every request.

import "github.com/go-redis/redis/v8"

// consumeScript atomically refills the token bucket based on elapsed time,
// checks whether enough tokens are available, and deducts if so.
//
// KEYS[1] = bucket hash key
// ARGV[1] = bucket_size      (int)
// ARGV[2] = refill_rate      (tokens per window)
// ARGV[3] = window_ms        (window duration in milliseconds)
// ARGV[4] = tokens_to_consume (int)
// ARGV[5] = now_ms           (current time in milliseconds)
//
// Returns {allowed (0/1), remaining_tokens, last_refill_ms}.
var consumeScript = redis.NewScript(`
local key            = KEYS[1]
local bucket_size    = tonumber(ARGV[1])
local refill_rate    = tonumber(ARGV[2])
local window_ms      = tonumber(ARGV[3])
local to_consume     = tonumber(ARGV[4])
local now            = tonumber(ARGV[5])

local data = redis.call('HMGET', key, 'tokens', 'last_refill_ms')
local tokens      = tonumber(data[1])
local last_refill = tonumber(data[2])

if tokens == nil then
    tokens      = bucket_size
    last_refill = now
end

-- Refill proportionally to elapsed time
if refill_rate > 0 and window_ms > 0 then
    local elapsed = now - last_refill
    if elapsed > 0 then
        local to_add = math.floor(elapsed * refill_rate / window_ms)
        if to_add > 0 then
            tokens      = math.min(tokens + to_add, bucket_size)
            last_refill = now
        end
    end
end

-- Check capacity
if tokens < to_consume then
    return {0, tokens, last_refill}
end

-- Deduct and persist
tokens = tokens - to_consume
redis.call('HMSET', key, 'tokens', tokens, 'last_refill_ms', last_refill)
redis.call('EXPIRE', key, 86400)
return {1, tokens, last_refill}
`)

// adjustScript atomically adjusts the bucket by a signed delta after the
// actual token usage is known (PreResponse stage). Positive delta means more
// tokens were used than reserved; negative means fewer.
//
// KEYS[1] = bucket hash key
// ARGV[1] = delta       (signed int: actual - reserved)
// ARGV[2] = bucket_size (int, upper cap)
//
// Returns {remaining_tokens}.
var adjustScript = redis.NewScript(`
local key         = KEYS[1]
local delta       = tonumber(ARGV[1])
local bucket_size = tonumber(ARGV[2])

local tokens = tonumber(redis.call('HGET', key, 'tokens'))
if tokens == nil then
    return {bucket_size}
end

tokens = tokens - delta
if tokens < 0 then
    tokens = 0
end
if tokens > bucket_size then
    tokens = bucket_size
end

redis.call('HSET', key, 'tokens', tokens)
return {tokens}
`)
