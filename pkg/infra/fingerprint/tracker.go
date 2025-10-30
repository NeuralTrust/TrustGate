package fingerprint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/cache"
	"github.com/NeuralTrust/TrustGate/pkg/utils"
	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
)

const (
	DefaultExpiration         = 5 * time.Minute
	fingerPrintKey            = "fp:%s"
	fingerPrintSeenKey        = "fp:%s:seen"
	fingerPrintBlockedKey     = "fp:%s:blocked"
	fingerPrintMaliciousKey   = "fp:%s:malicious"
	fingerPrintByIpKey        = "fp_by_ip:%s"
	fingerPrintByT0kenKey     = "fp_by_token:%s"
	fingerPrintByUserKey      = "fp_by_user:%s"
	fingerPrintByUserAgentKey = "fp_by_ua:%s"
)

//go:generate mockery --name=Tracker --dir=. --output=../../../mocks --filename=fingerprint_tracker_mock.go --case=underscore --with-expecter
type Tracker interface {
	MakeFingerprint(ctx *fiber.Ctx) Fingerprint
	CountMaliciousSimilarFingerprints(
		ctx context.Context,
		fps []Fingerprint,
		blockThreshold float64,
	) (int, error)
	CountBlockedSimilarFingerprints(
		ctx context.Context,
		fps []Fingerprint,
	) (int, error)
	Store(
		ctx context.Context,
		fp *Fingerprint,
		ttl time.Duration,
	) error
	FindSimilarFingerprints(
		ctx context.Context,
		fp *Fingerprint,
	) ([]Fingerprint, error)
	GetFingerprint(ctx context.Context, id string) (*Fingerprint, error)
	IsFingerprintBlocked(
		ctx context.Context,
		fp *Fingerprint,
	) (bool, error)
	IncrementMaliciousCount(
		ctx context.Context,
		id string,
		ttl time.Duration,
	) error
	GetMaliciousCount(
		ctx context.Context,
		id string,
	) (int, error)
	BlockFingerprint(
		ctx context.Context,
		fp *Fingerprint,
		duration time.Duration,
	) error
}

type tracker struct {
	redis cache.Cache
}

func NewFingerPrintTracker(redis cache.Cache) Tracker {
	return &tracker{
		redis: redis,
	}
}

func (p *tracker) MakeFingerprint(ctx *fiber.Ctx) Fingerprint {
	return Fingerprint{
		UserID:    strings.ToLower(strings.TrimSpace(p.getUserID(ctx))),
		Token:     strings.ToLower(strings.TrimSpace(p.getAuthToken(ctx))),
		IP:        p.getByIp(ctx),
		UserAgent: strings.ToLower(strings.TrimSpace(p.getUserAgent(ctx))),
	}
}

func (p *tracker) CountMaliciousSimilarFingerprints(
	ctx context.Context,
	fps []Fingerprint,
	blockThreshold float64,
) (int, error) {
	malicious := 0
	for _, f := range fps {
		id := f.ID()
		badKey := fmt.Sprintf(fingerPrintMaliciousKey, id)
		seenKey := fmt.Sprintf(fingerPrintSeenKey, id)

		pipe := p.redis.Client().Pipeline()
		bad := pipe.Get(ctx, badKey)
		seen := pipe.Get(ctx, seenKey)
		_, err := pipe.Exec(ctx)
		if err != nil {
			continue
		}

		badCount, err := bad.Int64()
		if err != nil {
			continue
		}
		seenCount, err := seen.Int64()
		if err != nil {
			continue
		}
		if seenCount > 0 && float64(badCount)/float64(seenCount) >= blockThreshold {
			malicious++
		}
	}
	return malicious, nil
}

func (p *tracker) CountBlockedSimilarFingerprints(
	ctx context.Context,
	fps []Fingerprint,
) (int, error) {
	if len(fps) == 0 {
		return 0, nil
	}

	pipe := p.redis.Client().Pipeline()
	cmds := make([]*redis.IntCmd, len(fps))

	for i, f := range fps {
		blockKey := fmt.Sprintf(fingerPrintBlockedKey, f.ID())
		cmds[i] = pipe.Exists(ctx, blockKey)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}

	blocked := 0
	for _, cmd := range cmds {
		exists, err := cmd.Result()
		if err == nil && exists == 1 {
			blocked++
		}
	}

	return blocked, nil
}

func (p *tracker) Store(
	ctx context.Context,
	fp *Fingerprint,
	ttl time.Duration,
) error {
	id := fp.ID()

	data, err := json.Marshal(fp)
	if err != nil {
		return err
	}

	pipe := p.redis.Client().TxPipeline()

	pipe.Set(ctx, fmt.Sprintf(fingerPrintKey, id), data, ttl)

	pipe.Incr(ctx, fmt.Sprintf(fingerPrintSeenKey, id))
	pipe.Expire(ctx, fmt.Sprintf(fingerPrintSeenKey, id), ttl)

	if fp.IP != "" {
		key := fmt.Sprintf(fingerPrintByIpKey, fp.IP)
		pipe.SAdd(ctx, key, id)
		pipe.Expire(ctx, key, ttl)
	}
	if fp.Token != "" {
		key := fmt.Sprintf(fingerPrintByT0kenKey, fp.Token)
		pipe.SAdd(ctx, key, id)
		pipe.Expire(ctx, key, ttl)
	}
	if fp.UserID != "" {
		key := fmt.Sprintf(fingerPrintByUserKey, fp.UserID)
		pipe.SAdd(ctx, key, id)
		pipe.Expire(ctx, key, ttl)
	}
	if fp.UserAgent != "" {
		key := fmt.Sprintf(fingerPrintByUserAgentKey, fp.UserAgent)
		pipe.SAdd(ctx, key, id)
		pipe.Expire(ctx, key, ttl)
	}

	_, err = pipe.Exec(ctx)
	return err
}

func (p *tracker) FindSimilarFingerprints(
	ctx context.Context,
	fp *Fingerprint,
) ([]Fingerprint, error) {
	var keys []string

	if fp.IP != "" {
		keys = append(keys, fmt.Sprintf(fingerPrintByIpKey, fp.IP))
	}
	if fp.Token != "" {
		keys = append(keys, fmt.Sprintf(fingerPrintByT0kenKey, fp.Token))
	}
	if fp.UserID != "" {
		keys = append(keys, fmt.Sprintf(fingerPrintByUserKey, fp.UserID))
	}
	if fp.UserAgent != "" {
		keys = append(keys, fmt.Sprintf(fingerPrintByUserAgentKey, fp.UserAgent))
	}

	if len(keys) < 2 {
		return nil, nil
	}

	ids, err := p.redis.Client().SUnion(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}

	var results []Fingerprint
	for _, id := range ids {
		if id == fp.ID() {
			continue
		}
		data, err := p.redis.Client().Get(ctx, fmt.Sprintf(fingerPrintKey, id)).Bytes()
		if err != nil {
			continue
		}
		var other Fingerprint
		if err := json.Unmarshal(data, &other); err == nil {
			matchCount := 0
			if fp.IP != "" && utils.LevenshteinDistance(fp.IP, other.IP) <= 2 {
				matchCount++
			}
			if fp.Token != "" && utils.LevenshteinDistance(fp.Token, other.Token) <= 2 {
				matchCount++
			}
			if fp.UserID != "" && utils.LevenshteinDistance(fp.UserID, other.UserID) <= 2 {
				matchCount++
			}
			if fp.UserAgent != "" && utils.LevenshteinDistance(fp.UserAgent, other.UserAgent) <= 2 {
				matchCount++
			}
			if matchCount >= 2 {
				results = append(results, other)
			}
		}
	}

	return results, nil
}

func (p *tracker) GetFingerprint(ctx context.Context, id string) (*Fingerprint, error) {
	key := fmt.Sprintf(fingerPrintKey, id)
	data, err := p.redis.Client().Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}

	var fp Fingerprint
	if err := json.Unmarshal(data, &fp); err != nil {
		return nil, err
	}

	return &fp, nil
}

func (p *tracker) IsFingerprintBlocked(
	ctx context.Context,
	fp *Fingerprint,
) (bool, error) {
	blockKey := fmt.Sprintf(fingerPrintBlockedKey, fp.ID())
	exists, err := p.redis.Client().Exists(ctx, blockKey).Result()
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

func (p *tracker) BlockFingerprint(
	ctx context.Context,
	fp *Fingerprint,
	duration time.Duration,
) error {
	blockKey := fmt.Sprintf(fingerPrintBlockedKey, fp.ID())
	return p.redis.Client().Set(ctx, blockKey, "1", duration).Err()
}

func (p *tracker) IncrementMaliciousCount(
	ctx context.Context,
	id string,
	ttl time.Duration,
) error {
	if err := p.redis.Client().Incr(ctx, fmt.Sprintf(fingerPrintMaliciousKey, id)).Err(); err != nil {
		return err
	}
	if err := p.redis.Client().Expire(ctx, fmt.Sprintf(fingerPrintMaliciousKey, id), ttl).Err(); err != nil {
		return err

	}
	return nil
}

func (p *tracker) GetMaliciousCount(
	ctx context.Context,
	id string,
) (int, error) {
	count, err := p.redis.Client().Get(ctx, fmt.Sprintf(fingerPrintMaliciousKey, id)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return int(count), nil
}

func (p *tracker) getUserID(ctx *fiber.Ctx) string {
	userHeaders := []string{
		"X-User-ID",
		"X-User-Id",
		"X-UserID",
		"User-ID",
	}

	for _, header := range userHeaders {
		if value := ctx.Get(header); value != "" {
			return value
		}
	}
	return ""
}

func (p *tracker) getAuthToken(ctx *fiber.Ctx) string {
	authHeader := ctx.Get("Authorization")
	if authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
		return authHeader
	}

	tokenHeaders := []string{
		"X-Access-Token",
		"X-Auth-Token",
	}

	for _, header := range tokenHeaders {
		if token := ctx.Get(header); token != "" {
			return token
		}
	}
	return ""
}

func (p *tracker) getByIp(ctx *fiber.Ctx) string {
	ipHeaders := []string{
		"X-Real-IP",
		"X-Forwarded-For",
		"X-Original-Forwarded-For",
		"True-Client-IP",
		"CF-Connecting-IP",
	}

	for _, header := range ipHeaders {
		if value := ctx.Get(header); value != "" {
			ips := strings.Split(value, ",")
			if len(ips) > 0 {
				ip := strings.TrimSpace(ips[0])
				if parsedIP := net.ParseIP(ip); parsedIP != nil {
					return ip
				}
			}
		}
	}
	return strings.TrimSpace(ctx.IP())
}

func (p *tracker) getUserAgent(ctx *fiber.Ctx) string {
	return ctx.Get("User-Agent")
}
