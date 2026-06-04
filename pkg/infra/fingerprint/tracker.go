package fingerprint

import (
	"net"
	"strings"

	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

//go:generate mockery --name=Tracker --dir=. --output=./mocks --filename=fingerprint_tracker_mock.go --case=underscore --with-expecter
type Tracker interface {
	MakeFingerprint(ctx *fiber.Ctx) Fingerprint
}

var _ Tracker = (*tracker)(nil)

type tracker struct{}

func NewFingerPrintTracker() Tracker {
	return &tracker{}
}

func (p *tracker) MakeFingerprint(ctx *fiber.Ctx) Fingerprint {
	return Fingerprint{
		UserID:    strings.ToLower(strings.TrimSpace(p.getUserID(ctx))),
		Token:     strings.ToLower(strings.TrimSpace(p.getAuthToken(ctx))),
		IP:        p.getByIp(ctx),
		UserAgent: strings.ToLower(strings.TrimSpace(p.getUserAgent(ctx))),
		SessionID: strings.ToLower(strings.TrimSpace(p.getSessionID(ctx))),
	}
}

func (p *tracker) getUserID(ctx *fiber.Ctx) string {
	userHeaders := []string{"X-User-ID", "X-User-Id", "X-UserID", "User-ID"}
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

	tokenHeaders := []string{"X-Access-Token", "X-Auth-Token"}
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
		value := ctx.Get(header)
		if value == "" {
			continue
		}
		ips := strings.Split(value, ",")
		if len(ips) == 0 {
			continue
		}
		ip := strings.TrimSpace(ips[0])
		if parsedIP := net.ParseIP(ip); parsedIP != nil {
			return ip
		}
	}
	return strings.TrimSpace(ctx.IP())
}

func (p *tracker) getUserAgent(ctx *fiber.Ctx) string {
	return ctx.Get("User-Agent")
}

func (p *tracker) getSessionID(ctx *fiber.Ctx) string {
	if p.sessionGenerated(ctx) {
		return ""
	}
	if v, ok := ctx.Locals(string(infracontext.SessionContextKey)).(string); ok && v != "" {
		return v
	}
	if v, ok := ctx.Context().Value(infracontext.SessionContextKey).(string); ok && v != "" {
		return v
	}
	return ""
}

func (p *tracker) sessionGenerated(ctx *fiber.Ctx) bool {
	if v, ok := ctx.Locals(string(infracontext.SessionGeneratedContextKey)).(bool); ok && v {
		return true
	}
	if v, ok := ctx.Context().Value(infracontext.SessionGeneratedContextKey).(bool); ok && v {
		return true
	}
	return false
}
