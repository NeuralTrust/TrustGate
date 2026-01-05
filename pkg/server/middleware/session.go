package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/domain/session"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

var jsonBufferPool = &sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

var sessionPool = sync.Pool{
	New: func() interface{} {
		return &session.Session{}
	},
}

// unsafeByteToString performs a zero-copy conversion from []byte to string
// using unsafe.Pointer to avoid memory allocation and improve performance.
//
// WARNING: This is an unsafe operation that bypasses Go's memory safety.
// It relies on the fact that both []byte and string have the same underlying structure.
// This function should only be used when:
// 1. The input []byte will not be modified after this conversion
// 2. Performance is critical in this code path
//
// The input byte slice must not be modified after calling this function,
// as that would lead to undefined behavior in the returned string.
func unsafeByteToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b)) // #nosec G103
}

type sessionMiddleware struct {
	logger     *logrus.Logger
	repository session.Repository
}

func NewSessionMiddleware(
	logger *logrus.Logger,
	repository session.Repository,
) Middleware {
	return &sessionMiddleware{
		logger:     logger,
		repository: repository,
	}
}

func (m *sessionMiddleware) Middleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		gatewayData, ok := ctx.Locals(string(common.GatewayDataContextKey)).(*types.GatewayData)
		if !ok {
			return ctx.Next()
		}

		if gatewayData.Gateway.SessionConfig == nil || !gatewayData.Gateway.SessionConfig.Enabled {
			return ctx.Next()
		}

		gatewayIDStr, ok := ctx.Locals(common.GatewayContextKey).(string)
		if !ok {
			return ctx.Next()
		}

		gatewayID, err := uuid.Parse(gatewayIDStr)
		if err != nil {
			m.logger.WithError(err).Error("failed to parse gateway ID")
			return ctx.Next()
		}

		// Parse body only once and store the result
		var bodyMap map[string]any
		body := ctx.Body()
		bodyParsed := false

		sessionID := m.getSessionID(ctx, gatewayData.Gateway.SessionConfig, &bodyMap, &bodyParsed, body)
		if sessionID == "" {
			return ctx.Next()
		}

		// Use only Fiber context for consistency
		ctx.Locals(common.SessionContextKey, sessionID)

		content := m.extractContent(ctx, gatewayData.Gateway.SessionConfig.Mapping, &bodyMap, &bodyParsed, body)

		ttl := time.Duration(gatewayData.Gateway.SessionConfig.TTL) * time.Second

		// Get session from pool
		sessObj := sessionPool.Get()
		sess, ok := sessObj.(*session.Session)
		if !ok {
			m.logger.Error("failed to get session from pool: invalid type")
			return ctx.Next()
		}
		sess.ID = sessionID
		sess.GatewayID = gatewayID
		sess.Content = content
		sess.CreatedAt = time.Now()
		sess.ExpiresAt = sess.CreatedAt.Add(ttl)

		if err := m.repository.Save(ctx.Context(), sess); err != nil {
			m.logger.WithError(err).Error("failed to save session")
		}
		sessionPool.Put(sess)
		return ctx.Next()
	}
}

func (m *sessionMiddleware) getSessionID(ctx *fiber.Ctx, config *types.SessionConfigDTO, bodyMap *map[string]any, bodyParsed *bool, body []byte) string {
	if sessionID := ctx.Get(config.HeaderName); sessionID != "" {
		return sessionID
	}

	if !*bodyParsed {
		if err := json.Unmarshal(body, bodyMap); err != nil {
			return ""
		}
		*bodyParsed = true
	}

	if id, ok := (*bodyMap)[config.BodyParamName].(string); ok {
		return id
	}
	return ""
}

func (m *sessionMiddleware) extractContent(ctx *fiber.Ctx, mapping string, bodyMap *map[string]any, bodyParsed *bool, body []byte) string {
	if mapping == "" {
		// Performance critical path: Use unsafe conversion for zero-copy
		// This is safe because the body slice is not modified after this point
		return unsafeByteToString(body)
	}

	// Use the already parsed body if available
	if !*bodyParsed {
		if err := json.Unmarshal(body, bodyMap); err != nil {
			m.logger.WithError(err).Debug("failed to parse request body")
			// Fallback to raw body when JSON parsing fails
			// Using unsafe conversion is appropriate here as this is an error path
			// and the body slice is not modified after this point
			return unsafeByteToString(body)
		}
		*bodyParsed = true
	}

	if value, ok := (*bodyMap)[mapping]; ok {
		switch v := value.(type) {
		case string:
			return v
		default:
			// Reuse a buffer from sync.Pool for JSON marshaling
			bufObj := jsonBufferPool.Get()
			buf, ok := bufObj.(*bytes.Buffer)
			if !ok {
				m.logger.Error("failed to get buffer from pool: invalid type")
				return fmt.Sprintf("%v", v)
			}
			buf.Reset()
			defer jsonBufferPool.Put(buf)

			if err := json.NewEncoder(buf).Encode(v); err == nil {
				return buf.String()[:buf.Len()-1] // Remove trailing newline
			}
			return fmt.Sprintf("%v", v)
		}
	}
	return ""
}
