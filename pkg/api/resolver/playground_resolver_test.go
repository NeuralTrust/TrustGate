package resolver

import (
	"net/http/httptest"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/config"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	infrajwt "github.com/NeuralTrust/AgentGateway/pkg/infra/auth/jwt"
	"github.com/gofiber/fiber/v2"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

const playgroundTestSecret = "playground-test-secret"

func signPlaygroundClaims(t *testing.T, secret string, claims *infrajwt.Claims) string {
	t.Helper()
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = golangjwt.NewNumericDate(time.Now().Add(5 * time.Minute))
	}
	token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	require.NoError(t, err)
	return token
}

func resolvePlaygroundToken(
	t *testing.T,
	secret string,
	token string,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
) (*appauth.AuthContext, error) {
	t.Helper()
	r := NewPlaygroundIdentityResolver(infrajwt.NewJwtManager(&config.ServerConfig{SecretKey: secret}))

	var authCtx *appauth.AuthContext
	var resolveErr error
	app := fiber.New()
	app.Get("/", func(c *fiber.Ctx) error {
		authCtx, resolveErr = r.Resolve(c, gw, rc)
		return c.SendStatus(fiber.StatusOK)
	})

	req := httptest.NewRequest(fiber.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set(HeaderPlaygroundToken, token)
	}
	_, err := app.Test(req)
	require.NoError(t, err)
	return authCtx, resolveErr
}

func playgroundTestConsumer() (*gatewaydomain.Gateway, *appconsumer.RoutableConsumer) {
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:          ids.New[ids.ConsumerKind](),
			GatewayID:   gw.ID,
			Slug:        "cons1234",
			RoutingMode: consumerdomain.RoutingModeRoleBased,
			Active:      true,
			RoleIDs:     []ids.RoleID{ids.New[ids.RoleKind]()},
		},
	}
	return gw, rc
}

func TestPlaygroundResolver_ValidToken(t *testing.T) {
	t.Parallel()
	gw, rc := playgroundTestConsumer()
	token := signPlaygroundClaims(t, playgroundTestSecret, &infrajwt.Claims{
		UserID:       "user-1",
		Purpose:      infrajwt.PurposePlayground,
		ConsumerSlug: rc.Consumer.Slug,
	})

	authCtx, err := resolvePlaygroundToken(t, playgroundTestSecret, token, gw, rc)
	require.NoError(t, err)
	require.Equal(t, appauth.MethodPlayground, authCtx.Method)
	require.Equal(t, gw.ID, authCtx.GatewayID)
	require.Equal(t, rc.Consumer.ID, authCtx.ConsumerID)
	require.Equal(t, "user-1", authCtx.Subject)
	require.Equal(t, rc.Consumer.RoleIDs, authCtx.RoleIDs)
}

func TestPlaygroundResolver_Rejections(t *testing.T) {
	t.Parallel()
	gw, rc := playgroundTestConsumer()

	tests := []struct {
		name    string
		secret  string
		token   string
		wantErr error
	}{
		{
			name:    "missing token",
			secret:  playgroundTestSecret,
			token:   "",
			wantErr: ErrUnauthenticated,
		},
		{
			name:   "admin token without purpose",
			secret: playgroundTestSecret,
			token: signPlaygroundClaims(t, playgroundTestSecret, &infrajwt.Claims{
				UserID:       "user-1",
				ConsumerSlug: rc.Consumer.Slug,
			}),
			wantErr: ErrForbidden,
		},
		{
			name:   "wrong consumer slug",
			secret: playgroundTestSecret,
			token: signPlaygroundClaims(t, playgroundTestSecret, &infrajwt.Claims{
				Purpose:      infrajwt.PurposePlayground,
				ConsumerSlug: "other-consumer",
			}),
			wantErr: ErrForbidden,
		},
		{
			name:   "missing consumer slug",
			secret: playgroundTestSecret,
			token: signPlaygroundClaims(t, playgroundTestSecret, &infrajwt.Claims{
				Purpose: infrajwt.PurposePlayground,
			}),
			wantErr: ErrForbidden,
		},
		{
			name:   "expired token",
			secret: playgroundTestSecret,
			token: signPlaygroundClaims(t, playgroundTestSecret, &infrajwt.Claims{
				Purpose:      infrajwt.PurposePlayground,
				ConsumerSlug: rc.Consumer.Slug,
				RegisteredClaims: golangjwt.RegisteredClaims{
					ExpiresAt: golangjwt.NewNumericDate(time.Now().Add(-time.Minute)),
				},
			}),
			wantErr: ErrUnauthenticated,
		},
		{
			name:   "wrong signature",
			secret: playgroundTestSecret,
			token: signPlaygroundClaims(t, "other-secret", &infrajwt.Claims{
				Purpose:      infrajwt.PurposePlayground,
				ConsumerSlug: rc.Consumer.Slug,
			}),
			wantErr: ErrUnauthenticated,
		},
		{
			name:   "empty server secret rejects all tokens",
			secret: "",
			token: signPlaygroundClaims(t, playgroundTestSecret, &infrajwt.Claims{
				Purpose:      infrajwt.PurposePlayground,
				ConsumerSlug: rc.Consumer.Slug,
			}),
			wantErr: ErrUnauthenticated,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			authCtx, err := resolvePlaygroundToken(t, tt.secret, tt.token, gw, rc)
			require.ErrorIs(t, err, tt.wantErr)
			require.Nil(t, authCtx)
		})
	}
}

func TestPlaygroundResolver_NilConsumerForbidden(t *testing.T) {
	t.Parallel()
	gw, rc := playgroundTestConsumer()
	token := signPlaygroundClaims(t, playgroundTestSecret, &infrajwt.Claims{
		Purpose:      infrajwt.PurposePlayground,
		ConsumerSlug: rc.Consumer.Slug,
	})

	authCtx, err := resolvePlaygroundToken(t, playgroundTestSecret, token, gw, nil)
	require.ErrorIs(t, err, ErrForbidden)
	require.Nil(t, authCtx)
}
