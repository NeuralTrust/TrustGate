package helpers

import (
	"encoding/json"
	"fmt"

	domainUpstream "github.com/NeuralTrust/TrustGate/pkg/domain/upstream"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/gcp"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fastjson"
)

type AuthDeps struct {
	TokenClient oauth.TokenClient
	SAService   gcp.ServiceAccountService
}

func ApplyTargetAuth(
	deps AuthDeps,
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	upstreamModel *domainUpstream.Upstream,
) error {
	if upstreamModel == nil || target == nil {
		return nil
	}
	var domainTarget *domainUpstream.Target
	for i := range upstreamModel.Targets {
		if upstreamModel.Targets[i].ID == target.ID {
			domainTarget = &upstreamModel.Targets[i]
			break
		}
	}
	if domainTarget == nil || domainTarget.Auth == nil {
		return nil
	}

	switch domainTarget.Auth.Type {
	case domainUpstream.AuthTypeOAuth2:
		return applyTargetOAuth(deps.TokenClient, req, target, domainTarget.Auth.OAuth)
	case domainUpstream.AuthTypeGCPServiceAccount:
		return applyTargetGCPServiceAccount(deps.SAService, req, target, upstreamModel.ID.String(), domainTarget)
	default:
		return nil
	}
}

func applyTargetOAuth(
	tokenClient oauth.TokenClient,
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	cfg *domainUpstream.TargetOAuthConfig,
) error {
	if cfg == nil {
		return nil
	}
	dto := oauth.TokenRequestDTO{
		TokenURL:     cfg.TokenURL,
		GrantType:    oauth.GrantType(cfg.GrantType),
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		UseBasicAuth: cfg.UseBasicAuth,
		Scopes:       cfg.Scopes,
		Audience:     cfg.Audience,
		Code:         cfg.Code,
		RedirectURI:  cfg.RedirectURI,
		CodeVerifier: cfg.CodeVerifier,
		RefreshToken: cfg.RefreshToken,
		Username:     cfg.Username,
		Password:     cfg.Password,
		Extra:        cfg.Extra,
	}
	accessToken, _, err := tokenClient.GetToken(req.Context, dto)
	if err != nil {
		return err
	}
	SetTargetBearerToken(req, target, accessToken)
	return nil
}

func applyTargetGCPServiceAccount(
	saService gcp.ServiceAccountService,
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	upstreamID string,
	domainTarget *domainUpstream.Target,
) error {
	if domainTarget.Auth.GCPServiceAccount == nil || *domainTarget.Auth.GCPServiceAccount == "" {
		return fmt.Errorf("gcp_service_account credentials not configured for target %s", domainTarget.ID)
	}

	sa, err := saService.DecryptSA(upstreamID, domainTarget.ID, *domainTarget.Auth.GCPServiceAccount)
	if err != nil {
		return fmt.Errorf("failed to decrypt service account: %w", err)
	}

	accessToken, err := saService.GetAccessToken(req.Context, upstreamID, domainTarget.ID, sa)
	if err != nil {
		return fmt.Errorf("failed to obtain GCP access token: %w", err)
	}

	SetTargetBearerToken(req, target, accessToken)
	return nil
}

func ApplyCredentialsAuth(req *fasthttp.Request, creds *types.CredentialsDTO, body []byte) error {
	if creds == nil {
		return nil
	}

	if creds.HeaderName != "" && creds.HeaderValue != "" {
		req.Header.Set(creds.HeaderName, creds.HeaderValue)
	}

	if creds.ParamName == "" || creds.ParamValue == "" {
		return nil
	}

	switch creds.ParamLocation {
	case "query":
		req.URI().QueryArgs().Set(creds.ParamName, creds.ParamValue)
	case "body":
		if len(body) == 0 {
			return nil
		}
		var p fastjson.Parser
		parsedBody, err := p.ParseBytes(body)
		if err != nil {
			return fmt.Errorf("failed to parse request body for credential injection: %w", err)
		}
		escaped, err := json.Marshal(creds.ParamValue)
		if err != nil {
			return fmt.Errorf("failed to marshal credential value: %w", err)
		}
		parsedBody.GetObject().Set(creds.ParamName, fastjson.MustParse(string(escaped)))
		req.SetBodyRaw(parsedBody.MarshalTo(nil))
	}
	return nil
}

func SetTargetBearerToken(
	req *types.RequestContext,
	target *types.UpstreamTargetDTO,
	token string,
) {
	target.Credentials.ApiKey = token
	if req.Headers == nil {
		req.Headers = make(map[string][]string)
	}
	req.Headers["Authorization"] = []string{"Bearer " + token}
	if target.Headers == nil {
		target.Headers = make(map[string]string)
	}
	target.Headers["Authorization"] = "Bearer " + token
}
