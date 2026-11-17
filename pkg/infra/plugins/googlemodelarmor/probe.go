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

package googlemodelarmor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/gcpauth"
	"golang.org/x/oauth2"
)

const (
	probeText             = "Connection test from the gateway."
	reasonServiceDisabled = "SERVICE_DISABLED"
	fallbackProbeTimeout  = 10 * time.Second
	// tokenClientMargin lets the probe's deadline expire before the token
	// client's own timeout, so a stalled token endpoint reads as a timeout:
	// x/oauth2 formats transport errors with %v and drops their cause.
	tokenClientMargin = 250 * time.Millisecond
)

var _ appplugins.ConnectionProber = (*Plugin)(nil)

type tokenStageError struct {
	err   error
	keyed bool
}

func (e *tokenStageError) Error() string { return e.err.Error() }

func (e *tokenStageError) Unwrap() error { return e.err }

// ProbeConnection sends one sanitizeUserPrompt call with settings' credentials
// and reports whether this gateway can use the template. It builds its own
// token sources and client, so a probe never adds to or evicts the caches that
// serve traffic.
func (p *Plugin) ProbeConnection(ctx context.Context, settings map[string]any) appplugins.ProbeResult {
	start := time.Now()
	cfg, err := parseConfig(settings)
	if err == nil {
		err = p.checkIdentity(cfg)
	}
	if err != nil {
		return probeResult(start, appplugins.ProbeInvalidConfig,
			"The policy settings are not valid for Google Model Armor.")
	}
	timeout := cfg.callTimeout(p.probeTimeout())
	newSources := p.newProbeSources
	if p.probeSourcesOverride != nil {
		newSources = p.probeSourcesOverride
	}
	creds := credentialsFromConfig(cfg.Credentials)
	keyed := creds.impersonateServiceAccount == "" && creds.serviceAccountJSON != ""
	ts := newSources(timeout).tokenSourceFor(creds)
	cl := newClientWithTokenSource(p.baseURL, timeout, func(ctx context.Context) (string, error) {
		token, err := ts(ctx)
		if err == nil {
			return token, nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = fmt.Errorf("%w: %w", ctxErr, err)
		}
		return "", &tokenStageError{err: err, keyed: keyed}
	})
	_, err = cl.SanitizeUserPrompt(ctx, cfg.Project, cfg.Location, cfg.Template, probeText)
	code, message := classifyProbe(err, cfg, timeout)
	return probeResult(start, code, message)
}

func probeResult(start time.Time, code, message string) appplugins.ProbeResult {
	return appplugins.ProbeResult{Code: code, Message: message, Latency: time.Since(start)}
}

func (p *Plugin) probeTimeout() time.Duration {
	if p.timeout > 0 {
		return p.timeout
	}
	return fallbackProbeTimeout
}

func (p *Plugin) newProbeSources(timeout time.Duration) *credentialSources {
	hc := &http.Client{
		Transport: p.probeTransport,
		Timeout:   timeout + tokenClientMargin,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	adc := p.adc
	if adc == nil {
		adc = gcpauth.NewApplicationDefaultCache()
	}
	return &credentialSources{
		adc:         adc.Token,
		serviceAcct: gcpauth.NewServiceAccountCache(gcpauth.WithHTTPClient(hc)).Token,
		impersonate: gcpauth.NewImpersonationCache(adc, gcpauth.WithImpersonationHTTPClient(hc)).Token,
	}
}

func classifyProbe(err error, cfg Settings, timeout time.Duration) (code, message string) {
	if err == nil {
		return appplugins.ProbeOK, fmt.Sprintf(
			"Model Armor answered with template %s in project %s (%s).", cfg.Template, cfg.Project, cfg.Location)
	}
	if isTimeout(err) {
		return appplugins.ProbeTimeout, fmt.Sprintf("Model Armor did not answer within %s.", timeout)
	}
	var tokenErr *tokenStageError
	if errors.As(err, &tokenErr) {
		return classifyTokenError(tokenErr)
	}
	var maErr *errModelArmor
	if errors.As(err, &maErr) {
		return classifyModelArmorStatus(maErr, cfg)
	}
	return unreachable()
}

func classifyTokenError(stage *tokenStageError) (code, message string) {
	err := stage.err
	var refused *gcpauth.ImpersonationRefused
	if errors.As(err, &refused) {
		switch refused.Status {
		case http.StatusUnauthorized:
			return gatewayIdentityRejected()
		case http.StatusForbidden:
			return appplugins.ProbePermissionDenied,
				"The gateway cannot impersonate the service account. Grant the gateway's identity " +
					"roles/iam.serviceAccountTokenCreator on it."
		case http.StatusNotFound:
			return appplugins.ProbeInvalidCredentials, "The service account to impersonate does not exist."
		case http.StatusTooManyRequests:
			return throttled()
		}
		return unreachable()
	}
	if gcpauth.KeyRejected(err) {
		if !stage.keyed {
			return gatewayIdentityRejected()
		}
		return appplugins.ProbeInvalidCredentials,
			"Google rejected the service account key. Check that the key and its service account are still enabled."
	}
	var retrieveErr *oauth2.RetrieveError
	if errors.As(err, &retrieveErr) && retrieveErr.Response != nil &&
		retrieveErr.Response.StatusCode == http.StatusTooManyRequests {
		return throttled()
	}
	return unreachable()
}

func classifyModelArmorStatus(e *errModelArmor, cfg Settings) (code, message string) {
	switch {
	case e.status == http.StatusUnauthorized:
		return appplugins.ProbeInvalidCredentials,
			"Model Armor did not accept the service account's credentials."
	case e.status == http.StatusForbidden && e.reason == reasonServiceDisabled:
		return appplugins.ProbeAPIDisabled,
			fmt.Sprintf("The Model Armor API is not enabled in project %s.", cfg.Project)
	case e.status == http.StatusForbidden:
		return appplugins.ProbePermissionDenied, fmt.Sprintf(
			"The service account cannot use Model Armor in project %s. Grant it roles/modelarmor.user, "+
				"and check that template %s exists in %s.", cfg.Project, cfg.Template, cfg.Location)
	case e.status == http.StatusNotFound, e.reason == reasonTemplateMissing,
		e.status == http.StatusBadRequest && e.configShaped:
		return appplugins.ProbeTemplateNotFound, fmt.Sprintf(
			"Template %s was not found in project %s, location %s.", cfg.Template, cfg.Project, cfg.Location)
	case e.status == http.StatusTooManyRequests:
		return throttled()
	case e.status >= http.StatusInternalServerError, e.status < http.StatusBadRequest:
		return unreachable()
	}
	return appplugins.ProbeInvalidConfig,
		"Model Armor rejected the request. Check the project, location and template."
}

func isTimeout(err error) bool {
	return errors.Is(err, context.DeadlineExceeded)
}

func gatewayIdentityRejected() (code, message string) {
	return appplugins.ProbeInvalidCredentials, "Google rejected this gateway's own identity."
}

func throttled() (code, message string) {
	return appplugins.ProbeThrottled, "Google is limiting requests to Model Armor. Try again in a moment."
}

func unreachable() (code, message string) {
	return appplugins.ProbeUnreachable,
		"Model Armor or Google's token endpoint could not be reached from this gateway."
}
