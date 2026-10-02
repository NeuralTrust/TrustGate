// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sts

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
)

func TestTokenClient_DefaultClientRefusesInternalIssuer(t *testing.T) {
	netguardtest.Deny(t)
	srv, hits := netguardtest.Hostile(t, nil)

	_, err := NewTokenClient(nil).Call(context.Background(), srv.URL, url.Values{"subject_token": {"t"}})
	require.Error(t, err)
	require.Zero(t, hits.Load(), "the discovery request must not reach an internal host")
}

// A public issuer can still advertise an internal token_endpoint; the POST that
// carries client_secret and subject_token must be refused at dial time.
func TestTokenClient_DiscoveredInternalTokenEndpointIsRefused(t *testing.T) {
	netguardtest.Deny(t)
	internal, internalHits := netguardtest.Hostile(t, nil)
	var issuerURL string
	issuer, issuerHits := netguardtest.Hostile(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "{\"issuer\":%q,\"token_endpoint\":%q}", issuerURL, internal.URL+"/token")
	})
	issuerURL = issuer.URL

	client := NewTokenClient(netguardtest.ClientTrusting(strings.TrimPrefix(issuer.URL, "http://")))
	_, err := client.Call(context.Background(), issuer.URL, url.Values{"client_secret": {"s3cret"}})
	require.ErrorIs(t, err, netguard.ErrBlockedDestination)
	require.EqualValues(t, 1, issuerHits.Load())
	require.Zero(t, internalHits.Load())
}
