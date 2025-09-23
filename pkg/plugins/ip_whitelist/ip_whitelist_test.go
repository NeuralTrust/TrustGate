package ip_whitelist_test

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common"
	"github.com/NeuralTrust/TrustGate/pkg/infra/fingerprint"
	"github.com/NeuralTrust/TrustGate/pkg/plugins/ip_whitelist"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestIPWhitelist_AllowExactIP(t *testing.T) {
	logger := logrus.New()
	pl := ip_whitelist.NewIPWhitelistPlugin(logger)

	cfg := types.PluginConfig{Settings: map[string]interface{}{
		"enabled": true,
		"ips":     []string{"1.2.3.4"},
	}}

	//  user|token|1.2.3.4|ua
	fp := &fingerprint.Fingerprint{UserID: "u", Token: "t", IP: "1.2.3.4", UserAgent: "ua"}
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, fp.ID())

	resp, err := pl.Execute(ctx, cfg, &types.RequestContext{}, &types.ResponseContext{}, nil)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestIPWhitelist_AllowCIDR(t *testing.T) {
	logger := logrus.New()
	pl := ip_whitelist.NewIPWhitelistPlugin(logger)

	cfg := types.PluginConfig{Settings: map[string]interface{}{
		"enabled": true,
		"cidrs":   []string{"10.0.0.0/8"},
	}}

	fp := &fingerprint.Fingerprint{UserID: "u", Token: "t", IP: "10.1.2.3", UserAgent: "ua"}
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, fp.ID())

	resp, err := pl.Execute(ctx, cfg, &types.RequestContext{}, &types.ResponseContext{}, nil)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, 200, resp.StatusCode)
}

func TestIPWhitelist_BlockUnknown(t *testing.T) {
	logger := logrus.New()
	pl := ip_whitelist.NewIPWhitelistPlugin(logger)

	cfg := types.PluginConfig{Settings: map[string]interface{}{
		"enabled": true,
		"ips":     []string{"1.2.3.4"},
	}}

	fp := &fingerprint.Fingerprint{UserID: "u", Token: "t", IP: "9.9.9.9", UserAgent: "ua"}
	ctx := context.WithValue(context.Background(), common.FingerprintIdContextKey, fp.ID())

	resp, err := pl.Execute(ctx, cfg, &types.RequestContext{}, &types.ResponseContext{}, nil)
	assert.Error(t, err)
	assert.Nil(t, resp)
}
