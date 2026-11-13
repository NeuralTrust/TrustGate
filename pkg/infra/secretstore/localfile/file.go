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

// Package localfile loads the secret store file (SECRET_STORES_FILE) that a
// customer-operated plane mounts from its deployment's values, and keeps the
// loaded stores current while the file changes.
package localfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

const fileVersion = 1

// maxFileBytes bounds the store file read into memory.
const maxFileBytes = 1 << 20

// inlineCredentialKeys may never appear in a store's auth block: the file is
// a ConfigMap, so a credential written there would leak. Each has a *_file
// counterpart that names a mounted Secret instead.
var inlineCredentialKeys = []string{"token", "secret_id", "jwt", "password", "api_key", "client_secret"}

type fileDoc struct {
	Version int         `yaml:"version"`
	Stores  []storeSpec `yaml:"stores"`
}

type cacheSpec struct {
	TTL         string `yaml:"ttl"`
	MaxStale    string `yaml:"max_stale"`
	NegativeTTL string `yaml:"negative_ttl"`
}

type storeSpec struct {
	Name              string                               `yaml:"name"`
	Type              secretstore.Type                     `yaml:"type"`
	AllowedPaths      []string                             `yaml:"allowed_paths"`
	Gateways          []string                             `yaml:"gateways"`
	Cache             cacheSpec                            `yaml:"cache"`
	HashiCorpVault    *secretstore.HashiCorpVaultConfig    `yaml:"hashicorp_vault"`
	AWSSecretsManager *secretstore.AWSSecretsManagerConfig `yaml:"aws_secrets_manager"`
	GCPSecretManager  *secretstore.GCPSecretManagerConfig  `yaml:"gcp_secret_manager"`
	File              *secretstore.FileConfig              `yaml:"file"`
	Env               *secretstore.EnvConfig               `yaml:"env"`
	AzureKeyVault     *secretstore.AzureKeyVaultConfig     `yaml:"azure_key_vault"`
	CyberArkConjur    *secretstore.CyberArkConjurConfig    `yaml:"cyberark_conjur"`
}

// Parse decodes and validates a store file. Decoding is strict: unknown keys,
// inline credentials, duplicate names and invalid stores are refused, so a
// typo fails the load instead of silently changing what a plane reads.
func Parse(raw []byte) ([]*secretstore.Store, error) {
	if len(raw) > maxFileBytes {
		return nil, fmt.Errorf("%w: the store file is larger than %d bytes", secretstore.ErrInvalidStore, maxFileBytes)
	}
	if err := refuseInlineCredentials(raw); err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var doc fileDoc
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: the store file is empty", secretstore.ErrInvalidStore)
		}
		return nil, fmt.Errorf("%w: %s", secretstore.ErrInvalidStore, redactScalars(err.Error()))
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: the store file must hold a single YAML document", secretstore.ErrInvalidStore)
	}
	if doc.Version != fileVersion {
		return nil, fmt.Errorf("%w: version must be %d", secretstore.ErrInvalidStore, fileVersion)
	}

	stores := make([]*secretstore.Store, 0, len(doc.Stores))
	seen := make(map[string]bool, len(doc.Stores))
	for i := range doc.Stores {
		store, err := doc.Stores[i].toStore()
		if err != nil {
			return nil, err
		}
		if seen[store.Name] {
			return nil, fmt.Errorf("%w: store %q is declared twice", secretstore.ErrInvalidStore, store.Name)
		}
		seen[store.Name] = true
		stores = append(stores, store)
	}
	return stores, nil
}

func (s *storeSpec) toStore() (*secretstore.Store, error) {
	name := s.Name
	cfg, err := s.typedConfig()
	if err != nil {
		return nil, err
	}
	gateways := make([]ids.GatewayID, 0, len(s.Gateways))
	for _, raw := range s.Gateways {
		id, err := ids.Parse[ids.GatewayKind](strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("%w: store %q: gateway %q is not a gateway id", secretstore.ErrInvalidStore, name, raw)
		}
		gateways = append(gateways, id)
	}
	cache, err := s.Cache.policy(name)
	if err != nil {
		return nil, err
	}
	store := &secretstore.Store{
		Name:         name,
		Type:         s.Type,
		AllowedPaths: s.AllowedPaths,
		Gateways:     gateways,
		Cache:        cache,
		Config:       cfg,
	}
	if err := store.Validate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *storeSpec) typedConfig() (secretstore.TypedConfig, error) {
	var blocks []secretstore.TypedConfig
	if s.HashiCorpVault != nil {
		blocks = append(blocks, s.HashiCorpVault)
	}
	if s.AWSSecretsManager != nil {
		blocks = append(blocks, s.AWSSecretsManager)
	}
	if s.GCPSecretManager != nil {
		blocks = append(blocks, s.GCPSecretManager)
	}
	if s.File != nil {
		blocks = append(blocks, s.File)
	}
	if s.Env != nil {
		blocks = append(blocks, s.Env)
	}
	if s.AzureKeyVault != nil {
		blocks = append(blocks, s.AzureKeyVault)
	}
	if s.CyberArkConjur != nil {
		blocks = append(blocks, s.CyberArkConjur)
	}
	switch {
	case len(blocks) == 0:
		return nil, fmt.Errorf("%w: store %q: the %s block is missing", secretstore.ErrInvalidStore, s.Name, s.Type)
	case len(blocks) > 1:
		return nil, fmt.Errorf("%w: store %q: exactly one type block is allowed", secretstore.ErrInvalidStore, s.Name)
	case blocks[0].StoreType() != s.Type:
		return nil, fmt.Errorf("%w: store %q: type %q does not match its %s block", secretstore.ErrInvalidStore, s.Name, s.Type, blocks[0].StoreType())
	}
	return blocks[0], nil
}

func (c cacheSpec) policy(store string) (secretstore.CachePolicy, error) {
	var p secretstore.CachePolicy
	for _, f := range []struct {
		key string
		raw string
		dst *time.Duration
	}{
		{"cache.ttl", c.TTL, &p.TTL},
		{"cache.max_stale", c.MaxStale, &p.MaxStale},
		{"cache.negative_ttl", c.NegativeTTL, &p.NegativeTTL},
	} {
		if f.raw == "" {
			continue
		}
		d, err := time.ParseDuration(f.raw)
		if err != nil || d <= 0 {
			return p, fmt.Errorf("%w: store %q: %s must be a positive duration such as 5m", secretstore.ErrInvalidStore, store, f.key)
		}
		*f.dst = d
	}
	return p, nil
}

// refuseInlineCredentials finds a credential written inline in any store's
// type block and names the store and the key, before strict decoding would
// report it as a mere unknown field.
func refuseInlineCredentials(raw []byte) error {
	var loose struct {
		Stores []map[string]any `yaml:"stores"`
	}
	if err := yaml.Unmarshal(raw, &loose); err != nil {
		return nil
	}
	for _, store := range loose.Stores {
		name, _ := store["name"].(string)
		for block, value := range store {
			if key, ok := findInlineCredential(value); ok {
				return fmt.Errorf("%w: store %q: %s.%s must not be written inline; mount it from a Kubernetes Secret and use %s_file",
					secretstore.ErrInvalidStore, name, block, key, lastKey(key))
			}
		}
	}
	return nil
}

func findInlineCredential(v any) (string, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	for key, child := range m {
		for _, forbidden := range inlineCredentialKeys {
			if key == forbidden {
				return key, true
			}
		}
		if path, ok := findInlineCredential(child); ok {
			return key + "." + path, true
		}
	}
	return "", false
}

// quotedScalar matches the values YAML errors quote in backticks. A value
// under a mistyped key may be a credential, and load errors are logged.
var quotedScalar = regexp.MustCompile("`[^`]*`")

func redactScalars(msg string) string {
	return quotedScalar.ReplaceAllString(msg, "`…`")
}

func lastKey(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}
