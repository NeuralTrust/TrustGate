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

package secretstore

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// Vault auth methods. Every one except approle and token is keyless.
const (
	VaultAuthKubernetes = "kubernetes"
	VaultAuthJWT        = "jwt"
	VaultAuthAppRole    = "approle"
	VaultAuthToken      = "token"
)

// Vault defaults.
const (
	DefaultVaultMount     = "secret"
	DefaultVaultKVVersion = 2
	// DefaultServiceAccountTokenFile is where Kubernetes projects the pod's
	// ServiceAccount token, which Vault Kubernetes auth presents.
	DefaultServiceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- a well-known file path, not a credential
)

// HashiCorpVaultConfig reads a KV secrets engine of HashiCorp Vault or
// OpenBao. Credentials are never inline: approle, token and jwt name files
// mounted from Kubernetes Secrets.
type HashiCorpVaultConfig struct {
	Address    string    `yaml:"address"`
	Namespace  string    `yaml:"namespace"`
	Mount      string    `yaml:"mount"`
	KVVersion  int       `yaml:"kv_version"`
	CACertFile string    `yaml:"ca_cert_file"`
	Auth       VaultAuth `yaml:"auth"`
}

// VaultAuth is how a plane logs in to Vault.
type VaultAuth struct {
	Method       string `yaml:"method"`
	Mount        string `yaml:"mount"`
	Role         string `yaml:"role"`
	RoleID       string `yaml:"role_id"`
	SecretIDFile string `yaml:"secret_id_file"`
	TokenFile    string `yaml:"token_file"`
	JWTFile      string `yaml:"jwt_file"`
}

// StoreType implements TypedConfig.
func (*HashiCorpVaultConfig) StoreType() Type { return TypeHashiCorpVault }

// EffectiveMount returns the KV mount, DefaultVaultMount when unset.
func (c *HashiCorpVaultConfig) EffectiveMount() string {
	if c.Mount == "" {
		return DefaultVaultMount
	}
	return c.Mount
}

// EffectiveKVVersion returns the KV version, DefaultVaultKVVersion when unset.
func (c *HashiCorpVaultConfig) EffectiveKVVersion() int {
	if c.KVVersion == 0 {
		return DefaultVaultKVVersion
	}
	return c.KVVersion
}

// EffectiveMount returns the auth mount, the method's name when unset.
func (a VaultAuth) EffectiveMount() string {
	if a.Mount == "" {
		return a.Method
	}
	return a.Mount
}

// EffectiveJWTFile returns the token file a kubernetes or jwt login
// presents, the pod's ServiceAccount token when unset.
func (a VaultAuth) EffectiveJWTFile() string {
	if a.JWTFile == "" {
		return DefaultServiceAccountTokenFile
	}
	return a.JWTFile
}

// Validate implements TypedConfig.
func (c *HashiCorpVaultConfig) Validate() error {
	if err := validateEndpoint("hashicorp_vault.address", c.Address, true); err != nil {
		return err
	}
	if v := c.EffectiveKVVersion(); v != 1 && v != 2 {
		return fmt.Errorf("%w: hashicorp_vault.kv_version must be 1 or 2", ErrInvalidStore)
	}
	if strings.Trim(c.EffectiveMount(), "/") == "" {
		return fmt.Errorf("%w: hashicorp_vault.mount must not be empty", ErrInvalidStore)
	}
	if err := validateOptionalFile("hashicorp_vault.ca_cert_file", c.CACertFile); err != nil {
		return err
	}
	return c.Auth.validate()
}

func (a VaultAuth) validate() error {
	switch a.Method {
	case VaultAuthKubernetes:
		if a.Role == "" {
			return fmt.Errorf("%w: hashicorp_vault.auth.role is required for kubernetes auth", ErrInvalidStore)
		}
		return validateOptionalFile("hashicorp_vault.auth.jwt_file", a.JWTFile)
	case VaultAuthJWT:
		if a.Role == "" {
			return fmt.Errorf("%w: hashicorp_vault.auth.role is required for jwt auth", ErrInvalidStore)
		}
		return validateOptionalFile("hashicorp_vault.auth.jwt_file", a.JWTFile)
	case VaultAuthAppRole:
		if a.RoleID == "" {
			return fmt.Errorf("%w: hashicorp_vault.auth.role_id is required for approle auth", ErrInvalidStore)
		}
		return validateRequiredFile("hashicorp_vault.auth.secret_id_file", a.SecretIDFile)
	case VaultAuthToken:
		return validateRequiredFile("hashicorp_vault.auth.token_file", a.TokenFile)
	default:
		return fmt.Errorf("%w: hashicorp_vault.auth.method must be %q, %q, %q or %q", ErrInvalidStore,
			VaultAuthKubernetes, VaultAuthJWT, VaultAuthAppRole, VaultAuthToken)
	}
}

// AWSSecretsManagerConfig reads AWS Secrets Manager with the SDK's default
// credential chain (IRSA, EKS Pod Identity, instance profile), optionally
// assuming a role first.
type AWSSecretsManagerConfig struct {
	Region        string `yaml:"region"`
	Endpoint      string `yaml:"endpoint"`
	AssumeRoleARN string `yaml:"assume_role_arn"`
}

// StoreType implements TypedConfig.
func (*AWSSecretsManagerConfig) StoreType() Type { return TypeAWSSecretsManager }

// Validate implements TypedConfig.
func (c *AWSSecretsManagerConfig) Validate() error {
	if strings.TrimSpace(c.Region) == "" {
		return fmt.Errorf("%w: aws_secrets_manager.region is required", ErrInvalidStore)
	}
	if err := validateEndpoint("aws_secrets_manager.endpoint", c.Endpoint, false); err != nil {
		return err
	}
	if c.AssumeRoleARN != "" && !strings.HasPrefix(c.AssumeRoleARN, "arn:") {
		return fmt.Errorf("%w: aws_secrets_manager.assume_role_arn must be an IAM role ARN", ErrInvalidStore)
	}
	return nil
}

// GCPSecretManagerConfig reads GCP Secret Manager with Application Default
// Credentials (GKE Workload Identity or a mounted key).
type GCPSecretManagerConfig struct {
	ProjectID string `yaml:"project_id"`
}

// StoreType implements TypedConfig.
func (*GCPSecretManagerConfig) StoreType() Type { return TypeGCPSecretManager }

// Validate implements TypedConfig.
func (c *GCPSecretManagerConfig) Validate() error {
	if strings.TrimSpace(c.ProjectID) == "" {
		return fmt.Errorf("%w: gcp_secret_manager.project_id is required", ErrInvalidStore)
	}
	return nil
}

// FileConfig reads files under Root, such as mounted Kubernetes Secrets. A
// reference path is <secret>/<key> under Root.
type FileConfig struct {
	Root string `yaml:"root"`
}

// StoreType implements TypedConfig.
func (*FileConfig) StoreType() Type { return TypeFile }

// Validate implements TypedConfig.
func (c *FileConfig) Validate() error {
	if !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) == string(filepath.Separator) {
		return fmt.Errorf("%w: file.root must be an absolute directory other than /", ErrInvalidStore)
	}
	return nil
}

// EnvConfig reads environment variables whose name starts with Prefix.
type EnvConfig struct {
	Prefix string `yaml:"prefix"`
}

// StoreType implements TypedConfig.
func (*EnvConfig) StoreType() Type { return TypeEnv }

// Validate implements TypedConfig.
func (c *EnvConfig) Validate() error {
	if strings.TrimSpace(c.Prefix) == "" {
		return fmt.Errorf("%w: env.prefix is required, so the store cannot read the plane's own variables", ErrInvalidStore)
	}
	return nil
}

func validateEndpoint(field, raw string, required bool) error {
	if raw == "" {
		if required {
			return fmt.Errorf("%w: %s is required", ErrInvalidStore, field)
		}
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return fmt.Errorf("%w: %s must be an http(s) URL with a host and no credentials", ErrInvalidStore, field)
	}
	return nil
}

func validateRequiredFile(field, path string) error {
	if path == "" {
		return fmt.Errorf("%w: %s is required; inline credentials are not accepted", ErrInvalidStore, field)
	}
	return validateOptionalFile(field, path)
}

func validateOptionalFile(field, path string) error {
	if path != "" && !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s must be an absolute path", ErrInvalidStore, field)
	}
	return nil
}
