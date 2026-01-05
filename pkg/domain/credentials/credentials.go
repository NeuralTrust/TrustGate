package credentials

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// Credentials represents authentication configuration for upstream services
type Credentials struct {
	// Api Key
	ApiKey string `json:"api_key,omitempty"`
	// Header-based auth
	HeaderName  string `json:"header_name,omitempty"`
	HeaderValue string `json:"header_value,omitempty"`

	// Parameter-based auth
	ParamName     string `json:"param_name,omitempty"`
	ParamValue    string `json:"param_value,omitempty"`
	ParamLocation string `json:"param_location,omitempty"` // "query" or "body"

	// Azure auth
	AzureUseManagedIdentity bool   `json:"azure_use_managed_identity,omitempty"`
	AzureEndpoint           string `json:"azure_endpoint,omitempty"`
	AzureVersion            string `json:"azure_version,omitempty"`
	AzureClientID           string `json:"azure_client_id,omitempty"`
	AzureClientSecret       string `json:"azure_client_secret,omitempty"`
	AzureTenantID           string `json:"azure_tenant_id,omitempty"`

	// GCP auth
	GCPUseServiceAccount  bool   `json:"gcp_use_service_account,omitempty"`
	GCPServiceAccountJSON string `json:"gcp_service_account_json,omitempty"`

	// AWS auth
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	AWSRegion          string `json:"aws_region,omitempty"`
	AWSSessionToken    string `json:"aws_session_token,omitempty"`
	AWSRole            string `json:"aws_role,omitempty"`
	AWSUseRole         bool   `json:"aws_use_role,omitempty"`
}

// Scan implements sql.Scanner for database deserialization
func (c *Credentials) Scan(value interface{}) error {
	bytes, ok := value.([]byte)
	if !ok {
		return fmt.Errorf("failed to scan Credentials: type assertion to []byte failed")
	}
	return json.Unmarshal(bytes, c)
}

// Value implements driver.Valuer for database serialization
func (c Credentials) Value() (driver.Value, error) {
	return json.Marshal(c)
}
