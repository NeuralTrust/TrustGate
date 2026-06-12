export interface ListResponse<T> {
  items: T[];
  page: number;
  size: number;
  total: number;
}

export interface ApiError {
  error: string;
  message?: string;
}

export interface Gateway {
  id: string;
  name: string;
  status: string;
  session_config?: SessionConfig | null;
  created_at: string;
  updated_at: string;
}

export interface SessionConfig {
  enabled: boolean;
  header_name?: string;
  body_param_name?: string;
}

export type AuthKind = "api_key" | "azure" | "aws" | "oauth2" | "gcp_service_account";

export interface ApiKeyAuth {
  api_key?: string;
  header_name?: string;
  header_value?: string;
  param_name?: string;
  param_value?: string;
  param_location?: string;
}

export interface AzureAuth {
  use_managed_identity?: boolean;
  endpoint?: string;
  version?: string;
  api_key?: string;
  client_id?: string;
  client_secret?: string;
  tenant_id?: string;
}

export interface AwsAuth {
  access_key_id?: string;
  secret_access_key?: string;
  region?: string;
  session_token?: string;
  role?: string;
  use_role?: boolean;
}

export interface TargetOAuthConfig {
  token_url: string;
  grant_type: string;
  client_id?: string;
  client_secret?: string;
  use_basic_auth?: boolean;
  scopes?: string[];
  audience?: string;
  extra?: Record<string, string>;
}

export interface TargetAuth {
  type: AuthKind;
  api_key?: ApiKeyAuth;
  azure?: AzureAuth;
  aws?: AwsAuth;
  oauth?: TargetOAuthConfig;
  gcp_service_account?: string;
}

export interface HealthChecks {
  passive: boolean;
  path?: string;
  headers?: Record<string, string>;
  threshold: number;
  interval: number;
}

export interface Registry {
  id: string;
  gateway_id: string;
  name: string;
  provider: string;
  provider_options?: Record<string, unknown>;
  description?: string;
  weight?: number;
  auth?: TargetAuth | null;
  health_checks?: HealthChecks | null;
  created_at: string;
  updated_at: string;
}

export type ConsumerType = "LLM" | "MCP" | "A2A";
export type Algorithm =
  | "round-robin"
  | "random"
  | "weighted-round-robin"
  | "least-connections"
  | "semantic";

export interface EmbeddingConfig {
  provider: string;
  model: string;
}

export interface FallbackBudget {
  max_attempts: number;
  max_total_latency_ms?: number;
  max_cost_usd?: number;
}

export interface Fallback {
  enabled: boolean;
  triggers?: string[];
  budget: FallbackBudget;
  chain: string[];
}

export interface ModelPolicy {
  allowed?: string[];
  default?: string;
}

export interface RegistryBinding {
  id: string;
  model_policies?: ModelPolicy | null;
}

export interface ConsumerWeight {
  registry_id: string;
  weight: number;
}

export interface Consumer {
  id: string;
  gateway_id: string;
  name: string;
  type: ConsumerType;
  path: string;
  algorithm: Algorithm;
  embedding_config?: EmbeddingConfig | null;
  headers?: Record<string, string>;
  active: boolean;
  registries: RegistryBinding[];
  auth_ids: string[];
  fallback?: Fallback | null;
  weights?: ConsumerWeight[];
  created_at: string;
  updated_at: string;
}

export type AuthType = "api_key" | "oauth2" | "mtls";

export interface OAuth2Config {
  issuer: string;
  audiences?: string[];
  jwks_url?: string;
  introspection_url?: string;
  client_id?: string;
  client_secret?: string;
  required_scopes?: string[];
  allowed_algorithms?: string[];
}

export interface MtlsConfig {
  ca_cert: string;
  allowed_common_names?: string[];
  allowed_dns_names?: string[];
  allowed_fingerprints?: string[];
}

export interface AuthConfig {
  oauth2?: OAuth2Config;
  mtls?: MtlsConfig;
}

export interface Auth {
  id: string;
  gateway_id: string;
  name: string;
  type: AuthType;
  enabled: boolean;
  config: AuthConfig;
  api_key?: string;
  created_at: string;
  updated_at: string;
}

export type PolicyStage = "pre_request" | "post_request" | "pre_response" | "post_response";

export interface Policy {
  id: string;
  gateway_id: string;
  consumer_ids?: string[];
  name: string;
  slug: string;
  enabled: boolean;
  global: boolean;
  priority: number;
  parallel?: boolean;
  settings?: Record<string, unknown>;
  stages?: PolicyStage[];
  created_at: string;
  updated_at: string;
}

export type AuthFieldType = "string" | "boolean";

export interface CatalogAuthField {
  key: string;
  label: string;
  type: AuthFieldType;
  description?: string;
  required?: boolean;
  secret?: boolean;
  default?: unknown;
}

export interface CatalogAuthTypeOption {
  type: AuthKind;
  variant?: string;
  label: string;
  description?: string;
  fields: CatalogAuthField[];
}

export interface ProviderOptionField {
  key: string;
  label: string;
  type: "string" | "enum" | "map";
  description?: string;
  required?: boolean;
  default?: unknown;
  enum?: string[];
}

export interface Provider {
  id: string;
  code: string;
  display_name: string;
  wire_format?: string;
  source?: string;
  metadata?: Record<string, unknown>;
  auth_types?: CatalogAuthTypeOption[];
  provider_options_schema?: ProviderOptionField[];
}

export interface Model {
  id: string;
  provider_id: string;
  slug: string;
  display_name?: string;
  context_window?: number;
  enabled: boolean;
}
