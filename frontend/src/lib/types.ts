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

export interface GatewayHosts {
  proxy?: string;
  mcp?: string;
}

export interface Gateway {
  id: string;
  slug: string;
  status: string;
  version?: string;
  domain?: string;
  hosts?: GatewayHosts | null;
  metadata?: Record<string, string> | null;
  telemetry?: Record<string, unknown> | null;
  client_tls?: Record<string, unknown> | null;
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

export type RegistryType = "LLM" | "MCP";

export type MCPAuthMode = "none" | "static" | "passthrough" | "exchange" | "forwarded";

export interface MCPAuth {
  mode: MCPAuthMode;
  header?: string;
  value?: string;
  expected_audience?: string;
  pattern?: string;
  audience?: string;
  actor?: string;
  scope?: string;
  provider?: string;
  registration?: string;
  client_id?: string;
  client_secret?: string;
  authorize_url?: string;
  token_url?: string;
  scopes?: string[];
  resource?: string;
}

export interface MCPTarget {
  /** Catalog server code this connection was created from (empty for custom servers). */
  code?: string;
  url: string;
  transport?: string;
  headers?: Record<string, string>;
  auth?: MCPAuth | null;
}

export interface Registry {
  id: string;
  gateway_id: string;
  name: string;
  type?: RegistryType;
  provider: string;
  provider_options?: Record<string, unknown>;
  description?: string;
  enabled?: boolean;
  auth?: TargetAuth | null;
  health_checks?: HealthChecks | null;
  mcp_target?: MCPTarget | null;
  created_at: string;
  updated_at: string;
}

export type ConsumerType = "LLM" | "MCP" | "A2A";
export type RoutingMode = "inline" | "role_based";
export type Algorithm =
  | "round-robin"
  | "random"
  | "weighted-round-robin"
  | "least-connections"
  | "semantic"
  | "smart-routing";

export interface EmbeddingAuth {
  api_key?: string;
  header_name?: string;
  header_value?: string;
  param_name?: string;
  param_value?: string;
  param_location?: string;
}

export interface EmbeddingConfig {
  provider: string;
  model: string;
  auth?: EmbeddingAuth | null;
}

export interface LBPoolMember {
  registry_id: string;
  models?: string[];
}

export interface SmartRoutingTier {
  min_score: number;
  registry_id: string;
}

export interface SmartRoutingConfig {
  tiers: SmartRoutingTier[];
}

export interface LBConfig {
  enabled: boolean;
  algorithm?: Algorithm;
  pool_alias?: string;
  members?: LBPoolMember[];
  embedding_config?: EmbeddingConfig | null;
  smart_routing?: SmartRoutingConfig | null;
}

export interface RegistryWeight {
  registry_id: string;
  weight: number;
}

export interface ModelPolicy {
  registry_id: string;
  allowed?: string[];
  default?: string;
}

export interface ToolkitEntry {
  registry_id: string;
  tool?: string;
  prompt?: string;
  resource?: string;
  expose_as?: string;
}

export interface FallbackBudget {
  max_attempts: number;
  max_total_latency_ms?: number;
}

export interface Fallback {
  enabled: boolean;
  triggers?: string[];
  budget: FallbackBudget;
  chain: string[];
}

export interface Consumer {
  id: string;
  gateway_id: string;
  name: string;
  type: ConsumerType;
  slug: string;
  routing_mode: RoutingMode;
  lb_config?: LBConfig | null;
  headers?: Record<string, string>;
  active: boolean;
  registry_ids: string[];
  registry_weights?: RegistryWeight[];
  role_ids: string[];
  auth_ids: string[];
  fallback?: Fallback | null;
  model_policies?: ModelPolicy[];
  toolkit?: ToolkitEntry[];
  fail_mode?: string;
  created_at: string;
  updated_at: string;
}

export type AuthType = "api_key" | "oauth2" | "oidc" | "mtls";

export interface OAuth2Config {
  issuer: string;
  audiences?: string[];
  jwks_url?: string;
  introspection_url?: string;
  client_id?: string;
  client_secret?: string;
  required_scopes?: string[];
  allowed_algorithms?: string[];
  session_mode?: boolean;
  userinfo_url?: string;
  subject_claim?: string;
  authorize_url?: string;
  token_url?: string;
}

export interface OidcConfig {
  issuer: string;
  audiences?: string[];
  jwks_url?: string;
  public_keys?: string[];
  required_scopes?: string[];
  allowed_algorithms?: string[];
  subject_claim?: string;
}

export interface MtlsConfig {
  ca_cert: string;
  allowed_common_names?: string[];
  allowed_dns_names?: string[];
  allowed_fingerprints?: string[];
}

export interface AuthConfig {
  oauth2?: OAuth2Config;
  oidc?: OidcConfig;
  mtls?: MtlsConfig;
}

// Auth types that can drive role-based (identity-provider) consumer routing.
export function isIdentityProviderAuth(type: AuthType): boolean {
  return type === "oauth2" || type === "oidc";
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

export type OidcMatch = "any" | "all";
export type OidcClaimOp = "equals" | "contains_any" | "contains_all";

export interface OidcClaim {
  path: string;
  op: OidcClaimOp;
  values: string[];
}

export interface OidcMapping {
  match: OidcMatch;
  claims: OidcClaim[];
}

export interface RoleModelPolicy {
  registry_id: string;
  allowed?: string[];
  default?: string;
}

export interface RoleToolkitEntry {
  registry_id: string;
  tool?: string;
  prompt?: string;
  resource?: string;
  expose_as?: string;
}

export interface RoleMcpPolicies {
  toolkit?: RoleToolkitEntry[];
  fail_mode?: string;
}

export interface Role {
  id: string;
  gateway_id: string;
  name: string;
  model_policies?: RoleModelPolicy[];
  mcp_policies?: RoleMcpPolicies | null;
  oidc_mapping?: OidcMapping | null;
  registry_ids: string[];
  created_at: string;
  updated_at: string;
}

export type PolicyStage = "pre_request" | "post_request" | "pre_response" | "post_response";
export type PolicyMode = "enforce" | "throttle" | "observe";

export interface Policy {
  id: string;
  gateway_id: string;
  consumer_ids?: string[];
  name: string;
  slug: string;
  description?: string;
  enabled: boolean;
  global: boolean;
  priority: number;
  parallel?: boolean;
  mode?: string;
  settings?: Record<string, unknown>;
  stages?: PolicyStage[];
  created_at: string;
  updated_at: string;
}

export interface PolicyCatalogEnumOption {
  value: string;
  label: string;
}

export interface PolicyCatalogField {
  key: string;
  label: string;
  type: "string" | "integer" | "number" | "boolean" | "duration" | "enum" | "object" | "array" | "map";
  description?: string;
  required?: boolean;
  default?: unknown;
  enum?: PolicyCatalogEnumOption[];
  fields?: PolicyCatalogField[];
  item?: Record<string, unknown>;
  key_options?: string[];
  value?: Record<string, unknown>;
}

export interface PolicyCatalogEntry {
  slug: string;
  name: string;
  description?: string;
  mandatory_stages: PolicyStage[];
  supported_stages: PolicyStage[];
  supported_modes: PolicyMode[];
  supported_protocols: string[];
  default_mode: string;
  settings_schema?: { fields?: PolicyCatalogField[] } | null;
}

export interface PolicyCatalogGroup {
  type: string;
  items: PolicyCatalogEntry[];
}

export interface PolicyCatalog {
  groups: PolicyCatalogGroup[];
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
  external_id?: string;
  display_name?: string;
  context_window?: number;
  max_output?: number;
  input_price?: string;
  output_price?: string;
  capabilities?: Record<string, unknown>;
  enabled: boolean;
  source?: string;
  release_date?: string;
  input_modalities?: string[];
  output_modalities?: string[];
}

export type MCPAuthHint = "none" | "static" | "oauth";

export interface MCPURLVariable {
  name: string;
  description?: string;
  required?: boolean;
  secret?: boolean;
  in?: "path" | "query";
}

export interface MCPAuthHeader {
  name: string;
  description?: string;
  required?: boolean;
  secret?: boolean;
  scheme?: "Bearer" | "Token" | "Basic" | "ApiKey" | "App" | "raw";
}

export interface MCPOAuth {
  registration?: string;
  dcr?: boolean;
  pkce?: boolean;
  authorize_url?: string;
  token_url?: string;
  scopes?: string[];
  resource?: string;
}

export interface MCPServer {
  code: string;
  display_name: string;
  vendor?: string;
  category?: string;
  description?: string;
  url: string;
  transport: string;
  auth_hint: MCPAuthHint;
  requires_auth: boolean;
  requires_config: boolean;
  relevance?: number;
  scopes?: string[];
  url_variables?: MCPURLVariable[];
  auth_headers?: MCPAuthHeader[];
  oauth?: MCPOAuth | null;
  metadata?: Record<string, unknown>;
  source?: string;
}

export interface MCPServersResponse {
  mcp_servers: MCPServer[];
}
