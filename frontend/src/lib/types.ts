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

export interface Entitlements {
  tier: string;
  burst_per_min?: number;
  quota_per_month?: number;
  max_instances?: number;
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
  entitlements?: Entitlements;
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

// A tool as the upstream MCP server advertised it: `name` plus whatever else it
// declared (description, inputSchema, …), passed through untouched.
export interface McpTool {
  name: string;
  description?: string;
  [key: string]: unknown;
}

export interface McpToolsResponse {
  tools: McpTool[];
}

export interface PriceOverride {
  input: number;
  output: number;
}

export interface RegistryPricing {
  discount?: number;
  overrides?: Record<string, PriceOverride>;
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
  pricing?: RegistryPricing | null;
  mcp_target?: MCPTarget | null;
  created_at: string;
  updated_at: string;
}

// Probe stage the connection test reached (Go: providers.ProbeStage).
export type ProbeStage = "connectivity" | "authentication" | "provider" | "unsupported";

// POST /v1/gateways/{id}/registries/test-connection always answers 200; `ok` and
// `stage` carry the outcome.
export interface TestConnectionResult {
  ok: boolean;
  stage: ProbeStage;
  provider: string;
  status_code?: number;
  latency_ms: number;
  message?: string;
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
  model?: string;
  weight?: number;
}

export interface SmartRoutingTier {
  min_score: number;
  registry_id: string;
  model?: string;
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

export type AuthType = "api_key" | "oauth2" | "mtls";

export interface OAuth2Config {
  issuer: string;
  audiences?: string[];
  jwks_url?: string;
  public_keys?: string[];
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

// Auth types that can drive role-based (identity-provider) consumer routing.
export function isIdentityProviderAuth(type: AuthType): boolean {
  return type === "oauth2";
}

export interface Auth {
  id: string;
  gateway_id: string;
  name: string;
  type: AuthType;
  enabled: boolean;
  config: AuthConfig;
  api_key?: string;
  // Non-secret recognition hints for api_key auths; the full key is only
  // returned once, at creation.
  key_prefix?: string;
  key_suffix?: string;
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
  // Same shape as the plugin catalog's enum options (Go: appplugins.EnumOption).
  enum?: PolicyCatalogEnumOption[];
}

export interface Provider {
  id: string;
  code: string;
  display_name: string;
  wire_format?: string;
  source?: string;
  metadata?: Record<string, unknown>;
  capabilities?: Record<string, boolean>;
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

// GET /v1/playground/traces/{trace_id} mirrors the metrics event the proxy
// captured (Go: events.Event, schema_version 3). Traces are kept in Redis behind
// a short TTL and only when the trace store is enabled, so a 404 means
// "expired, or never recorded".
export interface TraceConsumer {
  id?: string;
  name?: string;
}

export interface TraceStatus {
  code: number;
  is_timeout: boolean;
  outcome?: string;
  reason?: string;
}

export interface TraceRequest {
  method?: string;
  path?: string;
  provider?: string;
  registry_id?: string;
  model?: string;
  requested_model?: string;
  model_label?: string;
  temperature?: number;
  max_tokens?: number;
  stream: boolean;
  prompt_tokens?: number;
  body?: string;
  headers?: Record<string, string[]>;
}

export interface TraceResponse {
  status_code: number;
  latency_ms: number;
  completion_tokens?: number;
  finish_reason?: string;
  streaming: boolean;
  body?: string | null;
  headers?: Record<string, string[]>;
}

export interface TraceUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cached_input_tokens?: number;
  reasoning_output_tokens?: number;
}

export interface TraceCost {
  prompt_usd: number;
  completion_usd: number;
  total_usd: number;
  currency: string;
}

// The stages the wall clock splits into. PoliciesMs covers every stage the chain
// ran (post_response included), and gateway_ms discounts that async share.
export interface TraceLatency {
  total_ms: number;
  provider_ms: number;
  policies_ms: number;
  gateway_ms: number;
}

export interface TraceAttempt {
  registry_id?: string;
  provider?: string;
  attempt: number;
  fallback: boolean;
  pinned: boolean;
  route?: string;
  route_model?: string;
  outcome?: string;
  status_code: number;
  latency_ms: number;
}

export interface TracePolicyEntry {
  name: string;
  stage?: string;
  decision?: string;
  latency_ms: number;
  status_code?: number;
  error: boolean;
  flagged: boolean;
  score?: number;
  score_label?: string;
  extras?: unknown;
}

export interface TraceMcp {
  method: string;
  operation?: string;
  server_name?: string;
  registry_id?: string;
  host?: string;
  catalog_code?: string;
  transport?: string;
  tool?: string;
  upstream_tool?: string;
  prompt?: string;
  resource_uri?: string;
  targets?: number;
  upstream_status?: number;
  upstream_latency_ms?: number;
  rpc_error_code?: number;
}

export interface PlaygroundTrace {
  schema_version: number;
  kind: string;
  trace_id: string;
  gateway_id: string;
  tenant_id?: string;
  timestamp: string;
  occurred_on: number;
  end_timestamp: number;
  consumer: TraceConsumer;
  session_id?: string;
  turn_id?: string;
  ip?: string;
  status: TraceStatus;
  is_flagged: boolean;
  security?: string[];
  request: TraceRequest;
  response: TraceResponse;
  usage?: TraceUsage;
  cost?: TraceCost;
  latency: TraceLatency;
  attempts?: TraceAttempt[];
  policy_chain?: TracePolicyEntry[];
  mcp?: TraceMcp | null;
}

// GET /v1/config-sync/connections — data-plane liveness. Not gateway-scoped and
// without a pagination envelope: it returns every observed connection.
export interface ConfigSyncConnection {
  /** Opaque scope the data plane registered under. */
  scope: string;
  instance_id: string;
  /** "connected" or "disconnected"; treated as free-form for forward safety. */
  state: string;
  applied_version: string;
  first_seen: string;
  last_seen: string;
}

export interface ConfigSyncConnectionsResponse {
  items: ConfigSyncConnection[];
}
