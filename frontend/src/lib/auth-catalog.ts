import type {
  AuthKind,
  AzureAuth,
  AwsAuth,
  CatalogAuthField,
  CatalogAuthTypeOption,
  TargetAuth,
} from "@/lib/types";

export type AuthFieldValues = Record<string, string | boolean>;

export function authOptionKey(option: CatalogAuthTypeOption): string {
  return option.variant ?? option.type;
}

export function findAuthOption(
  options: CatalogAuthTypeOption[],
  key: string,
): CatalogAuthTypeOption | undefined {
  return options.find((option) => authOptionKey(option) === key);
}

export function fallbackAuthOptions(providerCode: string): CatalogAuthTypeOption[] {
  switch (providerCode) {
    case "azure":
      return [
        {
          type: "azure",
          variant: "api_key",
          label: "API Key",
          fields: [
            { key: "endpoint", label: "Endpoint", type: "string", required: true },
            { key: "version", label: "API Version", type: "string" },
            { key: "api_key", label: "API Key", type: "string", required: true, secret: true },
          ],
        },
        {
          type: "azure",
          variant: "service_principal",
          label: "Service principal",
          fields: [
            { key: "endpoint", label: "Endpoint", type: "string", required: true },
            { key: "tenant_id", label: "Tenant ID", type: "string", required: true },
            { key: "client_id", label: "Client ID", type: "string", required: true },
            { key: "client_secret", label: "Client Secret", type: "string", required: true, secret: true },
          ],
        },
        {
          type: "azure",
          variant: "managed_identity",
          label: "Managed identity",
          fields: [
            { key: "endpoint", label: "Endpoint", type: "string", required: true },
            {
              key: "use_managed_identity",
              label: "Use Managed Identity",
              type: "boolean",
              required: true,
              default: true,
            },
          ],
        },
      ];
    case "bedrock":
      return [
        {
          type: "aws",
          variant: "access_key",
          label: "Access key",
          fields: [
            { key: "region", label: "Region", type: "string", required: true },
            { key: "access_key_id", label: "Access Key ID", type: "string", required: true },
            { key: "secret_access_key", label: "Secret Access Key", type: "string", required: true, secret: true },
            { key: "session_token", label: "Session Token", type: "string", secret: true },
          ],
        },
        {
          type: "aws",
          variant: "assume_role",
          label: "Assume role",
          fields: [
            { key: "region", label: "Region", type: "string", required: true },
            { key: "access_key_id", label: "Access Key ID", type: "string", required: true },
            { key: "secret_access_key", label: "Secret Access Key", type: "string", required: true, secret: true },
            { key: "role", label: "Role ARN", type: "string", required: true },
            { key: "use_role", label: "Assume Role", type: "boolean", required: true, default: true },
          ],
        },
      ];
    case "vertex":
      return [
        {
          type: "gcp_service_account",
          label: "GCP Service Account",
          fields: [
            {
              key: "gcp_service_account",
              label: "Service Account JSON",
              type: "string",
              required: true,
              secret: true,
            },
          ],
        },
      ];
    default:
      return [
        {
          type: "api_key",
          label: "API Key",
          fields: [{ key: "api_key", label: "API Key", type: "string", required: true, secret: true }],
        },
      ];
  }
}

export function providerAuthOptions(
  providerCode: string,
  catalog?: CatalogAuthTypeOption[],
): CatalogAuthTypeOption[] {
  if (catalog && catalog.length > 0) {
    return catalog;
  }
  return fallbackAuthOptions(providerCode);
}

export function inferAuthOption(
  auth: TargetAuth,
  options: CatalogAuthTypeOption[],
): CatalogAuthTypeOption {
  const fallback = options[0];
  if (!fallback) {
    throw new Error("auth catalog options are required");
  }
  if (options.length === 1) {
    return fallback;
  }

  if (auth.type === "azure" && auth.azure) {
    const azure = auth.azure;
    if (azure.use_managed_identity) {
      return options.find((option) => option.variant === "managed_identity") ?? fallback;
    }
    if (azure.tenant_id || azure.client_id || azure.client_secret) {
      return options.find((option) => option.variant === "service_principal") ?? fallback;
    }
    if (azure.api_key) {
      return options.find((option) => option.variant === "api_key") ?? fallback;
    }
  }

  if (auth.type === "aws" && auth.aws) {
    if (auth.aws.use_role || auth.aws.role) {
      return options.find((option) => option.variant === "assume_role") ?? fallback;
    }
    return options.find((option) => option.variant === "access_key") ?? fallback;
  }

  return options.find((option) => option.type === auth.type) ?? fallback;
}

export function emptyFieldValues(option: CatalogAuthTypeOption): AuthFieldValues {
  const values: AuthFieldValues = {};
  for (const field of option.fields) {
    if (field.type === "boolean") {
      values[field.key] = typeof field.default === "boolean" ? field.default : false;
      continue;
    }
    values[field.key] = typeof field.default === "string" ? field.default : "";
  }
  return values;
}

export function fieldValuesFromAuth(
  auth: TargetAuth,
  option: CatalogAuthTypeOption,
): AuthFieldValues {
  const values = emptyFieldValues(option);
  const source = authPayload(auth);

  for (const field of option.fields) {
    const raw = source[field.key];
    if (raw === undefined || raw === null) {
      continue;
    }
    values[field.key] = typeof raw === "boolean" ? raw : String(raw);
  }

  return values;
}

function authPayload(auth: TargetAuth): Record<string, unknown> {
  switch (auth.type) {
    case "api_key":
      return { api_key: auth.api_key?.api_key ?? "" };
    case "azure":
      return { ...(auth.azure ?? {}) };
    case "aws":
      return { ...(auth.aws ?? {}) };
    case "gcp_service_account":
      return { gcp_service_account: auth.gcp_service_account ?? "" };
    case "oauth2":
      return { ...(auth.oauth ?? {}) };
    default:
      return {};
  }
}

export function buildTargetAuth(
  option: CatalogAuthTypeOption,
  values: AuthFieldValues,
): TargetAuth {
  const allowed = new Set(option.fields.map((field) => field.key));

  switch (option.type) {
    case "api_key": {
      const apiKey = stringValue(values, "api_key");
      return {
        type: "api_key",
        api_key: apiKey ? { api_key: apiKey } : {},
      };
    }
    case "azure": {
      const azure: AzureAuth = {};
      assignAzureField(azure, allowed, values, "endpoint");
      assignAzureField(azure, allowed, values, "version");
      assignAzureField(azure, allowed, values, "api_key");
      assignAzureField(azure, allowed, values, "tenant_id");
      assignAzureField(azure, allowed, values, "client_id");
      assignAzureField(azure, allowed, values, "client_secret");
      if (allowed.has("use_managed_identity")) {
        azure.use_managed_identity = Boolean(values.use_managed_identity);
      }
      return { type: "azure", azure };
    }
    case "aws": {
      const aws: AwsAuth = {};
      assignAwsField(aws, allowed, values, "region");
      assignAwsField(aws, allowed, values, "access_key_id");
      assignAwsField(aws, allowed, values, "secret_access_key");
      assignAwsField(aws, allowed, values, "session_token");
      assignAwsField(aws, allowed, values, "role");
      if (allowed.has("use_role")) {
        aws.use_role = Boolean(values.use_role);
      }
      return { type: "aws", aws };
    }
    case "gcp_service_account": {
      const serviceAccount = stringValue(values, "gcp_service_account");
      return { type: "gcp_service_account", gcp_service_account: serviceAccount };
    }
    case "oauth2":
      return {
        type: "oauth2",
        oauth: {
          token_url: stringValue(values, "token_url"),
          grant_type: stringValue(values, "grant_type") || "client_credentials",
          client_id: stringValue(values, "client_id") || undefined,
          client_secret: stringValue(values, "client_secret") || undefined,
          scopes: stringValue(values, "scopes")
            ? stringValue(values, "scopes")
                .split(",")
                .map((scope) => scope.trim())
                .filter(Boolean)
            : undefined,
        },
      };
    default:
      return { type: option.type as AuthKind };
  }
}

function assignAzureField(
  azure: AzureAuth,
  allowed: Set<string>,
  values: AuthFieldValues,
  key: keyof AzureAuth,
) {
  if (!allowed.has(key)) {
    return;
  }
  if (key === "use_managed_identity") {
    azure.use_managed_identity = Boolean(values[key]);
    return;
  }
  const value = stringValue(values, key);
  if (value) {
    azure[key] = value;
  }
}

function assignAwsField(
  aws: AwsAuth,
  allowed: Set<string>,
  values: AuthFieldValues,
  key: keyof AwsAuth,
) {
  if (!allowed.has(key) || key === "use_role") {
    return;
  }
  const value = stringValue(values, key);
  if (value) {
    aws[key] = value;
  }
}

function stringValue(values: AuthFieldValues, key: string): string {
  const value = values[key];
  return typeof value === "string" ? value.trim() : "";
}

export function missingRequiredFields(
  option: CatalogAuthTypeOption,
  values: AuthFieldValues,
  isEdit: boolean,
): CatalogAuthField[] {
  return option.fields.filter((field) => {
    if (!field.required) {
      return false;
    }
    if (field.secret && isEdit) {
      return false;
    }
    return !fieldHasValue(field, values[field.key]);
  });
}

function fieldHasValue(field: CatalogAuthField, value: string | boolean | undefined): boolean {
  if (field.type === "boolean") {
    return typeof value === "boolean";
  }
  return typeof value === "string" && value.trim() !== "";
}
