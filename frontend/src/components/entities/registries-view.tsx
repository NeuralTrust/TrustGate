"use client";

import { useState } from "react";
import { Plus, Trash2, Server } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useList, useCatalogQuery, errorMessage } from "@/lib/hooks";
import { useInvalidate } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader, ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Tabs, TabsList, TabTrigger, TabContent } from "@/components/ui/tabs";
import { Badge, EmptyState, PageLoader } from "@/components/ui/misc";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
<<<<<<< Updated upstream
import { Field, Input, Select } from "@/components/ui/field";
import { Section, SwitchRow, Grid2, Divider } from "@/components/ui/form-bits";
=======
import { Field, Input, Label } from "@/components/ui/field";
import { SwitchRow, Grid2 } from "@/components/ui/form-bits";
>>>>>>> Stashed changes
import type { Registry, Provider, TargetAuth, AuthKind } from "@/lib/types";

export function RegistriesView() {
  const { data: registries, isLoading } = useList<Registry>("registries");
  const { data: providers, isLoading: providersLoading } = useCatalogQuery<Provider>(
    "providers",
    "/v1/providers-catalog",
  );
  const form = useDisclosure();
  const [editing, setEditing] = useState<Registry | null>(null);
  const [connect, setConnect] = useState<Provider | null>(null);
  const [toDelete, setToDelete] = useState<Registry | null>(null);

  // A provider is "active" once the user has configured a registry (with
  // credentials) for it. We key the first registry per provider code.
  const registryByProvider = new Map<string, Registry>();
  for (const r of registries ?? []) {
    if (!registryByProvider.has(r.provider)) registryByProvider.set(r.provider, r);
  }

  function openProvider(p: Provider) {
    const existing = registryByProvider.get(p.code);
    setEditing(existing ?? null);
    setConnect(existing ? null : p);
    form.onOpen();
  }

  function handleOpenChange(v: boolean) {
    form.setOpen(v);
    if (!v) {
      setEditing(null);
      setConnect(null);
    }
  }

  return (
    <div>
      <PageHeader description="Configure LLM, MCP, and A2A connections in your AI gateway registry." />

      {isLoading || providersLoading ? (
        <PageLoader />
      ) : (
        <Tabs defaultValue="models">
          <TabsList>
            <TabTrigger value="models">Models</TabTrigger>
            <TabTrigger value="mcp">MCP</TabTrigger>
            <TabTrigger value="a2a">A2A</TabTrigger>
          </TabsList>

          <TabContent value="models" className="pt-4">
            <ProviderTable
              providers={providers ?? []}
              registryByProvider={registryByProvider}
              onOpen={openProvider}
            />
          </TabContent>
          <TabContent value="mcp" className="pt-4">
            <EmptyState
              icon={<Server className="h-5 w-5" />}
              title="No MCP connections"
              description="MCP backends will appear here once they are available in the catalog."
            />
          </TabContent>
          <TabContent value="a2a" className="pt-4">
            <EmptyState
              icon={<Server className="h-5 w-5" />}
              title="No A2A connections"
              description="A2A backends will appear here once they are available in the catalog."
            />
          </TabContent>
        </Tabs>
      )}

      {form.open && (
        <RegistryFormDialog
          open={form.open}
          onOpenChange={handleOpenChange}
          registry={editing}
          initialProvider={connect?.code}
          initialName={connect?.display_name}
          onDelete={
            editing
              ? () => {
                  const target = editing;
                  handleOpenChange(false);
                  setToDelete(target);
                }
              : undefined
          }
        />
      )}

      <DeleteRegistryDialog registry={toDelete} onClose={() => setToDelete(null)} />
    </div>
  );
}

function ProviderTable({
  providers,
  registryByProvider,
  onOpen,
}: {
  providers: Provider[];
  registryByProvider: Map<string, Registry>;
  onOpen: (p: Provider) => void;
}) {
  if (providers.length === 0) {
    return (
      <EmptyState
        icon={<Server className="h-5 w-5" />}
        title="No providers in the catalog"
        description="The provider catalog has not been seeded yet."
      />
    );
  }

  return (
    <Table>
      <THead>
        <TH>Name</TH>
        <TH>Type</TH>
        <TH>Status</TH>
      </THead>
      <TBody>
        {providers.map((p) => {
          const active = registryByProvider.has(p.code);
          const builtIn = (p.source ?? "seed") === "seed";
          return (
            <TR key={p.id} onClick={() => onOpen(p)}>
              <TD>
                <div className="flex items-center gap-3">
                  <span className="flex h-8 w-8 items-center justify-center rounded-(--radius) border border-border bg-surface-2 text-muted">
                    <Server className="h-4 w-4" />
                  </span>
                  <span className="font-medium text-fg">{p.display_name}</span>
                </div>
              </TD>
              <TD>
                <Badge>{builtIn ? "Built-in" : "Custom"}</Badge>
              </TD>
              <TD>
                {active ? <Badge tone="success">Active</Badge> : <Badge>Inactive</Badge>}
              </TD>
            </TR>
          );
        })}
      </TBody>
    </Table>
  );
}

function DeleteRegistryDialog({
  registry,
  onClose,
}: {
  registry: Registry | null;
  onClose: () => void;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  async function confirm() {
    if (!registry) return;
    setLoading(true);
    try {
      await api.del(`${gatewayScope(gatewayId)}/registries/${registry.id}`);
      toast({ variant: "success", title: "Registry deleted", description: registry.name });
      void invalidate("registries");
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Could not delete registry", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ConfirmDialog
      open={registry !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Delete registry"
      description={`"${registry?.name}" will be permanently removed. This fails if a consumer still references it.`}
      onConfirm={confirm}
      loading={loading}
    />
  );
}

// Most providers authenticate with a simple API key; the cloud providers need
// their native credential scheme. This drives the default (and resets when the
// provider changes) so the common case shows nothing but an API key field.
function defaultAuthType(provider: string): AuthKind {
  switch (provider) {
    case "azure":
      return "azure";
    case "bedrock":
      return "aws";
    case "vertex":
      return "gcp_service_account";
    default:
      return "api_key";
  }
}

interface AuthState {
  type: AuthKind;
  apiKey: string;
  headerName: string;
  headerValue: string;
  azureEndpoint: string;
  azureVersion: string;
  azureClientId: string;
  azureClientSecret: string;
  azureTenantId: string;
  azureManagedIdentity: boolean;
  awsAccessKeyId: string;
  awsSecretAccessKey: string;
  awsRegion: string;
  awsRole: string;
  awsUseRole: boolean;
  oauthTokenUrl: string;
  oauthGrantType: string;
  oauthClientId: string;
  oauthClientSecret: string;
  oauthScopes: string;
  gcpServiceAccount: string;
}

function emptyAuth(type: AuthKind = "api_key"): AuthState {
  return {
    type,
    apiKey: "",
    headerName: "",
    headerValue: "",
    azureEndpoint: "",
    azureVersion: "",
    azureClientId: "",
    azureClientSecret: "",
    azureTenantId: "",
    azureManagedIdentity: false,
    awsAccessKeyId: "",
    awsSecretAccessKey: "",
    awsRegion: "",
    awsRole: "",
    awsUseRole: false,
    oauthTokenUrl: "",
    oauthGrantType: "client_credentials",
    oauthClientId: "",
    oauthClientSecret: "",
    oauthScopes: "",
    gcpServiceAccount: "",
  };
}

function buildAuth(a: AuthState): TargetAuth {
  switch (a.type) {
    case "api_key":
      return {
        type: "api_key",
        api_key: {
          ...(a.apiKey ? { api_key: a.apiKey } : {}),
          ...(a.headerName ? { header_name: a.headerName, header_value: a.headerValue } : {}),
        },
      };
    case "azure":
      return {
        type: "azure",
        azure: {
          use_managed_identity: a.azureManagedIdentity,
          endpoint: a.azureEndpoint,
          version: a.azureVersion,
          client_id: a.azureClientId,
          client_secret: a.azureClientSecret,
          tenant_id: a.azureTenantId,
        },
      };
    case "aws":
      return {
        type: "aws",
        aws: {
          access_key_id: a.awsAccessKeyId,
          secret_access_key: a.awsSecretAccessKey,
          region: a.awsRegion,
          role: a.awsRole,
          use_role: a.awsUseRole,
        },
      };
    case "oauth2":
      return {
        type: "oauth2",
        oauth: {
          token_url: a.oauthTokenUrl,
          grant_type: a.oauthGrantType,
          client_id: a.oauthClientId,
          client_secret: a.oauthClientSecret,
          scopes: a.oauthScopes ? a.oauthScopes.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
        },
      };
    case "gcp_service_account":
      return { type: "gcp_service_account", gcp_service_account: a.gcpServiceAccount };
  }
}

function RegistryFormDialog({
  open,
  onOpenChange,
  registry,
  initialProvider,
  initialName,
  onDelete,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  registry: Registry | null;
  initialProvider?: string;
  initialName?: string;
  onDelete?: () => void;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const isEdit = registry !== null;

  // Provider is chosen by clicking a catalog row, and the connection name just
  // mirrors the provider — neither needs a form field.
  const provider = registry?.provider ?? initialProvider ?? "openai";
  const name = registry?.name ?? initialName ?? provider;

<<<<<<< Updated upstream
  const [name, setName] = useState(registry?.name ?? "");
  const [provider, setProvider] = useState(registry?.provider ?? "openai");
  const [weight, setWeight] = useState(String(registry?.weight ?? 1));
  const [description, setDescription] = useState(registry?.description ?? "");
  const [auth, setAuth] = useState<AuthState>(emptyAuth((registry?.auth?.type as AuthKind) ?? "api_key"));
  const [healthEnabled, setHealthEnabled] = useState(Boolean(registry?.health_checks));
  const [hcPath, setHcPath] = useState(registry?.health_checks?.path ?? "/health");
  const [hcThreshold, setHcThreshold] = useState(String(registry?.health_checks?.threshold ?? 3));
  const [hcInterval, setHcInterval] = useState(String(registry?.health_checks?.interval ?? 30));
  const [hcPassive, setHcPassive] = useState(registry?.health_checks?.passive ?? false);
=======
  const [auth, setAuth] = useState<AuthState>(
    emptyAuth((registry?.auth?.type as AuthKind) ?? defaultAuthType(provider)),
  );
  const [baseUrl, setBaseUrl] = useState(() => readBaseUrl(registry?.provider_options));
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>(() => readHeaderRows(registry?.provider_options));
>>>>>>> Stashed changes
  const [submitting, setSubmitting] = useState(false);

  function set<K extends keyof AuthState>(key: K, value: AuthState[K]) {
    setAuth((prev) => ({ ...prev, [key]: value }));
  }

  async function submit() {
    if (!name.trim()) {
      toast({ variant: "error", title: "Name is required" });
      return;
    }
    const body: Record<string, unknown> = {
      name: name.trim(),
      provider,
      weight: 1,
      auth: buildAuth(auth),
    };
<<<<<<< Updated upstream
    if (description.trim()) body.description = description.trim();
    if (healthEnabled) {
      body.health_checks = {
        passive: hcPassive,
        path: hcPath,
        threshold: Number(hcThreshold) || 1,
        interval: Number(hcInterval) || 1,
      };
=======
    if (provider === PROVIDER_OPTIONS_PROVIDER) {
      if (!baseUrl.trim()) {
        toast({
          variant: "error",
          title: "Base URL is required",
          description: "OpenAI-compatible providers need a base URL.",
        });
        return;
      }
      const headers: Record<string, string> = {};
      for (const row of headerRows) {
        const key = row.key.trim();
        if (key) headers[key] = row.value;
      }
      body.provider_options = {
        base_url: baseUrl.trim(),
        ...(Object.keys(headers).length > 0 ? { headers } : {}),
      };
    } else if (isEdit && registry.provider === provider && registry.provider_options) {
      // Preserve provider_options the form does not manage (e.g. vertex
      // project/location) so a full-replace PUT does not wipe them.
      body.provider_options = registry.provider_options;
>>>>>>> Stashed changes
    }

    setSubmitting(true);
    try {
      const base = `${gatewayScope(gatewayId)}/registries`;
      if (isEdit) {
        await api.put(`${base}/${registry.id}`, body);
      } else {
        await api.post(base, body);
      }
      toast({
        variant: "success",
        title: isEdit ? "Registry updated" : "Registry created",
        description: name,
      });
      void invalidate("registries");
      onOpenChange(false);
    } catch (err) {
      toast({ variant: "error", title: "Save failed", description: errorMessage(err) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader
          title={isEdit ? "Edit connection" : initialName ? `Connect ${initialName}` : "New connection"}
          description={
            isEdit
              ? "Updates replace the connection configuration in full."
              : "Set credentials to activate this provider."
          }
        />
        <DialogBody className="flex flex-col gap-5">
<<<<<<< Updated upstream
          <Grid2>
            <Field label="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="openai-primary" />
            </Field>
            <Field label="Provider">
              <Select value={provider} onChange={(e) => setProvider(e.target.value)}>
                {providers && providers.length > 0 ? (
                  providers.map((p) => (
                    <option key={p.id} value={p.code}>
                      {p.display_name}
                    </option>
                  ))
                ) : (
                  <option value="openai">openai</option>
                )}
              </Select>
            </Field>
          </Grid2>
          <Grid2>
            <Field label="Weight" hint="load balancing">
              <Input type="number" min={0} value={weight} onChange={(e) => setWeight(e.target.value)} />
            </Field>
            <Field label="Description" hint="optional">
              <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Primary OpenAI pool" />
            </Field>
          </Grid2>

          <Divider />

          <Section title="Authentication" description={isEdit ? "Secrets are write-only — re-enter to change them." : "Credentials used to reach the provider."}>
            <Field label="Type">
              <Select value={auth.type} onChange={(e) => set("type", e.target.value as AuthKind)}>
                {AUTH_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </Select>
=======
          {provider === PROVIDER_OPTIONS_PROVIDER && (
            <>
              <Field label="Base URL" hint="required">
                <Input
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder="https://api.together.xyz/v1"
                />
              </Field>
              <div className="flex flex-col gap-2">
                <Label hint="optional">Custom headers</Label>
                {headerRows.map((row, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <Input
                      value={row.key}
                      onChange={(e) => updateHeaderRow(i, "key", e.target.value)}
                      placeholder="X-Custom-Header"
                    />
                    <Input
                      value={row.value}
                      onChange={(e) => updateHeaderRow(i, "value", e.target.value)}
                      placeholder="value"
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => removeHeaderRow(i)}
                      aria-label="Remove header"
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                ))}
                <div>
                  <Button variant="ghost" size="sm" onClick={addHeaderRow}>
                    <Plus className="h-4 w-4" />
                    Add header
                  </Button>
                </div>
              </div>
            </>
          )}

          {auth.type === "api_key" && (
            <Field label="API key">
              <Input
                type="password"
                value={auth.apiKey}
                onChange={(e) => set("apiKey", e.target.value)}
                placeholder="sk-..."
              />
>>>>>>> Stashed changes
            </Field>
          )}

          {auth.type === "azure" && (
              <>
                <SwitchRow
                  label="Use managed identity"
                  checked={auth.azureManagedIdentity}
                  onCheckedChange={(v) => set("azureManagedIdentity", v)}
                />
                <Grid2>
                  <Field label="Endpoint">
                    <Input value={auth.azureEndpoint} onChange={(e) => set("azureEndpoint", e.target.value)} />
                  </Field>
                  <Field label="API version">
                    <Input value={auth.azureVersion} onChange={(e) => set("azureVersion", e.target.value)} />
                  </Field>
                </Grid2>
                <Grid2>
                  <Field label="Client ID">
                    <Input value={auth.azureClientId} onChange={(e) => set("azureClientId", e.target.value)} />
                  </Field>
                  <Field label="Client secret">
                    <Input type="password" value={auth.azureClientSecret} onChange={(e) => set("azureClientSecret", e.target.value)} />
                  </Field>
                </Grid2>
                <Field label="Tenant ID">
                  <Input value={auth.azureTenantId} onChange={(e) => set("azureTenantId", e.target.value)} />
                </Field>
              </>
            )}

            {auth.type === "aws" && (
              <>
                <SwitchRow label="Assume role" checked={auth.awsUseRole} onCheckedChange={(v) => set("awsUseRole", v)} />
                <Grid2>
                  <Field label="Access key ID">
                    <Input value={auth.awsAccessKeyId} onChange={(e) => set("awsAccessKeyId", e.target.value)} />
                  </Field>
                  <Field label="Secret access key">
                    <Input type="password" value={auth.awsSecretAccessKey} onChange={(e) => set("awsSecretAccessKey", e.target.value)} />
                  </Field>
                </Grid2>
                <Grid2>
                  <Field label="Region">
                    <Input value={auth.awsRegion} onChange={(e) => set("awsRegion", e.target.value)} placeholder="us-east-1" />
                  </Field>
                  <Field label="Role ARN" hint="optional">
                    <Input value={auth.awsRole} onChange={(e) => set("awsRole", e.target.value)} />
                  </Field>
                </Grid2>
              </>
            )}

            {auth.type === "oauth2" && (
              <>
                <Grid2>
                  <Field label="Token URL">
                    <Input value={auth.oauthTokenUrl} onChange={(e) => set("oauthTokenUrl", e.target.value)} />
                  </Field>
                  <Field label="Grant type">
                    <Input value={auth.oauthGrantType} onChange={(e) => set("oauthGrantType", e.target.value)} />
                  </Field>
                </Grid2>
                <Grid2>
                  <Field label="Client ID">
                    <Input value={auth.oauthClientId} onChange={(e) => set("oauthClientId", e.target.value)} />
                  </Field>
                  <Field label="Client secret">
                    <Input type="password" value={auth.oauthClientSecret} onChange={(e) => set("oauthClientSecret", e.target.value)} />
                  </Field>
                </Grid2>
                <Field label="Scopes" hint="comma-separated">
                  <Input value={auth.oauthScopes} onChange={(e) => set("oauthScopes", e.target.value)} placeholder="read, write" />
                </Field>
              </>
            )}

            {auth.type === "gcp_service_account" && (
              <Field label="Service account JSON">
                <Input value={auth.gcpServiceAccount} onChange={(e) => set("gcpServiceAccount", e.target.value)} placeholder='{"type":"service_account",...}' />
              </Field>
            )}
        </DialogBody>
        <DialogFooter>
          {isEdit && onDelete && (
            <Button variant="danger" onClick={onDelete} className="mr-auto">
              <Trash2 className="h-4 w-4" />
              Disconnect
            </Button>
          )}
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="primary" onClick={submit} loading={submitting}>
            {isEdit ? "Save changes" : "Connect"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
