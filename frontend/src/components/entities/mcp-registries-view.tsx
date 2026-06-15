"use client";

import { useMemo, useState } from "react";
import { Plus, Trash2, Server } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useInvalidate, useMcpCatalog, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Badge, EmptyState, Mono } from "@/components/ui/misc";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import type { MCPAuth, MCPAuthMode, MCPServer, MCPTarget, Registry } from "@/lib/types";

const CUSTOM = "__custom__";
const DEFAULT_TRANSPORT = "streamable-http";

type ExchangePattern = "impersonation" | "delegation" | "obo" | "token_exchange";

const CUSTOM_AUTH_MODES: { value: MCPAuthMode; label: string }[] = [
  { value: "none", label: "None" },
  { value: "static", label: "Static header" },
  { value: "forwarded", label: "OAuth (forwarded)" },
  { value: "passthrough", label: "Passthrough" },
  { value: "exchange", label: "Token exchange" },
];

const EXCHANGE_PATTERNS: { value: ExchangePattern; label: string }[] = [
  { value: "impersonation", label: "Impersonation" },
  { value: "delegation", label: "Delegation" },
  { value: "obo", label: "On-behalf-of (OBO)" },
  { value: "token_exchange", label: "Token exchange" },
];

function authModeLabel(target?: MCPTarget | null): string {
  const mode = target?.auth?.mode ?? "none";
  if (mode === "forwarded") {
    const reg = target?.auth?.registration;
    return reg ? `oauth (${reg})` : "oauth";
  }
  return mode;
}

function substituteUrl(server: MCPServer, values: Record<string, string>): string {
  let url = server.url;
  const query: string[] = [];
  for (const variable of server.url_variables ?? []) {
    const value = values[variable.name] ?? "";
    if (variable.in === "query") {
      if (value) query.push(`${encodeURIComponent(variable.name)}=${encodeURIComponent(value)}`);
    } else {
      url = url.replace(`{${variable.name}}`, encodeURIComponent(value));
    }
  }
  if (query.length > 0) {
    url += (url.includes("?") ? "&" : "?") + query.join("&");
  }
  return url;
}

function buildCatalogTarget(
  server: MCPServer,
  urlValues: Record<string, string>,
  headerValues: Record<string, string>,
  clientId: string,
  clientSecret: string,
): MCPTarget {
  const headers: Record<string, string> = {};
  let auth: MCPAuth = { mode: "none" };

  if (server.auth_hint === "static") {
    const required = server.auth_headers ?? [];
    const secretHeader = required.find((h) => h.secret) ?? required[0];
    if (secretHeader) {
      const raw = headerValues[secretHeader.name] ?? "";
      const prefix =
        secretHeader.scheme && secretHeader.scheme !== "raw" ? `${secretHeader.scheme} ` : "";
      auth = { mode: "static", header: secretHeader.name, value: `${prefix}${raw}` };
    }
    for (const header of required) {
      if (header === secretHeader) continue;
      const value = headerValues[header.name];
      if (value) headers[header.name] = value;
    }
  } else if (server.auth_hint === "oauth") {
    if (server.oauth?.registration === "manual") {
      auth = {
        mode: "forwarded",
        provider: server.code,
        registration: "manual",
        client_id: clientId,
        ...(clientSecret ? { client_secret: clientSecret } : {}),
        ...(server.oauth?.authorize_url ? { authorize_url: server.oauth.authorize_url } : {}),
        ...(server.oauth?.token_url ? { token_url: server.oauth.token_url } : {}),
        ...(server.oauth?.scopes?.length ? { scopes: server.oauth.scopes } : {}),
        ...(server.oauth?.resource ? { resource: server.oauth.resource } : {}),
      };
    } else {
      auth = { mode: "forwarded", provider: server.code, registration: "auto" };
    }
  }

  return {
    url: substituteUrl(server, urlValues),
    transport: server.transport || DEFAULT_TRANSPORT,
    ...(Object.keys(headers).length > 0 ? { headers } : {}),
    auth,
  };
}

export function McpRegistriesView({ registries }: { registries: Registry[] }) {
  const form = useDisclosure();
  const [toDelete, setToDelete] = useState<Registry | null>(null);

  const mcpRegistries = useMemo(
    () => registries.filter((r) => r.type === "MCP"),
    [registries],
  );

  return (
    <div className="flex flex-col gap-4">
      <div className="flex justify-end">
        <Button variant="primary" size="sm" onClick={form.onOpen}>
          <Plus className="h-4 w-4" />
          Add MCP server
        </Button>
      </div>

      {mcpRegistries.length === 0 ? (
        <EmptyState
          icon={<Server className="h-5 w-5" />}
          title="No MCP connections"
          description="Connect an MCP server from the catalog or add one manually."
          action={
            <Button variant="primary" size="sm" onClick={form.onOpen}>
              <Plus className="h-4 w-4" />
              Add MCP server
            </Button>
          }
        />
      ) : (
        <Table>
          <THead>
            <TH>Name</TH>
            <TH>URL</TH>
            <TH>Transport</TH>
            <TH>Auth</TH>
            <TH className="text-right pr-4">Actions</TH>
          </THead>
          <TBody>
            {mcpRegistries.map((r) => (
              <TR key={r.id}>
                <TD>
                  <span className="font-medium text-fg">{r.name}</span>
                </TD>
                <TD>
                  <Mono>{r.mcp_target?.url ?? "—"}</Mono>
                </TD>
                <TD>
                  <span className="text-[12px] text-muted">
                    {r.mcp_target?.transport ?? DEFAULT_TRANSPORT}
                  </span>
                </TD>
                <TD>
                  <Badge>{authModeLabel(r.mcp_target)}</Badge>
                </TD>
                <TD className="text-right pr-4">
                  <Button
                    variant="ghost"
                    size="icon"
                    onClick={() => setToDelete(r)}
                    aria-label="Delete"
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {form.open && <AddMcpDialog open={form.open} onOpenChange={form.setOpen} />}
      <DeleteMcpDialog registry={toDelete} onClose={() => setToDelete(null)} />
    </div>
  );
}

function DeleteMcpDialog({
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
      toast({ variant: "success", title: "MCP server removed", description: registry.name });
      void invalidate("registries");
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Could not remove", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ConfirmDialog
      open={registry !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Disconnect MCP server"
      description={`"${registry?.name}" will be removed. This fails if a consumer still references it.`}
      onConfirm={confirm}
      loading={loading}
    />
  );
}

function AddMcpDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const { data: catalog, isLoading: catalogLoading } = useMcpCatalog();

  const [selected, setSelected] = useState(CUSTOM);
  const [name, setName] = useState("");
  const [urlValues, setUrlValues] = useState<Record<string, string>>({});
  const [headerValues, setHeaderValues] = useState<Record<string, string>>({});
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");
  const [customUrl, setCustomUrl] = useState("");
  const [customAuthMode, setCustomAuthMode] = useState<MCPAuthMode>("none");
  const [customHeader, setCustomHeader] = useState("Authorization");
  const [customValue, setCustomValue] = useState("");
  const [expectedAudience, setExpectedAudience] = useState("");
  const [exchangePattern, setExchangePattern] = useState<ExchangePattern>("impersonation");
  const [exchangeAudience, setExchangeAudience] = useState("");
  const [exchangeActor, setExchangeActor] = useState("");
  const [exchangeScope, setExchangeScope] = useState("");
  const [fwdProvider, setFwdProvider] = useState("");
  const [fwdRegistration, setFwdRegistration] = useState<"auto" | "manual">("auto");
  const [fwdClientId, setFwdClientId] = useState("");
  const [fwdClientSecret, setFwdClientSecret] = useState("");
  const [fwdAuthorizeUrl, setFwdAuthorizeUrl] = useState("");
  const [fwdTokenUrl, setFwdTokenUrl] = useState("");
  const [fwdScopes, setFwdScopes] = useState("");
  const [fwdResource, setFwdResource] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const server = useMemo(
    () => (catalog ?? []).find((s) => s.code === selected) ?? null,
    [catalog, selected],
  );

  function selectServer(code: string) {
    setSelected(code);
    setUrlValues({});
    setHeaderValues({});
    setClientId("");
    setClientSecret("");
    const entry = (catalog ?? []).find((s) => s.code === code);
    setName(entry ? entry.display_name : "");
  }

  function buildCustomAuth(): { auth: MCPAuth } | { error: string } {
    switch (customAuthMode) {
      case "none":
        return { auth: { mode: "none" } };
      case "static":
        if (!customHeader.trim() || !customValue.trim()) {
          return { error: "Static auth needs a header and value" };
        }
        return {
          auth: { mode: "static", header: customHeader.trim(), value: customValue.trim() },
        };
      case "passthrough":
        if (!expectedAudience.trim()) {
          return { error: "Passthrough needs an expected audience" };
        }
        return { auth: { mode: "passthrough", expected_audience: expectedAudience.trim() } };
      case "exchange": {
        const auth: MCPAuth = { mode: "exchange", pattern: exchangePattern };
        if (exchangePattern === "obo") {
          if (!exchangeScope.trim()) return { error: "Scope is required for OBO" };
          auth.scope = exchangeScope.trim();
          return { auth };
        }
        if (!exchangeAudience.trim()) return { error: "Audience is required" };
        auth.audience = exchangeAudience.trim();
        if (exchangePattern === "delegation") {
          if (!exchangeActor.trim()) return { error: "Actor is required for delegation" };
          auth.actor = exchangeActor.trim();
        }
        return { auth };
      }
      case "forwarded": {
        if (!fwdProvider.trim()) return { error: "Provider is required" };
        if (fwdRegistration === "auto") {
          return {
            auth: { mode: "forwarded", provider: fwdProvider.trim(), registration: "auto" },
          };
        }
        if (!fwdClientId.trim()) {
          return { error: "Client ID is required for manual registration" };
        }
        const scopes = fwdScopes
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
        return {
          auth: {
            mode: "forwarded",
            provider: fwdProvider.trim(),
            registration: "manual",
            client_id: fwdClientId.trim(),
            ...(fwdClientSecret.trim() ? { client_secret: fwdClientSecret.trim() } : {}),
            ...(fwdAuthorizeUrl.trim() ? { authorize_url: fwdAuthorizeUrl.trim() } : {}),
            ...(fwdTokenUrl.trim() ? { token_url: fwdTokenUrl.trim() } : {}),
            ...(scopes.length > 0 ? { scopes } : {}),
            ...(fwdResource.trim() ? { resource: fwdResource.trim() } : {}),
          },
        };
      }
      default: {
        const _exhaustive: never = customAuthMode;
        return _exhaustive;
      }
    }
  }

  function buildBody(): Record<string, unknown> | null {
    const trimmedName = name.trim();
    if (!trimmedName) {
      toast({ variant: "error", title: "Name is required" });
      return null;
    }

    if (selected === CUSTOM) {
      const url = customUrl.trim();
      if (!/^https?:\/\//i.test(url)) {
        toast({ variant: "error", title: "A valid http(s) URL is required" });
        return null;
      }
      const result = buildCustomAuth();
      if ("error" in result) {
        toast({ variant: "error", title: result.error });
        return null;
      }
      const target: MCPTarget = { url, transport: DEFAULT_TRANSPORT, auth: result.auth };
      return { name: trimmedName, type: "MCP", mcp_target: target };
    }

    if (!server) {
      toast({ variant: "error", title: "Select an MCP server" });
      return null;
    }

    for (const variable of server.url_variables ?? []) {
      if (variable.required && !(urlValues[variable.name] ?? "").trim()) {
        toast({ variant: "error", title: `Missing ${variable.name}` });
        return null;
      }
    }
    if (server.auth_hint === "static") {
      for (const header of server.auth_headers ?? []) {
        if (header.required && !(headerValues[header.name] ?? "").trim()) {
          toast({ variant: "error", title: `Missing ${header.name}` });
          return null;
        }
      }
    }
    if (server.auth_hint === "oauth" && server.oauth?.registration === "manual" && !clientId.trim()) {
      toast({ variant: "error", title: "Client ID is required" });
      return null;
    }

    const target = buildCatalogTarget(server, urlValues, headerValues, clientId.trim(), clientSecret.trim());
    return {
      name: trimmedName,
      type: "MCP",
      ...(server.description ? { description: server.description } : {}),
      mcp_target: target,
    };
  }

  async function submit() {
    const body = buildBody();
    if (!body) return;
    setSubmitting(true);
    try {
      await api.post(`${gatewayScope(gatewayId)}/registries`, body);
      toast({ variant: "success", title: "MCP server connected", description: name.trim() });
      void invalidate("registries");
      onOpenChange(false);
    } catch (err) {
      toast({ variant: "error", title: "Save failed", description: errorMessage(err) });
    } finally {
      setSubmitting(false);
    }
  }

  const isOAuthAuto =
    server?.auth_hint === "oauth" && server.oauth?.registration !== "manual";
  const isOAuthManual =
    server?.auth_hint === "oauth" && server.oauth?.registration === "manual";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="lg">
        <DialogHeader
          title="Add MCP server"
          description="Connect an MCP backend from the catalog or add one manually."
        />
        <DialogBody className="flex flex-col gap-5">
          <Field label="Server">
            <Select
              value={selected}
              onChange={(e) => selectServer(e.target.value)}
              disabled={catalogLoading}
            >
              <option value={CUSTOM}>Custom server (manual URL)</option>
              {(catalog ?? []).map((s) => (
                <option key={s.code} value={s.code}>
                  {s.display_name}
                  {s.vendor ? ` — ${s.vendor}` : ""}
                </option>
              ))}
            </Select>
          </Field>

          <Field label="Name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="github-mcp" />
          </Field>

          {selected === CUSTOM ? (
            <>
              <Field label="URL" hint="required">
                <Input
                  value={customUrl}
                  onChange={(e) => setCustomUrl(e.target.value)}
                  placeholder="https://mcp.example.com/mcp"
                />
              </Field>
              <Field label="Authentication">
                <Select
                  value={customAuthMode}
                  onChange={(e) => setCustomAuthMode(e.target.value as MCPAuthMode)}
                >
                  {CUSTOM_AUTH_MODES.map((m) => (
                    <option key={m.value} value={m.value}>
                      {m.label}
                    </option>
                  ))}
                </Select>
              </Field>

              {customAuthMode === "static" && (
                <div className="flex items-center gap-2">
                  <Field label="Header" className="flex-1">
                    <Input
                      value={customHeader}
                      onChange={(e) => setCustomHeader(e.target.value)}
                      placeholder="Authorization"
                    />
                  </Field>
                  <Field label="Value" className="flex-1">
                    <Input
                      type="password"
                      value={customValue}
                      onChange={(e) => setCustomValue(e.target.value)}
                      placeholder="Bearer sk-..."
                    />
                  </Field>
                </div>
              )}

              {customAuthMode === "passthrough" && (
                <Field label="Expected audience" hint="required">
                  <Input
                    value={expectedAudience}
                    onChange={(e) => setExpectedAudience(e.target.value)}
                    placeholder="api://upstream"
                  />
                </Field>
              )}

              {customAuthMode === "exchange" && (
                <>
                  <Field label="Pattern">
                    <Select
                      value={exchangePattern}
                      onChange={(e) => setExchangePattern(e.target.value as ExchangePattern)}
                    >
                      {EXCHANGE_PATTERNS.map((p) => (
                        <option key={p.value} value={p.value}>
                          {p.label}
                        </option>
                      ))}
                    </Select>
                  </Field>
                  {exchangePattern === "obo" ? (
                    <Field label="Scope" hint="required">
                      <Input
                        value={exchangeScope}
                        onChange={(e) => setExchangeScope(e.target.value)}
                        placeholder="resource/.default"
                      />
                    </Field>
                  ) : (
                    <Field label="Audience" hint="required">
                      <Input
                        value={exchangeAudience}
                        onChange={(e) => setExchangeAudience(e.target.value)}
                        placeholder="https://upstream.example.com"
                      />
                    </Field>
                  )}
                  {exchangePattern === "delegation" && (
                    <Field label="Actor" hint="required">
                      <Input
                        value={exchangeActor}
                        onChange={(e) => setExchangeActor(e.target.value)}
                        placeholder="agent-1"
                      />
                    </Field>
                  )}
                </>
              )}

              {customAuthMode === "forwarded" && (
                <>
                  <Field label="Provider" hint="required">
                    <Input
                      value={fwdProvider}
                      onChange={(e) => setFwdProvider(e.target.value)}
                      placeholder="linear"
                    />
                  </Field>
                  <Field label="Registration">
                    <Select
                      value={fwdRegistration}
                      onChange={(e) => setFwdRegistration(e.target.value as "auto" | "manual")}
                    >
                      <option value="auto">Auto (dynamic client registration)</option>
                      <option value="manual">Manual (pre-registered app)</option>
                    </Select>
                  </Field>
                  {fwdRegistration === "auto" ? (
                    <p className="text-[13px] text-muted">
                      No credentials stored — each user authenticates in the browser at runtime.
                    </p>
                  ) : (
                    <>
                      <Field label="Client ID" hint="required">
                        <Input value={fwdClientId} onChange={(e) => setFwdClientId(e.target.value)} />
                      </Field>
                      <Field label="Client secret" hint="optional">
                        <Input
                          type="password"
                          value={fwdClientSecret}
                          onChange={(e) => setFwdClientSecret(e.target.value)}
                        />
                      </Field>
                      <Field label="Authorize URL" hint="optional">
                        <Input
                          value={fwdAuthorizeUrl}
                          onChange={(e) => setFwdAuthorizeUrl(e.target.value)}
                          placeholder="https://provider.com/oauth/authorize"
                        />
                      </Field>
                      <Field label="Token URL" hint="optional">
                        <Input
                          value={fwdTokenUrl}
                          onChange={(e) => setFwdTokenUrl(e.target.value)}
                          placeholder="https://provider.com/oauth/token"
                        />
                      </Field>
                      <Field label="Scopes" hint="optional, comma-separated">
                        <Input
                          value={fwdScopes}
                          onChange={(e) => setFwdScopes(e.target.value)}
                          placeholder="repo, read:user"
                        />
                      </Field>
                      <Field label="Resource" hint="optional">
                        <Input
                          value={fwdResource}
                          onChange={(e) => setFwdResource(e.target.value)}
                        />
                      </Field>
                    </>
                  )}
                </>
              )}
            </>
          ) : (
            server && (
              <>
                {server.description && (
                  <p className="text-[13px] text-muted">{server.description}</p>
                )}

                {(server.url_variables ?? []).map((variable) => (
                  <Field
                    key={variable.name}
                    label={variable.name}
                    hint={variable.required ? "required" : "optional"}
                  >
                    <Input
                      type={variable.secret ? "password" : "text"}
                      value={urlValues[variable.name] ?? ""}
                      onChange={(e) =>
                        setUrlValues((prev) => ({ ...prev, [variable.name]: e.target.value }))
                      }
                      placeholder={variable.description}
                    />
                  </Field>
                ))}

                {server.auth_hint === "static" &&
                  (server.auth_headers ?? []).map((header) => (
                    <Field
                      key={header.name}
                      label={header.name}
                      hint={header.required ? "required" : "optional"}
                    >
                      <Input
                        type={header.secret ? "password" : "text"}
                        value={headerValues[header.name] ?? ""}
                        onChange={(e) =>
                          setHeaderValues((prev) => ({ ...prev, [header.name]: e.target.value }))
                        }
                        placeholder={header.description}
                      />
                    </Field>
                  ))}

                {isOAuthAuto && (
                  <p className="text-[13px] text-muted">
                    This server uses OAuth. No credentials are stored here — each user
                    authenticates in the browser at runtime.
                  </p>
                )}

                {isOAuthManual && (
                  <>
                    <p className="text-[13px] text-muted">
                      This provider requires a pre-registered OAuth app. Users still log in at
                      runtime.
                    </p>
                    <Field label="Client ID" hint="required">
                      <Input value={clientId} onChange={(e) => setClientId(e.target.value)} />
                    </Field>
                    <Field label="Client secret" hint="optional">
                      <Input
                        type="password"
                        value={clientSecret}
                        onChange={(e) => setClientSecret(e.target.value)}
                      />
                    </Field>
                  </>
                )}
              </>
            )
          )}
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="primary" onClick={submit} loading={submitting}>
            Connect
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
