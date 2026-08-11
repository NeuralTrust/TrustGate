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
import { McpRegistriesView } from "./mcp-registries-view";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Field, Input, Label, Select } from "@/components/ui/field";
import { SwitchRow } from "@/components/ui/form-bits";
import {
  authOptionKey,
  buildTargetAuth,
  emptyFieldValues,
  fieldValuesFromAuth,
  findAuthOption,
  inferAuthOption,
  missingRequiredFields,
  providerAuthOptions,
  type AuthFieldValues,
} from "@/lib/auth-catalog";
import type { CatalogAuthField, Registry, Provider } from "@/lib/types";

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
            <McpRegistriesView registries={registries ?? []} />
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
          providerEntry={
            connect ??
            providers?.find((provider) => provider.code === editing?.provider) ??
            null
          }
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
      toast({ variant: "success", title: "Connection removed", description: registry.name });
      void invalidate("registries");
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Could not remove connection", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ConfirmDialog
      open={registry !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Disconnect provider"
      description={`"${registry?.name}" will be removed. This fails if a consumer still references it.`}
      onConfirm={confirm}
      loading={loading}
    />
  );
}

function CatalogAuthFieldInput({
  field,
  value,
  onChange,
}: {
  field: CatalogAuthField;
  value: string | boolean | undefined;
  onChange: (value: string | boolean) => void;
}) {
  if (field.type === "boolean") {
    return (
      <SwitchRow
        label={field.label}
        checked={Boolean(value)}
        onCheckedChange={onChange}
      />
    );
  }

  const inputType = field.secret ? "password" : "text";
  const isMultiline = field.key === "gcp_service_account";

  return (
    <Field label={field.label} hint={field.required ? "required" : undefined}>
      <Input
        type={inputType}
        value={typeof value === "string" ? value : ""}
        onChange={(event) => onChange(event.target.value)}
        placeholder={field.description ?? (isMultiline ? '{"type":"service_account",...}' : undefined)}
      />
    </Field>
  );
}

interface HeaderRow {
  key: string;
  value: string;
}

const PROVIDER_OPTIONS_PROVIDER = "openai_compatible";

function readBaseUrl(options: Record<string, unknown> | undefined): string {
  return typeof options?.base_url === "string" ? options.base_url : "";
}

function readHeaderRows(options: Record<string, unknown> | undefined): HeaderRow[] {
  const headers = options?.headers;
  if (headers && typeof headers === "object" && !Array.isArray(headers)) {
    return Object.entries(headers as Record<string, unknown>).map(([key, value]) => ({
      key,
      value: String(value),
    }));
  }
  return [];
}

function RegistryFormDialog({
  open,
  onOpenChange,
  registry,
  providerEntry,
  initialName,
  onDelete,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  registry: Registry | null;
  providerEntry: Provider | null;
  initialName?: string;
  onDelete?: () => void;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const isEdit = registry !== null;

  const provider = registry?.provider ?? providerEntry?.code ?? "openai";
  const name = registry?.name ?? initialName ?? provider;
  const authOptions = providerAuthOptions(provider, providerEntry?.auth_types);
  const defaultOption = authOptions[0]!;
  const initialOption = registry?.auth
    ? inferAuthOption(registry.auth, authOptions)
    : defaultOption;

  const [selectedAuthKey, setSelectedAuthKey] = useState(() => authOptionKey(initialOption));
  const [fieldValues, setFieldValues] = useState<AuthFieldValues>(() =>
    registry?.auth
      ? fieldValuesFromAuth(registry.auth, initialOption)
      : emptyFieldValues(initialOption),
  );
  const [baseUrl, setBaseUrl] = useState(() => readBaseUrl(registry?.provider_options));
  const [headerRows, setHeaderRows] = useState<HeaderRow[]>(() => readHeaderRows(registry?.provider_options));
  const [submitting, setSubmitting] = useState(false);

  const selectedOption = findAuthOption(authOptions, selectedAuthKey) ?? defaultOption;

  function setFieldValue(key: string, value: string | boolean) {
    setFieldValues((prev) => ({ ...prev, [key]: value }));
  }

  function selectAuthOption(key: string) {
    const option = findAuthOption(authOptions, key);
    if (!option) {
      return;
    }
    setSelectedAuthKey(key);
    setFieldValues(emptyFieldValues(option));
  }

  function updateHeaderRow(index: number, field: keyof HeaderRow, value: string) {
    setHeaderRows((prev) => prev.map((row, i) => (i === index ? { ...row, [field]: value } : row)));
  }

  function addHeaderRow() {
    setHeaderRows((prev) => [...prev, { key: "", value: "" }]);
  }

  function removeHeaderRow(index: number) {
    setHeaderRows((prev) => prev.filter((_, i) => i !== index));
  }

  async function submit() {
    const missing = missingRequiredFields(selectedOption, fieldValues, isEdit);
    if (missing.length > 0) {
      toast({
        variant: "error",
        title: "Missing required fields",
        description: missing.map((field) => field.label).join(", "),
      });
      return;
    }

    const body: Record<string, unknown> = {
      name,
      provider,
      auth: buildTargetAuth(selectedOption, fieldValues),
    };
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
        title: isEdit ? "Connection updated" : "Connection created",
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
              ? "Update the credentials for this connection."
              : "Set credentials to activate this provider."
          }
        />
        <DialogBody className="flex flex-col gap-5">
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

          {authOptions.length > 1 && (
            <Field label="Credential mode">
              <Select value={selectedAuthKey} onChange={(event) => selectAuthOption(event.target.value)}>
                {authOptions.map((option) => (
                  <option key={authOptionKey(option)} value={authOptionKey(option)}>
                    {option.label}
                  </option>
                ))}
              </Select>
            </Field>
          )}

          {selectedOption.description && (
            <p className="text-[13px] text-muted">{selectedOption.description}</p>
          )}

          {selectedOption.fields.map((field) => (
            <CatalogAuthFieldInput
              key={field.key}
              field={field}
              value={fieldValues[field.key]}
              onChange={(value) => setFieldValue(field.key, value)}
            />
          ))}
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
