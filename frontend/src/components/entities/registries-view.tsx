"use client";

import { useState } from "react";
import { Plus, Trash2, Server, PlugZap, Check, X } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useAllList, useCatalogQuery, errorMessage } from "@/lib/hooks";
import { useInvalidate } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader, ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Tabs, TabsList, TabTrigger, TabContent } from "@/components/ui/tabs";
import { Badge, EmptyState, PageLoader } from "@/components/ui/misc";
import { cn } from "@/lib/cn";
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
import type {
  CatalogAuthField,
  Registry,
  RegistryPricing,
  Provider,
  ProviderOptionField,
  ProbeStage,
  TestConnectionResult,
} from "@/lib/types";

export function RegistriesView() {
  const { data: registries, isLoading } = useAllList<Registry>("registries");
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
        <TH>Capabilities</TH>
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
                <div className="flex flex-wrap gap-1">
                  {p.capabilities?.chat ? <Badge>Chat</Badge> : null}
                  {p.capabilities?.embeddings ? <Badge>Embeddings</Badge> : null}
                  {p.capabilities?.rerank ? <Badge>Rerank</Badge> : null}
                </div>
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

type OptionTextValues = Record<string, string>;
type OptionMapValues = Record<string, HeaderRow[]>;

function readMapRows(value: unknown): HeaderRow[] {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return Object.entries(value as Record<string, unknown>).map(([key, entry]) => ({
      key,
      value: String(entry),
    }));
  }
  return [];
}

function initialOptionText(
  fields: ProviderOptionField[],
  options: Record<string, unknown> | undefined,
  isEdit: boolean,
): OptionTextValues {
  const values: OptionTextValues = {};
  for (const field of fields) {
    if (field.type === "map") continue;
    const current = options?.[field.key];
    if (typeof current === "string") {
      values[field.key] = current;
    } else if (!isEdit && typeof field.default === "string") {
      values[field.key] = field.default;
    } else {
      values[field.key] = "";
    }
  }
  return values;
}

function initialOptionMaps(
  fields: ProviderOptionField[],
  options: Record<string, unknown> | undefined,
): OptionMapValues {
  const values: OptionMapValues = {};
  for (const field of fields) {
    if (field.type === "map") values[field.key] = readMapRows(options?.[field.key]);
  }
  return values;
}

function missingRequiredOptions(
  fields: ProviderOptionField[],
  text: OptionTextValues,
  maps: OptionMapValues,
): ProviderOptionField[] {
  return fields.filter((field) => {
    if (!field.required) return false;
    if (field.type === "map") return (maps[field.key] ?? []).every((row) => !row.key.trim());
    return !(text[field.key] ?? "").trim();
  });
}

// Schema-managed keys are rebuilt from the form, so clearing a field removes it.
// Keys the catalog schema does not describe (e.g. options a newer backend added)
// are carried over so the write does not drop them.
function buildProviderOptions(
  fields: ProviderOptionField[],
  text: OptionTextValues,
  maps: OptionMapValues,
  existing: Record<string, unknown> | undefined,
): Record<string, unknown> {
  const managed = new Set(fields.map((field) => field.key));
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(existing ?? {})) {
    if (!managed.has(key)) out[key] = value;
  }
  for (const field of fields) {
    if (field.type === "map") {
      const entries: Record<string, string> = {};
      for (const row of maps[field.key] ?? []) {
        const key = row.key.trim();
        if (key) entries[key] = row.value;
      }
      if (Object.keys(entries).length > 0) out[field.key] = entries;
      continue;
    }
    const value = (text[field.key] ?? "").trim();
    if (value) out[field.key] = value;
  }
  return out;
}

type PricingOverrideRow = {
  model: string;
  input: string;
  output: string;
};

function initialOverrideRows(pricing: RegistryPricing | null | undefined): PricingOverrideRow[] {
  const overrides = pricing?.overrides ?? {};
  const rows = Object.entries(overrides).map(([model, rate]) => ({
    model,
    input: rate.input != null ? String(rate.input) : "",
    output: rate.output != null ? String(rate.output) : "",
  }));
  return rows.length > 0 ? rows : [{ model: "", input: "", output: "" }];
}

function buildPricingPayload(
  discountPct: string,
  rows: PricingOverrideRow[],
): RegistryPricing | undefined | "invalid" {
  const trimmedDiscount = discountPct.trim();
  let discount: number | undefined;
  if (trimmedDiscount !== "") {
    const pct = Number(trimmedDiscount);
    if (!Number.isFinite(pct) || pct < 0 || pct > 100) {
      return "invalid";
    }
    discount = pct / 100;
  }

  const overrides: Record<string, { input: number; output: number }> = {};
  for (const row of rows) {
    const model = row.model.trim();
    const inputRaw = row.input.trim();
    const outputRaw = row.output.trim();
    if (!model && !inputRaw && !outputRaw) {
      continue;
    }
    if (!model) {
      return "invalid";
    }
    const input = Number(inputRaw);
    const output = Number(outputRaw);
    if (!Number.isFinite(input) || !Number.isFinite(output) || input < 0 || output < 0) {
      return "invalid";
    }
    overrides[model] = { input, output };
  }

  if (discount == null && Object.keys(overrides).length === 0) {
    return undefined;
  }
  const pricing: RegistryPricing = {};
  if (discount != null && discount > 0) {
    pricing.discount = discount;
  }
  if (Object.keys(overrides).length > 0) {
    pricing.overrides = overrides;
  }
  return Object.keys(pricing).length > 0 ? pricing : undefined;
}

const STAGE_LABELS: Record<ProbeStage, string> = {
  connectivity: "Reaching the provider",
  authentication: "Authenticating",
  provider: "Provider response",
  unsupported: "Not supported",
};

function TestConnectionCard({
  result,
  scope,
}: {
  result: TestConnectionResult;
  scope: "form" | "saved";
}) {
  return (
    <div
      className={cn(
        "flex flex-col gap-1 rounded-(--radius) border px-3.5 py-2.5",
        result.ok ? "border-success/30 bg-success/8" : "border-danger/30 bg-danger/8",
      )}
    >
      <div className="flex items-center gap-2 text-[13px] font-medium">
        {result.ok ? (
          <Check className="h-4 w-4 text-success" />
        ) : (
          <X className="h-4 w-4 text-danger" />
        )}
        <span className={result.ok ? "text-success" : "text-danger"}>
          {result.ok ? "Connection ok" : `Failed at: ${STAGE_LABELS[result.stage] ?? result.stage}`}
        </span>
        <span className="ml-auto text-[12px] font-normal text-muted">
          {result.latency_ms} ms
          {result.status_code ? ` · HTTP ${result.status_code}` : ""}
        </span>
      </div>
      {result.message && <p className="text-[12px] text-muted">{result.message}</p>}
      <p className="text-[12px] text-faint">
        {scope === "saved"
          ? "Tested the saved configuration — re-enter the credentials to test unsaved changes."
          : "Tested the values in this form."}
      </p>
    </div>
  );
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
  // The provider catalog declares which provider_options a provider takes, so
  // the form renders them instead of hardcoding one provider's fields.
  const optionFields = providerEntry?.provider_options_schema ?? [];
  const [optionText, setOptionText] = useState<OptionTextValues>(() =>
    initialOptionText(optionFields, registry?.provider_options, isEdit),
  );
  const [optionMaps, setOptionMaps] = useState<OptionMapValues>(() =>
    initialOptionMaps(optionFields, registry?.provider_options),
  );
  const [discountPct, setDiscountPct] = useState(() =>
    registry?.pricing?.discount != null ? String(registry.pricing.discount * 100) : "",
  );
  const [overrideRows, setOverrideRows] = useState<PricingOverrideRow[]>(() =>
    initialOverrideRows(registry?.pricing),
  );
  const [submitting, setSubmitting] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    result: TestConnectionResult;
    scope: "form" | "saved";
  } | null>(null);

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

  function setOptionValue(key: string, value: string) {
    setOptionText((prev) => ({ ...prev, [key]: value }));
  }

  function updateMapRow(fieldKey: string, index: number, part: keyof HeaderRow, value: string) {
    setOptionMaps((prev) => ({
      ...prev,
      [fieldKey]: (prev[fieldKey] ?? []).map((row, i) =>
        i === index ? { ...row, [part]: value } : row,
      ),
    }));
  }

  function addMapRow(fieldKey: string) {
    setOptionMaps((prev) => ({ ...prev, [fieldKey]: [...(prev[fieldKey] ?? []), { key: "", value: "" }] }));
  }

  function removeMapRow(fieldKey: string, index: number) {
    setOptionMaps((prev) => ({
      ...prev,
      [fieldKey]: (prev[fieldKey] ?? []).filter((_, i) => i !== index),
    }));
  }

  // Tests the values currently in the form when they are complete; when editing
  // an existing connection whose secrets were not re-entered, tests the stored
  // configuration by id instead (the API accepts either shape, not both).
  async function testConnection() {
    const missingOptions = missingRequiredOptions(optionFields, optionText, optionMaps);
    const missingCredentials = missingRequiredFields(selectedOption, fieldValues, false);
    const canTestForm = missingOptions.length === 0 && missingCredentials.length === 0;

    let body: Record<string, unknown>;
    let scope: "form" | "saved";
    if (canTestForm) {
      scope = "form";
      body = { provider, auth: buildTargetAuth(selectedOption, fieldValues) };
      if (optionFields.length > 0) {
        body.provider_options = buildProviderOptions(
          optionFields,
          optionText,
          optionMaps,
          registry?.provider_options,
        );
      }
    } else if (isEdit) {
      scope = "saved";
      body = { registry_id: registry.id };
    } else {
      toast({
        variant: "error",
        title: "Fill in the credentials first",
        description: [...missingOptions, ...missingCredentials]
          .map((field) => field.label)
          .join(", "),
      });
      return;
    }

    setTesting(true);
    setTestResult(null);
    try {
      const result = await api.post<TestConnectionResult>(
        `${gatewayScope(gatewayId)}/registries/test-connection`,
        body,
      );
      setTestResult({ result, scope });
    } catch (err) {
      toast({ variant: "error", title: "Could not run the test", description: errorMessage(err) });
    } finally {
      setTesting(false);
    }
  }

  async function submit() {
    const missing = missingRequiredFields(selectedOption, fieldValues, isEdit);
    const missingOptions = missingRequiredOptions(optionFields, optionText, optionMaps);
    if (missing.length > 0 || missingOptions.length > 0) {
      toast({
        variant: "error",
        title: "Missing required fields",
        description: [...missingOptions, ...missing].map((field) => field.label).join(", "),
      });
      return;
    }

    const pricing = buildPricingPayload(discountPct, overrideRows);
    if (pricing === "invalid") {
      toast({
        variant: "error",
        title: "Invalid pricing",
        description: "Discount must be 0–100 and override rates must be non-negative USD per token.",
      });
      return;
    }

    const body: Record<string, unknown> = {
      name,
      provider,
      auth: buildTargetAuth(selectedOption, fieldValues),
    };
    if (optionFields.length > 0) {
      body.provider_options = buildProviderOptions(
        optionFields,
        optionText,
        optionMaps,
        registry?.provider_options,
      );
    }
    if (pricing !== undefined) {
      body.pricing = pricing;
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
          {optionFields.map((field) => {
            const hint = field.required ? "required" : "optional";
            if (field.type === "map") {
              const rows = optionMaps[field.key] ?? [];
              return (
                <div key={field.key} className="flex flex-col gap-2">
                  <Label hint={hint}>{field.label}</Label>
                  {rows.map((row, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <Input
                        value={row.key}
                        onChange={(e) => updateMapRow(field.key, i, "key", e.target.value)}
                        placeholder="X-Custom-Header"
                      />
                      <Input
                        value={row.value}
                        onChange={(e) => updateMapRow(field.key, i, "value", e.target.value)}
                        placeholder="value"
                      />
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => removeMapRow(field.key, i)}
                        aria-label={`Remove ${field.label} entry`}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  ))}
                  <div>
                    <Button variant="ghost" size="sm" onClick={() => addMapRow(field.key)}>
                      <Plus className="h-4 w-4" />
                      Add entry
                    </Button>
                  </div>
                </div>
              );
            }
            if (field.type === "enum") {
              return (
                <Field key={field.key} label={field.label} hint={hint}>
                  <Select
                    value={optionText[field.key] ?? ""}
                    onChange={(e) => setOptionValue(field.key, e.target.value)}
                  >
                    {!field.required && <option value="">Provider default</option>}
                    {(field.enum ?? []).map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </Select>
                </Field>
              );
            }
            return (
              <Field key={field.key} label={field.label} hint={hint}>
                <Input
                  value={optionText[field.key] ?? ""}
                  onChange={(e) => setOptionValue(field.key, e.target.value)}
                  placeholder={field.description}
                />
              </Field>
            );
          })}

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

          <div className="flex flex-col gap-2">
            <Label hint="optional">Contract pricing</Label>
            <p className="text-[13px] text-muted">
              USD per token. Absolute overrides win; otherwise the discount is applied to
              models.dev list prices. Accurate monthly cost estimates depend on matching the
              contract.
            </p>
            <Field label="List discount" hint="percent off list">
              <Input
                value={discountPct}
                onChange={(e) => setDiscountPct(e.target.value)}
                placeholder="20"
                inputMode="decimal"
              />
            </Field>
            {overrideRows.map((row, i) => (
              <div key={i} className="flex items-center gap-2">
                <Input
                  value={row.model}
                  onChange={(e) =>
                    setOverrideRows((prev) =>
                      prev.map((r, idx) => (idx === i ? { ...r, model: e.target.value } : r)),
                    )
                  }
                  placeholder="gpt-4o or gpt-4o-mini*"
                />
                <Input
                  value={row.input}
                  onChange={(e) =>
                    setOverrideRows((prev) =>
                      prev.map((r, idx) => (idx === i ? { ...r, input: e.target.value } : r)),
                    )
                  }
                  placeholder="input $/token"
                  inputMode="decimal"
                />
                <Input
                  value={row.output}
                  onChange={(e) =>
                    setOverrideRows((prev) =>
                      prev.map((r, idx) => (idx === i ? { ...r, output: e.target.value } : r)),
                    )
                  }
                  placeholder="output $/token"
                  inputMode="decimal"
                />
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setOverrideRows((prev) => prev.filter((_, idx) => idx !== i))}
                  aria-label="Remove price override"
                >
                  <Trash2 className="h-4 w-4" />
                </Button>
              </div>
            ))}
            <div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setOverrideRows((prev) => [...prev, { model: "", input: "", output: "" }])}
              >
                <Plus className="h-4 w-4" />
                Add model override
              </Button>
            </div>
          </div>

          {testResult && (
            <TestConnectionCard result={testResult.result} scope={testResult.scope} />
          )}
        </DialogBody>
        <DialogFooter>
          {isEdit && onDelete && (
            <Button variant="danger" onClick={onDelete} className="mr-auto">
              <Trash2 className="h-4 w-4" />
              Disconnect
            </Button>
          )}
          <Button
            variant="outline"
            onClick={testConnection}
            loading={testing}
            className={isEdit && onDelete ? undefined : "mr-auto"}
          >
            <PlugZap className="h-4 w-4" />
            Test connection
          </Button>
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
