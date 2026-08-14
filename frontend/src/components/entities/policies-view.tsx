"use client";

import { useState } from "react";
import { Plus, Pencil, Trash2, ShieldCheck, Globe, Copy } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { usePagedList, useInvalidate, usePolicyCatalog, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader, ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import {
  FilterSelect,
  ListToolbar,
  NoMatches,
  Pagination,
  SortHeader,
  useListControls,
} from "@/components/ui/list-controls";
import { Badge, EmptyState, PageLoader, Dot } from "@/components/ui/misc";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { Section, SwitchRow, Grid2, Divider } from "@/components/ui/form-bits";
import {
  PolicySettingsForm,
  buildSettingsDefaults,
  coerceSettings,
} from "@/components/entities/policy-settings-form";
import { cn } from "@/lib/cn";
import type { Policy, PolicyStage, PolicyCatalogEntry } from "@/lib/types";

const FALLBACK_SLUGS = [
  "rate_limiter",
  "token_rate_limiter",
  "request_size_limiter",
  "semantic_cache",
];

export function PoliciesView() {
  const controls = useListControls();
  const { data, isLoading } = usePagedList<Policy>("policies", controls.query);
  const policies = data?.items ?? [];
  const total = data?.total ?? 0;
  // `category` filters by catalog group, `type` by plugin slug — the API
  // intersects them, so the plugin list narrows to the chosen category.
  const { data: catalog } = usePolicyCatalog();
  const category = controls.filters.category ?? "";
  const plugins = (catalog ?? [])
    .filter((group) => category === "" || group.type === category)
    .flatMap((group) => group.items);
  const form = useDisclosure();
  const [editing, setEditing] = useState<Policy | null>(null);
  const [toDelete, setToDelete] = useState<Policy | null>(null);

  return (
    <div>
      <PageHeader
        description="Policies are plugin instances (rate limiting, budgets, caching…). Attach them to consumers or mark them global to apply gateway-wide."
        action={
          <Button
            variant="primary"
            onClick={() => {
              setEditing(null);
              form.onOpen();
            }}
          >
            <Plus className="h-4 w-4" />
            New policy
          </Button>
        }
      />

      {isLoading ? (
        <PageLoader />
      ) : total === 0 && !controls.isFiltered ? (
        <EmptyState
          icon={<ShieldCheck className="h-5 w-5" />}
          title="No policies yet"
          description="Create a plugin policy to enforce limits or transform traffic."
        />
      ) : (
        <>
          <ListToolbar controls={controls} placeholder="Search policies by name or slug…">
            <FilterSelect
              label="Category"
              value={category}
              onChange={(v) => {
                controls.setFilter("category", v);
                // The selected plugin may not belong to the new category.
                controls.setFilter("type", "");
              }}
            >
              <option value="">Any category</option>
              {(catalog ?? []).map((group) => (
                <option key={group.type} value={group.type}>
                  {group.type}
                </option>
              ))}
            </FilterSelect>
            <FilterSelect
              label="Plugin"
              value={controls.filters.type ?? ""}
              onChange={(v) => controls.setFilter("type", v)}
            >
              <option value="">Any plugin</option>
              {plugins.map((plugin) => (
                <option key={plugin.slug} value={plugin.slug}>
                  {plugin.name}
                </option>
              ))}
            </FilterSelect>
            <FilterSelect
              label="Mode"
              value={controls.filters.mode ?? ""}
              onChange={(v) => controls.setFilter("mode", v)}
            >
              <option value="">Any mode</option>
              <option value="enforce">enforce</option>
              <option value="throttle">throttle</option>
              <option value="observe">observe</option>
            </FilterSelect>
            <FilterSelect
              label="Scope"
              value={controls.filters.global ?? ""}
              onChange={(v) => controls.setFilter("global", v)}
            >
              <option value="">Any scope</option>
              <option value="true">Global</option>
              <option value="false">Scoped</option>
            </FilterSelect>
            <FilterSelect
              label="Status"
              value={controls.filters.enabled ?? ""}
              onChange={(v) => controls.setFilter("enabled", v)}
            >
              <option value="">Any status</option>
              <option value="true">Enabled</option>
              <option value="false">Disabled</option>
            </FilterSelect>
          </ListToolbar>

          {policies.length === 0 ? (
            <NoMatches controls={controls} label="policies" />
          ) : (
            <Table>
              <THead>
                <SortHeader controls={controls} field="name">
                  Name
                </SortHeader>
                <TH>Plugin</TH>
                <TH>Scope</TH>
                <SortHeader controls={controls} field="priority">
                  Priority
                </SortHeader>
                <TH>Stages</TH>
                <TH>Status</TH>
                <TH className="text-right pr-4">Actions</TH>
              </THead>
              <TBody>
                {policies.map((p) => (
                  <TR key={p.id}>
                    <TD>
                      <span className="font-medium text-fg">{p.name}</span>
                    </TD>
                    <TD>
                      <Badge tone="accent">{p.slug}</Badge>
                    </TD>
                    <TD>
                      {p.global ? (
                        <Badge tone="warning">
                          <Globe className="h-3 w-3" />
                          Global
                        </Badge>
                      ) : (
                        <span className="text-faint">scoped</span>
                      )}
                    </TD>
                    <TD>
                      <span className="text-[12px] text-muted tabular-nums">{p.priority}</span>
                    </TD>
                    <TD>
                      <span className="text-[12px] text-muted">
                        {p.stages && p.stages.length > 0 ? p.stages.join(", ") : "—"}
                      </span>
                    </TD>
                    <TD>
                      <span className="inline-flex items-center gap-2 text-muted">
                        <Dot active={p.enabled} />
                        {p.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </TD>
                    <TD className="text-right pr-4">
                      <div className="inline-flex gap-1">
                        <GlobalToggle policy={p} />
                        <DuplicateButton policy={p} />
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => {
                            setEditing(p);
                            form.onOpen();
                          }}
                          aria-label="Edit"
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => setToDelete(p)} aria-label="Delete">
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}

          <Pagination controls={controls} total={total} />
        </>
      )}

      {form.open && <PolicyFormDialog open={form.open} onOpenChange={form.setOpen} policy={editing} />}
      <DeletePolicyDialog policy={toDelete} onClose={() => setToDelete(null)} />
    </div>
  );
}

function GlobalToggle({ policy }: { policy: Policy }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  async function toggle() {
    setLoading(true);
    const url = `${gatewayScope(gatewayId)}/policies/${policy.id}/global`;
    try {
      if (policy.global) {
        await api.del(url);
        toast({ variant: "success", title: "Policy is now scoped" });
      } else {
        await api.post(url);
        toast({ variant: "success", title: "Policy is now global" });
      }
      void invalidate("policies");
    } catch (err) {
      toast({ variant: "error", title: "Could not change scope", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={toggle}
      loading={loading}
      aria-label="Toggle global"
      className={cn(policy.global && "text-warning")}
    >
      <Globe className="h-4 w-4" />
    </Button>
  );
}

/**
 * Copies a policy through the API. The copy is named with a numeric suffix,
 * starts scoped (never global) and carries no consumer associations, so the
 * toast says so instead of implying an identical twin.
 */
function DuplicateButton({ policy }: { policy: Policy }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  async function duplicate() {
    setLoading(true);
    try {
      const copy = await api.post<Policy>(
        `${gatewayScope(gatewayId)}/policies/${policy.id}/duplicate`,
      );
      toast({
        variant: "success",
        title: "Policy duplicated",
        description: `${copy.name} — scoped, with no consumers attached`,
      });
      void invalidate("policies");
    } catch (err) {
      toast({ variant: "error", title: "Could not duplicate", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <Button
      variant="ghost"
      size="icon"
      onClick={duplicate}
      loading={loading}
      aria-label="Duplicate"
    >
      <Copy className="h-4 w-4" />
    </Button>
  );
}

function DeletePolicyDialog({ policy, onClose }: { policy: Policy | null; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  async function confirm() {
    if (!policy) return;
    setLoading(true);
    try {
      await api.del(`${gatewayScope(gatewayId)}/policies/${policy.id}`);
      toast({ variant: "success", title: "Policy deleted", description: policy.name });
      void invalidate("policies");
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Could not delete", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ConfirmDialog
      open={policy !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Delete policy"
      description={`"${policy?.name}" will be permanently removed and detached from all consumers.`}
      onConfirm={confirm}
      loading={loading}
    />
  );
}

function PolicyFormDialog({
  open,
  onOpenChange,
  policy,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  policy: Policy | null;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const { data: catalogGroups } = usePolicyCatalog();
  const isEdit = policy !== null;

  const entries: PolicyCatalogEntry[] = (catalogGroups ?? []).flatMap((g) => g.items);
  const slugOptions = entries.length > 0 ? entries.map((e) => e.slug) : FALLBACK_SLUGS;

  const [name, setName] = useState(policy?.name ?? "");
  const [slug, setSlug] = useState(policy?.slug ?? slugOptions[0]!);
  const [mode, setMode] = useState(policy?.mode ?? "");
  const [enabled, setEnabled] = useState(policy?.enabled ?? true);
  const [stages, setStages] = useState<PolicyStage[]>(policy?.stages ?? ["pre_request"]);
  const [settings, setSettings] = useState<Record<string, unknown>>(policy?.settings ?? {});
  const [submitting, setSubmitting] = useState(false);

  const entry = entries.find((e) => e.slug === slug);
  const supportedModes = entry?.supported_modes ?? [];
  const settingsFields = entry?.settings_schema?.fields ?? [];

  // When creating, derive stages, mode and default settings from the selected
  // plugin's catalog schema. Editing keeps the persisted policy values. Done
  // during render (not in an effect) so the defaults land in the same commit as
  // the slug change; `appliedSlug` also covers the catalog arriving late.
  const [appliedSlug, setAppliedSlug] = useState<string | null>(null);
  if (!isEdit && entry && appliedSlug !== slug) {
    setAppliedSlug(slug);
    setStages(
      entry.mandatory_stages.length > 0
        ? entry.mandatory_stages
        : entry.supported_stages.slice(0, 1),
    );
    setMode(entry.default_mode || "");
    setSettings(buildSettingsDefaults(entry.settings_schema?.fields ?? []));
  }

  async function submit() {
    if (!name.trim() || !slug.trim()) {
      toast({ variant: "error", title: "Name and plugin are required" });
      return;
    }

    let parsedSettings: Record<string, unknown>;
    if (settingsFields.length > 0) {
      try {
        parsedSettings = coerceSettings(settingsFields, settings);
      } catch {
        toast({
          variant: "error",
          title: "Invalid settings",
          description: "Check the free-form JSON fields.",
        });
        return;
      }
    } else {
      // Schema not loaded (or plugin has none): preserve settings as-is.
      parsedSettings = settings;
    }

    const finalStages = entry
      ? Array.from(new Set([...entry.mandatory_stages, ...stages]))
      : stages;

    const body: Record<string, unknown> = {
      name: name.trim(),
      slug: slug.trim(),
      enabled,
      parallel: policy?.parallel ?? false,
      priority: policy?.priority ?? 0,
      stages: finalStages,
    };
    if (mode.trim()) body.mode = mode.trim();
    if (Object.keys(parsedSettings).length > 0) body.settings = parsedSettings;

    setSubmitting(true);
    try {
      const base = `${gatewayScope(gatewayId)}/policies`;
      if (isEdit) {
        await api.put(`${base}/${policy.id}`, body);
      } else {
        await api.post(base, body);
      }
      toast({
        variant: "success",
        title: isEdit ? "Policy updated" : "Policy created",
        description: name,
      });
      void invalidate("policies");
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
        <DialogHeader title={isEdit ? "Edit policy" : "New policy"} />
        <DialogBody className="flex flex-col gap-5">
          <Grid2>
            <Field label="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="global-rate-limit" />
            </Field>
            <Field label="Plugin">
              {catalogGroups && catalogGroups.length > 0 ? (
                <Select value={slug} onChange={(e) => setSlug(e.target.value)} disabled={isEdit}>
                  {catalogGroups.map((group) => (
                    <optgroup key={group.type} label={group.type}>
                      {group.items.map((it) => (
                        <option key={it.slug} value={it.slug}>
                          {it.name}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </Select>
              ) : (
                <Select value={slug} onChange={(e) => setSlug(e.target.value)} disabled={isEdit}>
                  {slugOptions.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
          </Grid2>

          {entry?.description && <p className="text-[12px] text-muted -mt-2">{entry.description}</p>}

          <Grid2>
            {supportedModes.length > 0 && (
              <Field label="Mode">
                <Select value={mode} onChange={(e) => setMode(e.target.value)}>
                  {supportedModes.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </Select>
              </Field>
            )}
            <div className="flex flex-col gap-2 justify-end">
              <SwitchRow label="Enabled" checked={enabled} onCheckedChange={setEnabled} />
            </div>
          </Grid2>

          <Divider />

          <Section title="Settings" description="Plugin-specific configuration.">
            <PolicySettingsForm fields={settingsFields} value={settings} onChange={setSettings} />
          </Section>
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="primary" onClick={submit} loading={submitting}>
            {isEdit ? "Save changes" : "Create policy"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
