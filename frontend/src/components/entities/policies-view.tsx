"use client";

import { useState } from "react";
import { Plus, Pencil, Trash2, ShieldCheck, Globe } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useList, useInvalidate, usePolicyCatalog, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader, ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Badge, EmptyState, PageLoader, Dot } from "@/components/ui/misc";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Field, Input, Select, Label } from "@/components/ui/field";
import { Section, SwitchRow, Grid2, Divider } from "@/components/ui/form-bits";
import { JsonEditor } from "@/components/ui/json-editor";
import { cn } from "@/lib/cn";
import type { Policy, PolicyStage, PolicyCatalogEntry } from "@/lib/types";

const FALLBACK_SLUGS = [
  "rate_limiter",
  "token_rate_limiter",
  "request_size_limiter",
  "semantic_cache",
];

const STAGES: PolicyStage[] = ["pre_request", "post_request", "pre_response", "post_response"];

export function PoliciesView() {
  const { data: policies, isLoading } = useList<Policy>("policies");
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
      ) : !policies || policies.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck className="h-5 w-5" />}
          title="No policies yet"
          description="Create a plugin policy to enforce limits or transform traffic."
        />
      ) : (
        <Table>
          <THead>
            <TH>Name</TH>
            <TH>Plugin</TH>
            <TH>Scope</TH>
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
  const [parallel, setParallel] = useState(policy?.parallel ?? false);
  const [priority, setPriority] = useState(String(policy?.priority ?? 0));
  const [stages, setStages] = useState<PolicyStage[]>(policy?.stages ?? ["pre_request"]);
  const [settings, setSettings] = useState(
    policy?.settings ? JSON.stringify(policy.settings, null, 2) : "{\n  \n}",
  );
  const [settingsValid, setSettingsValid] = useState(true);
  const [submitting, setSubmitting] = useState(false);

  const entry = entries.find((e) => e.slug === slug);
  const supportedModes = entry?.supported_modes ?? [];
  const settingsFields = entry?.settings_schema?.fields ?? [];

  function selectSlug(next: string) {
    setSlug(next);
    const catalogEntry = entries.find((e) => e.slug === next);
    if (!catalogEntry) return;
    if (catalogEntry.mandatory_stages.length > 0) {
      setStages(catalogEntry.mandatory_stages);
    } else if (catalogEntry.supported_stages.length > 0) {
      setStages([catalogEntry.supported_stages[0]!]);
    }
    setMode(catalogEntry.default_mode || "");
  }

  function toggleStage(stage: PolicyStage) {
    setStages((prev) =>
      prev.includes(stage) ? prev.filter((s) => s !== stage) : [...prev, stage],
    );
  }

  async function submit() {
    if (!name.trim() || !slug.trim()) {
      toast({ variant: "error", title: "Name and plugin are required" });
      return;
    }
    if (!settingsValid) {
      toast({ variant: "error", title: "Settings JSON is invalid" });
      return;
    }

    let parsedSettings: Record<string, unknown> | undefined;
    try {
      parsedSettings = settings.trim() ? JSON.parse(settings) : undefined;
    } catch {
      toast({ variant: "error", title: "Settings JSON is invalid" });
      return;
    }

    // Mandatory stages must always be present regardless of the toggles.
    const finalStages = entry
      ? Array.from(new Set([...entry.mandatory_stages, ...stages]))
      : stages;

    const body: Record<string, unknown> = {
      name: name.trim(),
      slug: slug.trim(),
      enabled,
      parallel,
      priority: Number(priority) || 0,
      stages: finalStages,
    };
    if (mode.trim()) body.mode = mode.trim();
    if (parsedSettings) body.settings = parsedSettings;

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
                <Select value={slug} onChange={(e) => selectSlug(e.target.value)} disabled={isEdit}>
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
                <Select value={slug} onChange={(e) => selectSlug(e.target.value)} disabled={isEdit}>
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
            <Field label="Priority" hint="lower runs first">
              <Input type="number" value={priority} onChange={(e) => setPriority(e.target.value)} />
            </Field>
            {supportedModes.length > 0 ? (
              <Field label="Mode">
                <Select value={mode} onChange={(e) => setMode(e.target.value)}>
                  {supportedModes.map((m) => (
                    <option key={m} value={m}>
                      {m}
                    </option>
                  ))}
                </Select>
              </Field>
            ) : (
              <div className="flex flex-col gap-2 justify-end">
                <SwitchRow label="Enabled" checked={enabled} onCheckedChange={setEnabled} />
              </div>
            )}
          </Grid2>

          {supportedModes.length > 0 && (
            <SwitchRow label="Enabled" checked={enabled} onCheckedChange={setEnabled} />
          )}

          <SwitchRow
            label="Parallel"
            description="Run this policy concurrently with others in the same stage."
            checked={parallel}
            onCheckedChange={setParallel}
          />

          <div className="flex flex-col gap-2">
            <Label>Stages</Label>
            <div className="grid grid-cols-2 gap-2">
              {STAGES.map((stage) => {
                const active = stages.includes(stage);
                return (
                  <button
                    key={stage}
                    type="button"
                    onClick={() => toggleStage(stage)}
                    className={cn(
                      "rounded-(--radius) border px-3 h-9 text-[13px] text-left transition-colors",
                      active
                        ? "border-accent/50 bg-accent/10 text-fg"
                        : "border-border bg-surface-2/40 text-muted hover:text-fg",
                    )}
                  >
                    {stage}
                  </button>
                );
              })}
            </div>
          </div>

          <Divider />

          <Section title="Settings" description="Plugin-specific configuration as JSON.">
            {settingsFields.length > 0 && (
              <div className="rounded-(--radius) border border-border bg-surface-2/30 px-3 py-2.5 flex flex-col gap-1">
                <p className="text-[11px] font-medium uppercase tracking-wider text-faint">Available fields</p>
                <ul className="flex flex-col gap-0.5">
                  {settingsFields.map((f) => (
                    <li key={f.key} className="text-[12px] text-muted">
                      <code className="text-accent">{f.key}</code>
                      <span className="text-faint"> · {f.type}{f.required ? " · required" : ""}</span>
                      {f.description ? <span className="text-faint"> — {f.description}</span> : null}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <JsonEditor value={settings} onChange={setSettings} onValidityChange={setSettingsValid} rows={9} />
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
