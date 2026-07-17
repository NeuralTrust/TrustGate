"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Pencil, Trash2, UsersRound, Settings2, Check, Server, X } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useList, useInvalidate, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader, ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Badge, EmptyState, PageLoader } from "@/components/ui/misc";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Tabs, TabsList, TabTrigger, TabContent } from "@/components/ui/tabs";
import { Field, Input, Select, Label } from "@/components/ui/field";
import { Grid2, SwitchRow, Divider } from "@/components/ui/form-bits";
import { cn } from "@/lib/cn";
import {
  ModelPolicyEditor,
  buildModelPolicies,
  modelPolicyStateFrom,
  type ModelPolicyState,
} from "./model-policy-editor";
import type { Role, Registry, OidcMapping, OidcClaim, OidcClaimOp } from "@/lib/types";

const CLAIM_OPS: { value: OidcClaimOp; label: string }[] = [
  { value: "equals", label: "equals" },
  { value: "contains_any", label: "contains any" },
  { value: "contains_all", label: "contains all" },
];

export function RolesView() {
  const { data: roles, isLoading } = useList<Role>("roles");
  const form = useDisclosure();
  const [editing, setEditing] = useState<Role | null>(null);
  const [detail, setDetail] = useState<Role | null>(null);
  const [toDelete, setToDelete] = useState<Role | null>(null);

  return (
    <div>
      <PageHeader
        description="Roles power role-based routing. A role maps OIDC/OAuth2 identity claims to a set of registries and model policies."
        action={
          <Button
            variant="primary"
            onClick={() => {
              setEditing(null);
              form.onOpen();
            }}
          >
            <Plus className="h-4 w-4" />
            New role
          </Button>
        }
      />

      {isLoading ? (
        <PageLoader />
      ) : !roles || roles.length === 0 ? (
        <EmptyState
          icon={<UsersRound className="h-5 w-5" />}
          title="No roles yet"
          description="Create a role to route identity-authenticated consumers by their claims."
        />
      ) : (
        <Table>
          <THead>
            <TH>Name</TH>
            <TH>OIDC mapping</TH>
            <TH>Registries</TH>
            <TH className="text-right pr-4">Actions</TH>
          </THead>
          <TBody>
            {roles.map((r) => (
              <TR key={r.id}>
                <TD>
                  <span className="font-medium text-fg">{r.name}</span>
                </TD>
                <TD>
                  {r.oidc_mapping ? (
                    <span className="text-[12px] text-muted">
                      match {r.oidc_mapping.match} · {r.oidc_mapping.claims.length} claim
                      {r.oidc_mapping.claims.length === 1 ? "" : "s"}
                    </span>
                  ) : (
                    <span className="text-faint">—</span>
                  )}
                </TD>
                <TD>
                  <span className="text-[12px] text-muted">{r.registry_ids.length}</span>
                </TD>
                <TD className="text-right pr-4">
                  <div className="inline-flex gap-1">
                    <Button variant="ghost" size="icon" onClick={() => setDetail(r)} aria-label="Configure">
                      <Settings2 className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => {
                        setEditing(r);
                        form.onOpen();
                      }}
                      aria-label="Edit"
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => setToDelete(r)} aria-label="Delete">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {form.open && <RoleFormDialog open={form.open} onOpenChange={form.setOpen} role={editing} />}
      {detail && (
        <RoleDetail roleId={detail.id} open={true} onOpenChange={(v) => !v && setDetail(null)} />
      )}
      <DeleteRoleDialog role={toDelete} onClose={() => setToDelete(null)} />
    </div>
  );
}

function DeleteRoleDialog({ role, onClose }: { role: Role | null; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  async function confirm() {
    if (!role) return;
    setLoading(true);
    try {
      await api.del(`${gatewayScope(gatewayId)}/roles/${role.id}`);
      toast({ variant: "success", title: "Role deleted", description: role.name });
      void invalidate("roles");
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Could not delete", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ConfirmDialog
      open={role !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Delete role"
      description={`"${role?.name}" will be permanently removed and detached from all consumers.`}
      onConfirm={confirm}
      loading={loading}
    />
  );
}

function emptyClaim(): OidcClaim {
  return { path: "", op: "equals", values: [] };
}

function RoleFormDialog({
  open,
  onOpenChange,
  role,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  role: Role | null;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const isEdit = role !== null;

  const [name, setName] = useState(role?.name ?? "");
  const [mappingEnabled, setMappingEnabled] = useState(role?.oidc_mapping != null);
  const [match, setMatch] = useState<OidcMapping["match"]>(role?.oidc_mapping?.match ?? "any");
  const [claims, setClaims] = useState<{ path: string; op: OidcClaimOp; values: string }[]>(
    (role?.oidc_mapping?.claims ?? [emptyClaim()]).map((c) => ({
      path: c.path,
      op: c.op,
      values: c.values.join(", "),
    })),
  );
  const [submitting, setSubmitting] = useState(false);

  const splitList = (v: string) => v.split(",").map((s) => s.trim()).filter(Boolean);

  function updateClaim(i: number, patch: Partial<{ path: string; op: OidcClaimOp; values: string }>) {
    setClaims((prev) => prev.map((c, idx) => (idx === i ? { ...c, ...patch } : c)));
  }

  function buildMapping(): OidcMapping | null | string {
    if (!mappingEnabled) return null;
    const built: OidcClaim[] = [];
    for (const c of claims) {
      const path = c.path.trim();
      const values = splitList(c.values);
      if (!path && values.length === 0) continue;
      if (!path) return "Every claim needs a path.";
      if (values.length === 0) return `Claim "${path}" needs at least one value.`;
      built.push({ path, op: c.op, values });
    }
    if (built.length === 0) return "Add at least one claim, or disable OIDC mapping.";
    return { match, claims: built };
  }

  async function submit() {
    if (!name.trim()) {
      toast({ variant: "error", title: "Name is required" });
      return;
    }
    const mapping = buildMapping();
    if (typeof mapping === "string") {
      toast({ variant: "error", title: mapping });
      return;
    }

    const body: Record<string, unknown> = { name: name.trim() };
    if (mapping) body.oidc_mapping = mapping;
    else if (isEdit) body.oidc_mapping = null;

    setSubmitting(true);
    try {
      const base = `${gatewayScope(gatewayId)}/roles`;
      if (isEdit) {
        await api.put(`${base}/${role.id}`, body);
      } else {
        await api.post(base, body);
      }
      toast({ variant: "success", title: isEdit ? "Role updated" : "Role created", description: name });
      void invalidate("roles");
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
          title={isEdit ? "Edit role" : "New role"}
          description="Bind registries and model policies from the role's configuration panel after creating it."
        />
        <DialogBody className="flex flex-col gap-5">
          <Field label="Name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="premium-users" />
          </Field>

          <Divider />

          <SwitchRow
            label="OIDC claim mapping"
            description="Assign this role automatically when an identity token matches the claims below."
            checked={mappingEnabled}
            onCheckedChange={setMappingEnabled}
          />

          {mappingEnabled && (
            <div className="flex flex-col gap-3">
              <Field label="Match">
                <Select value={match} onChange={(e) => setMatch(e.target.value as OidcMapping["match"])}>
                  <option value="any">Any claim matches</option>
                  <option value="all">All claims match</option>
                </Select>
              </Field>

              <div className="flex flex-col gap-2">
                <Label>Claims</Label>
                {claims.map((c, i) => (
                  <div key={i} className="rounded-(--radius) border border-border bg-surface-2/30 p-3 flex flex-col gap-2.5">
                    <Grid2>
                      <Field label="Path">
                        <Input
                          value={c.path}
                          onChange={(e) => updateClaim(i, { path: e.target.value })}
                          placeholder="realm_access.roles"
                        />
                      </Field>
                      <Field label="Operator">
                        <Select value={c.op} onChange={(e) => updateClaim(i, { op: e.target.value as OidcClaimOp })}>
                          {CLAIM_OPS.map((o) => (
                            <option key={o.value} value={o.value}>
                              {o.label}
                            </option>
                          ))}
                        </Select>
                      </Field>
                    </Grid2>
                    <div className="flex items-end gap-2">
                      <Field label="Values" hint="comma-separated" className="flex-1">
                        <Input
                          value={c.values}
                          onChange={(e) => updateClaim(i, { values: e.target.value })}
                          placeholder="admin, premium"
                        />
                      </Field>
                      {claims.length > 1 && (
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setClaims((prev) => prev.filter((_, idx) => idx !== i))}
                          aria-label="Remove claim"
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                ))}
                <div>
                  <Button variant="ghost" size="sm" onClick={() => setClaims((prev) => [...prev, { path: "", op: "equals", values: "" }])}>
                    <Plus className="h-4 w-4" />
                    Add claim
                  </Button>
                </div>
              </div>
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="primary" onClick={submit} loading={submitting}>
            {isEdit ? "Save changes" : "Create role"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RoleDetail({
  roleId,
  open,
  onOpenChange,
}: {
  roleId: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const gatewayId = useActiveGatewayId();
  const { data: role, isLoading } = useQuery({
    queryKey: ["role", gatewayId, roleId],
    queryFn: () => api.get<Role>(`${gatewayScope(gatewayId)}/roles/${roleId}`),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader title={role ? role.name : "Role"} description="Registries and model policies" />
        {isLoading || !role ? (
          <DialogBody>
            <PageLoader />
          </DialogBody>
        ) : (
          <Tabs defaultValue="registries">
            <div className="px-6 pt-3">
              <TabsList>
                <TabTrigger value="registries">Registries</TabTrigger>
                <TabTrigger value="models">Model policies</TabTrigger>
              </TabsList>
            </div>
            <DialogBody className="min-h-[340px]">
              <TabContent value="registries">
                <RoleRegistriesTab role={role} />
              </TabContent>
              <TabContent value="models">
                <RoleModelPoliciesTab role={role} onClose={() => onOpenChange(false)} />
              </TabContent>
            </DialogBody>
          </Tabs>
        )}
      </DialogContent>
    </Dialog>
  );
}

function useRoleInvalidate(roleId: string) {
  const qc = useQueryClient();
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  return () => {
    void qc.invalidateQueries({ queryKey: ["role", gatewayId, roleId] });
    void invalidate("roles");
  };
}

function RoleRegistriesTab({ role }: { role: Role }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useRoleInvalidate(role.id);
  const { toast } = useToast();
  const { data: registries, isLoading } = useList<Registry>("registries");
  const [pending, setPending] = useState<string | null>(null);

  const bound = new Set(role.registry_ids);

  async function toggle(registry: Registry, isBound: boolean) {
    setPending(registry.id);
    const url = `${gatewayScope(gatewayId)}/roles/${role.id}/registries/${registry.id}`;
    try {
      if (isBound) await api.del(url);
      else await api.post(url);
      invalidate();
    } catch (err) {
      toast({ variant: "error", title: "Could not update binding", description: errorMessage(err) });
    } finally {
      setPending(null);
    }
  }

  if (isLoading) return <p className="text-[13px] text-muted">Loading…</p>;
  if (!registries || registries.length === 0) {
    return <p className="text-[13px] text-faint">No registries available in this gateway.</p>;
  }

  return (
    <section className="flex flex-col gap-2.5">
      <div className="flex items-center gap-2 text-[13px] font-semibold text-fg">
        <span className="text-accent">
          <Server className="h-4 w-4" />
        </span>
        Registries
      </div>
      <div className="flex flex-col gap-1.5">
        {registries.map((registry) => {
          const isBound = bound.has(registry.id);
          return (
            <button
              key={registry.id}
              type="button"
              disabled={pending === registry.id}
              onClick={() => toggle(registry, isBound)}
              className={cn(
                "flex items-center justify-between gap-3 rounded-(--radius) border px-3.5 h-11 text-left transition-colors disabled:opacity-50",
                isBound
                  ? "border-accent/40 bg-accent/8"
                  : "border-border bg-surface-2/30 hover:border-border-strong",
              )}
            >
              <div className="flex items-center gap-2.5 min-w-0">
                <span
                  className={cn(
                    "flex h-4.5 w-4.5 items-center justify-center rounded border shrink-0",
                    isBound ? "bg-accent border-accent text-bg" : "border-border-strong text-transparent",
                  )}
                >
                  <Check className="h-3 w-3" />
                </span>
                <span className="text-[13px] text-fg truncate">
                  {registry.name} <span className="text-faint">({registry.provider})</span>
                </span>
              </div>
              <span className="text-[12px] text-faint shrink-0">{isBound ? "Attached" : "Attach"}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}

function RoleModelPoliciesTab({ role, onClose }: { role: Role; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useRoleInvalidate(role.id);
  const { toast } = useToast();
  const { data: registries } = useList<Registry>("registries");

  const attached = (registries ?? []).filter((r) => role.registry_ids.includes(r.id));
  const [state, setState] = useState<Record<string, ModelPolicyState>>(() =>
    modelPolicyStateFrom(role.model_policies),
  );
  const [saving, setSaving] = useState(false);

  async function save() {
    const policies = buildModelPolicies(attached, state);
    setSaving(true);
    try {
      await api.put(`${gatewayScope(gatewayId)}/roles/${role.id}`, { model_policies: policies });
      toast({ variant: "success", title: "Model policies saved" });
      invalidate();
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Save failed", description: errorMessage(err) });
    } finally {
      setSaving(false);
    }
  }

  if (attached.length === 0) {
    return (
      <p className="text-[13px] text-faint py-8 text-center">
        Attach registries first (Registries tab) to configure per-model allowlists.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <ModelPolicyEditor registries={attached} state={state} onChange={setState} />
      <div className="flex justify-end pt-2">
        <Button variant="primary" onClick={save} loading={saving}>
          Save model policies
        </Button>
      </div>
    </div>
  );
}
