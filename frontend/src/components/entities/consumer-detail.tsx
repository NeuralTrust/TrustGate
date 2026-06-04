"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Server, KeyRound, ShieldCheck } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useList, useInvalidate, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { Dialog, DialogContent, DialogHeader, DialogBody, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Tabs, TabsList, TabTrigger, TabContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { SwitchRow, Grid2 } from "@/components/ui/form-bits";
import { PageLoader, Badge } from "@/components/ui/misc";
import { cn } from "@/lib/cn";
import type { Consumer, Registry, Auth, Policy } from "@/lib/types";

const TRIGGERS = ["http_5xx", "http_429", "timeout", "provider_error", "plugin_rejection"];

export function ConsumerDetail({
  consumerId,
  open,
  onOpenChange,
}: {
  consumerId: string;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const gatewayId = useActiveGatewayId();
  const { data: consumer, isLoading } = useQuery({
    queryKey: ["consumer", gatewayId, consumerId],
    queryFn: () => api.get<Consumer>(`${gatewayScope(gatewayId)}/consumers/${consumerId}`),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent size="xl">
        <DialogHeader
          title={consumer ? consumer.name : "Consumer"}
          description={consumer?.path}
        />
        {isLoading || !consumer ? (
          <DialogBody>
            <PageLoader />
          </DialogBody>
        ) : (
          <Tabs defaultValue="bindings">
            <div className="px-6 pt-3">
              <TabsList>
                <TabTrigger value="bindings">Bindings</TabTrigger>
                <TabTrigger value="fallback">Fallback</TabTrigger>
                <TabTrigger value="models">Model policies</TabTrigger>
              </TabsList>
            </div>
            <DialogBody className="min-h-[340px]">
              <TabContent value="bindings">
                <BindingsTab consumer={consumer} />
              </TabContent>
              <TabContent value="fallback">
                <FallbackTab consumer={consumer} onClose={() => onOpenChange(false)} />
              </TabContent>
              <TabContent value="models">
                <ModelPoliciesTab consumer={consumer} onClose={() => onOpenChange(false)} />
              </TabContent>
            </DialogBody>
          </Tabs>
        )}
      </DialogContent>
    </Dialog>
  );
}

function useConsumerInvalidate(consumerId: string) {
  const qc = useQueryClient();
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  return () => {
    void qc.invalidateQueries({ queryKey: ["consumer", gatewayId, consumerId] });
    void invalidate("consumers");
  };
}

function BindingsTab({ consumer }: { consumer: Consumer }) {
  return (
    <div className="flex flex-col gap-6">
      <BindingSection
        consumer={consumer}
        kind="registries"
        title="Registries"
        icon={<Server className="h-4 w-4" />}
        boundIds={consumer.registry_ids}
        useItems={() => useList<Registry>("registries")}
      />
      <BindingSection
        consumer={consumer}
        kind="auths"
        title="Auth"
        icon={<KeyRound className="h-4 w-4" />}
        boundIds={consumer.auth_ids}
        useItems={() => useList<Auth>("auths")}
      />
      <BindingSection
        consumer={consumer}
        kind="policies"
        title="Policies"
        icon={<ShieldCheck className="h-4 w-4" />}
        boundIds={[]}
        useItems={() => useList<Policy>("policies")}
        isPolicyBound={(p) => (p.consumer_ids ?? []).includes(consumer.id)}
      />
    </div>
  );
}

interface NamedEntity {
  id: string;
  name: string;
  slug?: string;
  consumer_ids?: string[];
}

function BindingSection<T extends NamedEntity>({
  consumer,
  kind,
  title,
  icon,
  boundIds,
  useItems,
  isPolicyBound,
}: {
  consumer: Consumer;
  kind: "registries" | "auths" | "policies";
  title: string;
  icon: React.ReactNode;
  boundIds: string[];
  useItems: () => { data?: T[]; isLoading: boolean };
  isPolicyBound?: (item: T) => boolean;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useConsumerInvalidate(consumer.id);
  const { toast } = useToast();
  const { data: items, isLoading } = useItems();
  const [pending, setPending] = useState<string | null>(null);

  const bound = new Set(boundIds);

  async function toggle(item: T, isBound: boolean) {
    setPending(item.id);
    const url = `${gatewayScope(gatewayId)}/consumers/${consumer.id}/${kind}/${item.id}`;
    try {
      if (isBound) {
        await api.del(url);
      } else {
        await api.post(url);
      }
      invalidate();
    } catch (err) {
      toast({ variant: "error", title: "Could not update binding", description: errorMessage(err) });
    } finally {
      setPending(null);
    }
  }

  return (
    <section className="flex flex-col gap-2.5">
      <div className="flex items-center gap-2 text-[13px] font-semibold text-fg">
        <span className="text-accent">{icon}</span>
        {title}
      </div>
      {isLoading ? (
        <p className="text-[13px] text-muted">Loading…</p>
      ) : !items || items.length === 0 ? (
        <p className="text-[13px] text-faint">No {title.toLowerCase()} available in this gateway.</p>
      ) : (
        <div className="flex flex-col gap-1.5">
          {items.map((item) => {
            const isBound = isPolicyBound ? isPolicyBound(item) : bound.has(item.id);
            return (
              <button
                key={item.id}
                type="button"
                disabled={pending === item.id}
                onClick={() => toggle(item, isBound)}
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
                  <span className="text-[13px] text-fg truncate">{item.name}</span>
                  {item.slug && <Badge tone="neutral">{item.slug}</Badge>}
                </div>
                <span className="text-[12px] text-faint shrink-0">{isBound ? "Attached" : "Attach"}</span>
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}

function consumerBaseBody(consumer: Consumer): Record<string, unknown> {
  return {
    name: consumer.name,
    path: consumer.path,
    type: consumer.type,
    algorithm: consumer.algorithm,
    active: consumer.active,
    ...(consumer.headers ? { headers: consumer.headers } : {}),
  };
}

function FallbackTab({ consumer, onClose }: { consumer: Consumer; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useConsumerInvalidate(consumer.id);
  const { toast } = useToast();
  const { data: registries } = useList<Registry>("registries");

  const fb = consumer.fallback;
  const [enabled, setEnabled] = useState(fb?.enabled ?? false);
  const [triggers, setTriggers] = useState<string[]>(fb?.triggers ?? ["http_5xx"]);
  const [chain, setChain] = useState<string[]>(fb?.chain ?? []);
  const [maxAttempts, setMaxAttempts] = useState(String(fb?.budget?.max_attempts ?? 3));
  const [maxLatency, setMaxLatency] = useState(String(fb?.budget?.max_total_latency_ms ?? 5000));
  const [maxCost, setMaxCost] = useState(String(fb?.budget?.max_cost_usd ?? 0));
  const [saving, setSaving] = useState(false);

  const attached = (registries ?? []).filter((r) => consumer.registry_ids.includes(r.id));

  function toggleTrigger(t: string) {
    setTriggers((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]));
  }
  function toggleChain(id: string) {
    setChain((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  }

  async function save() {
    const body = consumerBaseBody(consumer);
    if (enabled) {
      if (chain.length === 0) {
        toast({ variant: "error", title: "Add at least one registry to the fallback chain" });
        return;
      }
      body.fallback = {
        enabled: true,
        triggers,
        chain,
        budget: {
          max_attempts: Number(maxAttempts) || 1,
          max_total_latency_ms: Number(maxLatency) || 0,
          max_cost_usd: Number(maxCost) || 0,
        },
      };
    } else {
      body.fallback = { enabled: false };
    }

    setSaving(true);
    try {
      await api.put(`${gatewayScope(gatewayId)}/consumers/${consumer.id}`, body);
      toast({ variant: "success", title: "Fallback saved" });
      invalidate();
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Save failed", description: errorMessage(err) });
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex flex-col gap-4">
      <SwitchRow
        label="Enable fallback"
        description="Retry against other registries when the primary fails."
        checked={enabled}
        onCheckedChange={setEnabled}
      />

      {enabled && (
        <>
          <div className="flex flex-col gap-2">
            <p className="text-[13px] font-medium text-fg">Triggers</p>
            <div className="flex flex-wrap gap-2">
              {TRIGGERS.map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => toggleTrigger(t)}
                  className={cn(
                    "rounded-full border px-3 h-7 text-[12px] transition-colors",
                    triggers.includes(t)
                      ? "border-accent/50 bg-accent/10 text-fg"
                      : "border-border text-muted hover:text-fg",
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <p className="text-[13px] font-medium text-fg">Fallback chain</p>
            {attached.length === 0 ? (
              <p className="text-[12px] text-faint">Attach registries first (Bindings tab).</p>
            ) : (
              <div className="flex flex-col gap-1.5">
                {attached.map((r) => (
                  <button
                    key={r.id}
                    type="button"
                    onClick={() => toggleChain(r.id)}
                    className={cn(
                      "flex items-center justify-between rounded-(--radius) border px-3.5 h-10 transition-colors",
                      chain.includes(r.id)
                        ? "border-accent/40 bg-accent/8"
                        : "border-border bg-surface-2/30 hover:border-border-strong",
                    )}
                  >
                    <span className="text-[13px] text-fg">{r.name}</span>
                    {chain.includes(r.id) && (
                      <span className="text-[12px] text-accent">#{chain.indexOf(r.id) + 1}</span>
                    )}
                  </button>
                ))}
              </div>
            )}
          </div>

          <div className="flex flex-col gap-2">
            <p className="text-[13px] font-medium text-fg">Budget</p>
            <Grid2>
              <Field label="Max attempts">
                <Input type="number" min={1} value={maxAttempts} onChange={(e) => setMaxAttempts(e.target.value)} />
              </Field>
              <Field label="Max latency (ms)">
                <Input type="number" min={0} value={maxLatency} onChange={(e) => setMaxLatency(e.target.value)} />
              </Field>
            </Grid2>
            <Field label="Max cost (USD)">
              <Input type="number" min={0} step="0.01" value={maxCost} onChange={(e) => setMaxCost(e.target.value)} />
            </Field>
          </div>
        </>
      )}

      <div className="flex justify-end gap-2.5 pt-2">
        <Button variant="primary" onClick={save} loading={saving}>
          Save fallback
        </Button>
      </div>
    </div>
  );
}

function ModelPoliciesTab({ consumer, onClose }: { consumer: Consumer; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useConsumerInvalidate(consumer.id);
  const { toast } = useToast();
  const { data: registries } = useList<Registry>("registries");

  const attached = (registries ?? []).filter((r) => consumer.registry_ids.includes(r.id));

  const initial: Record<string, { allowed: string; default: string }> = {};
  for (const mp of consumer.model_policies ?? []) {
    initial[mp.registry_id] = {
      allowed: (mp.allowed ?? []).join(", "),
      default: mp.default ?? "",
    };
  }
  const [state, setState] = useState(initial);
  const [saving, setSaving] = useState(false);

  function update(registryId: string, key: "allowed" | "default", value: string) {
    setState((prev) => ({
      ...prev,
      [registryId]: { allowed: "", default: "", ...prev[registryId], [key]: value },
    }));
  }

  async function save() {
    const modelPolicies = attached
      .map((r) => {
        const entry = state[r.id];
        if (!entry) return null;
        const allowed = entry.allowed.split(",").map((s) => s.trim()).filter(Boolean);
        if (allowed.length === 0 && !entry.default) return null;
        return { registry_id: r.id, allowed, default: entry.default || undefined };
      })
      .filter(Boolean);

    const body = consumerBaseBody(consumer);
    if (consumer.fallback) {
      body.fallback = {
        enabled: consumer.fallback.enabled,
        triggers: consumer.fallback.triggers,
        chain: consumer.fallback.chain,
        budget: {
          max_attempts: consumer.fallback.budget.max_attempts,
          max_total_latency_ms: consumer.fallback.budget.max_total_latency_ms,
          max_cost_usd: consumer.fallback.budget.max_cost_usd,
        },
      };
    }
    body.model_policies = modelPolicies;

    setSaving(true);
    try {
      await api.put(`${gatewayScope(gatewayId)}/consumers/${consumer.id}`, body);
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
        Attach registries first (Bindings tab) to configure per-model allowlists.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {attached.map((r) => (
        <div key={r.id} className="rounded-(--radius) border border-border bg-surface-2/30 p-3.5 flex flex-col gap-3">
          <p className="text-[13px] font-medium text-fg">{r.name}</p>
          <Field label="Allowed models" hint="comma-separated, empty = all">
            <Input
              value={state[r.id]?.allowed ?? ""}
              onChange={(e) => update(r.id, "allowed", e.target.value)}
              placeholder="gpt-4o, gpt-4o-mini"
            />
          </Field>
          <Field label="Default model" hint="optional">
            <Input
              value={state[r.id]?.default ?? ""}
              onChange={(e) => update(r.id, "default", e.target.value)}
              placeholder="gpt-4o"
            />
          </Field>
        </div>
      ))}
      <div className="flex justify-end pt-2">
        <Button variant="primary" onClick={save} loading={saving}>
          Save model policies
        </Button>
      </div>
    </div>
  );
}
