"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Server, KeyRound, ShieldCheck, ArrowUp, ArrowDown, X, UsersRound } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useList, useInvalidate, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { Dialog, DialogContent, DialogHeader, DialogBody } from "@/components/ui/dialog";
import { Tabs, TabsList, TabTrigger, TabContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Grid2 } from "@/components/ui/form-bits";
import { PageLoader, Badge } from "@/components/ui/misc";
import { cn } from "@/lib/cn";
import {
  ModelPolicyEditor,
  buildModelPolicies,
  modelPolicyStateFrom,
} from "./model-policy-editor";
import type { Consumer, Registry, Auth, Policy, Role, Algorithm, ModelPolicy, RoutingMode } from "@/lib/types";

const TRIGGERS = ["http_5xx", "http_429", "timeout", "provider_error", "plugin_rejection"];

// Routing "strategy" is a UI-level concept layered over the backend's
// (lb_config + fallback) model: "single"/"fallback" keep load balancing
// disabled, while the distribution strategies enable lb_config with the mapped
// algorithm.
type Strategy =
  | "single"
  | "fallback"
  | "round-robin"
  | "weighted"
  | "least-connections"
  | "random"
  | "semantic";

const STRATEGY_META: Record<Strategy, { label: string; hint: string }> = {
  single: { label: "Single target", hint: "Route every request to the attached registry." },
  fallback: {
    label: "Fallback",
    hint: "Try providers in declared order; on failure, route to the next. Order matters.",
  },
  "round-robin": { label: "Round robin", hint: "Even rotation across the attached registries." },
  weighted: {
    label: "Weighted",
    hint: "Distribute requests across registries by configurable per-registry weights.",
  },
  "least-connections": {
    label: "Least connections",
    hint: "Prefer the registry with the fewest in-flight requests.",
  },
  random: { label: "Random", hint: "Pick an attached registry at random." },
  semantic: { label: "Semantic", hint: "Route by embedding similarity (requires an embedding model)." },
};

// A strategy that enables lb_config (anything other than single/fallback).
function isLoadBalanced(s: Strategy): boolean {
  return s !== "single" && s !== "fallback";
}

function algorithmFor(s: Strategy): Algorithm {
  switch (s) {
    case "weighted":
      return "weighted-round-robin";
    case "least-connections":
      return "least-connections";
    case "random":
      return "random";
    case "semantic":
      return "semantic";
    case "single":
    case "fallback":
    case "round-robin":
      return "round-robin";
  }
}

function strategyOf(c: Consumer): Strategy {
  if (c.fallback?.enabled) return "fallback";
  if (!c.lb_config?.enabled) return "single";
  switch (c.lb_config.algorithm) {
    case "weighted-round-robin":
      return "weighted";
    case "least-connections":
      return "least-connections";
    case "random":
      return "random";
    case "semantic":
      return "semantic";
    default:
      return "round-robin";
  }
}

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
          description={consumer ? `/${consumer.slug}` : undefined}
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
                <TabTrigger value="routing">Routing</TabTrigger>
                <TabTrigger value="models">Model policies</TabTrigger>
              </TabsList>
            </div>
            <DialogBody className="min-h-[340px]">
              <TabContent value="bindings">
                <BindingsTab consumer={consumer} />
              </TabContent>
              <TabContent value="routing">
                <RoutingTab consumer={consumer} onClose={() => onOpenChange(false)} />
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
  const roleBased = consumer.routing_mode === "role_based";
  return (
    <div className="flex flex-col gap-6">
      {roleBased ? (
        <BindingSection
          consumer={consumer}
          kind="roles"
          title="Roles"
          icon={<UsersRound className="h-4 w-4" />}
          boundIds={consumer.role_ids}
          useItems={() => useList<Role>("roles")}
        />
      ) : (
        <BindingSection
          consumer={consumer}
          kind="registries"
          title="Registries"
          icon={<Server className="h-4 w-4" />}
          boundIds={consumer.registry_ids}
          useItems={() => useList<Registry>("registries")}
        />
      )}
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
  kind: "registries" | "roles" | "auths" | "policies";
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

// Model policies (registry_id → allowed/default) are required for every member
// of an enabled lb_config pool. This merges the consumer's existing policies
// with a bare entry for any attached registry that lacks one, so enabling load
// balancing never fails validation.
function poolModelPolicies(consumer: Consumer, attached: Registry[]): ModelPolicy[] {
  const existing = new Map((consumer.model_policies ?? []).map((p) => [p.registry_id, p]));
  return attached.map((r) => {
    const current = existing.get(r.id);
    const policy: ModelPolicy = { registry_id: r.id };
    if (current?.allowed && current.allowed.length > 0) policy.allowed = current.allowed;
    if (current?.default) policy.default = current.default;
    return policy;
  });
}

function RoutingTab({ consumer, onClose }: { consumer: Consumer; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useConsumerInvalidate(consumer.id);
  const { toast } = useToast();
  const { data: registries } = useList<Registry>("registries");

  const attached = (registries ?? []).filter((r) => consumer.registry_ids.includes(r.id));

  const emb = consumer.lb_config?.embedding_config;
  const [mode, setMode] = useState<RoutingMode>(consumer.routing_mode);
  const [strategy, setStrategy] = useState<Strategy>(strategyOf(consumer));
  const [embProvider, setEmbProvider] = useState(emb?.provider ?? "");
  const [embModel, setEmbModel] = useState(emb?.model ?? "");
  const [embKey, setEmbKey] = useState("");
  // Only user edits live in state; the displayed value falls back to the
  // consumer's configured weight, then a default of 1.
  const [weights, setWeights] = useState<Record<string, string>>(() => {
    const init: Record<string, string> = {};
    for (const w of consumer.registry_weights ?? []) init[w.registry_id] = String(w.weight);
    return init;
  });
  const fb = consumer.fallback;
  const [triggers, setTriggers] = useState<string[]>(fb?.triggers?.length ? fb.triggers : ["http_5xx"]);
  const [chain, setChain] = useState<string[]>(fb?.chain ?? []);
  const [maxAttempts, setMaxAttempts] = useState(String(fb?.budget?.max_attempts ?? 3));
  const [maxLatency, setMaxLatency] = useState(String(fb?.budget?.max_total_latency_ms ?? 5000));
  const [saving, setSaving] = useState(false);

  const meta = STRATEGY_META[strategy];
  const showSemantic = consumer.lb_config?.algorithm === "semantic" || strategy === "semantic";

  function displayWeight(r: Registry): string {
    return weights[r.id] ?? String(weightFromConsumer(r.id) ?? 1);
  }
  function weightFromConsumer(registryId: string): number | undefined {
    return (consumer.registry_weights ?? []).find((w) => w.registry_id === registryId)?.weight;
  }
  function weightOf(r: Registry): number {
    return Math.min(100, Math.max(1, Math.round(Number(displayWeight(r)) || 1)));
  }
  const totalWeight = attached.reduce((sum, r) => sum + weightOf(r), 0);

  function toggleTrigger(t: string) {
    setTriggers((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]));
  }
  function addToChain(id: string) {
    if (!id) return;
    setChain((prev) => (prev.includes(id) ? prev : [...prev, id]));
  }
  function removeFromChain(id: string) {
    setChain((prev) => prev.filter((x) => x !== id));
  }
  function moveChain(index: number, dir: -1 | 1) {
    setChain((prev) => {
      const j = index + dir;
      if (j < 0 || j >= prev.length) return prev;
      const next = [...prev];
      const moved = next.splice(index, 1)[0];
      if (moved === undefined) return prev;
      next.splice(j, 0, moved);
      return next;
    });
  }

  const registryById = new Map(attached.map((r) => [r.id, r]));
  const chainResolved = chain.filter((id) => registryById.has(id));
  const chainable = attached.filter((r) => !chain.includes(r.id));

  async function save() {
    const base = `${gatewayScope(gatewayId)}/consumers/${consumer.id}`;

    if (mode === "role_based") {
      setSaving(true);
      try {
        await api.put(base, { routing_mode: "role_based" });
        toast({ variant: "success", title: "Switched to role-based routing" });
        invalidate();
        onClose();
      } catch (err) {
        toast({ variant: "error", title: "Save failed", description: errorMessage(err) });
      } finally {
        setSaving(false);
      }
      return;
    }

    const body: Record<string, unknown> = { routing_mode: "inline" };

    if (isLoadBalanced(strategy)) {
      if (attached.length === 0) {
        toast({ variant: "error", title: "Attach at least one registry first (Bindings tab)." });
        return;
      }
      const lb: Record<string, unknown> = {
        enabled: true,
        algorithm: algorithmFor(strategy),
        members: attached.map((r) => ({ registry_id: r.id })),
      };

      if (strategy === "semantic") {
        if (!embProvider.trim() || !embModel.trim()) {
          toast({
            variant: "error",
            title: "Embedding model required",
            description: "Semantic routing needs an embedding provider and model.",
          });
          return;
        }
        lb.embedding_config = {
          provider: embProvider.trim(),
          model: embModel.trim(),
          ...(embKey.trim() ? { auth: { api_key: embKey.trim() } } : {}),
        };
      }

      if (strategy === "weighted" && totalWeight === 0) {
        toast({ variant: "error", title: "Set a weight above zero for at least one registry." });
        return;
      }

      body.lb_config = lb;
      body.fallback = { enabled: false };
      body.model_policies = poolModelPolicies(consumer, attached);
    } else if (strategy === "fallback") {
      if (chainResolved.length === 0) {
        toast({ variant: "error", title: "Add at least one registry to the fallback order." });
        return;
      }
      body.lb_config = { enabled: false };
      body.fallback = {
        enabled: true,
        triggers,
        chain: chainResolved,
        budget: {
          max_attempts: Number(maxAttempts) || 1,
          max_total_latency_ms: Number(maxLatency) || 0,
        },
      };
    } else {
      body.lb_config = { enabled: false };
      body.fallback = { enabled: false };
    }

    setSaving(true);
    try {
      // Weights are stored per registry association, not on the consumer body,
      // so they are updated through the (idempotent) attach endpoint.
      if (strategy === "weighted") {
        for (const r of attached) {
          await api.post(`${base}/registries/${r.id}`, { weight: weightOf(r) });
        }
      }
      await api.put(base, body);
      toast({ variant: "success", title: "Routing saved" });
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
      <Field label="Access mode">
        <Select value={mode} onChange={(e) => setMode(e.target.value as RoutingMode)}>
          <option value="inline">Inline (registries)</option>
          <option value="role_based">Role-based (identity)</option>
        </Select>
      </Field>

      {mode === "role_based" && (
        <div className="rounded-(--radius) border border-border bg-surface-2/30 p-3.5 text-[12px] text-muted">
          Routing is governed by the roles bound in the <span className="text-fg">Bindings</span> tab.
          A role-based consumer needs a single OIDC or OAuth2 auth and at least one role; each role
          carries its own registries and model policies.
        </div>
      )}

      {mode === "inline" && (
        <>
      <Field label="Strategy">
        <Select value={strategy} onChange={(e) => setStrategy(e.target.value as Strategy)}>
          <optgroup label="Without distribution">
            <option value="single">{STRATEGY_META.single.label}</option>
            <option value="fallback">{STRATEGY_META.fallback.label}</option>
          </optgroup>
          <optgroup label="Distribution strategies">
            <option value="round-robin">{STRATEGY_META["round-robin"].label}</option>
            <option value="weighted">{STRATEGY_META.weighted.label}</option>
            <option value="least-connections">{STRATEGY_META["least-connections"].label}</option>
            <option value="random">{STRATEGY_META.random.label}</option>
            {showSemantic && <option value="semantic">{STRATEGY_META.semantic.label}</option>}
          </optgroup>
        </Select>
      </Field>
      <p className="text-[12px] text-muted -mt-2">{meta.hint}</p>

      {strategy === "weighted" && (
        <div className="flex flex-col gap-2">
          <p className="text-[13px] font-medium text-fg">Registries</p>
          {attached.length === 0 ? (
            <p className="text-[12px] text-faint">Attach registries first (Bindings tab).</p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {attached.map((r) => {
                const pct = totalWeight > 0 ? Math.round((weightOf(r) / totalWeight) * 100) : 0;
                return (
                  <div
                    key={r.id}
                    className="flex items-center gap-3 rounded-(--radius) border border-border bg-surface-2/30 px-3.5 h-12"
                  >
                    <span className="flex-1 min-w-0 text-[13px] text-fg truncate">
                      {r.name} <span className="text-faint">({r.provider})</span>
                    </span>
                    <Input
                      type="number"
                      min={1}
                      max={100}
                      value={displayWeight(r)}
                      onChange={(e) => setWeights((prev) => ({ ...prev, [r.id]: e.target.value }))}
                      className="w-20"
                      aria-label={`Weight for ${r.name}`}
                    />
                    <span className="w-10 text-right text-[12px] text-muted tabular-nums">{pct}%</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {strategy === "fallback" && (
        <>
          <div className="flex flex-col gap-2">
            <p className="text-[13px] font-medium text-fg">Provider order</p>
            {attached.length === 0 ? (
              <p className="text-[12px] text-faint">Attach registries first (Bindings tab).</p>
            ) : (
              <>
                <div className="flex flex-col gap-1.5">
                  {chainResolved.map((id, index) => {
                    const r = registryById.get(id)!;
                    return (
                      <div
                        key={id}
                        className="flex items-center gap-2 rounded-(--radius) border border-border bg-surface-2/30 px-3 h-11"
                      >
                        <span className="flex h-6 w-6 items-center justify-center rounded border border-border text-[12px] text-muted shrink-0">
                          {index + 1}
                        </span>
                        <span className="flex-1 min-w-0 text-[13px] text-fg truncate">
                          {r.name} <span className="text-faint">({r.provider})</span>
                        </span>
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={index === 0}
                          onClick={() => moveChain(index, -1)}
                          aria-label="Move up"
                        >
                          <ArrowUp className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={index === chainResolved.length - 1}
                          onClick={() => moveChain(index, 1)}
                          aria-label="Move down"
                        >
                          <ArrowDown className="h-4 w-4" />
                        </Button>
                        <Button variant="ghost" size="icon" onClick={() => removeFromChain(id)} aria-label="Remove">
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    );
                  })}
                </div>
                {chainable.length > 0 && (
                  <Select
                    value=""
                    onChange={(e) => {
                      addToChain(e.target.value);
                      e.target.value = "";
                    }}
                  >
                    <option value="">Add a registry…</option>
                    {chainable.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.name} ({r.provider})
                      </option>
                    ))}
                  </Select>
                )}
              </>
            )}
          </div>

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
            <p className="text-[13px] font-medium text-fg">Budget</p>
            <Grid2>
              <Field label="Max attempts">
                <Input type="number" min={1} value={maxAttempts} onChange={(e) => setMaxAttempts(e.target.value)} />
              </Field>
              <Field label="Max latency (ms)">
                <Input type="number" min={0} value={maxLatency} onChange={(e) => setMaxLatency(e.target.value)} />
              </Field>
            </Grid2>
          </div>
        </>
      )}

      {strategy === "semantic" && (
        <div className="rounded-(--radius) border border-border bg-surface-2/30 p-3.5 flex flex-col gap-3">
          <p className="text-[13px] font-medium text-fg">Embedding model</p>
          <Grid2>
            <Field label="Provider">
              <Input value={embProvider} onChange={(e) => setEmbProvider(e.target.value)} placeholder="openai" />
            </Field>
            <Field label="Model">
              <Input value={embModel} onChange={(e) => setEmbModel(e.target.value)} placeholder="text-embedding-3-small" />
            </Field>
          </Grid2>
          <Field label="API key" hint="leave blank to keep the current key">
            <Input type="password" value={embKey} onChange={(e) => setEmbKey(e.target.value)} placeholder="sk-..." />
          </Field>
        </div>
      )}
        </>
      )}

      <div className="flex justify-end pt-2">
        <Button variant="primary" onClick={save} loading={saving}>
          Save routing
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

  const [state, setState] = useState(() => modelPolicyStateFrom(consumer.model_policies));
  const [saving, setSaving] = useState(false);

  async function save() {
    const policies = buildModelPolicies(attached, state);
    // An enabled lb_config requires a model policy for every pool member; keep
    // those covered with a bare entry so saving allowlists never breaks routing.
    if (consumer.lb_config?.enabled) {
      const covered = new Set(policies.map((p) => p.registry_id));
      for (const member of consumer.lb_config.members ?? []) {
        if (!covered.has(member.registry_id)) policies.push({ registry_id: member.registry_id });
      }
    }

    setSaving(true);
    try {
      await api.put(`${gatewayScope(gatewayId)}/consumers/${consumer.id}`, { model_policies: policies });
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
      <ModelPolicyEditor registries={attached} state={state} onChange={setState} />
      <div className="flex justify-end pt-2">
        <Button variant="primary" onClick={save} loading={saving}>
          Save model policies
        </Button>
      </div>
    </div>
  );
}
