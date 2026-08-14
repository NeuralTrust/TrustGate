"use client";

import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Server, KeyRound, ShieldCheck, ArrowUp, ArrowDown, X, UsersRound } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useAllList, useInvalidate, errorMessage } from "@/lib/hooks";
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
import {
  ToolkitEditor,
  FailModeField,
  buildToolkit,
  toolkitError,
  toolkitRowsFrom,
  type ToolkitRow,
} from "./toolkit-editor";
import type { Consumer, Registry, Algorithm, ModelPolicy, RoutingMode } from "@/lib/types";

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
  | "semantic"
  | "smart";

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
  smart: {
    label: "Smart routing",
    hint: "Route by message complexity: each tier maps a minimum score to a registry.",
  },
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
    case "smart":
      return "smart-routing";
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
    case "smart-routing":
      return "smart";
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
                {consumer.type === "MCP" && <TabTrigger value="toolkit">MCP toolkit</TabTrigger>}
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
              {consumer.type === "MCP" && (
                <TabContent value="toolkit">
                  <ToolkitTab consumer={consumer} onClose={() => onOpenChange(false)} />
                </TabContent>
              )}
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
        />
      ) : (
        <BindingSection
          consumer={consumer}
          kind="registries"
          title="Registries"
          icon={<Server className="h-4 w-4" />}
          boundIds={consumer.registry_ids}
        />
      )}
      <BindingSection
        consumer={consumer}
        kind="auths"
        title="Auth"
        icon={<KeyRound className="h-4 w-4" />}
        boundIds={consumer.auth_ids}
      />
      <BindingSection
        consumer={consumer}
        kind="policies"
        title="Policies"
        icon={<ShieldCheck className="h-4 w-4" />}
        boundIds={[]}
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

function BindingSection({
  consumer,
  kind,
  title,
  icon,
  boundIds,
  isPolicyBound,
}: {
  consumer: Consumer;
  kind: "registries" | "roles" | "auths" | "policies";
  title: string;
  icon: React.ReactNode;
  boundIds: string[];
  isPolicyBound?: (item: NamedEntity) => boolean;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useConsumerInvalidate(consumer.id);
  const { toast } = useToast();
  // `kind` doubles as the list resource name, so the section fetches its own
  // candidates instead of taking a hook as a prop.
  const { data: items, isLoading } = useAllList<NamedEntity>(kind);
  const [pending, setPending] = useState<string | null>(null);

  const bound = new Set(boundIds);

  async function toggle(item: NamedEntity, isBound: boolean) {
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

type PoolRoute = { registry_id: string; model: string; weight: string };

type TierDraft = { min_score: string; registry_id: string; model: string };

function poolRoutesFrom(consumer: Consumer): PoolRoute[] {
  const registryWeight = new Map((consumer.registry_weights ?? []).map((w) => [w.registry_id, w.weight]));
  return (consumer.lb_config?.members ?? []).map((m) => ({
    registry_id: m.registry_id,
    model: m.model ?? "",
    weight: String(m.weight ?? registryWeight.get(m.registry_id) ?? 1),
  }));
}

function mergePoolRoutes(routes: PoolRoute[], attached: Registry[]): PoolRoute[] {
  const attachedIds = new Set(attached.map((r) => r.id));
  const merged = routes.filter((r) => attachedIds.has(r.registry_id));
  const covered = new Set(merged.map((r) => r.registry_id));
  for (const r of attached) {
    if (!covered.has(r.id)) merged.push({ registry_id: r.id, model: "", weight: "1" });
  }
  return merged;
}

function routeWeightOf(route: PoolRoute): number {
  return Math.min(100, Math.max(1, Math.round(Number(route.weight) || 1)));
}

function routesOf(routes: PoolRoute[], registryId: string): PoolRoute[] {
  return routes.filter((r) => r.registry_id === registryId);
}

// Mirrors the backend route-identity rules so the user sees the problem before saving.
function poolRouteError(routes: PoolRoute[]): string | null {
  const seen = new Set<string>();
  for (const route of routes) {
    const model = route.model.trim();
    if (!model && routesOf(routes, route.registry_id).length > 1) {
      return "Every route of a registry that appears more than once needs a model.";
    }
    const key = `${route.registry_id}|${model}`;
    if (seen.has(key)) return "Two routes share the same registry and model.";
    seen.add(key);
  }
  return null;
}

// An enabled pool requires a policy per member and a pinned model inside any non-empty allowlist.
function poolModelPolicies(consumer: Consumer, attached: Registry[], routes: PoolRoute[]): ModelPolicy[] {
  const existing = new Map((consumer.model_policies ?? []).map((p) => [p.registry_id, p]));
  return attached.map((r) => {
    const current = existing.get(r.id);
    const allowed = current?.allowed ?? [];
    const policy: ModelPolicy = { registry_id: r.id };
    if (allowed.length > 0) {
      const pinned = routesOf(routes, r.id)
        .map((route) => route.model.trim())
        .filter((model) => model !== "" && !allowed.includes(model));
      policy.allowed = [...allowed, ...new Set(pinned)];
    }
    if (current?.default) policy.default = current.default;
    return policy;
  });
}

function RoutingTab({ consumer, onClose }: { consumer: Consumer; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useConsumerInvalidate(consumer.id);
  const { toast } = useToast();
  const { data: registries } = useAllList<Registry>("registries");

  const attached = (registries ?? []).filter((r) => consumer.registry_ids.includes(r.id));

  const emb = consumer.lb_config?.embedding_config;
  const [mode, setMode] = useState<RoutingMode>(consumer.routing_mode);
  const [strategy, setStrategy] = useState<Strategy>(strategyOf(consumer));
  const [embProvider, setEmbProvider] = useState(emb?.provider ?? "");
  const [embModel, setEmbModel] = useState(emb?.model ?? "");
  const [embKey, setEmbKey] = useState("");
  const [tiers, setTiers] = useState<TierDraft[]>(() =>
    (consumer.lb_config?.smart_routing?.tiers ?? []).map((t) => ({
      min_score: String(t.min_score),
      registry_id: t.registry_id,
      model: t.model ?? "",
    })),
  );
  const [routes, setRoutes] = useState<PoolRoute[]>(() => poolRoutesFrom(consumer));
  const fb = consumer.fallback;
  const [triggers, setTriggers] = useState<string[]>(fb?.triggers?.length ? fb.triggers : ["http_5xx"]);
  const [chain, setChain] = useState<string[]>(fb?.chain ?? []);
  const [maxAttempts, setMaxAttempts] = useState(String(fb?.budget?.max_attempts ?? 3));
  const [maxLatency, setMaxLatency] = useState(String(fb?.budget?.max_total_latency_ms ?? 5000));
  const [saving, setSaving] = useState(false);

  const meta = STRATEGY_META[strategy];
  const showSemantic = consumer.lb_config?.algorithm === "semantic" || strategy === "semantic";
  const showSmart = consumer.lb_config?.algorithm === "smart-routing" || strategy === "smart";

  function addTier() {
    setTiers((prev) => [...prev, { min_score: "", registry_id: "", model: "" }]);
  }
  function removeTier(index: number) {
    setTiers((prev) => prev.filter((_, i) => i !== index));
  }
  function updateTier(index: number, patch: Partial<TierDraft>) {
    setTiers((prev) => prev.map((tier, i) => (i === index ? { ...tier, ...patch } : tier)));
  }

  // Mutations rewrite the normalized list so edits survive the merge with attached registries.
  const poolRoutes = mergePoolRoutes(routes, attached);
  function addRoute(registryId: string) {
    if (!registryId) return;
    setRoutes([...poolRoutes, { registry_id: registryId, model: "", weight: "1" }]);
  }
  function removeRoute(index: number) {
    setRoutes(poolRoutes.filter((_, i) => i !== index));
  }
  function updateRoute(index: number, patch: Partial<PoolRoute>) {
    setRoutes(poolRoutes.map((route, i) => (i === index ? { ...route, ...patch } : route)));
  }
  const totalWeight = poolRoutes.reduce((sum, route) => sum + routeWeightOf(route), 0);

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
      const routeError = poolRouteError(poolRoutes);
      if (routeError) {
        toast({ variant: "error", title: routeError });
        return;
      }
      const lb: Record<string, unknown> = {
        enabled: true,
        algorithm: algorithmFor(strategy),
        members: poolRoutes.map((route) => ({
          registry_id: route.registry_id,
          ...(route.model.trim() ? { model: route.model.trim() } : {}),
          ...(strategy === "weighted" ? { weight: routeWeightOf(route) } : {}),
        })),
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

      if (strategy === "smart") {
        const parsed = tiers
          .filter((t) => t.registry_id)
          .map((t) => ({
            min_score: Number(t.min_score),
            registry_id: t.registry_id,
            ...(t.model.trim() ? { model: t.model.trim() } : {}),
          }));
        if (parsed.length === 0) {
          toast({ variant: "error", title: "Add at least one smart-routing tier with a registry." });
          return;
        }
        if (parsed.some((t) => Number.isNaN(t.min_score) || t.min_score < 0 || t.min_score > 1)) {
          toast({ variant: "error", title: "Each tier min score must be between 0 and 1." });
          return;
        }
        const ambiguous = parsed.find(
          (t) => !t.model && routesOf(poolRoutes, t.registry_id).length > 1,
        );
        if (ambiguous) {
          toast({
            variant: "error",
            title: "Pick a model for every tier whose registry has more than one route.",
          });
          return;
        }
        lb.smart_routing = { tiers: parsed };
      }

      body.lb_config = lb;
      body.fallback = { enabled: false };
      body.model_policies = poolModelPolicies(consumer, attached, poolRoutes);
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
      // The per-registry weight lives on the association, so it goes through the (idempotent) attach endpoint.
      if (strategy === "weighted") {
        for (const r of attached) {
          const route = routesOf(poolRoutes, r.id)[0];
          if (route) await api.post(`${base}/registries/${r.id}`, { weight: routeWeightOf(route) });
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
            {showSmart && <option value="smart">{STRATEGY_META.smart.label}</option>}
          </optgroup>
        </Select>
      </Field>
      <p className="text-[12px] text-muted -mt-2">{meta.hint}</p>

      {isLoadBalanced(strategy) && (
        <div className="flex flex-col gap-2">
          <p className="text-[13px] font-medium text-fg">Pool routes</p>
          <p className="text-[12px] text-muted -mt-1">
            Each route is a registry with an optional model. Add the same registry twice with different
            models to balance across them independently; leave the model blank to use the registry
            default from Model policies.
          </p>
          {attached.length === 0 ? (
            <p className="text-[12px] text-faint">Attach registries first (Bindings tab).</p>
          ) : (
            <>
              <div className="flex flex-col gap-1.5">
                {poolRoutes.map((route, i) => {
                  const r = registryById.get(route.registry_id);
                  const only = routesOf(poolRoutes, route.registry_id).length === 1;
                  const pct = totalWeight > 0 ? Math.round((routeWeightOf(route) / totalWeight) * 100) : 0;
                  return (
                    <div
                      key={`${route.registry_id}-${i}`}
                      className="flex items-center gap-3 rounded-(--radius) border border-border bg-surface-2/30 px-3.5 h-12"
                    >
                      <span className="w-40 shrink-0 text-[13px] text-fg truncate">
                        {r?.name} <span className="text-faint">({r?.provider})</span>
                      </span>
                      <Input
                        value={route.model}
                        onChange={(e) => updateRoute(i, { model: e.target.value })}
                        placeholder="registry default"
                        className="flex-1 min-w-0"
                        aria-label={`Model for ${r?.name}`}
                      />
                      {strategy === "weighted" && (
                        <>
                          <Input
                            type="number"
                            min={1}
                            max={100}
                            value={route.weight}
                            onChange={(e) => updateRoute(i, { weight: e.target.value })}
                            className="w-20"
                            aria-label={`Weight for ${r?.name}`}
                          />
                          <span className="w-10 text-right text-[12px] text-muted tabular-nums">{pct}%</span>
                        </>
                      )}
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={only}
                        onClick={() => removeRoute(i)}
                        aria-label="Remove route"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    </div>
                  );
                })}
              </div>
              <Select
                value=""
                onChange={(e) => {
                  addRoute(e.target.value);
                  e.target.value = "";
                }}
              >
                <option value="">Add a route…</option>
                {attached.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} ({r.provider})
                  </option>
                ))}
              </Select>
            </>
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

      {strategy === "smart" && (
        <div className="rounded-(--radius) border border-border bg-surface-2/30 p-3.5 flex flex-col gap-3">
          <p className="text-[13px] font-medium text-fg">Complexity tiers</p>
          <p className="text-[12px] text-muted -mt-1">
            The tier with the highest min score not above the message score wins. Requests fall back to
            round robin when the Firewall Complexity API is unavailable.
          </p>
          {attached.length === 0 ? (
            <p className="text-[12px] text-faint">Attach registries first (Bindings tab).</p>
          ) : (
            <div className="flex flex-col gap-2">
              {tiers.map((tier, i) => (
                <div key={i} className="flex items-end gap-2">
                  <div className="w-28">
                    <Field label="Min score">
                      <Input
                        type="number"
                        min={0}
                        max={1}
                        step={0.05}
                        value={tier.min_score}
                        onChange={(e) => updateTier(i, { min_score: e.target.value })}
                        placeholder="0.0"
                      />
                    </Field>
                  </div>
                  <div className="flex-1">
                    <Field label="Registry">
                      <Select
                        value={tier.registry_id}
                        onChange={(e) => updateTier(i, { registry_id: e.target.value, model: "" })}
                      >
                        <option value="">Select registry…</option>
                        {attached.map((r) => (
                          <option key={r.id} value={r.id}>
                            {r.name}
                          </option>
                        ))}
                      </Select>
                    </Field>
                  </div>
                  <div className="flex-1">
                    <Field label="Route">
                      <Select value={tier.model} onChange={(e) => updateTier(i, { model: e.target.value })}>
                        <option value="">Any route</option>
                        {routesOf(poolRoutes, tier.registry_id)
                          .filter((route) => route.model.trim() !== "")
                          .map((route, routeIndex) => (
                            <option key={`${route.model}-${routeIndex}`} value={route.model.trim()}>
                              {route.model.trim()}
                            </option>
                          ))}
                      </Select>
                    </Field>
                  </div>
                  <button
                    type="button"
                    onClick={() => removeTier(i)}
                    aria-label="Remove tier"
                    className="mb-1 grid size-9 place-items-center rounded-(--radius) border border-border text-muted hover:text-fg"
                  >
                    <X className="size-4" />
                  </button>
                </div>
              ))}
              <div>
                <Button variant="secondary" onClick={addTier}>
                  Add tier
                </Button>
              </div>
            </div>
          )}
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
  const { data: registries } = useAllList<Registry>("registries");

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

// The MCP policy (toolkit + fail_mode) lives on the consumer only in inline
// mode; a role-based consumer takes it from the roles it resolves to.
function ToolkitTab({ consumer, onClose }: { consumer: Consumer; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useConsumerInvalidate(consumer.id);
  const { toast } = useToast();
  const { data: registries } = useAllList<Registry>("registries");

  const attached = (registries ?? []).filter(
    (r) => r.type === "MCP" && consumer.registry_ids.includes(r.id),
  );

  const [rows, setRows] = useState<ToolkitRow[]>(() => toolkitRowsFrom(consumer.toolkit));
  const [failMode, setFailMode] = useState(consumer.fail_mode || "open");
  const [saving, setSaving] = useState(false);

  async function save() {
    const error = toolkitError(rows);
    if (error) {
      toast({ variant: "error", title: error });
      return;
    }
    setSaving(true);
    try {
      // An empty toolkit is stored as "no restriction", so clearing every entry
      // goes back to exposing whatever the attached servers advertise.
      await api.put(`${gatewayScope(gatewayId)}/consumers/${consumer.id}`, {
        toolkit: buildToolkit(rows),
        fail_mode: failMode,
      });
      toast({ variant: "success", title: "MCP toolkit saved" });
      invalidate();
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Save failed", description: errorMessage(err) });
    } finally {
      setSaving(false);
    }
  }

  if (consumer.routing_mode === "role_based") {
    return (
      <p className="text-[13px] text-faint py-8 text-center">
        This consumer resolves its access through roles — configure the toolkit on each role instead.
      </p>
    );
  }

  if (attached.length === 0 && rows.length === 0) {
    return (
      <p className="text-[13px] text-faint py-8 text-center">
        Attach an MCP server first (Bindings tab) to restrict which tools it exposes.
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <p className="text-[12px] text-muted">
        With no entries at all, everything the attached servers advertise is exposed. Add entries to
        expose only those, per server: a name, or <span className="font-mono">*</span> for every tool,
        prompt or resource of that kind. Resource patterns accept a trailing{" "}
        <span className="font-mono">*</span>; tools and prompts can be renamed with an exposed name.
      </p>
      <ToolkitEditor registries={attached} rows={rows} onChange={setRows} />
      <FailModeField value={failMode} onChange={setFailMode} />
      <div className="flex justify-end pt-2">
        <Button variant="primary" onClick={save} loading={saving}>
          Save MCP toolkit
        </Button>
      </div>
    </div>
  );
}
