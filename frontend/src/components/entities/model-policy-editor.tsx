"use client";

import { useState } from "react";
import { Plus, X } from "lucide-react";
import { useModelsCatalog } from "@/lib/hooks";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { cn } from "@/lib/cn";
import type { ModelPolicy, Registry } from "@/lib/types";

export interface ModelPolicyState {
  allowed: string[];
  default: string;
}

// buildModelPolicies turns the per-registry editor state into the array the
// admin API expects, dropping registries with no allowlist and no default
// (which the backend reads as "allow all models").
export function buildModelPolicies(
  registries: Registry[],
  state: Record<string, ModelPolicyState>,
): ModelPolicy[] {
  const out: ModelPolicy[] = [];
  for (const r of registries) {
    const entry = state[r.id];
    const allowed = entry?.allowed ?? [];
    const def = entry?.default?.trim() ?? "";
    if (allowed.length === 0 && !def) continue;
    const policy: ModelPolicy = { registry_id: r.id };
    if (allowed.length > 0) policy.allowed = allowed;
    if (def) policy.default = def;
    out.push(policy);
  }
  return out;
}

export function modelPolicyStateFrom(policies: ModelPolicy[] | undefined): Record<string, ModelPolicyState> {
  const state: Record<string, ModelPolicyState> = {};
  for (const p of policies ?? []) {
    state[p.registry_id] = { allowed: p.allowed ?? [], default: p.default ?? "" };
  }
  return state;
}

export function ModelPolicyEditor({
  registries,
  state,
  onChange,
}: {
  registries: Registry[];
  state: Record<string, ModelPolicyState>;
  onChange: (state: Record<string, ModelPolicyState>) => void;
}) {
  function update(registryId: string, next: ModelPolicyState) {
    onChange({ ...state, [registryId]: next });
  }

  return (
    <div className="flex flex-col gap-4">
      {registries.map((r) => (
        <ModelPolicyRow
          key={r.id}
          registry={r}
          value={state[r.id] ?? { allowed: [], default: "" }}
          onChange={(next) => update(r.id, next)}
        />
      ))}
    </div>
  );
}

function ModelPolicyRow({
  registry,
  value,
  onChange,
}: {
  registry: Registry;
  value: ModelPolicyState;
  onChange: (value: ModelPolicyState) => void;
}) {
  const { data: models } = useModelsCatalog(registry.provider);
  const [custom, setCustom] = useState("");

  const catalogSlugs = (models ?? []).map((m) => m.slug);
  const extraSlugs = value.allowed.filter((a) => !catalogSlugs.includes(a));
  const options = [...catalogSlugs, ...extraSlugs];

  function toggle(slug: string) {
    const allowed = value.allowed.includes(slug)
      ? value.allowed.filter((x) => x !== slug)
      : [...value.allowed, slug];
    const nextDefault = value.default && !allowed.includes(value.default) ? "" : value.default;
    onChange({ allowed, default: nextDefault });
  }

  function addCustom() {
    const slug = custom.trim();
    if (!slug || value.allowed.includes(slug)) {
      setCustom("");
      return;
    }
    onChange({ ...value, allowed: [...value.allowed, slug] });
    setCustom("");
  }

  return (
    <div className="rounded-(--radius) border border-border bg-surface-2/30 p-3.5 flex flex-col gap-3">
      <p className="text-[13px] font-medium text-fg">
        {registry.name} <span className="text-faint">({registry.provider})</span>
      </p>

      <Field label="Allowed models" hint="none selected = all models">
        {options.length > 0 ? (
          <div className="flex flex-wrap gap-1.5">
            {options.map((slug) => {
              const active = value.allowed.includes(slug);
              return (
                <button
                  key={slug}
                  type="button"
                  onClick={() => toggle(slug)}
                  className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-2.5 h-7 text-[12px] transition-colors",
                    active
                      ? "border-accent/50 bg-accent/10 text-fg"
                      : "border-border text-muted hover:text-fg",
                  )}
                >
                  {slug}
                  {active && <X className="h-3 w-3" />}
                </button>
              );
            })}
          </div>
        ) : (
          <p className="text-[12px] text-faint">No catalog models for this provider — add them manually below.</p>
        )}
      </Field>

      <div className="flex items-center gap-2">
        <Input
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), addCustom())}
          placeholder="add a model slug…"
          className="flex-1"
        />
        <Button variant="ghost" size="sm" onClick={addCustom}>
          <Plus className="h-4 w-4" />
          Add
        </Button>
      </div>

      <Field label="Default model" hint="optional, must be allowed">
        <Select
          value={value.default}
          onChange={(e) => onChange({ ...value, default: e.target.value })}
          disabled={value.allowed.length === 0}
        >
          <option value="">No default</option>
          {value.allowed.map((slug) => (
            <option key={slug} value={slug}>
              {slug}
            </option>
          ))}
        </Select>
      </Field>
    </div>
  );
}
