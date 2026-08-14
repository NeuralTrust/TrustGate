"use client";

import { Plus, X, TriangleAlert } from "lucide-react";
import { useRegistryTools, errorMessage } from "@/lib/hooks";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Badge } from "@/components/ui/misc";
import type { Registry, ToolkitEntry } from "@/lib/types";

export const TOOL_WILDCARD = "*";

export type ToolkitKind = "tool" | "prompt" | "resource";

const KINDS: ToolkitKind[] = ["tool", "prompt", "resource"];

const KIND_LABEL: Record<ToolkitKind, string> = {
  tool: "Tool",
  prompt: "Prompt",
  resource: "Resource",
};

const KIND_PLACEHOLDER: Record<ToolkitKind, string> = {
  tool: "tool name, or * for all tools",
  prompt: "prompt name, or * for all prompts",
  resource: "file:///docs/* or *",
};

/**
 * One toolkit entry as the form holds it. The API keeps the selector in a
 * per-kind field (tool / prompt / resource) with exactly one of them set, which
 * is awkward to edit, so the form carries (kind, value) and rebuilds the wire
 * shape on save.
 */
export interface ToolkitRow {
  registry_id: string;
  kind: ToolkitKind;
  value: string;
  expose_as: string;
}

export function toolkitRowsFrom(entries: ToolkitEntry[] | undefined): ToolkitRow[] {
  return (entries ?? []).map((entry) => {
    const kind: ToolkitKind = entry.prompt ? "prompt" : entry.resource ? "resource" : "tool";
    const value = (kind === "prompt" ? entry.prompt : kind === "resource" ? entry.resource : entry.tool) ?? "";
    return { registry_id: entry.registry_id, kind, value, expose_as: entry.expose_as ?? "" };
  });
}

export function buildToolkit(rows: ToolkitRow[]): ToolkitEntry[] {
  return rows.map((row) => {
    const entry: ToolkitEntry = { registry_id: row.registry_id };
    const value = row.value.trim();
    if (row.kind === "prompt") entry.prompt = value;
    else if (row.kind === "resource") entry.resource = value;
    else entry.tool = value;
    const alias = row.expose_as.trim();
    if (alias) entry.expose_as = alias;
    return entry;
  });
}

// Mirrors the toolkit rules the backend enforces (pkg/domain/consumer/toolkit.go)
// so the user sees the problem before the request goes out.
export function toolkitError(rows: ToolkitRow[]): string | null {
  const seen = new Set<string>();
  const aliases = new Map<string, ToolkitKind>();
  const plainNames: Record<ToolkitKind, Set<string>> = {
    tool: new Set(),
    prompt: new Set(),
    resource: new Set(),
  };

  for (const row of rows) {
    const value = row.value.trim();
    const alias = row.expose_as.trim();
    const kind = KIND_LABEL[row.kind].toLowerCase();

    if (!row.registry_id) return "Every entry needs a server.";
    if (!value) return `Every ${kind} entry needs a name or pattern.`;
    if (row.kind === "resource") {
      const star = value.indexOf("*");
      if (star >= 0 && star !== value.length - 1) {
        return `Resource pattern "${value}" is unsupported — only a trailing * is allowed.`;
      }
    }

    const key = `${row.registry_id}/${row.kind}/${value}`;
    if (seen.has(key)) return `Duplicate ${kind} "${value}" on the same server.`;
    seen.add(key);
    if (value !== TOOL_WILDCARD) plainNames[row.kind].add(value);

    if (alias) {
      if (row.kind === "resource") return "Resources are URI-addressed and cannot be renamed.";
      if (value === TOOL_WILDCARD) return `An entry exposing all ${kind}s cannot be renamed.`;
      if (aliases.has(alias)) return `Duplicate exposed name "${alias}".`;
      aliases.set(alias, row.kind);
    }
  }

  for (const [alias, kind] of aliases) {
    if (plainNames[kind].has(alias)) {
      return `Exposed name "${alias}" collides with another ${kind} of the same name.`;
    }
  }
  return null;
}

/**
 * fail_mode governs what the gateway does when one of the federated MCP servers
 * is unreachable: open serves what the reachable ones advertise, closed fails
 * the whole request.
 */
export function FailModeField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <Field label="When a server is unreachable" hint="fail_mode">
      <Select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="open">Skip it and serve the rest (open)</option>
        <option value="closed">Fail the request (closed)</option>
      </Select>
    </Field>
  );
}

export function ToolkitEditor({
  registries,
  rows,
  onChange,
}: {
  registries: Registry[];
  rows: ToolkitRow[];
  onChange: (rows: ToolkitRow[]) => void;
}) {
  // Entries can outlive their binding (a server detached after the toolkit was
  // saved). The backend rejects those, so they get their own card instead of
  // disappearing from the editor.
  const known = new Set(registries.map((r) => r.id));
  const orphanIds = [...new Set(rows.map((r) => r.registry_id).filter((id) => !known.has(id)))];

  function update(index: number, patch: Partial<ToolkitRow>) {
    onChange(rows.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }
  function remove(index: number) {
    onChange(rows.filter((_, i) => i !== index));
  }
  function add(registryId: string, kind: ToolkitKind, value = "") {
    onChange([...rows, { registry_id: registryId, kind, value, expose_as: "" }]);
  }

  return (
    <div className="flex flex-col gap-4">
      {registries.map((registry) => (
        <RegistryToolkitCard
          key={registry.id}
          registry={registry}
          rows={rows}
          onAdd={(kind, value) => add(registry.id, kind, value)}
          onUpdate={update}
          onRemove={remove}
        />
      ))}
      {orphanIds.map((id) => (
        <DetachedToolkitCard key={id} registryId={id} rows={rows} onUpdate={update} onRemove={remove} />
      ))}
    </div>
  );
}

// Row indices are the editor's identity for a row, so every card works on the
// flat list rather than a per-registry copy.
function indexedRows(rows: ToolkitRow[], registryId: string) {
  return rows.map((row, index) => ({ row, index })).filter((r) => r.row.registry_id === registryId);
}

function RegistryToolkitCard({
  registry,
  rows,
  onAdd,
  onUpdate,
  onRemove,
}: {
  registry: Registry;
  rows: ToolkitRow[];
  onAdd: (kind: ToolkitKind, value?: string) => void;
  onUpdate: (index: number, patch: Partial<ToolkitRow>) => void;
  onRemove: (index: number) => void;
}) {
  const { data: tools, isLoading, error } = useRegistryTools(registry.id);
  const mine = indexedRows(rows, registry.id);
  const listId = `mcp-tools-${registry.id}`;
  const taken = new Set(mine.filter((r) => r.row.kind === "tool").map((r) => r.row.value.trim()));
  const available = (tools ?? []).filter((t) => !taken.has(t.name));
  const hasWildcards = KINDS.every((kind) =>
    mine.some((r) => r.row.kind === kind && r.row.value.trim() === TOOL_WILDCARD),
  );

  function grantEverything() {
    for (const kind of KINDS) {
      if (!mine.some((r) => r.row.kind === kind && r.row.value.trim() === TOOL_WILDCARD)) {
        onAdd(kind, TOOL_WILDCARD);
      }
    }
  }

  return (
    <div className="rounded-(--radius) border border-border bg-surface-2/30 p-3.5 flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[13px] font-medium text-fg truncate">
            {registry.name} <span className="text-faint">({registry.provider})</span>
          </p>
          {error ? (
            <p className="text-[12px] text-warning mt-0.5 flex items-center gap-1.5">
              <TriangleAlert className="h-3.5 w-3.5 shrink-0" />
              Could not list tools ({errorMessage(error) ?? "unreachable"}) — add entries by name.
            </p>
          ) : (
            <p className="text-[12px] text-muted mt-0.5">
              {isLoading
                ? "Listing tools…"
                : `${tools?.length ?? 0} tool${tools?.length === 1 ? "" : "s"} advertised`}
            </p>
          )}
        </div>
        <Button variant="ghost" size="sm" onClick={grantEverything} disabled={hasWildcards}>
          Allow everything
        </Button>
      </div>

      {mine.length === 0 ? (
        <p className="text-[12px] text-faint">No entries — nothing from this server is exposed.</p>
      ) : (
        <div className="flex flex-col gap-1.5">
          {mine.map(({ row, index }) => (
            <ToolkitRowFields
              key={index}
              row={row}
              listId={listId}
              onUpdate={(patch) => onUpdate(index, patch)}
              onRemove={() => onRemove(index)}
            />
          ))}
        </div>
      )}

      <datalist id={listId}>
        <option value={TOOL_WILDCARD} />
        {(tools ?? []).map((tool) => (
          <option key={tool.name} value={tool.name}>
            {tool.description}
          </option>
        ))}
      </datalist>

      <div className="flex items-center gap-2">
        {available.length > 0 ? (
          <Select
            value=""
            className="flex-1 min-w-0"
            aria-label={`Add a tool from ${registry.name}`}
            onChange={(e) => {
              if (e.target.value) onAdd("tool", e.target.value);
              e.target.value = "";
            }}
          >
            <option value="">Add tool…</option>
            <option value={TOOL_WILDCARD}>All tools ({TOOL_WILDCARD})</option>
            {available.map((tool) => (
              <option key={tool.name} value={tool.name}>
                {tool.name}
              </option>
            ))}
          </Select>
        ) : (
          <Button variant="ghost" size="sm" onClick={() => onAdd("tool")}>
            <Plus className="h-4 w-4" />
            Add tool
          </Button>
        )}
        <Button variant="ghost" size="sm" onClick={() => onAdd("prompt")}>
          <Plus className="h-4 w-4" />
          Add prompt
        </Button>
        <Button variant="ghost" size="sm" onClick={() => onAdd("resource")}>
          <Plus className="h-4 w-4" />
          Add resource
        </Button>
      </div>
    </div>
  );
}

function ToolkitRowFields({
  row,
  listId,
  onUpdate,
  onRemove,
}: {
  row: ToolkitRow;
  listId?: string;
  onUpdate: (patch: Partial<ToolkitRow>) => void;
  onRemove: () => void;
}) {
  const isWildcard = row.value.trim() === TOOL_WILDCARD;
  // The API rejects an alias on resources and on wildcards, so switching into
  // either state drops it rather than saving something that cannot be stored.
  const aliasDisabled = row.kind === "resource" || isWildcard;

  return (
    <div className="flex items-center gap-2">
      <Select
        value={row.kind}
        className="w-30 shrink-0"
        aria-label="Entry kind"
        onChange={(e) => {
          const kind = e.target.value as ToolkitKind;
          onUpdate({ kind, expose_as: kind === "resource" ? "" : row.expose_as });
        }}
      >
        {KINDS.map((kind) => (
          <option key={kind} value={kind}>
            {KIND_LABEL[kind]}
          </option>
        ))}
      </Select>
      <Input
        value={row.value}
        list={row.kind === "tool" ? listId : undefined}
        placeholder={KIND_PLACEHOLDER[row.kind]}
        className="flex-1 min-w-0"
        aria-label={`${KIND_LABEL[row.kind]} name or pattern`}
        onChange={(e) => {
          const value = e.target.value;
          onUpdate({ value, expose_as: value.trim() === TOOL_WILDCARD ? "" : row.expose_as });
        }}
      />
      <Input
        value={row.expose_as}
        disabled={aliasDisabled}
        placeholder={aliasDisabled ? "—" : "expose as…"}
        className="w-40 shrink-0"
        aria-label="Exposed name"
        onChange={(e) => onUpdate({ expose_as: e.target.value })}
      />
      <Button variant="ghost" size="icon" onClick={onRemove} aria-label="Remove entry">
        <X className="h-4 w-4" />
      </Button>
    </div>
  );
}

function DetachedToolkitCard({
  registryId,
  rows,
  onUpdate,
  onRemove,
}: {
  registryId: string;
  rows: ToolkitRow[];
  onUpdate: (index: number, patch: Partial<ToolkitRow>) => void;
  onRemove: (index: number) => void;
}) {
  const mine = indexedRows(rows, registryId);
  return (
    <div className="rounded-(--radius) border border-warning/40 bg-warning/5 p-3.5 flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Badge tone="warning">Not attached</Badge>
        <span className="font-mono text-[12px] text-muted truncate">{registryId}</span>
      </div>
      <p className="text-[12px] text-muted">
        These entries point at a server that is no longer bound. Remove them, or re-attach the server
        before saving — the API rejects entries for unbound servers.
      </p>
      <div className="flex flex-col gap-1.5">
        {mine.map(({ row, index }) => (
          <ToolkitRowFields
            key={index}
            row={row}
            onUpdate={(patch) => onUpdate(index, patch)}
            onRemove={() => onRemove(index)}
          />
        ))}
      </div>
    </div>
  );
}
