"use client";

import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Label } from "@/components/ui/field";
import { SwitchRow } from "@/components/ui/form-bits";
import { JsonEditor } from "@/components/ui/json-editor";
import type { PolicyCatalogField } from "@/lib/types";

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function strv(v: unknown): string {
  return v === undefined || v === null ? "" : String(v);
}

function setKey(obj: Obj, key: string, value: unknown): Obj {
  const next = { ...obj };
  if (value === undefined) delete next[key];
  else next[key] = value;
  return next;
}

function defaultValue(field: PolicyCatalogField): unknown {
  switch (field.type) {
    case "boolean":
      return field.default ?? false;
    case "integer":
    case "number":
    case "string":
    case "duration":
    case "enum":
      return field.default;
    case "object": {
      if (field.fields && field.fields.length > 0) {
        const o = buildFields(field.fields);
        return Object.keys(o).length > 0 ? o : undefined;
      }
      return undefined;
    }
    case "array":
      return Array.isArray(field.default) ? field.default : undefined;
    case "map":
      return undefined;
    default: {
      const _exhaustive: never = field.type;
      return _exhaustive;
    }
  }
}

function buildFields(fields: PolicyCatalogField[]): Obj {
  const out: Obj = {};
  for (const f of fields) {
    const v = defaultValue(f);
    if (v !== undefined) out[f.key] = v;
  }
  return out;
}

function blankValue(field: PolicyCatalogField): unknown {
  const d = defaultValue(field);
  if (d !== undefined) return d;
  switch (field.type) {
    case "boolean":
      return false;
    case "object":
      return field.fields && field.fields.length > 0 ? buildFields(field.fields) : {};
    case "array":
      return [];
    case "map":
      return {};
    default:
      return "";
  }
}

/** buildSettingsDefaults produces the initial settings object for a plugin schema. */
export function buildSettingsDefaults(fields: PolicyCatalogField[]): Obj {
  return buildFields(fields);
}

function coerceScalar(field: PolicyCatalogField, v: unknown): unknown {
  switch (field.type) {
    case "boolean":
      return typeof v === "boolean" ? v : v === "true";
    case "integer": {
      const n = typeof v === "number" ? v : parseInt(String(v), 10);
      return Number.isFinite(n) ? Math.trunc(n) : undefined;
    }
    case "number": {
      const n = typeof v === "number" ? v : parseFloat(String(v));
      return Number.isFinite(n) ? n : undefined;
    }
    default: {
      const s = strv(v).trim();
      return s === "" ? undefined : s;
    }
  }
}

function coerceValue(field: PolicyCatalogField, v: unknown): unknown {
  switch (field.type) {
    case "string":
    case "duration":
    case "enum":
    case "integer":
    case "number":
    case "boolean":
      return coerceScalar(field, v);
    case "object": {
      if (field.fields && field.fields.length > 0) {
        const o = coerceFields(field.fields, isObj(v) ? v : {});
        return Object.keys(o).length > 0 ? o : undefined;
      }
      if (typeof v === "string") {
        const t = v.trim();
        return t === "" ? undefined : JSON.parse(t);
      }
      return isObj(v) ? v : undefined;
    }
    case "array": {
      if (!Array.isArray(v)) return undefined;
      const item = field.item as PolicyCatalogField | undefined;
      const arr = item ? v.map((x) => coerceValue(item, x)).filter((x) => x !== undefined) : v;
      return arr.length > 0 ? arr : undefined;
    }
    case "map": {
      if (!isObj(v)) return undefined;
      const valField = field.value as PolicyCatalogField | undefined;
      const out: Obj = {};
      for (const [k, val] of Object.entries(v)) {
        if (k.trim() === "") continue;
        const cv = valField ? coerceValue(valField, val) : val;
        if (cv !== undefined) out[k] = cv;
      }
      return Object.keys(out).length > 0 ? out : undefined;
    }
    default: {
      const _exhaustive: never = field.type;
      return _exhaustive;
    }
  }
}

function coerceFields(fields: PolicyCatalogField[], value: Obj): Obj {
  const out: Obj = {};
  for (const f of fields) {
    const cv = coerceValue(f, value[f.key]);
    if (cv !== undefined) out[f.key] = cv;
  }
  return out;
}

/**
 * coerceSettings walks the plugin schema and turns raw form state into the typed
 * settings payload the API expects, dropping empty values. It may throw if a
 * free-form JSON object field contains invalid JSON.
 */
export function coerceSettings(fields: PolicyCatalogField[], value: Obj): Obj {
  return coerceFields(fields, value);
}

function Described({ field, children }: { field: PolicyCatalogField; children: React.ReactNode }) {
  return (
    <Field label={field.label} hint={field.required ? "required" : undefined}>
      {children}
      {field.description && <p className="text-[11px] text-faint leading-snug">{field.description}</p>}
    </Field>
  );
}

function FieldControl({
  field,
  value,
  onChange,
}: {
  field: PolicyCatalogField;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  switch (field.type) {
    case "boolean":
      return (
        <SwitchRow
          label={field.label}
          description={field.description}
          checked={value === true}
          onCheckedChange={onChange}
        />
      );
    case "enum":
      return (
        <Described field={field}>
          <Select value={strv(value)} onChange={(e) => onChange(e.target.value || undefined)}>
            {!field.required && <option value="">—</option>}
            {(field.enum ?? []).map((o) => (
              <option key={o.value} value={o.value}>
                {o.label || o.value}
              </option>
            ))}
          </Select>
        </Described>
      );
    case "integer":
    case "number":
      return (
        <Described field={field}>
          <Input
            type="number"
            step={field.type === "integer" ? "1" : "any"}
            value={strv(value)}
            placeholder={field.default != null ? String(field.default) : undefined}
            onChange={(e) => onChange(e.target.value === "" ? undefined : e.target.value)}
          />
        </Described>
      );
    case "string":
    case "duration":
      return (
        <Described field={field}>
          <Input
            value={strv(value)}
            placeholder={field.default != null ? String(field.default) : undefined}
            onChange={(e) => onChange(e.target.value === "" ? undefined : e.target.value)}
          />
        </Described>
      );
    case "object":
      return <ObjectControl field={field} value={value} onChange={onChange} />;
    case "array":
      return (
        <ArrayControl field={field} value={Array.isArray(value) ? value : []} onChange={onChange} />
      );
    case "map":
      return <MapControl field={field} value={isObj(value) ? value : {}} onChange={onChange} />;
    default: {
      const _exhaustive: never = field.type;
      return _exhaustive;
    }
  }
}

function ObjectControl({
  field,
  value,
  onChange,
}: {
  field: PolicyCatalogField;
  value: unknown;
  onChange: (v: unknown) => void;
}) {
  if (field.fields && field.fields.length > 0) {
    const obj = isObj(value) ? value : {};
    return (
      <div className="flex flex-col gap-1.5">
        <Label hint={field.required ? "required" : undefined}>{field.label}</Label>
        {field.description && <p className="text-[11px] text-faint leading-snug">{field.description}</p>}
        <div className="rounded-(--radius) border border-border bg-surface-2/30 p-3 flex flex-col gap-4">
          {field.fields.map((f) => (
            <FieldControl
              key={f.key}
              field={f}
              value={obj[f.key]}
              onChange={(v) => onChange(setKey(obj, f.key, v))}
            />
          ))}
        </div>
      </div>
    );
  }
  const text = typeof value === "string" ? value : value ? JSON.stringify(value, null, 2) : "";
  return (
    <Described field={field}>
      <JsonEditor value={text} onChange={(v) => onChange(v === "" ? undefined : v)} rows={5} />
    </Described>
  );
}

function ItemBody({
  field,
  value,
  onChange,
  title,
}: {
  field: PolicyCatalogField;
  value: unknown;
  onChange: (v: unknown) => void;
  title?: string;
}) {
  if (field.type === "object" && field.fields && field.fields.length > 0) {
    const obj = isObj(value) ? value : {};
    return (
      <div className="flex flex-col gap-3">
        {title && (
          <p className="text-[11px] font-medium uppercase tracking-wider text-faint">{title}</p>
        )}
        {field.fields.map((f) => (
          <FieldControl
            key={f.key}
            field={f}
            value={obj[f.key]}
            onChange={(v) => onChange(setKey(obj, f.key, v))}
          />
        ))}
      </div>
    );
  }
  return <FieldControl field={field} value={value} onChange={onChange} />;
}

function ArrayControl({
  field,
  value,
  onChange,
}: {
  field: PolicyCatalogField;
  value: unknown[];
  onChange: (v: unknown) => void;
}) {
  const item = field.item as PolicyCatalogField | undefined;

  function update(i: number, v: unknown) {
    const next = [...value];
    next[i] = v;
    onChange(next);
  }
  function remove(i: number) {
    const next = value.filter((_, idx) => idx !== i);
    onChange(next.length > 0 ? next : undefined);
  }
  function add() {
    onChange([...value, item ? blankValue(item) : ""]);
  }

  const itemLabel = item?.label ?? "Item";

  return (
    <div className="flex flex-col gap-2">
      <Label hint={field.required ? "required" : undefined}>{field.label}</Label>
      {field.description && <p className="text-[11px] text-faint leading-snug -mt-1">{field.description}</p>}
      <div className="flex flex-col gap-2">
        {value.length === 0 && <p className="text-[12px] text-faint">No entries.</p>}
        {value.map((it, i) => (
          <div
            key={i}
            className="rounded-(--radius) border border-border bg-surface-2/30 p-2.5 flex gap-2 items-start"
          >
            <div className="flex-1 min-w-0">
              {item ? (
                <ItemBody
                  field={item}
                  value={it}
                  onChange={(v) => update(i, v)}
                  title={`${itemLabel} ${i + 1}`}
                />
              ) : (
                <Input value={strv(it)} onChange={(e) => update(i, e.target.value)} />
              )}
            </div>
            <Button variant="ghost" size="icon" onClick={() => remove(i)} aria-label="Remove entry">
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        ))}
      </div>
      <div>
        <Button variant="secondary" size="sm" onClick={add}>
          <Plus className="h-4 w-4" />
          Add {itemLabel.toLowerCase()}
        </Button>
      </div>
    </div>
  );
}

function MapControl({
  field,
  value,
  onChange,
}: {
  field: PolicyCatalogField;
  value: Obj;
  onChange: (v: unknown) => void;
}) {
  const valField = field.value as PolicyCatalogField | undefined;
  const keyOptions = field.key_options ?? [];
  const [newKey, setNewKey] = useState("");

  const usedKeys = new Set(Object.keys(value));
  const availableKeys = keyOptions.filter((k) => !usedKeys.has(k));

  function setEntry(k: string, v: unknown) {
    onChange(setKey(value, k, v));
  }
  function removeKey(k: string) {
    const next = { ...value };
    delete next[k];
    onChange(Object.keys(next).length > 0 ? next : undefined);
  }
  function addKey(k: string) {
    const key = k.trim();
    if (key === "" || usedKeys.has(key)) return;
    onChange({ ...value, [key]: valField ? blankValue(valField) : "" });
    setNewKey("");
  }

  const entries = Object.entries(value);

  return (
    <div className="flex flex-col gap-2">
      <Label hint={field.required ? "required" : undefined}>{field.label}</Label>
      {field.description && <p className="text-[11px] text-faint leading-snug -mt-1">{field.description}</p>}
      <div className="flex flex-col gap-2">
        {entries.length === 0 && <p className="text-[12px] text-faint">No entries.</p>}
        {entries.map(([k, v]) => (
          <div
            key={k}
            className="rounded-(--radius) border border-border bg-surface-2/30 p-2.5 flex flex-col gap-2"
          >
            <div className="flex items-center justify-between gap-2">
              <code className="text-[12px] text-accent">{k}</code>
              <Button variant="ghost" size="icon" onClick={() => removeKey(k)} aria-label="Remove entry">
                <Trash2 className="h-4 w-4" />
              </Button>
            </div>
            {valField ? (
              <ItemBody field={valField} value={v} onChange={(nv) => setEntry(k, nv)} />
            ) : (
              <Input value={strv(v)} onChange={(e) => setEntry(k, e.target.value)} />
            )}
          </div>
        ))}
      </div>
      <div className="flex gap-2">
        {availableKeys.length > 0 ? (
          <Select value={newKey} onChange={(e) => setNewKey(e.target.value)} className="flex-1">
            <option value="">Select key…</option>
            {availableKeys.map((k) => (
              <option key={k} value={k}>
                {k}
              </option>
            ))}
          </Select>
        ) : keyOptions.length === 0 ? (
          <Input
            value={newKey}
            onChange={(e) => setNewKey(e.target.value)}
            placeholder="New key"
            className="flex-1"
          />
        ) : (
          <p className="text-[12px] text-faint flex-1 self-center">All keys added.</p>
        )}
        <Button variant="secondary" size="sm" onClick={() => addKey(newKey)} disabled={newKey.trim() === ""}>
          <Plus className="h-4 w-4" />
          Add
        </Button>
      </div>
    </div>
  );
}

/** PolicySettingsForm renders a plugin's settings schema as a typed form. */
export function PolicySettingsForm({
  fields,
  value,
  onChange,
}: {
  fields: PolicyCatalogField[];
  value: Obj;
  onChange: (v: Obj) => void;
}) {
  if (!fields || fields.length === 0) {
    return <p className="text-[12px] text-muted">This plugin has no configurable settings.</p>;
  }
  return (
    <div className="flex flex-col gap-4">
      {fields.map((f) => (
        <FieldControl
          key={f.key}
          field={f}
          value={value[f.key]}
          onChange={(v) => onChange(setKey(value, f.key, v))}
        />
      ))}
    </div>
  );
}
