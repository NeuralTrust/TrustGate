"use client";

import { useState } from "react";
import { Textarea } from "@/components/ui/field";

export function JsonEditor({
  value,
  onChange,
  onValidityChange,
  rows = 8,
}: {
  value: string;
  onChange: (v: string) => void;
  onValidityChange?: (valid: boolean) => void;
  rows?: number;
}) {
  const [error, setError] = useState<string | null>(null);

  function handle(next: string) {
    onChange(next);
    if (next.trim() === "") {
      setError(null);
      onValidityChange?.(true);
      return;
    }
    try {
      JSON.parse(next);
      setError(null);
      onValidityChange?.(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Invalid JSON");
      onValidityChange?.(false);
    }
  }

  return (
    <div className="flex flex-col gap-1.5">
      <Textarea
        value={value}
        onChange={(e) => handle(e.target.value)}
        rows={rows}
        spellCheck={false}
        className={error ? "border-danger/60 focus:border-danger/60 focus:ring-danger/20" : ""}
      />
      {error && <p className="text-[12px] text-danger font-mono">{error}</p>}
    </div>
  );
}

export function parseJsonObject(value: string): Record<string, unknown> | undefined {
  if (value.trim() === "") return undefined;
  const parsed = JSON.parse(value);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("Expected a JSON object");
  }
  return parsed as Record<string, unknown>;
}
