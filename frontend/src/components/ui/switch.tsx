"use client";

import * as SwitchPrimitive from "@radix-ui/react-switch";
import { cn } from "@/lib/cn";

export function Switch({
  checked,
  onCheckedChange,
  disabled,
}: {
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <SwitchPrimitive.Root
      checked={checked}
      onCheckedChange={onCheckedChange}
      disabled={disabled}
      className={cn(
        "relative h-5 w-9 rounded-full border border-border-strong transition-colors outline-none focus-visible:ring-2 focus-visible:ring-accent/40 disabled:opacity-50",
        checked ? "bg-accent/80" : "bg-surface-2",
      )}
    >
      <SwitchPrimitive.Thumb
        className={cn(
          "block h-3.5 w-3.5 rounded-full bg-fg transition-transform translate-x-0.5 will-change-transform",
          checked && "translate-x-4",
        )}
      />
    </SwitchPrimitive.Root>
  );
}
