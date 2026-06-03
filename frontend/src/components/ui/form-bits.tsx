"use client";

import { cn } from "@/lib/cn";
import { Switch } from "@/components/ui/switch";

export function Section({
  title,
  description,
  children,
  className,
}: {
  title?: string;
  description?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-3", className)}>
      {title && (
        <div>
          <h4 className="text-[13px] font-semibold text-fg">{title}</h4>
          {description && <p className="text-[12px] text-muted mt-0.5">{description}</p>}
        </div>
      )}
      {children}
    </div>
  );
}

export function SwitchRow({
  label,
  description,
  checked,
  onCheckedChange,
}: {
  label: string;
  description?: string;
  checked: boolean;
  onCheckedChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-(--radius) border border-border bg-surface-2/40 px-3.5 py-2.5">
      <div>
        <p className="text-[13px] font-medium text-fg">{label}</p>
        {description && <p className="text-[12px] text-muted mt-0.5">{description}</p>}
      </div>
      <Switch checked={checked} onCheckedChange={onCheckedChange} />
    </div>
  );
}

export function Divider() {
  return <div className="h-px bg-border my-1" />;
}

export function Grid2({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-2 gap-3">{children}</div>;
}
