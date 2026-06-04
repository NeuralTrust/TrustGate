"use client";

import { cn } from "@/lib/cn";

export function Table({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <div className="overflow-hidden rounded-(--radius-lg) border border-border bg-surface">
      <table className={cn("w-full text-sm", className)}>{children}</table>
    </div>
  );
}

export function THead({ children }: { children: React.ReactNode }) {
  return (
    <thead className="bg-surface-2/50 border-b border-border">
      <tr className="text-left">{children}</tr>
    </thead>
  );
}

export function TH({ children, className }: { children?: React.ReactNode; className?: string }) {
  return (
    <th
      className={cn(
        "px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider text-faint",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function TBody({ children }: { children: React.ReactNode }) {
  return <tbody className="divide-y divide-border">{children}</tbody>;
}

export function TR({
  children,
  className,
  onClick,
}: {
  children: React.ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        "transition-colors",
        onClick && "cursor-pointer hover:bg-surface-2/60",
        className,
      )}
    >
      {children}
    </tr>
  );
}

export function TD({ children, className }: { children?: React.ReactNode; className?: string }) {
  return <td className={cn("px-4 py-3 text-[13px] text-fg/90 align-middle", className)}>{children}</td>;
}
