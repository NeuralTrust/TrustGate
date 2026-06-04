"use client";

import { forwardRef } from "react";
import { cn } from "@/lib/cn";

const inputBase =
  "w-full bg-surface-2 border border-border rounded-(--radius) px-3 text-sm text-fg placeholder:text-faint transition-colors outline-none focus:border-accent/70 focus:ring-2 focus:ring-accent/20 disabled:opacity-50";

export const Input = forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input ref={ref} className={cn(inputBase, "h-9.5", className)} {...props} />
  ),
);
Input.displayName = "Input";

export const Textarea = forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...props }, ref) => (
  <textarea
    ref={ref}
    className={cn(inputBase, "py-2 min-h-20 font-mono text-[13px] leading-relaxed", className)}
    {...props}
  />
));
Textarea.displayName = "Textarea";

export const Select = forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(({ className, children, ...props }, ref) => (
  <select
    ref={ref}
    className={cn(inputBase, "h-9.5 appearance-none cursor-pointer pr-9 bg-no-repeat", className)}
    style={{
      backgroundImage:
        "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%238a8a94' stroke-width='2'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E\")",
      backgroundPosition: "right 10px center",
    }}
    {...props}
  >
    {children}
  </select>
));
Select.displayName = "Select";

export function Label({
  className,
  children,
  hint,
  ...props
}: React.LabelHTMLAttributes<HTMLLabelElement> & { hint?: string }) {
  return (
    <label className={cn("flex items-center justify-between text-[13px] font-medium text-fg/90", className)} {...props}>
      <span>{children}</span>
      {hint && <span className="text-faint font-normal">{hint}</span>}
    </label>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
  className,
}: {
  label?: string;
  hint?: string;
  error?: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      {label && <Label hint={hint}>{label}</Label>}
      {children}
      {error && <p className="text-[12px] text-danger">{error}</p>}
    </div>
  );
}
