"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Check, ChevronsUpDown, Plus, Layers } from "lucide-react";
import { setActiveGateway } from "@/app/actions";
import { api } from "@/lib/admin-client";
import { useGateway } from "./gateway-context";
import { useToast } from "@/components/ui/toast";
import { Dialog, DialogContent, DialogHeader, DialogBody, DialogFooter, DialogClose } from "@/components/ui/dialog";
import { Field, Input } from "@/components/ui/field";
import { Button } from "@/components/ui/button";
import type { Gateway } from "@/lib/types";
import { cn } from "@/lib/cn";

export function GatewaySwitcher() {
  const { gateways, active } = useGateway();
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [createOpen, setCreateOpen] = useState(false);

  function switchTo(id: string) {
    if (id === active.id) return;
    startTransition(async () => {
      await setActiveGateway(id);
      router.refresh();
    });
  }

  return (
    <>
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <button
            disabled={isPending}
            className="flex items-center gap-2 rounded-(--radius) border border-border bg-surface-2 h-9 pl-2.5 pr-2 text-[13px] text-fg hover:border-border-strong transition-colors outline-none focus-visible:ring-2 focus-visible:ring-accent/40 max-w-56"
          >
            <Layers className="h-4 w-4 text-accent shrink-0" />
            <span className="truncate font-medium">{active.slug}</span>
            <ChevronsUpDown className="h-3.5 w-3.5 text-faint shrink-0" />
          </button>
        </DropdownMenu.Trigger>

        <DropdownMenu.Portal>
          <DropdownMenu.Content
            align="end"
            sideOffset={6}
            className="z-50 w-64 rounded-(--radius) border border-border-strong bg-elevated p-1.5 shadow-xl shadow-black/40 animate-content"
          >
            <div className="px-2 py-1.5 text-[11px] font-medium uppercase tracking-wider text-faint">
              Gateways
            </div>
            <div className="max-h-64 overflow-y-auto">
              {gateways.map((g: Gateway) => (
                <DropdownMenu.Item
                  key={g.id}
                  onSelect={() => switchTo(g.id)}
                  className="flex items-center gap-2 rounded-(--radius-sm) px-2 py-1.5 text-[13px] text-fg outline-none data-[highlighted]:bg-surface-2 cursor-pointer"
                >
                  <span
                    className={cn(
                      "flex h-4 w-4 items-center justify-center",
                      g.id === active.id ? "text-accent" : "text-transparent",
                    )}
                  >
                    <Check className="h-3.5 w-3.5" />
                  </span>
                  <span className="truncate flex-1">{g.slug}</span>
                </DropdownMenu.Item>
              ))}
            </div>
            <DropdownMenu.Separator className="my-1.5 h-px bg-border" />
            <DropdownMenu.Item
              onSelect={(e) => {
                e.preventDefault();
                setCreateOpen(true);
              }}
              className="flex items-center gap-2 rounded-(--radius-sm) px-2 py-1.5 text-[13px] text-muted outline-none data-[highlighted]:bg-surface-2 data-[highlighted]:text-fg cursor-pointer"
            >
              <span className="flex h-4 w-4 items-center justify-center">
                <Plus className="h-3.5 w-3.5" />
              </span>
              Create gateway
            </DropdownMenu.Item>
          </DropdownMenu.Content>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>

      <CreateGatewayDialog open={createOpen} onOpenChange={setCreateOpen} />
    </>
  );
}

function CreateGatewayDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const router = useRouter();
  const { toast } = useToast();
  const [slug, setSlug] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    setSubmitting(true);
    try {
      const trimmed = slug.trim();
      const gw = await api.post<Gateway>("/v1/gateways", trimmed ? { slug: trimmed } : {});
      await setActiveGateway(gw.id);
      toast({ variant: "success", title: "Gateway created", description: gw.slug });
      onOpenChange(false);
      setSlug("");
      router.refresh();
    } catch (err) {
      toast({
        variant: "error",
        title: "Could not create gateway",
        description: err instanceof Error ? err.message : undefined,
      });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader title="Create gateway" description="A gateway is an isolated routing environment." />
        <DialogBody>
          <Field label="Slug" hint="Optional — auto-generated if empty">
            <Input
              autoFocus
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && submit()}
              placeholder="e.g. staging-gateway"
            />
          </Field>
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="primary" onClick={submit} loading={submitting}>
            Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
