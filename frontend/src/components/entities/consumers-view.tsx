"use client";

import { useState } from "react";
import { Plus, Trash2, Users, Settings2, ChevronDown } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useList, useInvalidate, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader, ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Badge, EmptyState, PageLoader, Dot, Mono } from "@/components/ui/misc";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Field, Input, Select, Label } from "@/components/ui/field";
import { cn } from "@/lib/cn";
import { ConsumerDetail } from "./consumer-detail";
import { ApiKeyDialog } from "./auth-view";
import type { Consumer, ConsumerType, Registry, Auth } from "@/lib/types";

const CREATE_AUTH = "__create__";

const PROTOCOLS: { value: ConsumerType; label: string }[] = [
  { value: "LLM", label: "LLM" },
  { value: "MCP", label: "MCP" },
  { value: "A2A", label: "A2A" },
];

// The proxy route slug is generated server-side on creation; the UI surfaces it
// but does not derive it from the name.
function routingLabel(c: Consumer): string {
  if (c.routing_mode === "role_based") return "role-based";
  if (c.fallback?.enabled) return "fallback";
  if (c.lb_config?.enabled) return c.lb_config.algorithm ?? "round-robin";
  return "single";
}

export function ConsumersView() {
  const { data: consumers, isLoading } = useList<Consumer>("consumers");
  const create = useDisclosure();
  const [detail, setDetail] = useState<Consumer | null>(null);
  const [toDelete, setToDelete] = useState<Consumer | null>(null);
  const [generatedKey, setGeneratedKey] = useState<{ name: string; key: string } | null>(null);

  return (
    <div>
      <PageHeader
        description="Consumers are routed endpoints. Each exposes a slug-based route backed by registries, auth credentials and policies."
        action={
          <Button variant="primary" onClick={create.onOpen}>
            <Plus className="h-4 w-4" />
            New consumer
          </Button>
        }
      />

      {isLoading ? (
        <PageLoader />
      ) : !consumers || consumers.length === 0 ? (
        <EmptyState
          icon={<Users className="h-5 w-5" />}
          title="No consumers yet"
          description="Create a consumer to expose a route backed by your registries."
          action={
            <Button variant="primary" onClick={create.onOpen}>
              <Plus className="h-4 w-4" />
              New consumer
            </Button>
          }
        />
      ) : (
        <Table>
          <THead>
            <TH>Name</TH>
            <TH>Slug</TH>
            <TH>Type</TH>
            <TH>Routing</TH>
            <TH>Bindings</TH>
            <TH>Status</TH>
            <TH className="text-right pr-4">Actions</TH>
          </THead>
          <TBody>
            {consumers.map((c) => (
              <TR key={c.id}>
                <TD>
                  <span className="font-medium text-fg">{c.name}</span>
                </TD>
                <TD>
                  <Mono>{c.slug}</Mono>
                </TD>
                <TD>
                  <Badge>{c.type}</Badge>
                </TD>
                <TD>
                  <span className="text-muted text-[12px]">{routingLabel(c)}</span>
                </TD>
                <TD>
                  <span className="text-[12px] text-muted">
                    {c.registry_ids.length}r · {c.auth_ids.length}a
                  </span>
                </TD>
                <TD>
                  <span className="inline-flex items-center gap-2 text-muted">
                    <Dot active={c.active} />
                    {c.active ? "Active" : "Inactive"}
                  </span>
                </TD>
                <TD className="text-right pr-4">
                  <div className="inline-flex gap-1">
                    <Button variant="ghost" size="icon" onClick={() => setDetail(c)} aria-label="Configure">
                      <Settings2 className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => setToDelete(c)} aria-label="Delete">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {create.open && (
        <CreateConsumerDialog
          open={create.open}
          onOpenChange={create.setOpen}
          onKeyGenerated={(name, key) => setGeneratedKey({ name, key })}
        />
      )}
      {detail && (
        <ConsumerDetail
          consumerId={detail.id}
          open={detail !== null}
          onOpenChange={(v) => !v && setDetail(null)}
        />
      )}
      <DeleteConsumerDialog consumer={toDelete} onClose={() => setToDelete(null)} />
      <ApiKeyDialog data={generatedKey} onClose={() => setGeneratedKey(null)} />
    </div>
  );
}

function DeleteConsumerDialog({ consumer, onClose }: { consumer: Consumer | null; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  async function confirm() {
    if (!consumer) return;
    setLoading(true);
    try {
      await api.del(`${gatewayScope(gatewayId)}/consumers/${consumer.id}`);
      toast({ variant: "success", title: "Consumer deleted", description: consumer.name });
      void invalidate("consumers");
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Could not delete", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ConfirmDialog
      open={consumer !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Delete consumer"
      description={`"${consumer?.name}" and all its bindings will be permanently removed.`}
      onConfirm={confirm}
      loading={loading}
    />
  );
}

function CreateConsumerDialog({
  open,
  onOpenChange,
  onKeyGenerated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  onKeyGenerated: (name: string, key: string) => void;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const { data: registries } = useList<Registry>("registries");
  const { data: auths } = useList<Auth>("auths");

  const [name, setName] = useState("");
  const [type, setType] = useState<ConsumerType>("LLM");
  const [registryId, setRegistryId] = useState("");
  const [authOpen, setAuthOpen] = useState(false);
  const [authChoice, setAuthChoice] = useState(CREATE_AUTH);
  const [authName, setAuthName] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    if (!name.trim()) {
      toast({ variant: "error", title: "Name is required" });
      return;
    }
    const body: Record<string, unknown> = {
      name: name.trim(),
      type,
    };

    setSubmitting(true);
    try {
      const base = gatewayScope(gatewayId);
      const consumer = await api.post<Consumer>(`${base}/consumers`, body);
      const consumerBase = `${base}/consumers/${consumer.id}`;

      if (registryId) {
        await api.post(`${consumerBase}/registries/${registryId}`);
      }

      if (authChoice === CREATE_AUTH) {
        const keyName = authName.trim() || `${name.trim()}-key`;
        const auth = await api.post<Auth>(`${base}/auths`, {
          name: keyName,
          type: "api_key",
          enabled: true,
          config: {},
        });
        await api.post(`${consumerBase}/auths/${auth.id}`);
        void invalidate("auths");
        if (auth.api_key) onKeyGenerated(auth.name, auth.api_key);
      } else if (authChoice) {
        await api.post(`${consumerBase}/auths/${authChoice}`);
      }

      toast({ variant: "success", title: "Consumer created", description: name });
      void invalidate("consumers");
      onOpenChange(false);
    } catch (err) {
      toast({ variant: "error", title: "Save failed", description: errorMessage(err) });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader title="New consumer" />
        <DialogBody className="flex flex-col gap-5">
          <div className="flex flex-col gap-1.5">
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="chat-prod" />
            <p className="text-[12px] text-muted">
              A unique route slug is generated automatically on creation.
            </p>
          </div>

          <div className="flex flex-col gap-2">
            <Label>Protocol</Label>
            <div className="flex items-center gap-7 pt-0.5">
              {PROTOCOLS.map((p) => {
                const active = type === p.value;
                return (
                  <button
                    key={p.value}
                    type="button"
                    onClick={() => setType(p.value)}
                    className="group flex items-center gap-2.5"
                  >
                    <span
                      className={cn(
                        "flex h-4.5 w-4.5 items-center justify-center rounded-full border-2 transition-colors",
                        active ? "border-accent" : "border-border-strong group-hover:border-fg/40",
                      )}
                    >
                      {active && <span className="h-2 w-2 rounded-full bg-accent" />}
                    </span>
                    <span className={cn("text-[13px]", active ? "text-fg" : "text-muted")}>{p.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <Label>Target backend</Label>
            <Select value={registryId} onChange={(e) => setRegistryId(e.target.value)}>
              <option value="">Select a backend</option>
              {(registries ?? []).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} ({r.provider})
                </option>
              ))}
            </Select>
            <p className="text-[12px] text-muted">
              Start with one backend. Add fallbacks or load balancing after creation.
            </p>
          </div>

          <div className="flex flex-col gap-2">
            <Label>Authentication</Label>
            <div className="rounded-(--radius) border border-border bg-surface-2/40 p-3.5 flex flex-col gap-2.5">
              <div className="flex flex-col gap-0.5">
                <p className="text-[13px] text-fg">
                  {authChoice === CREATE_AUTH
                    ? "Defaults to API key"
                    : authChoice === ""
                      ? "No authentication"
                      : "Uses an existing credential"}
                </p>
                <p className="text-[12px] text-muted">
                  {authChoice === CREATE_AUTH
                    ? "A key is generated on creation. Change the auth method anytime."
                    : "Change the auth method anytime."}
                </p>
              </div>
              <button
                type="button"
                onClick={() => setAuthOpen((v) => !v)}
                className="inline-flex items-center gap-1.5 self-start text-[12px] font-medium text-accent transition-colors hover:text-accent/80"
              >
                <Settings2 className="h-3.5 w-3.5" />
                Change auth method
                <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", authOpen && "rotate-180")} />
              </button>

              {authOpen && (
                <div className="flex flex-col gap-3 border-t border-border pt-3">
                  <Field label="Auth method">
                    <Select value={authChoice} onChange={(e) => setAuthChoice(e.target.value)}>
                      <option value={CREATE_AUTH}>Generate new API key</option>
                      <option value="">No authentication</option>
                      {(auths ?? []).map((a) => (
                        <option key={a.id} value={a.id}>
                          {a.name} ({a.type})
                        </option>
                      ))}
                    </Select>
                  </Field>
                  {authChoice === CREATE_AUTH && (
                    <Field label="API key name" hint="optional">
                      <Input
                        value={authName}
                        onChange={(e) => setAuthName(e.target.value)}
                        placeholder={`${name.trim() || "consumer"}-key`}
                      />
                    </Field>
                  )}
                </div>
              )}
            </div>
          </div>
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="primary" onClick={submit} loading={submitting}>
            Create consumer
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
