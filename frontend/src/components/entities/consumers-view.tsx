"use client";

import { useState } from "react";
import { Plus, Trash2, Users, Settings2 } from "lucide-react";
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
import { Field, Input, Select } from "@/components/ui/field";
import { Grid2 } from "@/components/ui/form-bits";
import { ConsumerDetail } from "./consumer-detail";
import type { Consumer, ConsumerType, Algorithm } from "@/lib/types";

const ALGORITHMS: Algorithm[] = [
  "round-robin",
  "random",
  "weighted-round-robin",
  "least-connections",
  "semantic",
];

export function ConsumersView() {
  const { data: consumers, isLoading } = useList<Consumer>("consumers");
  const create = useDisclosure();
  const [detail, setDetail] = useState<Consumer | null>(null);
  const [toDelete, setToDelete] = useState<Consumer | null>(null);

  return (
    <div>
      <PageHeader
        description="Consumers are routed endpoints. Each binds a path to registries, auth credentials and policies."
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
            <TH>Path</TH>
            <TH>Type</TH>
            <TH>Algorithm</TH>
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
                  <Mono>{c.path}</Mono>
                </TD>
                <TD>
                  <Badge>{c.type}</Badge>
                </TD>
                <TD>
                  <span className="text-muted text-[12px]">{c.algorithm}</span>
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

      {create.open && <CreateConsumerDialog open={create.open} onOpenChange={create.setOpen} />}
      {detail && (
        <ConsumerDetail
          consumerId={detail.id}
          open={detail !== null}
          onOpenChange={(v) => !v && setDetail(null)}
        />
      )}
      <DeleteConsumerDialog consumer={toDelete} onClose={() => setToDelete(null)} />
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

function CreateConsumerDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();

  const [name, setName] = useState("");
  const [path, setPath] = useState("/v1/chat/completions");
  const [type, setType] = useState<ConsumerType>("LLM");
  const [algorithm, setAlgorithm] = useState<Algorithm>("round-robin");
  const [embProvider, setEmbProvider] = useState("openai");
  const [embModel, setEmbModel] = useState("text-embedding-3-small");
  const [embApiKey, setEmbApiKey] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function submit() {
    if (!name.trim() || !path.trim()) {
      toast({ variant: "error", title: "Name and path are required" });
      return;
    }
    const body: Record<string, unknown> = {
      name: name.trim(),
      path: path.trim(),
      type,
      algorithm,
    };
    if (algorithm === "semantic") {
      body.embedding_config = {
        provider: embProvider,
        model: embModel,
        ...(embApiKey ? { auth: { api_key: embApiKey } } : {}),
      };
    }

    setSubmitting(true);
    try {
      await api.post(`${gatewayScope(gatewayId)}/consumers`, body);
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
        <DialogHeader
          title="New consumer"
          description="Bind registries, auth and policies after creating the consumer."
        />
        <DialogBody className="flex flex-col gap-4">
          <Field label="Name">
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="chat-prod" />
          </Field>
          <Field label="Path" hint="route match">
            <Input value={path} onChange={(e) => setPath(e.target.value)} />
          </Field>
          <Grid2>
            <Field label="Type">
              <Select value={type} onChange={(e) => setType(e.target.value as ConsumerType)}>
                <option value="LLM">LLM</option>
                <option value="MCP">MCP</option>
                <option value="A2A">A2A</option>
              </Select>
            </Field>
            <Field label="Algorithm">
              <Select value={algorithm} onChange={(e) => setAlgorithm(e.target.value as Algorithm)}>
                {ALGORITHMS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </Select>
            </Field>
          </Grid2>

          {algorithm === "semantic" && (
            <div className="rounded-(--radius) border border-border bg-surface-2/40 p-3 flex flex-col gap-3">
              <p className="text-[12px] text-muted">Semantic routing requires an embedding model.</p>
              <Grid2>
                <Field label="Embedding provider">
                  <Input value={embProvider} onChange={(e) => setEmbProvider(e.target.value)} />
                </Field>
                <Field label="Embedding model">
                  <Input value={embModel} onChange={(e) => setEmbModel(e.target.value)} />
                </Field>
              </Grid2>
              <Field label="Embedding API key" hint="optional">
                <Input type="password" value={embApiKey} onChange={(e) => setEmbApiKey(e.target.value)} />
              </Field>
            </div>
          )}
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
