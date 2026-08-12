"use client";

import { useState } from "react";
import { Send, FlaskConical, Activity, ChevronDown } from "lucide-react";
import { useAllList, usePlaygroundTrace, isNotFound, errorMessage } from "@/lib/hooks";
import { useGateway } from "@/components/layout/gateway-context";
import { useToast } from "@/components/ui/toast";
import { PageHeader } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { SwitchRow } from "@/components/ui/form-bits";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Badge, EmptyState, PageLoader, Mono } from "@/components/ui/misc";
import { cn } from "@/lib/cn";
import type { Consumer } from "@/lib/types";

// Header the proxy stamps every response with; the BFF route echoes it back.
const TRACE_ID_HEADER = "X-AG-Trace-Id";

interface ChatCompletionChunk {
  choices?: { delta?: { content?: string } }[];
}

interface ChatCompletion {
  choices?: { message?: { content?: string } }[];
}

function chunkDelta(payload: string): string {
  try {
    const obj = JSON.parse(payload) as ChatCompletionChunk;
    return obj.choices?.[0]?.delta?.content ?? "";
  } catch {
    return "";
  }
}

function messageContent(json: unknown): string {
  return (json as ChatCompletion).choices?.[0]?.message?.content ?? "";
}

export function PlaygroundView() {
  const { data: consumers, isLoading } = useAllList<Consumer>("consumers");
  const llmConsumers = (consumers ?? []).filter((c) => c.type === "LLM" && c.active);

  const { active: activeGateway } = useGateway();
  const { toast } = useToast();
  const [consumerId, setConsumerId] = useState("");
  const [model, setModel] = useState("");
  const [prompt, setPrompt] = useState("");
  const [stream, setStream] = useState(true);
  const [sending, setSending] = useState(false);
  const [response, setResponse] = useState("");
  const [errorText, setErrorText] = useState<string | null>(null);
  const [traceId, setTraceId] = useState("");

  const selected = llmConsumers.find((c) => c.id === consumerId) ?? llmConsumers[0];

  async function send() {
    if (!selected) {
      toast({ variant: "error", title: "Select a consumer" });
      return;
    }
    if (!prompt.trim()) {
      toast({ variant: "error", title: "Prompt is required" });
      return;
    }

    const body: Record<string, unknown> = {
      messages: [{ role: "user", content: prompt }],
      stream,
    };
    if (model.trim()) body.model = model.trim();

    setSending(true);
    setResponse("");
    setErrorText(null);
    setTraceId("");
    try {
      const res = await fetch(`/api/playground/${selected.slug}/v1/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-AG-Gateway-Slug": activeGateway.slug,
        },
        body: JSON.stringify(body),
      });

      // Failures are traced too, so this is read before the status check.
      setTraceId(res.headers.get(TRACE_ID_HEADER) ?? "");

      if (!res.ok) {
        const text = await res.text();
        setErrorText(text || `Request failed with status ${res.status}`);
        toast({ variant: "error", title: `Proxy returned ${res.status}` });
        return;
      }

      if (stream && res.body) {
        await consumeStream(res.body, (delta) => setResponse((prev) => prev + delta));
      } else {
        const json: unknown = await res.json();
        setResponse(messageContent(json) || JSON.stringify(json, null, 2));
      }
    } catch (err) {
      const message = errorMessage(err) ?? "Request failed";
      setErrorText(message);
      toast({ variant: "error", title: "Send failed", description: message });
    } finally {
      setSending(false);
    }
  }

  return (
    <div>
      <PageHeader description="Send a test request through the gateway proxy to one of your consumer routes and inspect the response. Requests authenticate automatically — no consumer credential needed." />

      {isLoading ? (
        <PageLoader />
      ) : llmConsumers.length === 0 ? (
        <EmptyState
          icon={<FlaskConical className="h-5 w-5" />}
          title="No LLM consumers yet"
          description="Create an active LLM consumer with a route, then come back to test it here."
        />
      ) : (
        <div className="flex flex-col gap-6">
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="flex flex-col gap-4 rounded-(--radius-lg) border border-border bg-surface/40 p-5">
              <Field label="Consumer">
                <Select value={selected?.id ?? ""} onChange={(e) => setConsumerId(e.target.value)}>
                  {llmConsumers.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name}
                    </option>
                  ))}
                </Select>
              </Field>
              {selected && (
                <p className="text-[12px] text-muted -mt-1">
                  Route <Mono>POST /{selected.slug}/v1/chat/completions</Mono>
                </p>
              )}

              <Field label="Model" hint="optional — blank uses the route default">
                <Input value={model} onChange={(e) => setModel(e.target.value)} placeholder="gpt-4o-mini" />
              </Field>

              <Field label="Prompt">
                <Textarea
                  rows={6}
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  placeholder="Ask the model something..."
                />
              </Field>

              <SwitchRow
                label="Stream"
                description="Render the response token by token over SSE."
                checked={stream}
                onCheckedChange={setStream}
              />

              <div>
                <Button variant="primary" onClick={send} loading={sending}>
                  <Send className="h-4 w-4" />
                  Send request
                </Button>
              </div>
            </div>

            <div className="flex flex-col rounded-(--radius-lg) border border-border bg-surface/40 p-5">
              <h4 className="text-[13px] font-semibold text-fg mb-3">Response</h4>
              {errorText ? (
                <pre className="flex-1 overflow-auto whitespace-pre-wrap break-words rounded-(--radius) border border-danger/25 bg-danger/5 p-3 font-mono text-[12px] text-danger">
                  {errorText}
                </pre>
              ) : response ? (
                <pre className="flex-1 overflow-auto whitespace-pre-wrap break-words rounded-(--radius) border border-border bg-surface-2/40 p-3 font-mono text-[12px] text-fg">
                  {response}
                </pre>
              ) : (
                <div className="flex flex-1 items-center justify-center rounded-(--radius) border border-dashed border-border p-6 text-center text-[13px] text-faint">
                  The model response will appear here.
                </div>
              )}
            </div>
          </div>

          {traceId !== "" && <TraceSection key={traceId} traceId={traceId} />}
        </div>
      )}
    </div>
  );
}

/**
 * The trace of the last request. Collapsed by default: the event is only
 * fetched when the user asks for it, since it lives behind a short TTL and the
 * request itself already showed the response.
 */
function TraceSection({ traceId }: { traceId: string }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-(--radius-lg) border border-border bg-surface/40">
      <div className="flex flex-wrap items-center gap-3 px-5 py-4">
        <Activity className="h-4 w-4 text-faint" />
        <h4 className="text-[13px] font-semibold text-fg">Trace</h4>
        <Mono>{traceId}</Mono>
        <Button variant="ghost" size="sm" className="ml-auto" onClick={() => setOpen((v) => !v)}>
          {open ? "Hide" : "Inspect"}
          <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")} />
        </Button>
      </div>
      {open && (
        <div className="border-t border-border p-5">
          <TraceBody traceId={traceId} />
        </div>
      )}
    </div>
  );
}

function TraceBody({ traceId }: { traceId: string }) {
  const { data: trace, isLoading, error } = usePlaygroundTrace(traceId);

  if (isLoading) return <PageLoader />;

  if (error) {
    return (
      <p className="text-[13px] text-muted">
        {isNotFound(error)
          ? "No trace stored for this request. Traces expire after a short TTL, and the gateway only records them when the playground trace store is enabled."
          : (errorMessage(error) ?? "Could not load the trace.")}
      </p>
    );
  }
  if (!trace) return null;

  const usage = trace.usage;
  const cost = trace.cost;

  return (
    <div className="flex flex-col gap-5">
      <div className="grid gap-x-6 gap-y-3 sm:grid-cols-3 lg:grid-cols-4">
        <Fact label="Status">
          <span className="tabular-nums">{trace.status.code}</span>
          {trace.status.outcome && <span className="text-muted"> · {trace.status.outcome}</span>}
        </Fact>
        <Fact label="Provider">{trace.request.provider || "—"}</Fact>
        <Fact label="Model">{trace.request.model || trace.request.requested_model || "—"}</Fact>
        <Fact label="Total latency">{ms(trace.latency.total_ms)}</Fact>
        <Fact label="Provider latency">{ms(trace.latency.provider_ms)}</Fact>
        <Fact label="Policies latency">{ms(trace.latency.policies_ms)}</Fact>
        <Fact label="Gateway latency">{ms(trace.latency.gateway_ms)}</Fact>
        <Fact label="Tokens">
          {usage ? `${usage.prompt_tokens} in · ${usage.completion_tokens} out` : "—"}
        </Fact>
        <Fact label="Cost">{cost ? `${usd(cost.total_usd)} ${cost.currency}` : "—"}</Fact>
        <Fact label="Streaming">{trace.response.streaming ? "yes" : "no"}</Fact>
        <Fact label="Consumer">{trace.consumer.name || trace.consumer.id || "—"}</Fact>
        <Fact label="Flagged">
          {trace.is_flagged ? <Badge tone="danger">flagged</Badge> : "no"}
        </Fact>
      </div>

      {trace.status.reason && (
        <p className="text-[12px] text-danger">Reason: {trace.status.reason}</p>
      )}

      {trace.policy_chain && trace.policy_chain.length > 0 && (
        <div>
          <h5 className="text-[12px] font-semibold text-fg mb-2">Policy chain</h5>
          <Table>
            <THead>
              <TH>Policy</TH>
              <TH>Stage</TH>
              <TH>Decision</TH>
              <TH>Latency</TH>
              <TH>Outcome</TH>
            </THead>
            <TBody>
              {trace.policy_chain.map((entry, i) => (
                <TR key={`${entry.name}-${entry.stage ?? ""}-${i}`}>
                  <TD>
                    <span className="text-fg">{entry.name}</span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted">{entry.stage || "—"}</span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted">{entry.decision || "—"}</span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted tabular-nums">{ms(entry.latency_ms)}</span>
                  </TD>
                  <TD>
                    <span className="inline-flex gap-1.5">
                      {entry.error && <Badge tone="danger">error</Badge>}
                      {entry.flagged && <Badge tone="warning">flagged</Badge>}
                      {!entry.error && !entry.flagged && <span className="text-faint">ok</span>}
                    </span>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}

      {trace.attempts && trace.attempts.length > 0 && (
        <div>
          <h5 className="text-[12px] font-semibold text-fg mb-2">Attempts</h5>
          <Table>
            <THead>
              <TH>#</TH>
              <TH>Provider</TH>
              <TH>Route</TH>
              <TH>Status</TH>
              <TH>Latency</TH>
              <TH>Kind</TH>
            </THead>
            <TBody>
              {trace.attempts.map((attempt, i) => (
                <TR key={`${attempt.attempt}-${i}`}>
                  <TD>
                    <span className="tabular-nums text-muted">{attempt.attempt}</span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted">{attempt.provider || "—"}</span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted">
                      {attempt.route || attempt.route_model || "—"}
                    </span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted tabular-nums">{attempt.status_code}</span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted tabular-nums">{ms(attempt.latency_ms)}</span>
                  </TD>
                  <TD>
                    <span className="text-[12px] text-muted">
                      {attempt.fallback ? "fallback" : attempt.pinned ? "pinned" : "primary"}
                    </span>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}

      <details>
        <summary className="cursor-pointer text-[12px] text-muted hover:text-fg">Raw event</summary>
        <pre className="mt-2 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-(--radius) border border-border bg-surface-2/40 p-3 font-mono text-[11px] text-muted">
          {JSON.stringify(trace, null, 2)}
        </pre>
      </details>
    </div>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] uppercase tracking-wider text-faint">{label}</span>
      <span className="text-[13px] text-fg">{children}</span>
    </div>
  );
}

function ms(value: number): string {
  return `${value} ms`;
}

// Per-request costs are fractions of a cent, so a fixed 6-decimal form keeps
// them readable instead of collapsing to 0.00.
function usd(value: number): string {
  return value === 0 ? "0" : value.toFixed(6);
}

// consumeStream reads an OpenAI-style SSE chat completion stream, invoking onDelta
// with each content fragment until the [DONE] sentinel.
async function consumeStream(
  body: ReadableStream<Uint8Array>,
  onDelta: (delta: string) => void,
): Promise<void> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let newlineIndex: number;
    while ((newlineIndex = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, newlineIndex).trim();
      buffer = buffer.slice(newlineIndex + 1);
      if (!line.startsWith("data:")) continue;
      const payload = line.slice(5).trim();
      if (payload === "[DONE]") return;
      const delta = chunkDelta(payload);
      if (delta) onDelta(delta);
    }
  }
}
