"use client";

import { useState } from "react";
import { Send, FlaskConical } from "lucide-react";
import { useList, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { SwitchRow } from "@/components/ui/form-bits";
import { EmptyState, PageLoader, Mono } from "@/components/ui/misc";
import type { Consumer } from "@/lib/types";

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
  const { data: consumers, isLoading } = useList<Consumer>("consumers");
  const llmConsumers = (consumers ?? []).filter((c) => c.type === "LLM" && c.active);

  const { toast } = useToast();
  const [consumerId, setConsumerId] = useState("");
  const [model, setModel] = useState("");
  const [prompt, setPrompt] = useState("");
  const [stream, setStream] = useState(true);
  const [sending, setSending] = useState(false);
  const [response, setResponse] = useState("");
  const [errorText, setErrorText] = useState<string | null>(null);

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
    try {
      const res = await fetch(`/api/playground/${selected.slug}/v1/chat/completions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

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
      )}
    </div>
  );
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
