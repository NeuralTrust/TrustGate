"use client";

import { useState } from "react";
import { Plus, Pencil, Trash2, KeyRound, Copy, Check } from "lucide-react";
import { api, gatewayScope } from "@/lib/admin-client";
import { useActiveGatewayId } from "@/components/layout/gateway-context";
import { useList, useInvalidate, errorMessage } from "@/lib/hooks";
import { useToast } from "@/components/ui/toast";
import { PageHeader, ConfirmDialog, useDisclosure } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Table, THead, TBody, TH, TR, TD } from "@/components/ui/table";
import { Badge, EmptyState, PageLoader, Dot } from "@/components/ui/misc";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogBody,
  DialogFooter,
  DialogClose,
} from "@/components/ui/dialog";
import { Field, Input, Select } from "@/components/ui/field";
import { Section, SwitchRow, Grid2, Divider } from "@/components/ui/form-bits";
import type { Auth, AuthType } from "@/lib/types";

export function AuthView() {
  const { data: auths, isLoading } = useList<Auth>("auths");
  const form = useDisclosure();
  const [editing, setEditing] = useState<Auth | null>(null);
  const [toDelete, setToDelete] = useState<Auth | null>(null);
  const [generatedKey, setGeneratedKey] = useState<{ name: string; key: string } | null>(null);

  return (
    <div>
      <PageHeader
        description="Auth credentials authenticate clients calling the proxy. API keys are generated server-side and shown only once."
        action={
          <Button
            variant="primary"
            onClick={() => {
              setEditing(null);
              form.onOpen();
            }}
          >
            <Plus className="h-4 w-4" />
            New auth
          </Button>
        }
      />

      {isLoading ? (
        <PageLoader />
      ) : !auths || auths.length === 0 ? (
        <EmptyState
          icon={<KeyRound className="h-5 w-5" />}
          title="No auth credentials"
          description="Create an API key, OAuth2 or mTLS credential for your consumers."
        />
      ) : (
        <Table>
          <THead>
            <TH>Name</TH>
            <TH>Type</TH>
            <TH>Status</TH>
            <TH className="text-right pr-4">Actions</TH>
          </THead>
          <TBody>
            {auths.map((a) => (
              <TR key={a.id}>
                <TD>
                  <span className="font-medium text-fg">{a.name}</span>
                </TD>
                <TD>
                  <Badge tone="accent">{a.type}</Badge>
                </TD>
                <TD>
                  <span className="inline-flex items-center gap-2 text-muted">
                    <Dot active={a.enabled} />
                    {a.enabled ? "Enabled" : "Disabled"}
                  </span>
                </TD>
                <TD className="text-right pr-4">
                  <div className="inline-flex gap-1">
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => {
                        setEditing(a);
                        form.onOpen();
                      }}
                      aria-label="Edit"
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button variant="ghost" size="icon" onClick={() => setToDelete(a)} aria-label="Delete">
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TD>
              </TR>
            ))}
          </TBody>
        </Table>
      )}

      {form.open && (
        <AuthFormDialog
          open={form.open}
          onOpenChange={form.setOpen}
          auth={editing}
          onKeyGenerated={(name, key) => setGeneratedKey({ name, key })}
        />
      )}

      <DeleteAuthDialog auth={toDelete} onClose={() => setToDelete(null)} />
      <ApiKeyDialog data={generatedKey} onClose={() => setGeneratedKey(null)} />
    </div>
  );
}

function DeleteAuthDialog({ auth, onClose }: { auth: Auth | null; onClose: () => void }) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  async function confirm() {
    if (!auth) return;
    setLoading(true);
    try {
      await api.del(`${gatewayScope(gatewayId)}/auths/${auth.id}`);
      toast({ variant: "success", title: "Auth deleted", description: auth.name });
      void invalidate("auths");
      onClose();
    } catch (err) {
      toast({ variant: "error", title: "Could not delete", description: errorMessage(err) });
    } finally {
      setLoading(false);
    }
  }

  return (
    <ConfirmDialog
      open={auth !== null}
      onOpenChange={(v) => !v && onClose()}
      title="Delete auth"
      description={`"${auth?.name}" will be permanently removed. Consumers using it will lose this credential.`}
      onConfirm={confirm}
      loading={loading}
    />
  );
}

export function ApiKeyDialog({
  data,
  onClose,
}: {
  data: { name: string; key: string } | null;
  onClose: () => void;
}) {
  const [copied, setCopied] = useState(false);

  function copy() {
    if (!data) return;
    void navigator.clipboard.writeText(data.key);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <Dialog open={data !== null} onOpenChange={(v) => !v && onClose()}>
      <DialogContent>
        <DialogHeader
          title="API key generated"
          description="Copy this key now. For security it will never be shown again."
        />
        <DialogBody>
          <div className="rounded-(--radius) border border-border-strong bg-surface-2 p-3 flex items-center gap-3">
            <code className="flex-1 font-mono text-[13px] text-accent break-all">{data?.key}</code>
            <Button variant="secondary" size="icon" onClick={copy} aria-label="Copy">
              {copied ? <Check className="h-4 w-4 text-success" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
        </DialogBody>
        <DialogFooter>
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function AuthFormDialog({
  open,
  onOpenChange,
  auth,
  onKeyGenerated,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  auth: Auth | null;
  onKeyGenerated: (name: string, key: string) => void;
}) {
  const gatewayId = useActiveGatewayId();
  const invalidate = useInvalidate();
  const { toast } = useToast();
  const isEdit = auth !== null;

  const o2 = auth?.config.oauth2;
  const oidc = auth?.config.oidc;

  const [name, setName] = useState(auth?.name ?? "");
  const [type, setType] = useState<AuthType>(auth?.type ?? "api_key");
  const [enabled, setEnabled] = useState(auth?.enabled ?? true);

  const [issuer, setIssuer] = useState(o2?.issuer ?? oidc?.issuer ?? "");
  const [audiences, setAudiences] = useState((o2?.audiences ?? oidc?.audiences ?? []).join(", "));
  const [scopes, setScopes] = useState((o2?.required_scopes ?? oidc?.required_scopes ?? []).join(", "));
  const [algorithms, setAlgorithms] = useState(
    (o2?.allowed_algorithms ?? oidc?.allowed_algorithms ?? []).join(", "),
  );
  const [subjectClaim, setSubjectClaim] = useState(o2?.subject_claim ?? oidc?.subject_claim ?? "");
  const [jwksUrl, setJwksUrl] = useState(o2?.jwks_url ?? oidc?.jwks_url ?? "");

  const [introspectionUrl, setIntrospectionUrl] = useState(o2?.introspection_url ?? "");
  const [sessionMode, setSessionMode] = useState(o2?.session_mode ?? false);
  const [userinfoUrl, setUserinfoUrl] = useState(o2?.userinfo_url ?? "");
  const [authorizeUrl, setAuthorizeUrl] = useState(o2?.authorize_url ?? "");
  const [tokenUrl, setTokenUrl] = useState(o2?.token_url ?? "");
  const [clientId, setClientId] = useState(o2?.client_id ?? "");
  const [clientSecret, setClientSecret] = useState("");

  const [publicKeys, setPublicKeys] = useState((oidc?.public_keys ?? []).join("\n\n"));

  const [caCert, setCaCert] = useState(auth?.config.mtls?.ca_cert ?? "");
  const [commonNames, setCommonNames] = useState((auth?.config.mtls?.allowed_common_names ?? []).join(", "));

  const [submitting, setSubmitting] = useState(false);

  const splitList = (v: string) => v.split(",").map((s) => s.trim()).filter(Boolean);
  const splitPems = (v: string) =>
    v.split(/(?=-----BEGIN)/).map((s) => s.trim()).filter(Boolean);

  async function submit() {
    if (!name.trim()) {
      toast({ variant: "error", title: "Name is required" });
      return;
    }

    const body: Record<string, unknown> = { name: name.trim(), type, enabled };
    if (type === "api_key") {
      body.config = {};
    } else if (type === "oauth2") {
      const oauth2: Record<string, unknown> = {
        issuer,
        audiences: splitList(audiences),
        jwks_url: jwksUrl || undefined,
        introspection_url: introspectionUrl || undefined,
        userinfo_url: userinfoUrl || undefined,
        authorize_url: authorizeUrl || undefined,
        token_url: tokenUrl || undefined,
        client_id: clientId || undefined,
        subject_claim: subjectClaim || undefined,
        required_scopes: splitList(scopes),
        allowed_algorithms: splitList(algorithms),
        session_mode: sessionMode,
      };
      if (clientSecret) oauth2.client_secret = clientSecret;
      body.config = { oauth2 };
    } else if (type === "oidc") {
      body.config = {
        oidc: {
          issuer,
          audiences: splitList(audiences),
          jwks_url: jwksUrl || undefined,
          public_keys: splitPems(publicKeys),
          required_scopes: splitList(scopes),
          allowed_algorithms: splitList(algorithms),
          subject_claim: subjectClaim || undefined,
        },
      };
    } else {
      body.config = {
        mtls: {
          ca_cert: caCert,
          allowed_common_names: splitList(commonNames),
        },
      };
    }

    setSubmitting(true);
    try {
      const base = `${gatewayScope(gatewayId)}/auths`;
      if (isEdit) {
        await api.put(`${base}/${auth.id}`, body);
        toast({ variant: "success", title: "Auth updated", description: name });
      } else {
        const created = await api.post<Auth>(base, body);
        toast({ variant: "success", title: "Auth created", description: name });
        if (created.type === "api_key" && created.api_key) {
          onKeyGenerated(created.name, created.api_key);
        }
      }
      void invalidate("auths");
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
        <DialogHeader title={isEdit ? "Edit auth" : "New auth"} />
        <DialogBody className="flex flex-col gap-5">
          <Grid2>
            <Field label="Name">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="frontend-key" />
            </Field>
            <Field label="Type">
              <Select
                value={type}
                onChange={(e) => setType(e.target.value as AuthType)}
                disabled={isEdit}
              >
                <option value="api_key">API key</option>
                <option value="oauth2">OAuth2</option>
                <option value="oidc">OIDC</option>
                <option value="mtls">mTLS</option>
              </Select>
            </Field>
          </Grid2>

          <SwitchRow label="Enabled" checked={enabled} onCheckedChange={setEnabled} />

          {type === "api_key" && !isEdit && (
            <p className="text-[12px] text-muted rounded-(--radius) border border-border bg-surface-2/40 px-3 py-2.5">
              The key is generated by the server and revealed once after creation.
            </p>
          )}

          {type === "oauth2" && (
            <>
              <Divider />
              <Section title="OAuth2">
                <Field label="Issuer">
                  <Input value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="https://issuer.example.com" />
                </Field>
                <Grid2>
                  <Field label="JWKS URL" hint="or introspection">
                    <Input value={jwksUrl} onChange={(e) => setJwksUrl(e.target.value)} />
                  </Field>
                  <Field label="Introspection URL" hint="or JWKS">
                    <Input value={introspectionUrl} onChange={(e) => setIntrospectionUrl(e.target.value)} />
                  </Field>
                </Grid2>
                <Grid2>
                  <Field label="Audiences" hint="comma-separated">
                    <Input value={audiences} onChange={(e) => setAudiences(e.target.value)} />
                  </Field>
                  <Field label="Required scopes" hint="comma-separated">
                    <Input value={scopes} onChange={(e) => setScopes(e.target.value)} />
                  </Field>
                </Grid2>
                <Grid2>
                  <Field label="Allowed algorithms" hint="comma-separated">
                    <Input value={algorithms} onChange={(e) => setAlgorithms(e.target.value)} placeholder="RS256" />
                  </Field>
                  <Field label="Subject claim" hint="optional">
                    <Input value={subjectClaim} onChange={(e) => setSubjectClaim(e.target.value)} placeholder="sub" />
                  </Field>
                </Grid2>
                <SwitchRow
                  label="Session mode"
                  description="Use the authorization-code flow with server-managed sessions."
                  checked={sessionMode}
                  onCheckedChange={setSessionMode}
                />
                {sessionMode && (
                  <>
                    <Grid2>
                      <Field label="Authorize URL">
                        <Input value={authorizeUrl} onChange={(e) => setAuthorizeUrl(e.target.value)} />
                      </Field>
                      <Field label="Token URL">
                        <Input value={tokenUrl} onChange={(e) => setTokenUrl(e.target.value)} />
                      </Field>
                    </Grid2>
                    <Field label="UserInfo URL" hint="optional">
                      <Input value={userinfoUrl} onChange={(e) => setUserinfoUrl(e.target.value)} />
                    </Field>
                    <Grid2>
                      <Field label="Client ID">
                        <Input value={clientId} onChange={(e) => setClientId(e.target.value)} />
                      </Field>
                      <Field label="Client secret" hint={isEdit ? "blank keeps current" : undefined}>
                        <Input
                          type="password"
                          value={clientSecret}
                          onChange={(e) => setClientSecret(e.target.value)}
                        />
                      </Field>
                    </Grid2>
                  </>
                )}
              </Section>
            </>
          )}

          {type === "oidc" && (
            <>
              <Divider />
              <Section title="OIDC">
                <Field label="Issuer">
                  <Input value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="https://issuer.example.com" />
                </Field>
                <Grid2>
                  <Field label="Audiences" hint="comma-separated">
                    <Input value={audiences} onChange={(e) => setAudiences(e.target.value)} />
                  </Field>
                  <Field label="Required scopes" hint="comma-separated">
                    <Input value={scopes} onChange={(e) => setScopes(e.target.value)} />
                  </Field>
                </Grid2>
                <Field label="JWKS URL" hint="or provide public keys below">
                  <Input value={jwksUrl} onChange={(e) => setJwksUrl(e.target.value)} />
                </Field>
                <Field label="Public keys (PEM)" hint="one or more, or use JWKS">
                  <textarea
                    value={publicKeys}
                    onChange={(e) => setPublicKeys(e.target.value)}
                    rows={5}
                    spellCheck={false}
                    className="w-full bg-surface-2 border border-border rounded-(--radius) px-3 py-2 text-[12px] font-mono text-fg placeholder:text-faint outline-none focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
                    placeholder="-----BEGIN PUBLIC KEY-----"
                  />
                </Field>
                <Grid2>
                  <Field label="Allowed algorithms" hint="comma-separated, no HMAC">
                    <Input value={algorithms} onChange={(e) => setAlgorithms(e.target.value)} placeholder="RS256, ES256" />
                  </Field>
                  <Field label="Subject claim" hint="optional">
                    <Input value={subjectClaim} onChange={(e) => setSubjectClaim(e.target.value)} placeholder="sub" />
                  </Field>
                </Grid2>
              </Section>
            </>
          )}

          {type === "mtls" && (
            <>
              <Divider />
              <Section title="mTLS">
                <Field label="CA certificate (PEM)">
                  <textarea
                    value={caCert}
                    onChange={(e) => setCaCert(e.target.value)}
                    rows={5}
                    spellCheck={false}
                    className="w-full bg-surface-2 border border-border rounded-(--radius) px-3 py-2 text-[12px] font-mono text-fg placeholder:text-faint outline-none focus:border-accent/70 focus:ring-2 focus:ring-accent/20"
                    placeholder="-----BEGIN CERTIFICATE-----"
                  />
                </Field>
                <Field label="Allowed common names" hint="comma-separated">
                  <Input value={commonNames} onChange={(e) => setCommonNames(e.target.value)} />
                </Field>
              </Section>
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="ghost">Cancel</Button>
          </DialogClose>
          <Button variant="primary" onClick={submit} loading={submitting}>
            {isEdit ? "Save changes" : "Create auth"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
