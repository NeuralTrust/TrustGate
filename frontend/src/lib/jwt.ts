import "server-only";
import { SignJWT } from "jose";

const TOKEN_TTL_SECONDS = 60 * 60;
const PLAYGROUND_TOKEN_TTL_SECONDS = 5 * 60;

let cachedToken: { value: string; expiresAt: number } | null = null;

function secretKey(): Uint8Array {
  const secret = process.env.SERVER_SECRET_KEY;
  if (!secret) {
    throw new Error(
      "SERVER_SECRET_KEY is not set. The dashboard BFF needs it to sign admin API tokens.",
    );
  }
  return new TextEncoder().encode(secret);
}

export async function mintAdminToken(): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.expiresAt - now > 30) {
    return cachedToken.value;
  }

  const claims: Record<string, string> = {};
  const tenantId =
    process.env.ADMIN_TENANT_ID?.trim() ||
    process.env.ADMIN_TEAM_ID?.trim();
  if (tenantId) claims.tenant_id = tenantId;
  if (process.env.ADMIN_USER_ID) claims.user_id = process.env.ADMIN_USER_ID;

  const expiresAt = now + TOKEN_TTL_SECONDS;
  const value = await new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(expiresAt)
    .sign(secretKey());

  cachedToken = { value, expiresAt };
  return value;
}

// Mints a short-lived token that lets the playground exercise a consumer route
// without that consumer's credentials. The backend playground identity resolver
// requires purpose "playground" and a matching consumer slug; the admin API
// rejects purpose-tagged tokens, so this token grants nothing else.
export async function mintPlaygroundToken(consumerSlug: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);

  const claims: Record<string, string> = {
    purpose: "playground",
    consumer_slug: consumerSlug,
  };
  if (process.env.ADMIN_USER_ID) claims.user_id = process.env.ADMIN_USER_ID;

  return new SignJWT(claims)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt(now)
    .setExpirationTime(now + PLAYGROUND_TOKEN_TTL_SECONDS)
    .sign(secretKey());
}
