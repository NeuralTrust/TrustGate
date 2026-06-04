export class AdminApiError extends Error {
  code: string;
  status: number;

  constructor(status: number, code: string, message?: string) {
    super(message || code);
    this.name = "AdminApiError";
    this.status = status;
    this.code = code;
  }
}

async function parseError(res: Response): Promise<AdminApiError> {
  let code = `http_${res.status}`;
  let message: string | undefined;
  try {
    const data = (await res.json()) as { error?: string; message?: string };
    if (data.error) code = data.error;
    message = data.message;
  } catch {
    // body not JSON; keep defaults
  }
  return new AdminApiError(res.status, code, message);
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api/admin${path}`, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    throw await parseError(res);
  }

  if (res.status === 204) {
    return undefined as T;
  }
  const text = await res.text();
  if (!text) return undefined as T;
  return JSON.parse(text) as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  put: <T>(path: string, body?: unknown) => request<T>("PUT", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

export function gatewayScope(gatewayId: string): string {
  return `/v1/gateways/${gatewayId}`;
}
