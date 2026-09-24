// The console's only way to talk to the control plane.
//
// Everything goes through here so three rules hold in one place rather than at every call site:
// the session cookie is sent, the CSRF token rides on mutations, and a failure arrives as a
// typed error carrying the request id someone can quote.
//
// Responses are parsed with the schemas generated from proto/, not cast. A cast would make the
// contract a comment; fromJson makes a field the server renamed a runtime failure here rather
// than `undefined` rendered as blank three components away. That is the whole reason the console
// is worth calling the contract's second consumer.

import { fromJson } from "@bufbuild/protobuf";
import type { GenMessage } from "@bufbuild/protobuf/codegenv2";
import type { Message } from "@bufbuild/protobuf";

import {
  AccountSchema,
  AccessKeySchema,
  ListAccessKeysResponseSchema,
  type Account,
  type AccessKey,
} from "./gen/dariya/control/v1/account_pb";
import {
  PolicySchema,
  ListPoliciesResponseSchema,
  type Policy,
  type PolicyDocument,
} from "./gen/dariya/iam/v1/iam_pb";

const API = "/2026-09-01";

/** What the server sends when something goes wrong. Mirrors commonv1.Error. */
export class ApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly requestId: string,
    readonly status: number,
    readonly details?: Record<string, string>,
  ) {
    super(message);
    this.name = "ApiError";
  }

  /** Whether the person needs to sign in again, as opposed to not being allowed. */
  get isUnauthenticated(): boolean {
    return this.status === 401;
  }
}

/** The CSRF token from sign-in. Held in memory only: in storage it would outlive the tab, and in
 *  a cookie it would be sent automatically by exactly the forged request it exists to stop. */
let csrfToken: string | null = null;

export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
}

async function request(path: string, opts: RequestOptions = {}): Promise<Response> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {};

  if (opts.body !== undefined) headers["Content-Type"] = "application/json";

  // Only mutations need it, matching what the server enforces. Sending it on reads would work
  // and would also hide the day the server stopped requiring it.
  if (method !== "GET" && method !== "HEAD" && csrfToken) {
    headers["X-Dariya-Csrf"] = csrfToken;
  }

  const resp = await fetch(API + path, {
    method,
    headers,
    // Same-origin in dev via the Vite proxy, so the SameSite=Strict cookie is sent.
    credentials: "same-origin",
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });

  if (!resp.ok) throw await toApiError(resp);
  return resp;
}

async function toApiError(resp: Response): Promise<ApiError> {
  let code = "Unknown";
  let message = resp.statusText || "request failed";
  let requestId = resp.headers.get("X-Dariya-Request-Id") ?? "";
  let details: Record<string, string> | undefined;

  try {
    const body = await resp.json();
    if (typeof body?.code === "string") code = body.code;
    if (typeof body?.message === "string") message = body.message;
    if (typeof body?.request_id === "string") requestId = body.request_id;
    if (body?.details && typeof body.details === "object") details = body.details;
  } catch {
    // A non-JSON error body is itself worth surfacing rather than swallowing; the status and
    // whatever the header carried are all there is.
  }

  return new ApiError(code, message, requestId, resp.status, details);
}

/** parse runs a response through a generated schema, so a contract change fails here. */
async function parse<T extends Message>(resp: Response, schema: GenMessage<T>): Promise<T> {
  const json = await resp.json();
  try {
    return fromJson(schema, json, { ignoreUnknownFields: false });
  } catch (err) {
    throw new ApiError(
      "ContractMismatch",
      `the server sent a ${schema.typeName} this console does not understand: ${String(err)}`,
      resp.headers.get("X-Dariya-Request-Id") ?? "",
      resp.status,
    );
  }
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

export interface SignInResult {
  accountId: string;
  principalArn: string;
  csrfToken: string;
  expiresAtUnixMs: number;
}

export async function signIn(accessKeyId: string, secretAccessKey: string): Promise<SignInResult> {
  // Not through request(): sign-in is the one route with no session yet, and it is deliberately
  // the only unauthenticated one in the system.
  const resp = await fetch(`${API}/session/sign-in`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ accessKeyId, secretAccessKey }),
  });
  if (!resp.ok) throw await toApiError(resp);

  const result = (await resp.json()) as SignInResult;
  setCsrfToken(result.csrfToken);
  return result;
}

export async function whoAmI(): Promise<{ accountId: string; principalArn: string }> {
  const resp = await request("/session");
  return resp.json();
}

export async function signOut(): Promise<void> {
  await request("/session", { method: "DELETE" });
  setCsrfToken(null);
}

// ---------------------------------------------------------------------------
// Account and access keys
// ---------------------------------------------------------------------------

export async function getAccount(): Promise<Account> {
  return parse(await request("/account"), AccountSchema);
}

export async function listAccessKeys(): Promise<AccessKey[]> {
  const page = await parse(await request("/access-keys"), ListAccessKeysResponseSchema);
  return page.accessKeys;
}

/** The returned key carries the only copy of its secret that will ever exist. */
export async function createAccessKey(): Promise<AccessKey> {
  return parse(await request("/access-keys", { method: "POST", body: {} }), AccessKeySchema);
}

export async function deleteAccessKey(accessKeyId: string): Promise<void> {
  await request(`/access-keys/${encodeURIComponent(accessKeyId)}`, { method: "DELETE" });
}

// ---------------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------------

export async function listPolicies(): Promise<Policy[]> {
  const page = await parse(await request("/policies"), ListPoliciesResponseSchema);
  return page.policies;
}

export async function createPolicy(name: string, document: unknown): Promise<Policy> {
  return parse(
    await request(`/policies/${encodeURIComponent(name)}`, { method: "PUT", body: { document } }),
    PolicySchema,
  );
}

export async function deletePolicy(name: string): Promise<void> {
  await request(`/policies/${encodeURIComponent(name)}`, { method: "DELETE" });
}

export async function attachPolicy(name: string, principalArn: string): Promise<void> {
  await request(`/policies/${encodeURIComponent(name)}/attachments`, {
    method: "POST",
    body: { principalArn },
  });
}

export async function detachPolicy(name: string, principalArn: string): Promise<void> {
  await request(`/policies/${encodeURIComponent(name)}/detachments`, {
    method: "POST",
    body: { principalArn },
  });
}

export type { Account, AccessKey, Policy, PolicyDocument };
