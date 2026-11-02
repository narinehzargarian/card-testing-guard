import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { CardTestingGuard } from "./guard.js";
import { attemptFromStripeEvent, verifyStripeSignature } from "./stripe.js";
import type { Attempt, CheckRequest } from "./types.js";

export interface ServerOptions {
  guard: CardTestingGuard;
  /** Required for /v1 endpoints unless `allowNoAuth` is set. Sent as "Authorization: Bearer KEY". */
  apiKey?: string;
  allowNoAuth?: boolean;
  /** Turns on POST /webhooks/stripe. */
  stripeWebhookSecret?: string;
  log?: (message: string) => void;
}

const MAX_BODY = 256 * 1024;

/**
 * A small HTTP service around the guard, for shops whose checkout isn't written in JavaScript.
 *
 *   POST /v1/check           before charging; returns allow, challenge, or block, with reasons
 *   POST /v1/attempts        after the processor answers
 *   POST /webhooks/stripe    Stripe charge events, as an alternative to /v1/attempts
 *   GET  /v1/status          shop-wide mode and recent counts
 *   GET  /healthz
 */
export function createGuardServer(options: ServerOptions): Server {
  if (!options.apiKey && !options.allowNoAuth) {
    throw new Error("an apiKey is required; set allowNoAuth only for local testing");
  }
  const log = options.log ?? (() => {});
  return createServer((req, res) => {
    handle(req, res, options).catch((error: unknown) => {
      log(`error: ${(error as Error).message}`);
      if (!res.headersSent) send(res, 500, { error: "internal error" });
    });
  });
}

async function handle(req: IncomingMessage, res: ServerResponse, options: ServerOptions): Promise<void> {
  const path = new URL(req.url ?? "/", "http://localhost").pathname;
  if (req.method === "GET" && path === "/healthz") return send(res, 200, { status: "ok" });

  if (req.method === "POST" && path === "/webhooks/stripe") {
    if (!options.stripeWebhookSecret) return send(res, 404, { error: "Stripe webhooks are not configured" });
    const body = await readBody(req);
    if (body === undefined) return send(res, 413, { error: "body too large" });
    const signature = req.headers["stripe-signature"];
    if (!verifyStripeSignature(body, Array.isArray(signature) ? signature[0] : signature, options.stripeWebhookSecret)) {
      return send(res, 400, { error: "invalid signature" });
    }
    const attempt = attemptFromStripeEvent(parseJson(body));
    if (attempt) await options.guard.record(attempt);
    // Stripe retries anything but a 2xx, so other event types are acknowledged and ignored.
    return send(res, 200, { received: true, recorded: attempt !== undefined });
  }

  if (!path.startsWith("/v1/")) return send(res, 404, { error: "not found" });
  if (!authorized(req, options)) return send(res, 401, { error: "missing or wrong API key" });

  if (req.method === "GET" && path === "/v1/status") return send(res, 200, await options.guard.status());
  if (req.method !== "POST") return send(res, 405, { error: "method not allowed" });

  const body = await readBody(req);
  if (body === undefined) return send(res, 413, { error: "body too large" });
  const json = parseJson(body);
  if (json === undefined || typeof json !== "object" || json === null) return send(res, 400, { error: "body must be a JSON object" });

  if (path === "/v1/check") {
    const problem = validateCheck(json as Record<string, unknown>);
    if (problem) return send(res, 400, { error: problem });
    return send(res, 200, await options.guard.check(json as CheckRequest));
  }
  if (path === "/v1/attempts") {
    const problem = validateAttempt(json as Record<string, unknown>);
    if (problem) return send(res, 400, { error: problem });
    await options.guard.record(json as Attempt);
    return send(res, 202, { recorded: true });
  }
  return send(res, 404, { error: "not found" });
}

function authorized(req: IncomingMessage, options: ServerOptions): boolean {
  if (!options.apiKey) return options.allowNoAuth === true;
  const header = req.headers.authorization ?? "";
  const given = Buffer.from(header.startsWith("Bearer ") ? header.slice(7) : "");
  const expected = Buffer.from(options.apiKey);
  return given.length === expected.length && timingSafeEqual(given, expected);
}

const STRING_FIELDS = ["ip", "email", "customerId", "sessionId", "cardFingerprint", "bin", "last4", "declineCode", "currency"];

function validateCheck(body: Record<string, unknown>): string | undefined {
  if (!isAmount(body.amount)) return "amount must be a non-negative whole number of minor units, such as cents";
  if (body.timestamp !== undefined && !isTimestamp(body.timestamp)) return "timestamp must be milliseconds since the epoch";
  return validateStrings(body);
}

function validateAttempt(body: Record<string, unknown>): string | undefined {
  if (typeof body.id !== "string" || body.id.length === 0 || body.id.length > 200) return "id must be a non-empty string";
  if (!isTimestamp(body.timestamp)) return "timestamp must be milliseconds since the epoch";
  if (!isAmount(body.amount)) return "amount must be a non-negative whole number of minor units, such as cents";
  if (body.outcome !== "succeeded" && body.outcome !== "declined") return 'outcome must be "succeeded" or "declined"';
  return validateStrings(body);
}

function validateStrings(body: Record<string, unknown>): string | undefined {
  for (const field of STRING_FIELDS) {
    const value = body[field];
    if (value !== undefined && (typeof value !== "string" || value.length > 320)) return `${field} must be a string of at most 320 characters`;
  }
  return undefined;
}

function isAmount(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isTimestamp(value: unknown): boolean {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function readBody(req: IncomingMessage): Promise<string | undefined> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let tooLarge = false;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        tooLarge = true;
      } else {
        chunks.push(chunk);
      }
    });
    req.on("end", () => resolve(tooLarge ? undefined : Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function parseJson(body: string): unknown {
  try {
    return JSON.parse(body);
  } catch {
    return undefined;
  }
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(text) });
  res.end(text);
}
