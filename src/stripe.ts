import { createHmac, timingSafeEqual } from "node:crypto";
import type { Attempt } from "./types.js";

/**
 * Checks a webhook's Stripe-Signature header, following Stripe's documented scheme: an HMAC-SHA256
 * of "timestamp.body" using the endpoint's signing secret. Rejecting unsigned events stops anyone
 * from feeding the guard fake declines to trigger blocks.
 *
 * @param rawBody the exact bytes received; a re-serialized body won't match
 * @param toleranceSeconds rejects old events, so a captured webhook can't be replayed later
 */
export function verifyStripeSignature(rawBody: string, header: string | undefined, secret: string, toleranceSeconds = 300, nowSeconds = Date.now() / 1000): boolean {
  if (!header || !secret) return false;
  let timestamp: string | undefined;
  const signatures: string[] = [];
  for (const part of header.split(",")) {
    const [key, value] = part.split("=", 2);
    if (key?.trim() === "t") timestamp = value;
    if (key?.trim() === "v1" && value) signatures.push(value.trim());
  }
  if (!timestamp || !/^\d+$/.test(timestamp) || signatures.length === 0) return false;
  if (Math.abs(nowSeconds - Number(timestamp)) > toleranceSeconds) return false;
  const expected = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`, "utf8").digest();
  return signatures.some((signature) => {
    const given = Buffer.from(signature, "hex");
    return given.length === expected.length && timingSafeEqual(given, expected);
  });
}

/**
 * Turns a Stripe charge.succeeded or charge.failed event into an {@link Attempt}. Returns
 * undefined for other events, and for charges that aren't card payments.
 *
 * Stripe doesn't send the customer's IP or session in charge events. Put them in the
 * PaymentIntent's metadata as "ip" and "session_id" when you create it, and they're picked up here.
 */
export function attemptFromStripeEvent(event: unknown): Attempt | undefined {
  const e = event as StripeEvent;
  if (e?.type !== "charge.succeeded" && e?.type !== "charge.failed") return undefined;
  const charge = e.data?.object;
  const card = charge?.payment_method_details?.card;
  if (!charge?.id || typeof charge.amount !== "number" || typeof charge.created !== "number" || !card) return undefined;
  const declined = e.type === "charge.failed";
  return {
    id: charge.id,
    timestamp: charge.created * 1000,
    amount: charge.amount,
    currency: charge.currency?.toUpperCase(),
    outcome: declined ? "declined" : "succeeded",
    declineCode: declined ? (charge.outcome?.reason ?? charge.failure_code ?? undefined) : undefined,
    cardFingerprint: card.fingerprint ?? undefined,
    bin: card.iin ?? undefined,
    last4: card.last4 ?? undefined,
    ip: charge.metadata?.ip ?? charge.metadata?.client_ip ?? undefined,
    email: charge.billing_details?.email ?? charge.receipt_email ?? undefined,
    customerId: typeof charge.customer === "string" ? charge.customer : undefined,
    sessionId: charge.metadata?.session_id ?? undefined,
  };
}

interface StripeEvent {
  type?: string;
  data?: {
    object?: {
      id?: string;
      amount?: number;
      currency?: string;
      created?: number;
      customer?: string | null;
      receipt_email?: string | null;
      failure_code?: string | null;
      outcome?: { reason?: string | null } | null;
      metadata?: Record<string, string>;
      billing_details?: { email?: string | null } | null;
      payment_method_details?: { card?: { fingerprint?: string | null; last4?: string | null; iin?: string | null } | null } | null;
    };
  };
}
