import { createHmac } from "node:crypto";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Redis } from "ioredis";
import { CardTestingGuard } from "../src/guard.js";
import { createGuardServer } from "../src/server.js";
import { attemptFromStripeEvent, verifyStripeSignature } from "../src/stripe.js";
import { readAttempts } from "../src/csv.js";
import { scan } from "../src/scan.js";
import { simulate } from "../src/simulate.js";
import { MemoryStore, RedisStore } from "../src/store.js";
import { main } from "../src/cli.js";

const SECRET = "whsec_test_secret";

function sign(body: string, timestamp = Math.floor(Date.now() / 1000), secret = SECRET): string {
  return `t=${timestamp},v1=${createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex")}`;
}

const chargeFailed = {
  id: "evt_1",
  type: "charge.failed",
  data: {
    object: {
      id: "ch_1", amount: 150, currency: "usd", created: 1_772_000_000, customer: "cus_9", receipt_email: null,
      failure_code: "card_declined", outcome: { reason: "incorrect_cvc" }, metadata: { ip: "203.0.113.5", session_id: "sess_1" },
      billing_details: { email: "a@b.com" }, payment_method_details: { card: { fingerprint: "fp_1", last4: "4242" } },
    },
  },
};

describe("Stripe", () => {
  it("accepts a correctly signed body and rejects anything else", () => {
    const body = JSON.stringify(chargeFailed);
    expect(verifyStripeSignature(body, sign(body), SECRET)).toBe(true);
    expect(verifyStripeSignature(body + " ", sign(body), SECRET)).toBe(false);
    expect(verifyStripeSignature(body, sign(body, undefined, "whsec_other"), SECRET)).toBe(false);
    expect(verifyStripeSignature(body, sign(body, Math.floor(Date.now() / 1000) - 3600), SECRET)).toBe(false);
    expect(verifyStripeSignature(body, undefined, SECRET)).toBe(false);
    expect(verifyStripeSignature(body, "t=abc,v1=zz", SECRET)).toBe(false);
    // Stripe may list several signatures while a secret is being rotated.
    expect(verifyStripeSignature(body, `${sign(body, undefined, "whsec_old")},v1=${sign(body).split("v1=")[1]}`, SECRET)).toBe(true);
  });

  it("maps a failed charge, including metadata the shop added", () => {
    expect(attemptFromStripeEvent(chargeFailed)).toEqual({
      id: "ch_1", timestamp: 1_772_000_000_000, amount: 150, currency: "USD", outcome: "declined", declineCode: "incorrect_cvc",
      cardFingerprint: "fp_1", bin: undefined, last4: "4242", ip: "203.0.113.5", email: "a@b.com", customerId: "cus_9", sessionId: "sess_1",
    });
  });

  it("ignores other events and malformed ones", () => {
    expect(attemptFromStripeEvent({ type: "customer.created", data: { object: {} } })).toBeUndefined();
    expect(attemptFromStripeEvent({ type: "charge.failed", data: { object: { id: "ch_2" } } })).toBeUndefined();
    expect(attemptFromStripeEvent(null)).toBeUndefined();
  });
});

describe("HTTP service", () => {
  const guard = new CardTestingGuard();
  const server = createGuardServer({ guard, apiKey: "test-key", stripeWebhookSecret: SECRET });
  let base = "";
  beforeAll(async () => {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

  const post = (path: string, body: unknown, headers: Record<string, string> = { authorization: "Bearer test-key" }) =>
    fetch(base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: typeof body === "string" ? body : JSON.stringify(body) });

  it("needs the API key", async () => {
    expect((await post("/v1/check", { amount: 100 }, {})).status).toBe(401);
    expect((await post("/v1/check", { amount: 100 }, { authorization: "Bearer wrong-key" })).status).toBe(401);
    expect((await fetch(`${base}/healthz`)).status).toBe(200);
  });

  it("checks, records, and reports status", async () => {
    const check = await post("/v1/check", { amount: 2500, ip: "5.5.5.5" });
    expect(await check.json()).toMatchObject({ action: "allow", mode: "normal" });
    const record = await post("/v1/attempts", { id: "x1", timestamp: Date.now(), amount: 2500, outcome: "declined", ip: "5.5.5.5" });
    expect(record.status).toBe(202);
    const status = await fetch(`${base}/v1/status`, { headers: { authorization: "Bearer test-key" } });
    expect(((await status.json()) as { recent: { declines: number } }).recent.declines).toBeGreaterThanOrEqual(1);
  });

  it("rejects bad input with a clear message", async () => {
    expect(await (await post("/v1/check", { amount: -1 })).json()).toEqual({ error: expect.stringContaining("amount") });
    expect((await post("/v1/check", "not json")).status).toBe(400);
    expect((await post("/v1/attempts", { id: "x", timestamp: Date.now(), amount: 1, outcome: "maybe" })).status).toBe(400);
    expect((await post("/v1/check", { amount: 1, ip: 42 })).status).toBe(400);
    expect((await post("/v1/check", "x".repeat(300 * 1024))).status).toBe(413);
  });

  it("takes signed Stripe webhooks and refuses unsigned ones", async () => {
    const body = JSON.stringify({ ...chargeFailed, data: { object: { ...chargeFailed.data.object, id: "ch_web", created: Math.floor(Date.now() / 1000) } } });
    expect((await post("/webhooks/stripe", body, { "stripe-signature": "t=1,v1=00" })).status).toBe(400);
    const accepted = await post("/webhooks/stripe", body, { "stripe-signature": sign(body) });
    expect(await accepted.json()).toEqual({ received: true, recorded: true });
  });
});

describe("Redis store", () => {
  const url = process.env.REDIS_URL;
  it.skipIf(!url)("gives the same decisions as the memory store", async () => {
    const redis = new Redis(url!);
    const prefix = `test:${Date.now()}:`;
    try {
      const attempts = simulate({ seed: 4, days: 3, perDay: 150, attacks: ["single_ip_burst", "bin_enumeration"] });
      let clock = 0;
      const memory = new CardTestingGuard({ now: () => clock, store: new MemoryStore(() => clock) });
      // Redis expires keys by real time, so this replays recent-looking timestamps.
      const shift = Date.now() - attempts.at(-1)!.timestamp;
      const live = new CardTestingGuard({ now: () => clock + shift, store: new RedisStore(redis, prefix) });
      let compared = 0;
      for (const a of attempts.slice(-600)) {
        clock = a.timestamp;
        const shifted = { ...a, timestamp: a.timestamp + shift };
        const [m, r] = [await memory.check({ ...a }), await live.check({ ...shifted })];
        expect(r.action).toBe(m.action);
        await memory.record(a);
        await live.record(shifted);
        compared++;
      }
      expect(compared).toBe(600);
    } finally {
      const keys = await redis.keys(`${prefix}*`);
      if (keys.length) await redis.del(...keys);
      redis.disconnect();
    }
  }, 60_000);
});

describe("CSV and scan", () => {
  it("reads custom columns, keeps good rows, and reports bad ones", () => {
    const csv = [
      "Charge ID,Created (UTC),Amount,Status,Decline Reason,Card Fingerprint,Customer Email",
      "ch_1,2026-03-02 12:00:00,1.50,Failed,incorrect_cvc,fp1,a@b.com",
      'ch_2,2026-03-02 12:01:00,"1,250.00",Paid,,fp2,"c@d.com"',
      "ch_3,not a date,1.00,Paid,,fp3,e@f.com",
      "ch_4,2026-03-02 12:02:00,abc,Paid,,fp4,g@h.com",
    ].join("\r\n");
    const { attempts, errors } = readAttempts(csv, {
      id: "Charge ID", timestamp: "Created (UTC)", amount: "Amount", outcome: "Status", declinedValues: ["failed"],
      declineCode: "Decline Reason", cardFingerprint: "Card Fingerprint", email: "Customer Email",
    });
    expect(attempts.map((a) => [a.id, a.amount, a.outcome])).toEqual([["ch_1", 150, "declined"], ["ch_2", 125000, "succeeded"]]);
    expect(attempts[0]!.timestamp).toBe(Date.UTC(2026, 2, 2, 12));
    expect(errors.map((e) => e.line)).toEqual([4, 5]);
  });

  it("names the missing column", () => {
    expect(() => readAttempts("when,how much\n2026-01-01,1\n")).toThrow(/column "timestamp" not found/);
  });

  it("finds the attacks in simulated traffic and none in quiet traffic", async () => {
    const attacked = await scan(simulate({ seed: 5, days: 5, perDay: 200, attacks: ["rotating_proxies"] }));
    expect(attacked.attackWindows.length).toBeGreaterThanOrEqual(1);
    const quiet = await scan(simulate({ seed: 5, days: 5, perDay: 200, attacks: [] }));
    expect(quiet.attackWindows).toEqual([]);
  });

  it("the command line simulates, scans, and exits 1 when it finds an attack", async () => {
    const dir = await import("node:os").then((os) => os.tmpdir());
    const file = `${dir}/ctg-${Date.now()}.csv`;
    const lines: string[] = [];
    expect(await main(["simulate", "--out", file, "--days", "5"], (s) => lines.push(s))).toBe(0);
    expect(await main(["scan", file], (s) => lines.push(s))).toBe(1);
    expect(lines.join("\n")).toMatch(/attack period/);
    expect(await main(["scan", `${dir}/missing.csv`], () => {}, () => {})).toBe(2);
    expect(await main(["nonsense"], () => {})).toBe(2);
  });
});
