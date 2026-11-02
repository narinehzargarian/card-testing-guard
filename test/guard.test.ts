import { describe, expect, it } from "vitest";
import { CardTestingGuard, normalizeEmail } from "../src/guard.js";
import { resolveConfig } from "../src/config.js";
import type { Alert, Attempt } from "../src/types.js";

const T0 = Date.UTC(2026, 2, 2, 12);
const MIN = 60_000;

function setup() {
  let clock = T0;
  const alerts: Alert[] = [];
  const guard = new CardTestingGuard({ now: () => clock, onAlert: (a) => alerts.push(a) });
  return { guard, alerts, at: (t: number) => { clock = t; } };
}

let n = 0;
function attempt(overrides: Partial<Attempt>): Attempt {
  return { id: `t${++n}`, timestamp: T0, amount: 2500, outcome: "succeeded", ...overrides };
}

describe("per-identity rules", () => {
  it("allows an ordinary customer", async () => {
    const { guard } = setup();
    await guard.record(attempt({ ip: "1.1.1.1", cardFingerprint: "c1" }));
    const decision = await guard.check({ amount: 2500, ip: "1.1.1.1", cardFingerprint: "c1", timestamp: T0 + MIN });
    expect(decision).toEqual({ action: "allow", reasons: [], mode: "normal" });
  });

  it("challenges a third card and blocks a fifth from one IP within an hour", async () => {
    const { guard } = setup();
    for (let i = 1; i <= 2; i++) await guard.record(attempt({ ip: "2.2.2.2", cardFingerprint: `c${i}`, timestamp: T0 + i * MIN }));
    expect((await guard.check({ amount: 2500, ip: "2.2.2.2", cardFingerprint: "c2", timestamp: T0 + 5 * MIN })).action).toBe("allow");
    const third = await guard.check({ amount: 2500, ip: "2.2.2.2", cardFingerprint: "c3", timestamp: T0 + 5 * MIN });
    expect(third.action).toBe("challenge");
    expect(third.reasons[0]).toMatchObject({ rule: "distinct_cards", subject: "ip:2.2.2.2", value: 3, threshold: 3 });
    for (let i = 3; i <= 4; i++) await guard.record(attempt({ ip: "2.2.2.2", cardFingerprint: `c${i}`, timestamp: T0 + 6 * MIN }));
    expect((await guard.check({ amount: 2500, ip: "2.2.2.2", cardFingerprint: "c5", timestamp: T0 + 7 * MIN })).action).toBe("block");
    // An hour later, the cards have aged out.
    expect((await guard.check({ amount: 2500, ip: "2.2.2.2", cardFingerprint: "c6", timestamp: T0 + 70 * MIN })).action).toBe("allow");
  });

  it("counts declines and probing declines within 10 minutes", async () => {
    const { guard } = setup();
    await guard.record(attempt({ email: "a@x.com", outcome: "declined", declineCode: "incorrect_cvc" }));
    await guard.record(attempt({ email: "a@x.com", outcome: "declined", declineCode: "incorrect_cvc" }));
    const decision = await guard.check({ amount: 2500, email: "a@x.com", timestamp: T0 + MIN });
    expect(decision.action).toBe("challenge");
    expect(decision.reasons.map((r) => r.rule)).toEqual(["probing_declines"]);
    expect((await guard.check({ amount: 2500, email: "a@x.com", timestamp: T0 + 11 * MIN })).action).toBe("allow");
  });

  it("treats email variations as one person", async () => {
    expect(normalizeEmail(" Jane.Doe+promo@GoogleMail.com ")).toBe("janedoe@gmail.com");
    expect(normalizeEmail("jane.doe@company.com")).toBe("jane.doe@company.com");
    const { guard } = setup();
    for (const email of ["j.a.n.e@gmail.com", "jane+1@gmail.com", "JANE@gmail.com"]) {
      await guard.record(attempt({ email, outcome: "declined", declineCode: "generic_decline" }));
    }
    expect((await guard.check({ amount: 2500, email: "jane@gmail.com", timestamp: T0 + MIN })).action).toBe("challenge");
  });

  it("limits checkout attempts even when nothing reaches the processor", async () => {
    const { guard } = setup();
    let last;
    for (let i = 0; i < 20; i++) last = await guard.check({ amount: 2500, sessionId: "s1", timestamp: T0 + i * 1000 });
    expect(last?.action).toBe("block");
    expect(last?.reasons[0]?.rule).toBe("checks");
  });

  it("only counts small payments as small", async () => {
    const { guard } = setup();
    for (let i = 0; i < 5; i++) await guard.record(attempt({ ip: "3.3.3.3", amount: 100 }));
    expect((await guard.check({ amount: 100, ip: "3.3.3.3", timestamp: T0 + MIN })).reasons.map((r) => r.rule)).toContain("small_attempts");
    expect((await guard.check({ amount: 5000, ip: "3.3.3.3", timestamp: T0 + MIN })).reasons.map((r) => r.rule)).not.toContain("small_attempts");
  });

  it("recording the same attempt twice changes nothing", async () => {
    const { guard } = setup();
    const repeated = attempt({ ip: "4.4.4.4", outcome: "declined" });
    for (let i = 0; i < 5; i++) await guard.record(repeated);
    expect((await guard.check({ amount: 2500, ip: "4.4.4.4", timestamp: T0 + MIN })).action).toBe("allow");
    expect((await guard.status(T0 + MIN)).recent.declines).toBe(1);
  });
});

describe("shop-wide rules", () => {
  async function ordinaryDay(guard: CardTestingGuard, at: (t: number) => void) {
    // A day of normal traffic, so the usual rates are known.
    for (let i = 0; i < 24 * 12; i++) {
      const t = T0 - 26 * 3600_000 + i * 5 * MIN;
      at(t);
      await guard.record(attempt({ timestamp: t, ip: `9.9.${i % 200}.1`, outcome: i % 20 === 0 ? "declined" : "succeeded" }));
    }
  }

  it("raises one alert and enters elevated mode when declines spike across many IPs", async () => {
    const { guard, alerts, at } = setup();
    await ordinaryDay(guard, at);
    for (let i = 0; i < 20; i++) {
      const t = T0 + i * 20_000;
      at(t);
      await guard.record(attempt({ timestamp: t, ip: `7.7.7.${i}`, amount: 150, outcome: "declined", declineCode: "card_declined" }));
    }
    expect(alerts.map((a) => a.rule)).toContain("decline_rate_spike");
    expect(new Set(alerts.map((a) => a.rule)).size).toBe(alerts.length);  // Each rule alerts once per attack.
    const small = await guard.check({ amount: 150, ip: "8.8.8.8", timestamp: T0 + 7 * MIN });
    expect(small).toMatchObject({ action: "challenge", mode: "elevated" });
    expect((await guard.check({ amount: 4000, ip: "8.8.8.9", timestamp: T0 + 7 * MIN })).action).toBe("allow");
  });

  it("an attack can't raise its own baseline", async () => {
    const { guard, at } = setup();
    await ordinaryDay(guard, at);
    at(T0);
    const before = await guard.status(T0);
    for (let i = 0; i < 30; i++) await guard.record(attempt({ timestamp: T0 + i * 1000, outcome: "declined" }));
    expect((await guard.status(T0 + 31_000)).usualPer10Minutes).toEqual(before.usualPer10Minutes);
  });

  it("flags a BIN sweep only when it's mostly declines", async () => {
    const { guard, at } = setup();
    at(T0);
    for (let i = 0; i < 8; i++) await guard.record(attempt({ bin: "411111", last4: String(1000 + i), outcome: "succeeded" }));
    expect((await guard.check({ amount: 2500, bin: "411111", timestamp: T0 + MIN })).action).toBe("allow");
    for (let i = 0; i < 8; i++) await guard.record(attempt({ bin: "414720", last4: String(2000 + i), outcome: "declined" }));
    const sweep = await guard.check({ amount: 2500, bin: "414720", timestamp: T0 + MIN });
    expect(sweep.reasons.map((r) => r.rule)).toContain("bin_enumeration");
  });

  it("a failing alert handler never breaks recording", async () => {
    const guard = new CardTestingGuard({ now: () => T0, onAlert: () => { throw new Error("pager down"); } });
    for (let i = 0; i < 20; i++) await guard.record(attempt({ timestamp: T0 + i, outcome: "declined" }));
    expect((await guard.status(T0 + 100)).mode).toBe("elevated");
  });
});

describe("configuration", () => {
  it("merges partial settings with defaults", () => {
    const config = resolveConfig({ perIdentity: { declines: { block: 10 } }, smallAmount: 100 });
    expect(config.perIdentity.declines).toEqual({ challenge: 3, block: 10 });
    expect(config.smallAmount).toBe(100);
    expect(config.shop.minDeclines).toBe(12);
  });

  it("rejects settings that don't make sense", () => {
    expect(() => resolveConfig({ perIdentity: { declines: { challenge: 5, block: 2 } } })).toThrow(/block must be at least challenge/);
    expect(() => resolveConfig({ shop: { minDeclineRate: 2 } })).toThrow(/between 0 and 1/);
  });
});
