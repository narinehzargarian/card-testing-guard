import type { Attempt } from "./types.js";

/**
 * Generates checkout traffic with labeled card-testing attacks.
 *
 * There's no public dataset of real card-testing attacks, so this is how the guard is measured.
 * Results show it works on these patterns; they can't promise the same on a real shop's traffic.
 */
export type Scenario = "legit" | "single_ip_burst" | "rotating_proxies" | "bin_enumeration" | "slow_drip";

export interface LabeledAttempt extends Attempt {
  scenario: Scenario;
}

export interface SimulationOptions {
  seed?: number;
  days?: number;
  /** Legitimate attempts per day on an ordinary day. */
  perDay?: number;
  /** Adds a launch day with five times the traffic, to measure false alarms when a shop is busy. */
  launchDay?: boolean;
  attacks?: Exclude<Scenario, "legit">[];
  start?: number;
}

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

export function simulate(options: SimulationOptions = {}): LabeledAttempt[] {
  const random = rng(options.seed ?? 1);
  const days = options.days ?? 7;
  const perDay = options.perDay ?? 300;
  const start = options.start ?? Date.UTC(2026, 2, 1);
  const attempts: LabeledAttempt[] = [];
  let counter = 0;
  const id = () => `a${String(++counter).padStart(7, "0")}`;
  const pick = <T>(items: T[]): T => items[Math.floor(random() * items.length)]!;
  const ip = () => `${10 + Math.floor(random() * 200)}.${Math.floor(random() * 256)}.${Math.floor(random() * 256)}.${Math.floor(random() * 256)}`;
  // Real traffic spans thousands of card prefixes. A few big banks' prefixes are far more common,
  // so some prefixes repeat a lot, as they do in real checkouts.
  const binPool = Array.from({ length: 400 }, () => `${pick(["4", "4", "4", "5", "5", "3", "6"])}${String(Math.floor(random() * 100_000)).padStart(5, "0")}`);
  const popular = binPool.slice(0, 12);
  const bin = () => (random() < 0.3 ? pick(popular) : pick(binPool));

  // Returning customers, some of whom keep more than one card.
  const customers = Array.from({ length: Math.max(50, perDay * 2) }, (_, n) => ({
    email: `customer${n}@example.com`,
    ip: ip(),
    cards: Array.from({ length: random() < 0.15 ? 2 : 1 }, () => ({ fingerprint: `fp_${Math.floor(random() * 1e12).toString(36)}`, bin: bin(), last4: last4(random) })),
  }));

  for (let day = 0; day < days; day++) {
    const busy = options.launchDay && day === Math.floor(days / 2) ? 5 : 1;
    const count = Math.round(perDay * busy * (0.8 + random() * 0.4));
    for (let n = 0; n < count; n++) {
      const customer = pick(customers);
      const card = pick(customer.cards);
      // Busier in the afternoon and evening.
      const hour = 8 + Math.floor(Math.abs(gaussian(random)) * 4 + random() * 10) % 16;
      const t = start + day * DAY + hour * HOUR + Math.floor(random() * HOUR);
      const amount = Math.round(Math.exp(3.4 + gaussian(random) * 0.8) * 100);
      const session = `s_${Math.floor(random() * 1e12).toString(36)}`;
      const declinedFirst = random() < 0.06;
      if (declinedFirst) {
        // A real customer whose card fails, who often retries once and sometimes uses another card.
        attempts.push({
          id: id(), timestamp: t, amount, outcome: "declined", declineCode: pick(["insufficient_funds", "generic_decline", "incorrect_cvc", "expired_card"]),
          cardFingerprint: card.fingerprint, bin: card.bin, last4: card.last4, ip: customer.ip, email: customer.email, sessionId: session, scenario: "legit",
        });
        if (random() < 0.6) {
          const retry = random() < 0.5 ? card : { fingerprint: `fp_${Math.floor(random() * 1e12).toString(36)}`, bin: bin(), last4: last4(random) };
          attempts.push({
            id: id(), timestamp: t + 60_000 + Math.floor(random() * 120_000), amount, outcome: random() < 0.75 ? "succeeded" : "declined",
            declineCode: undefined, cardFingerprint: retry.fingerprint, bin: retry.bin, last4: retry.last4, ip: customer.ip, email: customer.email,
            sessionId: session, scenario: "legit",
          });
        }
      } else {
        attempts.push({
          id: id(), timestamp: t, amount, outcome: "succeeded", cardFingerprint: card.fingerprint, bin: card.bin, last4: card.last4,
          ip: customer.ip, email: customer.email, sessionId: session, scenario: "legit",
        });
      }
    }
  }

  const attacks = options.attacks ?? ["single_ip_burst", "rotating_proxies", "bin_enumeration", "slow_drip"];
  attacks.forEach((scenario, n) => {
    // Attacks land on later days, after the guard has seen ordinary traffic.
    const begin = start + Math.min(days - 1, 2 + n) * DAY + (2 + Math.floor(random() * 18)) * HOUR;
    const testCard = () => ({ fingerprint: `fp_${Math.floor(random() * 1e12).toString(36)}`, bin: bin(), last4: last4(random) });
    const attempt = (t: number, card: { fingerprint: string; bin: string; last4: string }, from: string, email: string): LabeledAttempt => {
      const works = random() < 0.12;
      return {
        id: id(), timestamp: t, amount: 50 + Math.floor(random() * 250), outcome: works ? "succeeded" : "declined",
        declineCode: works ? undefined : pick(["incorrect_cvc", "incorrect_number", "generic_decline", "expired_card", "card_declined", "invalid_expiry_year"]),
        cardFingerprint: card.fingerprint, bin: card.bin, last4: card.last4, ip: from, email, sessionId: `s_${Math.floor(random() * 1e12).toString(36)}`, scenario,
      };
    };
    if (scenario === "single_ip_burst") {
      // One machine, one email, 150 cards in about 15 minutes.
      const from = ip();
      for (let k = 0; k < 150; k++) attempts.push(attempt(begin + k * 6_000, testCard(), from, "buyer123@example.net"));
    } else if (scenario === "rotating_proxies") {
      // 250 attempts in an hour, each from a new IP and email, so no identity repeats.
      for (let k = 0; k < 250; k++) attempts.push(attempt(begin + k * 14_000, testCard(), ip(), `user${Math.floor(random() * 1e9)}@mailbox.test`));
    } else if (scenario === "bin_enumeration") {
      // Generated numbers that share a BIN, from rotating IPs.
      const bin = "414720";
      for (let k = 0; k < 120; k++) {
        attempts.push(attempt(begin + k * 20_000, { fingerprint: `fp_${Math.floor(random() * 1e12).toString(36)}`, bin, last4: String(1000 + k * 7).slice(-4) }, ip(), `x${k}@mailbox.test`));
      }
    } else {
      // One attempt every 2 to 4 minutes for 6 hours, from rotating IPs: designed to stay under velocity limits.
      let t = begin;
      for (let k = 0; t < begin + 6 * HOUR; k++) {
        attempts.push(attempt(t, testCard(), ip(), `slow${k}@mailbox.test`));
        t += 120_000 + Math.floor(random() * 120_000);
      }
    }
  });

  return attempts.sort((a, b) => a.timestamp - b.timestamp || a.id.localeCompare(b.id));
}

function last4(random: () => number): string {
  return String(Math.floor(random() * 10_000)).padStart(4, "0");
}

/** A small seeded generator, so a simulation can be repeated exactly. */
function rng(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 4_294_967_296;
  };
}

function gaussian(random: () => number): number {
  return Math.sqrt(-2 * Math.log(1 - random())) * Math.cos(2 * Math.PI * random());
}
