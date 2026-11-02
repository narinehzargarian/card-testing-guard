import { type GuardConfig, type GuardConfigInput, type Limit, resolveConfig } from "./config.js";
import { MemoryStore, type Store } from "./store.js";
import type { Action, Alert, Attempt, CheckRequest, Decision, Reason } from "./types.js";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const SHORT = 10 * MINUTE;
const BASELINE_HOURS = 24;

type Identity = "ip" | "email" | "customer" | "session";

export interface GuardOptions {
  config?: GuardConfigInput;
  store?: Store;
  /** Called once when a shop-wide attack starts. Errors thrown here are caught and ignored. */
  onAlert?: (alert: Alert) => void;
  /** Defaults to Date.now. Replaying past data supplies each event's own time instead. */
  now?: () => number;
}

/**
 * Detects card testing, where fraudsters run stolen cards through a checkout to find which work.
 *
 * Call {@link check} before charging a card, and {@link record} once the processor answers.
 * Every decision lists the rules behind it, so a blocked customer can be explained.
 */
export class CardTestingGuard {
  readonly config: GuardConfig;
  private readonly store: Store;
  private readonly onAlert: ((alert: Alert) => void) | undefined;
  private readonly now: () => number;

  constructor(options: GuardOptions = {}) {
    this.config = resolveConfig(options.config);
    this.now = options.now ?? Date.now;
    this.store = options.store ?? new MemoryStore(this.now);
    this.onAlert = options.onAlert;
  }

  /** Decides whether to allow a checkout, ask for a challenge such as a CAPTCHA, or block it. */
  async check(request: CheckRequest): Promise<Decision> {
    const t = request.timestamp ?? this.now();
    const identities = identitiesOf(request);
    const reasons: Reason[] = [];
    const per = this.config.perIdentity;
    const small = request.amount <= this.config.smallAmount;

    for (const [kind, value] of identities) {
      const subject = `${kind}:${value}`;
      const [cards, declines, probing, smallAttempts, checks] = await Promise.all([
        this.store.countWindow(`cards:${subject}`, t - HOUR),
        this.store.countWindow(`declines:${subject}`, t - SHORT),
        this.store.countWindow(`probing:${subject}`, t - SHORT),
        this.store.countWindow(`small:${subject}`, t - SHORT),
        this.store.countWindow(`checks:${subject}`, t - SHORT),
      ]);
      // A card that hasn't been seen with this identity would add one more distinct card.
      const newCard = request.cardFingerprint !== undefined
        && (await this.store.countWindow(`card-seen:${subject}:${request.cardFingerprint}`, t - HOUR)) === 0;
      apply(reasons, "distinct_cards", per.distinctCards, cards + (newCard ? 1 : 0), subject,
        (n) => `${n} different cards from this ${kind} in the last hour`);
      apply(reasons, "declines", per.declines, declines, subject, (n) => `${n} declines from this ${kind} in 10 minutes`);
      apply(reasons, "probing_declines", per.probingDeclines, probing, subject,
        (n) => `${n} declines for wrong card details from this ${kind} in 10 minutes`);
      if (small) {
        apply(reasons, "small_attempts", per.smallAttempts, smallAttempts + 1, subject,
          (n) => `${n} small payments from this ${kind} in 10 minutes`);
      }
      apply(reasons, "checks", per.checks, checks + 1, subject, (n) => `${n} checkout attempts from this ${kind} in 10 minutes`);
    }

    if (request.bin && (await this.binUnderAttack(request.bin, t))) {
      reasons.push({
        rule: "bin_enumeration", action: "challenge", subject: `bin:${request.bin}`, value: this.config.shop.binDistinctCards,
        threshold: this.config.shop.binDistinctCards, message: `Many different cards starting ${request.bin} were just tried`,
      });
    }

    if (small) {
      await this.store.increment(`m:small-checks:${Math.floor(t / MINUTE)}`, 1, HOUR + 2 * MINUTE);
    }
    const elevated = await this.sustainElevated(t);
    if (elevated) {
      // During an attack, small payments and anyone who was already declined get a challenge.
      const recentlyDeclined = await this.anyRecentDecline(identities, t);
      if (small || recentlyDeclined) {
        reasons.push({
          rule: "shop_under_attack", action: "challenge", value: 1, threshold: 1,
          message: small ? "Card testing is under way, so small payments need a challenge" : "Card testing is under way, and this customer was recently declined",
        });
      }
    }

    // Counted after deciding, so a request never counts against itself twice.
    await Promise.all(identities.map(([kind, value]) => this.store.addToWindow(`checks:${kind}:${value}`, `${t}:${Math.random()}`, t, SHORT)));

    return { action: strongest(reasons), reasons, mode: elevated ? "elevated" : "normal" };
  }

  /** Records what the processor said. Recording the same attempt twice changes nothing. */
  async record(attempt: Attempt): Promise<void> {
    const t = attempt.timestamp;
    const declined = attempt.outcome === "declined";
    const probing = declined && attempt.declineCode !== undefined && this.config.probingCodes.includes(attempt.declineCode);
    const small = attempt.amount <= this.config.smallAmount;
    const writes: Promise<void>[] = [];

    for (const [kind, value] of identitiesOf(attempt)) {
      const subject = `${kind}:${value}`;
      if (attempt.cardFingerprint) {
        writes.push(this.store.addToWindow(`cards:${subject}`, attempt.cardFingerprint, t, HOUR));
        writes.push(this.store.addToWindow(`card-seen:${subject}:${attempt.cardFingerprint}`, "1", t, HOUR));
      }
      if (declined) writes.push(this.store.addToWindow(`declines:${subject}`, attempt.id, t, SHORT));
      if (probing) writes.push(this.store.addToWindow(`probing:${subject}`, attempt.id, t, SHORT));
      if (small) writes.push(this.store.addToWindow(`small:${subject}`, attempt.id, t, SHORT));
    }
    if (attempt.bin && attempt.last4) {
      writes.push(this.store.addToWindow(`bin:${attempt.bin}`, attempt.last4, t, SHORT));
      if (declined) writes.push(this.store.addToWindow(`bin-declines:${attempt.bin}`, attempt.id, t, SHORT));
    }

    // Shop-wide counts, by minute for the last 10 minutes and by hour for the usual rate. Each
    // attempt is counted once, using a marker, so a redelivered webhook doesn't inflate them.
    const seen = await this.store.getValue(`seen:${attempt.id}`);
    if (seen === undefined) {
      writes.push(this.store.setValue(`seen:${attempt.id}`, "1", BASELINE_HOURS * HOUR));
      const minute = Math.floor(t / MINUTE);
      const hour = Math.floor(t / HOUR);
      const retainMinutes = HOUR + 2 * MINUTE;
      const retainHours = (BASELINE_HOURS + 2) * HOUR;
      writes.push(this.store.increment(`m:all:${minute}`, 1, retainMinutes));
      writes.push(this.store.increment(`h:all:${hour}`, 1, retainHours));
      if (declined) {
        writes.push(this.store.increment(`m:declined:${minute}`, 1, retainMinutes));
        writes.push(this.store.increment(`h:declined:${hour}`, 1, retainHours));
      }
      if (small) {
        writes.push(this.store.increment(`m:small:${minute}`, 1, retainMinutes));
        writes.push(this.store.increment(`h:small:${hour}`, 1, retainHours));
      }
    }
    await Promise.all(writes);
    await this.watchShop(t, attempt.bin);
  }

  /** The shop-wide picture right now, for dashboards and the status endpoint. */
  async status(at = this.now()): Promise<{ mode: "normal" | "elevated"; recent: ShopCounts; usualPer10Minutes: ShopCounts }> {
    const { recent, usual } = await this.shopCounts(at);
    const until = await this.store.getValue("elevated-until");
    return { mode: until !== undefined && Number(until) > at ? "elevated" : "normal", recent, usualPer10Minutes: usual };
  }

  private async watchShop(t: number, bin: string | undefined): Promise<void> {
    const shop = this.config.shop;
    const { recent, lastHour, usual } = await this.shopCounts(t);
    const alerts: Alert[] = [];

    const usualRate = usual.attempts > 0 ? usual.declines / usual.attempts : 0;
    const rateThreshold = Math.max(shop.minDeclineRate, shop.rateMultiplier * usualRate);
    const rate = recent.attempts > 0 ? recent.declines / recent.attempts : 0;
    if (recent.declines >= shop.minDeclines && rate >= rateThreshold) {
      alerts.push({
        rule: "decline_rate_spike", timestamp: t, value: round(rate), threshold: round(rateThreshold),
        message: `${Math.round(rate * 100)}% of payments declined in the last 10 minutes, against a usual ${Math.round(usualRate * 100)}%`,
      });
    }
    const hourRate = lastHour.attempts > 0 ? lastHour.declines / lastHour.attempts : 0;
    if (lastHour.declines >= shop.minDeclinesHour && hourRate >= rateThreshold) {
      alerts.push({
        rule: "slow_decline_rate_spike", timestamp: t, value: round(hourRate), threshold: round(rateThreshold),
        message: `${Math.round(hourRate * 100)}% of payments declined in the last hour, against a usual ${Math.round(usualRate * 100)}%`,
      });
    }
    const smallThreshold = Math.max(shop.minSmallAttempts, shop.smallMultiplier * usual.small);
    if (recent.small >= smallThreshold) {
      alerts.push({
        rule: "small_payment_spike", timestamp: t, value: recent.small, threshold: round(smallThreshold),
        message: `${recent.small} small payments in the last 10 minutes, against a usual ${round(usual.small)}`,
      });
    }
    if (bin && (await this.binUnderAttack(bin, t))) {
      alerts.push({
        rule: "bin_enumeration", timestamp: t, value: shop.binDistinctCards, threshold: shop.binDistinctCards,
        message: `Many different cards starting ${bin} were tried in 10 minutes`,
      });
    }
    if (alerts.length === 0) return;

    const wasElevated = Number((await this.store.getValue("elevated-until")) ?? 0) > t;
    await this.store.setValue("elevated-until", String(t + shop.elevatedMs), shop.elevatedMs);
    if (!wasElevated && this.onAlert) {
      for (const alert of alerts) {
        try {
          this.onAlert(alert);
        } catch {
          // A broken notification must never break payments.
        }
      }
    }
  }

  /**
   * Whether elevated mode is on. While it is, it stays on as long as small-amount checkout attempts
   * keep arriving well above the usual rate, even though stopped attempts produce no declines.
   */
  private async sustainElevated(t: number): Promise<boolean> {
    const until = Number((await this.store.getValue("elevated-until")) ?? 0);
    if (until <= t) return false;
    const minute = Math.floor(t / MINUTE);
    const hour = Math.floor(t / HOUR);
    const counts = await this.store.getCounters([
      ...Array.from({ length: 60 }, (_, i) => `m:small-checks:${minute - i}`),
      ...Array.from({ length: BASELINE_HOURS }, (_, i) => `h:small:${hour - 1 - i}`),
    ]);
    const smallChecksHour = counts.slice(0, 60).reduce((a, b) => a + b, 0);
    const usualSmallHour = counts.slice(60).reduce((a, b) => a + b, 0) / BASELINE_HOURS;
    const shop = this.config.shop;
    if (smallChecksHour >= Math.max(shop.minSmallChecksHour, shop.smallMultiplier * usualSmallHour)) {
      const extended = t + shop.elevatedMs;
      if (extended > until) await this.store.setValue("elevated-until", String(extended), shop.elevatedMs);
    }
    return true;
  }

  private async binUnderAttack(bin: string, t: number): Promise<boolean> {
    const [cards, declines] = await Promise.all([
      this.store.countWindow(`bin:${bin}`, t - SHORT),
      this.store.countWindow(`bin-declines:${bin}`, t - SHORT),
    ]);
    return cards >= this.config.shop.binDistinctCards && declines >= this.config.shop.binMinDeclines;
  }

  private async anyRecentDecline(identities: [Identity, string][], t: number): Promise<boolean> {
    for (const [kind, value] of identities) {
      if ((await this.store.countWindow(`declines:${kind}:${value}`, t - SHORT)) > 0) return true;
    }
    return false;
  }

  /**
   * Recent: the last 10 whole minutes. Usual: the average 10 minutes over the previous 24 hours,
   * not counting the current hour, so an attack doesn't raise its own baseline.
   */
  private async shopCounts(t: number): Promise<{ recent: ShopCounts; lastHour: ShopCounts; usual: ShopCounts }> {
    const minute = Math.floor(t / MINUTE);
    const hour = Math.floor(t / HOUR);
    const minutes = Array.from({ length: 60 }, (_, i) => minute - i);
    const hours = Array.from({ length: BASELINE_HOURS }, (_, i) => hour - 1 - i);
    const keys = [
      ...minutes.map((m) => `m:all:${m}`), ...minutes.map((m) => `m:declined:${m}`), ...minutes.map((m) => `m:small:${m}`),
      ...hours.map((h) => `h:all:${h}`), ...hours.map((h) => `h:declined:${h}`), ...hours.map((h) => `h:small:${h}`),
    ];
    const values = await this.store.getCounters(keys);
    const sum = (from: number, count: number) => values.slice(from, from + count).reduce((a, b) => a + b, 0);
    const recent = { attempts: sum(0, 10), declines: sum(60, 10), small: sum(120, 10) };
    const lastHour = { attempts: sum(0, 60), declines: sum(60, 60), small: sum(120, 60) };
    const perTenMinutes = 1 / (BASELINE_HOURS * 6);
    const usual = {
      attempts: sum(180, BASELINE_HOURS) * perTenMinutes,
      declines: sum(180 + BASELINE_HOURS, BASELINE_HOURS) * perTenMinutes,
      small: sum(180 + 2 * BASELINE_HOURS, BASELINE_HOURS) * perTenMinutes,
    };
    return { recent, lastHour, usual };
  }
}

export interface ShopCounts {
  attempts: number;
  declines: number;
  small: number;
}

function identitiesOf(source: { ip?: string; email?: string; customerId?: string; sessionId?: string }): [Identity, string][] {
  const result: [Identity, string][] = [];
  if (source.ip) result.push(["ip", source.ip.trim()]);
  if (source.email) result.push(["email", normalizeEmail(source.email)]);
  if (source.customerId) result.push(["customer", source.customerId]);
  if (source.sessionId) result.push(["session", source.sessionId]);
  return result;
}

/** Lowercases, and drops "+tags" and Gmail dots, which testers use to look like many people. */
export function normalizeEmail(email: string): string {
  const [rawLocal = "", rawDomain = ""] = email.trim().toLowerCase().split("@");
  let local = rawLocal.split("+")[0] ?? "";
  const domain = rawDomain === "googlemail.com" ? "gmail.com" : rawDomain;
  if (domain === "gmail.com") local = local.replaceAll(".", "");
  return `${local}@${domain}`;
}

function apply(reasons: Reason[], rule: string, limit: Limit, value: number, subject: string, describe: (n: number) => string): void {
  if (value >= limit.block) {
    reasons.push({ rule, action: "block", subject, value, threshold: limit.block, message: describe(value) });
  } else if (value >= limit.challenge) {
    reasons.push({ rule, action: "challenge", subject, value, threshold: limit.challenge, message: describe(value) });
  }
}

function strongest(reasons: Reason[]): Action {
  if (reasons.some((r) => r.action === "block")) return "block";
  return reasons.length > 0 ? "challenge" : "allow";
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
