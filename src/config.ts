/** A limit that first challenges, then blocks. Set either to Infinity to turn it off. */
export interface Limit {
  challenge: number;
  block: number;
}

export interface GuardConfig {
  /** Attempts at or below this amount, in minor units, count as "small". Testers favor tiny amounts. */
  smallAmount: number;

  /** Per IP, email, customer, and session. */
  perIdentity: {
    /** Distinct cards used in the last hour. Real customers rarely use more than two. */
    distinctCards: Limit;
    /** Declines in the last 10 minutes. */
    declines: Limit;
    /** Declines with codes that suggest guessing, like a wrong CVC, in the last 10 minutes. */
    probingDeclines: Limit;
    /** Small-amount attempts in the last 10 minutes. */
    smallAttempts: Limit;
    /** Checkout checks in the last 10 minutes, whatever happened next. */
    checks: Limit;
  };

  /** Shop-wide signs of an attack spread across many IPs. */
  shop: {
    /** Declines in 10 minutes before the 10-minute decline rate is judged at all. */
    minDeclines: number;
    /** Declines in an hour before the hourly decline rate is judged. Catches slow attacks that stay under the 10-minute limits. */
    minDeclinesHour: number;
    /** The 10-minute decline rate must reach this, and `rateMultiplier` times the usual rate. */
    minDeclineRate: number;
    rateMultiplier: number;
    /** Distinct last-4 digits seen with one BIN in 10 minutes. Testers often walk through generated numbers. */
    binDistinctCards: number;
    /** Declines on that BIN in the same 10 minutes. Popular bank BINs see many real cards; a sweep is mostly declines. */
    binMinDeclines: number;
    /** Small-amount attempts in 10 minutes, and how many times the usual number that must be. */
    minSmallAttempts: number;
    smallMultiplier: number;
    /**
     * Small-amount checkout attempts in an hour that keep elevated mode on. Stopped bots never reach
     * the processor, so declines fall once the guard works; this keeps it on while they keep trying.
     */
    minSmallChecksHour: number;
    /** How long elevated mode lasts after the last sign of an attack. */
    elevatedMs: number;
  };

  /** Decline codes that suggest someone is guessing card details. */
  probingCodes: string[];
}

export const DEFAULT_CONFIG: GuardConfig = {
  smallAmount: 300,
  perIdentity: {
    distinctCards: { challenge: 3, block: 5 },
    declines: { challenge: 3, block: 6 },
    probingDeclines: { challenge: 2, block: 4 },
    smallAttempts: { challenge: 4, block: 8 },
    checks: { challenge: 10, block: 20 },
  },
  shop: {
    minDeclines: 12,
    minDeclinesHour: 20,
    minDeclineRate: 0.3,
    rateMultiplier: 3,
    binDistinctCards: 6,
    binMinDeclines: 5,
    minSmallAttempts: 15,
    smallMultiplier: 4,
    minSmallChecksHour: 10,
    elevatedMs: 30 * 60_000,
  },
  probingCodes: [
    "incorrect_cvc", "invalid_cvc", "incorrect_number", "invalid_number", "invalid_expiry_month",
    "invalid_expiry_year", "incorrect_zip", "card_velocity_exceeded", "testmode_decline",
  ],
};

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? (T[K] extends unknown[] ? T[K] : DeepPartial<T[K]>) : T[K] };
export type GuardConfigInput = DeepPartial<GuardConfig>;

/** Fills in defaults and checks that limits make sense. */
export function resolveConfig(input: GuardConfigInput = {}): GuardConfig {
  const config: GuardConfig = {
    smallAmount: input.smallAmount ?? DEFAULT_CONFIG.smallAmount,
    perIdentity: {
      distinctCards: { ...DEFAULT_CONFIG.perIdentity.distinctCards, ...input.perIdentity?.distinctCards },
      declines: { ...DEFAULT_CONFIG.perIdentity.declines, ...input.perIdentity?.declines },
      probingDeclines: { ...DEFAULT_CONFIG.perIdentity.probingDeclines, ...input.perIdentity?.probingDeclines },
      smallAttempts: { ...DEFAULT_CONFIG.perIdentity.smallAttempts, ...input.perIdentity?.smallAttempts },
      checks: { ...DEFAULT_CONFIG.perIdentity.checks, ...input.perIdentity?.checks },
    },
    shop: { ...DEFAULT_CONFIG.shop, ...input.shop },
    probingCodes: input.probingCodes ?? DEFAULT_CONFIG.probingCodes,
  };
  for (const [name, limit] of Object.entries(config.perIdentity)) {
    if (!(limit.challenge > 0) || !(limit.block >= limit.challenge)) {
      throw new Error(`perIdentity.${name}: challenge must be above 0 and block must be at least challenge`);
    }
  }
  if (!(config.shop.minDeclineRate > 0 && config.shop.minDeclineRate <= 1)) {
    throw new Error("shop.minDeclineRate must be between 0 and 1");
  }
  if (!(config.smallAmount >= 0)) throw new Error("smallAmount must not be negative");
  return config;
}
