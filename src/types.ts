/** A payment attempt after the processor answered. Amounts are in minor units, such as cents. */
export interface Attempt {
  id: string;
  /** Milliseconds since the epoch. */
  timestamp: number;
  amount: number;
  currency?: string;
  outcome: "succeeded" | "declined";
  /** The processor's reason, such as Stripe's "incorrect_cvc". */
  declineCode?: string;
  /** A stable ID for the card that doesn't reveal the number, such as Stripe's card fingerprint. */
  cardFingerprint?: string;
  /** The card's first 6 to 8 digits. */
  bin?: string;
  last4?: string;
  ip?: string;
  email?: string;
  customerId?: string;
  sessionId?: string;
}

/** What's known at checkout, before charging the card. */
export interface CheckRequest {
  /** Milliseconds since the epoch. Defaults to now. */
  timestamp?: number;
  amount: number;
  ip?: string;
  email?: string;
  customerId?: string;
  sessionId?: string;
  cardFingerprint?: string;
  bin?: string;
  last4?: string;
}

export type Action = "allow" | "challenge" | "block";

export interface Reason {
  rule: string;
  action: Exclude<Action, "allow">;
  /** What the rule looked at, such as "ip:203.0.113.7". Absent for shop-wide rules. */
  subject?: string;
  value: number;
  threshold: number;
  message: string;
}

export interface Decision {
  action: Action;
  reasons: Reason[];
  /** "elevated" while a shop-wide attack is under way, when the guard is stricter. */
  mode: "normal" | "elevated";
}

/** Raised once when a shop-wide attack starts, so someone can be told. */
export interface Alert {
  rule: string;
  timestamp: number;
  value: number;
  threshold: number;
  message: string;
}
