import { CardTestingGuard } from "./guard.js";
import type { GuardConfigInput } from "./config.js";
import type { Action, Alert, Attempt } from "./types.js";

export interface AttackWindow {
  start: number;
  end: number;
  attempts: number;
  declines: number;
  rules: string[];
}

export interface ScanReport {
  attempts: number;
  declines: number;
  /** What the guard would have said before each attempt. */
  decisions: Record<Action, number>;
  /** Periods of shop-wide attack, merged when they overlap. */
  attackWindows: AttackWindow[];
  /** The identities that triggered rules most often. */
  flagged: { subject: string; attempts: number; rules: string[] }[];
}

/**
 * Replays past payment attempts in time order, asking the guard about each before recording it,
 * to show what it would have caught. Useful to answer "was I attacked?" from an export.
 */
export async function scan(attempts: Attempt[], config?: GuardConfigInput): Promise<ScanReport> {
  let clock = 0;
  const alerts: Alert[] = [];
  const guard = new CardTestingGuard({ config, now: () => clock, onAlert: (alert) => alerts.push(alert) });
  const decisions: Record<Action, number> = { allow: 0, challenge: 0, block: 0 };
  const flagged = new Map<string, { attempts: number; rules: Set<string> }>();
  const elevatedAt: number[] = [];
  let declines = 0;

  for (const attempt of [...attempts].sort((a, b) => a.timestamp - b.timestamp)) {
    clock = attempt.timestamp;
    const decision = await guard.check({ ...attempt, timestamp: attempt.timestamp });
    decisions[decision.action]++;
    for (const reason of decision.reasons) {
      if (!reason.subject) continue;
      const entry = flagged.get(reason.subject) ?? { attempts: 0, rules: new Set<string>() };
      entry.rules.add(reason.rule);
      flagged.set(reason.subject, entry);
    }
    for (const subject of new Set(decision.reasons.map((r) => r.subject).filter((s): s is string => s !== undefined))) {
      flagged.get(subject)!.attempts++;
    }
    await guard.record(attempt);
    if (attempt.outcome === "declined") declines++;
    if ((await guard.status(attempt.timestamp)).mode === "elevated") elevatedAt.push(attempt.timestamp);
  }

  return {
    attempts: attempts.length,
    declines,
    decisions,
    attackWindows: windows(elevatedAt, alerts, attempts, guard.config.shop.elevatedMs),
    flagged: [...flagged.entries()]
      .map(([subject, entry]) => ({ subject, attempts: entry.attempts, rules: [...entry.rules].sort() }))
      .sort((a, b) => b.attempts - a.attempts || a.subject.localeCompare(b.subject))
      .slice(0, 25),
  };
}

function windows(elevatedAt: number[], alerts: Alert[], attempts: Attempt[], gapMs: number): AttackWindow[] {
  const result: AttackWindow[] = [];
  for (const t of elevatedAt) {
    const last = result.at(-1);
    if (last && t - last.end <= gapMs) {
      last.end = t;
    } else {
      result.push({ start: t, end: t, attempts: 0, declines: 0, rules: [] });
    }
  }
  for (const window of result) {
    // Starts at the first alert that opened it, which can be just before the first elevated attempt.
    const opening = alerts.filter((a) => a.timestamp >= window.start - gapMs && a.timestamp <= window.end);
    window.start = Math.min(window.start, ...opening.map((a) => a.timestamp));
    window.rules = [...new Set(opening.map((a) => a.rule))].sort();
    for (const attempt of attempts) {
      if (attempt.timestamp >= window.start && attempt.timestamp <= window.end) {
        window.attempts++;
        if (attempt.outcome === "declined") window.declines++;
      }
    }
  }
  return result;
}
