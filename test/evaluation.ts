import { CardTestingGuard } from "../src/guard.js";
import type { GuardConfigInput } from "../src/config.js";
import { simulate, type Scenario, type SimulationOptions } from "../src/simulate.js";

export interface ScenarioResult {
  attempts: number;
  /** Share of attempts the guard challenged or blocked. For attacks, higher is better. */
  stopped: number;
  blocked: number;
  /** Minutes from the attack's first attempt to the first one stopped. */
  minutesToDetect?: number;
  /** Attack attempts that reached the processor and got an approval: a stolen card confirmed. */
  cardsConfirmed?: number;
}

/**
 * Replays traffic as a live checkout would: check, then charge only if allowed. Bots are assumed
 * to fail a challenge such as a CAPTCHA, and real customers to pass it.
 */
export async function evaluate(simulation: SimulationOptions, config?: GuardConfigInput): Promise<Record<Scenario, ScenarioResult>> {
  const attempts = simulate(simulation);
  let clock = 0;
  const guard = new CardTestingGuard({ config, now: () => clock });
  const results = new Map<Scenario, { attempts: number; stopped: number; blocked: number; firstAt?: number; firstStoppedAt?: number; confirmed: number }>();

  for (const attempt of attempts) {
    clock = attempt.timestamp;
    const decision = await guard.check({ ...attempt });
    const r = results.get(attempt.scenario) ?? { attempts: 0, stopped: 0, blocked: 0, confirmed: 0 };
    results.set(attempt.scenario, r);
    r.attempts++;
    r.firstAt ??= attempt.timestamp;
    const attack = attempt.scenario !== "legit";
    if (decision.action !== "allow") {
      r.stopped++;
      r.firstStoppedAt ??= attempt.timestamp;
    }
    if (decision.action === "block") r.blocked++;
    const charged = decision.action === "allow" || (decision.action === "challenge" && !attack);
    if (charged) {
      await guard.record(attempt);
      if (attack && attempt.outcome === "succeeded") r.confirmed++;
    }
  }

  const out = {} as Record<Scenario, ScenarioResult>;
  for (const [scenario, r] of results) {
    const attack = scenario !== "legit";
    out[scenario] = {
      attempts: r.attempts,
      stopped: r.stopped / r.attempts,
      blocked: r.blocked / r.attempts,
      ...(attack ? {
        minutesToDetect: r.firstStoppedAt === undefined ? undefined : Math.round(((r.firstStoppedAt - r.firstAt!) / 60_000) * 10) / 10,
        cardsConfirmed: r.confirmed,
      } : {}),
    };
  }
  return out;
}

export function format(results: Record<string, ScenarioResult>): string {
  return Object.entries(results).map(([scenario, r]) =>
    `${scenario.padEnd(17)} ${String(r.attempts).padStart(5)} attempts  stopped ${(r.stopped * 100).toFixed(1).padStart(5)}%  blocked ${(r.blocked * 100).toFixed(1).padStart(5)}%`
    + (r.minutesToDetect !== undefined || r.cardsConfirmed !== undefined
      ? `  detected after ${r.minutesToDetect ?? "never"} min, ${r.cardsConfirmed} cards confirmed` : "")).join("\n");
}
