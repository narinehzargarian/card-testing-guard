#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { DEFAULT_MAPPING, type CsvMapping, readAttempts } from "./csv.js";
import { CardTestingGuard } from "./guard.js";
import { scan } from "./scan.js";
import { createGuardServer } from "./server.js";
import { simulate } from "./simulate.js";
import { RedisStore, type RedisLike } from "./store.js";
import type { GuardConfigInput } from "./config.js";

const USAGE = `card-testing-guard: detect and stop card-testing attacks

Usage:
  card-testing-guard scan <payments.csv> [--mapping FILE] [--config FILE] [--json FILE]
      Replays past payment attempts and reports attacks the guard would have caught.
  card-testing-guard serve [--port 8787] [--config FILE]
      Runs the HTTP service. Reads CTG_API_KEY, and optionally STRIPE_WEBHOOK_SECRET and REDIS_URL.
  card-testing-guard simulate [--out traffic.csv] [--days 7] [--seed 1]
      Writes example traffic with attacks, to try the scan command on.

Exit codes: 0 when no attack was found, 1 when one was, 2 for unusable input.`;

export async function main(argv: string[], out: (s: string) => void = console.log, err: (s: string) => void = console.error): Promise<number> {
  const [command, ...rest] = argv;
  try {
    if (command === "scan") return await scanCommand(rest, out, err);
    if (command === "serve") return await serveCommand(rest, out);
    if (command === "simulate") return simulateCommand(rest, out);
    out(USAGE);
    return command === undefined || command === "--help" || command === "-h" ? 0 : 2;
  } catch (error) {
    err(`error: ${(error as Error).message}`);
    return 2;
  }
}

async function scanCommand(args: string[], out: (s: string) => void, err: (s: string) => void): Promise<number> {
  const { values, positionals } = parseArgs({
    args, allowPositionals: true,
    options: { mapping: { type: "string" }, config: { type: "string" }, json: { type: "string" } },
  });
  const file = positionals[0];
  if (!file) throw new Error("give a CSV file to scan");
  const mapping = values.mapping ? { ...DEFAULT_MAPPING, ...(readJson(values.mapping) as Partial<CsvMapping>) } : DEFAULT_MAPPING;
  const { attempts, errors } = readAttempts(readFileSync(file, "utf8"), mapping);
  for (const error of errors.slice(0, 20)) err(`warning: line ${error.line}: ${error.message}`);
  if (errors.length > 20) err(`warning: ${errors.length - 20} more unreadable rows`);

  const report = await scan(attempts, values.config ? (readJson(values.config) as GuardConfigInput) : undefined);
  if (values.json) writeFileSync(values.json, JSON.stringify(report, null, 2));

  out(`${report.attempts} attempts, ${report.declines} declined (${percent(report.declines, report.attempts)})`);
  out(`Before each attempt, the guard would have said: allow ${report.decisions.allow}, challenge ${report.decisions.challenge}, block ${report.decisions.block}`);
  if (report.attackWindows.length === 0) {
    out("No shop-wide attack found.");
  } else {
    out(`${report.attackWindows.length} attack period(s):`);
    for (const w of report.attackWindows) {
      out(`  ${new Date(w.start).toISOString()} to ${new Date(w.end).toISOString()}: ${w.attempts} attempts, ${w.declines} declined; ${w.rules.join(", ")}`);
    }
  }
  if (report.flagged.length > 0) {
    out("Most flagged:");
    for (const f of report.flagged.slice(0, 10)) out(`  ${f.subject}: ${f.attempts} attempts, ${f.rules.join(", ")}`);
  }
  return report.attackWindows.length > 0 ? 1 : 0;
}

async function serveCommand(args: string[], out: (s: string) => void): Promise<number> {
  const { values } = parseArgs({ args, options: { port: { type: "string", default: "8787" }, config: { type: "string" } } });
  const apiKey = process.env.CTG_API_KEY;
  if (!apiKey) throw new Error("set CTG_API_KEY to the key clients must send");
  let store;
  if (process.env.REDIS_URL) {
    const { Redis } = (await import("ioredis")) as unknown as { Redis: new (url: string) => RedisLike };
    store = new RedisStore(new Redis(process.env.REDIS_URL));
  }
  const guard = new CardTestingGuard({
    config: values.config ? (readJson(values.config) as GuardConfigInput) : undefined,
    store,
    onAlert: (alert) => out(JSON.stringify({ alert })),
  });
  const server = createGuardServer({ guard, apiKey, stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET, log: out });
  const port = Number(values.port);
  await new Promise<void>((resolve) => server.listen(port, resolve));
  out(`listening on port ${port}${store ? " with Redis" : " with in-memory state"}`);
  await new Promise<void>((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return 0;
}

function simulateCommand(args: string[], out: (s: string) => void): number {
  const { values } = parseArgs({
    args, options: { out: { type: "string", default: "traffic.csv" }, days: { type: "string", default: "7" }, seed: { type: "string", default: "1" } },
  });
  const attempts = simulate({ days: Number(values.days), seed: Number(values.seed), launchDay: true });
  const columns = ["id", "timestamp", "amount", "outcome", "decline_code", "card_fingerprint", "bin", "last4", "ip", "email", "session_id"];
  const rows = attempts.map((a) => [
    a.id, new Date(a.timestamp).toISOString(), (a.amount / 100).toFixed(2), a.outcome, a.declineCode ?? "",
    a.cardFingerprint ?? "", a.bin ?? "", a.last4 ?? "", a.ip ?? "", a.email ?? "", a.sessionId ?? "",
  ].join(","));
  writeFileSync(values.out, [columns.join(","), ...rows].join("\n") + "\n");
  out(`Wrote ${attempts.length} attempts to ${values.out}. Try: card-testing-guard scan ${values.out}`);
  return 0;
}

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(file, "utf8"));
}

function percent(part: number, whole: number): string {
  return whole === 0 ? "0%" : `${((100 * part) / whole).toFixed(1)}%`;
}

const invokedDirectly = process.argv[1] !== undefined && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (invokedDirectly || process.argv[1]?.endsWith("card-testing-guard")) {
  main(process.argv.slice(2)).then((code) => {
    process.exitCode = code;
  });
}
