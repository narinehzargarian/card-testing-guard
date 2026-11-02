import type { Attempt } from "./types.js";

/** Splits CSV text into rows, handling quoted fields, doubled quotes, and CRLF line ends. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      quoted = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      if (row.some((value) => value !== "")) rows.push(row);
      row = [];
      field = "";
    } else {
      field += c;
    }
  }
  row.push(field);
  if (row.some((value) => value !== "")) rows.push(row);
  return rows;
}

/**
 * Which columns hold what. Column names ignore case, spaces, and underscores.
 *
 * `timestampFormat` is "iso" (2026-03-02T14:05:00Z or 2026-03-02 14:05:00, read as UTC),
 * "seconds", or "milliseconds". `amountUnit` is "major" for 1.50, or "minor" for 150.
 * A row counts as declined when its outcome column holds one of `declinedValues`.
 */
export interface CsvMapping {
  id?: string;
  timestamp: string;
  timestampFormat?: "iso" | "seconds" | "milliseconds";
  amount: string;
  amountUnit?: "major" | "minor";
  outcome: string;
  declinedValues?: string[];
  declineCode?: string;
  cardFingerprint?: string;
  bin?: string;
  last4?: string;
  ip?: string;
  email?: string;
  customerId?: string;
  sessionId?: string;
}

export const DEFAULT_MAPPING: CsvMapping = {
  id: "id",
  timestamp: "timestamp",
  timestampFormat: "iso",
  amount: "amount",
  amountUnit: "major",
  outcome: "outcome",
  declinedValues: ["declined", "failed", "failure"],
  declineCode: "decline_code",
  cardFingerprint: "card_fingerprint",
  bin: "bin",
  last4: "last4",
  ip: "ip",
  email: "email",
  customerId: "customer_id",
  sessionId: "session_id",
};

export interface RowError {
  line: number;
  message: string;
}

/** Reads attempts, keeping good rows and reporting bad ones by line number. */
export function readAttempts(text: string, mapping: CsvMapping = DEFAULT_MAPPING): { attempts: Attempt[]; errors: RowError[] } {
  const rows = parseCsv(text.replace(/^﻿/, ""));
  const header = rows[0];
  if (!header) throw new Error("the file is empty");
  const normalize = (name: string) => name.toLowerCase().replace(/[\s_-]/g, "");
  const index = new Map(header.map((name, i) => [normalize(name), i]));
  const column = (name: string | undefined, required = false): number | undefined => {
    if (!name) return undefined;
    const found = index.get(normalize(name));
    if (found === undefined && required) throw new Error(`column "${name}" not found; the header has ${header.join(", ")}`);
    return found;
  };
  const columns = {
    id: column(mapping.id),
    timestamp: column(mapping.timestamp, true)!,
    amount: column(mapping.amount, true)!,
    outcome: column(mapping.outcome, true)!,
    declineCode: column(mapping.declineCode),
    cardFingerprint: column(mapping.cardFingerprint),
    bin: column(mapping.bin),
    last4: column(mapping.last4),
    ip: column(mapping.ip),
    email: column(mapping.email),
    customerId: column(mapping.customerId),
    sessionId: column(mapping.sessionId),
  };
  const declined = new Set((mapping.declinedValues ?? DEFAULT_MAPPING.declinedValues ?? []).map((v) => v.toLowerCase()));
  const attempts: Attempt[] = [];
  const errors: RowError[] = [];
  const ids = new Set<string>();
  rows.slice(1).forEach((row, i) => {
    const line = i + 2;
    const get = (c: number | undefined) => (c === undefined ? "" : (row[c] ?? "").trim());
    const optional = (c: number | undefined) => get(c) || undefined;
    try {
      const timestamp = parseTimestamp(get(columns.timestamp), mapping.timestampFormat ?? "iso");
      const amount = parseAmount(get(columns.amount), mapping.amountUnit ?? "major");
      const id = get(columns.id) || `row-${line}`;
      if (ids.has(id)) throw new Error(`id "${id}" appears more than once`);
      ids.add(id);
      attempts.push({
        id,
        timestamp,
        amount,
        outcome: declined.has(get(columns.outcome).toLowerCase()) ? "declined" : "succeeded",
        declineCode: optional(columns.declineCode),
        cardFingerprint: optional(columns.cardFingerprint),
        bin: optional(columns.bin),
        last4: optional(columns.last4),
        ip: optional(columns.ip),
        email: optional(columns.email),
        customerId: optional(columns.customerId),
        sessionId: optional(columns.sessionId),
      });
    } catch (error) {
      errors.push({ line, message: (error as Error).message });
    }
  });
  attempts.sort((a, b) => a.timestamp - b.timestamp || a.id.localeCompare(b.id));
  return { attempts, errors };
}

function parseTimestamp(value: string, format: "iso" | "seconds" | "milliseconds"): number {
  if (!value) throw new Error("timestamp is empty");
  if (format !== "iso") {
    if (!/^\d+(\.\d+)?$/.test(value)) throw new Error(`timestamp "${value}" is not a number`);
    return Math.round(Number(value) * (format === "seconds" ? 1000 : 1));
  }
  // Without a time zone, treat the time as UTC rather than the machine's local zone.
  const iso = /[zZ]|[+-]\d\d:?\d\d$/.test(value) ? value : `${value.replace(" ", "T")}Z`;
  const ms = Date.parse(iso);
  if (Number.isNaN(ms)) throw new Error(`timestamp "${value}" is not a date`);
  return ms;
}

function parseAmount(value: string, unit: "major" | "minor"): number {
  const cleaned = value.replace(/[$€£,\s]/g, "");
  if (!/^-?\d+(\.\d+)?$/.test(cleaned)) throw new Error(`amount "${value}" is not a number`);
  const amount = Math.abs(Number(cleaned));
  return unit === "minor" ? Math.round(amount) : Math.round(amount * 100);
}
