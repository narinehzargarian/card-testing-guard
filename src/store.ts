/**
 * Where recent activity is kept. Memory works for a single server; Redis shares state between
 * servers and survives restarts.
 *
 * Two kinds of data:
 * - Windows: time-stamped members, so "how many distinct cards has this IP used in the last hour"
 *   is a count. Adding a member again refreshes its time instead of counting it twice.
 * - Counters: shop-wide totals per time bucket, which stay small no matter how busy the shop is.
 */
export interface Store {
  /** Adds or refreshes a member, and drops members older than `retainMs`. */
  addToWindow(key: string, member: string, timestamp: number, retainMs: number): Promise<void>;
  /** Members seen at or after `since`. */
  countWindow(key: string, since: number): Promise<number>;
  increment(key: string, by: number, retainMs: number): Promise<void>;
  /** Values of several counters; missing ones are 0. */
  getCounters(keys: string[]): Promise<number[]>;
  /** Stores a value until it expires. */
  setValue(key: string, value: string, retainMs: number): Promise<void>;
  getValue(key: string): Promise<string | undefined>;
}

export class MemoryStore implements Store {
  private readonly windows = new Map<string, Map<string, number>>();
  private readonly counters = new Map<string, { value: number; expires: number }>();
  private readonly values = new Map<string, { value: string; expires: number }>();
  private operations = 0;

  /** @param clock used for expiring counters and values; replaying old data passes its own clock */
  constructor(private readonly clock: () => number = Date.now) {}

  async addToWindow(key: string, member: string, timestamp: number, retainMs: number): Promise<void> {
    let window = this.windows.get(key);
    if (!window) {
      window = new Map();
      this.windows.set(key, window);
    }
    window.set(member, Math.max(timestamp, window.get(member) ?? -Infinity));
    const cutoff = timestamp - retainMs;
    if (window.size > 64) {
      for (const [m, t] of window) {
        if (t < cutoff) window.delete(m);
      }
    }
    this.sweep();
  }

  async countWindow(key: string, since: number): Promise<number> {
    let count = 0;
    for (const t of this.windows.get(key)?.values() ?? []) {
      if (t >= since) count++;
    }
    return count;
  }

  async increment(key: string, by: number, retainMs: number): Promise<void> {
    const now = this.clock();
    const existing = this.counters.get(key);
    const value = existing && existing.expires > now ? existing.value + by : by;
    this.counters.set(key, { value, expires: now + retainMs });
  }

  async getCounters(keys: string[]): Promise<number[]> {
    const now = this.clock();
    return keys.map((key) => {
      const entry = this.counters.get(key);
      return entry && entry.expires > now ? entry.value : 0;
    });
  }

  async setValue(key: string, value: string, retainMs: number): Promise<void> {
    this.values.set(key, { value, expires: this.clock() + retainMs });
  }

  async getValue(key: string): Promise<string | undefined> {
    const entry = this.values.get(key);
    return entry && entry.expires > this.clock() ? entry.value : undefined;
  }

  /** Every so often, drops whole windows nothing has touched in a day, so memory can't grow forever. */
  private sweep(): void {
    if (++this.operations % 5000 !== 0) return;
    const cutoff = this.clock() - 24 * 3600_000;
    for (const [key, window] of this.windows) {
      let newest = -Infinity;
      for (const t of window.values()) newest = Math.max(newest, t);
      if (newest < cutoff) this.windows.delete(key);
    }
    const now = this.clock();
    for (const [key, entry] of this.counters) if (entry.expires <= now) this.counters.delete(key);
    for (const [key, entry] of this.values) if (entry.expires <= now) this.values.delete(key);
  }
}

/** The few ioredis methods used, so any compatible client works. */
export interface RedisLike {
  multi(): {
    zadd(key: string, score: number, member: string): unknown;
    zremrangebyscore(key: string, min: string | number, max: string | number): unknown;
    pexpire(key: string, ms: number): unknown;
    incrby(key: string, by: number): unknown;
    exec(): Promise<unknown>;
  };
  zcount(key: string, min: string | number, max: string | number): Promise<number>;
  mget(...keys: string[]): Promise<(string | null)[]>;
  set(key: string, value: string, mode: "PX", ms: number): Promise<unknown>;
  get(key: string): Promise<string | null>;
}

export class RedisStore implements Store {
  /** @param prefix keeps this tool's keys apart from anything else in the same Redis */
  constructor(private readonly redis: RedisLike, private readonly prefix = "ctg:") {}

  async addToWindow(key: string, member: string, timestamp: number, retainMs: number): Promise<void> {
    const k = this.prefix + key;
    // A newer timestamp replaces an older one, so re-adding refreshes instead of duplicating.
    const tx = this.redis.multi();
    tx.zadd(k, timestamp, member);
    tx.zremrangebyscore(k, "-inf", `(${timestamp - retainMs}`);
    tx.pexpire(k, retainMs);
    await tx.exec();
  }

  async countWindow(key: string, since: number): Promise<number> {
    return this.redis.zcount(this.prefix + key, since, "+inf");
  }

  async increment(key: string, by: number, retainMs: number): Promise<void> {
    const tx = this.redis.multi();
    tx.incrby(this.prefix + key, by);
    tx.pexpire(this.prefix + key, retainMs);
    await tx.exec();
  }

  async getCounters(keys: string[]): Promise<number[]> {
    if (keys.length === 0) return [];
    const values = await this.redis.mget(...keys.map((k) => this.prefix + k));
    return values.map((v) => (v === null ? 0 : Number(v)));
  }

  async setValue(key: string, value: string, retainMs: number): Promise<void> {
    await this.redis.set(this.prefix + key, value, "PX", retainMs);
  }

  async getValue(key: string): Promise<string | undefined> {
    return (await this.redis.get(this.prefix + key)) ?? undefined;
  }
}
