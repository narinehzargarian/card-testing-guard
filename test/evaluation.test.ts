import { describe, expect, it } from "vitest";
import { evaluate, format } from "./evaluation.js";

/**
 * Floors, not targets: a change that makes the guard noticeably worse on simulated traffic fails
 * here. The printed numbers are the ones quoted in the README.
 */
describe("evaluation on simulated traffic", () => {
  it("stops attacks while rarely bothering real customers", async () => {
    for (const seed of [1, 2, 3, 4, 5]) {
      const results = await evaluate({ seed, days: 7, perDay: 300, launchDay: true });
      console.log(`seed ${seed}\n${format(results)}`);
      expect(results.legit.blocked).toBe(0);
      expect(results.legit.stopped).toBeLessThan(0.01);
      expect(results.single_ip_burst.stopped).toBeGreaterThan(0.95);
      expect(results.rotating_proxies.stopped).toBeGreaterThan(0.85);
      expect(results.bin_enumeration.stopped).toBeGreaterThan(0.85);
      expect(results.slow_drip.stopped).toBeGreaterThan(0.4);
    }
  }, 120_000);
});
