# card-testing-guard

Detects and stops **card-testing attacks** on online checkouts, with rules you can read and no training data needed.

Card testing is when fraudsters run stolen card numbers through a shop's checkout, usually with tiny charges, to find out which cards still work. The shop pays decline fees, gets chargebacks, and can lose its payment account. Small shops, donation pages, and free trials are frequent targets, and they rarely have fraud tools.

`card-testing-guard` sits in front of your checkout:

- **Before charging**, it tells you to **allow**, **challenge** (for example, show a CAPTCHA), or **block**, and why.
- **After the processor answers**, it records the result and watches for attacks spread across many IPs.
- **For past data**, it scans an export of payment attempts and tells you whether you were attacked, and when.

## Install

Requires Node.js 20 or newer. Install straight from GitHub, which builds the package on install:

```sh
npm install github:narinehzargarian/card-testing-guard#v0.1.0
```

The commands below use `npx card-testing-guard`, which works once it's installed in your project.

## Use it in your checkout

```js
import { CardTestingGuard } from "card-testing-guard";

const guard = new CardTestingGuard({
  onAlert: (alert) => notifyTeam(alert.message),   // Called once when an attack starts
});

// Before charging the card
const decision = await guard.check({
  amount: 1500,                       // In cents
  ip: req.ip,
  email: req.body.email,
  sessionId: req.sessionID,
  cardFingerprint,                    // If your processor gives one before charging
});
if (decision.action === "block") return res.status(402).send("Payment could not be processed");
if (decision.action === "challenge") return res.json({ needsCaptcha: true });

// After the processor answers
await guard.record({
  id: charge.id,
  timestamp: Date.now(),
  amount: 1500,
  outcome: charge.paid ? "succeeded" : "declined",
  declineCode: charge.failure_code,
  cardFingerprint, ip: req.ip, email: req.body.email, sessionId: req.sessionID,
});
```

Every decision explains itself:

```json
{
  "action": "block",
  "mode": "normal",
  "reasons": [
    { "rule": "distinct_cards", "action": "block", "subject": "ip:198.51.100.7", "value": 7, "threshold": 5,
      "message": "7 different cards from this ip in the last hour" }
  ]
}
```

Don't tell a blocked customer which rule fired. A generic message gives a tester nothing to adjust to.

## Or run it as a service

For checkouts not written in JavaScript:

```sh
CTG_API_KEY=choose-a-long-random-key npx card-testing-guard serve --port 8787
```

| Endpoint | Purpose |
|---|---|
| `POST /v1/check` | Before charging. Returns the decision |
| `POST /v1/attempts` | After the processor answers |
| `POST /webhooks/stripe` | Stripe `charge.succeeded` and `charge.failed` events, signature-checked |
| `GET /v1/status` | Normal or elevated mode, and recent shop-wide counts |
| `GET /healthz` | Health check |

Send `Authorization: Bearer <CTG_API_KEY>` on `/v1` requests. Set `STRIPE_WEBHOOK_SECRET` to turn on the Stripe endpoint, and `REDIS_URL` to share state across several servers. Without Redis, state lives in memory and resets on restart.

**Stripe:** charge events don't include the customer's IP or session. Add them to the PaymentIntent's metadata as `ip` and `session_id`, and the webhook picks them up.

## Check whether you were attacked

```sh
npx card-testing-guard scan payments.csv --mapping mapping.json
```

This is real output from a week of simulated traffic with four attacks:

```
3961 attempts, 784 declined (19.8%)
Before each attempt, the guard would have said: allow 3356, challenge 459, block 146
4 attack period(s):
  2026-03-03T08:01:06.000Z to 2026-03-03T09:35:26.224Z: 150 attempts, 125 declined; decline_rate_spike
  2026-03-04T07:03:16.000Z to 2026-03-04T09:08:38.955Z: 273 attempts, 201 declined; small_payment_spike
  2026-03-05T10:01:40.000Z to 2026-03-05T12:00:57.680Z: 146 attempts, 99 declined; bin_enumeration
  2026-03-06T17:55:06.215Z to 2026-03-06T23:15:47.825Z: 211 attempts, 100 declined; slow_decline_rate_spike
Most flagged:
  email:buyer123@example.net: 148 attempts, checks, declines, distinct_cards, probing_declines, small_attempts
  ip:59.84.127.234: 148 attempts, checks, declines, distinct_cards, probing_declines, small_attempts
  bin:414720: 114 attempts, bin_enumeration
```

It exits with code 1 when it finds an attack, so it can run on a schedule. The mapping file says which columns to use, so any processor's export works:

```json
{
  "id": "Charge ID",
  "timestamp": "Created (UTC)",
  "amount": "Amount",
  "outcome": "Status",
  "declinedValues": ["failed"],
  "declineCode": "Decline Reason",
  "cardFingerprint": "Card Fingerprint",
  "email": "Customer Email"
}
```

Optional fields are `bin`, `last4`, `ip`, `customerId`, and `sessionId`. `timestampFormat` can be `iso`, `seconds`, or `milliseconds`, and `amountUnit` can be `major` (1.50) or `minor` (150). Your processor's export column names may differ from this example, so check the header row.

Try it on generated data:

```sh
npx card-testing-guard simulate --out traffic.csv && npx card-testing-guard scan traffic.csv
```

## The rules

**Per customer.** Each rule is counted separately per IP, email, customer ID, and session. Emails are normalized, so `j.ane+1@gmail.com` counts as `jane@gmail.com`.

| Rule | Challenge at | Block at | Window |
|---|---|---|---|
| Different cards | 3 | 5 | 1 hour |
| Declines | 3 | 6 | 10 minutes |
| Declines for wrong card details, like a bad CVC | 2 | 4 | 10 minutes |
| Small payments, $3 or less | 4 | 8 | 10 minutes |
| Checkout attempts | 10 | 20 | 10 minutes |

**Shop-wide.** These catch attacks spread across many IPs:

| Rule | Fires when |
|---|---|
| Decline spike | At least 12 declines in 10 minutes, and a decline rate of at least 30% and 3 times the usual rate |
| Slow decline spike | The same check over the last hour, with at least 20 declines. This catches slow attacks |
| Small-payment spike | At least 15 small payments in 10 minutes, and 4 times the usual number |
| BIN sweep | At least 6 different cards with the same first digits in 10 minutes, at least 5 of them declined |

A shop-wide rule calls `onAlert` once and turns on **elevated mode** for 30 minutes. In elevated mode, small payments and recently declined customers get a challenge. It stays on while small-payment attempts keep arriving well above normal, because a stopped bot produces no more declines and would otherwise end the alert.

"Usual" means the previous 24 hours, not counting the current hour, so an attack can't raise its own baseline.

All limits are settings:

```js
new CardTestingGuard({ config: { smallAmount: 100, perIdentity: { declines: { challenge: 4, block: 8 } } } });
```

## How well it works

There's no public dataset of real card-testing attacks, so I measured it on simulated traffic. That's a week of ordinary checkouts at about 300 a day, including real customers who are declined and retry, and a launch day at five times the normal traffic. Four kinds of attack were added. Results across five random seeds:

| Traffic | Stopped | Blocked | Detected after | Stolen cards confirmed |
|---|---|---|---|---|
| Real customers | 0.2% to 0.6%, all challenges | 0% | | |
| One IP, 150 cards in 15 minutes | 98.7% | 87.3% | seconds | 0 |
| 250 attempts from rotating proxies | 94% to 95% | 0% | about 3 minutes | 0 to 3 |
| BIN sweep | 94% to 95% | 0% | about 2 minutes | 0 to 2 |
| Slow drip, one every 2 to 4 minutes for 6 hours | 48% to 84% | 0% | 1 to 3 hours | 0 to 7 |

"Stopped" means challenged or blocked. The evaluation assumes bots fail a challenge and people pass it. The real-customer challenges all happened during attacks.

**What this means, honestly:**

- These numbers come from my simulator, so they show the rules work on these patterns. They don't promise the same results on your traffic. Start with `scan` on your own history before blocking anyone.
- A slow attack from rotating IPs is the hardest case. It's caught, but only after an hour or more.
- A challenge only helps if it actually stops bots. Use a real CAPTCHA, or 3-D Secure.
- This doesn't replace your processor's fraud tools. It adds rules you control in front of them.

## Design decisions

**Rules, not a model.** A small shop has no labeled fraud data to train on, and a shop owner can act on a rule they can read.

**Counted at checkout, not only at the processor.** Bots that get blocked never reach the processor, so the guard also counts its own checks. Otherwise, blocking an attack would make it look over.

**Repeats don't count twice.** Each attempt ID is recorded once, so a webhook delivered twice can't trigger a block.

**Bounded memory.** Shop-wide counts are kept per minute and per hour, so memory doesn't grow with traffic. Per-customer windows expire after an hour.

**Fails safe.** A broken alert handler never stops a payment from being recorded.

## Limits

- Elevated mode is shop-wide, so during an attack some real customers paying small amounts will see a challenge.
- With the in-memory store, each server has its own view. Use Redis when you run more than one.
- The Stripe webhook follows Stripe's documented event and signature format, and is tested against constructed events, not against a live Stripe account. Check the mapping with one of your own test-mode events.
- The service has a body size limit and API-key authentication, but no rate limiting of its own. Put it behind your own network or gateway.

## Development

```sh
npm install
npm test                                   # Add REDIS_URL=redis://localhost:6379 for the Redis tests
npm run build
```

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE)
