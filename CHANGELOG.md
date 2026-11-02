# Changelog

## 0.1.0

First release.

- Checkout decisions (allow, challenge, block) with a reason for each.
- Per-customer rules: different cards, declines, declines for wrong card details, small payments, and checkout attempts.
- Shop-wide detection: decline spikes over 10 minutes and an hour, small-payment spikes, and BIN sweeps, with an elevated mode.
- Memory and Redis stores.
- HTTP service with API-key authentication and signature-checked Stripe webhooks.
- `scan` command for past payment exports, and `simulate` for example traffic.
