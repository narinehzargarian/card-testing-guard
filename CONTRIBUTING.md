# Contributing

Thanks for helping.

## Most useful: what it missed, and what it got wrong

If the guard missed an attack on your shop, or challenged real customers, please open an issue describing the pattern:

- Roughly how many attempts there were, over how long.
- How many IPs, emails, and cards were involved.
- The amounts and decline codes.

**Never post real card data, emails, or IP addresses.** Describe the shape of the traffic, or replace the values with made-up ones.

## Code changes

1. Open an issue first for anything bigger than a small fix.
2. Add a test that fails without your change.
3. Run `npm test`, with `REDIS_URL` set if you touched the store.
4. If you change a rule or a default, include the evaluation output from before and after. `npm test` prints it.

Keep every decision explainable. A rule that can't say why it fired doesn't belong here.
