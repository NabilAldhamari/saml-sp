# Contributing to saml-sp

Thanks for helping! This project holds a high bar because mistakes here become
authentication bypasses in other people's products.

## Getting started

```bash
git clone https://github.com/NabilAldhamari/saml-sp.git
cd saml-sp
npm ci
npm test
```

Node.js ≥ 18 is required.

## Development workflow

| Command                           | What it does                                          |
| --------------------------------- | ----------------------------------------------------- |
| `npm test`                        | Run the Jest suite                                    |
| `npm run test:coverage`           | Tests + coverage (90% global thresholds are enforced) |
| `npm run lint` / `lint:fix`       | ESLint (type-aware)                                   |
| `npm run format` / `format:check` | Prettier                                              |
| `npm run typecheck`               | `tsc --noEmit`                                        |
| `npm run build`                   | tsup → dual ESM/CJS + type declarations in `dist/`    |
| `npm run verify`                  | Everything CI runs, in order — must pass before a PR  |

## Ground rules

- **Security first.** Anything touching `src/internal/validateResponse.ts`,
  `signature.ts`, `decrypt.ts`, or `parse.ts` needs tests demonstrating both the
  accepted and the rejected case. New validation must fail _closed_.
- **No new runtime dependencies** without prior discussion in an issue. Zero
  native/compiled dependencies is a feature.
- **Coverage stays ≥ 90%.** Test real crypto — the fixtures in
  `tests/helpers/fixtures.ts` sign and encrypt with the same libraries the
  production path uses. Don't mock the security path.
- **Errors are API.** New failure modes get a typed error class and a stable
  `code`, documented in the README error catalog.
- **Breaking changes** to the public API need a very good reason and a
  migration-guide entry.

## Pull requests

1. Fork, branch from `main`.
2. Make your change with tests and doc updates.
3. `npm run verify` locally.
4. Open the PR with a clear description of _why_. Small, focused PRs merge fast.

## Reporting security issues

Not via issues or PRs — see [SECURITY.md](./SECURITY.md).
