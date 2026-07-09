# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/).

## [3.1.0](https://github.com/NabilAldhamari/saml-sp/compare/v3.0.0...v3.1.0) (2026-07-09)


### Features

* add Single Logout (SLO) over the HTTP-Redirect binding ([c04ed14](https://github.com/NabilAldhamari/saml-sp/commit/c04ed146bc2645a206e88eccc1d7da94a4032cce))
* add Single Logout (SLO) support ([6f4a3e5](https://github.com/NabilAldhamari/saml-sp/commit/6f4a3e5595e4fea740d2390b5c9ea6cbfc386315))


### Documentation

* readme cleanup ([1370ed1](https://github.com/NabilAldhamari/saml-sp/commit/1370ed1baecf584341b8d708976b82feff6997d9))

## [3.0.0] — 2026-07-04

Security-focused rewrite. **v2 must not be used in production** — it performed
no signature verification, allowing anyone to forge a SAML response.

### Added

- **Full response validation pipeline**: XML signature verification
  (response- and assertion-level, via `xml-crypto`), issuer checks,
  `Destination`/`Recipient` checks, `AudienceRestriction`, `NotBefore`/`NotOnOrAfter`
  with configurable clock skew, `samlp:Status` handling, `InResponseTo`
  correlation, and per-assertion replay protection.
- Defences against signature wrapping (direct-child signatures only, reference-URI
  and unique-ID checks, extraction from verified content only), entity expansion
  (DOCTYPE rejection), NameID comment injection, algorithm downgrade (SHA-1
  rejected by default; `allowSha1` opt-out), and oversized payloads (`maxResponseSize`).
- `IdentityProvider` with `fromMetadata()` / `fromUrl()` — one-paste IdP setup,
  multi-certificate rollover support, federation (`EntitiesDescriptor`) handling.
- Typed error hierarchy (`SAMLError` and 11 subclasses) with stable `code`
  values and actionable messages.
- Spec-compliant HTTP-Redirect binding (DEFLATE + base64 + optional query
  signing) and HTTP-POST binding (auto-submitting form, optional embedded
  XML signature) for AuthnRequests. `RelayState`, `ForceAuthn`, `IsPassive`.
- Pluggable `RequestStore` / `ReplayCache` interfaces with bounded in-memory
  defaults, for multi-instance deployments.
- Dual ESM + CJS build with complete TypeScript declarations.
- CI (lint/typecheck/test matrix/build smoke tests), CodeQL, dependabot,
  npm publish with provenance; test coverage enforced at ≥90%.

### Changed

- `ServiceProvider` is now constructed synchronously with a single config
  object and requires IdP details (`idp`) up front.
- SP metadata now tells the truth: signing flags reflect configuration, no
  phantom `SingleLogoutService`, `validUntil` only on request, and the
  AuthnRequest `Issuer` is the SP entityId (was: the ACS URL).

### Removed

- **Breaking:** `SAMLRequest` and `SAMLResponse` classes (no signature
  verification — unsafe by design). See the README migration guide.
- **Breaking:** automatic key generation inside `ServiceProvider.create()`;
  use `ServiceProvider.generateKeyPair()` once and persist the result.

## [2.0.1] and earlier

See git history. Do not use in production.
