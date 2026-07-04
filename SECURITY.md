# Security Policy

saml-sp is security-critical software: it decides who is authenticated in the
applications that use it. We take reports seriously and appreciate the time it
takes to make one.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via [GitHub private vulnerability reporting](https://github.com/NabilAldhamari/saml-sp/security/advisories/new)
("Report a vulnerability" on the repository's Security tab).

Please include:

- the version affected,
- a description of the issue and its impact (e.g. "signature check bypass when …"),
- a proof of concept if you have one (a failing test case is perfect).

You can expect an acknowledgement within a few days. Fixes for confirmed
vulnerabilities are released as fast as practical, with a GitHub security
advisory and CVE where appropriate. Credit is given unless you prefer otherwise.

## Supported versions

| Version | Supported                                                                                      |
| ------- | ---------------------------------------------------------------------------------------------- |
| 3.x     | ✅                                                                                             |
| < 3.0   | ❌ — v2 performs no signature verification and must not be used in production. Upgrade to 3.x. |

## Security design notes

The validation pipeline and its attack-specific defences (signature wrapping,
comment injection, replay, entity expansion, algorithm downgrade) are documented
in the [Security model](./README.md#the-security-model) section of the README.
The test suite contains explicit regression tests for each of these defences —
please keep them passing.

## Test key material

The PEM private keys under `tests/helpers/keys.ts` are **fixtures generated for
this test suite only**. They protect nothing, are not used anywhere outside
tests, and are intentionally committed. Secret scanners flagging them can safely
allowlist that file.
