<h1 align="center">saml-sp</h1>

<p align="center"><b>The SAML 2.0 Service Provider you can't hold wrong.</b></p>

<p align="center">
  <a href="https://github.com/NabilAldhamari/saml-sp/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/NabilAldhamari/saml-sp/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://www.npmjs.com/package/saml-sp"><img alt="npm version" src="https://img.shields.io/npm/v/saml-sp"></a>
  <a href="https://www.npmjs.com/package/saml-sp"><img alt="npm downloads" src="https://img.shields.io/npm/dm/saml-sp"></a>
  <a href="./LICENSE"><img alt="MIT license" src="https://img.shields.io/npm/l/saml-sp"></a>
  <img alt="types included" src="https://img.shields.io/badge/types-included-blue">
  <img alt="node >= 18" src="https://img.shields.io/node/v/saml-sp">
</p>

Add enterprise SSO (Okta, Microsoft Entra ID, Google Workspace, AWS IAM Identity Center, Keycloak, …) to any Node.js app in minutes — with the security work already done for you.

```ts
import { ServiceProvider, IdentityProvider } from "saml-sp";

const sp = new ServiceProvider({
  entityId: "urn:example:my-app",
  assertionConsumerServiceUrl: "https://my-app.example.com/saml/acs",
  idp: await IdentityProvider.fromUrl("https://idp.example.com/metadata"), // paste & go
});

// 1. Send the user to the IdP
const { url } = await sp.createLoginRequest();

// 2. Validate what comes back — signatures, audience, timing, replay: all checked
const { profile } = await sp.consume(req);
console.log(profile.nameId, profile.attributes);
```

---

## Why saml-sp?

SAML is where authentication bugs become account takeovers. Most libraries make you assemble the security yourself — pick a validator, wire the clock-skew, remember to check the audience. **saml-sp is secure by default: if it validates, it's safe; if it isn't safe, you get a typed error explaining exactly why.**

|                                                         |    saml-sp     | @node-saml/node-saml |                 samlify                  | saml2-js |
| ------------------------------------------------------- | :------------: | :------------------: | :--------------------------------------: | :------: |
| Signature verification on by default                    |       ✅       |          ✅          | ⚠️ requires wiring an external validator |    ✅    |
| One-paste IdP metadata setup (`fromMetadata`/`fromUrl`) |       ✅       |          ❌          |                    ✅                    |    ❌    |
| Typed error classes with stable codes                   |       ✅       |          ❌          |                    ❌                    |    ❌    |
| Replay protection built in                              |       ✅       |      ⚠️ partial      |                    ❌                    |    ❌    |
| Signature-wrapping attack defences                      |       ✅       |          ✅          |                    ⚠️                    |    ⚠️    |
| SHA-1 rejected by default                               |       ✅       |          ❌          |                    ❌                    |    ❌    |
| Framework-agnostic (Express, Fastify, raw `http`, …)    |       ✅       |          ✅          |                    ✅                    |    ✅    |
| Zero native/compiled dependencies                       |       ✅       |          ✅          |                    ❌                    |    ✅    |
| TypeScript-first, dual ESM + CJS                        |       ✅       |     ⚠️ CJS only      |                    ⚠️                    |    ❌    |
| Config surface                                          | 1 small object |   ~40 flat options   |                  large                   |  large   |

If you need an Identity Provider implementation or Single Logout today, use [`samlify`](https://github.com/tngan/samlify) or [`@node-saml/node-saml`](https://github.com/node-saml/node-saml) — they are good libraries. If you need to **be a Service Provider** and want it correct on the first try, use saml-sp.

## Installation

```bash
npm install saml-sp
```

Node.js ≥ 18. TypeScript types included. ESM and CommonJS both supported.

## 5-minute quick start (Express)

**Step 1 — one-time setup.** Generate a keypair and print your SP metadata:

```ts
import fs from "node:fs";
import { ServiceProvider } from "saml-sp";

const keys = ServiceProvider.generateKeyPair();
fs.writeFileSync("sp-key.pem", keys.privateKey); // keep secret!
fs.writeFileSync("sp-cert.pem", keys.certificate);
```

> Generate **once** and reuse. Regenerating on every boot silently breaks the trust
> relationship registered with your IdP.

**Step 2 — the app.**

```ts
import express from "express";
import fs from "node:fs";
import { ServiceProvider, IdentityProvider, SAMLValidationError } from "saml-sp";

const idp = IdentityProvider.fromMetadata(
  fs.readFileSync("idp-metadata.xml", "utf8") // downloaded from your IdP
);

const sp = new ServiceProvider({
  entityId: "urn:example:my-app",
  assertionConsumerServiceUrl: "https://my-app.example.com/saml/acs",
  idp,
  privateKey: fs.readFileSync("sp-key.pem", "utf8"),
  certificate: fs.readFileSync("sp-cert.pem", "utf8"),
});

const app = express();

// Serve your SP metadata — register this URL (or its output) with the IdP.
app.get("/saml/metadata", (_req, res) => {
  res.type("application/xml").send(sp.metadata());
});

// Kick off login.
app.get("/login", async (_req, res) => {
  const { url } = await sp.createLoginRequest({ relayState: "/dashboard" });
  res.redirect(url);
});

// The IdP POSTs the SAML response here.
app.post("/saml/acs", async (req, res) => {
  try {
    const { profile, relayState } = await sp.consume(req);
    // ✅ Authenticated. Establish YOUR session here (cookie, JWT, …).
    console.log("user:", profile.nameId, profile.attributes);
    res.redirect(relayState === "/dashboard" ? relayState : "/");
  } catch (err) {
    if (err instanceof SAMLValidationError) {
      console.warn("SAML validation failed:", err.code, err.message);
      return res.status(401).send("Login failed.");
    }
    throw err;
  }
});

app.listen(3000);
```

That's the whole integration. No body-parser configuration needed for the ACS route — `sp.consume(req)` reads the raw request itself (with a size cap). If you already use `express.urlencoded()`, `sp.consume(req.body)` works too.

A runnable version lives in [`examples/express`](./examples/express).

## Setting up your IdP

<details>
<summary><b>Okta</b></summary>

1. Admin console → Applications → Create App Integration → **SAML 2.0**.
2. Single sign-on URL: your ACS URL (e.g. `https://my-app.example.com/saml/acs`).
3. Audience URI (SP Entity ID): your `entityId` (e.g. `urn:example:my-app`).
4. After creation: **Sign On tab → SAML Signing Certificates → Actions → View IdP metadata**. Save that XML and feed it to `IdentityProvider.fromMetadata()` (or use the metadata URL with `fromUrl`).

Okta signs assertions with SHA-256 by default — no extra options needed.

</details>

<details>
<summary><b>Microsoft Entra ID (Azure AD)</b></summary>

1. Entra admin center → Enterprise applications → New application → Create your own → _non-gallery_.
2. Single sign-on → SAML. Set **Identifier (Entity ID)** to your `entityId` and **Reply URL** to your ACS URL.
3. Copy the **App Federation Metadata Url** from section 3 and use `IdentityProvider.fromUrl(metadataUrl)`.

Entra signs the **assertion** (not the response) by default, which saml-sp accepts out of the box.

</details>

<details>
<summary><b>Google Workspace</b></summary>

1. Admin console → Apps → Web and mobile apps → Add custom SAML app.
2. Download the **IdP metadata** on step 2 → `IdentityProvider.fromMetadata()`.
3. ACS URL = your ACS endpoint, Entity ID = your `entityId`.

</details>

<details>
<summary><b>AWS IAM Identity Center</b></summary>

1. Applications → Add application → _custom SAML 2.0 application_.
2. Download the **IAM Identity Center SAML metadata file** → `IdentityProvider.fromMetadata()`.
3. Set the application ACS URL and audience to your ACS URL / `entityId`.

AWS requires a real `AuthnRequest` (a bare IdP-URL redirect is not enough) — `createLoginRequest()` produces exactly that.

</details>

<details>
<summary><b>Keycloak</b></summary>

1. Create a client with protocol **saml**; Client ID = your `entityId`.
2. Metadata is at `https://<host>/realms/<realm>/protocol/saml/descriptor` → `IdentityProvider.fromUrl()`.
3. Point the client's _Valid redirect URIs_ / ACS at your ACS URL.

</details>

## The security model

Every response passes through a strict pipeline. There is no way to get a `profile` out of saml-sp without all of these passing:

1. **Size cap** (1 MiB default) and base64 sanity checks.
2. **Hardened XML parsing** — `DOCTYPE` is rejected outright (entity-expansion attacks), parser errors abort instead of producing a partial tree, all element lookups are namespace-aware.
3. **Status check** — non-`Success` becomes a `ResponseStatusError` carrying the IdP's status codes.
4. **Addressing** — `Destination` and `SubjectConfirmationData/@Recipient` must match your ACS URL; `Issuer` must match the IdP's entityId (response _and_ assertion level).
5. **Signature verification** (via [`xml-crypto`](https://github.com/node-saml/xml-crypto)) — the assertion must be covered by a valid signature: either a signed `Response` envelope or a signed `Assertion`. Defences against known attacks:
   - only signatures that are **direct children** of the element they sign are accepted;
   - the signature's reference URI must match that element's `ID`, and that ID must be **unique** in the document (signature wrapping);
   - exactly one assertion per response — ambiguous responses are rejected;
   - after verification, data is extracted **only from the exact bytes the signature covers**;
   - SHA-1 algorithms are rejected unless you opt in (`allowSha1`);
   - multiple IdP certificates are tried in order, so IdP key rollover doesn't lock users out.
6. **Decryption** — `EncryptedAssertion` is decrypted with your private key; insecure algorithms (RSA-PKCS1 v1.5 key transport, 3DES) are refused. Signatures inside the decrypted assertion are then verified as above.
7. **Time windows** — `NotBefore` / `NotOnOrAfter` on both `Conditions` and `SubjectConfirmationData`, with a configurable `clockSkewMs` (default 30 s).
8. **Audience** — `AudienceRestriction` must include your `entityId`.
9. **InResponseTo** — responses must answer an `AuthnRequest` this SP actually issued (tracked automatically; pluggable store for multi-instance deployments). IdP-initiated SSO is **off** unless you enable `allowUnsolicited`.
10. **Replay protection** — each assertion ID is accepted exactly once (pluggable cache).

Also on by default: NameID extraction is immune to the classic comment-injection truncation, and `RelayState` is returned to you as _untrusted data_ — never redirect to it without validating it against an allowlist.

Found a vulnerability? Please report it privately — see [SECURITY.md](./SECURITY.md).

## API reference

### `new ServiceProvider(config)`

| Option                        | Type                                | Default         | Description                                                                      |
| ----------------------------- | ----------------------------------- | --------------- | -------------------------------------------------------------------------------- |
| `entityId`                    | `string`                            | _required_      | Unique ID of your SP (URN or URL). Must match what the IdP has registered.       |
| `assertionConsumerServiceUrl` | `string`                            | _required_      | Your ACS endpoint (absolute http(s) URL).                                        |
| `idp`                         | `IdentityProvider \| config object` | _required_      | The IdP to trust.                                                                |
| `privateKey`                  | `string` (PEM)                      | —               | Enables decryption of `EncryptedAssertion`s and request signing.                 |
| `certificate`                 | `string` (PEM)                      | —               | Published in your SP metadata.                                                   |
| `clockSkewMs`                 | `number`                            | `30000`         | Tolerated clock difference between you and the IdP.                              |
| `requireSignedAssertions`     | `boolean`                           | `true`          | Assertion must be covered by a valid signature. **Never disable in production.** |
| `requireSignedResponse`       | `boolean`                           | `false`         | Additionally require the outer `Response` to be signed.                          |
| `allowUnsolicited`            | `boolean`                           | `false`         | Accept IdP-initiated responses (no `InResponseTo`).                              |
| `allowSha1`                   | `boolean`                           | `false`         | Accept SHA-1 signatures from legacy IdPs.                                        |
| `signAuthnRequests`           | `boolean`                           | `false`         | Sign outgoing requests (redirect query signature / embedded POST signature).     |
| `nameIdFormat`                | `string`                            | `…:unspecified` | `NameIDPolicy` format requested from the IdP.                                    |
| `maxResponseSize`             | `number`                            | `1048576`       | Response size cap in bytes.                                                      |
| `requestStore`                | `RequestStore`                      | in-memory       | Outstanding request IDs; plug in Redis for multi-instance.                       |
| `replayCache`                 | `ReplayCache`                       | in-memory       | Consumed assertion IDs; plug in Redis for multi-instance.                        |

### Methods

- **`await sp.createLoginRequest(options?)`** → `{ id, url, binding, xml, fields?, html?, relayState? }`
  Options: `relayState`, `binding: "redirect" | "post"`, `forceAuthn`, `isPassive`.
  Redirect binding produces the deflated+signed URL; POST binding returns hidden form `fields` and a ready-to-serve auto-submitting `html` page.
- **`await sp.consume(input)`** → `{ profile, relayState? }`
  `input` is a raw `IncomingMessage` **or** a parsed body `{ SAMLResponse, RelayState }`.
- **`await sp.consumeXml(xml)`** → `{ profile }` for already-decoded XML.
- **`sp.metadata(options?)`** → SP metadata XML string (`{ validUntil?: Date }`).
- **`ServiceProvider.generateKeyPair(options?)`** → `{ privateKey, certificate }` (`keySize`, `days`, `commonName`).

### `IdentityProvider`

```ts
IdentityProvider.fromMetadata(xml);            // parse IdP metadata XML
await IdentityProvider.fromUrl(url);           // fetch + parse (Node 18+ fetch)
new IdentityProvider({
  entityId: "urn:idp",
  ssoUrl: "https://idp/sso",                   // HTTP-Redirect endpoint
  ssoPostUrl: "https://idp/sso",               // HTTP-POST endpoint (optional)
  certificates: [pemOrBase64, ...],            // signing certs; rollover supported
});
```

### `profile` (what you get back)

```ts
{
  nameId: string | null; // who logged in
  nameIdFormat: string | null;
  sessionIndex: string | null; // keep if you'll need logout later
  attributes: Record<string, string[]>;
  issuer: string;
  authnContextClassRef: string | null;
  notBefore: Date | null;
  notOnOrAfter: Date | null; // don't let YOUR session outlive this blindly
  inResponseTo: string | null;
  assertionXml: string; // raw verified assertion, for auditing
}
```

## Error catalog

All errors extend `SAMLError` and carry a stable `code` — branch on classes or codes, never on message text.

| Class                      | Code                          | Meaning / first thing to check                                                               |
| -------------------------- | ----------------------------- | -------------------------------------------------------------------------------------------- |
| `SAMLConfigError`          | `SAML_CONFIG_ERROR`           | Your configuration is invalid (bad URL, unparseable key/cert, missing IdP data).             |
| `SAMLParseError`           | `SAML_PARSE_ERROR`            | Malformed/oversized XML, wrong root element, missing required elements, DOCTYPE.             |
| `SignatureError`           | `SAML_SIGNATURE_INVALID`      | Signature failed verification — wrong/rotated IdP cert? Tampering?                           |
| `SignatureError`           | `SAML_SIGNATURE_MISSING`      | Nothing covered the assertion — IdP is sending unsigned assertions.                          |
| `DecryptionError`          | `SAML_DECRYPTION_FAILED`      | Your `privateKey` doesn't match the cert the IdP encrypts for.                               |
| `ResponseStatusError`      | `SAML_RESPONSE_STATUS`        | IdP said no. Inspect `.statusCode`, `.subStatusCode`, `.statusMessage`.                      |
| `AssertionTimeError`       | `SAML_ASSERTION_TIME_INVALID` | Expired / not yet valid. Check server clocks; consider `clockSkewMs`. `.reason` tells which. |
| `AudienceMismatchError`    | `SAML_AUDIENCE_MISMATCH`      | IdP restricted the assertion to a different entityId.                                        |
| `IssuerMismatchError`      | `SAML_ISSUER_MISMATCH`        | Response came from a different IdP than configured.                                          |
| `DestinationMismatchError` | `SAML_DESTINATION_MISMATCH`   | Response addressed to a different ACS URL.                                                   |
| `InResponseToError`        | `SAML_IN_RESPONSE_TO_INVALID` | Unsolicited/expired/duplicate response. IdP-initiated? See `allowUnsolicited`.               |
| `ReplayError`              | `SAML_REPLAY_DETECTED`        | The same assertion was presented twice.                                                      |

## Scaling beyond one process

The default request store and replay cache are in-memory. Behind a load balancer, provide shared implementations — the interfaces are tiny and may return promises:

```ts
const sp = new ServiceProvider({
  // ...
  requestStore: {
    store: (id) => redis.set(`saml:req:${id}`, "1", { EX: 600 }),
    consume: async (id) => (await redis.del(`saml:req:${id}`)) === 1,
  },
  replayCache: {
    register: async (id, expiresAt) =>
      (await redis.set(`saml:seen:${id}`, "1", {
        NX: true,
        PXAT: expiresAt.getTime(),
      })) !== null,
  },
});
```

## Migrating from v2

v3 is a security-focused rewrite. The v2 API (`SAMLRequest`, `SAMLResponse`) performed **no signature verification** and has been removed.

| v2                                                     | v3                                                                    |
| ------------------------------------------------------ | --------------------------------------------------------------------- |
| `await ServiceProvider.create({ assertionEndpoint })`  | `new ServiceProvider({ entityId, assertionConsumerServiceUrl, idp })` |
| auto-generated keys on boot                            | `ServiceProvider.generateKeyPair()` once, then reuse                  |
| `new SAMLRequest(idpUrl, acs).createAuthNURL()`        | `(await sp.createLoginRequest()).url`                                 |
| `new SAMLResponse({ privateKey }).processRequest(req)` | `(await sp.consume(req)).profile`                                     |
| `sp.createMetadata(path)`                              | `sp.metadata()` (write it yourself if you want a file)                |
| returns `null` on missing data                         | throws typed `SAMLError` subclasses                                   |

The one thing v3 _requires_ that v2 didn't: the IdP's signing certificate (via metadata or `certificates`). That requirement is the security fix.

## FAQ

**Do I need to configure body parsing for the ACS route?**
No. Pass the raw `req` and saml-sp reads it safely (capped at `maxResponseSize`). If your framework already parsed the body, pass `req.body` instead.

**My IdP only lets me download a metadata XML file, not a URL.**
`IdentityProvider.fromMetadata(fs.readFileSync("metadata.xml", "utf8"))`.

**How do I test my integration without a real IdP?**
Look at [`tests/e2e.test.ts`](./tests/e2e.test.ts) — it forges complete signed+encrypted IdP responses using only this library's dependencies. You can also temporarily set `requireSignedAssertions: false` against a mock — never in production.

**Login works but every response is rejected with `SAML_IN_RESPONSE_TO_INVALID` after a deploy.**
Your request store was wiped (it's in-memory by default) or you're running multiple instances. Plug in a shared `requestStore`.

**Why is Single Logout missing?**
Scoped out of v3.0 deliberately — a broken SLO is worse than none. It's next on the [roadmap](#roadmap).

## Roadmap

- Single Logout (SP-initiated LogoutRequest + LogoutResponse validation)
- HTTP-Artifact binding
- Optional SP metadata signing
- First-class session helpers/examples for popular frameworks

## Contributing

PRs welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). The bar: `npm run verify` must pass (format, lint, typecheck, ≥90% coverage, build).

## License

[MIT](./LICENSE)
