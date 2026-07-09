# saml-sp

**The SAML 2.0 Service Provider you can't hold wrong.**

[![CI](https://github.com/NabilAldhamari/saml-sp/actions/workflows/ci.yml/badge.svg)](https://github.com/NabilAldhamari/saml-sp/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/saml-sp)](https://www.npmjs.com/package/saml-sp)
[![npm downloads](https://img.shields.io/npm/dm/saml-sp)](https://www.npmjs.com/package/saml-sp)
[![license](https://img.shields.io/npm/l/saml-sp)](./LICENSE)
![node](https://img.shields.io/badge/node-%3E%3D18-43853d)

Add enterprise SSO (Okta, Microsoft Entra ID, Google Workspace, AWS IAM Identity Center, Keycloak, and more) to any Node.js app in minutes, with the security work already done for you.

```ts
import { ServiceProvider, IdentityProvider } from "saml-sp";

const sp = new ServiceProvider({
  entityId: "urn:example:my-app",
  assertionConsumerServiceUrl: "https://my-app.example.com/saml/acs",
  idp: await IdentityProvider.fromUrl("https://idp.example.com/metadata"), // paste & go
});

// 1. Send the user to the IdP
const { url } = await sp.createLoginRequest();

// 2. Validate what comes back. Signatures, audience, timing, replay: all checked.
const { profile } = await sp.consume(req);
console.log(profile.nameId, profile.attributes);
```

## Why saml-sp?

SAML is where authentication bugs become account takeovers. Most libraries make you assemble the security yourself: pick a validator, wire the clock skew, remember to check the audience. **saml-sp is secure by default. If it validates, it's safe; if it isn't safe, you get a typed error explaining exactly why.**

|                                       |    saml-sp     | @node-saml/node-saml |          samlify          | saml2-js |
| ------------------------------------- | :------------: | :------------------: | :-----------------------: | :------: |
| Signature verification on by default  |       ✅       |          ✅          | ⚠️ needs manual validator |    ✅    |
| One-paste IdP metadata setup          |       ✅       |          ❌          |            ✅             |    ❌    |
| Typed error classes with stable codes |       ✅       |          ❌          |            ❌             |    ❌    |
| Replay protection built in            |       ✅       |      ⚠️ partial      |            ❌             |    ❌    |
| SHA-1 rejected by default             |       ✅       |          ❌          |            ❌             |    ❌    |
| Zero native/compiled dependencies     |       ✅       |          ✅          |            ❌             |    ✅    |
| TypeScript-first, dual ESM + CJS      |       ✅       |     ⚠️ CJS only      |            ⚠️             |    ❌    |
| Config surface                        | 1 small object |   ~40 flat options   |           large           |  large   |

If you need to **be an Identity Provider**, use `samlify`. If you need to **be a Service Provider** (login, logout, metadata) and want it correct on the first try, use saml-sp.

## Installation

```bash
npm install saml-sp
```

Node.js >= 18. TypeScript types included. ESM and CommonJS both supported.

## Quick start (Express)

**Step 1: one-time setup.** Generate a keypair and keep it:

```ts
import fs from "node:fs";
import { ServiceProvider } from "saml-sp";

const keys = ServiceProvider.generateKeyPair();
fs.writeFileSync("sp-key.pem", keys.privateKey); // keep secret!
fs.writeFileSync("sp-cert.pem", keys.certificate);
```

> Generate **once** and reuse. Regenerating on every boot silently breaks the trust relationship registered with your IdP.

**Step 2: the app.**

```ts
import express from "express";
import fs from "node:fs";
import { ServiceProvider, IdentityProvider, SAMLValidationError } from "saml-sp";

const sp = new ServiceProvider({
  entityId: "urn:example:my-app",
  assertionConsumerServiceUrl: "https://my-app.example.com/saml/acs",
  idp: IdentityProvider.fromMetadata(fs.readFileSync("idp-metadata.xml", "utf8")),
  privateKey: fs.readFileSync("sp-key.pem", "utf8"),
  certificate: fs.readFileSync("sp-cert.pem", "utf8"),
});

const app = express();

// Register this URL (or its output) with your IdP.
app.get("/saml/metadata", (_req, res) => {
  res.type("application/xml").send(sp.metadata());
});

app.get("/login", async (_req, res) => {
  const { url } = await sp.createLoginRequest({ relayState: "/dashboard" });
  res.redirect(url);
});

// The IdP POSTs the SAML response here.
app.post("/saml/acs", async (req, res) => {
  try {
    const { profile } = await sp.consume(req);
    // Authenticated. Establish YOUR session here (cookie, JWT, ...).
    res.redirect("/dashboard");
  } catch (err) {
    if (err instanceof SAMLValidationError) {
      console.warn("SAML validation failed:", err.code);
      return res.status(401).send("Login failed.");
    }
    throw err;
  }
});

app.listen(3000);
```

That's the whole integration. No body-parser setup needed: `sp.consume(req)` reads the raw request itself with a size cap. If you already use `express.urlencoded()`, `sp.consume(req.body)` works too. A runnable version lives in [`examples/express`](./examples/express).

## Single Logout (SLO)

saml-sp supports both directions of SAML Single Logout over the HTTP-Redirect binding: the user clicks "log out" in your app (SP-initiated), or logs out at the IdP / another app and the IdP tells you (IdP-initiated). Messages are signed by default and inbound messages must be signed by the IdP.

Add one config option (it is published in your metadata automatically) and one route:

```ts
const sp = new ServiceProvider({
  // ...same as above...
  singleLogoutServiceUrl: "https://my-app.example.com/saml/slo",
});

// SP-initiated: your "Log out" button. Use the values you saved at login.
app.get("/logout", async (req, res) => {
  const { url } = await sp.createLogoutRequest({
    nameId: req.session.nameId,
    nameIdFormat: req.session.nameIdFormat,
    sessionIndex: req.session.sessionIndex,
  });
  req.session.destroy();
  res.redirect(url); // off to the IdP
});

// The SLO endpoint receives BOTH directions; branch on result.type.
app.get("/saml/slo", async (req, res) => {
  const result = await sp.receiveLogout(req);
  if (result.type === "response") {
    // The IdP confirmed the logout we started.
    return res.redirect("/logged-out");
  }
  // IdP-initiated: end the local session for result.nameId, then acknowledge.
  await endSessionFor(result.nameId, result.sessionIndex);
  res.redirect(result.responseUrl);
});
```

Save `profile.nameId`, `profile.nameIdFormat`, and `profile.sessionIndex` in your session at login time; the IdP needs them to match the user. Inbound logout messages are verified (signature, issuer, destination, `InResponseTo`) exactly like login responses; failures throw the same typed errors.

## Setting up your IdP

<details>
<summary><b>Okta</b></summary>

1. Admin console > Applications > Create App Integration > **SAML 2.0**.
2. Single sign-on URL: your ACS URL. Audience URI (SP Entity ID): your `entityId`.
3. After creation: Sign On tab > SAML Signing Certificates > Actions > **View IdP metadata**. Feed that XML to `IdentityProvider.fromMetadata()` (or the URL to `fromUrl`).

</details>

<details>
<summary><b>Microsoft Entra ID (Azure AD)</b></summary>

1. Enterprise applications > New application > Create your own (non-gallery).
2. Single sign-on > SAML. Identifier = your `entityId`, Reply URL = your ACS URL.
3. Copy the **App Federation Metadata Url** and use `IdentityProvider.fromUrl(metadataUrl)`.

Entra signs the assertion (not the response) by default, which saml-sp accepts out of the box.

</details>

<details>
<summary><b>Google Workspace</b></summary>

1. Admin console > Apps > Web and mobile apps > Add custom SAML app.
2. Download the IdP metadata on step 2 and pass it to `IdentityProvider.fromMetadata()`.
3. ACS URL = your ACS endpoint, Entity ID = your `entityId`.

</details>

<details>
<summary><b>AWS IAM Identity Center</b></summary>

1. Applications > Add application > custom SAML 2.0 application.
2. Download the metadata file and pass it to `IdentityProvider.fromMetadata()`.
3. Set the application ACS URL and audience to your ACS URL / `entityId`.

AWS requires a real AuthnRequest (a bare IdP-URL redirect is not enough); `createLoginRequest()` produces exactly that.

</details>

<details>
<summary><b>Keycloak</b></summary>

1. Create a client with protocol **saml**; Client ID = your `entityId`.
2. Metadata lives at `https://<host>/realms/<realm>/protocol/saml/descriptor`; use `IdentityProvider.fromUrl()`.
3. Point the client's ACS / valid redirect URIs at your ACS URL.

</details>

## The security model

Every response passes a strict pipeline. There is no way to get a `profile` out of saml-sp without all of these passing:

1. **Size cap** (1 MiB default) and base64 sanity checks.
2. **Hardened XML parsing**: DOCTYPE rejected outright, parser errors abort, all lookups namespace-aware.
3. **Status check**: non-Success becomes a `ResponseStatusError` carrying the IdP's status codes.
4. **Addressing**: `Destination` and `Recipient` must match your ACS URL; `Issuer` must match the IdP entityId at both response and assertion level.
5. **Signature verification** (via [xml-crypto](https://github.com/node-saml/xml-crypto)): the assertion must be covered by a valid signature. Only direct-child signatures count, the reference URI must match the signed element's unique ID (wrapping defence), exactly one assertion per response, data is extracted only from the exact bytes the signature covers, SHA-1 is refused unless you opt in, and multiple IdP certificates are tried in order so key rollover doesn't lock users out.
6. **Decryption**: `EncryptedAssertion` is decrypted with your private key; insecure algorithms (RSA-PKCS1 v1.5, 3DES) are refused.
7. **Time windows**: `NotBefore`/`NotOnOrAfter` on both `Conditions` and `SubjectConfirmationData`, with configurable `clockSkewMs` (default 30 s).
8. **Audience**: `AudienceRestriction` must include your `entityId`.
9. **InResponseTo**: responses must answer an AuthnRequest this SP actually issued. IdP-initiated SSO is off unless you enable `allowUnsolicited`.
10. **Replay protection**: each assertion ID is accepted exactly once.

Single Logout messages get the same treatment: the redirect-binding query signature is verified against the IdP certificates (required by default, SHA-1 refused), the inflated message is size-capped against decompression bombs, and issuer, destination, `InResponseTo`, and status are all checked before you see a result.

NameID extraction is immune to comment-injection truncation, and `RelayState` comes back to you as untrusted data: never redirect to it without an allowlist.

Found a vulnerability? Report it privately: see [SECURITY.md](./SECURITY.md).

## API reference

### `new ServiceProvider(config)`

| Option                        | Type               | Default       | Description                                                            |
| ----------------------------- | ------------------ | ------------- | ---------------------------------------------------------------------- |
| `entityId`                    | `string`           | required      | Unique ID of your SP. Must match what the IdP has registered.          |
| `assertionConsumerServiceUrl` | `string`           | required      | Your ACS endpoint (absolute http(s) URL).                              |
| `idp`                         | `IdentityProvider` | required      | The IdP to trust (instance or plain config object).                    |
| `privateKey`                  | `string` (PEM)     |               | Enables decryption of encrypted assertions and request signing.        |
| `certificate`                 | `string` (PEM)     |               | Published in your SP metadata.                                         |
| `clockSkewMs`                 | `number`           | `30000`       | Tolerated clock difference between you and the IdP.                    |
| `requireSignedAssertions`     | `boolean`          | `true`        | Assertion must be signature-covered. **Never disable in production.**  |
| `requireSignedResponse`       | `boolean`          | `false`       | Additionally require the outer `Response` to be signed.                |
| `allowUnsolicited`            | `boolean`          | `false`       | Accept IdP-initiated responses (no `InResponseTo`).                    |
| `allowSha1`                   | `boolean`          | `false`       | Accept SHA-1 signatures from legacy IdPs.                              |
| `signAuthnRequests`           | `boolean`          | `false`       | Sign outgoing requests.                                                |
| `singleLogoutServiceUrl`      | `string`           |               | Your SLO endpoint; enables Single Logout and is published in metadata. |
| `signLogoutMessages`          | `boolean`          | `true`        | Sign outbound logout messages (needs `privateKey`).                    |
| `requireSignedLogout`         | `boolean`          | `true`        | Require inbound logout messages to be signed by the IdP.               |
| `nameIdFormat`                | `string`           | `unspecified` | `NameIDPolicy` format requested from the IdP.                          |
| `maxResponseSize`             | `number`           | `1048576`     | Response size cap in bytes.                                            |
| `requestStore`                | `RequestStore`     | in-memory     | Outstanding request IDs; plug in Redis for multi-instance.             |
| `replayCache`                 | `ReplayCache`      | in-memory     | Consumed assertion IDs; plug in Redis for multi-instance.              |

### Methods

- `await sp.createLoginRequest(options?)` returns `{ id, url, binding, xml, fields?, html?, relayState? }`. Options: `relayState`, `binding: "redirect" | "post"`, `forceAuthn`, `isPassive`. The POST binding returns hidden form `fields` plus a ready-to-serve auto-submitting `html` page.
- `await sp.consume(input)` returns `{ profile, relayState? }`. Input is a raw `IncomingMessage` or a parsed body `{ SAMLResponse, RelayState }`.
- `await sp.consumeXml(xml)` for already-decoded XML.
- `await sp.createLogoutRequest({ nameId, nameIdFormat?, sessionIndex?, relayState? })` returns `{ id, url, xml }`; redirect the browser to `url`.
- `await sp.receiveLogout(input)` handles the SLO endpoint (a GET `IncomingMessage` or raw query string). Returns `{ type: "response", ... }` for IdP confirmations or `{ type: "request", nameId, sessionIndex, responseUrl, ... }` for IdP-initiated logouts.
- `sp.metadata(options?)` returns your SP metadata XML (`{ validUntil?: Date }`).
- `ServiceProvider.generateKeyPair(options?)` returns `{ privateKey, certificate }`.

### `IdentityProvider`

```ts
IdentityProvider.fromMetadata(xml); // parse IdP metadata XML
await IdentityProvider.fromUrl(url); // fetch + parse
new IdentityProvider({
  entityId: "urn:idp",
  ssoUrl: "https://idp/sso", // HTTP-Redirect endpoint
  ssoPostUrl: "https://idp/sso", // HTTP-POST endpoint (optional)
  sloUrl: "https://idp/slo", // SingleLogoutService (optional, enables SLO)
  certificates: [pemOrBase64], // signing certs; rollover supported
});
// fromMetadata()/fromUrl() pick up SingleLogoutService endpoints automatically.
```

### `profile`

```ts
{
  nameId: string | null;
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

All errors extend `SAMLError` and carry a stable `code`. Branch on classes or codes, never on message text.

| Class                      | Code                          | First thing to check                                              |
| -------------------------- | ----------------------------- | ----------------------------------------------------------------- |
| `SAMLConfigError`          | `SAML_CONFIG_ERROR`           | Bad URL, unparseable key/cert, missing IdP data.                  |
| `SAMLParseError`           | `SAML_PARSE_ERROR`            | Malformed/oversized XML, missing elements, DOCTYPE.               |
| `SignatureError`           | `SAML_SIGNATURE_INVALID`      | Wrong or rotated IdP cert? Tampering?                             |
| `SignatureError`           | `SAML_SIGNATURE_MISSING`      | The IdP is sending unsigned assertions.                           |
| `DecryptionError`          | `SAML_DECRYPTION_FAILED`      | Your key doesn't match the cert the IdP encrypts for.             |
| `ResponseStatusError`      | `SAML_RESPONSE_STATUS`        | IdP said no. Inspect `.statusCode` / `.statusMessage`.            |
| `AssertionTimeError`       | `SAML_ASSERTION_TIME_INVALID` | Server clocks; consider `clockSkewMs`. `.reason` tells which end. |
| `AudienceMismatchError`    | `SAML_AUDIENCE_MISMATCH`      | IdP restricted the assertion to a different entityId.             |
| `IssuerMismatchError`      | `SAML_ISSUER_MISMATCH`        | Response came from a different IdP than configured.               |
| `DestinationMismatchError` | `SAML_DESTINATION_MISMATCH`   | Response addressed to a different ACS URL.                        |
| `InResponseToError`        | `SAML_IN_RESPONSE_TO_INVALID` | Unsolicited/expired/duplicate. IdP-initiated? `allowUnsolicited`. |
| `ReplayError`              | `SAML_REPLAY_DETECTED`        | The same assertion was presented twice.                           |

## Scaling beyond one process

The default request store and replay cache are in-memory. Behind a load balancer, provide shared implementations; the interfaces are tiny and may return promises:

```ts
const sp = new ServiceProvider({
  // ...
  requestStore: {
    store: (id) => redis.set(`saml:req:${id}`, "1", { EX: 600 }),
    consume: async (id) => (await redis.del(`saml:req:${id}`)) === 1,
  },
  replayCache: {
    register: async (id, expiresAt) =>
      (await redis.set(`saml:seen:${id}`, "1", { NX: true, PXAT: expiresAt.getTime() })) !== null,
  },
});
```

## FAQ

**Do I need body parsing for the ACS route?**
No. Pass the raw `req`; saml-sp reads it safely with a size cap. If your framework already parsed the body, pass `req.body`.

**How do I test without a real IdP?**
See [`tests/e2e.test.ts`](./tests/e2e.test.ts): it forges complete signed and encrypted IdP responses using only this library's dependencies.

**Every response is rejected with `SAML_IN_RESPONSE_TO_INVALID` after a deploy.**
Your request store was wiped (it's in-memory by default) or you run multiple instances. Plug in a shared `requestStore`.

## Roadmap

Planned, in priority order:

1. **IdP metadata refresh**: opt-in periodic re-fetch of `fromUrl` metadata so IdP certificate rollover needs no redeploy.
2. **Framework recipes**: first-class examples for Fastify, Next.js route handlers, and NestJS.
3. **`npx saml-sp init`**: interactive CLI that generates your keypair, SP metadata, and starter code.
4. **SLO over HTTP-POST binding** (Redirect is supported today), **HTTP-Artifact binding**, and signed SP metadata.

Shipped: ~~Single Logout (SP- and IdP-initiated, HTTP-Redirect, signed)~~ in v3.1.

Want one of these sooner? Open an issue and say so; priority follows demand.

## Contributing

PRs welcome, see [CONTRIBUTING.md](./CONTRIBUTING.md). The bar: `npm run verify` must pass (format, lint, typecheck, >=90% coverage, build).

## License

[MIT](./LICENSE)
