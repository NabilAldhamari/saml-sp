# saml-sp
## _SAML 2.0 Service Provider Library for Node.js_

`saml-sp` is a TypeScript-first Node.js library for implementing a SAML 2.0 Service Provider. It handles RSA keypair generation, SP metadata creation, AuthnRequest building, and encrypted assertion decryption.

## Installation

```bash
npm install saml-sp
```

## Features

- Generate RSA keypairs (2048 or 4096-bit) or supply your own
- Build SP metadata XML ready to upload to your Identity Provider
- Generate AuthnRequest URLs for IdPs that require them (e.g. AWS IAM Identity Center)
- Parse and decrypt SAML assertions from IdP POST responses
- Full TypeScript types included

---

## Quick Start

### 1. Configure the Service Provider

On first run, generate and save your keypair and metadata, then upload `metadata.xml` to your IdP.

```ts
import { ServiceProvider } from "saml-sp";

const sp = await ServiceProvider.create({
  assertionEndpoint: "https://yourapp.com/saml/consume",
  entityID: "urn:yourapp:sp",   // optional
  keyLength: 2048,              // optional, default: 2048
});

sp.saveKeys("./saml-keys");          // writes private.pem + cert.crt
sp.createMetadata("./metadata.xml"); // writes metadata.xml
```

On subsequent runs, load your existing keypair instead of regenerating:

```ts
import fs from "fs";
import { ServiceProvider } from "saml-sp";

const sp = await ServiceProvider.create({
  assertionEndpoint: "https://yourapp.com/saml/consume",
  privateKey:  fs.readFileSync("./saml-keys/private.pem", "utf-8"),
  certificate: fs.readFileSync("./saml-keys/cert.crt",    "utf-8"),
});
```

### 2. Handle Login and the SAML Response

```ts
import express from "express";
import fs from "fs";
import { ServiceProvider, SAMLRequest, SAMLResponse } from "saml-sp";

const app = express();

const IDP_URL = "https://your-idp.example.com/sso/saml";
const ACS_URL = "https://yourapp.com/saml/consume";

const sp = await ServiceProvider.create({
  assertionEndpoint: ACS_URL,
  privateKey:  fs.readFileSync("./saml-keys/private.pem", "utf-8"),
  certificate: fs.readFileSync("./saml-keys/cert.crt",    "utf-8"),
});

// Redirect users to the IdP to authenticate.
// Some IdPs (e.g. Okta) only need the raw IdP SSO URL.
// Others (e.g. AWS IAM Identity Center) require a signed AuthnRequest in the URL.
app.get("/login", (req, res) => {
  // With AuthnRequest (AWS IAM Identity Center, ADFS, etc.)
  const samlReq = new SAMLRequest(IDP_URL, ACS_URL);
  res.redirect(samlReq.createAuthNURL());

  // Without AuthnRequest (Okta, etc.) — just redirect directly:
  // res.redirect(IDP_URL);
});

// Receive and process the SAML response from the IdP.
app.post("/saml/consume", async (req, res) => {
  const samlRes = new SAMLResponse({
    privateKey: fs.readFileSync("./saml-keys/private.pem", "utf-8"),
  });

  const assertion = await samlRes.processRequest(req);

  if (!assertion) {
    res.status(400).send("Invalid SAML response.");
    return;
  }

  console.log("NameID:",     assertion.nameID);
  console.log("Attributes:", assertion.attributes);

  // Establish your session here, then redirect the user.
  res.redirect("/dashboard");
});

app.get("/saml/consume", (req, res) => res.redirect("/login"));

app.listen(3000);
```

---

## API Reference

### `ServiceProvider`

#### `ServiceProvider.create(options): Promise<ServiceProvider>`

Async factory method. Always use this instead of `new ServiceProvider()` when you need auto-generated keys.

| Option | Type | Required | Description |
|---|---|---|---|
| `assertionEndpoint` | `string` | ✅ | Your ACS (Assertion Consumer Service) URL — where the IdP will POST the SAML response after login |
| `privateKey` | `string` | — | PEM-encoded private key. If omitted alongside `certificate`, a keypair is generated automatically |
| `certificate` | `string` | — | PEM-encoded certificate. Must be supplied together with `privateKey` |
| `entityID` | `string` | — | SP entity ID included in requests and metadata. Defaults to a random value |
| `keyLength` | `2048 \| 4096` | — | RSA key size used when auto-generating a keypair. Default: `2048` |

#### `ServiceProvider.generateKeys(keyLength?): Promise<KeyPair>`

Static method. Generates a new RSA keypair and self-signed certificate without creating a full `ServiceProvider` instance.

#### `sp.createMetadata(outputPath?): string`

Returns the SP metadata XML string. If `outputPath` is provided, also writes the file to disk.

#### `sp.saveKeys(dir?): void`

Writes `private.pem` and `cert.crt` to `dir` (default: current working directory).

---

### `SAMLRequest`

```ts
const samlReq = new SAMLRequest(idpURL, assertionEndpoint);
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `idpURL` | `string` | ✅ | The SSO URL provided by your IdP |
| `assertionEndpoint` | `string` | ✅ | Your ACS URL |

#### `samlReq.generateAuthNRequest(): string`

Returns the raw AuthnRequest XML string.

#### `samlReq.createAuthNURL(): string`

Returns the full IdP redirect URL with the Base64-encoded `SAMLRequest` query parameter appended. Any pre-existing query parameters on the IdP URL are preserved.

---

### `SAMLResponse`

```ts
const samlRes = new SAMLResponse({ privateKey: "..." });
```

| Option | Type | Required | Description |
|---|---|---|---|
| `privateKey` | `string` | ✅ | PEM-encoded private key used to decrypt assertions |

#### `samlRes.processRequest(req): Promise<ParsedAssertion | null>`

Reads and decodes the `SAMLResponse` POST parameter from an incoming HTTP request, then decrypts and parses the assertion. Returns `null` if no assertion is found.

#### `samlRes.processXML(xml: string): Promise<ParsedAssertion | null>`

Same as `processRequest`, but accepts a raw XML string directly. Useful if you've already extracted and decoded the response outside this library.

#### `ParsedAssertion`

| Field | Type | Description |
|---|---|---|
| `nameID` | `string \| null` | The authenticated user's NameID |
| `attributes` | `Record<string, string[]>` | All attributes from the assertion's `AttributeStatement` |
| `notBefore` | `Date \| null` | Assertion validity start time |
| `notOnOrAfter` | `Date \| null` | Assertion expiry time |
| `xml` | `string` | The raw decrypted assertion XML |

Both methods validate `NotBefore` and `NotOnOrAfter` and throw if the assertion is outside its valid window.

---

## License

MIT