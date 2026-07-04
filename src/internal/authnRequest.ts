import { createSign, randomBytes } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { create } from "xmlbuilder2";
import { SignedXml } from "xml-crypto";
import { SAMLConfigError } from "../errors";

export const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
const SHA256_DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

/** Generate a SAML-safe unique ID (NCName: must not start with a digit). */
export function generateId(): string {
  return `_${randomBytes(16).toString("hex")}`;
}

export interface AuthnRequestParams {
  id: string;
  destination: string;
  assertionConsumerServiceUrl: string;
  issuer: string;
  nameIdFormat: string;
  forceAuthn?: boolean;
  isPassive?: boolean;
}

/** Build the AuthnRequest XML document. */
export function buildAuthnRequestXml(params: AuthnRequestParams): string {
  const request: Record<string, unknown> = {
    "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "@ID": params.id,
    "@Version": "2.0",
    "@IssueInstant": new Date().toISOString(),
    "@Destination": params.destination,
    "@AssertionConsumerServiceURL": params.assertionConsumerServiceUrl,
    "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
  };
  if (params.forceAuthn) request["@ForceAuthn"] = "true";
  if (params.isPassive) request["@IsPassive"] = "true";

  request["saml:Issuer"] = params.issuer;
  request["samlp:NameIDPolicy"] = {
    "@Format": params.nameIdFormat,
    "@AllowCreate": "true",
  };

  return create({ "samlp:AuthnRequest": request }).end();
}

/**
 * Embed an enveloped XML signature into an AuthnRequest (used by the POST binding).
 * Per the SAML schema, the Signature element is placed directly after Issuer.
 */
export function signAuthnRequestXml(xml: string, requestId: string, privateKey: string): string {
  const sig = new SignedXml({ privateKey });
  sig.signatureAlgorithm = RSA_SHA256;
  sig.canonicalizationAlgorithm = EXC_C14N;
  sig.addReference({
    xpath: "/*[local-name(.)='AuthnRequest']",
    uri: `#${requestId}`,
    digestAlgorithm: SHA256_DIGEST,
    transforms: [ENVELOPED, EXC_C14N],
  });
  sig.computeSignature(xml, {
    prefix: "ds",
    location: {
      reference: "/*[local-name(.)='AuthnRequest']/*[local-name(.)='Issuer']",
      action: "after",
    },
  });
  return sig.getSignedXml();
}

export interface RedirectUrlParams {
  ssoUrl: string;
  requestXml: string;
  relayState?: string;
  /** When provided, the query string is signed per the HTTP-Redirect binding spec. */
  privateKey?: string;
}

/**
 * Build the HTTP-Redirect binding URL: `base64(deflateRaw(xml))`, URL-encoded,
 * optionally signed (SigAlg + Signature query parameters, computed over the
 * encoded query string in the exact order SAMLRequest, RelayState, SigAlg).
 */
export function buildRedirectUrl(params: RedirectUrlParams): string {
  const encoded = deflateRawSync(Buffer.from(params.requestXml, "utf8")).toString("base64");

  const parts = [`SAMLRequest=${encodeURIComponent(encoded)}`];
  if (params.relayState !== undefined) {
    parts.push(`RelayState=${encodeURIComponent(params.relayState)}`);
  }
  if (params.privateKey) {
    parts.push(`SigAlg=${encodeURIComponent(RSA_SHA256)}`);
    const signer = createSign("RSA-SHA256");
    signer.update(parts.join("&"));
    const signature = signer.sign(params.privateKey).toString("base64");
    parts.push(`Signature=${encodeURIComponent(signature)}`);
  }

  const separator = params.ssoUrl.includes("?") ? "&" : "?";
  return `${params.ssoUrl}${separator}${parts.join("&")}`;
}

export interface PostBindingParams {
  ssoPostUrl: string;
  requestXml: string;
  relayState?: string;
}

export interface PostBinding {
  url: string;
  fields: Record<string, string>;
  html: string;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Build the HTTP-POST binding payload: base64 (no deflate) + auto-submitting form. */
export function buildPostBinding(params: PostBindingParams): PostBinding {
  const fields: Record<string, string> = {
    SAMLRequest: Buffer.from(params.requestXml, "utf8").toString("base64"),
  };
  if (params.relayState !== undefined) {
    fields.RelayState = params.relayState;
  }

  const inputs = Object.entries(fields)
    .map(
      ([name, value]) =>
        `<input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}"/>`
    )
    .join("\n      ");

  const html = `<!DOCTYPE html>
<html lang="en">
  <head><meta charset="utf-8"><title>Redirecting…</title></head>
  <body onload="document.forms[0].submit()">
    <noscript><p>JavaScript is disabled. Click the button to continue signing in.</p></noscript>
    <form method="post" action="${escapeHtml(params.ssoPostUrl)}">
      ${inputs}
      <noscript><button type="submit">Continue</button></noscript>
    </form>
  </body>
</html>`;

  return { url: params.ssoPostUrl, fields, html };
}

/** Validate that a string is an absolute http(s) URL. */
export function assertHttpUrl(value: string, label: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch (err) {
    throw new SAMLConfigError(`${label} must be a valid absolute URL, got "${value}".`, {
      cause: err,
    });
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new SAMLConfigError(`${label} must use http(s), got "${value}".`);
  }
}
