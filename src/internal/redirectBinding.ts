import { createSign, createVerify } from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import { SAMLParseError, SignatureError } from "../errors";
import { normalizeCertificate } from "./pem";

/** SigAlg URIs supported for the HTTP-Redirect binding query signature. */
export const REDIRECT_SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
export const REDIRECT_SIG_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

const SIG_ALG_TO_HASH: Record<string, string> = {
  [REDIRECT_SIG_RSA_SHA256]: "RSA-SHA256",
  [REDIRECT_SIG_RSA_SHA1]: "RSA-SHA1",
};

export type RedirectMessageType = "SAMLRequest" | "SAMLResponse";

export interface BuildRedirectParams {
  /** Endpoint to send the message to (may already contain a query string). */
  destination: string;
  /** Raw XML message. */
  message: string;
  type: RedirectMessageType;
  relayState?: string;
  /** When provided, the query is signed (RSA-SHA256) per the HTTP-Redirect binding spec. */
  privateKey?: string;
}

/**
 * Build an HTTP-Redirect binding URL: `base64(deflateRaw(xml))`, URL-encoded, with an
 * optional detached signature over the exact query string (`SAMLRequest|SAMLResponse`,
 * then `RelayState` if present, then `SigAlg`, in that order).
 */
export function buildRedirectUrl(params: BuildRedirectParams): string {
  const encoded = deflateRawSync(Buffer.from(params.message, "utf8")).toString("base64");

  const parts = [`${params.type}=${encodeURIComponent(encoded)}`];
  if (params.relayState !== undefined) {
    parts.push(`RelayState=${encodeURIComponent(params.relayState)}`);
  }
  if (params.privateKey) {
    parts.push(`SigAlg=${encodeURIComponent(REDIRECT_SIG_RSA_SHA256)}`);
    const signer = createSign("RSA-SHA256");
    signer.update(parts.join("&"));
    parts.push(
      `Signature=${encodeURIComponent(signer.sign(params.privateKey).toString("base64"))}`
    );
  }

  const separator = params.destination.includes("?") ? "&" : "?";
  return `${params.destination}${separator}${parts.join("&")}`;
}

export interface ParsedRedirect {
  type: RedirectMessageType;
  /** The inflated XML message. */
  message: string;
  relayState?: string;
  sigAlg?: string;
  /** Base64 signature value, if the query was signed. */
  signature?: string;
  /**
   * The exact octet string the signature covers, reconstructed from the raw
   * (as-received) percent-encoded values. Verifying against re-encoded values is
   * unreliable, so this preserves the original encoding.
   */
  signedString?: string;
}

/** Split a raw query string into params without decoding the values. */
function rawParams(rawQuery: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const pair of rawQuery.replace(/^\?/, "").split("&")) {
    if (!pair) continue;
    const eq = pair.indexOf("=");
    const key = eq === -1 ? pair : pair.slice(0, eq);
    const value = eq === -1 ? "" : pair.slice(eq + 1);
    if (!map.has(key)) map.set(key, value);
  }
  return map;
}

/**
 * Parse a raw HTTP-Redirect binding query string. `maxBytes` bounds the inflated
 * message to defend against decompression bombs.
 */
export function parseRedirectQuery(rawQuery: string, maxBytes: number): ParsedRedirect {
  if (rawQuery.length > maxBytes) {
    throw new SAMLParseError(
      `Redirect-binding query exceeds the maximum accepted size of ${maxBytes} bytes.`
    );
  }

  const raw = rawParams(rawQuery);
  const type: RedirectMessageType | null = raw.has("SAMLRequest")
    ? "SAMLRequest"
    : raw.has("SAMLResponse")
      ? "SAMLResponse"
      : null;
  if (!type) {
    throw new SAMLParseError(
      "Query string contains neither a SAMLRequest nor a SAMLResponse parameter."
    );
  }

  const rawMessage = raw.get(type) ?? "";
  const message = inflateMessage(decodeURIComponent(rawMessage), maxBytes);

  const rawRelayState = raw.get("RelayState");
  const rawSigAlg = raw.get("SigAlg");
  const rawSignature = raw.get("Signature");

  const parsed: ParsedRedirect = {
    type,
    message,
    relayState: rawRelayState !== undefined ? decodeURIComponent(rawRelayState) : undefined,
    sigAlg: rawSigAlg !== undefined ? decodeURIComponent(rawSigAlg) : undefined,
    signature: rawSignature !== undefined ? decodeURIComponent(rawSignature) : undefined,
  };

  if (parsed.signature !== undefined && rawSigAlg !== undefined) {
    const segments = [`${type}=${rawMessage}`];
    if (rawRelayState !== undefined) segments.push(`RelayState=${rawRelayState}`);
    segments.push(`SigAlg=${rawSigAlg}`);
    parsed.signedString = segments.join("&");
  }

  return parsed;
}

/**
 * Verify the detached signature on a parsed redirect message against the IdP's
 * certificates. Throws SignatureError when unsigned (missing) or invalid.
 */
export function verifyRedirectSignature(
  parsed: ParsedRedirect,
  certificates: readonly string[],
  allowSha1: boolean
): void {
  if (!parsed.signature || !parsed.sigAlg || !parsed.signedString) {
    throw new SignatureError(
      "The redirect-binding SAML message is not signed, but signed logout is required. " +
        "If your IdP does not sign SLO messages, set requireSignedLogout: false (not recommended).",
      "SAML_SIGNATURE_MISSING"
    );
  }

  const hash = SIG_ALG_TO_HASH[parsed.sigAlg];
  if (!hash || (parsed.sigAlg === REDIRECT_SIG_RSA_SHA1 && !allowSha1)) {
    throw new SignatureError(
      `SigAlg "${parsed.sigAlg}" is not allowed.` +
        (parsed.sigAlg === REDIRECT_SIG_RSA_SHA1
          ? " SHA-1 is deprecated; set allowSha1: true only if your IdP cannot be upgraded."
          : "")
    );
  }

  const signatureBuf = Buffer.from(parsed.signature, "base64");
  for (const certificate of certificates) {
    const verifier = createVerify(hash);
    verifier.update(parsed.signedString);
    try {
      if (verifier.verify(normalizeCertificate(certificate), signatureBuf)) return;
    } catch {
      // Try the next certificate (supports IdP key rollover).
    }
  }

  throw new SignatureError(
    "Redirect-binding signature failed verification against all configured IdP certificates."
  );
}

function inflateMessage(base64: string, maxBytes: number): string {
  let buffer: Buffer;
  try {
    buffer = inflateRawSync(Buffer.from(base64, "base64"), { maxOutputLength: maxBytes });
  } catch (err) {
    throw new SAMLParseError(
      "Failed to inflate the redirect-binding SAML message (not valid DEFLATE data, or too large).",
      { cause: err }
    );
  }
  return buffer.toString("utf8");
}
