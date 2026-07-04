import { X509Certificate } from "node:crypto";
import { SAMLConfigError } from "../errors";

const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Normalize an X.509 certificate into canonical PEM form.
 * Accepts full PEM (with headers), raw base64 (as found in metadata XML,
 * possibly with embedded whitespace), and any line-ending style.
 */
export function normalizeCertificate(input: string): string {
  const body = input.replace(/-----(BEGIN|END)[A-Z0-9 ]*-----/g, "").replace(/\s+/g, "");

  if (body.length === 0 || !BASE64_RE.test(body)) {
    throw new SAMLConfigError(
      "Invalid certificate: expected PEM or base64-encoded X.509 certificate data."
    );
  }

  // body is non-empty here, so the match always succeeds
  const lines = body.match(/.{1,64}/g) as string[];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

/**
 * Normalize and cryptographically validate a certificate.
 * Throws SAMLConfigError if the input is not a parseable X.509 certificate.
 */
export function validateCertificate(input: string, label = "certificate"): string {
  const pem = normalizeCertificate(input);
  try {
    new X509Certificate(pem);
  } catch (err) {
    throw new SAMLConfigError(`Invalid ${label}: not a parseable X.509 certificate.`, {
      cause: err,
    });
  }
  return pem;
}

/** The single-line base64 body of a certificate (as embedded in metadata XML). */
export function certificateBody(input: string): string {
  return normalizeCertificate(input)
    .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
    .replace(/\s+/g, "");
}
