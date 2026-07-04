/**
 * Typed error hierarchy for saml-sp.
 *
 * Every error carries a stable machine-readable `code` so callers can branch on
 * failure modes without string-matching messages:
 *
 * ```ts
 * try {
 *   await sp.consume(req);
 * } catch (err) {
 *   if (err instanceof ReplayError) { ... }
 *   if (err instanceof SAMLError && err.code === "SAML_ASSERTION_TIME_INVALID") { ... }
 * }
 * ```
 */

/** Union of all stable error codes thrown by saml-sp. */
export type SAMLErrorCode =
  | "SAML_ERROR"
  | "SAML_CONFIG_ERROR"
  | "SAML_PARSE_ERROR"
  | "SAML_VALIDATION_ERROR"
  | "SAML_SIGNATURE_INVALID"
  | "SAML_SIGNATURE_MISSING"
  | "SAML_DECRYPTION_FAILED"
  | "SAML_RESPONSE_STATUS"
  | "SAML_ASSERTION_TIME_INVALID"
  | "SAML_AUDIENCE_MISMATCH"
  | "SAML_ISSUER_MISMATCH"
  | "SAML_DESTINATION_MISMATCH"
  | "SAML_IN_RESPONSE_TO_INVALID"
  | "SAML_REPLAY_DETECTED";

/** Base class for every error thrown by saml-sp. */
export class SAMLError extends Error {
  readonly code: SAMLErrorCode;

  constructor(message: string, code: SAMLErrorCode = "SAML_ERROR", options?: { cause?: unknown }) {
    super(message, options);
    this.name = new.target.name;
    this.code = code;
  }
}

/** The library was configured incorrectly (bad URL, missing key, invalid certificate, …). */
export class SAMLConfigError extends SAMLError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, "SAML_CONFIG_ERROR", options);
  }
}

/** The XML could not be parsed, or required elements were missing/ambiguous. */
export class SAMLParseError extends SAMLError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, "SAML_PARSE_ERROR", options);
  }
}

/** Base class for all response-validation failures. */
export class SAMLValidationError extends SAMLError {
  constructor(
    message: string,
    code: SAMLErrorCode = "SAML_VALIDATION_ERROR",
    options?: { cause?: unknown }
  ) {
    super(message, code, options);
  }
}

/** The XML signature was missing, malformed, or failed cryptographic verification. */
export class SignatureError extends SAMLValidationError {
  constructor(
    message: string,
    code: Extract<
      SAMLErrorCode,
      "SAML_SIGNATURE_INVALID" | "SAML_SIGNATURE_MISSING"
    > = "SAML_SIGNATURE_INVALID",
    options?: { cause?: unknown }
  ) {
    super(message, code, options);
  }
}

/** An EncryptedAssertion could not be decrypted with the configured private key. */
export class DecryptionError extends SAMLValidationError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, "SAML_DECRYPTION_FAILED", options);
  }
}

/** The IdP reported a non-Success `samlp:Status` (e.g. the user was denied). */
export class ResponseStatusError extends SAMLValidationError {
  /** Top-level `StatusCode` value, e.g. `urn:oasis:names:tc:SAML:2.0:status:Responder`. */
  readonly statusCode: string;
  /** Nested second-level `StatusCode` value, when present. */
  readonly subStatusCode: string | null;
  /** Human-readable `StatusMessage` from the IdP, when present. */
  readonly statusMessage: string | null;

  constructor(statusCode: string, subStatusCode: string | null, statusMessage: string | null) {
    const detail = [subStatusCode, statusMessage].filter(Boolean).join(" — ");
    super(
      `IdP returned non-Success status "${statusCode}"${detail ? ` (${detail})` : ""}. ` +
        "This usually means the IdP rejected the login (user denied, misconfigured app, or invalid request).",
      "SAML_RESPONSE_STATUS"
    );
    this.statusCode = statusCode;
    this.subStatusCode = subStatusCode;
    this.statusMessage = statusMessage;
  }
}

/** The assertion is outside its validity window (`NotBefore` / `NotOnOrAfter`). */
export class AssertionTimeError extends SAMLValidationError {
  readonly reason: "not-yet-valid" | "expired";

  constructor(reason: "not-yet-valid" | "expired", boundary: Date) {
    super(
      reason === "expired"
        ? `Assertion has expired (NotOnOrAfter: ${boundary.toISOString()}). ` +
            "If your server clock is slightly off, consider increasing the clockSkewMs option."
        : `Assertion is not yet valid (NotBefore: ${boundary.toISOString()}). ` +
            "If your server clock is slightly off, consider increasing the clockSkewMs option.",
      "SAML_ASSERTION_TIME_INVALID"
    );
    this.reason = reason;
  }
}

/** The assertion's `AudienceRestriction` does not include this SP's entityId. */
export class AudienceMismatchError extends SAMLValidationError {
  constructor(expected: string, actual: readonly string[]) {
    super(
      `Assertion audience mismatch: expected "${expected}" but the assertion is restricted to ` +
        `[${actual.map((a) => `"${a}"`).join(", ")}]. ` +
        "Check that the SP entityId configured here matches the one registered with your IdP.",
      "SAML_AUDIENCE_MISMATCH"
    );
  }
}

/** The `Issuer` of the response/assertion does not match the configured IdP entityId. */
export class IssuerMismatchError extends SAMLValidationError {
  constructor(expected: string, actual: string | null) {
    super(
      `Issuer mismatch: expected "${expected}" but got "${actual ?? "<missing>"}". ` +
        "Check that the IdP entityId in your configuration matches your IdP's metadata.",
      "SAML_ISSUER_MISMATCH"
    );
  }
}

/** The response's `Destination` does not match this SP's ACS URL. */
export class DestinationMismatchError extends SAMLValidationError {
  constructor(expected: string, actual: string) {
    super(
      `Destination mismatch: the response was addressed to "${actual}" but this SP's ` +
        `assertionConsumerServiceUrl is "${expected}".`,
      "SAML_DESTINATION_MISMATCH"
    );
  }
}

/** `InResponseTo` did not match an outstanding AuthnRequest (possible replay or CSRF). */
export class InResponseToError extends SAMLValidationError {
  constructor(message: string) {
    super(message, "SAML_IN_RESPONSE_TO_INVALID");
  }
}

/** The same assertion was presented more than once. */
export class ReplayError extends SAMLValidationError {
  constructor(assertionId: string) {
    super(
      `Assertion "${assertionId}" has already been consumed — replay detected and rejected.`,
      "SAML_REPLAY_DETECTED"
    );
  }
}
