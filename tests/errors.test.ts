import {
  AssertionTimeError,
  AudienceMismatchError,
  DecryptionError,
  DestinationMismatchError,
  InResponseToError,
  IssuerMismatchError,
  ReplayError,
  ResponseStatusError,
  SAMLConfigError,
  SAMLError,
  SAMLParseError,
  SAMLValidationError,
  SignatureError,
} from "../src";

describe("error hierarchy", () => {
  it.each([
    [new SAMLConfigError("x"), "SAML_CONFIG_ERROR", SAMLError],
    [new SAMLParseError("x"), "SAML_PARSE_ERROR", SAMLError],
    [new SAMLValidationError("x"), "SAML_VALIDATION_ERROR", SAMLError],
    [new SignatureError("x"), "SAML_SIGNATURE_INVALID", SAMLValidationError],
    [
      new SignatureError("x", "SAML_SIGNATURE_MISSING"),
      "SAML_SIGNATURE_MISSING",
      SAMLValidationError,
    ],
    [new DecryptionError("x"), "SAML_DECRYPTION_FAILED", SAMLValidationError],
    [new ResponseStatusError("code", null, null), "SAML_RESPONSE_STATUS", SAMLValidationError],
    [
      new AssertionTimeError("expired", new Date()),
      "SAML_ASSERTION_TIME_INVALID",
      SAMLValidationError,
    ],
    [new AudienceMismatchError("a", ["b"]), "SAML_AUDIENCE_MISMATCH", SAMLValidationError],
    [new IssuerMismatchError("a", "b"), "SAML_ISSUER_MISMATCH", SAMLValidationError],
    [new DestinationMismatchError("a", "b"), "SAML_DESTINATION_MISMATCH", SAMLValidationError],
    [new InResponseToError("x"), "SAML_IN_RESPONSE_TO_INVALID", SAMLValidationError],
    [new ReplayError("id"), "SAML_REPLAY_DETECTED", SAMLValidationError],
  ] as const)("%p carries code %s and extends the right base", (err, code, base) => {
    expect(err.code).toBe(code);
    expect(err).toBeInstanceOf(base);
    expect(err).toBeInstanceOf(SAMLError);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe(err.constructor.name);
  });

  it("ResponseStatusError exposes structured status fields", () => {
    const err = new ResponseStatusError(
      "urn:oasis:names:tc:SAML:2.0:status:Requester",
      "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
      "Denied by policy"
    );
    expect(err.statusCode).toBe("urn:oasis:names:tc:SAML:2.0:status:Requester");
    expect(err.subStatusCode).toBe("urn:oasis:names:tc:SAML:2.0:status:RequestDenied");
    expect(err.statusMessage).toBe("Denied by policy");
    expect(err.message).toContain("Denied by policy");
  });

  it("AssertionTimeError distinguishes expiry from prematurity", () => {
    const when = new Date("2030-01-01T00:00:00Z");
    expect(new AssertionTimeError("expired", when).reason).toBe("expired");
    expect(new AssertionTimeError("not-yet-valid", when).reason).toBe("not-yet-valid");
    expect(new AssertionTimeError("expired", when).message).toContain("2030-01-01");
    expect(new AssertionTimeError("expired", when).message).toContain("clockSkewMs");
  });

  it("preserves the underlying cause", () => {
    const cause = new Error("boom");
    const err = new SAMLParseError("wrapper", { cause });
    expect(err.cause).toBe(cause);
  });

  it("mentions both expected and actual values in mismatch errors", () => {
    expect(new IssuerMismatchError("urn:expected", "urn:actual").message).toMatch(
      /urn:expected.*urn:actual/
    );
    expect(new IssuerMismatchError("urn:expected", null).message).toContain("<missing>");
    expect(new DestinationMismatchError("https://a", "https://b").message).toMatch(
      /https:\/\/b.*https:\/\/a/
    );
  });
});
