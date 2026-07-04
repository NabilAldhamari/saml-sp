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
  SAMLParseError,
  SignatureError,
} from "../src";
import {
  RSA_SHA1,
  SHA1_DIGEST,
  buildAssertionXml,
  buildResponseXml,
  buildValidResponse,
  encryptAssertion,
  makeSp,
  minutesFromNow,
  signAssertion,
  signResponse,
  testId,
} from "./helpers/fixtures";
import { EVIL_KEYS, IDP_KEYS } from "./helpers/keys";

describe("response validation — happy paths", () => {
  it("accepts a response with a signed assertion and extracts the full profile", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const { profile } = await sp.consumeXml(xml);

    expect(profile.nameId).toBe("alice@example.com");
    expect(profile.nameIdFormat).toBe("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
    expect(profile.sessionIndex).toBe("session-123");
    expect(profile.issuer).toBe("urn:test:idp");
    expect(profile.authnContextClassRef).toBe(
      "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    );
    expect(profile.attributes).toEqual({
      email: ["alice@example.com"],
      roles: ["admin", "user"],
    });
    expect(profile.notBefore).toBeInstanceOf(Date);
    expect(profile.notOnOrAfter).toBeInstanceOf(Date);
    expect(profile.assertionXml).toContain("Assertion");
  });

  it("accepts a response signed only at the Response level", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ signAssertion: false, signResponse: true });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("accepts a response signed at both levels", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ signResponse: true });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("accepts an encrypted assertion that is signed inside the encryption", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ encrypt: true });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("accepts a signed response containing an unsigned encrypted assertion", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      encrypt: true,
      signAssertion: false,
      signResponse: true,
    });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("supports AES-256-CBC encrypted assertions", async () => {
    const sp = makeSp();
    const assertionId = testId();
    const signed = signAssertion(buildAssertionXml({ id: assertionId }), assertionId);
    const encrypted = await encryptAssertion(
      signed,
      undefined,
      "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
    );
    const xml = buildResponseXml(encrypted);
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("supports IdP certificate rollover (older cert listed first)", async () => {
    const sp = makeSp({
      idp: {
        entityId: "urn:test:idp",
        ssoUrl: "https://idp.example.com/sso/redirect",
        certificates: [EVIL_KEYS.certificate, IDP_KEYS.certificate],
      },
    });
    const xml = await buildValidResponse();
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("accepts an assertion without Conditions (falls back to SubjectConfirmationData expiry)", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ assertion: { includeConditions: false } });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.notBefore).toBeNull();
    expect(profile.notOnOrAfter).toBeInstanceOf(Date);
  });

  it("accepts multiple audiences as long as one matches", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      assertion: { audiences: ["urn:someone:else", "urn:test:sp"] },
    });
    await expect(sp.consumeXml(xml)).resolves.toBeDefined();
  });

  it("accepts an unsigned assertion only when requireSignedAssertions is explicitly disabled", async () => {
    const sp = makeSp({ requireSignedAssertions: false });
    const xml = await buildValidResponse({ signAssertion: false });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });
});

describe("response validation — signature enforcement", () => {
  it("rejects a completely unsigned response by default", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ signAssertion: false });
    await expect(sp.consumeXml(xml)).rejects.toThrow(SignatureError);
    await expect(sp.consumeXml(xml)).rejects.toMatchObject({ code: "SAML_SIGNATURE_MISSING" });
  });

  it("rejects an unsigned response when requireSignedResponse is set, even if the assertion is signed", async () => {
    const sp = makeSp({ requireSignedResponse: true });
    const xml = await buildValidResponse(); // assertion signed, response not
    await expect(sp.consumeXml(xml)).rejects.toMatchObject({ code: "SAML_SIGNATURE_MISSING" });
  });

  it("rejects an assertion tampered with after signing", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const tampered = xml.replace("alice@example.com", "mallory@example.com");
    await expect(sp.consumeXml(tampered)).rejects.toThrow(SignatureError);
  });

  it("rejects a response tampered with after response-level signing", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ signAssertion: false, signResponse: true });
    const tampered = xml.replace("alice@example.com", "mallory@example.com");
    await expect(sp.consumeXml(tampered)).rejects.toThrow(SignatureError);
  });

  it("rejects an assertion signed by an untrusted key", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      signOptions: { privateKey: EVIL_KEYS.privateKey },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(SignatureError);
    await expect(sp.consumeXml(xml)).rejects.toMatchObject({ code: "SAML_SIGNATURE_INVALID" });
  });

  it("ignores signatures that are not direct children of the signed element", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    // Relocate the signature into the Subject element: it must no longer count.
    const sigMatch = xml.match(/<ds:Signature[\s\S]*?<\/ds:Signature>/);
    expect(sigMatch).not.toBeNull();
    const moved = xml
      .replace(sigMatch![0], "")
      .replace(/<saml:Subject>/, `<saml:Subject>${sigMatch![0]}`);
    await expect(sp.consumeXml(moved)).rejects.toMatchObject({ code: "SAML_SIGNATURE_MISSING" });
  });

  it("rejects multiple direct-child signatures", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const sigMatch = xml.match(/<ds:Signature[\s\S]*?<\/ds:Signature>/);
    const doubled = xml.replace(sigMatch![0], sigMatch![0] + sigMatch![0]);
    await expect(sp.consumeXml(doubled)).rejects.toThrow(/expected at most one/);
  });

  it("rejects documents where the signed ID is duplicated (wrapping attempt)", async () => {
    const sp = makeSp();
    const assertionId = testId();
    let xml = buildResponseXml(buildAssertionXml({ id: assertionId }));
    xml = signAssertion(xml, assertionId);
    // An attacker smuggles a second element carrying the same ID.
    const wrapped = xml.replace(
      /<saml:Assertion /,
      `<samlp:Extensions><Evil ID="${assertionId}"/></samlp:Extensions><saml:Assertion `
    );
    await expect(sp.consumeXml(wrapped)).rejects.toThrow(/share the ID/);
  });

  it("rejects a signature whose reference URI points at a different element", async () => {
    const sp = makeSp();
    const assertionId = testId();
    const responseId = testId();
    let xml = buildResponseXml(buildAssertionXml({ id: assertionId }), { id: responseId });
    xml = signResponse(xml, responseId);
    // Relocate the (valid) Response signature so it sits inside the Assertion:
    // it now references #responseId, not the assertion's ID.
    const sigMatch = xml.match(/<ds:Signature[\s\S]*?<\/ds:Signature>/);
    expect(sigMatch).not.toBeNull();
    const moved = xml
      .replace(sigMatch![0], "")
      .replace("<saml:Subject>", `${sigMatch![0]}<saml:Subject>`);
    await expect(sp.consumeXml(moved)).rejects.toThrow(SignatureError);
    await expect(sp.consumeXml(moved)).rejects.toThrow(/does not match/);
  });

  it("rejects SHA-1 signatures by default with a helpful message", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      signOptions: { signatureAlgorithm: RSA_SHA1, digestAlgorithm: SHA1_DIGEST },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(/SHA-1 is deprecated/);
  });

  it("accepts SHA-1 signatures when allowSha1 is enabled", async () => {
    const sp = makeSp({ allowSha1: true });
    const xml = await buildValidResponse({
      signOptions: { signatureAlgorithm: RSA_SHA1, digestAlgorithm: SHA1_DIGEST },
    });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.nameId).toBe("alice@example.com");
  });
});

describe("response validation — encryption", () => {
  it("rejects an encrypted assertion when no privateKey is configured", async () => {
    const sp = makeSp({ privateKey: undefined, certificate: undefined });
    const xml = await buildValidResponse({ encrypt: true, signResponse: true });
    await expect(sp.consumeXml(xml)).rejects.toThrow(SAMLConfigError);
  });

  it("rejects an assertion encrypted for a different recipient", async () => {
    const sp = makeSp({ privateKey: EVIL_KEYS.privateKey });
    const xml = await buildValidResponse({ encrypt: true });
    await expect(sp.consumeXml(xml)).rejects.toThrow(DecryptionError);
  });

  it("requires a signature covering the encrypted assertion", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ encrypt: true, signAssertion: false });
    await expect(sp.consumeXml(xml)).rejects.toMatchObject({ code: "SAML_SIGNATURE_MISSING" });
  });
});

describe("response validation — status, addressing, issuer", () => {
  it("surfaces IdP error statuses with structured fields", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml(), {
      statusCode: "urn:oasis:names:tc:SAML:2.0:status:Responder",
      subStatusCode: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
      statusMessage: "User cancelled",
    });
    const err = await sp.consumeXml(xml).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ResponseStatusError);
    const statusErr = err as ResponseStatusError;
    expect(statusErr.statusCode).toBe("urn:oasis:names:tc:SAML:2.0:status:Responder");
    expect(statusErr.subStatusCode).toBe("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
    expect(statusErr.statusMessage).toBe("User cancelled");
  });

  it("rejects a response without a Status element", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml(), { omitStatus: true });
    await expect(sp.consumeXml(xml)).rejects.toThrow(SAMLParseError);
  });

  it("rejects a Status without a StatusCode", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml()).replace(
      /<samlp:StatusCode[\s\S]*?<\/samlp:Status>/,
      "</samlp:Status>"
    );
    await expect(sp.consumeXml(xml)).rejects.toThrow(/no StatusCode element/);
  });

  it("rejects a StatusCode without a Value attribute", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml()).replace(
      /<samlp:StatusCode Value="[^"]*">/,
      "<samlp:StatusCode>"
    );
    await expect(sp.consumeXml(xml)).rejects.toThrow(/no Value attribute/);
  });

  it("rejects a Destination that is not this SP's ACS URL", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml(), {
      destination: "https://evil.example.com/acs",
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(DestinationMismatchError);
  });

  it("rejects a SubjectConfirmationData Recipient that is not the ACS URL", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      assertion: { recipient: "https://evil.example.com/acs" },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(DestinationMismatchError);
  });

  it("rejects a response-level Issuer mismatch", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml(), { issuer: "urn:evil:idp" });
    await expect(sp.consumeXml(xml)).rejects.toThrow(IssuerMismatchError);
  });

  it("rejects an assertion-level Issuer mismatch even when correctly signed", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ assertion: { issuer: "urn:evil:idp" } });
    await expect(sp.consumeXml(xml)).rejects.toThrow(IssuerMismatchError);
  });

  it("rejects an assertion with a missing Issuer", async () => {
    const sp = makeSp({ requireSignedAssertions: false });
    const xml = buildResponseXml(buildAssertionXml({ issuer: null }));
    await expect(sp.consumeXml(xml)).rejects.toThrow(IssuerMismatchError);
  });

  it("rejects an audience restriction that excludes this SP", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({ assertion: { audiences: ["urn:someone:else"] } });
    const err = await sp.consumeXml(xml).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AudienceMismatchError);
    expect((err as AudienceMismatchError).message).toContain("urn:someone:else");
  });
});

describe("response validation — time windows", () => {
  it("rejects an expired assertion", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      assertion: { notOnOrAfter: minutesFromNow(-5), scNotOnOrAfter: minutesFromNow(5) },
    });
    const err = await sp.consumeXml(xml).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AssertionTimeError);
    expect((err as AssertionTimeError).reason).toBe("expired");
  });

  it("rejects a not-yet-valid assertion", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      assertion: { notBefore: minutesFromNow(5), notOnOrAfter: minutesFromNow(10) },
    });
    const err = await sp.consumeXml(xml).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AssertionTimeError);
    expect((err as AssertionTimeError).reason).toBe("not-yet-valid");
  });

  it("tolerates small clock drift within clockSkewMs (default 30s)", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      assertion: {
        notOnOrAfter: new Date(Date.now() - 10_000),
        scNotOnOrAfter: minutesFromNow(5),
      },
    });
    await expect(sp.consumeXml(xml)).resolves.toBeDefined();
  });

  it("enforces strict timing when clockSkewMs is 0", async () => {
    const sp = makeSp({ clockSkewMs: 0 });
    const xml = await buildValidResponse({
      assertion: {
        notOnOrAfter: new Date(Date.now() - 10_000),
        scNotOnOrAfter: minutesFromNow(5),
      },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(AssertionTimeError);
  });

  it("rejects an expired SubjectConfirmationData NotOnOrAfter", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      assertion: { scNotOnOrAfter: minutesFromNow(-5) },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(AssertionTimeError);
  });

  it("rejects a not-yet-valid SubjectConfirmationData NotBefore", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse({
      assertion: { scNotBefore: minutesFromNow(5) },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(AssertionTimeError);
  });

  it("rejects garbage timestamps", async () => {
    const sp = makeSp();
    const assertionId = testId();
    let assertion = buildAssertionXml({ id: assertionId });
    assertion = assertion.replace(/NotBefore="[^"]*"/, 'NotBefore="not-a-date"');
    let xml = buildResponseXml(assertion);
    xml = signAssertion(xml, assertionId);
    await expect(sp.consumeXml(xml)).rejects.toThrow(SAMLParseError);
  });
});

describe("response validation — InResponseTo and replay", () => {
  it("accepts a solicited response answering an outstanding request", async () => {
    const sp = makeSp({ allowUnsolicited: false });
    const login = await sp.createLoginRequest();
    const xml = await buildValidResponse({
      assertion: { inResponseTo: login.id },
      response: { inResponseTo: login.id },
    });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.inResponseTo).toBe(login.id);
  });

  it("accepts InResponseTo carried only on the Response element", async () => {
    const sp = makeSp({ allowUnsolicited: false });
    const login = await sp.createLoginRequest();
    const xml = await buildValidResponse({ response: { inResponseTo: login.id } });
    const { profile } = await sp.consumeXml(xml);
    expect(profile.inResponseTo).toBe(login.id);
  });

  it("rejects a response answering an unknown request", async () => {
    const sp = makeSp({ allowUnsolicited: false });
    const xml = await buildValidResponse({
      assertion: { inResponseTo: "_unknown" },
      response: { inResponseTo: "_unknown" },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(InResponseToError);
  });

  it("rejects the same request ID being answered twice", async () => {
    const sp = makeSp({ allowUnsolicited: false });
    const login = await sp.createLoginRequest();
    const first = await buildValidResponse({
      assertion: { inResponseTo: login.id },
      response: { inResponseTo: login.id },
    });
    await sp.consumeXml(first);
    const second = await buildValidResponse({
      assertion: { inResponseTo: login.id },
      response: { inResponseTo: login.id },
    });
    await expect(sp.consumeXml(second)).rejects.toThrow(InResponseToError);
  });

  it("rejects mismatching InResponseTo between Response and SubjectConfirmationData", async () => {
    const sp = makeSp({ allowUnsolicited: false });
    const login = await sp.createLoginRequest();
    const xml = await buildValidResponse({
      assertion: { inResponseTo: login.id },
      response: { inResponseTo: "_different" },
    });
    await expect(sp.consumeXml(xml)).rejects.toThrow(/mismatch/i);
  });

  it("rejects unsolicited responses unless allowUnsolicited is set", async () => {
    const sp = makeSp({ allowUnsolicited: false });
    const xml = await buildValidResponse();
    await expect(sp.consumeXml(xml)).rejects.toThrow(/allowUnsolicited/);
  });

  it("supports asynchronous request stores", async () => {
    const stored = new Set<string>();
    const sp = makeSp({
      allowUnsolicited: false,
      requestStore: {
        store: (id) => {
          stored.add(id);
          return Promise.resolve();
        },
        consume: (id) => Promise.resolve(stored.delete(id)),
      },
    });
    const login = await sp.createLoginRequest();
    expect(stored.has(login.id)).toBe(true);
    const xml = await buildValidResponse({ assertion: { inResponseTo: login.id } });
    await expect(sp.consumeXml(xml)).resolves.toBeDefined();
  });

  it("detects assertion replay", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    await sp.consumeXml(xml);
    await expect(sp.consumeXml(xml)).rejects.toThrow(ReplayError);
  });
});

describe("response validation — structure", () => {
  const cases: Array<[string, string]> = [
    ["not XML at all", "this is not xml"],
    ["a non-Response root", `<Foo xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/>`],
    [
      "a DOCTYPE declaration",
      `<!DOCTYPE foo [<!ENTITY x "y">]><samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
    ],
  ];
  for (const [name, xml] of cases) {
    it(`rejects ${name}`, async () => {
      const sp = makeSp();
      await expect(sp.consumeXml(xml)).rejects.toThrow(SAMLParseError);
    });
  }

  it("rejects a response with no assertion", async () => {
    const sp = makeSp();
    const xml = buildResponseXml("");
    await expect(sp.consumeXml(xml)).rejects.toThrow(/no Assertion/);
  });

  it("rejects a response with multiple assertions", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml() + buildAssertionXml());
    await expect(sp.consumeXml(xml)).rejects.toThrow(/2 assertions/);
  });

  it("rejects a wrong Response version", async () => {
    const sp = makeSp();
    const xml = buildResponseXml(buildAssertionXml(), { version: "1.1" });
    await expect(sp.consumeXml(xml)).rejects.toThrow(/Version/);
  });

  it("rejects a wrong Assertion version", async () => {
    const sp = makeSp();
    const assertionId = testId();
    let xml = buildResponseXml(buildAssertionXml({ id: assertionId, version: "1.1" }));
    xml = signAssertion(xml, assertionId);
    await expect(sp.consumeXml(xml)).rejects.toThrow(/Version/);
  });

  it("rejects an assertion without an ID", async () => {
    const sp = makeSp({ requireSignedAssertions: false });
    const xml = buildResponseXml(buildAssertionXml().replace(/ID="[^"]*" /, ""));
    await expect(sp.consumeXml(xml)).rejects.toThrow(/no ID/);
  });

  it("handles NameID values containing XML comments without truncation", async () => {
    const sp = makeSp({ requireSignedAssertions: false });
    const assertion = buildAssertionXml().replace(
      "alice@example.com</saml:NameID>",
      "alice@example.com<!---->.evil.test</saml:NameID>"
    );
    const { profile } = await sp.consumeXml(buildResponseXml(assertion));
    // The full text must be extracted — a comment must never truncate the NameID.
    expect(profile.nameId).toBe("alice@example.com.evil.test");
  });
});
