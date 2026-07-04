import { SAMLConfigError, SAMLError, SAMLValidationError, SignatureError } from "../src";
import { parseXml, serialize } from "../src/internal/parse";
import { certificateBody, normalizeCertificate } from "../src/internal/pem";
import {
  buildAssertionXml,
  buildResponseXml,
  makeSp,
  signAssertion,
  testId,
} from "./helpers/fixtures";
import { EVIL_KEYS, IDP_KEYS } from "./helpers/keys";

describe("pem helpers", () => {
  it("normalizes a PEM certificate to canonical form", () => {
    const pem = normalizeCertificate(IDP_KEYS.certificate);
    expect(pem.startsWith("-----BEGIN CERTIFICATE-----\n")).toBe(true);
    expect(pem.endsWith("-----END CERTIFICATE-----\n")).toBe(true);
    // Idempotent
    expect(normalizeCertificate(pem)).toBe(pem);
  });

  it("normalizes raw base64 (metadata-style) input", () => {
    const body = certificateBody(IDP_KEYS.certificate);
    const scattered = body.replace(/(.{40})/g, "$1\n  ");
    expect(normalizeCertificate(scattered)).toBe(normalizeCertificate(IDP_KEYS.certificate));
  });

  it.each([
    ["empty input", ""],
    ["whitespace only", "   \n  "],
    ["non-base64 characters", "@@@not-base64@@@"],
  ])("rejects %s", (_name, input) => {
    expect(() => normalizeCertificate(input)).toThrow(SAMLConfigError);
  });

  it("strips PEM armour in certificateBody", () => {
    const body = certificateBody(IDP_KEYS.certificate);
    expect(body).not.toContain("BEGIN");
    expect(body).not.toMatch(/\s/);
  });
});

describe("parse helpers", () => {
  it("parses and serializes round-trip", () => {
    const doc = parseXml(`<a xmlns="urn:x"><b>hi</b></a>`);
    expect(serialize(doc.documentElement!)).toContain("<b>hi</b>");
  });

  it("rejects a document with no root element", () => {
    expect(() => parseXml("<!-- only a comment -->")).toThrow(SAMLError);
  });

  it("rejects an empty string", () => {
    expect(() => parseXml("")).toThrow(SAMLError);
  });

  it("rejects DOCTYPE case-insensitively", () => {
    expect(() => parseXml(`<!doctype html><a/>`)).toThrow(/DOCTYPE/);
  });
});

describe("signature verification edge cases", () => {
  it("wraps low-level xml-crypto failures in SignatureError", async () => {
    const sp = makeSp();
    const assertionId = testId();
    let xml = buildResponseXml(buildAssertionXml({ id: assertionId }));
    xml = signAssertion(xml, assertionId);
    // Corrupt the SignatureValue so xml-crypto throws instead of returning false.
    const corrupted = xml.replace(
      /<ds:SignatureValue>[^<]+<\/ds:SignatureValue>/,
      "<ds:SignatureValue>@@@ not base64 @@@</ds:SignatureValue>"
    );
    const err = await sp.consumeXml(corrupted).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SignatureError);
  });

  it("reports failure against all certificates when several are configured", async () => {
    const sp = makeSp({
      idp: {
        entityId: "urn:test:idp",
        ssoUrl: "https://idp.example.com/sso/redirect",
        certificates: [EVIL_KEYS.certificate, EVIL_KEYS.certificate],
      },
    });
    const assertionId = testId();
    let xml = buildResponseXml(buildAssertionXml({ id: assertionId }));
    xml = signAssertion(xml, assertionId);
    await expect(sp.consumeXml(xml)).rejects.toThrow(SignatureError);
  });
});

describe("base error classes", () => {
  it("SAMLError defaults to the SAML_ERROR code", () => {
    const err = new SAMLError("generic");
    expect(err.code).toBe("SAML_ERROR");
    expect(err.name).toBe("SAMLError");
  });

  it("SAMLValidationError defaults to SAML_VALIDATION_ERROR", () => {
    expect(new SAMLValidationError("v").code).toBe("SAML_VALIDATION_ERROR");
  });
});
