import { X509Certificate, createPrivateKey } from "node:crypto";
import { IdentityProvider, SAMLConfigError, SAMLParseError, ServiceProvider } from "../src";
import {
  ACS_URL,
  buildValidResponse,
  makeSp,
  mockGetRequest,
  mockPostRequest,
  toPostBody,
} from "./helpers/fixtures";
import { IDP_KEYS, SP_KEYS } from "./helpers/keys";

const IDP_CONFIG = {
  entityId: "urn:test:idp",
  ssoUrl: "https://idp.example.com/sso",
  certificates: [IDP_KEYS.certificate],
};

describe("ServiceProvider — configuration validation", () => {
  const base = {
    entityId: "urn:test:sp",
    assertionConsumerServiceUrl: ACS_URL,
    idp: IDP_CONFIG,
  };

  it("constructs with a plain IdP config object", () => {
    const sp = new ServiceProvider(base);
    expect(sp.idp).toBeInstanceOf(IdentityProvider);
  });

  it("constructs with an IdentityProvider instance", () => {
    const idp = new IdentityProvider(IDP_CONFIG);
    const sp = new ServiceProvider({ ...base, idp });
    expect(sp.idp).toBe(idp);
  });

  it.each([
    ["empty entityId", { ...base, entityId: "  " }],
    ["missing entityId", { ...base, entityId: undefined }],
    ["missing ACS URL", { ...base, assertionConsumerServiceUrl: undefined }],
    ["relative ACS URL", { ...base, assertionConsumerServiceUrl: "/saml/acs" }],
    ["non-http ACS URL", { ...base, assertionConsumerServiceUrl: "ftp://sp.example.com/acs" }],
    ["missing idp", { ...base, idp: undefined }],
    ["invalid privateKey", { ...base, privateKey: "not-a-key" }],
    ["invalid certificate", { ...base, certificate: "not-a-cert" }],
    ["negative clockSkewMs", { ...base, clockSkewMs: -1 }],
    ["NaN clockSkewMs", { ...base, clockSkewMs: Number.NaN }],
    ["zero maxResponseSize", { ...base, maxResponseSize: 0 }],
    ["signAuthnRequests without privateKey", { ...base, signAuthnRequests: true }],
  ])("rejects %s", (_name, config) => {
    expect(() => new ServiceProvider(config as never)).toThrow(SAMLConfigError);
  });

  it("trims the entityId", () => {
    const sp = new ServiceProvider({ ...base, entityId: "  urn:test:sp  " });
    expect(sp.entityId).toBe("urn:test:sp");
  });
});

describe("ServiceProvider.generateKeyPair", () => {
  it("returns a usable PEM keypair", () => {
    const kp = ServiceProvider.generateKeyPair();
    expect(() => createPrivateKey(kp.privateKey)).not.toThrow();
    const cert = new X509Certificate(kp.certificate);
    expect(cert.subject).toContain("saml-sp");
  });

  it("honours a custom common name", () => {
    const kp = ServiceProvider.generateKeyPair({ commonName: "my-app" });
    expect(new X509Certificate(kp.certificate).subject).toContain("my-app");
  });

  it("produces keypairs accepted by the ServiceProvider constructor", () => {
    const kp = ServiceProvider.generateKeyPair();
    expect(
      () =>
        new ServiceProvider({
          entityId: "urn:test:sp",
          assertionConsumerServiceUrl: ACS_URL,
          idp: IDP_CONFIG,
          privateKey: kp.privateKey,
          certificate: kp.certificate,
        })
    ).not.toThrow();
  });
});

describe("ServiceProvider.consume — input handling", () => {
  it("consumes a pre-parsed body object and returns RelayState", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const { profile, relayState } = await sp.consume({
      SAMLResponse: Buffer.from(xml).toString("base64"),
      RelayState: "/dashboard",
    });
    expect(profile.nameId).toBe("alice@example.com");
    expect(relayState).toBe("/dashboard");
  });

  it("omits relayState when the IdP sends an empty one", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const result = await sp.consume({
      SAMLResponse: Buffer.from(xml).toString("base64"),
      RelayState: "",
    });
    expect(result.relayState).toBeUndefined();
  });

  it("consumes a raw IncomingMessage POST", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const req = mockPostRequest(toPostBody(xml, "/after-login"));
    const { profile, relayState } = await sp.consume(req as never);
    expect(profile.nameId).toBe("alice@example.com");
    expect(relayState).toBe("/after-login");
  });

  it("handles chunked request bodies", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const req = mockPostRequest(toPostBody(xml), 64);
    const { profile } = await sp.consume(req as never);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("handles string chunks from decoded streams", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const req = mockGetRequest();
    req.method = "POST";
    process.nextTick(() => {
      req.emit("data", toPostBody(xml)); // string, not Buffer
      req.emit("end");
    });
    const { profile } = await sp.consume(req as never);
    expect(profile.nameId).toBe("alice@example.com");
  });

  it("rejects non-POST requests with a helpful message", async () => {
    const sp = makeSp();
    await expect(sp.consume(mockGetRequest() as never)).rejects.toThrow(/HTTP POST/);
  });

  it("rejects bodies without a SAMLResponse parameter", async () => {
    const sp = makeSp();
    const req = mockPostRequest("foo=bar");
    await expect(sp.consume(req as never)).rejects.toThrow(/no SAMLResponse/);
  });

  it("propagates request stream errors", async () => {
    const sp = makeSp();
    const req = mockGetRequest();
    req.method = "POST";
    process.nextTick(() => req.emit("error", new Error("socket hang up")));
    await expect(sp.consume(req as never)).rejects.toThrow("socket hang up");
  });

  it("aborts oversized request bodies and destroys the socket", async () => {
    const sp = makeSp({ maxResponseSize: 128 });
    const req = mockPostRequest(`SAMLResponse=${"A".repeat(4096)}`, 64);
    await expect(sp.consume(req as never)).rejects.toThrow(/maximum accepted size/);
    expect(req.destroyed).toBe(true);
  });

  it("rejects an oversized SAMLResponse in a pre-parsed body", async () => {
    const sp = makeSp({ maxResponseSize: 64 });
    await expect(sp.consume({ SAMLResponse: "A".repeat(100) })).rejects.toThrow(
      /maximum accepted size/
    );
  });

  it.each([
    ["null", null],
    ["a number", 42],
    ["an object without SAMLResponse", { foo: "bar" }],
  ])("rejects %s as input", async (_name, input) => {
    const sp = makeSp();
    await expect(sp.consume(input as never)).rejects.toThrow(SAMLParseError);
  });

  it("rejects a SAMLResponse that is not base64", async () => {
    const sp = makeSp();
    await expect(sp.consume({ SAMLResponse: "!!!not-base64!!!" })).rejects.toThrow(
      /not valid base64/
    );
  });

  it("rejects base64 that does not decode to XML", async () => {
    const sp = makeSp();
    await expect(
      sp.consume({ SAMLResponse: Buffer.from("hello world").toString("base64") })
    ).rejects.toThrow(/not XML/);
  });

  it("tolerates whitespace inside the base64 payload", async () => {
    const sp = makeSp();
    const xml = await buildValidResponse();
    const b64 = Buffer.from(xml).toString("base64");
    const withNewlines = b64.replace(/(.{76})/g, "$1\n");
    const { profile } = await sp.consume({ SAMLResponse: withNewlines });
    expect(profile.nameId).toBe("alice@example.com");
  });
});

describe("ServiceProvider.consumeXml — input handling", () => {
  it("rejects empty input", async () => {
    const sp = makeSp();
    await expect(sp.consumeXml("")).rejects.toThrow(SAMLParseError);
    await expect(sp.consumeXml("   ")).rejects.toThrow(SAMLParseError);
  });

  it("rejects oversized XML", async () => {
    const sp = makeSp({ maxResponseSize: 16 });
    await expect(sp.consumeXml("<Response></Response>")).rejects.toThrow(/maximum accepted size/);
  });
});

describe("ServiceProvider.metadata", () => {
  it("emits accurate SP metadata", () => {
    const sp = makeSp();
    const xml = sp.metadata();
    expect(xml).toContain('entityID="urn:test:sp"');
    expect(xml).toContain(`Location="${ACS_URL}"`);
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    expect(xml).toContain('AuthnRequestsSigned="false"');
    expect(xml).toContain('WantAssertionsSigned="true"');
    expect(xml).toContain('use="signing"');
    expect(xml).toContain('use="encryption"');
    // v2 bugs that must stay fixed:
    expect(xml).not.toContain("SingleLogoutService");
    expect(xml).not.toContain("validUntil");
  });

  it("reflects signAuthnRequests and requireSignedAssertions in the flags", () => {
    const sp = makeSp({ signAuthnRequests: true, requireSignedAssertions: false });
    const xml = sp.metadata();
    expect(xml).toContain('AuthnRequestsSigned="true"');
    expect(xml).toContain('WantAssertionsSigned="false"');
  });

  it("omits KeyDescriptors when no certificate is configured", () => {
    const sp = makeSp({ certificate: undefined, privateKey: undefined });
    expect(sp.metadata()).not.toContain("KeyDescriptor");
  });

  it("includes validUntil only when requested", () => {
    const sp = makeSp();
    const until = new Date("2030-01-01T00:00:00.000Z");
    expect(sp.metadata({ validUntil: until })).toContain('validUntil="2030-01-01T00:00:00.000Z"');
  });

  it("embeds the certificate body without PEM armour", () => {
    const sp = makeSp();
    const xml = sp.metadata();
    expect(xml).not.toContain("BEGIN CERTIFICATE");
    const body = SP_KEYS.certificate
      .replace(/-----(BEGIN|END) CERTIFICATE-----/g, "")
      .replace(/\s+/g, "");
    expect(xml).toContain(body.slice(0, 60));
  });

  it("is rejected by IdentityProvider.fromMetadata with a helpful message", () => {
    const sp = makeSp();
    expect(() => IdentityProvider.fromMetadata(sp.metadata())).toThrow(/IdP.*not SP|not.*IdP/i);
  });
});
