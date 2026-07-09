import { inflateRawSync } from "node:zlib";
import {
  DestinationMismatchError,
  InResponseToError,
  IssuerMismatchError,
  ResponseStatusError,
  SAMLConfigError,
  SAMLParseError,
  SignatureError,
} from "../src";
import { parseRedirectQuery, verifyRedirectSignature } from "../src/internal/redirectBinding";
import {
  IDP_ENTITY_ID,
  IDP_SLO_URL,
  SP_ENTITY_ID,
  SP_SLO_URL,
  buildIdpLogoutRequestXml,
  buildIdpLogoutResponseXml,
  makeLogoutSp,
  makeSp,
  mockGetRequestWithQuery,
  toRedirectQuery,
} from "./helpers/fixtures";
import { SP_KEYS } from "./helpers/keys";

const RSA_SHA1_SIG = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

function decodeRedirect(url: string): { xml: string; params: URLSearchParams } {
  const parsed = new URL(url);
  const type = parsed.searchParams.has("SAMLRequest") ? "SAMLRequest" : "SAMLResponse";
  const encoded = parsed.searchParams.get(type)!;
  const xml = inflateRawSync(Buffer.from(encoded, "base64")).toString("utf8");
  return { xml, params: parsed.searchParams };
}

// ---------------------------------------------------------------------------
// SP-initiated logout: createLogoutRequest
// ---------------------------------------------------------------------------

describe("createLogoutRequest", () => {
  it("builds a signed redirect to the IdP SLO endpoint", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({
      nameId: "alice@example.com",
      nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
      sessionIndex: "session-123",
    });

    expect(logout.binding).toBe("redirect");
    expect(logout.url.startsWith(`${IDP_SLO_URL}?`)).toBe(true);

    const { xml, params } = decodeRedirect(logout.url);
    expect(xml).toContain("samlp:LogoutRequest");
    expect(xml).toContain(`ID="${logout.id}"`);
    expect(xml).toContain(`<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>`);
    expect(xml).toContain("alice@example.com");
    expect(xml).toContain('Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"');
    expect(xml).toContain("<samlp:SessionIndex>session-123</samlp:SessionIndex>");

    // The query is signed with the SP key by default.
    expect(params.get("Signature")).not.toBeNull();
    const parsed = parseRedirectQuery(logout.url.split("?")[1]!, 1_048_576);
    expect(() => verifyRedirectSignature(parsed, [SP_KEYS.certificate], false)).not.toThrow();
  });

  it("stores the request ID for InResponseTo correlation", async () => {
    const stored: string[] = [];
    const sp = makeLogoutSp({
      requestStore: {
        store: (id) => {
          stored.push(id);
        },
        consume: () => true,
      },
    });
    const logout = await sp.createLogoutRequest({ nameId: "alice@example.com" });
    expect(stored).toEqual([logout.id]);
  });

  it("omits the NameID Format and SessionIndex when not provided", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "alice@example.com" });
    const { xml } = decodeRedirect(logout.url);
    expect(xml).not.toContain("Format=");
    expect(xml).not.toContain("SessionIndex");
  });

  it("propagates RelayState", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com", relayState: "/bye" });
    expect(new URL(logout.url).searchParams.get("RelayState")).toBe("/bye");
    expect(logout.relayState).toBe("/bye");
  });

  it("does not sign when signLogoutMessages is false", async () => {
    const sp = makeLogoutSp({ signLogoutMessages: false });
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    expect(new URL(logout.url).searchParams.get("Signature")).toBeNull();
  });

  it("throws when the IdP has no SLO endpoint", async () => {
    const sp = makeSp({
      idp: {
        entityId: IDP_ENTITY_ID,
        ssoUrl: "https://idp.example.com/sso",
        certificates: [SP_KEYS.certificate],
      },
      singleLogoutServiceUrl: SP_SLO_URL,
    });
    await expect(sp.createLogoutRequest({ nameId: "a@b.com" })).rejects.toThrow(SAMLConfigError);
  });

  it("throws when nameId is missing", async () => {
    const sp = makeLogoutSp();
    await expect(sp.createLogoutRequest({ nameId: "" })).rejects.toThrow(SAMLConfigError);
  });
});

// ---------------------------------------------------------------------------
// receiveLogout: LogoutResponse (answering our SP-initiated logout)
// ---------------------------------------------------------------------------

describe("receiveLogout — LogoutResponse", () => {
  it("completes an SP-initiated logout round trip", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "alice@example.com" });

    const responseXml = buildIdpLogoutResponseXml({ inResponseTo: logout.id });
    const query = toRedirectQuery("SAMLResponse", responseXml, { relayState: "/done" });

    const result = await sp.receiveLogout(query);
    expect(result.type).toBe("response");
    if (result.type === "response") {
      expect(result.success).toBe(true);
      expect(result.issuer).toBe(IDP_ENTITY_ID);
      expect(result.inResponseTo).toBe(logout.id);
      expect(result.relayState).toBe("/done");
    }
  });

  it("rejects a response answering an unknown request", async () => {
    const sp = makeLogoutSp();
    const responseXml = buildIdpLogoutResponseXml({ inResponseTo: "_never-issued" });
    const query = toRedirectQuery("SAMLResponse", responseXml);
    await expect(sp.receiveLogout(query)).rejects.toThrow(InResponseToError);
  });

  it("surfaces a non-Success logout status", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    const responseXml = buildIdpLogoutResponseXml({
      inResponseTo: logout.id,
      statusCode: "urn:oasis:names:tc:SAML:2.0:status:Requester",
      statusMessage: "Partial logout",
    });
    const query = toRedirectQuery("SAMLResponse", responseXml);
    const err = await sp.receiveLogout(query).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ResponseStatusError);
    expect((err as ResponseStatusError).statusMessage).toBe("Partial logout");
  });

  it("rejects a response from the wrong issuer", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    const responseXml = buildIdpLogoutResponseXml({
      inResponseTo: logout.id,
      issuer: "urn:evil:idp",
    });
    const query = toRedirectQuery("SAMLResponse", responseXml);
    await expect(sp.receiveLogout(query)).rejects.toThrow(IssuerMismatchError);
  });

  it("rejects a response addressed to a different SLO endpoint", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    const responseXml = buildIdpLogoutResponseXml({
      inResponseTo: logout.id,
      destination: "https://evil.example.com/slo",
    });
    const query = toRedirectQuery("SAMLResponse", responseXml);
    await expect(sp.receiveLogout(query)).rejects.toThrow(DestinationMismatchError);
  });

  it("rejects an unsigned response when signed logout is required", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    const responseXml = buildIdpLogoutResponseXml({ inResponseTo: logout.id });
    const query = toRedirectQuery("SAMLResponse", responseXml, { privateKey: null });
    await expect(sp.receiveLogout(query)).rejects.toMatchObject({
      code: "SAML_SIGNATURE_MISSING",
    });
  });

  it("accepts an unsigned response when requireSignedLogout is false", async () => {
    const sp = makeLogoutSp({ requireSignedLogout: false });
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    const responseXml = buildIdpLogoutResponseXml({ inResponseTo: logout.id });
    const query = toRedirectQuery("SAMLResponse", responseXml, { privateKey: null });
    const result = await sp.receiveLogout(query);
    expect(result.type).toBe("response");
  });

  it("rejects a response whose signature does not verify", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    const responseXml = buildIdpLogoutResponseXml({ inResponseTo: logout.id });
    let query = toRedirectQuery("SAMLResponse", responseXml);
    // Flip the RelayState after signing so the signed string no longer matches.
    query = `${query}&RelayState=tampered`;
    await expect(sp.receiveLogout(query)).rejects.toThrow(SignatureError);
  });

  it("rejects SHA-1 signatures by default but accepts them with allowSha1", async () => {
    const strict = makeLogoutSp();
    const lenient = makeLogoutSp({ allowSha1: true });
    const logoutStrict = await strict.createLogoutRequest({ nameId: "a@b.com" });
    const logoutLenient = await lenient.createLogoutRequest({ nameId: "a@b.com" });

    const strictQuery = toRedirectQuery(
      "SAMLResponse",
      buildIdpLogoutResponseXml({ inResponseTo: logoutStrict.id }),
      { sigAlg: RSA_SHA1_SIG }
    );
    await expect(strict.receiveLogout(strictQuery)).rejects.toThrow(/SHA-1 is deprecated/);

    const lenientQuery = toRedirectQuery(
      "SAMLResponse",
      buildIdpLogoutResponseXml({ inResponseTo: logoutLenient.id }),
      { sigAlg: RSA_SHA1_SIG }
    );
    await expect(lenient.receiveLogout(lenientQuery)).resolves.toMatchObject({ type: "response" });
  });
});

// ---------------------------------------------------------------------------
// receiveLogout: IdP-initiated LogoutRequest
// ---------------------------------------------------------------------------

describe("receiveLogout — IdP-initiated LogoutRequest", () => {
  it("returns the subject and a signed acknowledgement URL", async () => {
    const sp = makeLogoutSp();
    const requestXml = buildIdpLogoutRequestXml({
      id: "_idp-req-1",
      nameId: "bob@example.com",
      sessionIndex: "sess-9",
    });
    const query = toRedirectQuery("SAMLRequest", requestXml, { relayState: "/state" });

    const result = await sp.receiveLogout(query);
    expect(result.type).toBe("request");
    if (result.type === "request") {
      expect(result.nameId).toBe("bob@example.com");
      expect(result.sessionIndex).toBe("sess-9");
      expect(result.issuer).toBe(IDP_ENTITY_ID);
      expect(result.relayState).toBe("/state");

      const { xml, params } = decodeRedirect(result.responseUrl);
      expect(result.responseUrl.startsWith(`${IDP_SLO_URL}?`)).toBe(true);
      expect(xml).toContain("samlp:LogoutResponse");
      expect(xml).toContain('InResponseTo="_idp-req-1"');
      expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:status:Success");
      // RelayState is echoed back to the IdP, and the response is signed by the SP.
      expect(params.get("RelayState")).toBe("/state");
      const parsed = parseRedirectQuery(result.responseUrl.split("?")[1]!, 1_048_576);
      expect(() => verifyRedirectSignature(parsed, [SP_KEYS.certificate], false)).not.toThrow();
    }
  });

  it("rejects a LogoutRequest from the wrong issuer", async () => {
    const sp = makeLogoutSp();
    const query = toRedirectQuery(
      "SAMLRequest",
      buildIdpLogoutRequestXml({ issuer: "urn:evil:idp" })
    );
    await expect(sp.receiveLogout(query)).rejects.toThrow(IssuerMismatchError);
  });

  it("rejects a LogoutRequest addressed to the wrong endpoint", async () => {
    const sp = makeLogoutSp();
    const query = toRedirectQuery(
      "SAMLRequest",
      buildIdpLogoutRequestXml({ destination: "https://evil.example.com/slo" })
    );
    await expect(sp.receiveLogout(query)).rejects.toThrow(DestinationMismatchError);
  });

  it("rejects an unsigned IdP LogoutRequest when signed logout is required", async () => {
    const sp = makeLogoutSp();
    const query = toRedirectQuery("SAMLRequest", buildIdpLogoutRequestXml(), {
      privateKey: null,
    });
    await expect(sp.receiveLogout(query)).rejects.toMatchObject({
      code: "SAML_SIGNATURE_MISSING",
    });
  });

  it("acknowledges without signing when the SP has no privateKey", async () => {
    const sp = makeSp({
      privateKey: undefined,
      certificate: undefined,
      singleLogoutServiceUrl: SP_SLO_URL,
      requireSignedLogout: false,
    });
    const query = toRedirectQuery("SAMLRequest", buildIdpLogoutRequestXml(), {
      privateKey: null,
    });
    const result = await sp.receiveLogout(query);
    expect(result.type).toBe("request");
    if (result.type === "request") {
      expect(new URL(result.responseUrl).searchParams.get("Signature")).toBeNull();
    }
  });
});

// ---------------------------------------------------------------------------
// receiveLogout: malformed messages and edge cases
// ---------------------------------------------------------------------------

describe("receiveLogout — malformed messages", () => {
  const lenient = () => makeLogoutSp({ requireSignedLogout: false });

  it("exposes nested sub-status on logout failures", async () => {
    const sp = makeLogoutSp();
    const logout = await sp.createLogoutRequest({ nameId: "a@b.com" });
    const query = toRedirectQuery(
      "SAMLResponse",
      buildIdpLogoutResponseXml({
        inResponseTo: logout.id,
        statusCode: "urn:oasis:names:tc:SAML:2.0:status:Responder",
        subStatusCode: "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
      })
    );
    const err = await sp.receiveLogout(query).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ResponseStatusError);
    expect((err as ResponseStatusError).subStatusCode).toBe(
      "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
    );
  });

  it("treats a LogoutResponse without a Status as a failure", async () => {
    const sp = lenient();
    const query = toRedirectQuery("SAMLResponse", buildIdpLogoutResponseXml({ omitStatus: true }), {
      privateKey: null,
    });
    const err = await sp.receiveLogout(query).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ResponseStatusError);
    expect((err as ResponseStatusError).statusCode).toBe("<missing>");
  });

  it("rejects a LogoutResponse without an ID", async () => {
    const sp = lenient();
    const xml = buildIdpLogoutResponseXml().replace(/ID="[^"]*" /, "");
    const query = toRedirectQuery("SAMLResponse", xml, { privateKey: null });
    await expect(sp.receiveLogout(query)).rejects.toThrow(/no ID/);
  });

  it("rejects a LogoutRequest without an ID", async () => {
    const sp = lenient();
    const xml = buildIdpLogoutRequestXml().replace(/ID="[^"]*" /, "");
    const query = toRedirectQuery("SAMLRequest", xml, { privateKey: null });
    await expect(sp.receiveLogout(query)).rejects.toThrow(/no ID/);
  });

  it("rejects a SAMLRequest that is not a LogoutRequest", async () => {
    const sp = lenient();
    const query = toRedirectQuery(
      "SAMLRequest",
      `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_x"/>`,
      { privateKey: null }
    );
    await expect(sp.receiveLogout(query)).rejects.toThrow(/Expected a samlp:LogoutRequest/);
  });

  it("handles a LogoutRequest without a NameID", async () => {
    const sp = lenient();
    const xml = buildIdpLogoutRequestXml().replace(/<saml:NameID>[^<]*<\/saml:NameID>/, "");
    const query = toRedirectQuery("SAMLRequest", xml, { privateKey: null });
    const result = await sp.receiveLogout(query);
    expect(result.type).toBe("request");
    if (result.type === "request") {
      expect(result.nameId).toBeNull();
    }
  });

  it("fails to acknowledge when the IdP has no SLO endpoint", async () => {
    // A LogoutRequest arrives, but the IdP metadata never declared where to answer.
    const sp = makeSp({
      idp: {
        entityId: IDP_ENTITY_ID,
        ssoUrl: "https://idp.example.com/sso",
        certificates: [SP_KEYS.certificate],
      },
      singleLogoutServiceUrl: SP_SLO_URL,
      requireSignedLogout: false,
    });
    const query = toRedirectQuery("SAMLRequest", buildIdpLogoutRequestXml(), {
      privateKey: null,
    });
    await expect(sp.receiveLogout(query)).rejects.toThrow(SAMLConfigError);
  });
});

// ---------------------------------------------------------------------------
// receiveLogout: input handling
// ---------------------------------------------------------------------------

describe("receiveLogout — input handling", () => {
  it("accepts a GET IncomingMessage carrying the query", async () => {
    const sp = makeLogoutSp();
    const req = mockGetRequestWithQuery(toRedirectQuery("SAMLRequest", buildIdpLogoutRequestXml()));
    const result = await sp.receiveLogout(req as never);
    expect(result.type).toBe("request");
  });

  it("rejects a query with neither SAMLRequest nor SAMLResponse", async () => {
    const sp = makeLogoutSp({ requireSignedLogout: false });
    await expect(sp.receiveLogout("foo=bar")).rejects.toThrow(SAMLParseError);
  });

  it("rejects an undecodable message", async () => {
    const sp = makeLogoutSp({ requireSignedLogout: false });
    await expect(sp.receiveLogout("SAMLRequest=not%20deflate")).rejects.toThrow(SAMLParseError);
  });

  it("rejects an oversized query", async () => {
    const sp = makeLogoutSp({ maxResponseSize: 32, requireSignedLogout: false });
    const query = toRedirectQuery("SAMLRequest", buildIdpLogoutRequestXml());
    await expect(sp.receiveLogout(query)).rejects.toThrow(/maximum accepted size/);
  });

  it("rejects a non-GET, non-string input", async () => {
    const sp = makeLogoutSp();
    await expect(sp.receiveLogout(42 as never)).rejects.toThrow(SAMLParseError);
  });

  it("rejects a request whose URL has no query string", async () => {
    const sp = makeLogoutSp();
    const req = mockGetRequestWithQuery("");
    (req as unknown as { url: string }).url = "/saml/slo"; // no '?' at all
    await expect(sp.receiveLogout(req as never)).rejects.toThrow(
      /neither a SAMLRequest nor a SAMLResponse/
    );
  });
});

// ---------------------------------------------------------------------------
// Metadata advertises the SP SingleLogoutService
// ---------------------------------------------------------------------------

describe("metadata with SLO", () => {
  it("advertises SingleLogoutService when configured", () => {
    const sp = makeLogoutSp();
    const xml = sp.metadata();
    expect(xml).toContain("md:SingleLogoutService");
    expect(xml).toContain(`Location="${SP_SLO_URL}"`);
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect");
  });

  it("omits SingleLogoutService when not configured", () => {
    const sp = makeSp();
    expect(sp.metadata()).not.toContain("SingleLogoutService");
  });
});
