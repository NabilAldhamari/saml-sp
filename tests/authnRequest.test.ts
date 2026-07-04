import { createVerify } from "node:crypto";
import { inflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";
import { SAMLConfigError } from "../src";
import { IDP_SSO_POST_URL, IDP_SSO_URL, SP_ENTITY_ID, makeSp } from "./helpers/fixtures";
import { SP_KEYS } from "./helpers/keys";

function decodeRedirect(url: string): { xml: string; params: URLSearchParams } {
  const parsed = new URL(url);
  const encoded = parsed.searchParams.get("SAMLRequest");
  expect(encoded).not.toBeNull();
  const xml = inflateRawSync(Buffer.from(encoded!, "base64")).toString("utf8");
  return { xml, params: parsed.searchParams };
}

describe("createLoginRequest — redirect binding", () => {
  it("produces a spec-compliant deflated+base64 SAMLRequest", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest();

    expect(login.binding).toBe("redirect");
    expect(login.url.startsWith(`${IDP_SSO_URL}?`)).toBe(true);

    const { xml } = decodeRedirect(login.url);
    expect(xml).toContain("samlp:AuthnRequest");
    expect(xml).toContain(`Destination="${IDP_SSO_URL}"`);
    expect(xml).toContain('Version="2.0"');
    expect(xml).toContain(`<saml:Issuer>${SP_ENTITY_ID}</saml:Issuer>`);
    expect(xml).toContain('AssertionConsumerServiceURL="https://sp.example.com/saml/acs"');
    expect(xml).toContain("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
    expect(xml).toContain("NameIDPolicy");
    expect(xml).toBe(login.xml);
  });

  it("uses the request ID as the AuthnRequest ID attribute", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest();
    expect(login.xml).toContain(`ID="${login.id}"`);
  });

  it("generates a unique ID per request", async () => {
    const sp = makeSp();
    const a = await sp.createLoginRequest();
    const b = await sp.createLoginRequest();
    expect(a.id).not.toBe(b.id);
  });

  it("includes a fresh IssueInstant", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest();
    const instant = login.xml.match(/IssueInstant="([^"]+)"/)?.[1];
    expect(instant).toBeDefined();
    expect(Date.now() - new Date(instant!).getTime()).toBeLessThan(5_000);
  });

  it("propagates RelayState", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest({ relayState: "/return?to=here" });
    const { params } = decodeRedirect(login.url);
    expect(params.get("RelayState")).toBe("/return?to=here");
    expect(login.relayState).toBe("/return?to=here");
  });

  it("preserves query parameters already present on the IdP SSO URL", async () => {
    const sp = makeSp({
      idp: {
        entityId: "urn:test:idp",
        ssoUrl: `${IDP_SSO_URL}?tenant=acme`,
        certificates: [SP_KEYS.certificate],
      },
    });
    const login = await sp.createLoginRequest();
    const parsed = new URL(login.url);
    expect(parsed.searchParams.get("tenant")).toBe("acme");
    expect(parsed.searchParams.get("SAMLRequest")).not.toBeNull();
  });

  it("sets ForceAuthn and IsPassive when requested", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest({ forceAuthn: true, isPassive: true });
    expect(login.xml).toContain('ForceAuthn="true"');
    expect(login.xml).toContain('IsPassive="true"');
  });

  it("omits ForceAuthn and IsPassive by default", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest();
    expect(login.xml).not.toContain("ForceAuthn");
    expect(login.xml).not.toContain("IsPassive");
  });

  it("honours a custom nameIdFormat", async () => {
    const sp = makeSp({ nameIdFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" });
    const login = await sp.createLoginRequest();
    expect(login.xml).toContain('Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"');
  });

  it("records the request ID in the request store", async () => {
    const stored: string[] = [];
    const sp = makeSp({
      requestStore: {
        store: (id) => {
          stored.push(id);
        },
        consume: () => false,
      },
    });
    const login = await sp.createLoginRequest();
    expect(stored).toEqual([login.id]);
  });
});

describe("createLoginRequest — signed redirect binding", () => {
  it("signs the query string per the HTTP-Redirect binding spec", async () => {
    const sp = makeSp({ signAuthnRequests: true });
    const login = await sp.createLoginRequest({ relayState: "abc" });

    const query = login.url.split("?")[1]!;
    const parts = query.split("&");
    const sigIndex = parts.findIndex((p) => p.startsWith("Signature="));
    expect(sigIndex).toBe(parts.length - 1);

    const signedData = parts.slice(0, sigIndex).join("&");
    expect(signedData).toMatch(/^SAMLRequest=.*&RelayState=abc&SigAlg=/);

    const signature = decodeURIComponent(parts[sigIndex]!.slice("Signature=".length));
    const verifier = createVerify("RSA-SHA256");
    verifier.update(signedData);
    expect(verifier.verify(SP_KEYS.certificate, Buffer.from(signature, "base64"))).toBe(true);
  });

  it("produces a signature that fails verification if the query is tampered with", async () => {
    const sp = makeSp({ signAuthnRequests: true });
    const login = await sp.createLoginRequest({ relayState: "abc" });

    const query = login.url.split("?")[1]!;
    const parts = query.split("&");
    const sigIndex = parts.findIndex((p) => p.startsWith("Signature="));
    const tampered = parts
      .slice(0, sigIndex)
      .join("&")
      .replace("RelayState=abc", "RelayState=evil");
    const signature = decodeURIComponent(parts[sigIndex]!.slice("Signature=".length));

    const verifier = createVerify("RSA-SHA256");
    verifier.update(tampered);
    expect(verifier.verify(SP_KEYS.certificate, Buffer.from(signature, "base64"))).toBe(false);
  });
});

describe("createLoginRequest — POST binding", () => {
  it("returns base64 fields and an auto-submitting form", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest({ binding: "post", relayState: "xyz" });

    expect(login.binding).toBe("post");
    expect(login.url).toBe(IDP_SSO_POST_URL);
    const xml = Buffer.from(login.fields!.SAMLRequest!, "base64").toString("utf8");
    expect(xml).toContain("samlp:AuthnRequest");
    expect(xml).toContain(`Destination="${IDP_SSO_POST_URL}"`);
    expect(login.fields!.RelayState).toBe("xyz");
    expect(login.html).toContain(`action="${IDP_SSO_POST_URL}"`);
    expect(login.html).toContain("document.forms[0].submit()");
  });

  it("escapes HTML metacharacters in form values", async () => {
    const sp = makeSp();
    const login = await sp.createLoginRequest({
      binding: "post",
      relayState: `"><script>alert(1)</script>`,
    });
    expect(login.html).not.toContain("<script>alert(1)</script>");
    expect(login.html).toContain("&quot;&gt;&lt;script&gt;");
  });

  it("embeds a verifiable XML signature when signAuthnRequests is enabled", async () => {
    const sp = makeSp({ signAuthnRequests: true });
    const login = await sp.createLoginRequest({ binding: "post" });

    expect(login.xml).toContain("ds:Signature");
    // The signature must sit inside the AuthnRequest, right after Issuer.
    expect(login.xml).toMatch(/<\/saml:Issuer><ds:Signature/);

    const sig = new SignedXml({ publicCert: SP_KEYS.certificate });
    const signatureXml = login.xml.match(/<ds:Signature[\s\S]*?<\/ds:Signature>/)![0];
    sig.loadSignature(signatureXml);
    expect(sig.checkSignature(login.xml)).toBe(true);
  });

  it("is used automatically when the IdP only offers a POST endpoint", async () => {
    const sp = makeSp({
      idp: {
        entityId: "urn:test:idp",
        ssoPostUrl: IDP_SSO_POST_URL,
        certificates: [SP_KEYS.certificate],
      },
    });
    const login = await sp.createLoginRequest();
    expect(login.binding).toBe("post");
  });

  it("rejects an explicit binding the IdP does not offer", async () => {
    const spNoPost = makeSp({
      idp: {
        entityId: "urn:test:idp",
        ssoUrl: IDP_SSO_URL,
        certificates: [SP_KEYS.certificate],
      },
    });
    await expect(spNoPost.createLoginRequest({ binding: "post" })).rejects.toThrow(SAMLConfigError);

    const spNoRedirect = makeSp({
      idp: {
        entityId: "urn:test:idp",
        ssoPostUrl: IDP_SSO_POST_URL,
        certificates: [SP_KEYS.certificate],
      },
    });
    await expect(spNoRedirect.createLoginRequest({ binding: "redirect" })).rejects.toThrow(
      SAMLConfigError
    );
  });
});
