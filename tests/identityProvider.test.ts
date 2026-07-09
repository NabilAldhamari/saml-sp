import { IdentityProvider, SAMLConfigError, SAMLParseError } from "../src";
import { certificateBody } from "../src/internal/pem";
import { IDP_KEYS } from "./helpers/keys";

const CERT_BODY = certificateBody(IDP_KEYS.certificate);

/** Okta-shaped metadata: md: prefixes, both bindings, single signing cert. */
function oktaMetadata({
  certBodies = [CERT_BODY],
  wantSigned = false,
  withSlo = false,
}: { certBodies?: string[]; wantSigned?: boolean; withSlo?: boolean } = {}): string {
  const slo = withSlo
    ? `<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-1.okta.com/app/app1/slo/saml"/>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-1.okta.com/app/app1/slo/saml/post"/>`
    : "";
  const keyDescriptors = certBodies
    .map(
      (body) => `<md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>${body}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>`
    )
    .join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://www.okta.com/exk1234567890">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="${wantSigned}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    ${keyDescriptors}
    ${slo}
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://dev-1.okta.com/app/app1/sso/saml"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://dev-1.okta.com/app/app1/sso/saml"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

/** Entra-shaped metadata: default (unprefixed) namespace, redirect-only. */
function entraMetadata(): string {
  return `<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/tenant-id/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data><X509Certificate>${CERT_BODY}</X509Certificate></X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/tenant-id/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
}

describe("IdentityProvider — constructor", () => {
  const base = {
    entityId: "urn:test:idp",
    ssoUrl: "https://idp.example.com/sso",
    certificates: [IDP_KEYS.certificate],
  };

  it("constructs with valid config", () => {
    const idp = new IdentityProvider(base);
    expect(idp.entityId).toBe("urn:test:idp");
    expect(idp.ssoUrl).toBe("https://idp.example.com/sso");
    expect(idp.certificates).toHaveLength(1);
    expect(idp.wantAuthnRequestsSigned).toBe(false);
  });

  it("accepts a raw base64 certificate and normalizes it to PEM", () => {
    const idp = new IdentityProvider({ ...base, certificates: [CERT_BODY] });
    expect(idp.certificates[0]).toContain("-----BEGIN CERTIFICATE-----");
  });

  it.each([
    ["missing entityId", { ...base, entityId: "" }],
    ["no SSO endpoints", { entityId: "x", certificates: base.certificates }],
    ["invalid ssoUrl", { ...base, ssoUrl: "not-a-url" }],
    ["invalid ssoPostUrl", { ...base, ssoPostUrl: "ftp://idp.example.com" }],
    ["empty certificates", { ...base, certificates: [] }],
    ["garbage certificate", { ...base, certificates: ["not-a-cert!!!"] }],
    ["well-formed base64 that is not a certificate", { ...base, certificates: ["aGVsbG8="] }],
  ])("rejects %s", (_name, config) => {
    expect(() => new IdentityProvider(config as never)).toThrow(SAMLConfigError);
  });
});

describe("IdentityProvider.fromMetadata", () => {
  it("parses Okta-shaped metadata", () => {
    const idp = IdentityProvider.fromMetadata(oktaMetadata());
    expect(idp.entityId).toBe("http://www.okta.com/exk1234567890");
    expect(idp.ssoUrl).toBe("https://dev-1.okta.com/app/app1/sso/saml");
    expect(idp.ssoPostUrl).toBe("https://dev-1.okta.com/app/app1/sso/saml");
    expect(idp.certificates).toHaveLength(1);
    expect(idp.certificates[0]).toContain("-----BEGIN CERTIFICATE-----");
    expect(idp.wantAuthnRequestsSigned).toBe(false);
  });

  it("parses Entra-shaped metadata using the default namespace", () => {
    const idp = IdentityProvider.fromMetadata(entraMetadata());
    expect(idp.entityId).toBe("https://sts.windows.net/tenant-id/");
    expect(idp.ssoUrl).toBe("https://login.microsoftonline.com/tenant-id/saml2");
    expect(idp.ssoPostUrl).toBeUndefined();
    expect(idp.certificates).toHaveLength(1);
  });

  it("collects multiple signing certificates (rollover) and dedupes", () => {
    const xml = oktaMetadata({ certBodies: [CERT_BODY, CERT_BODY, CERT_BODY] });
    const idp = IdentityProvider.fromMetadata(xml);
    expect(idp.certificates).toHaveLength(1); // deduped
  });

  it("reads WantAuthnRequestsSigned", () => {
    const idp = IdentityProvider.fromMetadata(oktaMetadata({ wantSigned: true }));
    expect(idp.wantAuthnRequestsSigned).toBe(true);
  });

  it("parses SingleLogoutService endpoints per binding", () => {
    const idp = IdentityProvider.fromMetadata(oktaMetadata({ withSlo: true }));
    expect(idp.sloUrl).toBe("https://dev-1.okta.com/app/app1/slo/saml");
    expect(idp.sloPostUrl).toBe("https://dev-1.okta.com/app/app1/slo/saml/post");
  });

  it("leaves SLO endpoints undefined when the IdP offers none", () => {
    const idp = IdentityProvider.fromMetadata(oktaMetadata());
    expect(idp.sloUrl).toBeUndefined();
    expect(idp.sloPostUrl).toBeUndefined();
  });

  it("accepts KeyDescriptors without a use attribute", () => {
    const xml = oktaMetadata().replace('use="signing"', "");
    const idp = IdentityProvider.fromMetadata(xml);
    expect(idp.certificates).toHaveLength(1);
  });

  it("ignores encryption-only KeyDescriptors", () => {
    const xml = oktaMetadata({ certBodies: [CERT_BODY, CERT_BODY] }).replace(
      'use="signing"',
      'use="encryption"'
    );
    const idp = IdentityProvider.fromMetadata(xml);
    expect(idp.certificates).toHaveLength(1);
  });

  it("unwraps EntitiesDescriptor federation documents", () => {
    const xml = `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">
      <md:EntityDescriptor entityID="urn:some:sp-only">
        <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>
      </md:EntityDescriptor>
      ${oktaMetadata().replace(/<\?xml[^>]*\?>/, "")}
    </md:EntitiesDescriptor>`;
    const idp = IdentityProvider.fromMetadata(xml);
    expect(idp.entityId).toBe("http://www.okta.com/exk1234567890");
  });

  it.each([
    ["SP metadata", oktaMetadata().replace(/IDPSSODescriptor/g, "SPSSODescriptor")],
    ["metadata without entityID", oktaMetadata().replace(/entityID="[^"]*"/, "")],
    ["a non-metadata document", `<foo/>`],
    [
      "metadata without SSO endpoints",
      oktaMetadata().replace(/<md:SingleSignOnService[^>]*\/>/g, ""),
    ],
    [
      "metadata without certificates",
      oktaMetadata().replace(/<md:KeyDescriptor[\s\S]*<\/md:KeyDescriptor>/, ""),
    ],
  ])("rejects %s with SAMLConfigError", (_name, xml) => {
    expect(() => IdentityProvider.fromMetadata(xml)).toThrow(SAMLConfigError);
  });

  it("rejects metadata containing a DOCTYPE", () => {
    expect(() => IdentityProvider.fromMetadata(`<!DOCTYPE x>${oktaMetadata()}`)).toThrow(
      SAMLParseError
    );
  });
});

describe("IdentityProvider.fromUrl", () => {
  it("fetches and parses metadata", async () => {
    const fakeFetch = (() =>
      Promise.resolve(new Response(oktaMetadata(), { status: 200 }))) as typeof fetch;
    const idp = await IdentityProvider.fromUrl("https://idp.example.com/metadata", {
      fetch: fakeFetch,
    });
    expect(idp.entityId).toBe("http://www.okta.com/exk1234567890");
  });

  it("rejects non-2xx responses", async () => {
    const fakeFetch = (() =>
      Promise.resolve(new Response("nope", { status: 503 }))) as typeof fetch;
    await expect(
      IdentityProvider.fromUrl("https://idp.example.com/metadata", { fetch: fakeFetch })
    ).rejects.toThrow(/HTTP 503/);
  });

  it("wraps network failures in SAMLConfigError", async () => {
    const fakeFetch = (() => Promise.reject(new Error("ECONNREFUSED"))) as typeof fetch;
    await expect(
      IdentityProvider.fromUrl("https://idp.example.com/metadata", { fetch: fakeFetch })
    ).rejects.toThrow(SAMLConfigError);
  });

  it("rejects invalid URLs upfront", async () => {
    await expect(IdentityProvider.fromUrl("not a url")).rejects.toThrow(SAMLConfigError);
  });
});
