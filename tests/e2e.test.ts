/**
 * Full handshake simulation without a real IdP:
 * keypair → SP → SP metadata → IdP metadata ingestion → AuthnRequest →
 * (IdP side: signed + encrypted response answering the request) → consume → replay defence.
 */
import { inflateRawSync } from "node:zlib";
import { IdentityProvider, SAMLValidationError, ServiceProvider } from "../src";
import { certificateBody } from "../src/internal/pem";
import {
  buildAssertionXml,
  buildResponseXml,
  encryptAssertion,
  mockPostRequest,
  signAssertion,
  signResponse,
  testId,
  toPostBody,
} from "./helpers/fixtures";
import { IDP_KEYS } from "./helpers/keys";

const ACS = "https://app.example.com/saml/acs";
const SP_ENTITY = "urn:e2e:sp";
const IDP_ENTITY = "urn:e2e:idp";

function idpMetadataXml(): string {
  return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="${IDP_ENTITY}">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>${certificateBody(IDP_KEYS.certificate)}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.e2e.example.com/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`;
}

describe("end-to-end SP ⇄ IdP handshake", () => {
  it("completes the full solicited, signed, encrypted flow", async () => {
    // 1. SP bootstrap: keys, IdP metadata ingestion, SP construction.
    const keys = ServiceProvider.generateKeyPair();
    const idp = IdentityProvider.fromMetadata(idpMetadataXml());
    const sp = new ServiceProvider({
      entityId: SP_ENTITY,
      assertionConsumerServiceUrl: ACS,
      idp,
      privateKey: keys.privateKey,
      certificate: keys.certificate,
      requireSignedResponse: true,
    });

    // 2. SP metadata is valid XML carrying our cert (what you upload to the IdP).
    const spMetadata = sp.metadata();
    expect(spMetadata).toContain(`entityID="${SP_ENTITY}"`);
    expect(spMetadata).toContain(certificateBody(keys.certificate).slice(0, 60));

    // 3. Login: redirect URL carries a valid, inflatable AuthnRequest.
    const login = await sp.createLoginRequest({ relayState: "/deep/link" });
    expect(login.url).toMatch(/^https:\/\/idp\.e2e\.example\.com\/sso\?/);
    const samlRequest = new URL(login.url).searchParams.get("SAMLRequest")!;
    const requestXml = inflateRawSync(Buffer.from(samlRequest, "base64")).toString("utf8");
    expect(requestXml).toContain(`<saml:Issuer>${SP_ENTITY}</saml:Issuer>`);
    expect(requestXml).toContain(`AssertionConsumerServiceURL="${ACS}"`);

    // 4. "IdP side": build a signed assertion answering the request, encrypt it
    //    for the SP's certificate, wrap it in a signed response.
    const assertionId = testId();
    const responseId = testId();
    const assertion = signAssertion(
      buildAssertionXml({
        id: assertionId,
        issuer: IDP_ENTITY,
        audiences: [SP_ENTITY],
        recipient: ACS,
        inResponseTo: login.id,
        nameId: "bob@example.com",
        attributes: { displayName: ["Bob Example"], groups: ["engineering", "oncall"] },
      }),
      assertionId
    );
    const encrypted = await encryptAssertion(assertion, keys.certificate);
    const responseXml = signResponse(
      buildResponseXml(encrypted, {
        id: responseId,
        issuer: IDP_ENTITY,
        destination: ACS,
        inResponseTo: login.id,
      }),
      responseId
    );

    // 5. The IdP POSTs to the ACS endpoint; the SP consumes the raw request.
    const req = mockPostRequest(toPostBody(responseXml, "/deep/link"), 256);
    const { profile, relayState } = await sp.consume(req as never);

    expect(relayState).toBe("/deep/link");
    expect(profile.nameId).toBe("bob@example.com");
    expect(profile.issuer).toBe(IDP_ENTITY);
    expect(profile.inResponseTo).toBe(login.id);
    expect(profile.attributes.groups).toEqual(["engineering", "oncall"]);
    expect(profile.sessionIndex).toBe("session-123");

    // 6. Replaying the exact same response must fail. For a solicited response the
    //    consumed request ID trips first (layered defence); the assertion replay
    //    cache would catch it regardless (see validateResponse tests).
    const replay = mockPostRequest(toPostBody(responseXml, "/deep/link"));
    await expect(sp.consume(replay as never)).rejects.toThrow(SAMLValidationError);
  });
});
