import { create } from "xmlbuilder2";
import { certificateBody } from "./pem";

export interface MetadataParams {
  entityId: string;
  assertionConsumerServiceUrl: string;
  singleLogoutServiceUrl?: string;
  certificate?: string;
  signAuthnRequests: boolean;
  requireSignedAssertions: boolean;
  nameIdFormat: string;
  /** Optional metadata expiry. Omitted by default so the document never goes stale. */
  validUntil?: Date;
}

const REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/** Build SP metadata XML that accurately reflects the SP's configuration. */
export function buildMetadataXml(params: MetadataParams): string {
  const descriptor: Record<string, unknown> = {
    "@AuthnRequestsSigned": params.signAuthnRequests ? "true" : "false",
    "@WantAssertionsSigned": params.requireSignedAssertions ? "true" : "false",
    "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
  };

  if (params.certificate) {
    const body = certificateBody(params.certificate);
    descriptor["md:KeyDescriptor"] = (["signing", "encryption"] as const).map((use) => ({
      "@use": use,
      "ds:KeyInfo": {
        "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
        "ds:X509Data": { "ds:X509Certificate": body },
      },
    }));
  }

  // Schema order: KeyDescriptor, SingleLogoutService, NameIDFormat, AssertionConsumerService.
  if (params.singleLogoutServiceUrl) {
    descriptor["md:SingleLogoutService"] = [
      { "@Binding": REDIRECT_BINDING, "@Location": params.singleLogoutServiceUrl },
      { "@Binding": POST_BINDING, "@Location": params.singleLogoutServiceUrl },
    ];
  }

  descriptor["md:NameIDFormat"] = params.nameIdFormat;
  descriptor["md:AssertionConsumerService"] = {
    "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
    "@Location": params.assertionConsumerServiceUrl,
    "@index": "0",
    "@isDefault": "true",
  };

  const entity: Record<string, unknown> = {
    "@xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "@entityID": params.entityId,
    "md:SPSSODescriptor": descriptor,
  };
  if (params.validUntil) {
    entity["@validUntil"] = params.validUntil.toISOString();
  }

  return create({ "md:EntityDescriptor": entity }).end({ prettyPrint: true });
}
