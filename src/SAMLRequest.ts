import { create } from "xmlbuilder2";
import { generateRandomEntityID } from "./utils";

export class SAMLRequest {
    private readonly idpURL: URL;
    private readonly assertionEndpoint: string;

    constructor(idpURL: string, assertionEndpoint: string) {
        if (!assertionEndpoint || assertionEndpoint.length === 0) {
            throw new Error("assertionEndpoint is required.");
        }
        this.idpURL = new URL(idpURL);   // throws if malformed
        new URL(assertionEndpoint);       // throws if malformed
        this.assertionEndpoint = assertionEndpoint;
    }

    generateAuthNRequest(): string {
        const id = generateRandomEntityID();
        const issueInstant = new Date().toISOString();

        return create({
            "samlp:AuthnRequest": {
                "@xmlns:samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
                "@xmlns:saml": "urn:oasis:names:tc:SAML:2.0:assertion",
                "@ID": id,
                "@Version": "2.0",
                "@IssueInstant": issueInstant,
                "@Destination": this.idpURL.toString(),
                "@AssertionConsumerServiceURL": this.assertionEndpoint,
                "@ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                "saml:Issuer": this.assertionEndpoint,
                "samlp:NameIDPolicy": {
                    "@Format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                    "@AllowCreate": "true",
                },
            },
        }).end();
    }

    /** Returns the full redirect URL with SAMLRequest encoded in the query string. */
    createAuthNURL(): string {
        const encoded = Buffer.from(this.generateAuthNRequest()).toString("base64");
        const url = new URL(this.idpURL.toString());
        url.searchParams.set("SAMLRequest", encoded);
        return url.toString();
    }
}