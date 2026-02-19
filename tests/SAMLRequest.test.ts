import { SAMLRequest } from "../src";

const IDP_URL = "https://idp.example.com/sso";
const ACS_URL = "https://sp.example.com/acs";

describe("SAMLRequest – constructor", () => {
    it("throws when assertionEndpoint is empty", () => {
        expect(() => new SAMLRequest(IDP_URL, "")).toThrow(
            "assertionEndpoint is required"
        );
    });

    it("throws when idpURL is not a valid URL", () => {
        expect(() => new SAMLRequest("not-a-url", ACS_URL)).toThrow();
    });

    it("throws when assertionEndpoint is not a valid URL", () => {
        expect(() => new SAMLRequest(IDP_URL, "not-a-url")).toThrow();
    });

    it("accepts an idpURL that already has query parameters", () => {
        expect(
            () => new SAMLRequest("https://idp.example.com/sso?foo=bar", ACS_URL)
        ).not.toThrow();
    });

    it("constructs successfully with valid arguments", () => {
        expect(() => new SAMLRequest(IDP_URL, ACS_URL)).not.toThrow();
    });
});

describe("SAMLRequest – generateAuthNRequest", () => {
    let req: SAMLRequest;

    beforeEach(() => {
        req = new SAMLRequest(IDP_URL, ACS_URL);
    });

    it("returns a non-empty XML string", () => {
        const xml = req.generateAuthNRequest();
        expect(xml.length).toBeGreaterThan(0);
    });

    it("contains the AuthnRequest element", () => {
        expect(req.generateAuthNRequest()).toContain("AuthnRequest");
    });

    it("contains the correct SAML protocol namespace", () => {
        expect(req.generateAuthNRequest()).toContain(
            "urn:oasis:names:tc:SAML:2.0:protocol"
        );
    });

    it("sets Version to 2.0", () => {
        expect(req.generateAuthNRequest()).toContain('Version="2.0"');
    });

    it("sets Destination to the IdP URL", () => {
        expect(req.generateAuthNRequest()).toContain(
            `Destination="${IDP_URL}"`
        );
    });

    it("sets AssertionConsumerServiceURL to the ACS URL", () => {
        expect(req.generateAuthNRequest()).toContain(
            `AssertionConsumerServiceURL="${ACS_URL}"`
        );
    });

    it("sets HTTP-POST ProtocolBinding", () => {
        expect(req.generateAuthNRequest()).toContain(
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        );
    });

    it("generates a unique ID on each call", () => {
        const id1 = req.generateAuthNRequest().match(/ID="([^"]+)"/)?.[1];
        const id2 = req.generateAuthNRequest().match(/ID="([^"]+)"/)?.[1];
        expect(id1).toBeDefined();
        expect(id2).toBeDefined();
        expect(id1).not.toBe(id2);
    });

    it("includes a NameIDPolicy element", () => {
        expect(req.generateAuthNRequest()).toContain("NameIDPolicy");
    });

    it("includes a valid IssueInstant timestamp", () => {
        const match = req
            .generateAuthNRequest()
            .match(/IssueInstant="([^"]+)"/);
        expect(match).not.toBeNull();
        const ts = new Date(match![1]);
        expect(ts.getTime()).not.toBeNaN();
        // Should be within the last 5 seconds
        expect(Date.now() - ts.getTime()).toBeLessThan(5000);
    });
});

describe("SAMLRequest – createAuthNURL", () => {
    it("returns a URL beginning with the IdP base URL", () => {
        const req = new SAMLRequest(IDP_URL, ACS_URL);
        expect(req.createAuthNURL()).toMatch(/^https:\/\/idp\.example\.com\/sso/);
    });

    it("includes a SAMLRequest query parameter", () => {
        const req = new SAMLRequest(IDP_URL, ACS_URL);
        const url = new URL(req.createAuthNURL());
        expect(url.searchParams.get("SAMLRequest")).not.toBeNull();
    });

    it("SAMLRequest value decodes to valid AuthnRequest XML", () => {
        const req = new SAMLRequest(IDP_URL, ACS_URL);
        const url = new URL(req.createAuthNURL());
        const encoded = url.searchParams.get("SAMLRequest")!;
        const decoded = Buffer.from(encoded, "base64").toString("utf-8");
        expect(decoded).toContain("AuthnRequest");
    });

    it("preserves existing query parameters on the IdP URL", () => {
        const req = new SAMLRequest(
            "https://idp.example.com/sso?tenant=acme",
            ACS_URL
        );
        const url = new URL(req.createAuthNURL());
        expect(url.searchParams.get("tenant")).toBe("acme");
        expect(url.searchParams.get("SAMLRequest")).not.toBeNull();
    });

    it("produces a different URL on each call due to unique IDs", () => {
        const req = new SAMLRequest(IDP_URL, ACS_URL);
        expect(req.createAuthNURL()).not.toBe(req.createAuthNURL());
    });
});