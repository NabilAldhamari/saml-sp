import { EventEmitter } from "events";
import { SAMLResponse } from "../src/SAMLResponse";
import { ServiceProvider } from "../src/ServiceProvider";
import { KeyPair } from "../src/types";

let sharedKeys: KeyPair;

beforeAll(async () => {
    sharedKeys = await ServiceProvider.generateKeys(2048);
});

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Build a minimal assertion XML with configurable timestamps and attributes. */
function buildAssertionXML({
                               notBefore,
                               notOnOrAfter,
                               nameID = "user@example.com",
                               attributes = {} as Record<string, string[]>,
                               tagPrefix = "",
                           }: {
    notBefore?: Date;
    notOnOrAfter?: Date;
    nameID?: string;
    attributes?: Record<string, string[]>;
    tagPrefix?: string;
}): string {
    const p = tagPrefix ? `${tagPrefix}:` : "";

    const conditionAttrs = [
        notBefore ? `NotBefore="${notBefore.toISOString()}"` : "",
        notOnOrAfter ? `NotOnOrAfter="${notOnOrAfter.toISOString()}"` : "",
    ]
        .filter(Boolean)
        .join(" ");

    const attrStatements = Object.entries(attributes)
        .map(
            ([name, values]) =>
                `<${p}Attribute Name="${name}">` +
                values
                    .map((v) => `<${p}AttributeValue>${v}</${p}AttributeValue>`)
                    .join("") +
                `</${p}Attribute>`
        )
        .join("");

    const nsAttr = tagPrefix
        ? `xmlns:${tagPrefix}="urn:oasis:names:tc:SAML:2.0:assertion"`
        : "";

    return `
    <${p}Assertion ${nsAttr}>
      <${p}Conditions ${conditionAttrs}></${p}Conditions>
      <${p}Subject>
        <${p}NameID>${nameID}</${p}NameID>
      </${p}Subject>
      <${p}AttributeStatement>
        ${attrStatements}
      </${p}AttributeStatement>
    </${p}Assertion>
  `;
}

/** Wrap raw XML in a SAMLResponse envelope and Base64-encode it as a POST body. */
function buildPostBody(innerXML: string): string {
    const envelope = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    ${innerXML}
  </samlp:Response>`;
    const encoded = Buffer.from(envelope).toString("base64");
    return `SAMLResponse=${encodeURIComponent(encoded)}`;
}

/** Create a minimal mock of IncomingMessage that emits a POST body. */
function mockPostRequest(body: string): any {
    const emitter = new EventEmitter() as any;
    emitter.method = "POST";
    process.nextTick(() => {
        emitter.emit("data", Buffer.from(body));
        emitter.emit("end");
    });
    return emitter;
}

function mockGetRequest(): any {
    const emitter = new EventEmitter() as any;
    emitter.method = "GET";
    return emitter;
}

// Reusable timestamps
const PAST = new Date(Date.now() - 1000 * 60 * 60);       // 1 hour ago
const FUTURE = new Date(Date.now() + 1000 * 60 * 60);     // 1 hour from now
const FAR_PAST = new Date(Date.now() - 1000 * 60 * 60 * 2); // 2 hours ago

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

describe("SAMLResponse – constructor", () => {
    it("throws when privateKey is missing", () => {
        expect(() => new SAMLResponse({ privateKey: "" })).toThrow(
            "privateKey is required"
        );
    });

    it("constructs successfully with a valid private key", () => {
        expect(
            () => new SAMLResponse({ privateKey: sharedKeys.privateKey })
        ).not.toThrow();
    });
});

// ---------------------------------------------------------------------------
// processXML – basic parsing (unencrypted assertions)
// ---------------------------------------------------------------------------

describe("SAMLResponse – processXML – basic parsing", () => {
    let samlResponse: SAMLResponse;

    beforeAll(() => {
        samlResponse = new SAMLResponse({ privateKey: sharedKeys.privateKey });
    });

    it("returns null when neither Assertion nor EncryptedAssertion is present", async () => {
        const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"></samlp:Response>`;
        const result = await samlResponse.processXML(xml);
        expect(result).toBeNull();
    });

    it("extracts nameID from a plain Assertion", async () => {
        const xml = buildAssertionXML({
            notBefore: PAST,
            notOnOrAfter: FUTURE,
            nameID: "alice@example.com",
        });
        const result = await samlResponse.processXML(xml);
        expect(result?.nameID).toBe("alice@example.com");
    });

    it("extracts nameID using the saml2 namespace prefix", async () => {
        const xml = buildAssertionXML({
            notBefore: PAST,
            notOnOrAfter: FUTURE,
            nameID: "bob@example.com",
            tagPrefix: "saml2",
        });
        const result = await samlResponse.processXML(xml);
        expect(result?.nameID).toBe("bob@example.com");
    });

    it("returns null nameID when NameID element is absent", async () => {
        const xml = `
      <Assertion>
        <Conditions NotBefore="${PAST.toISOString()}" NotOnOrAfter="${FUTURE.toISOString()}"></Conditions>
        <Subject></Subject>
      </Assertion>
    `;
        const result = await samlResponse.processXML(xml);
        expect(result?.nameID).toBeNull();
    });

    it("extracts attributes correctly", async () => {
        const xml = buildAssertionXML({
            notBefore: PAST,
            notOnOrAfter: FUTURE,
            attributes: {
                email: ["alice@example.com"],
                roles: ["admin", "user"],
            },
        });
        const result = await samlResponse.processXML(xml);
        expect(result?.attributes["email"]).toEqual(["alice@example.com"]);
        expect(result?.attributes["roles"]).toEqual(["admin", "user"]);
    });

    it("returns empty attributes object when AttributeStatement is absent", async () => {
        const xml = `
      <Assertion>
        <Conditions NotBefore="${PAST.toISOString()}" NotOnOrAfter="${FUTURE.toISOString()}"></Conditions>
      </Assertion>
    `;
        const result = await samlResponse.processXML(xml);
        expect(result?.attributes).toEqual({});
    });

    it("returns the raw XML in the result", async () => {
        const xml = buildAssertionXML({
            notBefore: PAST,
            notOnOrAfter: FUTURE,
        });
        const result = await samlResponse.processXML(xml);
        expect(result?.xml).toContain("Assertion");
    });

    it("normalises CRLF line endings before parsing", async () => {
        const xml = buildAssertionXML({
            notBefore: PAST,
            notOnOrAfter: FUTURE,
            nameID: "carol@example.com",
        }).replace(/\n/g, "\r\n");

        const result = await samlResponse.processXML(xml);
        expect(result?.nameID).toBe("carol@example.com");
    });
});

// ---------------------------------------------------------------------------
// processXML – timestamp validation
// ---------------------------------------------------------------------------

describe("SAMLResponse – processXML – timestamp validation", () => {
    let samlResponse: SAMLResponse;

    beforeAll(() => {
        samlResponse = new SAMLResponse({ privateKey: sharedKeys.privateKey });
    });

    it("accepts a valid assertion (NotBefore in past, NotOnOrAfter in future)", async () => {
        const xml = buildAssertionXML({ notBefore: PAST, notOnOrAfter: FUTURE });
        await expect(samlResponse.processXML(xml)).resolves.not.toBeNull();
    });

    it("throws when NotOnOrAfter is in the past", async () => {
        const xml = buildAssertionXML({
            notBefore: FAR_PAST,
            notOnOrAfter: PAST,
        });
        await expect(samlResponse.processXML(xml)).rejects.toThrow(
            "Assertion has expired"
        );
    });

    it("throws when NotBefore is in the future", async () => {
        const xml = buildAssertionXML({
            notBefore: FUTURE,
            notOnOrAfter: new Date(Date.now() + 1000 * 60 * 60 * 2),
        });
        await expect(samlResponse.processXML(xml)).rejects.toThrow(
            "Assertion not yet valid"
        );
    });

    it("accepts an assertion with no Conditions element", async () => {
        const xml = `<Assertion><Subject><NameID>user@example.com</NameID></Subject></Assertion>`;
        const result = await samlResponse.processXML(xml);
        expect(result?.notBefore).toBeNull();
        expect(result?.notOnOrAfter).toBeNull();
    });

    it("accepts an assertion with Conditions but no timestamp attributes", async () => {
        const xml = `
      <Assertion>
        <Conditions></Conditions>
        <Subject><NameID>user@example.com</NameID></Subject>
      </Assertion>
    `;
        await expect(samlResponse.processXML(xml)).resolves.not.toBeNull();
    });

    it("populates notBefore and notOnOrAfter on the result", async () => {
        const xml = buildAssertionXML({ notBefore: PAST, notOnOrAfter: FUTURE });
        const result = await samlResponse.processXML(xml);
        expect(result?.notBefore?.getTime()).toBeCloseTo(PAST.getTime(), -2);
        expect(result?.notOnOrAfter?.getTime()).toBeCloseTo(FUTURE.getTime(), -2);
    });
});

// ---------------------------------------------------------------------------
// processRequest
// ---------------------------------------------------------------------------

describe("SAMLResponse – processRequest", () => {
    let samlResponse: SAMLResponse;

    beforeAll(() => {
        samlResponse = new SAMLResponse({ privateKey: sharedKeys.privateKey });
    });

    it("rejects non-POST requests", async () => {
        const req = mockGetRequest();
        await expect(samlResponse.processRequest(req)).rejects.toThrow(
            "HTTP POST"
        );
    });

    it("returns null when SAMLResponse param is absent", async () => {
        const req = mockPostRequest("foo=bar");
        const result = await samlResponse.processRequest(req);
        expect(result).toBeNull();
    });

    it("parses a valid POST body and returns an assertion", async () => {
        const assertionXML = buildAssertionXML({
            notBefore: PAST,
            notOnOrAfter: FUTURE,
            nameID: "dave@example.com",
        });
        const body = buildPostBody(assertionXML);
        const req = mockPostRequest(body);

        const result = await samlResponse.processRequest(req);
        expect(result?.nameID).toBe("dave@example.com");
    });

    it("handles a chunked POST body correctly", async () => {
        const assertionXML = buildAssertionXML({
            notBefore: PAST,
            notOnOrAfter: FUTURE,
            nameID: "eve@example.com",
        });
        const body = buildPostBody(assertionXML);

        const emitter = new EventEmitter() as any;
        emitter.method = "POST";

        // Emit data in two chunks
        process.nextTick(() => {
            const mid = Math.floor(body.length / 2);
            emitter.emit("data", Buffer.from(body.slice(0, mid)));
            emitter.emit("data", Buffer.from(body.slice(mid)));
            emitter.emit("end");
        });

        const result = await samlResponse.processRequest(emitter);
        expect(result?.nameID).toBe("eve@example.com");
    });

    it("propagates stream errors as rejected promises", async () => {
        const emitter = new EventEmitter() as any;
        emitter.method = "POST";

        process.nextTick(() => {
            emitter.emit("error", new Error("Stream exploded"));
        });

        await expect(samlResponse.processRequest(emitter)).rejects.toThrow(
            "Stream exploded"
        );
    });
});