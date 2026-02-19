import { DOMParser, DOMParserOptions } from "@xmldom/xmldom";
import * as xmlenc from "xml-encryption";
import { IncomingMessage } from "http";

// Pre-declare all SAML namespace prefixes so the parser never throws a
// NamespaceError on fragments where xmlns:* attributes are absent.
// NamespaceErrors are fatalErrors inside @xmldom/xmldom's SAX layer and are
// thrown before the onError handler is ever called, so the only reliable fix
// is to seed the parser with the known prefixes upfront.
const PARSER_OPTIONS: DOMParserOptions = {
    xmlns: {
        saml:   "urn:oasis:names:tc:SAML:2.0:assertion",
        saml2:  "urn:oasis:names:tc:SAML:2.0:assertion",
        samlp:  "urn:oasis:names:tc:SAML:2.0:protocol",
        samlp2: "urn:oasis:names:tc:SAML:2.0:protocol",
        ds:     "http://www.w3.org/2000/09/xmldsig#",
        xenc:   "http://www.w3.org/2001/04/xmlenc#",
        md:     "urn:oasis:names:tc:SAML:2.0:metadata",
    },
};
import { DecryptOptions, ParsedAssertion } from "./types";

export class SAMLResponse {
    private readonly decryptOptions: DecryptOptions;

    constructor(decryptOptions: DecryptOptions) {
        if (!decryptOptions.privateKey) {
            throw new Error("privateKey is required to decrypt assertions.");
        }
        this.decryptOptions = decryptOptions;
    }

    /** Parse and decrypt a SAML response from an incoming HTTP POST request. */
    async processRequest(req: IncomingMessage): Promise<ParsedAssertion | null> {
        const rawXML = await this.extractXMLFromRequest(req);
        if (!rawXML) return null;
        return this.processXML(rawXML);
    }

    /** Parse and decrypt a SAML response from a raw XML string. */
    async processXML(xml: string): Promise<ParsedAssertion | null> {
        const normalised = xml.replace(/\r\n?/g, "\n");
        const doc = new DOMParser(PARSER_OPTIONS).parseFromString(normalised, "text/xml");

        const encryptedNode =
            doc.getElementsByTagName("saml2:EncryptedAssertion")[0] ??
            doc.getElementsByTagName("EncryptedAssertion")[0] ??
            null;

        let assertionXML: string;

        if (encryptedNode) {
            assertionXML = await this.decryptNode(encryptedNode.toString());
        } else {
            const plainNode =
                doc.getElementsByTagName("saml2:Assertion")[0] ??
                doc.getElementsByTagName("Assertion")[0] ??
                null;
            if (!plainNode) return null;
            assertionXML = plainNode.toString();
        }

        return this.parseAssertion(assertionXML);
    }

    private decryptNode(encryptedXML: string): Promise<string> {
        const options = {
            key: this.decryptOptions.privateKey,
            disallowDecryptionWithInsecureAlgorithm: true,
            warnInsecureAlgorithm: true,
        };

        return new Promise((resolve, reject) => {
            xmlenc.decrypt(
                encryptedXML,
                options,
                (err: Error | null, result: string) => {
                    if (err) reject(new Error(`Decryption failed: ${err.message}`));
                    else resolve(result);
                }
            );
        });
    }

    private parseAssertion(assertionXML: string): ParsedAssertion {
        const doc = new DOMParser(PARSER_OPTIONS).parseFromString(assertionXML, "text/xml");

        const conditions =
            doc.getElementsByTagName("saml2:Conditions")[0] ??
            doc.getElementsByTagName("Conditions")[0] ??
            null;

        let notBefore: Date | null = null;
        let notOnOrAfter: Date | null = null;

        if (conditions) {
            const nb = conditions.getAttribute("NotBefore");
            const nooa = conditions.getAttribute("NotOnOrAfter");
            if (nb) notBefore = new Date(nb);
            if (nooa) notOnOrAfter = new Date(nooa);
        }

        const now = new Date();

        if (notBefore && now < notBefore) {
            throw new Error(
                `Assertion not yet valid. NotBefore: ${notBefore.toISOString()}`
            );
        }
        if (notOnOrAfter && now >= notOnOrAfter) {
            throw new Error(
                `Assertion has expired. NotOnOrAfter: ${notOnOrAfter.toISOString()}`
            );
        }

        const nameIDNode =
            doc.getElementsByTagName("saml2:NameID")[0] ??
            doc.getElementsByTagName("NameID")[0] ??
            null;

        const nameID = nameIDNode?.textContent ?? null;

        const attributes: Record<string, string[]> = {};
        const attrNodes =
            doc.getElementsByTagName("saml2:Attribute").length > 0
                ? doc.getElementsByTagName("saml2:Attribute")
                : doc.getElementsByTagName("Attribute");

        for (let i = 0; i < attrNodes.length; i++) {
            const attr = attrNodes[i];
            const name = attr.getAttribute("Name");
            if (!name) continue;

            const valueNodes =
                attr.getElementsByTagName("saml2:AttributeValue").length > 0
                    ? attr.getElementsByTagName("saml2:AttributeValue")
                    : attr.getElementsByTagName("AttributeValue");

            const values: string[] = [];
            for (let j = 0; j < valueNodes.length; j++) {
                const text = valueNodes[j].textContent;
                if (text) values.push(text);
            }

            attributes[name] = values;
        }

        return { xml: assertionXML, nameID, attributes, notBefore, notOnOrAfter };
    }

    private extractXMLFromRequest(req: IncomingMessage): Promise<string | null> {
        return new Promise((resolve, reject) => {
            if (req.method !== "POST") {
                return reject(new Error("SAML responses must arrive via HTTP POST."));
            }

            let body = "";
            req.on("data", (chunk: Buffer) => {
                body += chunk.toString();
            });
            req.on("error", reject);
            req.on("end", () => {
                const params = new URLSearchParams(body);
                const samlResponse = params.get("SAMLResponse");
                if (!samlResponse) return resolve(null);

                const xml = Buffer.from(samlResponse, "base64").toString("utf-8");
                resolve(xml.length > 0 ? xml : null);
            });
        });
    }
}