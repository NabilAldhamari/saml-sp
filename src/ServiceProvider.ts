import * as fs from "fs";
import * as selfsigned from "selfsigned";
import { create } from "xmlbuilder2";
import { SPOptions, KeyPair } from "./types";
import { generateRandomEntityID, extractPEMBody } from "./utils";

export class ServiceProvider {
    readonly entityID: string;
    readonly assertionEndpoint: string;
    certificate: string;
    privateKey: string;

    constructor(options: SPOptions & { certificate: string; privateKey: string }) {
        if (!options.assertionEndpoint || options.assertionEndpoint.length === 0) {
            throw new Error("assertionEndpoint is required.");
        }
        new URL(options.assertionEndpoint); // throws if malformed

        this.assertionEndpoint = options.assertionEndpoint;
        this.entityID = options.entityID ?? generateRandomEntityID();
        this.certificate = options.certificate;
        this.privateKey = options.privateKey;
    }

    /** Async factory — use this instead of `new ServiceProvider()` when you need auto-generated keys. */
    static async create(options: SPOptions): Promise<ServiceProvider> {
        if (options.certificate && options.privateKey) {
            return new ServiceProvider(options as SPOptions & { certificate: string; privateKey: string });
        }
        const kp = await ServiceProvider.generateKeys(options.keyLength ?? 2048);
        return new ServiceProvider({ ...options, ...kp });
    }

    static async generateKeys(keyLength: 2048 | 4096 = 2048): Promise<KeyPair> {
        const attrs = [{ name: "commonName", value: "saml-sp" }];
        const result = selfsigned.generate(attrs, {
            keySize: keyLength,
            algorithm: "sha256",
        });
        return {
            privateKey: result.private as string,
            certificate: result.cert as string,
        };
    }

    saveKeys(dir = "."): void {
        fs.writeFileSync(`${dir}/private.pem`, this.privateKey, "utf-8");
        fs.writeFileSync(`${dir}/cert.crt`, this.certificate, "utf-8");
    }

    /** Returns the metadata XML string and optionally writes it to disk. */
    createMetadata(outputPath?: string): string {
        const certBody = extractPEMBody(this.certificate);

        const xml = create({
            "md:EntityDescriptor": {
                "@xmlns:md": "urn:oasis:names:tc:SAML:2.0:metadata",
                "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
                "@entityID": this.entityID,
                "@validUntil": new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString(),
                "md:SPSSODescriptor": {
                    "@AuthnRequestsSigned": "true",
                    "@WantAssertionsSigned": "true",
                    "@protocolSupportEnumeration": "urn:oasis:names:tc:SAML:2.0:protocol",
                    "md:KeyDescriptor": [
                        this.keyDescriptor("signing", certBody),
                        this.keyDescriptor("encryption", certBody),
                    ],
                    "md:SingleLogoutService": {
                        "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                        "@Location": this.assertionEndpoint,
                    },
                    "md:AssertionConsumerService": {
                        "@Binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                        "@Location": this.assertionEndpoint,
                        "@index": "0",
                        "@isDefault": "true",
                    },
                },
            },
        }).end({ prettyPrint: true });

        if (outputPath) {
            fs.writeFileSync(outputPath, xml, "utf-8");
        }

        return xml;
    }

    private keyDescriptor(use: "signing" | "encryption", certBody: string) {
        return {
            "@use": use,
            "ds:KeyInfo": {
                "@xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
                "ds:X509Data": { "ds:X509Certificate": certBody },
            },
        };
    }
}