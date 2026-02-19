export interface SPOptions {
    assertionEndpoint: string;
    certificate?: string;
    privateKey?: string;
    entityID?: string;
    keyLength?: 2048 | 4096;
}

export interface KeyPair {
    privateKey: string;
    certificate: string;
}

export interface DecryptOptions {
    privateKey: string;
}

export interface ParsedAssertion {
    xml: string;
    nameID: string | null;
    attributes: Record<string, string[]>;
    notBefore: Date | null;
    notOnOrAfter: Date | null;
}