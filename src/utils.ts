import * as crypto from "node:crypto";

export function generateRandomEntityID(): string {
    return "_" + crypto.randomBytes(21).toString("hex");
}

/** Strips PEM headers/footers and line breaks, returning the bare Base64 body. */
export function extractPEMBody(pem: string): string {
    return pem
        .replace(/(-----[A-Z\s]+-----)/g, "")
        .replace(/[\r\n]/g, "")
        .trim();
}