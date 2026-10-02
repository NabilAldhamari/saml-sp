import * as xmlenc from "xml-encryption";
import { DecryptionError } from "../errors";

// Algorithms refused outright. AES-CBC is deliberately allowed: xml-encryption 6 flags it as
// insecure, but it is still the default of many production IdPs, and the decrypted assertion
// must still carry a valid signature.
const REFUSED_ALGORITHMS = [
  "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
  "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
];

/**
 * Decrypt an `EncryptedAssertion` (or its inner `EncryptedData`) with the SP's
 * private key. Insecure algorithms (RSA-PKCS1 v1.5 key transport, 3DES) are
 * rejected outright.
 */
export function decryptAssertion(encryptedXml: string, privateKey: string): Promise<string> {
  const algorithms = [
    ...encryptedXml.matchAll(
      /<(?:\w+:)?EncryptionMethod\b[^>]*\bAlgorithm\s*=\s*["']([^"']+)["']/g
    ),
  ].map((m) => m[1] as string);
  const refused = algorithms.find((a) => REFUSED_ALGORITHMS.includes(a));
  if (refused) {
    return Promise.reject(
      new DecryptionError(`Refusing to decrypt: insecure encryption algorithm ${refused}.`)
    );
  }

  return new Promise((resolve, reject) => {
    xmlenc.decrypt(
      encryptedXml,
      {
        key: privateKey,
        disallowDecryptionWithInsecureAlgorithm: false,
        warnInsecureAlgorithm: false,
      },
      (err, result) => {
        if (err) {
          reject(
            new DecryptionError(
              "Failed to decrypt EncryptedAssertion. Check that the configured privateKey matches " +
                "the encryption certificate registered with your IdP.",
              { cause: err }
            )
          );
        } else if (!result) {
          reject(new DecryptionError("Decryption produced empty output."));
        } else {
          resolve(result);
        }
      }
    );
  });
}
