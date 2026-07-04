import * as xmlenc from "xml-encryption";
import { DecryptionError } from "../errors";

/**
 * Decrypt an `EncryptedAssertion` (or its inner `EncryptedData`) with the SP's
 * private key. Insecure algorithms (RSA-PKCS1 v1.5 key transport, 3DES) are
 * rejected outright.
 */
export function decryptAssertion(encryptedXml: string, privateKey: string): Promise<string> {
  return new Promise((resolve, reject) => {
    xmlenc.decrypt(
      encryptedXml,
      {
        key: privateKey,
        disallowDecryptionWithInsecureAlgorithm: true,
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
