import { SignedXml } from "xml-crypto";
import type { Document, Element } from "@xmldom/xmldom";
import { SignatureError } from "../errors";
import { NS, childElements } from "./parse";
import { normalizeCertificate } from "./pem";

const SIGNATURE_ALGORITHMS = new Set([
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
  "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
]);
const DIGEST_ALGORITHMS = new Set([
  "http://www.w3.org/2001/04/xmlenc#sha256",
  "http://www.w3.org/2001/04/xmlenc#sha512",
]);
const SHA1_SIGNATURE = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
const SHA1_DIGEST = "http://www.w3.org/2000/09/xmldsig#sha1";

export interface VerifiedSignature {
  /** The canonicalized XML that was actually covered by the verified signature. */
  signedContent: string;
}

/**
 * Find the `ds:Signature` that is a *direct child* of `element`.
 * Signatures nested deeper are ignored on purpose: accepting them enables
 * signature-wrapping attacks. More than one direct signature is rejected.
 */
export function findDirectChildSignature(element: Element): Element | null {
  const signatures = childElements(element, NS.DS, "Signature");
  if (signatures.length > 1) {
    throw new SignatureError(
      `Found ${signatures.length} Signature elements directly under <${element.localName}>; expected at most one.`
    );
  }
  return signatures[0] ?? null;
}

function assertUniqueId(doc: Document, id: string): void {
  const stack: Element[] = doc.documentElement ? [doc.documentElement] : [];
  let count = 0;
  while (stack.length > 0) {
    const el = stack.pop() as Element;
    if (el.getAttribute("ID") === id) {
      count++;
      if (count > 1) {
        throw new SignatureError(
          `Multiple elements share the ID "${id}" — refusing to verify (possible signature-wrapping attack).`
        );
      }
    }
    for (let i = 0; i < el.childNodes.length; i++) {
      const child = el.childNodes.item(i);
      if (child && child.nodeType === 1) stack.push(child as Element);
    }
  }
}

/**
 * Verify an enveloped XML signature over `element` inside `containingXml`.
 *
 * Guarantees on success:
 * - the signature is a direct child of `element` and references `element` by ID,
 * - the referenced ID is unique in the document,
 * - the signature verifies against one of `certificates`,
 * - only allowlisted algorithms were used (SHA-1 requires `allowSha1`),
 * - the returned `signedContent` is exactly the canonical XML the signature covers,
 *   so callers can safely re-parse it and extract data from verified content only.
 */
export function verifyEnvelopedSignature(
  containingXml: string,
  element: Element,
  signatureElement: Element,
  certificates: readonly string[],
  allowSha1 = false
): VerifiedSignature {
  const elementId = element.getAttribute("ID");
  if (!elementId) {
    throw new SignatureError(
      `Signed <${element.localName}> element has no ID attribute; cannot verify its signature reference.`
    );
  }
  /* istanbul ignore else -- elements reaching this point always belong to a document */
  if (element.ownerDocument) {
    assertUniqueId(element.ownerDocument, elementId);
  }

  const signatureAllowlist = new Set(SIGNATURE_ALGORITHMS);
  const digestAllowlist = new Set(DIGEST_ALGORITHMS);
  if (allowSha1) {
    signatureAllowlist.add(SHA1_SIGNATURE);
    digestAllowlist.add(SHA1_DIGEST);
  }

  let lastError: unknown;

  for (const certificate of certificates) {
    const sig = new SignedXml({ publicCert: normalizeCertificate(certificate) });
    try {
      // xml-crypto accepts a DOM node; xmldom nodes are structurally compatible.
      sig.loadSignature(signatureElement);

      const references = sig.getReferences();
      if (references.length !== 1) {
        throw new SignatureError(
          `Signature must cover exactly one reference, found ${references.length}.`
        );
      }
      const reference = references[0] as NonNullable<(typeof references)[number]>;
      const uri = reference.uri ?? "";
      if (uri !== `#${elementId}`) {
        throw new SignatureError(
          `Signature reference URI "${uri}" does not match the signed element's ID "#${elementId}" ` +
            "(possible signature-wrapping attack)."
        );
      }

      const signatureAlgorithm = sig.signatureAlgorithm ?? "";
      if (!signatureAllowlist.has(signatureAlgorithm)) {
        throw new SignatureError(
          `Signature algorithm "${signatureAlgorithm}" is not allowed.` +
            (signatureAlgorithm === SHA1_SIGNATURE
              ? " SHA-1 is deprecated; set allowSha1: true only if your IdP cannot be upgraded."
              : "")
        );
      }
      const digestAlgorithm = reference.digestAlgorithm ?? "";
      if (!digestAllowlist.has(digestAlgorithm)) {
        throw new SignatureError(
          `Digest algorithm "${digestAlgorithm}" is not allowed.` +
            (digestAlgorithm === SHA1_DIGEST
              ? " SHA-1 is deprecated; set allowSha1: true only if your IdP cannot be upgraded."
              : "")
        );
      }

      if (!sig.checkSignature(containingXml)) {
        lastError = new SignatureError("Signature value does not verify against this certificate.");
        continue; // try the next certificate (IdP key rollover)
      }

      const signedContent = sig.getSignedReferences()[0];
      /* istanbul ignore if -- a verified signature always yields its signed reference;
         kept as a hard stop should xml-crypto's contract ever change. */
      if (!signedContent) {
        throw new SignatureError("Signature verified but produced no signed content.");
      }
      return { signedContent };
    } catch (err) {
      lastError = err;
    }
  }

  if (lastError instanceof SignatureError) {
    throw lastError;
  }
  throw new SignatureError(
    "XML signature verification failed against all configured IdP certificates. " +
      "Verify that the certificates in your IdP configuration are current.",
    "SAML_SIGNATURE_INVALID",
    { cause: lastError }
  );
}
