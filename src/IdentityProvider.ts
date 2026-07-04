import type { Element } from "@xmldom/xmldom";
import { SAMLConfigError } from "./errors";
import { assertHttpUrl } from "./internal/authnRequest";
import { NS, childElements, firstChild, isElement, parseXml, textOf } from "./internal/parse";
import { validateCertificate } from "./internal/pem";
import type { IdentityProviderConfig } from "./types";

const REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
const POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

/**
 * Describes the Identity Provider this SP trusts: its entityID, SSO endpoints,
 * and signing certificates.
 *
 * The easiest way to construct one is from the IdP's metadata XML:
 *
 * ```ts
 * const idp = IdentityProvider.fromMetadata(metadataXml);
 * // or, fetched over HTTPS:
 * const idp = await IdentityProvider.fromUrl("https://idp.example.com/metadata");
 * ```
 */
export class IdentityProvider {
  readonly entityId: string;
  /** SSO endpoint for the HTTP-Redirect binding, if the IdP offers one. */
  readonly ssoUrl?: string;
  /** SSO endpoint for the HTTP-POST binding, if the IdP offers one. */
  readonly ssoPostUrl?: string;
  /** Normalized PEM signing certificates, tried in order (supports rollover). */
  readonly certificates: readonly string[];
  /** Whether the IdP's metadata asks for signed AuthnRequests. */
  readonly wantAuthnRequestsSigned: boolean;

  constructor(config: IdentityProviderConfig) {
    if (!config || typeof config.entityId !== "string" || config.entityId.trim() === "") {
      throw new SAMLConfigError("IdentityProvider requires a non-empty entityId.");
    }
    if (!config.ssoUrl && !config.ssoPostUrl) {
      throw new SAMLConfigError(
        "IdentityProvider requires at least one SSO endpoint (ssoUrl or ssoPostUrl)."
      );
    }
    if (config.ssoUrl) assertHttpUrl(config.ssoUrl, "IdentityProvider ssoUrl");
    if (config.ssoPostUrl) assertHttpUrl(config.ssoPostUrl, "IdentityProvider ssoPostUrl");
    if (!Array.isArray(config.certificates) || config.certificates.length === 0) {
      throw new SAMLConfigError(
        "IdentityProvider requires at least one signing certificate. " +
          "You can find it in your IdP's metadata under KeyDescriptor[use=signing]."
      );
    }

    this.entityId = config.entityId.trim();
    this.ssoUrl = config.ssoUrl;
    this.ssoPostUrl = config.ssoPostUrl;
    this.certificates = config.certificates.map((cert) =>
      validateCertificate(cert, "IdP certificate")
    );
    this.wantAuthnRequestsSigned = config.wantAuthnRequestsSigned ?? false;
  }

  /**
   * Parse IdP metadata XML (as downloaded from Okta, Entra ID, Google, Keycloak, …)
   * into a ready-to-use IdentityProvider.
   */
  static fromMetadata(metadataXml: string): IdentityProvider {
    const doc = parseXml(metadataXml, "IdP metadata");
    // parseXml guarantees a root element
    const root = doc.documentElement as Element;

    let entityDescriptor: Element | null = null;
    if (isElement(root, NS.MD, "EntityDescriptor")) {
      entityDescriptor = root;
    } else if (isElement(root, NS.MD, "EntitiesDescriptor")) {
      // Federation metadata: pick the first entity that describes an IdP.
      const candidates = root.getElementsByTagNameNS(NS.MD, "EntityDescriptor");
      for (let i = 0; i < candidates.length; i++) {
        const candidate = candidates.item(i);
        if (candidate && firstChild(candidate, NS.MD, "IDPSSODescriptor")) {
          entityDescriptor = candidate;
          break;
        }
      }
    }
    if (!entityDescriptor) {
      throw new SAMLConfigError(
        "IdP metadata does not contain an EntityDescriptor. " +
          "Make sure you pasted the IdP (not SP) metadata XML."
      );
    }

    const entityId = entityDescriptor.getAttribute("entityID");
    if (!entityId) {
      throw new SAMLConfigError("IdP metadata EntityDescriptor is missing the entityID attribute.");
    }

    const idpDescriptor = firstChild(entityDescriptor, NS.MD, "IDPSSODescriptor");
    if (!idpDescriptor) {
      throw new SAMLConfigError(
        "IdP metadata does not contain an IDPSSODescriptor — this metadata does not describe " +
          "an Identity Provider. Make sure you pasted the IdP (not SP) metadata XML."
      );
    }

    let ssoUrl: string | undefined;
    let ssoPostUrl: string | undefined;
    for (const service of childElements(idpDescriptor, NS.MD, "SingleSignOnService")) {
      const binding = service.getAttribute("Binding");
      const location = service.getAttribute("Location");
      if (!location) continue;
      if (binding === REDIRECT_BINDING && !ssoUrl) ssoUrl = location;
      if (binding === POST_BINDING && !ssoPostUrl) ssoPostUrl = location;
    }
    if (!ssoUrl && !ssoPostUrl) {
      throw new SAMLConfigError(
        "IdP metadata contains no SingleSignOnService endpoint for the HTTP-Redirect or HTTP-POST binding."
      );
    }

    const certificates: string[] = [];
    for (const keyDescriptor of childElements(idpDescriptor, NS.MD, "KeyDescriptor")) {
      const use = keyDescriptor.getAttribute("use");
      if (use && use !== "signing") continue; // encryption-only keys are not for verification
      const keyInfo = firstChild(keyDescriptor, NS.DS, "KeyInfo");
      const x509Data = keyInfo && firstChild(keyInfo, NS.DS, "X509Data");
      if (!x509Data) continue;
      for (const certEl of childElements(x509Data, NS.DS, "X509Certificate")) {
        const body = textOf(certEl);
        if (body && !certificates.includes(body)) certificates.push(body);
      }
    }
    if (certificates.length === 0) {
      throw new SAMLConfigError(
        "IdP metadata contains no signing certificate (KeyDescriptor/X509Certificate)."
      );
    }

    const wantSigned = idpDescriptor.getAttribute("WantAuthnRequestsSigned") === "true";

    return new IdentityProvider({
      entityId,
      ssoUrl,
      ssoPostUrl,
      certificates,
      wantAuthnRequestsSigned: wantSigned,
    });
  }

  /** Fetch metadata XML over HTTP(S) and parse it. Requires Node 18+ (global fetch). */
  static async fromUrl(url: string, options?: { fetch?: typeof fetch }): Promise<IdentityProvider> {
    assertHttpUrl(url, "Metadata URL");
    const fetchImpl = options?.fetch ?? fetch;
    let response: Response;
    try {
      response = await fetchImpl(url, { redirect: "follow" });
    } catch (err) {
      throw new SAMLConfigError(`Failed to fetch IdP metadata from ${url}.`, { cause: err });
    }
    if (!response.ok) {
      throw new SAMLConfigError(
        `Failed to fetch IdP metadata from ${url}: HTTP ${response.status}.`
      );
    }
    return IdentityProvider.fromMetadata(await response.text());
  }
}
