import { EventEmitter } from "node:events";
import { X509Certificate, createSign, randomBytes } from "node:crypto";
import { deflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";
import * as xmlenc from "xml-encryption";
import { IdentityProvider } from "../../src/IdentityProvider";
import { ServiceProvider } from "../../src/ServiceProvider";
import type { ServiceProviderConfig } from "../../src/types";
import { IDP_KEYS, SP_KEYS } from "./keys";

export const SP_ENTITY_ID = "urn:test:sp";
export const IDP_ENTITY_ID = "urn:test:idp";
export const ACS_URL = "https://sp.example.com/saml/acs";
export const SP_SLO_URL = "https://sp.example.com/saml/slo";
export const IDP_SSO_URL = "https://idp.example.com/sso/redirect";
export const IDP_SSO_POST_URL = "https://idp.example.com/sso/post";
export const IDP_SLO_URL = "https://idp.example.com/slo/redirect";

export const RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
export const RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
export const SHA256_DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256";
export const SHA1_DIGEST = "http://www.w3.org/2000/09/xmldsig#sha1";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

export function testId(): string {
  return `_${randomBytes(16).toString("hex")}`;
}

export function minutesFromNow(minutes: number): Date {
  return new Date(Date.now() + minutes * 60_000);
}

// ---------------------------------------------------------------------------
// SP construction
// ---------------------------------------------------------------------------

/** A ServiceProvider wired to the test IdP; unsolicited allowed unless overridden. */
export function makeSp(overrides: Partial<ServiceProviderConfig> = {}): ServiceProvider {
  return new ServiceProvider({
    entityId: SP_ENTITY_ID,
    assertionConsumerServiceUrl: ACS_URL,
    idp: new IdentityProvider({
      entityId: IDP_ENTITY_ID,
      ssoUrl: IDP_SSO_URL,
      ssoPostUrl: IDP_SSO_POST_URL,
      sloUrl: IDP_SLO_URL,
      certificates: [IDP_KEYS.certificate],
    }),
    privateKey: SP_KEYS.privateKey,
    certificate: SP_KEYS.certificate,
    allowUnsolicited: true,
    ...overrides,
  });
}

/** A ServiceProvider with SLO fully wired (SP + IdP logout endpoints). */
export function makeLogoutSp(overrides: Partial<ServiceProviderConfig> = {}): ServiceProvider {
  return makeSp({ singleLogoutServiceUrl: SP_SLO_URL, ...overrides });
}

// ---------------------------------------------------------------------------
// Assertion / Response XML builders
// ---------------------------------------------------------------------------

export interface AssertionOptions {
  id?: string;
  version?: string;
  issuer?: string | null;
  nameId?: string;
  nameIdFormat?: string;
  notBefore?: Date | null;
  notOnOrAfter?: Date | null;
  audiences?: string[] | null;
  recipient?: string | null;
  inResponseTo?: string;
  scNotOnOrAfter?: Date | null;
  scNotBefore?: Date | null;
  sessionIndex?: string;
  authnContextClassRef?: string;
  attributes?: Record<string, string[]>;
  includeConditions?: boolean;
  includeSubject?: boolean;
}

/** A structurally complete, spec-shaped assertion with sane valid defaults. */
export function buildAssertionXml(options: AssertionOptions = {}): string {
  const {
    id = testId(),
    version = "2.0",
    issuer = IDP_ENTITY_ID,
    nameId = "alice@example.com",
    nameIdFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    notBefore = minutesFromNow(-5),
    notOnOrAfter = minutesFromNow(5),
    audiences = [SP_ENTITY_ID],
    recipient = ACS_URL,
    inResponseTo,
    scNotOnOrAfter = minutesFromNow(5),
    scNotBefore = null,
    sessionIndex = "session-123",
    authnContextClassRef = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
    attributes = { email: ["alice@example.com"], roles: ["admin", "user"] },
    includeConditions = true,
    includeSubject = true,
  } = options;

  const issueInstant = new Date().toISOString();

  const issuerXml = issuer === null ? "" : `<saml:Issuer>${issuer}</saml:Issuer>`;

  let conditionsXml = "";
  if (includeConditions) {
    const attrs = [
      notBefore ? `NotBefore="${notBefore.toISOString()}"` : "",
      notOnOrAfter ? `NotOnOrAfter="${notOnOrAfter.toISOString()}"` : "",
    ]
      .filter(Boolean)
      .join(" ");
    const audienceXml =
      audiences === null
        ? ""
        : `<saml:AudienceRestriction>${audiences
            .map((a) => `<saml:Audience>${a}</saml:Audience>`)
            .join("")}</saml:AudienceRestriction>`;
    conditionsXml = `<saml:Conditions ${attrs}>${audienceXml}</saml:Conditions>`;
  }

  let subjectXml = "";
  if (includeSubject) {
    const scdAttrs = [
      recipient ? `Recipient="${recipient}"` : "",
      scNotOnOrAfter ? `NotOnOrAfter="${scNotOnOrAfter.toISOString()}"` : "",
      scNotBefore ? `NotBefore="${scNotBefore.toISOString()}"` : "",
      inResponseTo ? `InResponseTo="${inResponseTo}"` : "",
    ]
      .filter(Boolean)
      .join(" ");
    subjectXml = `<saml:Subject>
      <saml:NameID Format="${nameIdFormat}">${nameId}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData ${scdAttrs}/>
      </saml:SubjectConfirmation>
    </saml:Subject>`;
  }

  const attributeXml = Object.entries(attributes)
    .map(
      ([name, values]) =>
        `<saml:Attribute Name="${name}">${values
          .map((v) => `<saml:AttributeValue>${v}</saml:AttributeValue>`)
          .join("")}</saml:Attribute>`
    )
    .join("");
  const attributeStatement =
    Object.keys(attributes).length > 0
      ? `<saml:AttributeStatement>${attributeXml}</saml:AttributeStatement>`
      : "";

  return `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${id}" Version="${version}" IssueInstant="${issueInstant}">${issuerXml}${subjectXml}${conditionsXml}<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${sessionIndex}"><saml:AuthnContext><saml:AuthnContextClassRef>${authnContextClassRef}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>${attributeStatement}</saml:Assertion>`;
}

export interface ResponseOptions {
  id?: string;
  version?: string;
  issuer?: string | null;
  destination?: string | null;
  inResponseTo?: string;
  statusCode?: string;
  subStatusCode?: string;
  statusMessage?: string;
  omitStatus?: boolean;
}

/** Wrap inner XML (assertion or EncryptedAssertion) in a samlp:Response envelope. */
export function buildResponseXml(innerXml: string, options: ResponseOptions = {}): string {
  const {
    id = testId(),
    version = "2.0",
    issuer = IDP_ENTITY_ID,
    destination = ACS_URL,
    inResponseTo,
    statusCode = "urn:oasis:names:tc:SAML:2.0:status:Success",
    subStatusCode,
    statusMessage,
    omitStatus = false,
  } = options;

  const attrs = [
    `ID="${id}"`,
    `Version="${version}"`,
    `IssueInstant="${new Date().toISOString()}"`,
    destination ? `Destination="${destination}"` : "",
    inResponseTo ? `InResponseTo="${inResponseTo}"` : "",
  ]
    .filter(Boolean)
    .join(" ");

  const issuerXml = issuer === null ? "" : `<saml:Issuer>${issuer}</saml:Issuer>`;
  const statusXml = omitStatus
    ? ""
    : `<samlp:Status><samlp:StatusCode Value="${statusCode}">${
        subStatusCode ? `<samlp:StatusCode Value="${subStatusCode}"/>` : ""
      }</samlp:StatusCode>${
        statusMessage ? `<samlp:StatusMessage>${statusMessage}</samlp:StatusMessage>` : ""
      }</samlp:Status>`;

  return `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ${attrs}>${issuerXml}${statusXml}${innerXml}</samlp:Response>`;
}

// ---------------------------------------------------------------------------
// Signing / encryption (the "IdP side" of the handshake)
// ---------------------------------------------------------------------------

export interface SignOptions {
  privateKey?: string;
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
}

function signElement(
  xml: string,
  localName: "Assertion" | "Response" | "AuthnRequest",
  elementId: string,
  options: SignOptions = {}
): string {
  const sig = new SignedXml({ privateKey: options.privateKey ?? IDP_KEYS.privateKey });
  sig.signatureAlgorithm = options.signatureAlgorithm ?? RSA_SHA256;
  sig.canonicalizationAlgorithm = EXC_C14N;
  sig.addReference({
    xpath: `//*[local-name(.)='${localName}']`,
    uri: `#${elementId}`,
    digestAlgorithm: options.digestAlgorithm ?? SHA256_DIGEST,
    transforms: [ENVELOPED, EXC_C14N],
  });
  sig.computeSignature(xml, {
    prefix: "ds",
    location: {
      reference: `//*[local-name(.)='${localName}']/*[local-name(.)='Issuer']`,
      action: "after",
    },
  });
  return sig.getSignedXml();
}

/** Sign the Assertion element (inside a response document or standalone). */
export function signAssertion(xml: string, assertionId: string, options?: SignOptions): string {
  return signElement(xml, "Assertion", assertionId, options);
}

/** Sign the Response element. Do this AFTER signing the assertion (if both). */
export function signResponse(xml: string, responseId: string, options?: SignOptions): string {
  return signElement(xml, "Response", responseId, options);
}

/** Encrypt an assertion for the SP, exactly as an IdP would. */
export function encryptAssertion(
  assertionXml: string,
  spCertificate: string = SP_KEYS.certificate,
  encryptionAlgorithm:
    | "http://www.w3.org/2009/xmlenc11#aes256-gcm"
    | "http://www.w3.org/2001/04/xmlenc#aes256-cbc" = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
): Promise<string> {
  const publicKey = new X509Certificate(spCertificate).publicKey
    .export({ type: "spki", format: "pem" })
    .toString();

  return new Promise((resolve, reject) => {
    xmlenc.encrypt(
      assertionXml,
      {
        rsa_pub: publicKey,
        pem: spCertificate,
        encryptionAlgorithm,
        keyEncryptionAlgorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p",
      },
      (err, result) => {
        if (err) reject(err);
        else
          resolve(
            `<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${result}</saml:EncryptedAssertion>`
          );
      }
    );
  });
}

/**
 * One-stop builder for the common case: a Success response containing a single
 * assertion, signed at the requested levels.
 */
export async function buildValidResponse(
  options: {
    assertion?: AssertionOptions;
    response?: ResponseOptions;
    signAssertion?: boolean;
    signResponse?: boolean;
    encrypt?: boolean;
    signOptions?: SignOptions;
  } = {}
): Promise<string> {
  const assertionId = options.assertion?.id ?? testId();
  const responseId = options.response?.id ?? testId();
  let assertionXml = buildAssertionXml({ ...options.assertion, id: assertionId });

  if (options.encrypt) {
    if (options.signAssertion !== false) {
      assertionXml = signAssertion(assertionXml, assertionId, options.signOptions);
    }
    const encrypted = await encryptAssertion(assertionXml);
    let responseXml = buildResponseXml(encrypted, { ...options.response, id: responseId });
    if (options.signResponse) {
      responseXml = signResponse(responseXml, responseId, options.signOptions);
    }
    return responseXml;
  }

  let responseXml = buildResponseXml(assertionXml, { ...options.response, id: responseId });
  if (options.signAssertion !== false) {
    responseXml = signAssertion(responseXml, assertionId, options.signOptions);
  }
  if (options.signResponse) {
    responseXml = signResponse(responseXml, responseId, options.signOptions);
  }
  return responseXml;
}

// ---------------------------------------------------------------------------
// Single Logout builders (the "IdP side")
// ---------------------------------------------------------------------------

const SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol";
const SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

export interface IdpLogoutRequestOptions {
  id?: string;
  issuer?: string | null;
  destination?: string | null;
  nameId?: string;
  sessionIndex?: string;
}

/** Build an IdP-initiated LogoutRequest XML. */
export function buildIdpLogoutRequestXml(options: IdpLogoutRequestOptions = {}): string {
  const {
    id = testId(),
    issuer = IDP_ENTITY_ID,
    destination = SP_SLO_URL,
    nameId = "alice@example.com",
    sessionIndex = "session-123",
  } = options;
  const issuerXml = issuer === null ? "" : `<saml:Issuer>${issuer}</saml:Issuer>`;
  const destAttr = destination === null ? "" : `Destination="${destination}"`;
  const sessionXml = sessionIndex ? `<samlp:SessionIndex>${sessionIndex}</samlp:SessionIndex>` : "";
  return `<samlp:LogoutRequest xmlns:samlp="${SAMLP_NS}" xmlns:saml="${SAML_NS}" ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString()}" ${destAttr}>${issuerXml}<saml:NameID>${nameId}</saml:NameID>${sessionXml}</samlp:LogoutRequest>`;
}

export interface IdpLogoutResponseOptions {
  id?: string;
  issuer?: string | null;
  destination?: string | null;
  inResponseTo?: string;
  statusCode?: string;
  subStatusCode?: string;
  statusMessage?: string;
  omitStatus?: boolean;
}

/** Build an IdP LogoutResponse XML answering our LogoutRequest. */
export function buildIdpLogoutResponseXml(options: IdpLogoutResponseOptions = {}): string {
  const {
    id = testId(),
    issuer = IDP_ENTITY_ID,
    destination = SP_SLO_URL,
    inResponseTo,
    statusCode = "urn:oasis:names:tc:SAML:2.0:status:Success",
    subStatusCode,
    statusMessage,
    omitStatus = false,
  } = options;
  const issuerXml = issuer === null ? "" : `<saml:Issuer>${issuer}</saml:Issuer>`;
  const destAttr = destination === null ? "" : `Destination="${destination}"`;
  const irtAttr = inResponseTo ? `InResponseTo="${inResponseTo}"` : "";
  const subXml = subStatusCode ? `<samlp:StatusCode Value="${subStatusCode}"/>` : "";
  const messageXml = statusMessage
    ? `<samlp:StatusMessage>${statusMessage}</samlp:StatusMessage>`
    : "";
  const statusXml = omitStatus
    ? ""
    : `<samlp:Status><samlp:StatusCode Value="${statusCode}">${subXml}</samlp:StatusCode>${messageXml}</samlp:Status>`;
  return `<samlp:LogoutResponse xmlns:samlp="${SAMLP_NS}" xmlns:saml="${SAML_NS}" ID="${id}" Version="2.0" IssueInstant="${new Date().toISOString()}" ${destAttr} ${irtAttr}>${issuerXml}${statusXml}</samlp:LogoutResponse>`;
}

const REDIRECT_SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

export interface RedirectQueryOptions {
  relayState?: string;
  /** Sign the query with this key (defaults to the IdP key). Pass null to leave unsigned. */
  privateKey?: string | null;
  sigAlg?: string;
}

/** Encode a message as a signed (or unsigned) HTTP-Redirect binding query string. */
export function toRedirectQuery(
  type: "SAMLRequest" | "SAMLResponse",
  xml: string,
  options: RedirectQueryOptions = {}
): string {
  const encoded = deflateRawSync(Buffer.from(xml, "utf8")).toString("base64");
  const parts = [`${type}=${encodeURIComponent(encoded)}`];
  if (options.relayState !== undefined) {
    parts.push(`RelayState=${encodeURIComponent(options.relayState)}`);
  }
  const signKey =
    options.privateKey === null ? undefined : (options.privateKey ?? IDP_KEYS.privateKey);
  if (signKey) {
    const sigAlg = options.sigAlg ?? REDIRECT_SIG_RSA_SHA256;
    parts.push(`SigAlg=${encodeURIComponent(sigAlg)}`);
    const hash = sigAlg.endsWith("sha1") ? "RSA-SHA1" : "RSA-SHA256";
    const signer = createSign(hash);
    signer.update(parts.join("&"));
    parts.push(`Signature=${encodeURIComponent(signer.sign(signKey).toString("base64"))}`);
  }
  return parts.join("&");
}

/** A mock GET IncomingMessage carrying a redirect-binding query at the given path. */
export function mockGetRequestWithQuery(query: string, path = "/saml/slo"): MockRequest {
  const req = mockGetRequest();
  (req as unknown as { url: string }).url = `${path}?${query}`;
  return req;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

export function toPostBody(responseXml: string, relayState?: string): string {
  const params = new URLSearchParams({
    SAMLResponse: Buffer.from(responseXml, "utf8").toString("base64"),
  });
  if (relayState !== undefined) params.set("RelayState", relayState);
  return params.toString();
}

export interface MockRequest extends EventEmitter {
  method: string;
  destroyed: boolean;
  destroy(): void;
}

/** Minimal IncomingMessage stand-in that emits the given body. */
export function mockPostRequest(body: string, chunkSize = Infinity): MockRequest {
  const req = new EventEmitter() as MockRequest;
  req.method = "POST";
  req.destroyed = false;
  req.destroy = () => {
    req.destroyed = true;
  };
  process.nextTick(() => {
    for (let i = 0; i < body.length; i += Math.min(chunkSize, body.length)) {
      if (req.destroyed) return;
      req.emit("data", Buffer.from(body.slice(i, i + chunkSize)));
      if (chunkSize === Infinity) break;
    }
    if (!req.destroyed) req.emit("end");
  });
  return req;
}

export function mockGetRequest(): MockRequest {
  const req = new EventEmitter() as MockRequest;
  req.method = "GET";
  req.destroyed = false;
  req.destroy = () => {
    req.destroyed = true;
  };
  return req;
}
