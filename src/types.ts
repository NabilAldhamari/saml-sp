import type { IncomingMessage } from "node:http";
import type { IdentityProvider } from "./IdentityProvider";

/** A PEM private key and self-signed certificate pair. */
export interface KeyPair {
  privateKey: string;
  certificate: string;
}

export interface GenerateKeyPairOptions {
  /** RSA modulus length. Default: `2048`. */
  keySize?: 2048 | 4096;
  /** Certificate validity in days. Default: `3650` (10 years). */
  days?: number;
  /** Certificate common name. Default: `"saml-sp"`. */
  commonName?: string;
}

/** Manual IdP configuration — use `IdentityProvider.fromMetadata()` to derive this from metadata XML. */
export interface IdentityProviderConfig {
  /** The IdP entityID, matched against the `Issuer` of incoming responses. */
  entityId: string;
  /** SSO endpoint for the HTTP-Redirect binding. At least one of `ssoUrl`/`ssoPostUrl` is required. */
  ssoUrl?: string;
  /** SSO endpoint for the HTTP-POST binding. */
  ssoPostUrl?: string;
  /** SingleLogoutService endpoint for the HTTP-Redirect binding (enables SLO). */
  sloUrl?: string;
  /** SingleLogoutService endpoint for the HTTP-POST binding. */
  sloPostUrl?: string;
  /**
   * One or more X.509 signing certificates (PEM or raw base64). Multiple certificates
   * are tried in order, which supports IdP certificate rollover.
   */
  certificates: string[];
  /** Whether the IdP declares `WantAuthnRequestsSigned` in its metadata. Informational. */
  wantAuthnRequestsSigned?: boolean;
}

/** Pluggable store for outstanding AuthnRequest IDs (backs `InResponseTo` validation). */
export interface RequestStore {
  /** Remember a request ID that we issued. */
  store(id: string): void | Promise<void>;
  /**
   * Consume a request ID: return `true` if it was outstanding (and remove it so it
   * cannot be used twice), `false` if unknown or expired.
   */
  consume(id: string): boolean | Promise<boolean>;
}

/** Pluggable cache of consumed assertion IDs (backs replay detection). */
export interface ReplayCache {
  /**
   * Register an assertion ID. Return `true` if it was new, `false` if it was
   * already present (replay). Entries may be evicted after `expiresAt`.
   */
  register(id: string, expiresAt: Date): boolean | Promise<boolean>;
}

export interface ServiceProviderConfig {
  /** Unique identifier for this SP, e.g. `"urn:example:sp"` or your app URL. */
  entityId: string;
  /** Your ACS endpoint — the URL where the IdP POSTs SAML responses. */
  assertionConsumerServiceUrl: string;
  /** The Identity Provider this SP trusts. */
  idp: IdentityProvider | IdentityProviderConfig;
  /** PEM private key. Required for decrypting assertions and signing requests. */
  privateKey?: string;
  /** PEM certificate published in SP metadata (signing/encryption KeyDescriptors). */
  certificate?: string;
  /** Tolerated clock difference between SP and IdP, in milliseconds. Default: `30_000`. */
  clockSkewMs?: number;
  /**
   * Require every assertion to be covered by a valid signature — either a signed
   * `Response` envelope or a signed `Assertion`. Default: `true`.
   * Only disable this in tests. Never disable it in production.
   */
  requireSignedAssertions?: boolean;
  /** Additionally require the top-level `Response` element itself to be signed. Default: `false`. */
  requireSignedResponse?: boolean;
  /** Accept IdP-initiated (unsolicited) responses without `InResponseTo`. Default: `false`. */
  allowUnsolicited?: boolean;
  /** Accept SHA-1 based signature/digest algorithms from legacy IdPs. Default: `false`. */
  allowSha1?: boolean;
  /** Sign outgoing AuthnRequests (requires `privateKey`). Default: `false`. */
  signAuthnRequests?: boolean;
  /** `NameIDPolicy` format requested in AuthnRequests. Default: `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`. */
  nameIdFormat?: string;
  /**
   * Your SP's SingleLogoutService endpoint (HTTP-Redirect binding). Published in SP
   * metadata and required for the IdP to address logout messages back to you.
   */
  singleLogoutServiceUrl?: string;
  /**
   * Sign outbound LogoutRequest/LogoutResponse messages when a `privateKey` is
   * available. Default: `true`. (No signing happens without a `privateKey`.)
   */
  signLogoutMessages?: boolean;
  /** Require inbound SLO messages to carry a valid signature. Default: `true`. */
  requireSignedLogout?: boolean;
  /** Maximum accepted SAML response size in bytes. Default: `1_048_576` (1 MiB). */
  maxResponseSize?: number;
  /** Store for outstanding request IDs. Default: in-memory with a 10-minute TTL. */
  requestStore?: RequestStore;
  /** Cache for consumed assertion IDs. Default: in-memory. */
  replayCache?: ReplayCache;
}

export interface LoginRequestOptions {
  /** Opaque state returned by the IdP alongside the response. Treat as untrusted input. */
  relayState?: string;
  /** SAML binding to use. Default: `"redirect"` (falls back to `"post"` if the IdP has no redirect endpoint). */
  binding?: "redirect" | "post";
  /** Ask the IdP to re-authenticate the user even if they have an active session. */
  forceAuthn?: boolean;
  /** Ask the IdP to authenticate without user interaction. */
  isPassive?: boolean;
}

export interface LoginRequest {
  /** The AuthnRequest ID. Stored automatically for `InResponseTo` validation. */
  id: string;
  /** Binding actually used. */
  binding: "redirect" | "post";
  /**
   * For the redirect binding: the full IdP URL to redirect the user to.
   * For the POST binding: the IdP endpoint to POST `fields` to.
   */
  url: string;
  /** For the POST binding: hidden form fields (`SAMLRequest`, optionally `RelayState`). */
  fields?: Record<string, string>;
  /** For the POST binding: a ready-to-serve auto-submitting HTML page. */
  html?: string;
  /** The raw AuthnRequest XML — useful for debugging. */
  xml: string;
  relayState?: string;
}

/** The validated identity extracted from a SAML assertion. */
export interface SAMLProfile {
  /** The authenticated subject's NameID (usually an email address or opaque ID). */
  nameId: string | null;
  nameIdFormat: string | null;
  /** IdP session identifier, needed later for Single Logout. */
  sessionIndex: string | null;
  /** All attributes from the assertion's `AttributeStatement`. */
  attributes: Record<string, string[]>;
  /** The assertion issuer (the IdP entityId). */
  issuer: string;
  authnContextClassRef: string | null;
  notBefore: Date | null;
  notOnOrAfter: Date | null;
  /** The AuthnRequest ID this response answers, if any. */
  inResponseTo: string | null;
  /** The raw (decrypted, signature-verified) assertion XML. */
  assertionXml: string;
}

export interface ConsumeResult {
  profile: SAMLProfile;
  /** RelayState echoed by the IdP. Untrusted input — never redirect to it blindly. */
  relayState?: string;
}

/** A pre-parsed POST body, e.g. `req.body` from Express with urlencoded parsing. */
export interface SAMLResponseBody {
  SAMLResponse: string;
  RelayState?: string;
}

/** Input accepted by `ServiceProvider.consume()`. */
export type ConsumeInput = IncomingMessage | SAMLResponseBody;

export interface LogoutRequestOptions {
  /** The subject to log out. Pass `profile.nameId` from the original login. */
  nameId: string;
  /** The subject's NameID `Format`. Pass `profile.nameIdFormat` so the IdP can match the subject. */
  nameIdFormat?: string;
  /** The IdP session to terminate. Pass `profile.sessionIndex`. */
  sessionIndex?: string;
  /** Opaque state echoed back on the LogoutResponse. Untrusted input on return. */
  relayState?: string;
}

/** SP-initiated logout, ready to send via HTTP-Redirect. */
export interface LogoutRequest {
  /** The LogoutRequest ID. Stored automatically for `InResponseTo` validation. */
  id: string;
  binding: "redirect";
  /** Redirect the user's browser here to begin logout at the IdP. */
  url: string;
  /** The raw LogoutRequest XML — useful for debugging. */
  xml: string;
  relayState?: string;
}

/** Result of `receiveLogout()` when the IdP answered our SP-initiated logout. */
export interface LogoutResponseResult {
  type: "response";
  /** Always `true`: a non-Success status throws `ResponseStatusError` instead. */
  success: true;
  issuer: string | null;
  /** The LogoutRequest ID this response answered, if any. */
  inResponseTo: string | null;
  relayState?: string;
}

/** Result of `receiveLogout()` when the IdP initiated the logout. */
export interface LogoutRequestResult {
  type: "request";
  /** The subject the IdP wants logged out. Clear this user's local session. */
  nameId: string | null;
  /** The IdP session index being terminated, if provided. */
  sessionIndex: string | null;
  issuer: string | null;
  relayState?: string;
  /**
   * Redirect the user's browser here to acknowledge the logout back to the IdP.
   * The response is built and signed for you.
   */
  responseUrl: string;
}

/** Discriminated result of `receiveLogout()`. Branch on `.type`. */
export type LogoutResult = LogoutResponseResult | LogoutRequestResult;

/** Input accepted by `ServiceProvider.receiveLogout()`: a GET request or its raw query string. */
export type LogoutInput = IncomingMessage | string;
