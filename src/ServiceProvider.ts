import { createPrivateKey } from "node:crypto";
import type { IncomingMessage } from "node:http";
import * as selfsigned from "selfsigned";
import {
  DestinationMismatchError,
  InResponseToError,
  IssuerMismatchError,
  ResponseStatusError,
  SAMLConfigError,
  SAMLParseError,
} from "./errors";
import { IdentityProvider } from "./IdentityProvider";
import {
  assertHttpUrl,
  buildAuthnRequestXml,
  buildPostBinding,
  generateId,
  signAuthnRequestXml,
} from "./internal/authnRequest";
import {
  STATUS_SUCCESS,
  buildLogoutRequestXml,
  buildLogoutResponseXml,
  parseLogoutRequest,
  parseLogoutResponse,
} from "./internal/logout";
import { buildMetadataXml } from "./internal/metadata";
import { validateCertificate } from "./internal/pem";
import {
  buildRedirectUrl,
  parseRedirectQuery,
  verifyRedirectSignature,
} from "./internal/redirectBinding";
import { InMemoryReplayCache, InMemoryRequestStore } from "./internal/stores";
import { validateResponse } from "./internal/validateResponse";
import type {
  ConsumeInput,
  ConsumeResult,
  GenerateKeyPairOptions,
  KeyPair,
  LogoutInput,
  LogoutRequest,
  LogoutRequestOptions,
  LogoutResult,
  LoginRequest,
  LoginRequestOptions,
  ReplayCache,
  RequestStore,
  SAMLResponseBody,
  ServiceProviderConfig,
} from "./types";

const DEFAULT_NAME_ID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
const DEFAULT_CLOCK_SKEW_MS = 30_000;
const DEFAULT_MAX_RESPONSE_SIZE = 1_048_576; // 1 MiB

/**
 * A SAML 2.0 Service Provider.
 *
 * ```ts
 * const sp = new ServiceProvider({
 *   entityId: "urn:example:sp",
 *   assertionConsumerServiceUrl: "https://app.example.com/saml/acs",
 *   idp: IdentityProvider.fromMetadata(metadataXml),
 * });
 *
 * const { url } = await sp.createLoginRequest();       // redirect the user here
 * const { profile } = await sp.consume(req);           // in your ACS route
 * ```
 */
export class ServiceProvider {
  readonly entityId: string;
  readonly assertionConsumerServiceUrl: string;
  readonly idp: IdentityProvider;

  private readonly privateKey?: string;
  private readonly certificate?: string;
  private readonly singleLogoutServiceUrl?: string;
  private readonly clockSkewMs: number;
  private readonly requireSignedAssertions: boolean;
  private readonly requireSignedResponse: boolean;
  private readonly allowUnsolicited: boolean;
  private readonly allowSha1: boolean;
  private readonly signAuthnRequests: boolean;
  private readonly signLogoutMessages: boolean;
  private readonly requireSignedLogout: boolean;
  private readonly nameIdFormat: string;
  private readonly maxResponseSize: number;
  private readonly requestStore: RequestStore;
  private readonly replayCache: ReplayCache;

  constructor(config: ServiceProviderConfig) {
    if (typeof config.entityId !== "string" || config.entityId.trim() === "") {
      throw new SAMLConfigError("ServiceProvider requires a non-empty entityId.");
    }
    if (typeof config.assertionConsumerServiceUrl !== "string") {
      throw new SAMLConfigError("ServiceProvider requires an assertionConsumerServiceUrl.");
    }
    assertHttpUrl(config.assertionConsumerServiceUrl, "assertionConsumerServiceUrl");
    if (!config.idp) {
      throw new SAMLConfigError(
        "ServiceProvider requires an idp — construct one with IdentityProvider.fromMetadata() " +
          "or pass { entityId, ssoUrl, certificates } directly."
      );
    }

    this.entityId = config.entityId.trim();
    this.assertionConsumerServiceUrl = config.assertionConsumerServiceUrl;
    this.idp =
      config.idp instanceof IdentityProvider ? config.idp : new IdentityProvider(config.idp);

    if (config.privateKey !== undefined) {
      try {
        createPrivateKey(config.privateKey);
      } catch (err) {
        throw new SAMLConfigError("privateKey is not a parseable PEM private key.", {
          cause: err,
        });
      }
      this.privateKey = config.privateKey;
    }
    if (config.certificate !== undefined) {
      this.certificate = validateCertificate(config.certificate, "SP certificate");
    }
    if (config.singleLogoutServiceUrl !== undefined) {
      assertHttpUrl(config.singleLogoutServiceUrl, "singleLogoutServiceUrl");
      this.singleLogoutServiceUrl = config.singleLogoutServiceUrl;
    }

    this.clockSkewMs = config.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
    if (!Number.isFinite(this.clockSkewMs) || this.clockSkewMs < 0) {
      throw new SAMLConfigError("clockSkewMs must be a non-negative number of milliseconds.");
    }
    this.maxResponseSize = config.maxResponseSize ?? DEFAULT_MAX_RESPONSE_SIZE;
    if (!Number.isFinite(this.maxResponseSize) || this.maxResponseSize <= 0) {
      throw new SAMLConfigError("maxResponseSize must be a positive number of bytes.");
    }

    this.requireSignedAssertions = config.requireSignedAssertions ?? true;
    this.requireSignedResponse = config.requireSignedResponse ?? false;
    this.allowUnsolicited = config.allowUnsolicited ?? false;
    this.allowSha1 = config.allowSha1 ?? false;
    this.signAuthnRequests = config.signAuthnRequests ?? false;
    if (this.signAuthnRequests && !this.privateKey) {
      throw new SAMLConfigError("signAuthnRequests: true requires a privateKey.");
    }
    this.signLogoutMessages = config.signLogoutMessages ?? true;
    this.requireSignedLogout = config.requireSignedLogout ?? true;
    this.nameIdFormat = config.nameIdFormat ?? DEFAULT_NAME_ID_FORMAT;
    this.requestStore = config.requestStore ?? new InMemoryRequestStore();
    this.replayCache = config.replayCache ?? new InMemoryReplayCache();
  }

  /**
   * Create a login (AuthnRequest) for the configured IdP.
   * The request ID is stored automatically so the response's `InResponseTo` can be validated.
   */
  async createLoginRequest(options: LoginRequestOptions = {}): Promise<LoginRequest> {
    const binding = options.binding ?? (this.idp.ssoUrl ? "redirect" : "post");
    const destination = binding === "redirect" ? this.idp.ssoUrl : this.idp.ssoPostUrl;
    if (!destination) {
      throw new SAMLConfigError(
        `The IdP has no SSO endpoint for the "${binding}" binding. ` +
          `Available: ${[this.idp.ssoUrl && "redirect", this.idp.ssoPostUrl && "post"]
            .filter(Boolean)
            .join(", ")}.`
      );
    }

    const id = generateId();
    let xml = buildAuthnRequestXml({
      id,
      destination,
      assertionConsumerServiceUrl: this.assertionConsumerServiceUrl,
      issuer: this.entityId,
      nameIdFormat: this.nameIdFormat,
      forceAuthn: options.forceAuthn,
      isPassive: options.isPassive,
    });

    await this.requestStore.store(id);

    if (binding === "post") {
      if (this.signAuthnRequests && this.privateKey) {
        xml = signAuthnRequestXml(xml, id, this.privateKey);
      }
      const post = buildPostBinding({
        ssoPostUrl: destination,
        requestXml: xml,
        relayState: options.relayState,
      });
      return {
        id,
        binding,
        url: post.url,
        fields: post.fields,
        html: post.html,
        xml,
        relayState: options.relayState,
      };
    }

    const url = buildRedirectUrl({
      destination,
      message: xml,
      type: "SAMLRequest",
      relayState: options.relayState,
      privateKey: this.signAuthnRequests ? this.privateKey : undefined,
    });
    return { id, binding, url, xml, relayState: options.relayState };
  }

  /**
   * Create an SP-initiated Single Logout request (HTTP-Redirect binding).
   * Redirect the user's browser to the returned `url`. The request ID is stored so
   * the IdP's LogoutResponse can be correlated via `InResponseTo`.
   *
   * Pass the values you captured at login time:
   *
   * ```ts
   * const { url } = await sp.createLogoutRequest({
   *   nameId: profile.nameId,
   *   nameIdFormat: profile.nameIdFormat ?? undefined,
   *   sessionIndex: profile.sessionIndex ?? undefined,
   * });
   * res.redirect(url);
   * ```
   */
  async createLogoutRequest(options: LogoutRequestOptions): Promise<LogoutRequest> {
    const destination = this.idp.sloUrl;
    if (!destination) {
      throw new SAMLConfigError(
        "The IdP has no SingleLogoutService endpoint for the HTTP-Redirect binding, " +
          "so Single Logout is not available. Check your IdP metadata."
      );
    }
    if (!options || typeof options.nameId !== "string" || options.nameId === "") {
      throw new SAMLConfigError(
        "createLogoutRequest requires the user's nameId (use profile.nameId from login)."
      );
    }

    const id = generateId();
    const xml = buildLogoutRequestXml({
      id,
      destination,
      issuer: this.entityId,
      nameId: options.nameId,
      nameIdFormat: options.nameIdFormat,
      sessionIndex: options.sessionIndex,
    });

    await this.requestStore.store(id);

    const url = buildRedirectUrl({
      destination,
      message: xml,
      type: "SAMLRequest",
      relayState: options.relayState,
      privateKey: this.shouldSignLogout() ? this.privateKey : undefined,
    });
    return { id, binding: "redirect", url, xml, relayState: options.relayState };
  }

  /**
   * Handle an inbound Single Logout message at your SLO endpoint (HTTP-Redirect binding).
   *
   * The same endpoint receives both directions, so the result is discriminated:
   * - `{ type: "response" }` — the IdP acknowledged the logout you initiated. The
   *   session is already gone on the IdP side; clear anything local and finish.
   * - `{ type: "request" }` — the IdP is logging the user out. Clear the local
   *   session for `nameId`, then redirect the browser to `responseUrl` to
   *   acknowledge back to the IdP.
   *
   * `input` is a Node `IncomingMessage` (a GET request) or the raw query string.
   */
  async receiveLogout(input: LogoutInput): Promise<LogoutResult> {
    const rawQuery = this.extractQuery(input);
    const parsed = parseRedirectQuery(rawQuery, this.maxResponseSize);

    if (this.requireSignedLogout || parsed.signature !== undefined) {
      verifyRedirectSignature(parsed, this.idp.certificates, this.allowSha1);
    }

    if (parsed.type === "SAMLResponse") {
      const message = parseLogoutResponse(parsed.message);
      this.assertLogoutIssuer(message.issuer);
      this.assertLogoutDestination(message.destination);

      if (message.inResponseTo) {
        const known = await this.requestStore.consume(message.inResponseTo);
        if (!known) {
          throw new InResponseToError(
            `LogoutResponse InResponseTo "${message.inResponseTo}" does not match any ` +
              "outstanding LogoutRequest (expired, already used, or issued by another process)."
          );
        }
      }
      if (message.statusCode !== STATUS_SUCCESS) {
        throw new ResponseStatusError(
          message.statusCode ?? "<missing>",
          message.subStatusCode,
          message.statusMessage
        );
      }
      return {
        type: "response",
        success: true,
        issuer: message.issuer,
        inResponseTo: message.inResponseTo,
        ...(parsed.relayState !== undefined ? { relayState: parsed.relayState } : {}),
      };
    }

    const message = parseLogoutRequest(parsed.message);
    this.assertLogoutIssuer(message.issuer);
    this.assertLogoutDestination(message.destination);

    const responseUrl = this.buildLogoutResponseUrl(message.id, parsed.relayState);
    return {
      type: "request",
      nameId: message.nameId,
      sessionIndex: message.sessionIndex,
      issuer: message.issuer,
      responseUrl,
      ...(parsed.relayState !== undefined ? { relayState: parsed.relayState } : {}),
    };
  }

  /**
   * Validate a SAML response and extract the authenticated profile.
   *
   * Accepts either a Node `IncomingMessage` (the raw ACS POST request — the body is
   * read with a size cap) or a pre-parsed body object `{ SAMLResponse, RelayState }`
   * (e.g. `req.body` from Express with urlencoded parsing enabled).
   *
   * Throws a subclass of `SAMLValidationError` when any check fails.
   */
  async consume(input: ConsumeInput): Promise<ConsumeResult> {
    let body: SAMLResponseBody;
    if (isIncomingMessage(input)) {
      body = await this.readBody(input);
    } else if (input && typeof input.SAMLResponse === "string") {
      body = input;
    } else {
      throw new SAMLParseError(
        "consume() expects an IncomingMessage or an object with a SAMLResponse field. " +
          "Did the IdP POST to the right endpoint, and is body parsing configured?"
      );
    }

    const xml = this.decodeSamlResponse(body.SAMLResponse);
    const profile = await this.validate(xml);
    return body.RelayState !== undefined && body.RelayState !== ""
      ? { profile, relayState: body.RelayState }
      : { profile };
  }

  /** Like `consume()`, but takes the already base64-decoded response XML. */
  async consumeXml(xml: string): Promise<ConsumeResult> {
    if (typeof xml !== "string" || xml.trim() === "") {
      throw new SAMLParseError("consumeXml() expects a non-empty XML string.");
    }
    this.assertSize(Buffer.byteLength(xml, "utf8"));
    const profile = await this.validate(xml);
    return { profile };
  }

  /** SP metadata XML to register with your IdP. */
  metadata(options: { validUntil?: Date } = {}): string {
    return buildMetadataXml({
      entityId: this.entityId,
      assertionConsumerServiceUrl: this.assertionConsumerServiceUrl,
      singleLogoutServiceUrl: this.singleLogoutServiceUrl,
      certificate: this.certificate,
      signAuthnRequests: this.signAuthnRequests,
      requireSignedAssertions: this.requireSignedAssertions,
      nameIdFormat: this.nameIdFormat,
      validUntil: options.validUntil,
    });
  }

  /**
   * Generate an RSA keypair with a self-signed certificate.
   * Generate once, store the PEMs securely, and reuse them — regenerating on every
   * boot breaks the trust relationship registered with your IdP.
   */
  static generateKeyPair(options: GenerateKeyPairOptions = {}): KeyPair {
    const result = selfsigned.generate(
      [{ name: "commonName", value: options.commonName ?? "saml-sp" }],
      {
        keySize: options.keySize ?? 2048,
        days: options.days ?? 3650,
        algorithm: "sha256",
      }
    );
    return { privateKey: result.private, certificate: result.cert };
  }

  private validate(xml: string): ReturnType<typeof validateResponse> {
    return validateResponse(xml, {
      spEntityId: this.entityId,
      assertionConsumerServiceUrl: this.assertionConsumerServiceUrl,
      idpEntityId: this.idp.entityId,
      certificates: this.idp.certificates,
      privateKey: this.privateKey,
      clockSkewMs: this.clockSkewMs,
      requireSignedAssertions: this.requireSignedAssertions,
      requireSignedResponse: this.requireSignedResponse,
      allowUnsolicited: this.allowUnsolicited,
      allowSha1: this.allowSha1,
      requestStore: this.requestStore,
      replayCache: this.replayCache,
    });
  }

  private shouldSignLogout(): boolean {
    return this.signLogoutMessages && this.privateKey !== undefined;
  }

  private assertLogoutIssuer(issuer: string | null): void {
    if (issuer !== this.idp.entityId) {
      throw new IssuerMismatchError(this.idp.entityId, issuer);
    }
  }

  private assertLogoutDestination(destination: string | null): void {
    if (destination && this.singleLogoutServiceUrl && destination !== this.singleLogoutServiceUrl) {
      throw new DestinationMismatchError(this.singleLogoutServiceUrl, destination);
    }
  }

  private buildLogoutResponseUrl(inResponseTo: string, relayState?: string): string {
    const destination = this.idp.sloUrl;
    if (!destination) {
      throw new SAMLConfigError(
        "Cannot acknowledge the IdP logout: the IdP has no SingleLogoutService (HTTP-Redirect) endpoint."
      );
    }
    const xml = buildLogoutResponseXml({
      id: generateId(),
      destination,
      issuer: this.entityId,
      inResponseTo,
    });
    return buildRedirectUrl({
      destination,
      message: xml,
      type: "SAMLResponse",
      relayState,
      privateKey: this.shouldSignLogout() ? this.privateKey : undefined,
    });
  }

  private extractQuery(input: LogoutInput): string {
    if (typeof input === "string") return input;
    if (isIncomingMessage(input)) {
      const url = input.url ?? "";
      const queryIndex = url.indexOf("?");
      return queryIndex === -1 ? "" : url.slice(queryIndex + 1);
    }
    throw new SAMLParseError(
      "receiveLogout() expects an IncomingMessage (GET) or a raw query string."
    );
  }

  private decodeSamlResponse(samlResponse: string): string {
    if (typeof samlResponse !== "string" || samlResponse.trim() === "") {
      throw new SAMLParseError("Request body has no SAMLResponse parameter.");
    }
    this.assertSize(samlResponse.length);
    const normalized = samlResponse.replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) {
      throw new SAMLParseError("SAMLResponse is not valid base64.");
    }
    const xml = Buffer.from(normalized, "base64").toString("utf8");
    if (!xml.trimStart().startsWith("<")) {
      throw new SAMLParseError("Decoded SAMLResponse is not XML.");
    }
    return xml;
  }

  private assertSize(bytes: number): void {
    if (bytes > this.maxResponseSize) {
      throw new SAMLParseError(
        `SAML response exceeds the maximum accepted size of ${this.maxResponseSize} bytes. ` +
          "Increase maxResponseSize only if your IdP legitimately sends larger responses."
      );
    }
  }

  private readBody(req: IncomingMessage): Promise<SAMLResponseBody> {
    return new Promise((resolve, reject) => {
      if (req.method !== "POST") {
        reject(
          new SAMLParseError(
            `SAML responses must arrive via HTTP POST, got ${req.method ?? "<unknown>"}. ` +
              "Point the IdP's ACS configuration at this endpoint with the HTTP-POST binding."
          )
        );
        return;
      }

      const chunks: Buffer[] = [];
      let received = 0;
      let done = false;

      const fail = (err: Error): void => {
        if (done) return;
        done = true;
        reject(err);
      };

      req.on("data", (chunk: Buffer | string) => {
        const buf = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
        received += buf.length;
        if (received > this.maxResponseSize) {
          fail(
            new SAMLParseError(
              `Request body exceeds the maximum accepted size of ${this.maxResponseSize} bytes.`
            )
          );
          req.destroy();
          return;
        }
        chunks.push(buf);
      });
      req.on("error", fail);
      req.on("end", () => {
        if (done) return;
        done = true;
        const params = new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
        const samlResponse = params.get("SAMLResponse");
        if (!samlResponse) {
          reject(
            new SAMLParseError(
              "POST body has no SAMLResponse parameter. Expected an " +
                "application/x-www-form-urlencoded body from the IdP."
            )
          );
          return;
        }
        const relayState = params.get("RelayState");
        resolve(
          relayState === null
            ? { SAMLResponse: samlResponse }
            : { SAMLResponse: samlResponse, RelayState: relayState }
        );
      });
    });
  }
}

function isIncomingMessage(input: unknown): input is IncomingMessage {
  return (
    typeof input === "object" &&
    input !== null &&
    typeof (input as IncomingMessage).on === "function"
  );
}
