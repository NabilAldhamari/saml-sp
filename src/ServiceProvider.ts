import { createPrivateKey } from "node:crypto";
import type { IncomingMessage } from "node:http";
import * as selfsigned from "selfsigned";
import { SAMLConfigError, SAMLParseError } from "./errors";
import { IdentityProvider } from "./IdentityProvider";
import {
  assertHttpUrl,
  buildAuthnRequestXml,
  buildPostBinding,
  buildRedirectUrl,
  generateId,
  signAuthnRequestXml,
} from "./internal/authnRequest";
import { buildMetadataXml } from "./internal/metadata";
import { validateCertificate } from "./internal/pem";
import { InMemoryReplayCache, InMemoryRequestStore } from "./internal/stores";
import { validateResponse } from "./internal/validateResponse";
import type {
  ConsumeInput,
  ConsumeResult,
  GenerateKeyPairOptions,
  KeyPair,
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
  private readonly clockSkewMs: number;
  private readonly requireSignedAssertions: boolean;
  private readonly requireSignedResponse: boolean;
  private readonly allowUnsolicited: boolean;
  private readonly allowSha1: boolean;
  private readonly signAuthnRequests: boolean;
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
      ssoUrl: destination,
      requestXml: xml,
      relayState: options.relayState,
      privateKey: this.signAuthnRequests ? this.privateKey : undefined,
    });
    return { id, binding, url, xml, relayState: options.relayState };
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

function isIncomingMessage(input: ConsumeInput): input is IncomingMessage {
  return (
    typeof input === "object" &&
    input !== null &&
    typeof (input as IncomingMessage).on === "function"
  );
}
