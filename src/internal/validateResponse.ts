import type { Element } from "@xmldom/xmldom";
import {
  AssertionTimeError,
  AudienceMismatchError,
  DestinationMismatchError,
  InResponseToError,
  IssuerMismatchError,
  ReplayError,
  ResponseStatusError,
  SAMLConfigError,
  SAMLParseError,
  SignatureError,
} from "../errors";
import type { ReplayCache, RequestStore, SAMLProfile } from "../types";
import { decryptAssertion } from "./decrypt";
import {
  NS,
  attrOf,
  childElements,
  dateAttr,
  firstChild,
  isElement,
  parseXml,
  serialize,
  textOf,
} from "./parse";
import { findDirectChildSignature, verifyEnvelopedSignature } from "./signature";

const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
const BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
const DEFAULT_REPLAY_TTL_MS = 60 * 60_000;

export interface ValidationContext {
  spEntityId: string;
  assertionConsumerServiceUrl: string;
  idpEntityId: string;
  certificates: readonly string[];
  privateKey?: string;
  clockSkewMs: number;
  requireSignedAssertions: boolean;
  requireSignedResponse: boolean;
  allowUnsolicited: boolean;
  allowSha1: boolean;
  requestStore: RequestStore;
  replayCache: ReplayCache;
}

/**
 * The full response validation pipeline. Order matters:
 * structure → status → addressing → signatures → decryption → semantics → replay.
 * Returns the extracted profile only if every check passes.
 */
export async function validateResponse(
  rawXml: string,
  ctx: ValidationContext
): Promise<SAMLProfile> {
  const doc = parseXml(rawXml, "SAML response");
  // parseXml guarantees a root element
  const response = doc.documentElement as Element;
  if (!isElement(response, NS.SAMLP, "Response")) {
    throw new SAMLParseError(
      `Expected a samlp:Response root element, got <${response.localName}>.`
    );
  }
  if (attrOf(response, "Version") !== "2.0") {
    throw new SAMLParseError('SAML response Version must be "2.0".');
  }

  checkStatus(response);

  const destination = attrOf(response, "Destination");
  if (destination && destination !== ctx.assertionConsumerServiceUrl) {
    throw new DestinationMismatchError(ctx.assertionConsumerServiceUrl, destination);
  }

  const responseIssuer = textOf(firstChild(response, NS.SAML, "Issuer"));
  if (responseIssuer && responseIssuer !== ctx.idpEntityId) {
    throw new IssuerMismatchError(ctx.idpEntityId, responseIssuer);
  }

  // --- Response-level signature -------------------------------------------------
  const responseSignature = findDirectChildSignature(response);
  let trustedResponse: Element | null = null;
  if (responseSignature) {
    const { signedContent } = verifyEnvelopedSignature(
      rawXml,
      response,
      responseSignature,
      ctx.certificates,
      ctx.allowSha1
    );
    const trustedRoot = parseXml(signedContent, "signed response content")
      .documentElement as Element;
    if (!isElement(trustedRoot, NS.SAMLP, "Response")) {
      throw new SignatureError("Response signature does not cover a samlp:Response element.");
    }
    trustedResponse = trustedRoot;
  } else if (ctx.requireSignedResponse) {
    throw new SignatureError(
      "The SAML response is not signed but requireSignedResponse is enabled.",
      "SAML_SIGNATURE_MISSING"
    );
  }
  const responseSigned = trustedResponse !== null;

  // --- Locate exactly one assertion (from verified content when available) -------
  const source = trustedResponse ?? response;
  const encryptedAssertions = childElements(source, NS.SAML, "EncryptedAssertion");
  const plainAssertions = childElements(source, NS.SAML, "Assertion");
  const total = encryptedAssertions.length + plainAssertions.length;
  if (total === 0) {
    throw new SAMLParseError("SAML response contains no Assertion or EncryptedAssertion.");
  }
  if (total > 1) {
    throw new SAMLParseError(
      `SAML response contains ${total} assertions; refusing to process an ambiguous response.`
    );
  }

  let assertion: Element;
  /** XML string that contains `assertion` — used to verify its signature. */
  let assertionContainerXml: string;
  let assertionCovered = responseSigned;

  const encryptedAssertion = encryptedAssertions[0];
  if (encryptedAssertion) {
    if (!ctx.privateKey) {
      throw new SAMLConfigError(
        "Received an EncryptedAssertion but no privateKey is configured on the ServiceProvider."
      );
    }
    const decrypted = await decryptAssertion(serialize(encryptedAssertion), ctx.privateKey);
    const decryptedRoot = parseXml(decrypted, "decrypted assertion").documentElement as Element;
    if (!isElement(decryptedRoot, NS.SAML, "Assertion")) {
      throw new SAMLParseError("Decrypted content is not a saml:Assertion element.");
    }
    assertion = decryptedRoot;
    assertionContainerXml = decrypted;
  } else {
    assertion = plainAssertions[0] as Element;
    assertionContainerXml = responseSigned ? serialize(trustedResponse as Element) : rawXml;
  }

  // --- Assertion-level signature --------------------------------------------------
  const assertionSignature = findDirectChildSignature(assertion);
  if (assertionSignature) {
    const { signedContent } = verifyEnvelopedSignature(
      assertionContainerXml,
      assertion,
      assertionSignature,
      ctx.certificates,
      ctx.allowSha1
    );
    const trustedAssertion = parseXml(signedContent, "signed assertion content")
      .documentElement as Element;
    if (!isElement(trustedAssertion, NS.SAML, "Assertion")) {
      throw new SignatureError("Assertion signature does not cover a saml:Assertion element.");
    }
    assertion = trustedAssertion;
    assertionCovered = true;
  }

  if (ctx.requireSignedAssertions && !assertionCovered) {
    throw new SignatureError(
      "Neither the SAML response nor its assertion carries a valid signature. " +
        "saml-sp requires signed assertions by default; if you are testing against a mock IdP " +
        "you can temporarily set requireSignedAssertions: false — never do this in production.",
      "SAML_SIGNATURE_MISSING"
    );
  }

  // --- Semantic checks (on verified content only, when signatures are present) ----
  if (attrOf(assertion, "Version") !== "2.0") {
    throw new SAMLParseError('Assertion Version must be "2.0".');
  }
  const assertionId = attrOf(assertion, "ID");
  if (!assertionId) {
    throw new SAMLParseError("Assertion has no ID attribute.");
  }

  const issuer = textOf(firstChild(assertion, NS.SAML, "Issuer"));
  if (issuer !== ctx.idpEntityId) {
    throw new IssuerMismatchError(ctx.idpEntityId, issuer);
  }

  const now = Date.now();
  let notBefore: Date | null = null;
  let notOnOrAfter: Date | null = null;

  const conditions = firstChild(assertion, NS.SAML, "Conditions");
  if (conditions) {
    notBefore = dateAttr(conditions, "NotBefore", "Conditions");
    notOnOrAfter = dateAttr(conditions, "NotOnOrAfter", "Conditions");
    if (notBefore && now + ctx.clockSkewMs < notBefore.getTime()) {
      throw new AssertionTimeError("not-yet-valid", notBefore);
    }
    if (notOnOrAfter && now - ctx.clockSkewMs >= notOnOrAfter.getTime()) {
      throw new AssertionTimeError("expired", notOnOrAfter);
    }

    const restrictions = childElements(conditions, NS.SAML, "AudienceRestriction");
    if (restrictions.length > 0) {
      const audiences: string[] = [];
      for (const restriction of restrictions) {
        for (const audience of childElements(restriction, NS.SAML, "Audience")) {
          const value = textOf(audience);
          if (value) audiences.push(value);
        }
      }
      if (!audiences.includes(ctx.spEntityId)) {
        throw new AudienceMismatchError(ctx.spEntityId, audiences);
      }
    }
  }

  // --- Subject / bearer confirmation ----------------------------------------------
  const subject = firstChild(assertion, NS.SAML, "Subject");
  const nameIdEl = subject ? firstChild(subject, NS.SAML, "NameID") : null;

  let subjectConfirmationInResponseTo: string | null = null;
  if (subject) {
    for (const confirmation of childElements(subject, NS.SAML, "SubjectConfirmation")) {
      if (attrOf(confirmation, "Method") !== BEARER) continue;
      const data = firstChild(confirmation, NS.SAML, "SubjectConfirmationData");
      if (!data) continue;

      const recipient = attrOf(data, "Recipient");
      if (recipient && recipient !== ctx.assertionConsumerServiceUrl) {
        throw new DestinationMismatchError(ctx.assertionConsumerServiceUrl, recipient);
      }
      const scNotOnOrAfter = dateAttr(data, "NotOnOrAfter", "SubjectConfirmationData");
      if (scNotOnOrAfter && now - ctx.clockSkewMs >= scNotOnOrAfter.getTime()) {
        throw new AssertionTimeError("expired", scNotOnOrAfter);
      }
      const scNotBefore = dateAttr(data, "NotBefore", "SubjectConfirmationData");
      if (scNotBefore && now + ctx.clockSkewMs < scNotBefore.getTime()) {
        throw new AssertionTimeError("not-yet-valid", scNotBefore);
      }
      subjectConfirmationInResponseTo = attrOf(data, "InResponseTo");
      if (!notOnOrAfter && scNotOnOrAfter) notOnOrAfter = scNotOnOrAfter;
      break;
    }
  }

  // --- InResponseTo (solicited vs unsolicited) -------------------------------------
  const responseInResponseTo = attrOf(response, "InResponseTo");
  if (
    responseInResponseTo &&
    subjectConfirmationInResponseTo &&
    responseInResponseTo !== subjectConfirmationInResponseTo
  ) {
    throw new InResponseToError(
      "InResponseTo mismatch between the Response element and its SubjectConfirmationData."
    );
  }
  const inResponseTo = subjectConfirmationInResponseTo ?? responseInResponseTo;
  if (inResponseTo) {
    const known = await ctx.requestStore.consume(inResponseTo);
    if (!known) {
      throw new InResponseToError(
        `InResponseTo "${inResponseTo}" does not match any outstanding AuthnRequest. ` +
          "The request may have expired (default TTL 10 minutes), already been used, or been " +
          "issued by another process — use a shared requestStore when running multiple instances."
      );
    }
  } else if (!ctx.allowUnsolicited) {
    throw new InResponseToError(
      "Unsolicited SAML response (no InResponseTo). If you intend to support IdP-initiated " +
        "SSO, set allowUnsolicited: true."
    );
  }

  // --- Replay protection ------------------------------------------------------------
  const replayExpiry = notOnOrAfter ?? new Date(now + DEFAULT_REPLAY_TTL_MS);
  const fresh = await ctx.replayCache.register(
    assertionId,
    new Date(replayExpiry.getTime() + ctx.clockSkewMs)
  );
  if (!fresh) {
    throw new ReplayError(assertionId);
  }

  // --- Profile extraction -------------------------------------------------------------
  const authnStatement = firstChild(assertion, NS.SAML, "AuthnStatement");
  const authnContext = authnStatement && firstChild(authnStatement, NS.SAML, "AuthnContext");

  const attributes: Record<string, string[]> = {};
  const attributeStatement = firstChild(assertion, NS.SAML, "AttributeStatement");
  if (attributeStatement) {
    for (const attribute of childElements(attributeStatement, NS.SAML, "Attribute")) {
      const name = attrOf(attribute, "Name");
      if (!name) continue;
      const values: string[] = [];
      for (const valueEl of childElements(attribute, NS.SAML, "AttributeValue")) {
        const value = valueEl.textContent?.trim();
        if (value) values.push(value);
      }
      attributes[name] = values;
    }
  }

  return {
    nameId: textOf(nameIdEl),
    nameIdFormat: nameIdEl ? attrOf(nameIdEl, "Format") : null,
    sessionIndex: authnStatement ? attrOf(authnStatement, "SessionIndex") : null,
    attributes,
    issuer: ctx.idpEntityId,
    authnContextClassRef: authnContext
      ? textOf(firstChild(authnContext, NS.SAML, "AuthnContextClassRef"))
      : null,
    notBefore,
    notOnOrAfter,
    inResponseTo: inResponseTo ?? null,
    assertionXml: serialize(assertion),
  };
}

function checkStatus(response: Element): void {
  const status = firstChild(response, NS.SAMLP, "Status");
  if (!status) {
    throw new SAMLParseError("SAML response has no samlp:Status element.");
  }
  const statusCode = firstChild(status, NS.SAMLP, "StatusCode");
  if (!statusCode) {
    throw new SAMLParseError("SAML response Status has no StatusCode element.");
  }
  const value = attrOf(statusCode, "Value");
  if (!value) {
    throw new SAMLParseError("SAML response StatusCode has no Value attribute.");
  }
  if (value !== STATUS_SUCCESS) {
    const nested = firstChild(statusCode, NS.SAMLP, "StatusCode");
    const subStatus = nested ? attrOf(nested, "Value") : null;
    const message = textOf(firstChild(status, NS.SAMLP, "StatusMessage"));
    throw new ResponseStatusError(value, subStatus, message);
  }
}
