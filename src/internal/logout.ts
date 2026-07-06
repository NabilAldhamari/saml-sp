import type { Element } from "@xmldom/xmldom";
import { create } from "xmlbuilder2";
import { SAMLParseError } from "../errors";
import { NS, attrOf, firstChild, isElement, parseXml, textOf } from "./parse";

export const STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

export interface LogoutRequestParams {
  id: string;
  destination: string;
  issuer: string;
  nameId: string;
  nameIdFormat?: string;
  sessionIndex?: string;
}

/** Build a `samlp:LogoutRequest` (SP-initiated logout). */
export function buildLogoutRequestXml(params: LogoutRequestParams): string {
  const nameId: Record<string, unknown> = { "#": params.nameId };
  if (params.nameIdFormat) nameId["@Format"] = params.nameIdFormat;

  // Key order matters: schema requires Issuer, then NameID, then SessionIndex.
  const request: Record<string, unknown> = {
    "@xmlns:samlp": NS.SAMLP,
    "@xmlns:saml": NS.SAML,
    "@ID": params.id,
    "@Version": "2.0",
    "@IssueInstant": new Date().toISOString(),
    "@Destination": params.destination,
    "saml:Issuer": params.issuer,
    "saml:NameID": nameId,
  };
  if (params.sessionIndex) request["samlp:SessionIndex"] = params.sessionIndex;

  return create({ "samlp:LogoutRequest": request }).end();
}

export interface LogoutResponseParams {
  id: string;
  destination: string;
  issuer: string;
  inResponseTo: string;
}

/** Build a Success `samlp:LogoutResponse` (acknowledging an IdP-initiated logout). */
export function buildLogoutResponseXml(params: LogoutResponseParams): string {
  return create({
    "samlp:LogoutResponse": {
      "@xmlns:samlp": NS.SAMLP,
      "@xmlns:saml": NS.SAML,
      "@ID": params.id,
      "@Version": "2.0",
      "@IssueInstant": new Date().toISOString(),
      "@Destination": params.destination,
      "@InResponseTo": params.inResponseTo,
      "saml:Issuer": params.issuer,
      "samlp:Status": {
        "samlp:StatusCode": { "@Value": STATUS_SUCCESS },
      },
    },
  }).end();
}

export interface ParsedLogoutRequest {
  id: string;
  issuer: string | null;
  destination: string | null;
  nameId: string | null;
  nameIdFormat: string | null;
  sessionIndex: string | null;
}

/** Parse an inbound `samlp:LogoutRequest` (IdP-initiated logout). */
export function parseLogoutRequest(xml: string): ParsedLogoutRequest {
  const root = parseXml(xml, "LogoutRequest").documentElement as Element;
  if (!isElement(root, NS.SAMLP, "LogoutRequest")) {
    throw new SAMLParseError(`Expected a samlp:LogoutRequest, got <${root.localName}>.`);
  }
  const id = attrOf(root, "ID");
  if (!id) throw new SAMLParseError("LogoutRequest has no ID attribute.");

  const nameIdEl = firstChild(root, NS.SAML, "NameID");
  return {
    id,
    issuer: textOf(firstChild(root, NS.SAML, "Issuer")),
    destination: attrOf(root, "Destination"),
    nameId: textOf(nameIdEl),
    nameIdFormat: nameIdEl ? attrOf(nameIdEl, "Format") : null,
    sessionIndex: textOf(firstChild(root, NS.SAMLP, "SessionIndex")),
  };
}

export interface ParsedLogoutResponse {
  id: string;
  issuer: string | null;
  destination: string | null;
  inResponseTo: string | null;
  statusCode: string | null;
  subStatusCode: string | null;
  statusMessage: string | null;
}

/** Parse an inbound `samlp:LogoutResponse` (answering our SP-initiated logout). */
export function parseLogoutResponse(xml: string): ParsedLogoutResponse {
  const root = parseXml(xml, "LogoutResponse").documentElement as Element;
  if (!isElement(root, NS.SAMLP, "LogoutResponse")) {
    throw new SAMLParseError(`Expected a samlp:LogoutResponse, got <${root.localName}>.`);
  }
  const id = attrOf(root, "ID");
  if (!id) throw new SAMLParseError("LogoutResponse has no ID attribute.");

  const status = firstChild(root, NS.SAMLP, "Status");
  const statusCode = status ? firstChild(status, NS.SAMLP, "StatusCode") : null;
  const nested = statusCode ? firstChild(statusCode, NS.SAMLP, "StatusCode") : null;

  return {
    id,
    issuer: textOf(firstChild(root, NS.SAML, "Issuer")),
    destination: attrOf(root, "Destination"),
    inResponseTo: attrOf(root, "InResponseTo"),
    statusCode: statusCode ? attrOf(statusCode, "Value") : null,
    subStatusCode: nested ? attrOf(nested, "Value") : null,
    statusMessage: textOf(status ? firstChild(status, NS.SAMLP, "StatusMessage") : null),
  };
}
