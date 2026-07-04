import type { Document, Element, Node } from "@xmldom/xmldom";
import { DOMParser, XMLSerializer, onErrorStopParsing } from "@xmldom/xmldom";
import { SAMLParseError } from "../errors";

/** XML namespaces used throughout SAML 2.0. */
export const NS = {
  SAMLP: "urn:oasis:names:tc:SAML:2.0:protocol",
  SAML: "urn:oasis:names:tc:SAML:2.0:assertion",
  MD: "urn:oasis:names:tc:SAML:2.0:metadata",
  DS: "http://www.w3.org/2000/09/xmldsig#",
  XENC: "http://www.w3.org/2001/04/xmlenc#",
} as const;

const ELEMENT_NODE = 1;

/**
 * Parse XML with a hardened configuration:
 * - documents containing a DOCTYPE are rejected outright (entity-expansion attacks),
 * - any parser-level error aborts parsing instead of producing a partial tree.
 */
export function parseXml(xml: string, what = "XML document"): Document {
  if (/<!DOCTYPE/i.test(xml)) {
    throw new SAMLParseError(
      `Refusing to parse ${what}: DOCTYPE declarations are not allowed in SAML messages.`
    );
  }

  let doc: Document;
  try {
    doc = new DOMParser({ onError: onErrorStopParsing }).parseFromString(xml, "text/xml");
  } catch (err) {
    throw new SAMLParseError(`Failed to parse ${what}: not well-formed XML.`, { cause: err });
  }

  /* istanbul ignore if -- xmldom reports rootless documents as fatal parse errors,
     which are caught above; this guard survives as defence in depth. */
  if (!doc.documentElement) {
    throw new SAMLParseError(`Failed to parse ${what}: document has no root element.`);
  }
  return doc;
}

/** Serialize a DOM node back to an XML string (with namespace fixup). */
export function serialize(node: Node): string {
  return new XMLSerializer().serializeToString(node);
}

/** True if `node` is an element with the given namespace URI and local name. */
export function isElement(node: Node | null, namespaceURI: string, localName: string): boolean {
  return (
    node !== null &&
    node.nodeType === ELEMENT_NODE &&
    node.namespaceURI === namespaceURI &&
    node.localName === localName
  );
}

/** All direct element children of `parent` matching namespace + local name. */
export function childElements(parent: Element, namespaceURI: string, localName: string): Element[] {
  const result: Element[] = [];
  for (let i = 0; i < parent.childNodes.length; i++) {
    const child = parent.childNodes.item(i);
    if (child && isElement(child, namespaceURI, localName)) {
      result.push(child as Element);
    }
  }
  return result;
}

/** First direct element child of `parent` matching namespace + local name, or null. */
export function firstChild(
  parent: Element,
  namespaceURI: string,
  localName: string
): Element | null {
  return childElements(parent, namespaceURI, localName)[0] ?? null;
}

/**
 * Trimmed text content of an element, or null if empty/absent.
 *
 * `textContent` concatenates *all* descendant text nodes, so a NameID like
 * `user@example.com<!--x-->.evil.com` yields the full string rather than the
 * truncated prefix — the classic comment-injection bypass does not apply.
 */
export function textOf(el: Element | null): string | null {
  const text = el?.textContent?.trim();
  return text ? text : null;
}

/** Non-empty attribute value, or null. */
export function attrOf(el: Element, name: string): string | null {
  const value = el.getAttribute(name);
  return value ? value : null;
}

/** Parse an ISO timestamp attribute; throws SAMLParseError on garbage. */
export function dateAttr(el: Element, name: string, what: string): Date | null {
  const raw = attrOf(el, name);
  if (raw === null) return null;
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) {
    throw new SAMLParseError(`Invalid ${name} timestamp on ${what}: "${raw}".`);
  }
  return date;
}
