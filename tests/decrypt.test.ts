/**
 * Unit tests for the xml-encryption wrapper. The library is mocked here so the
 * hard-to-reach callback branches are covered; the real encryption round-trip is
 * exercised in validateResponse.test.ts and e2e.test.ts.
 */
jest.mock("xml-encryption", () => ({ decrypt: jest.fn() }));

import * as xmlenc from "xml-encryption";
import { DecryptionError } from "../src";
import { decryptAssertion } from "../src/internal/decrypt";

const decryptMock = xmlenc.decrypt as unknown as jest.Mock;

describe("decryptAssertion", () => {
  beforeEach(() => decryptMock.mockReset());

  it("resolves with the decrypted XML", async () => {
    decryptMock.mockImplementation((_xml, _opts, cb: (e: Error | null, r?: string) => void) =>
      cb(null, "<saml:Assertion/>")
    );
    await expect(decryptAssertion("<enc/>", "key")).resolves.toBe("<saml:Assertion/>");
  });

  const encrypted = (alg: string): string =>
    `<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">` +
    `<xenc:EncryptionMethod Algorithm="${alg}"/></xenc:EncryptedData>`;

  it.each([
    "http://www.w3.org/2001/04/xmlenc#rsa-1_5",
    "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
  ])("refuses %s before calling the library", async (alg) => {
    const err = await decryptAssertion(encrypted(alg), "key").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DecryptionError);
    expect((err as Error).message).toMatch(/insecure encryption algorithm/);
    expect(decryptMock).not.toHaveBeenCalled();
  });

  it("allows AES-CBC (still the default of many IdPs)", async () => {
    decryptMock.mockImplementation((_xml, _opts, cb: (e: Error | null, r?: string) => void) =>
      cb(null, "<a/>")
    );
    await expect(
      decryptAssertion(encrypted("http://www.w3.org/2001/04/xmlenc#aes256-cbc"), "key")
    ).resolves.toBe("<a/>");
    expect(decryptMock).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({ key: "key", disallowDecryptionWithInsecureAlgorithm: false }),
      expect.any(Function)
    );
  });

  it("wraps decryption failures in DecryptionError with the cause attached", async () => {
    const cause = new Error("bad key");
    decryptMock.mockImplementation((_xml, _opts, cb: (e: Error | null, r?: string) => void) =>
      cb(cause)
    );
    const err = await decryptAssertion("<enc/>", "key").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(DecryptionError);
    expect((err as DecryptionError).cause).toBe(cause);
  });

  it("rejects empty decryption output", async () => {
    decryptMock.mockImplementation((_xml, _opts, cb: (e: Error | null, r?: string) => void) =>
      cb(null, "")
    );
    await expect(decryptAssertion("<enc/>", "key")).rejects.toThrow(/empty output/);
  });
});
