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

  it("disallows insecure algorithms in the options it passes down", async () => {
    decryptMock.mockImplementation((_xml, _opts, cb: (e: Error | null, r?: string) => void) =>
      cb(null, "<a/>")
    );
    await decryptAssertion("<enc/>", "key");
    expect(decryptMock).toHaveBeenCalledWith(
      "<enc/>",
      expect.objectContaining({
        key: "key",
        disallowDecryptionWithInsecureAlgorithm: true,
      }),
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
