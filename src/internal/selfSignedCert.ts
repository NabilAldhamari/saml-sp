import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";

/** Minimal DER encoder, just enough for a self-signed X.509 v3 certificate. */
function der(tag: number, ...parts: Buffer[]): Buffer {
  const body = Buffer.concat(parts);
  const n = body.length;
  let len: Buffer;
  if (n < 0x80) len = Buffer.from([n]);
  else if (n < 0x100) len = Buffer.from([0x81, n]);
  else len = Buffer.from([0x82, n >> 8, n & 0xff]);
  return Buffer.concat([Buffer.from([tag]), len, body]);
}

const SEQUENCE = 0x30;
const SET = 0x31;

function oid(dotted: string): Buffer {
  const [a, b, ...rest] = dotted.split(".").map(Number) as [number, number, ...number[]];
  const bytes = [a * 40 + b];
  for (const value of rest) {
    const chunk = [value & 0x7f];
    for (let v = value >> 7; v > 0; v >>= 7) chunk.unshift((v & 0x7f) | 0x80);
    bytes.push(...chunk);
  }
  return der(0x06, Buffer.from(bytes));
}

/** DER INTEGER from big-endian unsigned bytes. */
function integer(bytes: Buffer): Buffer {
  let b = bytes;
  while (b.length > 1 && b[0] === 0 && (b[1] as number) < 0x80) b = b.subarray(1);
  return der(0x02, (b[0] as number) >= 0x80 ? Buffer.concat([Buffer.from([0]), b]) : b);
}

function time(date: Date): Buffer {
  const iso = date.toISOString().replace(/[-:T]/g, "");
  // RFC 5280: UTCTime through 2049, GeneralizedTime afterwards.
  return date.getUTCFullYear() < 2050
    ? der(0x17, Buffer.from(`${iso.slice(2, 14)}Z`, "ascii"))
    : der(0x18, Buffer.from(`${iso.slice(0, 14)}Z`, "ascii"));
}

const SHA256_WITH_RSA = der(SEQUENCE, oid("1.2.840.113549.1.1.11"), der(0x05));

/** Generate an RSA keypair plus a self-signed SHA-256 certificate using only `node:crypto`. */
export function generateSelfSigned(opts: { commonName: string; keySize: number; days: number }): {
  privateKey: string;
  certificate: string;
} {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: opts.keySize });

  const name = der(
    SEQUENCE,
    der(SET, der(SEQUENCE, oid("2.5.4.3"), der(0x0c, Buffer.from(opts.commonName, "utf8"))))
  );
  const now = Date.now();
  const serial = randomBytes(16);
  serial[0] = (serial[0] as number) & 0x7f; // keep the INTEGER positive

  const tbs = der(
    SEQUENCE,
    der(0xa0, integer(Buffer.from([2]))), // version: v3
    integer(serial),
    SHA256_WITH_RSA,
    name, // issuer
    der(SEQUENCE, time(new Date(now - 60_000)), time(new Date(now + opts.days * 86_400_000))),
    name, // subject (self-signed)
    publicKey.export({ type: "spki", format: "der" })
  );

  const signature = createSign("sha256").update(tbs).sign(privateKey);
  const cert = der(
    SEQUENCE,
    tbs,
    SHA256_WITH_RSA,
    der(0x03, Buffer.from([0]), signature) // BIT STRING, 0 unused bits
  );

  const b64 = (cert.toString("base64").match(/.{1,64}/g) as string[]).join("\n");
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    certificate: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`,
  };
}
