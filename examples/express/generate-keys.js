/** One-time SP keypair generation. Keep sp-key.pem secret; never commit it. */
const fs = require("node:fs");
const { ServiceProvider } = require("saml-sp");

const keys = ServiceProvider.generateKeyPair({ commonName: "saml-sp-demo" });
fs.writeFileSync("sp-key.pem", keys.privateKey);
fs.writeFileSync("sp-cert.pem", keys.certificate);
console.log("Wrote sp-key.pem and sp-cert.pem — reuse these; do not regenerate per boot.");
