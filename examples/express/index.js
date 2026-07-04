/**
 * Minimal saml-sp + Express integration.
 *
 * Setup:
 *   1. node generate-keys.js               (once — writes sp-key.pem / sp-cert.pem)
 *   2. Download your IdP metadata XML to ./idp-metadata.xml
 *   3. BASE_URL=https://my-app.example.com node index.js
 *
 * Register http(s)://<BASE_URL>/saml/metadata with your IdP.
 */
const express = require("express");
const fs = require("node:fs");
const { ServiceProvider, IdentityProvider, SAMLValidationError } = require("saml-sp");

const BASE_URL = process.env.BASE_URL ?? "http://localhost:3000";

const sp = new ServiceProvider({
  entityId: process.env.SP_ENTITY_ID ?? "urn:example:saml-sp-demo",
  assertionConsumerServiceUrl: `${BASE_URL}/saml/acs`,
  idp: IdentityProvider.fromMetadata(fs.readFileSync("./idp-metadata.xml", "utf8")),
  privateKey: fs.readFileSync("./sp-key.pem", "utf8"),
  certificate: fs.readFileSync("./sp-cert.pem", "utf8"),
});

const app = express();

app.get("/", (_req, res) => {
  res.send('<a href="/login">Sign in with SSO</a>');
});

app.get("/saml/metadata", (_req, res) => {
  res.type("application/xml").send(sp.metadata());
});

app.get("/login", async (_req, res, next) => {
  try {
    const { url } = await sp.createLoginRequest({ relayState: "/welcome" });
    res.redirect(url);
  } catch (err) {
    next(err);
  }
});

app.post("/saml/acs", async (req, res) => {
  try {
    const { profile } = await sp.consume(req);
    // Demo only: render the profile. In a real app, create YOUR session here.
    res.send(
      `<h1>Welcome, ${escapeHtml(profile.nameId ?? "unknown user")}</h1>` +
        `<pre>${escapeHtml(JSON.stringify(profile.attributes, null, 2))}</pre>`
    );
  } catch (err) {
    if (err instanceof SAMLValidationError) {
      console.warn("SAML validation failed:", err.code, err.message);
      return res.status(401).send("Login failed — see server logs.");
    }
    console.error(err);
    res.status(500).send("Unexpected error.");
  }
});

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

app.listen(3000, () => {
  console.log(`SP running: ${BASE_URL}`);
  console.log(`Metadata:   ${BASE_URL}/saml/metadata`);
});
