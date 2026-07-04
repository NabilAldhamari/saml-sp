# saml-sp Express example

```bash
npm install
node generate-keys.js                 # once
# download your IdP metadata to ./idp-metadata.xml
node index.js
```

Then register `http://localhost:3000/saml/metadata` (or its XML output) with
your IdP and click "Sign in with SSO" at `http://localhost:3000`.

For a real deployment set `BASE_URL` (your public https origin) and
`SP_ENTITY_ID`, and terminate TLS in front of the app — IdPs will refuse to
POST assertions to plain-http ACS URLs outside local testing.
