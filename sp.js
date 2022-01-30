const SAML     = require("./saml-sp");
const SSO_URL  = "http://localhost:8888/saml/consume";

let sp = new SAML.ServiceProvider({
    assertionEndpoint: SSO_URL
});

sp.saveRSAKeys(); // this will save the private key and certificate in the current directory
sp.createMetaData(); // this will save the metadata.xml file in the current directory