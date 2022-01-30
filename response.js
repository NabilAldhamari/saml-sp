const SAML     = require("./saml-sp");
const express  = require('express');
let app        = express();

const IDP_URL = "https://[IDP]/sso/saml";
const SSO_URL = "http://localhost:8888/saml/consume";

let sp = SAML.ServiceProvider({
    assertionEndpoint: SSO_URL,
    encyptionKeyLength: 2048
});

app.get('/', function(req, res){
    res.redirect("/saml/consume");
});

app.get('/login', function(req, res){
    let SAMLRequest     = new SAML.Request(IDP_URL, REDIRECT_URI);
    let authNRequestURL = SAMLRequest.createAuthNURL();

    // if okta then do not use the authNRequest URL
    res.redirect(IDP_URL);

    /*
        // if authenticating against AWS SSO then
        res.redirect(authNRequestURL);
    */
});

app.post('/saml/consume', function(req, res, next){
    let SAMLResponse = new SAML.Response(req);
    SAMLResponse.decryptAssertions().then((decrypted_data) => {
        console.log(decrypted_data);
    });
});

app.get('/saml/consume', function(req,res){
    res.redirect("/login");
});

app.listen(8888);
