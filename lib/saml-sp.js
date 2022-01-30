const crypto     = require('crypto');
const selfsigned = require('selfsigned');
const fs         = require('fs');
const xmlbuilder = require('xmlbuilder2');
const xmldom     = require('xmldom');
const xmlenc     = require('xml-encryption');
const SAML       = {
    generateRandomEntityID: () => {
        return '_' + crypto.randomBytes(21).toString('hex');
    },

    ServiceProvider: class{
        constructor(options){
            if (!options.assertionEndpoint){
                throw new Error("A Service provider needs an assertion endpoint to function properly.");
            }

            this.encryptionKeylength = 1024;
            this.certificate         = options['certificate'] || null;
            this.privateKey          = options['private_key'] || null;
            this.entityID            = options['entityID']    || SAML.generateRandomEntityID();

            this.setAssertionEndpoint(options.assertionEndpoint);

            if (this.certificate == null && this.privateKey == null){
                this.privateKey, this.certificate = this.generateKeys(options['key_length']);
            }
        }

        setAssertionEndpoint(assertionEndpoint){
            if (assertionEndpoint.length > 0){
                this.assertionEndpoint = assertionEndpoint;
            }else{
                throw new Error("Assertion URL is required.");
            }
        }

        generateKeys(encryptionKeylength){
            if ([1024, 2048].includes(encryptionKeylength)){
                this.encryptionKeylength = encryptionKeylength;
            }

            const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {
                modulusLength: this.encryptionKeylength,
                publicKeyEncoding: {type: 'spki',format: 'pem'},
                privateKeyEncoding: {type: 'pkcs8',format: 'pem'}
            }); 

            this.privateKey  = privateKey;
            this.certificate = this.createCertificate(privateKey, publicKey);
            
            return {'private_key': this.privateKey, 'cert': this.certificate};
        }

        createCertificate(privateKey, publicKey){
            let selfSignedCert = selfsigned.generate(null, {
                clientCertificate: true,
                keyPair: { publicKey: publicKey, privateKey: privateKey }
            });

            return selfSignedCert.cert;
        }

        saveRSAKeys(){
            if (this.privateKey && this.certificate){
                fs.writeFileSync("./private.pem", this.privateKey, 'utf-8', (err) =>{
                    if (err){
                    throw new Error(err);
                    }
                });
                
                fs.writeFileSync("./cert.crt", this.certificate.cert, 'utf-8', (err) =>{
                    if (err){
                    throw new Error(err);
                    }
                });
            }else{
                throw new Error("No RSA keys were generated, run generateKeys(length) and try again.");
            }
        }   

        createMetaData(){
            let xmlMetaData = xmlbuilder.create({
                'md:EntityDescriptor': {
                '@xmlns:md': 'urn:oasis:names:tc:SAML:2.0:metadata',
                '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
                '@entityID': this.entityID,
                '@validUntil': (new Date(Date.now() + 1000 * 60 * 60)).toISOString(),
                'md:SPSSODescriptor': {
                    '@protocolSupportEnumeration': 'urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol',
                    'md:KeyDescriptor': this.signXMLWithCertificate('signing', this.certificate.cert),
                    'md:SingleLogoutService': {
                        '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                        '@Location': this.assertionEndpoint
                },
                'md:AssertionConsumerService': {
                    '@Binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
                    '@Location': this.assertionEndpoint,
                    '@index': '0'
                }
                }
            }
            }).end({pretty:true});

            fs.writeFileSync('./metadata.xml', xmlMetaData, 'utf-8', (err) => {
                if (err){
                    throw new Error("Service provider metadata cannot be written to the same directory.");
                }
            });
        }

        signXMLWithCertificate(XMLUse, key){
            if (['signing', 'encryption'].includes(XMLUse)){
                return {
                    '@use': XMLUse,
                    'ds:KeyInfo': {
                        '@xmlns:ds': 'http://www.w3.org/2000/09/xmldsig#',
                        'ds:X509Data': {
                            'ds:X509Certificate': this.stripCommentsFromKeys(key)
                        }
                    }
                }
            }
        }

        stripCommentsFromKeys(key){
            let regex = /([-]+[A-Z\s]+[-]+)/g;
            return String(key).replace(regex, '').replace(/[\r\n]/g, '');
        }
    },

    Request: class{
        constructor(idpURL, assertionEndpoint){
            if (assertionEndpoint.length == 0){
                throw new Error("Assertion Endpoint is required.");
            }else if (idpURL.length == 0){
                throw new Error("The Identity provider URL is required.");
            }

            this.idpURL            = idpURL;
            this.assertionEndpoint = assertionEndpoint;
        }

        generateAuthNRequest(){
            let idHash = SAML.generateRandomEntityID(); 
            return `
                <?xml version="1.0"?>
                    <saml2p:AuthnRequest xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="${idHash}" ForceAuthn="true" AssertionConsumerServiceURL="${this.assertionEndpoint}" IssueInstant="2021-12-31T18:47:47Z" Version="2.0" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
                </saml2p:AuthnRequest>
            `;
        }
    
        createAuthNURL(){
            if (this.idpURL.length == 0 || this.idpURL.includes('?')){
                throw new Error("Invalid Identity Provider URL");
            }
    
            return this.idpURL + '?SAMLRequest='+Buffer.from(this.generateAuthNRequest()).toString('base64');
        }
    },

    Response: class{
        constructor(req){
            this.req      = req;
            this.response = "";
        }

        async decryptAssertions(){
            await this.formatResponse().then((xml) => {
                this.response = xml;
            });

            if (this.response.length > 0){
                let xml       = this.response.toString().replace(/\r\n?/g, '\n')
                let doc       = (new xmldom.DOMParser()).parseFromString(xml)
                
                var options = {
                    key: fs.readFileSync(__dirname + '/private.pem'),
                    disallowDecryptionWithInsecureAlgorithm: true,
                    warnInsecureAlgorithm: true
                };

                let encryptedAssertion = doc.getElementsByTagName('saml2:EncryptedAssertion')[0].toString();
                if (encryptedAssertion.length > 0){
                    return (new Promise((resolve, reject) => {
                        xmlenc.decrypt(encryptedAssertion, options, function(err, decryptedAssertions) {
                            if (err){
                                throw new Error(err);
                            }
                            
                            resolve(decryptedAssertions);
                        });
                    }));
                }
            }

            return null;
        }

        async formatResponse(){
            let body = "";

            if (this.req.method === "POST") {
                this.req.on("data", chunk => {
                    body += decodeURIComponent(chunk.toString());
                });
        
                return (new Promise((resolve, reject) => {
                    this.req.on("end", () => {
                        let base64    = body.split("&")[0].replace("SAMLResponse=", "");
                        let buf       = Buffer.from(base64, 'base64'); 
                        let xmlBuffer = buf.toString();

                        if (xmlBuffer.length > 0){
                            resolve(xmlBuffer);
                        }else{
                            reject("Empty SAMLResponse was encounterd!");
                        }
                    });
                }));
            }
        }
    }
}

module.exports = SAML;