# SAML-SP
## _SAML Service Provider Node.js Library_
SAML-SP is a simple node.js library that allows for easy SAML service provider entity creation along with its RSA key-pairs and the decryption of assertions.

## Features
- Generate RSA key-pairs or use existing ones.
- Create the service provider metadata file to be uploaded to the Identity service provider.
- Formats and decrypts the assertions from the SAML response.
## Installation
_Will be available to install via npm soon_

## Examples
### 1. Configure the Service provider ###

```js
const SAML     = require("./saml-sp");
const SSO_URL  = "http://localhost:8888/saml/consume";

let sp = new SAML.ServiceProvider({
    assertionEndpoint: SSO_URL
});

sp.saveRSAKeys(); // this will save the private key and certificate in the current directory
sp.createMetaData(); // this will save the metadata.xml file in the current directory
```

### 2. Reading the SAMLResponse ###

```js

```
## Library Components
The library exposes three different classes each one is used for a different phase of the SAML implementation as follows:
### 1. Service provider Class ###
```let sp = new SAML.ServiceProvider(options);```
The options is an object that can have the following attributes:
| Attrbute | note |
| ------ | ------ |
| assertionEndpoint (```*Required*```) | The redirect URI after a successful authentication with the IDP |
| encyptionKeyLength | The length of the encryption key. default=1024 |
| certificate | Supply a PEM certificate if you already have one, otherwise one will be created for you. |
| privateKey | Supply a PEM Private Key if you already have one, otherwise one will be created for you. |
| entityID | An optional entity ID to be added to your SAML requests. |

### 2. Request Class ###
```js
let sp = new SAML.Request(IDP_URL, ASSERTION_ENDPOINT);
let authNRequestURL = SAMLRequest.createAuthNURL();
```
Used to create the AuthNRequest for Identity providers such as AWS SSO, please note that some Identity providers like okta do not expect a SAML request in the URL therefore the user should be redirected to the SSO url without using this option.

| Attrbute | note |
| ------ | ------ |
| IDP_URL (```*Required*```) | The SSO URL given to you by the Identity provider, this is where users go to authenticate. |
| ASSERTION_ENDPOINT (```*Required*```) | The redirect URI after a successful authentication with the IDP |

### 3. Response Class ###
```js
let SAMLResponse = new SAML.Response(req);
SAMLResponse.decryptAssertions().then((decrypted_data) => {
    console.log(decrypted_data);
});
```
This class is used to interpret the SAMLResponse and decrypt the assertions.
| Attrbute | note |
| ------ | ------ |
| req (```*Required*```) | The ```req``` object given by express js POST route. |

## License
MIT
