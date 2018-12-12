# Java Spring example
This example covers how to implement and configure a Java Spring project to work with Onegini's OpenID Connect Provider (OP). The example is based on the
project [spring-google-openidconnect](https://github.com/fromi/spring-google-openidconnect).

## Clone and configure your IDE
To get the example up and running, first you'll need to clone it:

`git clone https://github.com/Onegini/java-spring-oidc-example.git`

### IntelliJ

Go to `File->Open` and open the file `java-spring-oidc-example/pom.xml`, open it as a project.

The class `com.onegini.oidc.Application` should automatically be found and set up a run configuration for you so you can run it within IntelliJ.

## Onegini Configuration
You'll need to properly setup your client using the Onegini Admin panel before you can begin testing.
Refer to the [OpenID Connect documentation](https://docs.onegini.com/msp/5.0/token-server/topics/oidc/index.html). 

The Web client must support the following scopes:
  * openid
  * profile
  
The Onegini Token Server only redirects to preconfigured endpoints after login or logout. You must configure the following endpoints in the Onegini Token Server:
  * Redirect URL: `http://localhost:8080/login`
  * Post Logout Redirect URL: `http://localhost:8080/signout-callback-oidc`
  
### Configuring ID Token Encryption
The Onegini Token Server supports encryption of the ID token to provide confidentiality of the claims. It can be configured by providing a JWKS endpoint and 
choosing an encryption method in [OpenID Connect configuration](https://docs.onegini.com/msp/5.0/token-server/topics/web-clients/web-client-configuration.html#enabling-openid-connect-capability):
  * Encryption method: select one of encryption method that will be used to encrypt the ID Token.
  * JWKS URI: An endpoint that returns a list of public keys for encryption purposes. In this example it is exposed at 
  `http://localhost:8080/.well-known/jwks.json`. These keys typically would be stored in your database and would not change frequently. This example generates 
  them each time the application is started.

## Set up the application configuration

Modify `application.properties` in _/src/main/resources_ or use one of the mechanisms Spring Boot supports to [override property values](https://docs.spring.io/spring-boot/docs/current/reference/html/howto-properties-and-configuration.html).
The following properties must be set:

  * onegini.oidc.clientId: the client identifier of the Web client that supports OpenID Connect
  * onegini.oidc.clientSecret: the client secret of the Web client that supports OpenID Connect
  * onegini.oidc.issuer: the base URL of the Token Server instance
  
Optional properties:  
  * onegini.oidc.idTokenEncryptionEnabled: boolean for enabling ID token encryption. This should match the server side configuration

___Example configuration___

```
onegini.oidc.clientId=openid-client
onegini.oidc.clientSecret=secret
onegini.oidc.issuer=http://localhost:7878/oauth
onegini.oidc.idTokenEncryptionEnabled=true
```

## Run and test
Run the example via the Run configuration in IntelliJ or via the command line: `mvn spring-boot:run`. The Token Server needs to be accessible to start this 
application since it connects to the well-known-configuration endpoint during start up.

Go to [http://localhost:8080](http://localhost:8080) 

You should see a page with a link to a secured resource. When you click the link you wil be redirected to authenticate. If everything goes well, you will be 
returned to a page where you see user information and the claims from the ID token. The user identifier is the value of the "sub" claim in the ID token.
            
## How it works

### OAuth2Client
[OAuth2Client.java](src/main/java/com/onegini/oidc/security/OAuth2Client.java) configures the OAuth flow for Spring Security. It uses discovery 
to find the endpoints used by the OAuth flow. By default the scopes "openid" and "profile" are requested.

### OpenIdConnectAuthenticationFilter
[OpenIdConnectAuthenticationFilter.java](src/main/java/com/onegini/oidc/security/OpenIdConnectAuthenticationFilter.java) is the filter used during
authentication. It obtains the ID token and creates the principal using some of the data.

Depending on the scope and configuration used in your environment, the user data returned in the ID token will differ. Adjust the 
`OpenIDConnectAuthenticationFilter` class accordingly to match the correct fields.
In this example we use the `sub` and the `name` value, but you can use any value configured for your environment.

### OpenIdTokenValidationWrapper
[OpenIdTokenValidationWrapper.java](src/main/java/com/onegini/oidc/security/OpenIdTokenValidatorWrapper.java) validates the ID token. It validates
its signature against the keys that are returned by the JWKS endpoint of the OP. It verifies that the claims are from the issuer, intended for the correct 
audience and that they have not expired.

### UserInfo
The [UserInfo.java](src/main/java/com/onegini/oidc/model/UserInfo.java) is a POJO for user information. It is used as user principal in Spring 
Security.

### TokenDetails
The [TokenDetails.java](src/main/java/com/onegini/oidc/model/TokenDetails.java) is a POJO for additional details about the token used during 
authentication. In this project it contains the claims of the JWT.

### Security configuration
In [SecurityConfiguration.java](src/main/java/com/onegini/oidc/security/SecurityConfiguration.java) we configure the Spring Security filters used 
to authenticate the user and authorize the controllers of our application.

### SampleSecuredController
The [SampleSecuredController.java](src/main/java/com/onegini/oidc/SampleSecuredController.java) has a protected endpoint `/secured`. It populates
the modelMap for the template that shows the user information, ID token and the claims.

### LogoutController
The [LogoutController.java](src/main/java/com/onegini/oidc/LogoutController.java) contains the logic to end the session. The user first comes to
the `/logout` endpoint. If the user was logged in via an ID token, they are redirected to the end session endpoint of the OP. The OP ends the session of the 
user and redirects it back to `http://localhost:8080/signout-callback-oidc`. Then the user is logged out in Spring Security and redirected to the home page.

## Encryption/Decryption

### JweWellKnownJwksController
The [JweWellKnownJwksController.java](src/main/java/com/onegini/oidc/JweWellKnownJwksController.java) is responsible for returning the JWKS list (for encryption 
purposes). This is an example implementation defined by the [OpenID Connect Encryption spec](https://openid.net/specs/openid-connect-core-1_0.html#RotateEncKeys).
This example uses the `ECDH_ES` algorithm by default. You can swap to another asymmetric algorithm such as `RSA_OAEP_256` using the 
`ASYMMETRIC_ENCRYPTION_ALGORITHM` variable. The `MAX_AGE` variable defined in this class defines how long the Token Server will cache the response.
This should align with your key rotation strategy. It also validates that the key's encryption algorithm is supported by checking the supported algorithms 
exposed by the [OpenID Provider Metadata](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata) This example generates keys every time 
the application is started and stores them in memory. In a production situation, keys should be persisted in some way and proper key rotation followed. See 
[JSON Web Key (JWK) RFC-7517](https://tools.ietf.org/html/rfc7517) for more information. This controller is only exposed when the property
`onegini.oidc.idTokenEncryptionEnabled` is set to `true`. If your client is not configured for encryption, there is no need for this controller.

### JweKeyGenerator
The [JweKeyGenerator.java](src/main/java/com/onegini/oidc/encryption/JweKeyGenerator.java) is responsible for key generation. It shows how to generate the RSA 
and EC keys. This could be used to help you generate keys to persist elsewhere.

### JwkSetProvider
The [JwkSetProvider.java](src/main/java/com/onegini/oidc/encryption/JwkSetProvider.java) has a storage role for caching the encryption keys. In a production 
environment it should be modified to grab the keys from where they have been stored.

### JweDecrypterService
The [JweDecrypterService.java](src/main/java/com/onegini/oidc/encryption/JweDecrypterService.java) does the decryption of the ID token. The `decrypt` 
method consumes the encrypted JWT and tries to decrypt it by finding the relevant key. It then passes that key with the encrypted JWT to `nimbusds-jose-jwt` 
library which decrypts it and returns the Signed JWT.

## Troubleshooting

Connecting this Relying Party example with the Onegini Token Server requires configuration of both applications. This section describes some situations that may 
go wrong. 

### Application fails to start

The RP can only start up when the Onegini Token Server is running. During the start up the RP tries to connect to the well-known-configuration endpoint of the
Onegini Token Server.

* Check that the Onegini Token Server is running
* Check that the property `onegini.oidc.issuer` points to the URL of that Onegini Token Server

### 401 - Unauthorized during login

This means that the authentication has failed. 

You may see this when the Relying Party has disabled ID Token encryption but the configuration in the Onegini Token Server has enabled it. When this is the 
case, there are two solutions:
* Enable ID Token encryption in the RP via the property `onegini.oidc.idTokenEncryptionEnabled=true` and restart the application
* Disable ID Token encryption in the Onegini Token Server. Call the logout endpoint http://localhost:8080/logout before logging in again.

### 500 - Internal server error during login

An error page is shown during login with a message "Server did not return an Encrypted JWT but encryption was enabled. Check your server side configuration".

You see this when the Relying Party has enabled ID Token encryption but the configuration in the Onegini Token Server has disabled it.

There are two solutions:
* Disable ID Token encryption in the RP via the property `onegini.oidc.idTokenEncryptionEnabled=false` and restart the application
* Enable ID Token encryption in the Onegini Token Server. Call the logout endpoint http://localhost:8080/logout before logging in again.

### Confirmation page is shown after logout

There can be several reasons why this page is shown by the Onegini Token Server after logging out with the RP:
* The POST logout redirect URL is not properly configured. Refer to the [Onegini Configuration](#onegini-configuration)
* ID Token encryption is enabled