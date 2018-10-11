# Java Spring example
This example covers how to implement and configure a Java Spring project to work with Onegini's OpenID Connect Provider. The example is based on the project 
[spring-google-openidconnect](https://github.com/fromi/spring-google-openidconnect).

## Clone and configure your IDE
To get the example up and running clone and configure it.

`git clone https://github.com/Onegini/java-spring-oidc-example.git`

### IntelliJ

Go to `File->Open` and open the spring-google-openidconnect/pom.xml, open it as a project.

The `com.github.fromi.openidconnect.Application` should automatically be found and set up a run configuration for you so you can run it
within IntelliJ.

## Onegini Configuration
You'll need to properly setup your client using the Onegini Admin panel before you can begin testing.
Refer to the [OpenID Connect documentation](https://docs.onegini.com/msp/5.0/token-server/topics/oidc/index.html). 

The Web client must support the following scopes:
  * openid
  * profile
  
The Onegini Token Server only redirects to preconfigured endpoints after login or logout. You must configure the following endpoints in the Onegini Token Server:
  * Redirect URL: `http://localhost:8080/`
  * Post Logout Redirect URL: `http://localhost:8080/signout-callback-oidc`

## Set up the application configuration

Modify `application.properties` in _/src/main/resources_ or use one of the mechanisms Spring Boot supports to [override property values](https://docs.spring.io/spring-boot/docs/current/reference/html/howto-properties-and-configuration.html).
The following properties must be set:

  * onegini.oauth2.clientId: the client identifier of the Web client that supports OpenID Connect
  * onegini.oauth2.clientSecret: the client secret of the Web client that supports OpenID Connect
  * onegini.oauth2.issuer: the base URL of the Token Server instance

___Example configuration___

```
onegini.oauth2.clientId=openid-client
onegini.oauth2.clientSecret=secret
onegini.oauth2.issuer=http://localhost:7878/oauth
```

## Run and test
Run the example via the Run configuration in IntelliJ or via the command line: `mvn spring-boot:run`. The Token Server needs to be accessible to start this 
application since it connects to the well-known-configuration endpoint during start up.

Go to [http://localhost:8080](http://localhost:8080) 

You should see a page with a link to a secured resource. When you click the link you wil be redirected to authenticate. If everything goes well, you will be 
returned to a page where you see user information and the claims from the ID token. The user identifier is the value of the "sub" claim in the ID token.
            
## How it works

### OAuth2Client
[OAuth2Client.java](src/main/java/com/github/fromi/openidconnect/security/OAuth2Client.java) configures the OAuth flow for Spring Security. It uses discovery 
to find the endpoints used by the OAuth flow. By default the scopes "openid" and "profile" are requested.

### OpenIdConnectAuthenticationFilter
[OpenIdConnectAuthenticationFilter.java](src/main/java/com/github/fromi/openidconnect/security/OpenIdConnectAuthenticationFilter.java) is the filter used during
authentication. It adds user information during authentication Depending on your environment this could be different. There are mainly two ways to do this:

In the code we show both ways. The second way is commented out. The first one also covers the ID token validation.

Depending on the scope and configuration used in your environment the user data returned in the ID token will differ. Adjust the 
`OpenIDConnectAuthenticationFilter` class accordingly to match the correct fields.
In this example we use the `sub` and the `name` value, but you can use any value configured for your environment.

### OpenIdTokenValidationWrapper
[OpenIdTokenValidationWrapper.java](src/main/java/com/github/fromi/openidconnect/security/OpenIdTokenValidatorWrapper.java) validates the ID token. It validates
its signature against the keys that are returned by the JWKS endpoint of the OP. It verifies that the claims are from the issuer, intended for the correct 
audience and that they have not expired.

### UserInfo
The [UserInfo.java](src/main/java/com/github/fromi/openidconnect/model/UserInfo.java) is a POJO for user information. It is used as user principal in Spring 
Security.

### TokenDetails
The [TokenDetails.java](src/main/java/com/github/fromi/openidconnect/model/TokenDetails.java) is a POJO for additional details about the token used during 
authentication. In this project it contains the claims of the JWT.

### Security configuration
In [SecurityConfiguration.java](src/main/java/com/github/fromi/openidconnect/security/SecurityConfiguration.java) we configure the Spring Security filters used 
to authenticate the user and authorize the controllers of our application.

### SampleSecuredController
The [SampleSecuredController.java](src/main/java/com/github/fromi/openidconnect/SampleSecuredController.java) has a protected endpoint `/secured`. It populates
the modelMap for the template that shows the user information, ID token and the claims.

### LogoutController
Thie [LogoutController.java](src/main/java/com/github/fromi/openidconnect/LogoutController.java) contains the logic to end the session. The user first comes to
the `/logout` endpoint. If the user was logged in via an ID token, they are redirected to the end session endpoint of the OP. The OP ends the session of the 
user and redirects it back to `http://localhost:8080/signout-callback-oidc`. Then the user is logged out in Spring Security and redirected to the home page.