# Java Spring example
This example covers how to implement and configure a Java Spring project to work with our OpenID Connect 
Provider. The example uses a pre made example from github made by [fromi](https://github.com/fromi/spring-google-openidconnect).

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
The default redirect URL of this application is `http://localhost:8080/login`. This needs to be set in the Web client configuration.

The Web client must support the following scopes:
  * openid
  * profile

## Set up the application configuration

Modify `application.yml` in _/src/main/resources_ or use one of the mechanisms Spring Boot supports to [override property values](https://docs.spring.io/spring-boot/docs/current/reference/html/howto-properties-and-configuration.html).
The following properties must be set:

  * onegini.oauth2.clientId: the client identifier of the Web client that supports OpenID Connect
  * onegini.oauth2.clientSecret: the client secret of the Web client that supports OpenID Connect
  * onegini.oauth2.issuer: the base URL of the Token Server instance

___Example configuration___

      onegini:
          oauth2:
            clientId: openid-client
            clientSecret: secret
            issuer: http://localhost:7878/oauth

## Run and test
Run the example via the Run configuration in IntelliJ or via the command line: `mvn spring-boot:run`. The Token Server needs to be accessible to start this 
application since it connects to the well-known-configuration endpoint.

Go to [http://localhost:8080](http://localhost:8080) 

You should see a page with a hyperlink to go to a secured resource. When you click the link you wil be redirected to authenticate. If everything goes well, you 
will be returned to a page where you see user information. The user identifier is the value of the "sub" claim in the ID token.
            
## How it works

### OAuth2Client
[OAuth2Client.java](src/main/java/com/github/fromi/openidconnect/security/OAuth2Client.java) configures the OAuth flow for Spring Security. It uses discovery 
to find the endpoints used by the OAuth flow. By default the scopes "openid" and "profile" are requested.

### OpenIDConnectAuthenticationFilter
[OpenIDConnectAuthenticationFilter.java](src/main/java/com/github/fromi/openidconnect/security/OpenIDConnectAuthenticationFilter.java) is the filter used during
authentication. We have extended it to handle the retrieval of UserInfo. Depending on your
environment this could be different. There are mainly two ways to do this:

1. Get the UserInfo data from the ID Token
2. Get the UserInfo data from the user info endpoint

In the code we show both ways. The second way is commented out. The first one also covers the ID token validation.

Depending on the scope and configuration used in your environment the user data returned in the ID token or by the
user info endpoint will differ. Adjust the `OpenIDConnectAuthenticationFilter` class accordingly to match the correct fields.
In this example we only use the sub value, but you can use any value configured for your environment.

### UserInfo
The [UserInfo.java](src/main/java/com/github/fromi/openidconnect/security/UserInfo.java) is a POJO for user information. It is used as user principal in Spring 
Security.

### Security configuration
In [SecurityConfiguration.java](src/main/java/com/github/fromi/openidconnect/security/SecurityConfiguration.java) we configure the Spring Security filters used 
to authenticate the user and authorize the controllers of our application.

### SampleSecuredController
The [SampleSecuredController.java](src/main/java/com/github/fromi/openidconnect/SampleSecuredController.java) has a protected endpoint `/secured`. It prints 
the UserInfo object.