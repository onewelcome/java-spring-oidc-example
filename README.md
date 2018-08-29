# Java Spring example
This example covers how to implement and configure a Java Spring project to work with our OpenID Connect 
Provider. The example uses a pre made example from github made by [fromi](https://github.com/fromi/spring-google-openidconnect).

## Clone and configure your IDE
To get the example up and running just clone and configure it.

Clone this repo: https://github.com/Onegini/java-spring-oidc-example.git

`git clone https://github.com/Onegini/java-spring-oidc-example.git`

**Intellij**

Go to `File->Open` and open the spring-google-openidconnect/pom.xml, open it as a project.

The `com.github.fromi.openidconnect.Application` should automatically be found and set up a run configuration for you so you can easily run it
within Intellij.

## Set up configuration

To configure you'll need three values, see [Configuration](#configuration) heading.

Below is a sample some configuration for Spring-Boot to work with the provided sample code. If you have your own configuration, the code will likely
need to be modified.

Create `application.yml` in _/src/main/resources_.

Add the following yml configuration:
    
    onegini:
      oauth2:
        clientId: [clientId]
        clientSecret: [clientSecret]
        issuer: [OneginiOIDCProviderPartyUrl]
    server:
      port: [portnumberForYourWebapp]

___Example configuration___

      onegini:
          oauth2:
            clientId: BA6ABD4E53ADF688F28C8D3B7E8C5D31C2B93F5E0F640A1F764D7EE25A540C4E
            clientSecret: B44402649A47C90E4850B7B6BD98AAEC40602F7450E721434BE9C056D97C93B0
            issuer: https://onegini-op.test.onegini.io/oauth/
        server:
          port: 8080
                
## Run and test
Run and test the Spring boot application. You should be able to see a page with a hyperlink _Go to some secured resource_.
When you click the link you wil be redirected to authenticate. If everything goes well, you will be returned to a page where
you see the username value. When you use our UserInfo example this should be the sub value.
            
# How it works
If you want to implement this in another project you can take a look at the code and discover how it is structured.
There are multiple ways and configurations you could use. We try to explain how this example works.

## Configuration
The configuration we set up is used inside `OAuth2Client`. You'll need a running instance of the [Token Server][ts] (TS). 
The TS should have an OIDC Web Client registered ([see docs][ts-oidc]) to become a OP. The OP will have a `clientId` and a 
`clientSecret` and an `issuer` url where the OP resides. These configurations are usually provided by us, if you do not have 
them or you need to register a new client please ask the TS administrator.

## OAuth2Client
This configures the OAuth flow inside the spring framework. It uses discovery to find the endpoints used by the OAuth flow.

## OpenIDConnectAuthenticationFilter
This is the filter used during authentication, we extend it to handle the retrieval of UserInfo. Depending on your
environment this could be different. There are mainly two ways to do this:

1. Get the UserInfo data from the ID Token
2. Get the UserInfo data from the user info endpoint

In the example we show both ways. The second way is commented out. The first one also cover the ID token validation.

## UserInfo
Depending on the scope and configuration used in your environment the user data returned in the ID token or by the
user info endpoint will differ. Adjust the `OpenIDConnectAuthenticationFilter` class accordingly to match the correct fields.
In this example we only use the sub value, but you can use any value configured for your environment.

## Security configuration
In here we configure the security filters used to authorize and authenticate the controllers of our application. 
Within spring there are multiple ways to do this, use whatever method you prefer.

[ts]: https://docs.onegini.com/msp/token-server/8.2.0/index.html
[ts-oidc]: https://docs.onegini.com/msp/token-server/8.2.0-SNAPSHOT/topics/oidc/configuration/configuration.html