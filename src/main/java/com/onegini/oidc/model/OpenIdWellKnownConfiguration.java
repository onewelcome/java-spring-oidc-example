package com.onegini.oidc.model;

import java.util.Collection;

import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;


@Data
@EqualsAndHashCode
@NoArgsConstructor
public class OpenIdWellKnownConfiguration {

  private String issuer;
  private String authorizationEndpoint;
  private String tokenEndpoint;
  private String jwksUri;
  private String userinfoEndpoint;
  private Collection<String> responseTypesSupported;
  private Collection<String> subjectTypesSupported;
  private Collection<String> idTokenSigningAlgValues;
  private Collection<String> scopesSupported;
  private Collection<String> claimsSupported;
  private String checkSessionIframe;
  private String endSessionEndpoint;
  private boolean frontchannelLogoutSupported;
  private boolean frontchannelLogoutSessionSupported;
  private Collection<String> idTokenEncryptionAlgValuesSupported;
  private Collection<String> idTokenEncryptionEncValuesSupported;

}