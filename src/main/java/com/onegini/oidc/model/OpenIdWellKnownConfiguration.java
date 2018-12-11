package com.onegini.oidc.model;

import java.util.Collection;


public class OpenIdWellKnownConfiguration {

  public OpenIdWellKnownConfiguration() {
    //nothing
  }

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

  public String getIssuer() {
    return issuer;
  }

  public OpenIdWellKnownConfiguration setIssuer(final String issuer) {
    this.issuer = issuer;
    return this;
  }

  public String getAuthorizationEndpoint() {
    return authorizationEndpoint;
  }

  public OpenIdWellKnownConfiguration setAuthorizationEndpoint(final String authorizationEndpoint) {
    this.authorizationEndpoint = authorizationEndpoint;
    return this;
  }

  public String getTokenEndpoint() {
    return tokenEndpoint;
  }

  public OpenIdWellKnownConfiguration setTokenEndpoint(final String tokenEndpoint) {
    this.tokenEndpoint = tokenEndpoint;
    return this;
  }

  public String getJwksUri() {
    return jwksUri;
  }

  public OpenIdWellKnownConfiguration setJwksUri(final String jwksUri) {
    this.jwksUri = jwksUri;
    return this;
  }

  public String getUserinfoEndpoint() {
    return userinfoEndpoint;
  }

  public OpenIdWellKnownConfiguration setUserinfoEndpoint(final String userinfoEndpoint) {
    this.userinfoEndpoint = userinfoEndpoint;
    return this;
  }

  public Collection<String> getResponseTypesSupported() {
    return responseTypesSupported;
  }

  public OpenIdWellKnownConfiguration setResponseTypesSupported(final Collection<String> responseTypesSupported) {
    this.responseTypesSupported = responseTypesSupported;
    return this;
  }

  public Collection<String> getSubjectTypesSupported() {
    return subjectTypesSupported;
  }

  public OpenIdWellKnownConfiguration setSubjectTypesSupported(final Collection<String> subjectTypesSupported) {
    this.subjectTypesSupported = subjectTypesSupported;
    return this;
  }

  public Collection<String> getIdTokenSigningAlgValues() {
    return idTokenSigningAlgValues;
  }

  public OpenIdWellKnownConfiguration setIdTokenSigningAlgValues(final Collection<String> idTokenSigningAlgValues) {
    this.idTokenSigningAlgValues = idTokenSigningAlgValues;
    return this;
  }

  public Collection<String> getScopesSupported() {
    return scopesSupported;
  }

  public OpenIdWellKnownConfiguration setScopesSupported(final Collection<String> scopesSupported) {
    this.scopesSupported = scopesSupported;
    return this;
  }

  public Collection<String> getClaimsSupported() {
    return claimsSupported;
  }

  public OpenIdWellKnownConfiguration setClaimsSupported(final Collection<String> claimsSupported) {
    this.claimsSupported = claimsSupported;
    return this;
  }

  public String getCheckSessionIframe() {
    return checkSessionIframe;
  }

  public OpenIdWellKnownConfiguration setCheckSessionIframe(final String checkSessionIframe) {
    this.checkSessionIframe = checkSessionIframe;
    return this;
  }

  public String getEndSessionEndpoint() {
    return endSessionEndpoint;
  }

  public OpenIdWellKnownConfiguration setEndSessionEndpoint(final String endSessionEndpoint) {
    this.endSessionEndpoint = endSessionEndpoint;
    return this;
  }

  public boolean isFrontchannelLogoutSupported() {
    return frontchannelLogoutSupported;
  }

  public OpenIdWellKnownConfiguration setFrontchannelLogoutSupported(final boolean frontchannelLogoutSupported) {
    this.frontchannelLogoutSupported = frontchannelLogoutSupported;
    return this;
  }

  public boolean isFrontchannelLogoutSessionSupported() {
    return frontchannelLogoutSessionSupported;
  }

  public OpenIdWellKnownConfiguration setFrontchannelLogoutSessionSupported(final boolean frontchannelLogoutSessionSupported) {
    this.frontchannelLogoutSessionSupported = frontchannelLogoutSessionSupported;
    return this;
  }

  public Collection<String> getIdTokenEncryptionAlgValuesSupported() {
    return idTokenEncryptionAlgValuesSupported;
  }

  public OpenIdWellKnownConfiguration setIdTokenEncryptionAlgValuesSupported(final Collection<String> idTokenEncryptionAlgValuesSupported) {
    this.idTokenEncryptionAlgValuesSupported = idTokenEncryptionAlgValuesSupported;
    return this;
  }

  public Collection<String> getIdTokenEncryptionEncValuesSupported() {
    return idTokenEncryptionEncValuesSupported;
  }

  public OpenIdWellKnownConfiguration setIdTokenEncryptionEncValuesSupported(final Collection<String> idTokenEncryptionEncValuesSupported) {
    this.idTokenEncryptionEncValuesSupported = idTokenEncryptionEncValuesSupported;
    return this;
  }
}