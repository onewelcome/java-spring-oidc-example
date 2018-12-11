package com.onegini.oidc.model;

public class UserInfo {

  private final String id;
  private final String name;
  private final String idToken;
  private final String encryptedIdToken;

  public UserInfo(final String id, final String name, final String idToken, final String encryptedIdToken) {
    this.id = id;
    this.name = name;
    this.idToken = idToken;
    this.encryptedIdToken = encryptedIdToken;
  }

  public String getId() {
    return id;
  }

  public String getName() {
    return name;
  }

  public String getIdToken() {
    return idToken;
  }

  public String getEncryptedIdToken() {
    return encryptedIdToken;
  }

  public boolean isEncryptionEnabled() {
    return encryptedIdToken != null;
  }
}