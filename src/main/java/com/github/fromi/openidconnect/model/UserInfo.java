package com.github.fromi.openidconnect.model;

public class UserInfo {

  private final String id;
  private final String name;
  private final String idToken;

  public UserInfo(final String id, final String name, final String idToken) {
    this.id = id;
    this.name = name;
    this.idToken = idToken;
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

}