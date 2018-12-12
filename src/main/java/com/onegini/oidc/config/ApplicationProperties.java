package com.onegini.oidc.config;

import javax.validation.constraints.NotBlank;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import lombok.Getter;
import lombok.Setter;

@Validated
@Configuration
@ConfigurationProperties(prefix = "onegini.oidc")
@Getter
@Setter
public class ApplicationProperties {
  @NotBlank
  private String clientId;
  @NotBlank
  private String clientSecret;
  @NotBlank
  private String issuer;
  private boolean idTokenEncryptionEnabled;
}