package com.github.fromi.openidconnect;

import java.security.Principal;

import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SampleSecuredController {

  public static final String SECURED_URL = "/secured";

  @RequestMapping(SECURED_URL)
  public Object userInfo(final Principal principal) {
    if (principal instanceof PreAuthenticatedAuthenticationToken) {
      return ((PreAuthenticatedAuthenticationToken) principal).getPrincipal();
    }
    return principal;
  }
}