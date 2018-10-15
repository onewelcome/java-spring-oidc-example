package com.onegini.oidc;

import java.security.Principal;

import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

import com.onegini.oidc.model.TokenDetails;

@Controller
public class SampleSecuredController {

  public static final String PAGE_SECURED = "/secured";

  @GetMapping(PAGE_SECURED)
  public String userInfo(final Principal principal, final ModelMap modelMap) {

    if (principal instanceof PreAuthenticatedAuthenticationToken) {
      final PreAuthenticatedAuthenticationToken authenticationToken = (PreAuthenticatedAuthenticationToken) principal;
      final TokenDetails tokenDetails = (TokenDetails) authenticationToken.getDetails();
      modelMap.addAttribute("jwtClaimsSet", tokenDetails.getJwtClaimsSet());
      modelMap.addAttribute("userInfo", authenticationToken.getPrincipal());
    }

    return "secured";
  }
}