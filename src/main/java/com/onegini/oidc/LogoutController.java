package com.onegini.oidc;

import java.security.Principal;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import org.springframework.web.util.UriComponentsBuilder;

import com.onegini.oidc.config.ApplicationProperties;
import com.onegini.oidc.model.UserInfo;

@Controller
public class LogoutController {

  private static final Logger LOG = LoggerFactory.getLogger(LogoutController.class);

  private static final String WELL_KNOWN_CONFIG_PATH = "/.well-known/openid-configuration";
  private static final String PAGE_SIGNOUT_CALLBACK_OIDC = "/signout-callback-oidc";
  public static final String PAGE_LOGOUT = "/logout";

  @Resource
  private ApplicationProperties applicationProperties;
  @Resource
  private OAuth2RestOperations restTemplate;

  @GetMapping(PAGE_LOGOUT)
  private String logout(final HttpServletRequest request, final HttpServletResponse response, final Principal principal) {
    if (principal instanceof PreAuthenticatedAuthenticationToken) {
      final Map configuration = restTemplate.getForObject(applicationProperties.getIssuer() + WELL_KNOWN_CONFIG_PATH, Map.class);

      final String endSessionEndpoint = configuration == null ? null : (String) configuration.get("end_session_endpoint");

      if (StringUtils.hasLength(endSessionEndpoint)) {
        return endOpenIdSession((PreAuthenticatedAuthenticationToken) principal, endSessionEndpoint);
      }
    }

    return doLogout(request, response);
  }

  @GetMapping(PAGE_SIGNOUT_CALLBACK_OIDC)
  public String callbackOidc(final HttpServletRequest request, final HttpServletResponse response) {
    LOG.info("Signout callback from OP");
    return doLogout(request, response);
  }

  private String endOpenIdSession(final PreAuthenticatedAuthenticationToken principal, final String endSessionEndpoint) {
    final UserInfo userInfo = (UserInfo) principal.getPrincipal();

    final MultiValueMap<String, String> requestParameters = new LinkedMultiValueMap<>();

    final String postLogoutRedirectUri = ServletUriComponentsBuilder.fromCurrentContextPath().path(PAGE_SIGNOUT_CALLBACK_OIDC).build().toUriString();
    requestParameters.add("post_logout_redirect_uri", postLogoutRedirectUri);
    requestParameters.add("id_token_hint", userInfo.getIdToken());

    final String redirectUri = UriComponentsBuilder.fromUriString(endSessionEndpoint)
        .queryParams(requestParameters)
        .build().toUriString();

    LOG.info("Redirect to OP end session");
    return "redirect:" + redirectUri;
  }

  private String doLogout(final HttpServletRequest request, final HttpServletResponse response) {
    final Authentication auth = SecurityContextHolder.getContext().getAuthentication();
    if (auth != null) {
      LOG.info("End user session in Spring Security");
      new SecurityContextLogoutHandler().logout(request, response, auth);
    }
    return "redirect:/";
  }
}