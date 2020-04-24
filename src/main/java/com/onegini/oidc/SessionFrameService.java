package com.onegini.oidc;

import java.net.URI;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Service;
import org.springframework.ui.ModelMap;

import com.onegini.oidc.config.ApplicationProperties;

@Service
public class SessionFrameService {

  private static final String ORIGIN = "origin";
  private static final String OPENID_SERVER = "openid_server";

  @Resource
  private ApplicationProperties applicationProperties;

  public void addSessionFramesAttributes(final ModelMap modelMap, final HttpServletRequest request) {
    final URI originUri = URI.create(request.getRequestURL().toString());
    final String origin = originUri.getScheme() + "://" + originUri.getAuthority();
    modelMap.addAttribute(ORIGIN, origin);

    final String openIdProvider = applicationProperties.getIssuer();
    modelMap.addAttribute(OPENID_SERVER, applicationProperties.getIssuer().substring(0, openIdProvider.indexOf("/oauth")));
  }

}
