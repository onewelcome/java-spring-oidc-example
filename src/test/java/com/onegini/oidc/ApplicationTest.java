package com.onegini.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

import javax.annotation.Resource;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import com.onegini.oidc.model.OpenIdDiscovery;

@SpringBootTest(classes = Application.class)
class ApplicationTest {

  @Resource
  private IndexController controller;
  @MockBean
  private OpenIdDiscovery openIdDiscovery;

  @Test
  void should_start_application_context() {
    assertThat(controller).isNotNull();

    verify(openIdDiscovery).getTokenEndpoint();
  }

}