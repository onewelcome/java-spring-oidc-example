package com.onegini.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import java.io.InputStream;
import java.net.URI;

import javax.annotation.Resource;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.IOUtils;
import lombok.SneakyThrows;

@SpringBootTest(classes = Application.class)
class ApplicationTest {

  @Resource
  private IndexController controller;
  @Resource
  private RestTemplate restTemplate;

  private MockRestServiceServer mockServer;

  @BeforeEach
  void setUp() {
    mockServer = MockRestServiceServer.createServer(restTemplate);

    mockOpenIdConfiguration();
  }

  @SneakyThrows
  private void mockOpenIdConfiguration() {
    final ClassPathResource resource = new ClassPathResource("openid-configuration.json");

    try (final InputStream inputStream = resource.getInputStream()) {
      final String openidConfiguration = IOUtils.readInputStreamToString(inputStream);
      mockServer.expect(ExpectedCount.once(),
          requestTo(URI.create("http://localhost:7878/oauth/.well-known/openid-configuration")))
          .andExpect(method(HttpMethod.GET))
          .andRespond(withStatus(HttpStatus.OK)
              .contentType(MediaType.APPLICATION_JSON)
              .body(openidConfiguration)
          );
    }
  }

  @Test
  void should_start_application_context() {
    assertThat(controller).isNotNull();
  }

}