package ir.fidar.pam.service.impl;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import ir.fidar.core.util.StringUtils;
import ir.fidar.core.util.WebUtils;
import ir.fidar.pam.exception.KavoshServerNotConfiguredException;
import ir.fidar.pam.exception.KavoshServerNotReachableException;
import ir.fidar.pam.management.KavoshIntegrationProperties;
import ir.fidar.pam.service.KavoshIntegrationService;
import java.io.File;
import java.net.URI;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import okhttp3.OkHttpClient;
import okhttp3.OkHttpClient.Builder;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.boot.web.client.RootUriTemplateHandler;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.OkHttp3ClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class KavoshIntegrationServiceImpl implements KavoshIntegrationService {
   private final KavoshIntegrationProperties kavoshIntegrationProperties;
   private final RestTemplate restTemplate;

   public KavoshIntegrationServiceImpl(KavoshIntegrationProperties kavoshIntegrationProperties) {
      this.kavoshIntegrationProperties = kavoshIntegrationProperties;
      this.restTemplate = new RestTemplateBuilder(new RestTemplateCustomizer[0])
         .requestFactory(() -> new OkHttp3ClientHttpRequestFactory(this.getUnsafeOkHttpClient()))
         .defaultHeader("content-type", new String[]{"application/json"})
         .setConnectTimeout(Duration.ZERO)
         .setReadTimeout(Duration.ZERO)
         .uriTemplateHandler(new RootUriTemplateHandler(this.getBaseAddress()))
         .build();
   }

   @Override
   public void validateIntegration() throws KavoshServerNotReachableException, KavoshServerNotConfiguredException {
      if (StringUtils.hasContent(this.kavoshIntegrationProperties.getHost()) && StringUtils.hasContent(this.kavoshIntegrationProperties.getToken())) {
         if (!WebUtils.isHostReachable(this.kavoshIntegrationProperties.getHost(), this.kavoshIntegrationProperties.getPort())) {
            throw new KavoshServerNotReachableException();
         }
      } else {
         throw new KavoshServerNotConfiguredException();
      }
   }

   @Override
   public String getTempStoragePath() {
      return this.kavoshIntegrationProperties.getTempStorage();
   }

   @Override
   public String sendFile(File file) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException {
      return this.sendFile(file, file.getName());
   }

   @Override
   public String sendFile(File file, String name) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException {
      this.validateIntegration();
      UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUri(URI.create("/"));
      uriComponentsBuilder.queryParam("speed-mode", new Object[]{this.kavoshIntegrationProperties.getSpeedMode().name()});
      HttpHeaders headers = this.getCommonHttpHeaders();
      headers.setContentType(MediaType.MULTIPART_FORM_DATA);
      HttpHeaders fileHeaders = new HttpHeaders();
      fileHeaders.setContentDisposition(ContentDisposition.builder("form-data").name("file").filename(name).build());
      MultiValueMap<String, Object> body = new LinkedMultiValueMap();
      body.add("file", new HttpEntity(new FileSystemResource(file), fileHeaders));
      HttpEntity<MultiValueMap<String, Object>> httpEntity = new HttpEntity(body, headers);
      ResponseEntity<ObjectNode> response = this.restTemplate
         .postForEntity(uriComponentsBuilder.build().encode().toUriString(), httpEntity, ObjectNode.class, new Object[0]);
      return response.getStatusCode().is2xxSuccessful() ? ((ObjectNode)response.getBody()).get("content").get("uuid").asText() : null;
   }

   @Override
   public KavoshIntegrationService.FileStatus getStatus(String requestIdentifier) throws KavoshServerNotReachableException, KavoshServerNotConfiguredException {
      this.validateIntegration();
      UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUri(URI.create("/")).path(requestIdentifier);
      HttpHeaders headers = this.getCommonHttpHeaders();
      HttpEntity<Void> httpEntity = new HttpEntity(headers);
      String url = uriComponentsBuilder.build().encode().toUriString();
      ResponseEntity<ObjectNode> response = this.restTemplate.exchange(url, HttpMethod.GET, httpEntity, ObjectNode.class, new Object[0]);
      if (response.getStatusCode().is2xxSuccessful()) {
         JsonNode content = ((ObjectNode)response.getBody()).get("content");
         int totalScans = this.getIntValue(content, "totalScans");
         int finishedScans = this.getIntValue(content, "finishedScans");
         int infectedDetected = this.getIntValue(content, "infectedDetectionCount");
         return totalScans != finishedScans
            ? KavoshIntegrationService.FileStatus.SCANNING
            : (infectedDetected == 0 ? KavoshIntegrationService.FileStatus.CLEAN : KavoshIntegrationService.FileStatus.INFECTED);
      } else {
         return null;
      }
   }

   private String getBaseAddress() {
      String protocol = this.kavoshIntegrationProperties.isHttps() ? "https" : "http";
      return protocol
         + "://"
         + this.kavoshIntegrationProperties.getHost()
         + ":"
         + this.kavoshIntegrationProperties.getPort()
         + (this.kavoshIntegrationProperties.getBaseUrl().startsWith("/") ? "" : "/")
         + this.kavoshIntegrationProperties.getBaseUrl();
   }

   private HttpHeaders getCommonHttpHeaders() {
      HttpHeaders headers = new HttpHeaders();
      headers.set("token", this.kavoshIntegrationProperties.getToken());
      headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
      return headers;
   }

   private OkHttpClient getUnsafeOkHttpClient() {
      try {
         TrustManager[] trustAllCerts = new TrustManager[]{new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
               return new X509Certificate[0];
            }
         }};
         SSLContext sslContext = SSLContext.getInstance("SSL");
         sslContext.init(null, trustAllCerts, new SecureRandom());
         SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
         Builder builder = new Builder();
         builder.sslSocketFactory(sslSocketFactory, (X509TrustManager)trustAllCerts[0]);
         builder.hostnameVerifier(new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
               return true;
            }
         });
         return builder.build();
      } catch (Exception var6) {
         throw new RuntimeException(var6);
      }
   }

   private Integer getIntValue(JsonNode node, String property) {
      return node.get(property).asInt();
   }
}
