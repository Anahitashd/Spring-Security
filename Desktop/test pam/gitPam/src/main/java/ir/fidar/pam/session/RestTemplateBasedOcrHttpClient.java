package ir.fidar.pam.session;

import ir.fidar.pam.management.OcrServerProperties;
import java.net.URI;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Map.Entry;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.boot.web.client.RootUriTemplateHandler;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class RestTemplateBasedOcrHttpClient implements OcrHttpClient {
   private static final String QUERY_TEMPLATE = "psm={psm}&data={data}&oem={oem}&resize={resize}";
   private final OcrServerProperties ocrServerProperties;
   private final RestTemplate restTemplate;

   public RestTemplateBasedOcrHttpClient(OcrServerProperties ocrServerProperties) {
      this.ocrServerProperties = ocrServerProperties;
      this.restTemplate = new RestTemplateBuilder(new RestTemplateCustomizer[0])
         .setConnectTimeout(Duration.ofMillis(500L))
         .setReadTimeout(Duration.ofSeconds(0L))
         .uriTemplateHandler(new RootUriTemplateHandler(this.getServerRootUri()))
         .build();
   }

   @Override
   public String sendExtractionRequest(String base64Image) {
      return this.sendExtractionRequest(this.decodeBase64(base64Image));
   }

   @Override
   public String sendExtractionRequest(String base64Image, Integer psm) {
      return this.sendExtractionRequest(this.decodeBase64(base64Image), psm);
   }

   @Override
   public String sendExtractionRequest(String base64Image, Integer psm, OcrHttpClient.Dataset dataset) {
      return this.sendExtractionRequest(this.decodeBase64(base64Image), psm, dataset);
   }

   @Override
   public String sendExtractionRequest(String base64Image, Integer psm, OcrHttpClient.Dataset dataset, int oem) {
      return this.sendExtractionRequest(this.decodeBase64(base64Image), psm, dataset, oem);
   }

   @Override
   public String sendExtractionRequest(String base64Image, Integer psm, OcrHttpClient.Dataset dataset, int oem, Map<String, String> tesseractConfigVariables) {
      return this.sendExtractionRequest(this.decodeBase64(base64Image), psm, dataset, oem, tesseractConfigVariables);
   }

   @Override
   public String sendExtractionRequest(
      String base64Image, Integer psm, OcrHttpClient.Dataset dataset, int oem, Map<String, String> tesseractConfigVariables, boolean resize
   ) {
      return this.sendExtractionRequest(this.decodeBase64(base64Image), psm, dataset, oem, tesseractConfigVariables, resize);
   }

   @Override
   public String sendExtractionRequest(byte[] imageBytes) {
      return this.sendExtractionRequest(imageBytes, null);
   }

   @Override
   public String sendExtractionRequest(byte[] imageBytes, Integer psm) {
      return this.sendExtractionRequest(imageBytes, psm, OcrHttpClient.Dataset.BEST);
   }

   @Override
   public String sendExtractionRequest(byte[] imageBytes, Integer psm, OcrHttpClient.Dataset dataset) {
      return this.sendExtractionRequest(imageBytes, psm, OcrHttpClient.Dataset.BEST, 1);
   }

   @Override
   public String sendExtractionRequest(byte[] imageBytes, Integer psm, OcrHttpClient.Dataset dataset, int oem) {
      return this.sendExtractionRequest(imageBytes, psm, OcrHttpClient.Dataset.BEST, oem, null);
   }

   @Override
   public String sendExtractionRequest(byte[] imageBytes, Integer psm, OcrHttpClient.Dataset dataset, int oem, Map<String, String> tesseractConfigVariables) {
      return this.sendExtractionRequest(imageBytes, psm, dataset, oem, tesseractConfigVariables, false);
   }

   @Override
   public String sendExtractionRequest(
      byte[] imageBytes, Integer psm, OcrHttpClient.Dataset dataset, int oem, Map<String, String> tesseractConfigVariables, boolean resize
   ) {
      try {
         UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUri(URI.create("/"));
         uriComponentsBuilder = uriComponentsBuilder.query("psm={psm}&data={data}&oem={oem}&resize={resize}");
         if (tesseractConfigVariables != null) {
            for (Entry<String, String> entry : tesseractConfigVariables.entrySet()) {
               uriComponentsBuilder = uriComponentsBuilder.queryParam(entry.getKey(), new Object[]{entry.getValue()});
            }
         }

         return (String)this.restTemplate
            .postForObject(
               uriComponentsBuilder.buildAndExpand(new Object[]{psm, dataset, oem, resize}).encode().toUriString(), imageBytes, String.class, new Object[0]
            );
      } catch (Exception var10) {
         var10.printStackTrace();
         return null;
      }
   }

   private String getServerRootUri() {
      return "http://" + this.ocrServerProperties.getIpAddress() + ":" + this.ocrServerProperties.getPort() + this.ocrServerProperties.getRequestUrl();
   }

   private byte[] decodeBase64(String base64) {
      return Base64.getDecoder().decode(base64);
   }
}
