package ir.fidar.pam.session.ocr;

import ir.fidar.pam.management.Markers;
import java.net.URI;
import java.time.Duration;
import java.util.LinkedList;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.boot.web.client.RestTemplateCustomizer;
import org.springframework.boot.web.client.RootUriTemplateHandler;
import org.springframework.http.HttpEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public class OcrRequestExecutor implements Runnable {
   private static final Logger LOGGER = LogManager.getLogger();
   private final ExecutorService executorService = Executors.newFixedThreadPool(1);
   private final RestTemplate restTemplate;
   private final Queue<OcrRequest> requestQueue;
   private final OcrHostProperties ocrHostProperties;
   private OcrRequestExecutor.Status status;

   public OcrRequestExecutor(OcrHostProperties ocrHostProperties) {
      this.ocrHostProperties = ocrHostProperties;
      this.restTemplate = new RestTemplateBuilder(new RestTemplateCustomizer[0])
         .setConnectTimeout(Duration.ofSeconds(5L))
         .setReadTimeout(Duration.ZERO)
         .uriTemplateHandler(new RootUriTemplateHandler(this.getServerRootUri()))
         .build();
      this.requestQueue = new LinkedList<>();
      this.status = OcrRequestExecutor.Status.OPEN;
   }

   public void startListening() {
      this.executorService.execute(this);
   }

   public void registerRequest(OcrRequest ocrRequest) {
      synchronized (this.requestQueue) {
         this.requestQueue.add(ocrRequest);
         this.requestQueue.notify();
      }
   }

   public void shutDown() {
      this.status = OcrRequestExecutor.Status.CLOSE;
   }

   @Override
   public void run() {
      while (true) {
         synchronized (this.requestQueue) {
            if (!this.status.equals(OcrRequestExecutor.Status.OPEN)) {
               while (!this.requestQueue.isEmpty()) {
                  this.pollRequestAndExecuteIt();
               }

               return;
            }

            if (this.requestQueue.isEmpty()) {
               try {
                  this.requestQueue.wait();
                  this.pollRequestAndExecuteIt();
               } catch (InterruptedException var4) {
                  var4.printStackTrace();
               }
            } else {
               this.pollRequestAndExecuteIt();
            }
         }
      }
   }

   private void pollRequestAndExecuteIt() {
      synchronized (this.requestQueue) {
         OcrRequest ocrRequest = this.requestQueue.poll();
         if (ocrRequest != null) {
            try {
               UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.fromUri(URI.create("/"));
               uriComponentsBuilder.path(ocrRequest.getRequestType().getApi());
               uriComponentsBuilder.queryParam("sid", new Object[]{ocrRequest.getSessionId()});
               Map<String, String> query = ocrRequest.getQuery();
               if (query != null) {
                  for (String key : query.keySet()) {
                     uriComponentsBuilder.queryParam(key, new Object[]{query.get(key)});
                  }
               }

               switch (ocrRequest.getRequestType().getHttpMethod()) {
                  case GET:
                     this.restTemplate.getForObject(uriComponentsBuilder.build().encode().toUriString(), Void.class, new Object[0]);
                     break;
                  case POST:
                     HttpEntity<String> requestBody = new HttpEntity(ocrRequest.getContent());
                     this.restTemplate.postForObject(uriComponentsBuilder.build().encode().toUriString(), requestBody, Void.class, new Object[0]);
               }
            } catch (Exception var8) {
               LOGGER.error(Markers.SESSION, "Unexpected error occurred while capturing image content for session '{}'", ocrRequest.getSessionId(), var8);
            }
         }
      }
   }

   private String getServerRootUri() {
      return "http://" + this.ocrHostProperties.getHost() + ":" + this.ocrHostProperties.getPort() + "/api";
   }

   private static enum Status {
      OPEN,
      CLOSE;
   }
}
