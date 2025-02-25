package ir.fidar.pam.session.ocr;

import org.springframework.http.HttpMethod;

public enum OcrRequestType {
   INIT(HttpMethod.GET, "init"),
   CAPTURE(HttpMethod.POST, "capture"),
   CLOSE(HttpMethod.GET, "close");

   private HttpMethod httpMethod;
   private String api;

   private OcrRequestType(HttpMethod httpMethod, String api) {
      this.httpMethod = httpMethod;
      this.api = api;
   }

   public HttpMethod getHttpMethod() {
      return this.httpMethod;
   }

   public String getApi() {
      return this.api;
   }
}
