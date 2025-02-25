package ir.fidar.pam.session.ocr;

import java.util.Map;

public class OcrRequest {
   private String sessionId;
   private OcrRequestType requestType;
   private String content;
   private Map<String, String> query;

   public OcrRequest(String sessionId, OcrRequestType requestType, Map<String, String> query) {
      this.sessionId = sessionId;
      this.requestType = requestType;
      this.query = query;
   }

   public OcrRequest(String sessionId, OcrRequestType requestType, String content, Map<String, String> query) {
      this.sessionId = sessionId;
      this.requestType = requestType;
      this.content = content;
      this.query = query;
   }

   public String getSessionId() {
      return this.sessionId;
   }

   public OcrRequestType getRequestType() {
      return this.requestType;
   }

   public String getContent() {
      return this.content;
   }

   public Map<String, String> getQuery() {
      return this.query;
   }
}
