package ir.fidar.pam.session.inputextraction.model;

public class RemoteSessionExtractionTaskRegistry {
   private final String sessionId;
   private final String input;
   private final InputSource inputSource;

   public RemoteSessionExtractionTaskRegistry(String sessionId, String input, InputSource inputSource) {
      this.sessionId = sessionId;
      this.input = input;
      this.inputSource = inputSource;
   }

   public String getSessionId() {
      return this.sessionId;
   }

   public String getInput() {
      return this.input;
   }

   public InputSource getInputSource() {
      return this.inputSource;
   }
}
