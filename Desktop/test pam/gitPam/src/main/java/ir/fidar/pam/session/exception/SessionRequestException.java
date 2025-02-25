package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class SessionRequestException extends Exception {
   private WebsocketSessionCloseStatus closeStatus;

   public SessionRequestException(WebsocketSessionCloseStatus closeStatus) {
      this.closeStatus = closeStatus;
   }

   public WebsocketSessionCloseStatus getCloseStatus() {
      return this.closeStatus;
   }
}
