package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class SessionNotFountException extends SessionRequestException {
   public SessionNotFountException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
