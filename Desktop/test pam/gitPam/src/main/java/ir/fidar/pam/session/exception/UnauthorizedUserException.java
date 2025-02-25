package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class UnauthorizedUserException extends SessionRequestException {
   public UnauthorizedUserException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
