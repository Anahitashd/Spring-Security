package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class InvalidSessionRequestParametersException extends SessionRequestException {
   public InvalidSessionRequestParametersException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
