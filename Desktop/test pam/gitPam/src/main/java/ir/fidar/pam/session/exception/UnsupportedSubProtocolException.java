package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class UnsupportedSubProtocolException extends SessionRequestException {
   public UnsupportedSubProtocolException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
