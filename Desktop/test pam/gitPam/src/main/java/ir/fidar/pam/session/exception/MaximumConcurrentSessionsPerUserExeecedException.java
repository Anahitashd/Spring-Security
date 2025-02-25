package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class MaximumConcurrentSessionsPerUserExeecedException extends SessionRequestException {
   public MaximumConcurrentSessionsPerUserExeecedException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
