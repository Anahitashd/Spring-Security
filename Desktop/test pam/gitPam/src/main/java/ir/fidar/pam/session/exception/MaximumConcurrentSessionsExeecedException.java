package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class MaximumConcurrentSessionsExeecedException extends SessionRequestException {
   public MaximumConcurrentSessionsExeecedException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
