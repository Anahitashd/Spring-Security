package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class ExpiredAccessRuleException extends SessionRequestException {
   public ExpiredAccessRuleException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
