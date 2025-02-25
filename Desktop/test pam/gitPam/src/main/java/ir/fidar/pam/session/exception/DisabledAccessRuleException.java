package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class DisabledAccessRuleException extends SessionRequestException {
   public DisabledAccessRuleException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
