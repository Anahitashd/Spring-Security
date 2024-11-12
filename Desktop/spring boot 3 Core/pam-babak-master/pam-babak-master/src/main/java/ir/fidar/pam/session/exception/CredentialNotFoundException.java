package ir.fidar.pam.session.exception;

import ir.fidar.pam.session.websocket.WebsocketSessionCloseStatus;

public class CredentialNotFoundException extends SessionRequestException {
   public CredentialNotFoundException(WebsocketSessionCloseStatus closeStatus) {
      super(closeStatus);
   }
}
