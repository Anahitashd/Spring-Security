package ir.fidar.pam.session.tunnel;

import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.protocol.GuacamoleStatus;

public class GuacamoleStreamException extends GuacamoleServerException {
   private final GuacamoleStatus status;

   public GuacamoleStreamException(GuacamoleStatus status, String message) {
      super(message);
      this.status = status;
   }

   public GuacamoleStatus getStatus() {
      return this.status;
   }
}
