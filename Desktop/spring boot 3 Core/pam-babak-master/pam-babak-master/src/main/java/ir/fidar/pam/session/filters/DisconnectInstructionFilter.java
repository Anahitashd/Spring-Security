package ir.fidar.pam.session.filters;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.protocol.GuacamoleFilter;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.springframework.stereotype.Component;

@Component
public class DisconnectInstructionFilter implements GuacamoleFilter {
   public GuacamoleInstruction filter(GuacamoleInstruction guacamoleInstruction) throws GuacamoleException {
      return guacamoleInstruction.getOpcode().equalsIgnoreCase("disconnect") ? guacamoleInstruction : null;
   }
}
