package ir.fidar.pam.session.filters;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.protocol.GuacamoleFilter;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.springframework.stereotype.Component;

@Component
public class TabKeyFilter implements GuacamoleFilter {
   public GuacamoleInstruction filter(GuacamoleInstruction guacamoleInstruction) throws GuacamoleException {
      return guacamoleInstruction.getOpcode().equalsIgnoreCase("key") && ((String)guacamoleInstruction.getArgs().get(0)).equalsIgnoreCase("65289")
         ? guacamoleInstruction
         : null;
   }
}
