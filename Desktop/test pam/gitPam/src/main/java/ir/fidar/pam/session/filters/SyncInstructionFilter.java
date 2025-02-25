package ir.fidar.pam.session.filters;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.protocol.GuacamoleFilter;
import org.apache.guacamole.protocol.GuacamoleInstruction;
import org.springframework.stereotype.Component;

@Component
public class SyncInstructionFilter implements GuacamoleFilter {
   private static final Set<String> SYNC_INSTRUCTIONS = Stream.of("sync", "nop", "ping").collect(Collectors.toSet());

   public GuacamoleInstruction filter(GuacamoleInstruction guacamoleInstruction) throws GuacamoleException {
      return SYNC_INSTRUCTIONS.contains(guacamoleInstruction.getOpcode()) ? guacamoleInstruction : null;
   }
}
