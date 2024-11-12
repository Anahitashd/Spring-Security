package ir.fidar.pam.session.filters;

import org.apache.guacamole.protocol.GuacamoleInstruction;

public interface SessionInputValidator {
   void validate(GuacamoleInstruction var1) throws Exception;
}
