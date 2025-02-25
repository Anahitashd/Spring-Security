package ir.fidar.pam.session.inputextraction.processor.consoletype;

import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.session.inputextraction.model.consoletype.ConsoleTypeRemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.AbstractOrderedSessionTypeAwareInstructionProcessor;
import ir.fidar.pam.session.inputextraction.processor.SessionType;
import java.util.Set;

public abstract class AbstractConsoleTypeInstructionProcessor<T>
   extends AbstractOrderedSessionTypeAwareInstructionProcessor<T, ConsoleTypeRemoteSessionInputExtraction> {
   @Override
   public Set<ConnectionType> getSessionTypes() {
      return SessionType.CONSOLE.getConnectionTypes();
   }
}
