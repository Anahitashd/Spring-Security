package ir.fidar.pam.session.inputextraction.processor;

import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import java.util.Collections;
import java.util.Set;

public abstract class AbstractCommonSessionTypeInstructionProcessor<T>
   extends AbstractOrderedSessionTypeAwareInstructionProcessor<T, RemoteSessionInputExtraction> {
   @Override
   public Set<ConnectionType> getSessionTypes() {
      return Collections.emptySet();
   }
}
