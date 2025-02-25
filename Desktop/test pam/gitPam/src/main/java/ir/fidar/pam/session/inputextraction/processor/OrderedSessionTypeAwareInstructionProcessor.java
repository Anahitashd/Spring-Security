package ir.fidar.pam.session.inputextraction.processor;

import ir.fidar.pam.domain.type.ConnectionType;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import java.util.Set;
import org.springframework.core.Ordered;

public interface OrderedSessionTypeAwareInstructionProcessor<T extends RemoteSessionInputExtraction> extends InstructionProcessor<T>, Ordered {
   Set<ConnectionType> getSessionTypes();
}
