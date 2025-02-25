package ir.fidar.pam.session.inputextraction.processor.extractor;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public interface InputExtractor<T> {
   boolean extractable(GuacamoleInstruction var1, RemoteSessionInputExtraction var2);

   T extract(GuacamoleInstruction var1, RemoteSessionInputExtraction var2);
}
