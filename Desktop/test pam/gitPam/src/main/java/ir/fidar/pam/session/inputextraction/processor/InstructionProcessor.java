package ir.fidar.pam.session.inputextraction.processor;

import ir.fidar.pam.session.inputextraction.model.InputSource;
import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public interface InstructionProcessor<T extends RemoteSessionInputExtraction> {
   boolean processInput(GuacamoleInstruction var1, InputSource var2, T var3);
}
