package ir.fidar.pam.session.inputextraction.processor.extractor.consoletype;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public class RightMouseClickExtractor implements InputExtractor<Void> {
   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return instruction.getOpcode().equalsIgnoreCase("mouse") && ((String)instruction.getArgs().get(2)).equalsIgnoreCase("4");
   }

   public Void extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return null;
   }
}
