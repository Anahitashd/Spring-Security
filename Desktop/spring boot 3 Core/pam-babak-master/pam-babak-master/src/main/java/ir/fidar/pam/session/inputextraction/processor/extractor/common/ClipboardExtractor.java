package ir.fidar.pam.session.inputextraction.processor.extractor.common;

import ir.fidar.pam.session.inputextraction.model.RemoteSessionInputExtraction;
import ir.fidar.pam.session.inputextraction.processor.extractor.InputExtractor;
import org.apache.guacamole.protocol.GuacamoleInstruction;

public class ClipboardExtractor implements InputExtractor<Void> {
   @Override
   public boolean extractable(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return instruction.getOpcode().equalsIgnoreCase("clipboard");
   }

   public Void extract(GuacamoleInstruction instruction, RemoteSessionInputExtraction remoteSessionInputExtraction) {
      return null;
   }
}
